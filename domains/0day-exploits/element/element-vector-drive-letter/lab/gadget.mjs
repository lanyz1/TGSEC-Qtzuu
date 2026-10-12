#!/usr/bin/env node
/**
 * Gadget of Element Desktop v1.12.29 vector: protocol (electron-main.ts).
 * Pin tag v1.12.29 commit 2d90d6b7b601ecb9ccdf81239a43b4396b4b0c9e.
 *
 * Copied: protocol.registerFileProtocol("vector", ...) pathname split, webapp
 * prefix, path.normalize(path.join(...target.slice(2))), startsWith("..")
 * jail, path.join(baseDir, relTarget). Host is macOS/Linux; Node path.win32
 * is the Windows parser. Native Element Desktop is not run.
 *
 * Drive-letter leftover: join of C:, Windows, win.ini is absolute, so the
 * ".." check does not fire. Electron's own pattern also rejects
 * path.isAbsolute. This gadget opens the absolute relTarget (asar dropped).
 * Node path.win32.join(asar, abs) concatenates; path.win32.resolve drops
 * asar. POSIX path does not treat C: as absolute.
 */

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { URL } from "node:url";

const LABEL = "element-vector-drive-letter";
const WITNESS = "ELEMENT-VECTOR-DRIVE-LETTER-WITNESS";
const PIN = "v1.12.29";
const PIN_COMMIT = "2d90d6b7b601ecb9ccdf81239a43b4396b4b0c9e";
const LISTEN_HOST = "0.0.0.0";
const LISTEN_PORT = 19610;
const ASAR_WIN = "C:\\Program Files\\Element\\resources\\webapp.asar";
const ASAR_POSIX = "/lab/asar";
const ASAR_DIR = "/lab/asar";
const ORACLE_WIN = "C:\\Windows\\win.ini";
const ORACLE_LAB = "/lab/oracle/win.ini";
const NET_METHOD_NOT_SUPPORTED = -322;
const NET_UNKNOWN_URL_SCHEME = -302;
const NET_NAME_NOT_RESOLVED = -105;
const NET_FILE_NOT_FOUND = -6;

/**
 * Copied from apps/desktop/src/electron-main.ts (v1.12.29) and parameterized
 * on Node path.win32 vs path.posix. rejectAbsolute is the missing Electron
 * check; the pin does not pass it.
 *
 * @param {string} requestUrl
 * @param {path.PlatformPath} pathMod
 * @param {string} asarPath
 * @param {boolean} rejectAbsolute
 */
function handleVectorFileProtocol(requestUrl, pathMod, asarPath, rejectAbsolute) {
    const parsedUrl = new URL(requestUrl);
    if (parsedUrl.protocol !== "vector:") {
        return { error: NET_UNKNOWN_URL_SCHEME };
    }
    if (parsedUrl.host !== "vector") {
        return { error: NET_NAME_NOT_RESOLVED };
    }

    const target = parsedUrl.pathname.split("/");

    // path starts with a '/'
    if (target[0] !== "") {
        return { error: NET_FILE_NOT_FOUND };
    }

    if (target[target.length - 1] == "") {
        target[target.length - 1] = "index.html";
    }

    let baseDir;
    if (target[1] === "webapp") {
        baseDir = asarPath;
    } else {
        return { error: NET_FILE_NOT_FOUND };
    }

    // Normalise the base dir and the target path separately, then make sure
    // the target path isn't trying to back out beyond its root
    baseDir = pathMod.normalize(baseDir);

    const relTarget = pathMod.normalize(pathMod.join(...target.slice(2)));
    if (relTarget.startsWith("..")) {
        return { error: NET_FILE_NOT_FOUND, relTarget, baseDir };
    }
    if (rejectAbsolute && pathMod.isAbsolute(relTarget)) {
        return { error: NET_FILE_NOT_FOUND, relTarget, baseDir };
    }
    const absTarget = pathMod.join(baseDir, relTarget);
    return { path: absTarget, relTarget, baseDir };
}

/**
 * @param {path.PlatformPath} pathMod
 * @param {string} baseDir
 * @param {string} absPath
 */
function escapesJail(pathMod, baseDir, absPath) {
    const root = pathMod.resolve(baseDir);
    const resolved = pathMod.resolve(absPath);
    const rel = pathMod.relative(root, resolved);
    return rel.startsWith("..") || pathMod.isAbsolute(rel);
}

/**
 * @param {string} winPath
 */
function winKey(winPath) {
    return path.win32.normalize(winPath).toLowerCase();
}

/**
 * @param {path.PlatformPath} pathMod
 * @param {object} handled
 */
function openHandled(pathMod, handled) {
    if (handled.error !== undefined) {
        return { status: 404, body: "", open: "none" };
    }
    const relAbsolute = pathMod.isAbsolute(handled.relTarget);
    if (relAbsolute) {
        const resolved = pathMod.resolve(handled.baseDir, handled.relTarget);
        if (
            pathMod === path.win32 &&
            winKey(handled.relTarget) === winKey(ORACLE_WIN) &&
            winKey(resolved) === winKey(ORACLE_WIN)
        ) {
            return {
                status: 200,
                body: fs.readFileSync(ORACLE_LAB, "utf8"),
                open: "escaped-absolute",
            };
        }
        return { status: 404, body: "", open: "none" };
    }

    const relInside = pathMod.relative(handled.baseDir, handled.path);
    if (relInside.startsWith("..") || pathMod.isAbsolute(relInside)) {
        return { status: 404, body: "", open: "none" };
    }
    const mapped = path.posix.join(ASAR_DIR, relInside.split(pathMod.sep).join("/"));
    const asarRoot = path.posix.resolve(ASAR_DIR);
    if (path.posix.relative(asarRoot, mapped).startsWith("..")) {
        return { status: 404, body: "", open: "none" };
    }
    if (!fs.existsSync(mapped) || !fs.statSync(mapped).isFile()) {
        return { status: 404, body: "", open: "none" };
    }
    return { status: 200, body: fs.readFileSync(mapped, "utf8"), open: "asar" };
}

/**
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
function sendPing(req, res) {
    const body = "pong\n";
    res.writeHead(200, {
        "content-type": "text/plain; charset=utf-8",
        "content-length": Buffer.byteLength(body),
        "x-lab-how": "gadget",
        "x-lab": LABEL,
        "x-pin": PIN,
        "x-pin-commit": PIN_COMMIT,
        "x-witness": WITNESS,
    });
    res.end(body);
}

/**
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {URL} parsed
 */
function sendProtocol(req, res, parsed) {
    if (req.method !== "GET") {
        res.writeHead(405, { allow: "GET" });
        res.end();
        return;
    }

    const requestUrl = parsed.searchParams.get("url") || "";
    const pathName = parsed.searchParams.get("path") || "win32";
    const rejectAbsolute = parsed.searchParams.get("patched") === "1";
    const pathMod = pathName === "posix" ? path.posix : path.win32;
    const asarPath = pathMod === path.win32 ? ASAR_WIN : ASAR_POSIX;

    let handled;
    try {
        handled = handleVectorFileProtocol(requestUrl, pathMod, asarPath, rejectAbsolute);
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
        res.end(message);
        return;
    }

    const opened = openHandled(pathMod, handled);
    const relTarget = handled.relTarget || "";
    const joinPath = handled.path || "";
    const resolvePath =
        relTarget !== "" ? pathMod.resolve(handled.baseDir || asarPath, relTarget) : "";
    const relAbsolute = relTarget !== "" && pathMod.isAbsolute(relTarget);
    const escaped =
        relTarget !== "" &&
        handled.error === undefined &&
        escapesJail(pathMod, handled.baseDir || asarPath, resolvePath || joinPath);

    const headers = {
        "content-type": "text/plain; charset=utf-8",
        "x-lab-how": "gadget",
        "x-lab": LABEL,
        "x-pin": PIN,
        "x-pin-commit": PIN_COMMIT,
        "x-path-api": pathMod === path.win32 ? "win32" : "posix",
        "x-patched": rejectAbsolute ? "yes" : "no",
        "x-error": handled.error !== undefined ? String(handled.error) : "",
        "x-rel-target": relTarget,
        "x-rel-absolute": relAbsolute ? "yes" : "no",
        "x-dotdot": relTarget.startsWith("..") ? "reject" : "pass",
        "x-join-path": joinPath,
        "x-resolve-path": resolvePath,
        "x-escaped": escaped ? "yes" : "no",
        "x-open": opened.open,
    };
    res.writeHead(opened.status, headers);
    res.end(opened.body);
}

const server = http.createServer((req, res) => {
    let parsed;
    try {
        parsed = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    } catch {
        res.writeHead(400);
        res.end();
        return;
    }

    if (req.method === "GET" && parsed.pathname === "/ping") {
        sendPing(req, res);
        return;
    }
    if (parsed.pathname === "/protocol") {
        sendProtocol(req, res, parsed);
        return;
    }
    res.writeHead(404);
    res.end();
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
    process.stdout.write(
        `gadget listen ${LISTEN_HOST}:${LISTEN_PORT} label=${LABEL} pin=${PIN} how=gadget\n`,
    );
});
