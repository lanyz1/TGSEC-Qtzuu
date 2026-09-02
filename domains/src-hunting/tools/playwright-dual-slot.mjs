#!/usr/bin/env node
/**
 * Playwright MCP dual-slot launcher
 *
 * Keeps two Chrome instances (CDP ports) ready for concurrent Grok sessions.
 * First AI window claims the free slot; the next window takes the other.
 *
 * stdio is fully delegated to @playwright/mcp (MCP protocol stays intact).
 * Diagnostics go to stderr only.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

// 常规调试口：先开的 AI 占 9222，后开的占闲置的 9223
const PORTS = [9222, 9223];
const BASE_DIR = path.join(
  process.env.LOCALAPPDATA || os.tmpdir(),
  "mcp-shared-browsers"
);
const LOCK_DIR = path.join(BASE_DIR, "locks");
const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  path.join(
    process.env.LOCALAPPDATA || "",
    "Google\\Chrome\\Application\\chrome.exe"
  ),
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
].filter(Boolean);

const EXTRA_MCP_ARGS = [
  "--browser=chrome",
  "--caps=vision,pdf",
];

function log(...args) {
  console.error("[playwright-dual-slot]", ...args);
}

function ensureDirs() {
  fs.mkdirSync(LOCK_DIR, { recursive: true });
  for (const port of PORTS) {
    fs.mkdirSync(path.join(BASE_DIR, `slot-${port}`), { recursive: true });
  }
}

function lockPath(port) {
  return path.join(LOCK_DIR, `slot-${port}.lock`);
}

function isPidAlive(pid) {
  if (!pid || !Number.isFinite(pid)) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function readLock(port) {
  const file = lockPath(port);
  try {
    const raw = fs.readFileSync(file, "utf8").trim();
    const data = JSON.parse(raw);
    if (isPidAlive(data.pid)) return data;
    fs.unlinkSync(file);
    return null;
  } catch {
    try {
      fs.unlinkSync(file);
    } catch {
      /* ignore */
    }
    return null;
  }
}

function tryAcquireLock(port) {
  const file = lockPath(port);
  const existing = readLock(port);
  if (existing) return false;

  const payload = JSON.stringify(
    {
      pid: process.pid,
      port,
      startedAt: new Date().toISOString(),
    },
    null,
    0
  );

  try {
    const fd = fs.openSync(file, "wx");
    fs.writeFileSync(fd, payload);
    fs.closeSync(fd);
    // Re-read in case of rare race
    const again = JSON.parse(fs.readFileSync(file, "utf8"));
    if (again.pid !== process.pid) return false;
    return true;
  } catch {
    return false;
  }
}

function releaseLock(port) {
  const file = lockPath(port);
  try {
    const raw = fs.readFileSync(file, "utf8");
    const data = JSON.parse(raw);
    if (data.pid === process.pid) fs.unlinkSync(file);
  } catch {
    /* ignore */
  }
}

function findChrome() {
  for (const p of CHROME_CANDIDATES) {
    try {
      if (p && fs.existsSync(p)) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}

function portOpen(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port }, () => {
      socket.end();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.setTimeout(500, () => {
      socket.destroy();
      resolve(false);
    });
  });
}

function cdpVersion(port) {
  return new Promise((resolve) => {
    const req = http.get(
      {
        host: "127.0.0.1",
        port,
        path: "/json/version",
        timeout: 1500,
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(body));
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

async function ensureChrome(port) {
  const version = await cdpVersion(port);
  if (version) {
    log(`Chrome already up on ${port}:`, version.Browser || "ok");
    return;
  }

  const chrome = findChrome();
  if (!chrome) {
    throw new Error(
      "Chrome/Edge not found. Set CHROME_PATH to the browser executable."
    );
  }

  const userDataDir = path.join(BASE_DIR, `slot-${port}`);
  const args = [
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${userDataDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-sync",
    "about:blank",
  ];

  log(`Starting Chrome for slot ${port}:`, chrome);
  const child = spawn(chrome, args, {
    detached: true,
    stdio: "ignore",
    windowsHide: false,
  });
  child.unref();

  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const v = await cdpVersion(port);
    if (v) {
      log(`Chrome ready on ${port}`);
      return;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`Chrome CDP did not become ready on port ${port}`);
}

/**
 * Dual-slot: first free lock wins (9222 first, then 9223).
 * Do NOT steal another session's live CDP — each Grok window owns one port.
 * ensureChrome only starts Chrome if that port has no CDP yet; never kills browsers.
 */
function pickSlot() {
  for (const port of PORTS) {
    if (tryAcquireLock(port)) return port;
  }
  return null;
}

function runMcp(port) {
  const endpoint = `http://127.0.0.1:${port}`;
  const args = [
    "-y",
    "@playwright/mcp@latest",
    `--cdp-endpoint=${endpoint}`,
    ...EXTRA_MCP_ARGS,
  ];

  log(`Launching Playwright MCP → ${endpoint}`);
  log(`Slots: ${PORTS.join(", ")} | this session: ${port}`);

  // Prefer original CLI if the dual-slot wrapper is installed in npx cache
  // (avoids double-wrapping when config also points at this launcher).
  const originalCli = path.join(
    process.env.LOCALAPPDATA || "",
    "npm-cache",
    "_npx",
    "9833c18b2d85bc59",
    "node_modules",
    "@playwright",
    "mcp",
    "cli.original.js"
  );

  let child;
  if (fs.existsSync(originalCli)) {
    child = spawn(
      process.execPath,
      [originalCli, `--cdp-endpoint=${endpoint}`, ...EXTRA_MCP_ARGS],
      { stdio: "inherit", env: process.env }
    );
  } else if (process.platform === "win32") {
    child = spawn("cmd.exe", ["/d", "/s", "/c", "npx", ...args], {
      stdio: "inherit",
      windowsHide: true,
      env: process.env,
    });
  } else {
    child = spawn("npx", args, { stdio: "inherit", env: process.env });
  }

  const cleanup = () => {
    releaseLock(port);
  };

  process.on("exit", cleanup);
  process.on("SIGINT", () => {
    cleanup();
    try {
      child.kill("SIGINT");
    } catch {
      /* ignore */
    }
    process.exit(130);
  });
  process.on("SIGTERM", () => {
    cleanup();
    try {
      child.kill("SIGTERM");
    } catch {
      /* ignore */
    }
    process.exit(143);
  });

  child.on("exit", (code, signal) => {
    cleanup();
    if (signal) process.exit(1);
    process.exit(code ?? 0);
  });

  child.on("error", (err) => {
    cleanup();
    log("Failed to start npx/@playwright/mcp:", err.message);
    process.exit(1);
  });
}

async function main() {
  ensureDirs();

  const port = pickSlot();
  if (port == null) {
    log(
      `Both slots busy (${PORTS.join(
        ", "
      )}). Close one Grok Playwright session and retry.`
    );
    for (const p of PORTS) {
      const lock = readLock(p);
      if (lock) log(`  port ${p} held by pid ${lock.pid} since ${lock.startedAt}`);
    }
    process.exit(2);
  }

  log(`Claimed slot port ${port} (pid ${process.pid})`);
  log(`Rule: 9222/9223 are independent sessions — never proxy or steal the other slot.`);

  try {
    // Only starts Chrome if CDP is down on THIS port — never kill other slot browsers
    await ensureChrome(port);
  } catch (err) {
    releaseLock(port);
    log(err.message || err);
    process.exit(1);
  }

  runMcp(port);
}

main().catch((err) => {
  log(err?.stack || err);
  process.exit(1);
});
