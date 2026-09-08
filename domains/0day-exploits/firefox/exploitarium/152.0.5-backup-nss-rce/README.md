# Firefox 152.0.5 Backup Recovery to NSS DLL Load PoC

This folder contains a browser-delivered Windows x64 proof that opens Calculator from a signed stock Firefox `152.0.5` installation. The verified workflow starts with one HTTP navigation. Firefox then downloads the two delivery files, crosses from the content process into a privileged `about:welcome` actor, restores a crafted profile backup, launches the restored Firefox parent process, and loads the proof DLL through NSS configuration recovery.

The chain combines a Wasm/Baseline-JIT memory-safety entry with BrowserBridge principal handling, privileged actor authorization, backup recovery policy, and NSS module-loading behavior.

## Tested Target

| Property | Value |
| --- | --- |
| Operating system | Windows 11 Home x64, `10.0.26200`, build 26200 |
| Firefox | Signed stock Windows x64 Firefox `152.0.5` |
| Build ID | `20260706120035` |
| `firefox.exe` SHA-256 | `BA9EEFD0420B7481984335DF8C729CA97BB7B0391FC5F781DCE72702B2340275` |
| `xul.dll` SHA-256 | `F29D9EDEAC624A2393D9B21882D775714ECA45F75ECE84FE43E141A85FD3A60E` |

The Wasm payloads contain native offsets for this exact x64 Firefox binary. Additional Firefox binaries require matching offsets and regenerated Wasm artifacts.

## Files

| File | Purpose |
| --- | --- |
| `server.py` | Resolves the Windows Downloads known folder, prepares the backup, serves the PoC, and records proof callbacks. |
| `build_backup.py` | Builds the schema-v2 single-file Firefox profile backup. |
| `exploit.html` | Performs delivery, content-process exploitation, BrowserBridge navigation, and privileged restore dispatch. |
| `stage.html` | Supplies the out-of-process child frame used to obtain the child `BrowsingContext` identifier. |
| `child_id_probe.wasm` | Recovers the out-of-process child context identifier from native Firefox objects. |
| `native_browserbridge.wasm` | Builds and sends the privileged BrowserBridge load state. |
| `firefox_calc_payload.dll` | Windows x64 Calculator proof payload. |
| `calc_payload.c` | Source for the proof DLL. |
| `SHA256SUMS.txt` | Hash manifest for the tracked PoC files. |

`FirefoxBackup_RCE.html` and `proof.jsonl` are generated at runtime.

## Reproduction

Prerequisites:

- the tested Firefox build listed above;
- Python 3;
- default automatic Downloads behavior;
- `firefox_calc_payload.dll` and `FirefoxBackup_RCE.html` absent from the current Downloads known folder.

Start the local origin from this folder:

```powershell
python -B server.py
```

The server prints the visit URL:

```text
http://127.0.0.1:8896/
```

Open that URL in the tested stock Firefox build. The `firefox.exe` command may receive the URL directly:

```powershell
& "C:\path\to\firefox.exe" "http://127.0.0.1:8896/"
```

After the initial navigation, the sequence is automatic. Expected results are:

1. the proof DLL and generated backup appear in Downloads;
2. `proof.jsonl` records the native probe, privileged navigation, archive metadata, and restore dispatch;
3. Firefox launches the restored profile in a new parent process;
4. Calculator opens from the proof DLL's process-attach entry.

The server exits early when either delivery filename already exists, preserving the download names used by the restored NSS configuration.

## End-to-End Sequence

1. `server.py` resolves the current user's Downloads known folder through the Windows known-folder registry value.
2. `build_backup.py` generates an unencrypted Firefox backup whose manifest includes `credentials_and_security` and `preferences` resources.
3. `exploit.html` dispatches browser downloads for `firefox_calc_payload.dll` and `FirefoxBackup_RCE.html`.
4. `child_id_probe.wasm` uses the Wasm/Baseline-JIT primitive to obtain native control in the content process, walks the child window context, and returns the target `BrowsingContext` identifier to JavaScript.
5. `native_browserbridge.wasm` resolves the corresponding `BrowserBridgeChild` and sends a load state carrying a system principal for `about:welcome`.
6. A second BrowserBridge load evaluates a `javascript:` URI in that privileged page.
7. The injected page script initializes the BackupUI actor and dispatches `BackupUI:GetBackupFileInfo` with the generated backup path.
8. After Firefox validates and reports the archive metadata, the script dispatches `BackupUI:RestoreFromBackupFile` with automatic profile launch enabled by the parent recovery flow.
9. Recovery copies the supplied `pkcs11.txt` from the `credentials_and_security` resource into the restored profile.
10. Firefox quits the original profile and starts the restored parent process.
11. NSS reads the restored module database and asks the Windows loader to load `firefox_calc_payload.dll` from Downloads.
12. The DLL process-attach entry calls `WinExec("calc.exe", SW_SHOWNORMAL)`.

## Technical Analysis

### Content-Process Entry

The two Wasm modules share a Baseline-JIT corruption primitive and use the leaked JIT return address to derive the sprayed native entry and stack-repair locations. The first payload walks the live child window-context structures and writes the out-of-process child `BrowsingContext` identifier back to Wasm linear memory. The second payload resolves the browser-bridge actor for that identifier, constructs an `nsDocShellLoadState`, assigns a system principal, and invokes the bridge load method.

The exploit returns to JavaScript after each native dispatch. The proof log therefore records native return values, resolved actor pointers, and the later privileged-page callbacks in one browser session.

### Privileged Actor Boundary

`about:welcome` runs in the shared `privilegedabout` remote type. The BackupUI child actor accepts page-dispatched custom events and forwards their data to the parent actor. Parent-side handling relies on the actor's process placement while accepting the supplied backup path and restore operation.

The BrowserBridge step supplies the privileged navigation and then evaluates the recovery script inside the resulting `about:welcome` document. That script can reach the BackupUI event surface and initiate profile recovery from the downloaded archive.

### Backup Recovery

The generated outer archive sets `encConfig` to `null`. Its inner manifest declares these resources:

```json
{
  "credentials_and_security": null,
  "preferences": {}
}
```

Recovery accepts the archive and restores the credentials resource, including attacker-supplied `pkcs11.txt`, into the new profile. The preferences resource also carries a minimal profile copy of the DLL for compatibility with selectable-profile recovery.

The module database entry points to the delivered Downloads path:

```text
library=C:\\Users\\<user>\\Downloads\\firefox_calc_payload.dll
name=Firefox Calculator Module
parameters=
NSS=
```

### NSS Module Load

During startup of the restored parent process, NSS parses the text module database and reaches `PR_LoadLibraryWithFlags` for the supplied `library=` value. Windows executes the DLL entry point as part of loading the image. NSS subsequently attempts to resolve the PKCS#11 interface functions.

The supplied DLL's PE export directory is empty. Its process-attach entry is sufficient for the Calculator proof before interface resolution occurs.

## Source Trace

The relevant Firefox `152.0.5` source locations are:

| Source | Lines | Role |
| --- | ---: | --- |
| `browser/components/DesktopActorRegistry.sys.mjs` | `269-306` | BackupUI actor registration and privileged remote-type placement. |
| `browser/components/backup/BackupUIChild.sys.mjs` | `22-33`, `90-109` | Page event listeners and child-to-parent message forwarding. |
| `browser/components/backup/BackupUIParent.sys.mjs` | `124-138`, `213-248` | Backup metadata and restore message handling. |
| `browser/components/backup/BackupService.sys.mjs` | `1562-1579`, `2742-2909`, `3426-3457` | Archive inspection, resource recovery, profile creation, and automatic launch. |
| `browser/components/backup/resources/CredentialsAndSecurityBackupResource.sys.mjs` | `25-32`, `57-84` | Credentials/security resource policy and file recovery. |
| `security/nss/lib/util/utilmod.c` | `228-245` | Text module database library-field parsing. |
| `security/nss/lib/pk11wrap/pk11load.c` | `449-506` | Dynamic library load followed by PKCS#11 interface resolution. |

## Verified Repository Replay

The files in this folder were replayed on July 11, 2026 by starting the local server and passing only `http://127.0.0.1:8896/` to the tested stock `firefox.exe`.

Recorded milestones:

| Milestone | Result |
| --- | --- |
| Initial navigation | `2026-07-11T08:59:56.2385139-05:00` |
| Native child-context return | `probe_returned` |
| System-principal bridge return | `bootstrap_returned` |
| Privileged script bridge return | `javascript_returned` |
| Validated archive | `isEncrypted=false`, app `152.0.5`, build `20260706120035` |
| Restore dispatch | `2026-07-11T09:00:14.643754-05:00` |
| Calculator process | PID `34792`, start `2026-07-11T09:00:15.3588699-05:00` |
| Windows launch evidence | AppModel-Runtime Event `201`, record `39574` |
| Restored Firefox parent | PID `35312` |

The restored parent command line selected the generated profile and opened `about:editprofile#restoredProfile`, matching the automatic recovery path.

## Artifact Hashes

| Artifact | SHA-256 |
| --- | --- |
| `firefox_calc_payload.dll` | `6C354DCD4C5B45802AD98EAC6382AD05DA58C64757ACB307D3AF024F605268EC` |
| `child_id_probe.wasm` | `5F642BA6E322B111E53E29858AEDC5850B93005D78CB6D19C156BAB491D468CF` |
| `native_browserbridge.wasm` | `3EDAA1F6EF07DAC9B4366C2FD47F9AA86D004D15CDB241C368D2B8CBE54491E8` |

The generated backup hash varies with its timestamp, host metadata, and resolved Downloads path. Its embedded DLL bytes match `firefox_calc_payload.dll`.

## Fix Direction

- Bind BackupUI operations to an authoritative document principal, an exact approved URI, and a capability created by the genuine recovery interface.
- Require a trusted activation token for archive selection and restore dispatch.
- Enforce resource encryption requirements during recovery as well as backup creation.
- Restrict credentials/security recovery to validated files and reject restored external module paths.
- Validate NSS module configuration before loading a referenced library.
- Add regression coverage for page-dispatched BackupUI events, shared privileged remote types, unencrypted credentials resources, and external `pkcs11.txt` library paths.

## Responsible Use

Use this material for authorized reproduction, browser hardening, and regression testing.
