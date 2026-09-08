# Discord 1.0.9245 Activity-to-Native Calculator PoC

This folder contains a browser-delivered Windows x64 proof that starts in a custom Discord Activity and opens Windows Calculator from the installed stock Discord client. The entry renderer is created by Discord with its normal Activity sandbox configuration. The page obtains an engine memory primitive, changes the auxiliary-window policy used by that renderer, opens a second renderer, invokes Discord's internal Electron IPC bridge, persists a temporary web-application endpoint, and requests an application relaunch. The relaunched main renderer loads the native stage, resolves `CreateProcessW`, and starts `C:\Windows\System32\calc.exe`.

The reproduction uses Discord's normal Developer Portal URL mapping and App Launcher flow. The installed `Discord.exe`, its packaged application resources, and the user's normal Discord profile remain the target throughout the chain.

## Tested Target

| Property | Value |
| --- | --- |
| Operating system | Windows 11 x64, `10.0.26200` |
| Discord channel | Stable |
| Discord version | `1.0.9245` |
| Electron | `37.6.0` |
| Chromium | `138.0.7204.251` |
| V8 | `13.8.258.32-electron.0` |
| `Discord.exe` SHA-256 | `C14A6B393AAD5EFAF7E9CCB2BADDBE6943D00B2073D777A6786FDD5AC405722E` |
| Native proof | `CreateProcessW(L"C:\\Windows\\System32\\calc.exe", ...)` |

The native layouts, compressed map candidates, generated-code signatures, and Discord renderer offsets in the payload correspond to this exact build.

## Files

| File | Purpose |
| --- | --- |
| `server.js` | One-shot Activity server, payload coordinator, proof collector, and recovery endpoint. |
| `exploit.html` | Renderer memory primitive and generated native payload builder. |
| `wasm-module-builder.js` | WebAssembly bytecode construction support used by the renderer stage. |
| `run.ps1` | Validates the stock target, backs up Discord settings, starts the server, observes completion, restores settings, and signals recovery. |
| `evidence/verified-stock-run.json` | Sanitized target and result record from the verified stock-client run. |
| `SHA256SUMS.txt` | Hashes for the tracked proof artifacts. |

Runtime state is written beneath `.state/` and `logs/`. Those paths are excluded from Git.

## Requirements

- Windows 11 x64.
- The tested stable Discord build at `%LOCALAPPDATA%\Discord\app-1.0.9245\Discord.exe`.
- A running stock Discord desktop session using that executable.
- Node.js available as `node` in `PATH`.
- PowerShell 5.1 or later.
- A Discord developer application owned by the testing account or its developer team.
- An HTTPS tunnel that forwards to `http://127.0.0.1:3077`.
- Windows Calculator closed before starting the proof.

The launcher verifies the target executable hash before serving the Activity. It also requires exactly one stock Discord browser process and refuses an occupied listener port or an existing Calculator process.

## Activity Configuration

Discord documents Activities as web applications loaded in client iframes and routed through its per-application proxy. The Developer Portal supplies the URL mapping and creates a default `Launch` entry point when Activities are enabled.

1. Open the Discord Developer Portal and create a development application.
2. Add the testing account to the owning developer team when the application is team-owned.
3. Enable Developer Mode in the desktop client under **User Settings > Advanced**.
4. Open **Activities > Settings** for the application and enable Activities.
5. Start an HTTPS tunnel to local port `3077`.
6. Open **Activities > URL Mappings** and add this mapping:

   | Prefix | Target |
   | --- | --- |
   | `/` | `<PUBLIC_TUNNEL_HOST>` |

7. Save the mapping. Discord will expose the Activity through `https://<APPLICATION_ID>.discordsays.com` while forwarding mapped requests to the tunnel target.
8. Use the default `Launch` entry point from Discord's App Launcher in a test channel.

The placeholder application identifier and tunnel host are supplied by the person reproducing the proof. No application credential, bot token, OAuth token, or fixed application identifier is embedded in the files.

## Reproduction

Start a tunnel in the first terminal. Discord's Activity guide uses `cloudflared`; another HTTPS reverse tunnel can be used when it forwards every path without an interstitial page.

```powershell
cloudflared tunnel --url http://127.0.0.1:3077
```

Copy the generated HTTPS origin. In a second terminal, run the launcher from this folder:

```powershell
.\run.ps1 -PublicOrigin "https://<PUBLIC_TUNNEL_HOST>"
```

The launcher prints:

```text
Server ready on http://127.0.0.1:3077/
Public origin: https://<PUBLIC_TUNNEL_HOST>
Launch the configured Activity in stock Discord, wait for lease-granted, then press Run Calculator proof once.
```

In Discord:

1. Open the test application's Activity from the App Launcher.
2. Keep one Activity instance open.
3. Wait until the Activity reports `lease-granted` and `stage-two-prefetched`.
4. Press **Run Calculator proof** once.
5. Allow approximately twenty seconds for the popup policy stage, Electron IPC sequence, application relaunch, and native stage.

The expected visible sequence is:

1. a small auxiliary Discord window appears;
2. Discord relaunches after the temporary endpoint and path are persisted;
3. Calculator opens and remains available on the desktop;
4. the native renderer exit is verified;
5. the original Discord settings bytes are restored;
6. Discord relaunches on its normal endpoint.

On completion, `run.ps1` prints the Calculator process identifiers, the restored settings hash, and the server log path. Calculator is intentionally left open as the benign proof result.

## End-to-End Sequence

1. Discord loads the mapped Activity inside its normal sandboxed Activity renderer.
2. The Activity registers a random per-session instance and obtains a one-shot server lease.
3. The server returns the popup-policy worker and prefetches the second-stage document.
4. The Activity copies its response CSP nonce onto every script in the prefetched document. This preserves script execution when the Discord proxy assigns a fresh nonce to each response.
5. The first renderer drives the engine optimization path into a type confusion and builds an in-cage arbitrary read/write primitive.
6. The payload recovers the V8 cage base, finds the generated function dispatch entry, locates the native marker and function epilogue, and installs a compact native trampoline.
7. The worker makes the popup-policy instruction page writable, changes the conditional popup branch and sandbox-flag propagation instruction, flushes the instruction cache, restores page protection, restores the generated-code dispatch instruction, and returns through the signature-checked V8 epilogue.
8. `window.open()` now creates the auxiliary window. The Activity stops its initial navigation and writes the nonce-adjusted second-stage document into the initial document.
9. The second renderer rebuilds the memory primitive and locates Discord's Electron IPC implementation in the loaded image.
10. A generated Win64 payload constructs three native IPC invocations:
    - `DISCORD_SETTINGS_SET("WEBAPP_ENDPOINT", <ACTIVITY_PROXY_ORIGIN>)`;
    - `DISCORD_SETTINGS_SET("WEBAPP_PATH", "/native-proof")`;
    - `DISCORD_APP_RELAUNCH()`.
11. The payload waits three seconds before the final invocation so the two asynchronous settings handlers persist their values before relaunch.
12. Discord starts a new main renderer for the temporary endpoint and requests `/native-proof` from the Activity proxy.
13. The native page runs the engine stage again in that renderer, resolves imported `CreateProcessW`, `Sleep`, and `ExitProcess` addresses from the stock Discord image, and writes the Calculator path into generated executable memory.
14. The native trampoline calls `CreateProcessW`, checks its return value, and keeps the renderer alive for ten seconds while Calculator activates.
15. The renderer exits with the proof sentinel. The following renderer reads Discord's recorded renderer exit, reports successful native completion, and waits for recovery.
16. `run.ps1` restores the exact settings backup and writes the recovery signal.
17. The verification page requests the final Discord relaunch after both native verification and settings recovery are true.

## Why the Chain Works

### Renderer Memory Primitive

The renderer stage trains property accesses across two feedback-compatible shapes and uses a WebAssembly reference callback to change the optimized value representation. Confused stores plant the map and elements fields for a fake double array without asking JavaScript to inspect the transient map object. A canary read validates the resulting primitive before native addresses are consumed.

The primitive supports:

- compressed object address recovery;
- fake object construction;
- arbitrary reads and writes inside the V8 pointer-compression cage;
- recovery of full native pointers through generated-code and dispatch-table structures;
- writes into selected generated executable memory.

The payload scans live generated code rather than assuming a single JIT allocation address. It matches the stage header, native marker, dispatch entry, and return epilogue before installing each trampoline.

### Activity Popup Policy

The Activity iframe omits popup permission. The renderer-side policy path contains a conditional branch that rejects the auxiliary window and an adjacent branch that controls sandbox-flag propagation. The worker changes those instructions in the stock Discord image, then returns normally from generated code. The process-wide change lets the existing user activation create the auxiliary Discord window.

### Electron IPC Boundary

Discord exposes renderer-facing IPC machinery through its Electron integration. The second-stage native payload resolves the current V8 isolate, Electron's native IPC object, and the invoke implementation. It builds V8 strings and argument arrays directly, then invokes Discord's settings and relaunch channels with attacker-selected arguments.

Persisting the temporary endpoint moves the next stage into Discord's main web-application renderer after relaunch. The three-second gap between the second settings write and the relaunch request is required because the invoke transport completes asynchronously in the browser process.

### Native Windows Launch

The relaunched renderer receives the same engine entry and a different generated payload. The payload walks the stock executable's import table to obtain `CreateProcessW`, `Sleep`, and `ExitProcess`. It prepares `STARTUPINFOW` and `PROCESS_INFORMATION` on a valid Win64 call frame, supplies the absolute Calculator path as `lpApplicationName`, and records success through a distinct renderer exit value.

The ten-second dwell keeps the compromised renderer and its newly created child alive while the packaged Calculator application activates. Windows records the Calculator activation through AppModel-Runtime event `201`.

## One-Shot Coordination

The server issues one lease to one Activity instance. Each server start creates a new generation value, so an Activity page left open from an earlier run cannot consume the next lease. The stage-two document is issued only for the matching instance and token. Once `/native-proof` is requested, further stage-two dispatch is disabled.

This state is visible at:

```text
http://127.0.0.1:3077/protocol/state
http://127.0.0.1:3077/rce/state
```

Useful server milestones include:

```text
RCE_STAGE2_PAGE_ISSUED
RCE_POPUP_PATCH_PAYLOAD_ISSUED
RCE_STAGE1_DISPATCH_OBSERVED
RCE_NATIVE_PAYLOAD_ARMED
RCE_NATIVE_EXIT_SUCCESS
RCE_RECOVERY_RELAUNCH_OBSERVED
```

## Recovery

Before the server starts, `run.ps1` reads the current `%APPDATA%\discord\settings.json` bytes and stores a timestamped backup under `.state/`. It restores those exact bytes after the native success signal and verifies their SHA-256 value. The same restoration runs from the launcher's `finally` block when the server exits, the user interrupts the script, or the proof times out.

The recovery signal is written only after the settings hash matches the backup. The verification page requests Discord's final relaunch only after it has independently observed the native renderer exit value and the server reports that recovery is ready.

## Verified Stock Run

The proof was replayed on July 14, 2026 through a custom Activity mapped to a local HTTPS endpoint. The target was the signed installed stable `Discord.exe` listed above.

| Milestone | Result |
| --- | --- |
| Activity renderer | loaded with `--enable-sandbox` |
| Stage-two CSP adjustment | current response nonce applied to every script |
| Popup policy worker | native patch returned through the V8 epilogue |
| Auxiliary window | created after the policy change |
| Settings persistence | temporary endpoint and `/native-proof` path written |
| Electron relaunch | requested after the persistence delay |
| Native page | loaded by the relaunched stock Discord client |
| Windows API | `CreateProcessW` returned success |
| Calculator activation | AppModel-Runtime event `201` |
| Calculator window | title `Calculator`, visible and active on the desktop |
| Native verification | exact renderer exit sentinel observed |
| Settings recovery | original SHA-256 restored |
| Final state | Discord relaunched on its original endpoint |

The sanitized replay record is stored in `evidence/verified-stock-run.json`.

## Reproducibility Notes

- Use one Activity instance and press the proof button once.
- Close Calculator before starting so the process observation is unambiguous.
- Keep the tunnel and `run.ps1` running until recovery completes.
- Use a tunnel that forwards the root path and all subpaths without a browser warning page.
- Update the Developer Portal root mapping whenever the tunnel hostname changes.
- A fresh server process creates a fresh lease generation after each run.
- The payload's map candidates and native instruction locations are tied to the tested executable hash.

## Fix Direction

- Ship a V8 build containing the relevant engine corrections.
- Validate renderer-origin authority for settings mutation and application relaunch IPC channels.
- Prevent Activity and auxiliary renderers from invoking privileged Discord settings channels.
- Keep the main web-application renderer sandboxed across endpoint changes and relaunches.
- Derive popup and auxiliary-context sandbox flags from immutable browser-process policy.
- Treat persisted web-application endpoints as privileged configuration and reject renderer-selected origins.
- Add regression coverage for Activity CSP nonce rewriting, popup creation from sandboxed frames, renderer-origin IPC authorization, endpoint persistence ordering, and relaunch behavior.

## References

- [Discord: Building Your First Activity](https://docs.discord.com/developers/activities/building-an-activity)
- [Discord: How Activities Work](https://docs.discord.com/developers/activities/how-activities-work)
- [Discord: Activity Local Development and URL Mapping](https://docs.discord.com/developers/activities/development-guides/local-development)
- [Discord: Activity Networking](https://docs.discord.com/developers/activities/development-guides/networking)

## Responsible Use

Use this proof only with an application, Discord account, device, and network endpoint that you own or are explicitly authorized to test.
