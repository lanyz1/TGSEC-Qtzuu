# dotnet-memshell 要点（自 README 提炼）

- 定位：三个插入位置互不相同的 .NET 内存马，单文件 .cs 载荷、一次反序列化武装；不新增端口、不改 web.config、不落地文件；对无标记流量零扰动。
- #1 HttpModuleShell：`HttpApplication` 模块事件管线（含 HttpApplicationFactory._freeList 池广播）；触发为请求头 `MSH-Cmd: <cmd>`。
- #2 WsTakeoverShell：HTTP→WebSocket 升级点连接接管；子协议 `msh` 握手 → AcceptWebSocketRequest(Duplex) 全双工收发命令。
- #3 RemotingUriShell：既有 Remoting 通道的 AppDomain URI 表注册 well-known 服务（`RegisterWellKnownServiceType(E.Svc, "msh", Singleton)`）；业务 URI 并存。
- 实测（Windows 11 + IIS 10 集成管线真机）：三马均验证通过；集成管线 AddEvent 只有 RequestNotification.AcquireRequestState 被派发（BeginRequest/LogRequest/UpdateRequestCache 实测不触发）。
- WS 接管必须抑制页面输出：处理函数置 `Response.SuppressContent=true` + `StatusCode=101`，否则连接被收尾（WebSocketException 0x80070040）；`RemapHandler` 该阶段不可用。
- 投递：前提为目标 machineKey 已知/泄露；`ysoserial.exe -p ViewState -g XamlAssemblyLoadFromFile`（ActivitySurrogateSelectorFromFile 不触发；TypeConfuseDelegate 走进程外）；ViewState 插件 Uri.EscapeDataString 约 32K 上限（大程序集需 gzip）。
- 本地测试：`tools/build.ps1` + `tools/Loader.aspx`（实验用加载器，勿部署生产）。
- 检测：module 容器步骤清单/`_execSteps` 长度比对、AppDomain.GetAssemblies() 中 Location 为空的程序集、陌生 WS 子协议、RemotingConfiguration 未声明 URI、machineKey 视同高危凭据。

@TGSEC社区 · @TGSEC-Qtzuu 整理
