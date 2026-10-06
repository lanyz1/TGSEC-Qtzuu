# crackws — WebSocket ⇄ HTTP 桥要点

- 核心能力：把 WebSocket 桥接成本地 HTTP。`crackws bridge --listen 127.0.0.1:8899` 做「HTTP 请求 ⇄ WS 消息」映射、会话池、模板注入、多帧响应聚合，HTTP 扫描器因此可直接对纯 WS 协议作业。
- 典型链：`sqlmap -u 'http://127.0.0.1:8899/msg/login?username=admin&password=1' -p password --batch --dump -T users` —— 复用 sqlmap 的布尔/时间/UNION 完整检测引擎打 WebSocket。
- 零配置模式：`--target` 直连自动套用内置 `generic`（内置 profile 只指向回环地址）；`POST /raw`（或 `?data=`）把 HTTP 请求体**原样**灌进 WebSocket，无参数映射也能打陌生协议（sqlmap 配 `--data` 即可）。
- profile（YAML）描述「消息长什么样、哪些位置是注入点、回复怎么读」：`requests[].template` + `{{占位符}}` + `params`；`target.headers/subprotocols`；`response.idle_ms` 静默窗口（一次请求回多条消息）、`select/accept_types/match_path/extract` 提取回执；`setup[]` 每条新连接先登录、`extract[].name`→`{{token}}` 串后续消息。
- 已用两种截然不同的协议验证：JSON 信封（`examples/vuln-ws-server.py`，dump users）与**纯文本无 type 判别符**的位置参数协议 `LOGIN <user> <pass>`（`examples/alt-ws-server.py`，dump accounts）；无 type 协议上 `recon` 正确报告「0 个可区分 type」。
- `target.settle_ms` 为「连上即推送 banner」场景引入：不排空服务端主动推送的首条消息就会污染第一个响应（该项目由此修掉两个 recon 真实缺陷）。
- `--fresh-session`：应对「一条连接只允许登录一次」的目标。
- 自身能力面：probe / recon（协议逆向、类型与字段枚举）、注入检测（SQL / NoSQL / 命令注入 / SSTI / XSS / JSON 注入 / 认证绕过）、字典 fuzz 与聚类、录制回放、报告导出、交互式 REPL。
- 构建：`make build / release / test / test-live`；仅编译期依赖 `gopkg.in/yaml.v3`；发布构建 CGO_ENABLED=0 静态链接 + `-trimpath -ldflags "-s -w"`，7 平台产物 + SHA256SUMS.txt。
- `scripts/release.sh` 按可用内存反推编译并行度（瓶颈是内存而非 CPU）：`budget=MemAvailable-768MiB`、`jobs=clamp(budget/512MiB,1,min(cpu,4))`、GOMAXPROCS=jobs、GOMEMLIMIT=budget/jobs、`nice -n 19 ionice -c 3`；各平台串行编译。
- `docs/writing-profiles.md`（已复制）：profile 字段 ↔ WebSocket 概念完整映射教程，面向新手到进阶；`crackws profile export examples/vuln-sqli.yaml` 可导出全文。
- 合规：仅用于授权安全测试、CTF 与教学；`examples/` 下两个靶场为故意留洞的本地隔离测试夹具（MIT）。

@TGSEC社区 · @TGSEC-Qtzuu 整理
