# 密探 mitan v2.0.5 — 关键事实（源: Readme / 密探MCP+AI / 如何下载安装）

- v2.0 为 Rust + Tauri 重写（v1.0 是 JavaFX）；支持 Windows 11+ / macOS / Linux（AppImage、deb）；macOS 包无苹果签名（需 `spctl --master-disable` + `xattr -d com.apple.quarantine`），Windows 依赖 WebView2
- 空间测绘聚合 8 个引擎：FOFA、Hunter、Quake、ZoomEye、DayDayMap、Censys、Shodan、零零信安；内置语法转换算法把常见搜索语法自动适配各引擎，免手工改写
- 断点续扫覆盖耗时模块：指纹识别、JsFinder、目录扫描、子域名、端口扫描、弱口令、POC
- MCP 服务：应用内「启动MCP服务」→ 复制配置 → 粘贴进 AI 客户端（Workbuddy：专家/技能/连接器→自定义连接器→配置MCP；Trae：MCP→+添加→手动配置）；局域网使用时对命令执行、文件删除等危险操作需确认
- 弱口令模块覆盖 mysql / sqlserver / oracle / mongodb / postgresql / redis / 达梦 / ssh / ftp / socks5；POC 扫描前可按指纹或关键词检索 POC
- heapdump 解析（数据库连接信息、SQL、IP、JWT token）；微信小程序多版本解包并提取 API/URL/aksk，接口可一键发起未授权检测
- 典型 AI+MCP 链路：主体查询 → 资产测绘 → 指纹识别/JsFinder/目录扫描 → 弱口令 → POC 验证，交互结果统一存入项目历史记录按项目隔离

@TGSEC社区 · @TGSEC-Qtzuu 整理
