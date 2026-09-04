# Windows 后渗凭证采集面（WinDump 型）

非注入、HTML 报告导向的客户端凭证/主机信息采集清单。

## 采集面
- 浏览器 Chromium 系密码/Cookie
- RDP / PuTTY / WinSCP / FileZilla / MobaXterm / SecureCRT / FinalShell / Xmanager
- Navicat / DBeaver / OpenVPN / TightVNC / UltraVNC
- 系统信息 / 进程 / 网络（DNSCache、路由、网卡、WIFI、Netstat）

## 用法
1. 授权后渗环境编译或对照 `Cred/`、`Network/`、`SystemInfo.cs` 等模块做检查清单
2. 输出 HTML 报告归档到证据目录
3. 与 `PEN-GetHash.md` / `windows-lateral-movement` 交叉使用

注意：仅用于授权评估；不要把采集器当免杀产品硬塞。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
