# 渗透测试九阶段工具速查

> 来源: TG-SEC社区《新手渗透入门指南》工具清单
> 蒸馏日期: 2026-07-23
> 用途: 工具分类索引与黑骡能力缺口对照

---

## 九阶段框架

| 阶段 | 核心目标 | TG-SEC 代表工具 | 黑骡现有覆盖 |
|------|---------|----------------|-------------|
| 01 信息收集 | 外网资产发现 | goby, oneforall, dirsearch, enscan | `recon-entry-ops` + `recon-apis` |
| 02 漏洞扫描 | 中间件与漏洞识别 | xray, fscan, supersql, Seay-Svn | `nuclei` + `chain-ops` 指纹 |
| 03 漏洞利用 | GetShell/权限获取 | Burp, 蚁剑, 冰蝎, 哥斯拉, MYExploit | `web-api-ops` + `binary-exploitation` |
| 04 免杀绕过 | 对抗杀软/WAF | foxbypass, GByPass, veo, cf | ❌ 缺口: `evasion-techniques` |
| 05 隧道代理 | 内网穿透 | frp, Neo-reGeorg, suo5, clash | `proxy-pool` |
| 06 弱口令 | 账号爆破 | dogs_v2.1, wy876, weekpasswd | `cred-hunt` |
| 07 本地提权 | 低权→高权 | tiquan, yanni, PotatoTool, heapdump | `binary-exploitation` / `poison-ops` P6 |
| 08 横向后渗 | 横向+持久化 | mimikatz, Cobalt Strike, ladon, yongheng | `ad-internal-ops` + `red-team-arsenal` |
| 09 辅助资源 | 加解密/工具箱 | decrypt, jd-gui, auxtools | `reverse-pcap-ops` |

## 黑骡工具缺口（对照后发现的）

### 需补装

| 工具 | 用途 | 阶段 | 优先级 |
|------|------|------|--------|
| `suo5` | HTTP 全双工隧道（Neo-reGeorg 继任者） | 05 隧道 | 高 |
| `veo` | 轻量化内存远控（无文件执行） | 04 免杀 | 中 |

### 已有等价物

| TG-SEC 工具 | 黑骡等价物 | 说明 |
|------------|-----------|------|
| goby/FOFAviewer | `recon-apis` (FOFA/uncover) | API 驱动，更可脚本化 |
| xray/afrog | `nuclei` + templates | 模板生态更丰富 |
| Burp Suite | `mitmproxy` + `curl` + `jwt_tool` | 已装，命令行可编排 |
| 蚁剑/冰蝎/哥斯拉 | `web-api-ops` 含 payload 库 | 方法论驱动，工具可下载 |
| frp | `proxy-pool` | 已有代理能力 |
| mimikatz | `impacket` (secretsdump) | 已装，覆盖 Windows 凭据 |
| jd-gui | `binary-exploitation` 覆盖 Java 反编译 | 有其他反编译路径 |

## 免杀缺口详细

`evasion-techniques` Skill 仍未创建。TG-SEC 清单中的映射：

| 免杀子类 | TG-SEC 工具 | 需求描述 |
|---------|------------|---------|
| EXE 免杀 | adyu, aniya, foxbypass | Windows PE 免杀加载器 |
| WebShell 流量免杀 | XG_NTAL_V2 | Webshell 流量混淆 |
| WAF 绕过 | GByPass.jar, cf | Java 编码绕过 + 请求头伪造 |
| 内存无文件执行 | veo | 无落地文件的远控 |

> 这部分需要在 `evasion-techniques` Skill 中统一补全。

## 来源

- 文档: TG-SEC社区《新手渗透入门指南-工具清单》v1.0
- 许可: 公开学习资料，仅供授权安全研究使用
