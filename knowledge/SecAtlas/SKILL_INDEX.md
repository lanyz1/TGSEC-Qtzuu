# 骡子 · 安全 Skill 索引

> 历史快照生成于 2026-07-23 | 归档 **47** 个 Skill | 13 个分类
>
> ⚠️ 快照中的 skill 多数已不在当前环境；**当前实际加载 126 个**（2026-08-16 实况），见「当前活跃 Skill」。
>
> 📊 **完整能力索引** → [CAPABILITY.md](./CAPABILITY.md)（含技术卡/工具/知识/案例/镜像全貌）

## 当前活跃 Skill（2026-08-16 实况）

真源 `/root/.hermes/skills/security/` 当前含 **126 个**安全 Skill，由两部分组成：
1. **思念派大星全能技能包导入（2026-08）**：按漏洞类型/攻击面组织的 120+ 技能（auth/injection/file/business/api/cloud/mobile/iot/wireless/取证/后渗透等全栈），见系统 `skills_list`。
2. **既有 4 个授权渗透主 Skill**（下述，长期维护）：

| Skill | 描述 | 标签 |
| --- | --- | --- |
| `authorized-web-pentest` | 授权 Web 渗透测试全流程：资产测绘→指纹→扫描→漏洞验证→报告。 | web, pentest, authorized, recon, reporting |
| `web-app-pentest` | 授权 Web 应用渗透测试方法论。 | web, pentest, methodology |
| `web-pentest` | 授权站点 Web 渗透：侦察/指纹/SPA/打码/越权/上传。 | web, pentest, recon, captcha, idor, upload |
| `ruoyi-biz-pentest` | 若依(RuoYi)系定制业务站渗透：管理接口发现/越权读写/打码登录/多 vhost 入口轮换。 | ruoyi, business, idor, captcha, vhost |

以下 47 个为 2026-07-23 归档快照，仅作方法论参考。

## 分类概览

| 分类 | 数量 |
| --- | ---: |
| 编排与治理 | 13 |
| 侦察与信息收集 | 6 |
| Web与API安全 | 4 |
| 投毒作战 | 1 |
| 云与容器安全 | 3 |
| AD与内网渗透 | 2 |
| 二进制与逆向 | 3 |
| 移动安全 | 1 |
| LLM与AI安全 | 3 |
| 取证与事件响应 | 3 |
| 威胁建模 | 1 |
| 凭据与供应链 | 2 |
| 工具与辅助 | 5 |

---

## 编排与治理

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `pentest-orchestrator` | 0.7.1 | 跨测绘→验证→证据→修复→复测的完整授权评估总编排。 | orchestration, pentest, blackbox, evidence, recovery, reporting, retest |
| `engagement-scope` | 0.4.1 | 新主动目标开工前补授权、范围、模式、禁区、预算与停手条件。 | authorization, scope, rules-of-engagement, safety, pentest |
| `finding-verification` | 0.4.1 | 候选漏洞、扫描结果、弱口令等的正反例裁决、修复与复测。 | verification, false-positive, evidence, poc, remediation, retest |
| `evidence-contract` | 1.0.0 | 统一证据合同模板：三源归一，单一真源。 | evidence, contract, verification, finding, standardization |
| `chain-ops` | 0.4.4 | 已有指纹/CVE/403等线索时做组合推断、适用性与失败换路。 | redteam, chain, recon, planning, pentest |
| `ecc-ops` | 0.1.1 | 切换目标、重型扫描前的会话目标锁定与防串。 | session, target-lock, isolation, pentest, ECC |
| `pentagi-lessons` | 0.7.2 | 长任务卡死、重复工具、5/10检查点、中断恢复与多Agent交接。 | planning, supervision, multi-agent, orchestration, evidence, recovery |
| `pentest-cases` | 1.0.0 | 案例库与战术指纹匹配：记录每次攻击的成功/失败路径，新目标自动匹配历史经验推荐攻击链。 | cases, lessons, fingerprint, knowledge-base, pattern-matching |
| `shannon-pipeline` | 1.0.0 | Shannon白盒AI渗透测试方法论——五阶段流水线（Pre-Recon→Recon→Vuln→Exploit→Report）。 | pentest, whitebox, pipeline, methodology, shannon |
| `target-playbooks` | 0.5.3 | 目标类型未知时生成 T01-T17 或自创可证伪攻击角度卡。 | playbook, taxonomy, web, api, pentest |
| `hexstrike-matrix` | 0.4.1 | 用户问用什么 Kali 工具时，按阶段/风险/证据选最小工具集。 | tools, hexstrike, evidence, recovery, recon |
| `acs-playbooks` | 0.3.1 | 仅按指定主题读取 ACS 精选手册；不作为默认渗透入口。 | playbook, ACS, web, api, credentials, pentest, active-directory, aws, kubernetes |
| `lab-learning` | 0.3.2 | 公开 CTF/靶场/Flag 的分析、打靶与复盘；真实目标不用。 | labs, ctf, training, reasoning, web, reverse, pwn, forensics |

## 侦察与信息收集

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `recon-entry-ops` | 0.3.1 | 侦察与信息收集——子域名枚举、DNS查询、端口扫描、httpx探活、Katana爬虫、JS源码分析、目录爆破、指纹识别、Google Dork、资产测绘。 | recon, fofa, subdomain, httpx, katana, git, backup, cloud-storage, proxy |
| `recon-apis` | 0.6.1 | 单次 FOFA/uncover/GoFOFA 查询、探活或 2captcha wrapper。 | FOFA, uncover, GoFOFA, httpx, katana, gau, 2captcha, OSINT, recon, captcha |
| `osint-operations` | 1.0 | Comprehensive OSINT operations: external reconnaissance, domain enumeration, email harvesting, credential leak discovery, threat actor profiling, AI-driven cross-source correlation. | osint, reconnaissance, threat-intelligence, spiderfoot, theharvester, dnstwist, certificate-transparency, paste-monitoring, subdomain-enumeration, red-team |
| `blackbox-artifacts` | 0.2.4 | 匿名公开 JS/source map/APK/字节码/镜像/SBOM 分析。 | blackbox, public-artifacts, source-map, mobile, bytecode, container, evidence |
| `telegram-query-ops` | 1.1.1 | 查询 @/t.me/tg、Bot/频道/Mini App 公共 MTProto 元数据。 | telegram, mtproto, mini-app, bot, channel, public-metadata, query |
| `cve-intelligence` | 1.0.0 | CVE漏洞查询与PoC检索——基于trickest/cve（16万条CVE/1999-2026）。 | cve, vulnerability, intelligence, poc, exploit |

## Web与API安全

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `web-api-ops` | 1.0.0 | Web与API安全测试——SQL注入/XSS/SSRF/SSTI/命令注入/文件包含/IDOR越权/JWT攻击/OAuth/OIDC/CORS/CSRF/GraphQL/反序列化/请求走私/XXE。含完整payload库。 | web, api, jwt, oauth, ssrf, graphql, idor, secrets |
| `web-runtime-security` | 0.1.2 | Next/Nuxt SSR、RSC、缓存、WebSocket/SSE 授权测试。 | nextjs, nuxt, ssr, react-server-components, graphql, websocket, sse, cache-security |
| `high-value-assessment` | 0.3.1 | 凭证/后台/API越权/支付/Web3 六类高价值路径选择。 | authorized-assessment, secrets, admin, api, jwt, oauth, payment, web3, evidence |
| `bug-bounty-methodology` | 1.0.0 | 漏洞赏金方法论——从侦察到报告的完整赏金猎人工作流，含高星项目经验总结。 | bug-bounty, methodology, recon, automation, reporting |

## 投毒作战

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `poison-ops` | 1.0.0 | 六条投毒链路——Web缓存/日志→LFI→RCE/DNS-ARP/CI-CD流水线/Session-Config/数据层。覆盖投递→驻留→触发→验证端到端。 | poisoning, cache-poisoning, log-poisoning, dns-poisoning, arp-spoofing, cicd, supply-chain, red-team, persistence |

## 云与容器安全

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `cloud-security-aws` | 1.0 | Comprehensive AWS cloud security — IAM hardening, S3 auditing, CloudTrail/GuardDuty, offensive testing (Pacu/CloudFox/ScoutSuite), Lambda/serverless, KMS, WAF, EKS. Merged from 90+ Anthropic skills. | aws, cloud-security, iam, s3, pacu, cloudtrail, guardduty, security-hub, containers, kubernetes, eks, lambda |
| `cloud-security-azure-gcp` | 1.0 | Azure与GCP云安全——Azure安全中心/Defender/Entra ID IAM/PIM/Conditional Access/Sentinel SIEM/ROADtools/AADInternals攻击/GCP IAM审计/Organization Policy/Forseti/SCC/VPC防火墙。 | azure, gcp, entra-id, defender-for-cloud, sentinel, roadtools, forseti, organization-policy, iam, conditional-access, cloud-security |
| `container-kubernetes-security` | 1.0.0 | 容器与Kubernetes安全——K8s集群渗透/Docker逃逸/特权容器/镜像漏洞扫描Trivy/Grype/Pod安全策略/NetworkPolicy/RBAC滥用/kubelet攻击/etcd未授权/Wazuh SIEM。 | kubernetes, container, docker, escape, xdr, siem, security |

## AD与内网渗透

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `ad-attack-defense` | 1.0.0 | Active Directory 攻防综合技能：涵盖 LDAP/Kerberos/SMB/BloodHound/AD CS 的侦察、攻击路径分析、凭据提取、横向移动、权限提升和持久化技术，以及对应的检测和防御策略。 | active-directory, kerberos, ldap, ad-cs, bloodhound, kerberoasting, dcsync, golden-ticket, pass-the-ticket, ntlm-relay, lateral-movement, detection, defense |
| `ad-internal-ops` | 0.1.1 | Active Directory域渗透——LDAP/Kerberos/SMB/BloodHound/AD CS攻击路径分析、凭据提取、横向移动、权限提升、域控攻击。 | active-directory, ldap, kerberos, smb, bloodhound, adcs |

## 二进制与逆向

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `binary-exploitation` | 1.1.0 | 二进制漏洞利用与逆向工程——PWN/栈溢出/堆溢出/格式化字符串/UAF/ROP链/Shellcode/GDB调试/pwntools/checksec/ROPgadget/反汇编objdump/IDA/Ghidra。 | pwn, binary, reverse, heap, elf, disassembly, exploitation |
| `reverse-pcap-ops` | 0.1.1 | native二进制、Frida、PCAP、私有协议、WebSocket加密分析。 | reverse, binary, pcap, protocol, frida, mitm, exploitation |
| `malware-analysis` | 1.0.0 | 恶意软件分析——静态分析/动态分析/逆向工程/IOC提取/YARA规则/沙箱/反混淆/持久化调查/Ghidra/PE分析/反汇编。 | malware-analysis, reverse-engineering, static-analysis, dynamic-analysis, yara, ioc-extraction, sandbox, deobfuscation, persistence, ghidra |

## 移动安全

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `mobile-security-testing` | 1.0.0 | 移动应用安全测试——iOS/Android APP渗透测试、APK/IPA逆向分析、Frida/Objection动态Hook、SSL证书固定绕过、BurpSuite抓包、MobSF静态扫描、数据存储安全、IPC漏洞、OWASP MASVS。 | mobile-security, android, ios, frida, objection, burp-suite, ssl-pinning, keychain, reverse-engineering, owasp-mastg, static-analysis, dynamic-analysis |

## LLM与AI安全

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `llm-jailbreak-arsenal` | 1.0.0 | LLM大模型越狱与提示注入攻击——5梯队25+战法（角色扮演/编码绕过/多语言/思维链劫持/系统提示提取）。含ChatGPT/Claude/Gemini/Grok破甲。 | jailbreak, prompt-injection, llm-security, red-team, ai-safety, bypass |
| `agent-skill-security` | 1.0.0 | AI Agent Skill 安全审计——基于 NVIDIA SkillSpector 的 68 项检测规则，覆盖 17 类漏洞（提示注入/数据外泄/提权/供应链等）。 | ai-security, skill-audit, supply-chain, prompt-injection, agent-safety |
| `agent-self-check` | 0.1.1 | 审计 Agent 密钥、权限、Hook/工具注入、供应链与配置安全。 | self-check, security, audit, llm, agent, secrets, permissions, hooks, supply-chain |

## 取证与事件响应

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `forensic-analysis` | 1.0.0 | 数字取证与事件响应DFIR——内存取证/Volatility/磁盘取证/Autopsy/网络取证/Wireshark/时间线分析Plaso/端点取证KAPE/证据收集/数据恢复/浏览器取证/邮件取证/移动取证/云取证。 | forensics, dfir, memory-forensics, disk-forensics, network-forensics, cloud-forensics, timeline, evidence-collection, file-recovery, volatility, plaso, kape, wireshark, autopsy |
| `incident-response` | 1.0.0 | 事件响应与应急处理——安全事件分类分级/遏制/根除/恢复/NIST 800-61/SANS PICERL/SOC运营/钓鱼事件/勒索软件/云安全事件/数据泄露处置。 | incident-response, triage, containment, eradication, recovery, nist-800-61, sans-picerl, soc, phishing, ransomware, cloud-ir, playbook, breach |
| `threat-hunting` | 1.0 | 威胁狩猎——主动假设驱动的威胁搜索，覆盖SIEM/EDR(Elastic/Splunk)、YARA/Sigma规则、LOLBin/持久化/C2/Webshell检测、APT TTP分析(MITRE ATT&CK)、MISP威胁情报、基础设施追踪。 | threat-hunting, siem, edr, yara, sigma, mitre-attack, lolbins, misp, detection-engineering |

## 威胁建模

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `threat-modeling` | 0.2.1 | 威胁建模——按资产/角色/数据流/信任边界做STRIDE威胁建模与攻击树分析。 | threat-modeling, stride, attack-tree, trust-boundary, planning |

## 凭据与供应链

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `cred-hunt` | 0.3.2 | 公开 Git/JS/备份/云对象的凭证暴露取证与误报裁决。 | credentials, secrets, git, javascript, backup, cloud, verification |
| `skill-supply-chain` | 0.1.2 | 安装前审计外部 Agent Skill 来源/许可/提交/提示注入/脚本。 | skill-security, supply-chain, prompt-injection, provenance, github |

## 工具与辅助

| Skill | 版本 | 描述 | 标签 |
| --- | --- | --- | --- |
| `temp-email` | 1.0.0 | 临时邮箱/一次性邮箱——GuerrillaMail自动创建/检查/等待邮件，用于注册验证、密码重置等场景。 | temp-email, disposable, guerrilla, registration, verification |
| `proxy-pool` | 0.3.1 | 地区限制、固定出口、会话粘性与代理故障切换用 mule-proxy。 | proxy, socks5, http-proxy, egress, authorized-testing |
| `telegram-platform-security` | 0.1.7 | Telegram平台安全测试——Webhook注入/Login Widget安全/Mini App安全/MTProto协议/机器人API安全/Bot Token泄露/客户端安全。 | telegram, bot-api, webhook, oidc, mini-app, mtproto, client-security |
| `red-team-arsenal` | 1.0.0 | 红队工具武器库——按杀伤链阶段（侦察→初始访问→执行→持久化→提权→防御规避→凭据访问→横向移动→C2→数据外泄）编排的工具清单。含Sliver/Havoc/Cobalt Strike/Impacket/Mimikatz/BloodHound/CrackMapExec。 | red-team, arsenal, kill-chain, tools, adversary-simulation |
| `gambling-platform-attack-surface` | 0.1.0 | 博彩/灰产Telegram Mini App平台标准攻击面测绘与利用流程——汇率操纵、支付网关劫持、配置读写。 | gambling, telegram-mini-app, business-logic, ruoyi, config-manipulation |

---

> **维护说明**：上方「当前活跃 Skill」与 `/root/.hermes/skills/security/` 同步；47 个历史快照为 2026-07-23 归档，保留作方法论参考，不再随 cron 同步覆盖。
