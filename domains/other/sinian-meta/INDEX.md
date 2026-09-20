# Pentest Skills Index

这个索引文件用于快速浏览相关 `pentest_skills`。
参考来源：hack-skills，仅作为辅助技能。

> 图例：(router) = 路由入口；(playbook) = 深度攻击手册；(agent) = 多代理编排器；(legacy) = 早期 `-testing` 版本，已被同名 playbook 取代但保留备用；(NEW) = 新增技能；(STRENGTHENED) = 深度强化；(2026) = 已融入2026最新技术。

## Recon & Methodology

- [recon-and-methodology](./recon-and-methodology/SKILL.md) - 结构化测试方法论、授权、侦察编排、证据处理 (NEW, STRENGTHENED, 2026)
- [recon-for-sec](./recon-for-sec/SKILL.md) - 通用目标侦察：子域/DNS/端口/指纹/vhost/云存储/被动情报 (NEW, 2026)
- [insecure-source-code-management](./insecure-source-code-management/SKILL.md) - `.git`/`.env`/备份泄露：.git目录利用链/.env扫描/CI-CD密钥泄露/Dockerfile密钥提取/备份文件发现 (STRENGTHENED, 2026)
- [subdomain-takeover](./subdomain-takeover/SKILL.md) - 子域接管 (STRENGTHENED, 2026)

## API / Auth

- [api-sec](./api-sec/SKILL.md) - API 安全总路由 (router, 2026)
- [api-recon-and-docs](./api-recon-and-docs/SKILL.md) - API 发现与文档探测 (STRENGTHENED, 2026)
- [api-authorization-and-bola](./api-authorization-and-bola/SKILL.md) - API 授权与 BOLA (STRENGTHENED, 2026)
- [api-auth-and-jwt-abuse](./api-auth-and-jwt-abuse/SKILL.md) - API 认证、JWT/Token 滥用、速率限制绕过 (STRENGTHENED, 2026)
- [graphql-and-hidden-parameters](./graphql-and-hidden-parameters/SKILL.md) - GraphQL 内省、批量、隐藏字段、Federation子图注入、APQ哈希预测 (STRENGTHENED, 2026)
- [auth-sec](./auth-sec/SKILL.md) - 认证安全路由 (router, 2026)
- [authbypass-authentication-flaws](./authbypass-authentication-flaws/SKILL.md) - 认证绕过：默认凭证暴破/SQL注入登录绕过/JWT none算法/AI驱动自适应认证绕过 (STRENGTHENED, 2026)
- [jwt-oauth-token-attacks](./jwt-oauth-token-attacks/SKILL.md) - JWT / Token 密码学攻击与 OAuth 流程攻击 (STRENGTHENED, 2026)
- [oauth-oidc-misconfiguration](./oauth-oidc-misconfiguration/SKILL.md) - OAuth / OIDC 配置缺陷：隐式流程token窃取/授权码拦截/OIDC算法混淆/2026 MCP OAuth (STRENGTHENED, 2026)
- [saml-sso-assertion-attacks](./saml-sso-assertion-attacks/SKILL.md) - SAML / SSO 断言攻击：XSW签名包装/X.509证书混淆/重放攻击/2026云SSO联邦 (STRENGTHENED, 2026)
- [401-403-bypass-techniques](./401-403-bypass-techniques/SKILL.md) - 401/403 绕过：路径型绕过/HTTP方法覆盖/Host头操纵/2026 API网关(Kong/APISIX/Traefik) (STRENGTHENED, 2026)
- [idor-broken-object-authorization](./idor-broken-object-authorization/SKILL.md) - IDOR：REST API枚举/UUID预测/GraphQL嵌套IDOR/2026 AI模型API授权 (STRENGTHENED, 2026)

## Injection / Server-Side

- [injection-checking](./injection-checking/SKILL.md) - 注入类测试入口 (router, 2026)
- [ai-llm-attack-surface](./ai-llm-attack-surface/SKILL.md) - AI/LLM/MCP 攻击面：MCP 注入、工具投毒、Prompt→RCE 链、ML pickle RCE、LLM SSTI、OWASP LLM Top 10 2025、A2A协议攻击、跨协议信任继承、Vector DB后门、模型合并供应链 (STRENGTHENED, 2026)
- [sqli-sql-injection](./sqli-sql-injection/SKILL.md) - SQL 注入：WAF绕过认证绕过/DNS外带盲注/INTO OUTFILE RCE/NoSQL注入/GraphQL批量SQLi (STRENGTHENED, 2026)
- [cmdi-command-injection](./cmdi-command-injection/SKILL.md) - 命令注入：OOB DNS外带/exiftool CVE/IFS花括号通配符绕过/CI-CD管道注入/Windows PowerShell (STRENGTHENED, 2026)
- [ssti-server-side-template-injection](./ssti-server-side-template-injection/SKILL.md) - SSTI：LangChain/LangGraph模板注入、AI管道盲注、多模态模板注入 (STRENGTHENED, 2026)
- [xxe-xml-external-entity](./xxe-xml-external-entity/SKILL.md) - XXE：SSRF链/盲XXE OOB外带/PHP expect RCE/SOAP参数实体/2026 AI配置文件XXE (STRENGTHENED, 2026)
- [jndi-injection](./jndi-injection/SKILL.md) - JNDI 注入：Log4Shell全链/Spring4Shell/Redis Hessian/2026 Quarkus Micronaut/WAF绕过 (STRENGTHENED, 2026)
- [expression-language-injection](./expression-language-injection/SKILL.md) - EL 注入：Spring SpEL RCE/JBoss JMX/Tomcat JSP/2026 Quarkus Qute/反射API绕过 (STRENGTHENED, 2026)
- [xslt-injection](./xslt-injection/SKILL.md) - XSLT 注入：.NET 9 XsltSettings绕过(TrustedXslt降级/msxsl:script Roslyn编译RCE)/XSLT+XXE链实战(document() SSRF云元数据/XInclude)/云XSLT服务注入(AWS API Gateway映射模板/Azure Logic Apps)/2026处理器漏洞(libxslt RCE/Saxon-EE反序列化/Xalan script) (STRENGTHENED, 2026)
- [csv-formula-injection](./csv-formula-injection/SKILL.md) - CSV / 表格公式注入：HYPERLINK外带/DDE RCE/SaaS导出注入/PowerShell执行/2026 AI数据管道 (NEW, STRENGTHENED, 2026)
- [supply-chain-attacks](./supply-chain-attacks/SKILL.md) - 软件供应链攻击：依赖混淆/CI-CD投毒/容器注册表/MCP供应链/AI模型投毒/OWASP A03:2025 (NEW, 2026)
- [deserialization-insecure](./deserialization-insecure/SKILL.md) - 不安全反序列化：Java CC gadget链/Python pickle RCE/.NET ViewState/2026 AI模型反序列化(PyTorch/HuggingFace/ONNX) (STRENGTHENED, 2026)
- [ssrf-server-side-request-forgery](./ssrf-server-side-request-forgery/SKILL.md) - SSRF (2026)
- [dns-rebinding-attacks](./dns-rebinding-attacks/SKILL.md) - DNS Rebinding (2026)
- [dns-pollution-hijacking](./dns-pollution-hijacking/SKILL.md) - DNS污染与DNS劫持：协议层竞速注入/Kaminsky缓存投毒/路由器ISP劫持/DoH-DoT-DNSSEC对抗 (NEW, 2026)
- [isp-traffic-hijacking](./isp-traffic-hijacking/SKILL.md) - 运营商流量劫持：DNS/HTTP/HTTPS/BGP/DPI多层级劫持技术、广告注入、SSL剥离、证书替换、路由操纵、5G信令劫持 (NEW, 2026)

## Database Security

- [database-security](./database-security/SKILL.md) - 数据库安全测试全栈：SQL注入/NoSQL注入/数据库配置审计/权限提升/横向移动/存储过程后门/云数据库安全/Redis/MongoDB/Elasticsearch/PostgreSQL/MySQL/Oracle/MSSQL/2026最新数据库攻击/向量数据库/图数据库/时序数据库 (NEW, 2026)

## Client / Browser / HTTP

- [xss-cross-site-scripting](./xss-cross-site-scripting/SKILL.md) - XSS：DOM XSS账户接管/CSP nonce DOM clobbering绕过/mXSS DOMPurify绕过/XSS→SSRF/2026 AI聊天XSS (STRENGTHENED, 2026)
- [clickjacking](./clickjacking/SKILL.md) - 点击劫持：2FA启用覆盖/拖放数据外传/X-Frame-Options CVE绕过/双重框架CSRF/2026 WebAuthn劫持 (STRENGTHENED, 2026)
- [cors-cross-origin-misconfiguration](./cors-cross-origin-misconfiguration/SKILL.md) - CORS：null origin窃取/通配符+凭据/正则绕过/内网SSRF/2026 Serverless CORS (STRENGTHENED, 2026)
- [csrf-cross-site-request-forgery](./csrf-cross-site-request-forgery/SKILL.md) - CSRF：密码修改SameSite绕过/JSON API CSRF/CORS跨域POST/登录CSRF/2026 GraphQL CSRF (STRENGTHENED, 2026)
- [csp-bypass-advanced](./csp-bypass-advanced/SKILL.md) - CSP 绕过：JSONP端点/Angular模板注入/Script Gadgets/img-src外传/2026 Import Maps+ES Modules (STRENGTHENED, 2026)
- [websocket-security](./websocket-security/SKILL.md) - WebSocket 安全：CSWSH跨站劫持/盲注SQLi/认证绕过/socket.io RCE/2026 AI流式WebSocket (STRENGTHENED, 2026)
- [request-smuggling](./request-smuggling/SKILL.md) - 请求走私：HTTP/2降级走私/TE.CL+CL.TE/Turbo Intruder/AWS ALB+Nginx/缓存投毒 (STRENGTHENED, 2026)
- [http-host-header-attacks](./http-host-header-attacks/SKILL.md) - Host Header 攻击 (2026)
- [http-parameter-pollution](./http-parameter-pollution/SKILL.md) - HPP：API网关HPP/JSON参数污染/GraphQL HPP/OAuth参数污染/WAF绕过HPP (STRENGTHENED, 2026)
- [http2-specific-attacks](./http2-specific-attacks/SKILL.md) - HTTP/2 攻击 (2026)
- [web-cache-deception](./web-cache-deception/SKILL.md) - Web Cache 欺骗/投毒：Pingora缓存键碰撞、边缘计算投毒、API网关缓存绕过、AI驱动缓存操纵 (STRENGTHENED, 2026)
- [waf-bypass-techniques](./waf-bypass-techniques/SKILL.md) - WAF 绕过：WAF指纹识别/Cloudflare专项/AWS+Azure WAF/SQLi编码绕过/XSS变异绕过/IP轮换限流绕过/HTTP/2降级 (STRENGTHENED, 2026)
- [dangling-markup-injection](./dangling-markup-injection/SKILL.md) - Dangling Markup (2026)
- [crlf-injection](./crlf-injection/SKILL.md) - CRLF 注入：HTTP响应分割/会话固定/缓存中毒/2026 HTTP/2 HPACK头部操纵 (STRENGTHENED, 2026)
- [email-header-injection](./email-header-injection/SKILL.md) - 邮件头注入：垃圾邮件中继/BCC外传/发件人伪造钓鱼/2026 AI通知系统注入 (STRENGTHENED, 2026)

## Files / Access / Exposure

- [file-access-vuln](./file-access-vuln/SKILL.md) - 文件访问问题：S3桶全量窃取/Azure Blob匿名访问/GCS枚举/2026 AI管道模型制品泄露 (router, STRENGTHENED, 2026)
- [path-traversal-lfi](./path-traversal-lfi/SKILL.md) - 路径遍历/LFI：php://filter chain RCE/Spring CVE-2024-22243/日志投毒RCE/Zip Slip/2026云存储前缀遍历 (STRENGTHENED, 2026)
- [file-upload-testing](./file-upload-testing/SKILL.md) - 文件上传：Content-Type操纵/.htaccess绕过/竞争条件/GIF+PHP Polyglot/2026 AI模型文件Pickle RCE (STRENGTHENED, 2026)
- [webshell-evasion](./webshell-evasion/SKILL.md) - WebShell免杀与管理：静态免杀(变量混淆/字符串加密/注释混淆/代码压缩)/动态免杀(行为伪装/UA白名单/Referer校验)/多语言WebShell(PHP/ASP/ASPX/JSP/Java/Node.js/Python)/2026最新免杀(AI变异/大模型混淆/AST变形)/管理工具(蚁剑/冰蝎/哥斯拉免杀配置)/内存马(Java Filter/Listener/Servlet/Godzilla/PHP/ASP.NET)/检测绕过(阿里云/腾讯云/Cloudflare/Imperva专项)/一过性WebShell(无文件/日志型/注册表)/WAF穿透(分块传输/压缩/TLS指纹/HTTP2多路复用)/实战全链路(文件上传绕过+免杀+权限维持) (NEW, 2026)
- [open-redirect](./open-redirect/SKILL.md) - 开放重定向：OAuth token窃取/反斜杠绕过/javascript: XSS/SSO SAML RelayState/2026 AI回调URL (STRENGTHENED, 2026)

## Logic / Workflow

- [business-logic-vuln](./business-logic-vuln/SKILL.md) - 业务逻辑漏洞入口 (router, 2026)
- [business-logic-vulnerabilities](./business-logic-vulnerabilities/SKILL.md) - 业务逻辑漏洞：电商价格篡改/积分负值滥用/工作流验证跳过/2026 AI内容审核绕过 (STRENGTHENED, 2026)
- [race-condition](./race-condition/SKILL.md) - 竞态条件：优惠券并发重放/余额双花/邮件验证码绕限流/2026 AI API限流绕过 (STRENGTHENED, 2026)
- [type-juggling](./type-juggling/SKILL.md) - PHP 类型混淆：JSON类型混淆(JSON5/JSONC解析器差异)/Node.js-Python-Go比较陷阱/AI API类型污染(LLM参数混淆/JSON Schema绕过)/2026 CVE集群(PHP 8.4/Python 3.13/Temporal API) (STRENGTHENED, 2026)
- [prototype-pollution](./prototype-pollution/SKILL.md) - 原型污染：Express+EJS RCE/__proto__ XSS/lodash.merge污染/2026 LangChain/AutoGen AI SDK污染 (STRENGTHENED, 2026)
- [prototype-pollution-advanced](./prototype-pollution-advanced/SKILL.md) - 高级原型污染 (2026)
- [ghost-bits-cast-attack](./ghost-bits-cast-attack/SKILL.md) - Ghost Bits / 类型转换攻击：受影响组件扩展(Tomcat/Spring/Netty/Rust actix-web/Go chi等)/自动化检测脚本(Python+Semgrep)/联动PoC(原型污染→Ghost Bits→RCE链)/语言运行时修复进展(V8/JSCore/SpiderMonkey/Python/PHP/Ruby/Go/Rust) (NEW, STRENGTHENED, 2026)

## Agents (Multi-Agent Orchestrators)

- [api-agent](./api-agent/SKILL.md) - API 安全编排 (2026)
- [auth-agent](./auth-agent/SKILL.md) - 认证安全编排 (2026)
- [injection-agent](./injection-agent/SKILL.md) - 注入类编排 (2026)
- [business-agent](./business-agent/SKILL.md) - 业务逻辑编排 (2026)
- [file-agent](./file-agent/SKILL.md) - 文件访问编排 (2026)
- [misc-agent](./misc-agent/SKILL.md) - 杂项编排 (2026)
- [poc-agent](./poc-agent/SKILL.md) - PoC 生成编排 (2026)
- [vuln-analysis-agent](./vuln-analysis-agent/SKILL.md) - 漏洞分析编排 (2026)

## Legacy Testing Skills (早期版本，同名 playbook 已取代)

- [api-security-testing](./api-security-testing/SKILL.md) - API 安全测试 (legacy)
- [business-logic-testing](./business-logic-testing/SKILL.md) - 业务逻辑测试 (legacy)
- [command-injection-testing](./command-injection-testing/SKILL.md) - 命令注入测试 (legacy)
- [csrf-testing](./csrf-testing/SKILL.md) - CSRF 测试 (legacy)
- [deserialization-testing](./deserialization-testing/SKILL.md) - 反序列化测试 (legacy)
- [idor-testing](./idor-testing/SKILL.md) - IDOR 测试 (legacy)
- [ldap-injection-testing](./ldap-injection-testing/SKILL.md) - LDAP 注入测试：LDAP盲注自动化/AD CS ESC1-ESC8滥用链/NoSQL交叉注入/2026 CVE集群/云目录服务注入/AI辅助LDAP注入 (STRENGTHENED, 2026)
- [sql-injection-testing](./sql-injection-testing/SKILL.md) - SQL 注入测试 (legacy)
- [ssrf-testing](./ssrf-testing/SKILL.md) - SSRF 测试 (legacy)
- [xpath-injection-testing](./xpath-injection-testing/SKILL.md) - XPath 注入测试：XPath盲注自动化/XPath+XXE链式攻击/XSLT联动注入(代码执行/SSRF)/NoSQL图查询注入/2026 CVE集群/AI辅助XPath注入 (STRENGTHENED, 2026)
- [xss-testing](./xss-testing/SKILL.md) - XSS 测试 (legacy)
- [xxe-testing](./xxe-testing/SKILL.md) - XXE 测试 (legacy)

## Internal Network / Active Directory

- [linux-privilege-escalation](./linux-privilege-escalation/SKILL.md) - Linux提权全栈：SUID/SGID滥用/Capability/Cron劫持/内核CVE(2021-4034/2022-0847/2023-0386/2024-21626)/容器逃逸(Docker Socket/privileged/runc)/eBPF提权(JIT喷射/verifier绕过)/Sudo绕过/通配符注入/共享库劫持/NFS/Systemd/2026最新CVE/自动化工具链(LinPEAS/pspy/traitor) (NEW, 2026)
- [active-directory-lateral-movement](./active-directory-lateral-movement/SKILL.md) - AD内网渗透与横向移动：BloodHound侦察/Kerberos攻击(AS-REP/Kerberoasting/票据伪造)/NTLM中继/凭据传递/ACL滥用/ADCS证书攻击 (NEW, 2026)
- [password-attacks-credential-access](./password-attacks-credential-access/SKILL.md) - 密码攻击与凭据获取全栈：在线暴力破解(Hydra/Medusa/Ncrack多协议/HTTP2+QUIC)/离线Hash破解(Hashcat 2026规则引擎/John/分布式集群)/密码喷射(域+O365/AzureAD/MFA绕过)/Windows凭据(SAM/LSASS/DPAPI/浏览器密码/LaZagne)/Linux凭据(Shadow/SSH密钥/配置文件/历史文件)/Kerberos攻击(Roasting/Golden-Silver-Diamond-Sapphire Ticket/委派/PAC签名绕过)/NTLM攻击(中继/Responder/Inveigh/ADCS ESC1-8/强制认证)/凭据传递(PtH/PtT/Overpass)/2026最新技术(AI密码猜测/量子计算/Passwordless绕过/FIDO2攻击)/无线网络(WPA2/WPA3/PMKID/Evil Twin)/凭据存储(密码管理器/云SecretsManager/GitHub泄露)/自动化工具链(CrackMapExec/NetExec/BloodHound/PlumHound)/实战完整攻击链(密码喷射→Kerberoasting→PtH→DCSync→DC控制) (NEW, 2026)
- [windows-privilege-escalation](./windows-privilege-escalation/SKILL.md) - Windows提权全栈：信息收集/服务权限滥用/计划任务/注册表/令牌窃取(PrintSpoofer/GodPotato/JuicyPotato)/内核漏洞(MS16-032/MS17-010/CVE-2020-0787~CVE-2026)/UAC绕过(fodhelper/sdclt/silentcleanup/CMSTP)/AppLocker与Defender绕过(LOLBAS/MSBuild/AMSI)/凭据提取(mimikatz/LSASS/SAM/DPAPI/浏览器密码)/DLL劫持/域提权(Kerberoasting/AS-REP/ACL滥用/ADCS ESC1-8/PrintNightmare/ZeroLogon/DCSync/Golden-Silver Ticket/NTLM中继)/2026最新技术(Win11 24H2/Credential Guard绕过/VBS降级/LSA保护绕过/Recall提权)/自动化工具链(WinPEAS/Seatbelt/SharpUp/PowerUp/Sherlock/Watson)/实战案例 (NEW, 2026)
- [persistence-mechanisms](./persistence-mechanisms/SKILL.md) - 持久化机制全栈：Windows持久化(注册表Run/RunOnce/服务/计划任务/WMI事件订阅/启动文件夹/DLL劫持/COM劫持/AppInit_DLLs/BITS/SSP/LSA/凭据提供者/打印监视器/Time Providers/Office加载项/屏幕保护/IFEO/AppCert DLLs/Netsh Helper/Svchost劫持)/Win11 24H2新持久化(WSL/Windows Terminal/Sandbox/Recall/Dev Home/Copilot)/Linux持久化(crontab/systemd timer/rc.local/.bashrc/SSH authorized_keys/MOTD/PAM/LD_PRELOAD/LKM/init.d/桌面文件/APT钩子/udev规则/系统二进制)/macOS持久化(LaunchDaemons/Agents/Login Items/Periodic Scripts/Emond/Authorization Plugins/QuickLook/Zsh)/C2框架(Sliver/Cobalt Strike/Havoc/Merlin/Mythic/域前置/CDN/DoH-DoT/社交媒体C2/GitHub C2/Dead-Drop)/2026最新(eBPF内核级/K8s DaemonSet/容器镜像层/Serverless/AWS Lambda层/Azure Functions/CI-CD管道/GitHub Actions/WebAssembly/EDR白名单/固件UEFI/BIOS/SMM)/Rootkit(用户态LD_PRELOAD/内核态LKM/eBPF Rootkit/文件隐藏/进程隐藏/网络隐藏/键盘记录/驱动级/固件级)/检测绕过(时间延迟/环境键控/反沙箱/反分析/反取证/日志清理/时间戳篡改/ADS数据流/注册表偏移)/WebShell持久化(PHP/ASPX/JSP/Java内存马/Nginx模块/Apache模块/IIS模块/计划任务触发/心跳检测/多级代理)/检测清除(Autoruns/Sysinternals/检测脚本/EDR规则/Sigma/YARA/内存取证/清除工具)/自动化工具链(SharPersist/PowerSploit/PowerView/SharpStay/Hidden/Totem/LaZagne)/实战案例(NTLM中继→RCE→凭据提取→持久化→C2上线→横向移动→域控持久化) (NEW, 2026)

## Post-Exploitation / Data Exfiltration / Scanning

- [post-exploitation-framework](./post-exploitation-framework/SKILL.md) - 后渗透框架与横向移动全栈：凭据收集(Mimikatz/SharpDPAPI/Diamond Ticket)/态势感知(BloodHound CE/Seatbelt)/横向移动(WMI/PsExec/WinRM/DCOM/Kerberos)/权限提升(Token/SeImpersonate/UAC Bypass)/持久化(注册表/WMI/计划任务)/数据收集与外泄(DNS隧道/HTTP/云存储)/C2框架(Cobalt Strike 4.11/Sliver 1.6/Mythic/Havoc)/域完全控制(DCSync/DCShadow/Golden Ticket/ADCS/ADFS)/云环境后渗透(AWS/Azure/GCP/K8s/Serverless)/反取证(日志清理/EDR遥测投毒/时间戳篡改)/2026专项(AI辅助后渗透/ML目标选择/自适应C2/LLM绕过)/检测规避矩阵(CrowdStrike/SentinelOne/Defender/Carbon Black) (NEW, 2026)
- [data-exfiltration](./data-exfiltration/SKILL.md) - 数据外泄技术全栈：网络外泄(HTTP/DNS隧道/ICMP/DoH-DoT-DoQ)/协议隧道(SSH/WebSocket/Slack/Telegram/Discord/MCP/WebRTC)/云存储外泄(S3/Azure Blob/GCS/Serverless)/物理介质(USB/BLE/WiFi Direct/NFC/Thunderbolt DMA)/隐写与隐蔽信道(LSB音频视频/Diffusion模型/TCP ISN)/时间隐信道(Jitter/泊松分布)/死信投递(Pastebin/GitHub Gist/IPFS/Arweave/区块链/NFT)/DLP绕过(压缩加密/AI检测绕过/同形字)/加密外泄(AES/ChaCha20/后量子Kyber)/2026前沿(5G切片/边缘计算/WebAssembly/eBPF/QUIC/AI调度/联邦学习梯度泄露) (NEW, 2026)
- [security-scanning](./security-scanning/SKILL.md) - 漏洞扫描与自动化安全测试全栈：网络扫描(Nmap/Masscan/ZMap/IPv6/云环境)/Web扫描(Burp Pro 2026/ZAP/Nikto/API/GraphQL)/漏洞扫描(Nessus/OpenVAS/Qualys/CVE匹配/Nuclei 3.x模板)/SAST(Semgrep/CodeQL/SonarQube/AI代码审计)/DAST-IAST(动态扫描/字节码插桩/API模糊)/容器与云扫描(Trivy/Grype/Kube-Bench/Kube-Hunter/Prowler/ScoutSuite)/AI驱动扫描(LLM漏洞发现/智能Fuzzing/强化学习路径规划)/持续安全(CI-CD流水线/GitHub Actions/SBOM)/扫描编排(Airflow/DefectDojo/自动修复) (NEW, 2026)

## Defensive / Operations / Audit

- [vulnerability-assessment](./vulnerability-assessment/SKILL.md) - 漏洞评估 (2026)
- [secure-code-review](./secure-code-review/SKILL.md) - 安全代码审计 (2026)
- [security-automation](./security-automation/SKILL.md) - 安全自动化 (2026)
- [security-awareness-training](./security-awareness-training/SKILL.md) - 安全意识培训 (2026)
- [incident-response](./incident-response/SKILL.md) - 应急响应 (2026)
- [cloud-security-audit](./cloud-security-audit/SKILL.md) - 云安全审计：AWS IAM 7条提权链/Azure AD应用权限/GCP服务账号/2026 AWS Bedrock+Vertex AI (STRENGTHENED, 2026)
- [container-security-testing](./container-security-testing/SKILL.md) - 容器安全测试：Docker API未授权RCE/K8s RBAC滥用/runc+containerd CVE逃逸/2026 AI ML沙箱绕过 (STRENGTHENED, 2026)
- [cloud-security-pentesting](./cloud-security-pentesting/SKILL.md) - 云安全渗透测试：AWS/Azure/GCP/阿里云全栈攻击矩阵/IAM 7条提权链/元数据SSRF/云存储/S3劫持/Serverless注入/K8s攻击/容器逃逸/CI-CD投毒/云原生C2/2026最新云攻击面 (NEW, 2026)
- [network-penetration-testing](./network-penetration-testing/SKILL.md) - 网络渗透测试：AD 2026新CVE(Kerberos PAC/NTLM Relay签名绕过/ADCS ESC1-8)/eBPF Rootkit检测/云内网横向(IMDSv2绕过/IAM角色链)/IPv6攻击(SLAAC/NDP欺骗)/零信任绕过(ZTNA/SDP)/AI红队自动化/BloodHound+LLM路径分析/2026内网工具链(NetExec/Sliver/Havoc)/容器内网横向(K8s RBAC/Pod逃逸)/无文件横向(WMI/PowerShell/.NET Assembly)/协议漏洞(HTTP3-QUIC/TLS1.3降级) (STRENGTHENED, 2026)
- [unauthorized-access-common-services](./unauthorized-access-common-services/SKILL.md) - 暴露/未授权服务访问（RMI/T3/AJP/JMX/Redis/ES/Docker/K8s）：Redis/MongoDB/ES/Docker API/K8s API/Jenkins/Hadoop实战利用链 (NEW, STRENGTHENED, 2026)
- [mobile-app-security-testing](./mobile-app-security-testing/SKILL.md) - 移动应用安全测试 (2026)

## Anti-Forensics

- [anti-forensics](./anti-forensics/SKILL.md) - 反取证技术全栈：痕迹清理/日志销毁/时间戳篡改/文件隐藏/数据擦除/内存反取证/磁盘反取证/网络反取证/2026最新反取证(AI生成噪音/LLM日志伪造/EDR遥测投毒)/EDR绕过(ETW/AMSI/内核回调)/ML取证对抗/量子取证/容器K8s取证/反取证检测与验证 (NEW, 2026)

## Platform-Specific Security

- [telegram-mini-app-bot-security](./telegram-mini-app-bot-security/SKILL.md) - Telegram Mini App & Bot安全：initData伪造/WebView XSS/令牌泄露/TON集成/Stars欺诈/NPM供应链 (NEW, 2026)

## Financial Identity Security

- [account-opening-security](./account-opening-security/SKILL.md) - 开户安全测试全栈：KYC绕过/身份认证缺陷/活体检测注入(虚拟摄像头/Deepfake)/合成身份欺诈/证件OCR绕过/批量注册API滥用/视频面签绕过/风险测评绕过/生物特征模板注入/声纹验证/KYC SDK逆向/NFC芯片验证/2026 AI驱动开户攻击/身份信息查询API攻击面(6条身份查询API+2个政府服务自动化脚本) (NEW, STRENGTHENED, 2026)

## Social Engineering

- [social-engineering-framework](./social-engineering-framework/SKILL.md) - 社会工程学攻击框架：钓鱼攻击(鱼叉/批量/Smishing/Vishing/Quishing)/邮件伪造(SPF/DKIM/DMARC绕过)/钓鱼页面克隆(HTTPS伪装/Typosquatting/IDN同形异义字)/水坑攻击(恶意JS/供应链/CDN投毒)/信息收集(OSINT/社交媒体/泄露数据库)/2026 AI社工(LLM钓鱼/DeepFake语音克隆/AI虚假身份)/社工库技术(数据清洗/关联分析/知识图谱/暗网)/物理社工(尾随/USB投递/工作证伪造)/社工防御对抗(培训绕过/沙箱逃逸/指纹伪造)/合规法律边界 (NEW, 2026)

## Reverse Engineering

- [reverse-engineering](./reverse-engineering/SKILL.md) - 逆向工程全栈技能：AI辅助逆向(GhidrAssist/VulChatGPT/Binary Ninja Sidekick/HELIOS) + 移动应用逆向(Frida/Objection/JADX/Root检测绕过/SSL Pinning绕过/Flutter RN逆向) + 二进制漏洞挖掘(angr符号执行/SysFuSS/Bangr模糊测试/混合分析) + 固件逆向(binwalk/SWD-JTAG/SPI sniffing/QEMU模拟) + 反混淆与反反调试(SiMBA++/MBA表达式化简/控制流平坦化恢复/VMP壳分析) + WebAssembly逆向(WABT/wasm-tools/SeeWasm/wasm2c) + 密码学协议逆向(CryptoLyzer/CryptoBap/侧信道辅助恢复) + 硬件逆向(DPA/EMA/电压故障注入/ChipWhisperer) + OLLVM混淆逆向(D810-ng v0.6.6/deflat.py/ollvm-unflattener/Arkari/Pluto Trap Angr/AI辅助BinDeObfBench) + UPX脱壳(5.x对抗/修改检测修复/动态OEP定位/Unipacker/Qiling) + 商业壳逆向(VMProtect 3.6滚动密钥/Themida LZSS/Enigma/多层壳迭代/Scylla IAT重建) + 压缩逆向(gzip/LZMA/Zstd/LZ4/Brotli/压缩盲区/卡方判别/多层压缩加密链/固件文件系统) + .NET反混淆(de4dot/dnlib/ConfuserEx逆向/.NET Reactor Necrobit/dnGuard native hook/MegaDumper/MetaFix) + Java/Android加固脱壳(ProGuard/Allatori/ZKM/360加固/腾讯乐固/爱加密/梆梆VMP/Frida DEX dump/BlackDex/FART/Youpk) + 反调试深度对抗(PEB/NtQueryInformationProcess/RDTSC时序/硬件断点/VEH/ScyllaHide/TitanHide/eBPF检测/CET shadow stack/TPM证明/AI行为分析) + 动态二进制插桩(DynamoRIO code cache/Intel PIN/Frida Stalker覆盖率/QBDI轻量级/iOS越狱检测绕过) + 模拟执行框架(Qiling OS层模拟/Unicorn CPU模拟/QEMU-user跨架构/模拟脱壳通用方案) + 符号执行与污点分析(angr explore/KLEE LLVM IR/Manticore EVM智能合约/Triton concolic/QSYM混合fuzzing/SymCC编译插桩) + 二进制差分(BinDiff图同构/Diaphora多算法/DarunGrim/恶意软件变种分析/AI辅助CodeBERT差分) + iOS应用脱壳(FairPlay DRM/frida-ios-dump/dumpdecrypted/Azul KFD免越狱/objection/Swift 6.0 actor并发逆向) + 恶意软件动态分析(Cuckoo/DRAKVUF硬件级沙箱/沙箱对抗绕过/YARA规则/2026趋势AI恶意软件/LotL/eBPF rootkit) + DRM与许可证逆向(keygen注册机/Patch验证函数/硬件指纹Frida Hook/激活服务器模拟Flask/USB Dongle模拟/White-box密码学DCA/DFA/BGE攻击) (STRENGTHENED, 2026) — 25节/2708行

## Exploit Development

- [exploit-development-framework](./exploit-development-framework/SKILL.md) - 漏洞利用开发框架：栈溢出/堆利用/UAF/类型混淆/竞态条件/ROP链构建/JOP/栈迁移/堆风水/IO_FILE利用/ret2dlresolve/ASLR绕过/PIE绕过/NX绕过/Canary绕过/CFG绕过/CET影子栈绕过/MTE绕过/CFI绕过/浏览器利用(V8/WebKit)/内核利用(eBPF/LKSM/Dirty-Pipe)/PAC绕过/AI辅助ROP/LLM漏洞挖掘/符号执行/shellcode(x86_64/ARM64)/虚拟机逃逸(QEMU/VirtualBox/Hyper-V)/沙箱逃逸(Electron/Snap/Chrome/Android)/glibc 2.38+/musl/Win11 24H2/WSL2/CVE实战案例 (NEW, 2026)

## IoT / Embedded Security

- [iot-security-testing](./iot-security-testing/SKILL.md) - IoT/嵌入式安全测试全栈技能：固件分析(SPI/SWD/JTAG/eMMC/binwalk/unblob/Ghidra/OFRAK)/硬件安全(UART/JTAG/SWD/SPI Flash/I2C/PCB逆向)/通信协议(MQTT/CoAP/ZigBee/BLE/Z-Wave/LoRaWAN/NFC/RFID)/移动端与云平台(IoT App逆向/API安全/MQTT Broker未授权)/2026新攻击面(Matter/Thread/5G IoT/边缘计算/AIoT)/硬件工具链(JTAGulator/BusPirate/Proxmark3/HackRF)/嵌入式系统(TrustZone/安全启动/TEE/UBoot)/车联网(CAN/OBD-II/UDS/ECU/V2X)/ICS-SCADA(Modbus/DNP3/OPC UA/PLC) (NEW, STRENGTHENED, 2026) — 1916行

## Wireless Security

- [wireless-security](./wireless-security/SKILL.md) - 无线安全测试全栈：WiFi安全(WPA2/WPA3/PMKID/WPS)/蓝牙安全(BLE/Classic)/ZigBee/Z-Wave/NFC/RFID/无线键盘鼠标/2026最新无线攻击(WiFi7/WPA4)/5G安全/卫星通信/无人机安全/软件定义无线电(SDR) (NEW, 2026)

## Omnipotent Fusion Skills

- [sinian-omnipotent](./sinian-omnipotent/SKILL.md) - 思念全能安全技能集 v2.4：AI免杀对抗v9.0(BYOUD-Gap/VEH LayeredSyscall/ML对抗/国产三巨头/APK免杀) + CDN/WAF溯源v5.0(50种方法/四维指纹/贝叶斯评分/51家CDN) + Telegram平台安全v2.0(MTProto/TON/AI Bot/Business API) + AI提示词破甲 + 下一代模型专项破甲 + AI破甲驱动的渗透测试提示词工程 + AI驱动全域渗透测试编排系统 + AI自适应对抗与自进化攻击系统 + AI Agent生态攻防与多模态破甲 + Web3开发服务全栈(EVM/Solana合约/DApp/DeFi/审计/上币/KOL) + 逆向工程融合层(AI辅助RE×EDR逆向提取/移动逆向×TG协议/WASM逆向×CDN投毒/合约字节码反编译×Web3/固件逆向×供应链/硬件侧信道攻击) + 跨域融合(Telegram C2/CDN穿透免杀部署/Bot溯源联动/全域攻击链编排/Web3安全联动/十域融合超级攻击链) (NEW, 2026) — 十域融合，11 Part / 83 章

## Web3 Development Services

- [web3-dev-services](./web3-dev-services/SKILL.md) - Web3开发服务全栈技能：EVM链/Solana链合约开发(Solidity/Rust/Anchor) + DApp/DeFi项目定制(DEX/借贷/质押/NFT/GameFi) + Web3官网(Next.js/SEO) + 白皮书(技术/商业/Tokenomics建模) + 合约审计(CertiK/SlowMist) + Bitget代币上架全流程 + KOL资源矩阵(Twitter/YouTube/TikTok) + 海外老外站台(顾问/PR/社区运营) (NEW, 2026)

## Misc / Demo

- [cyberstrike-eino-demo](./cyberstrike-eino-demo/SKILL.md) - Eino 演示
