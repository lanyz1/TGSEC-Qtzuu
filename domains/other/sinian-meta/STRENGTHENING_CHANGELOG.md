# 渗透测试 Skills 深度强化变更记录

> 本技能集经历三十九轮深度强化。
> **第三十九轮**：三大技能2026深度强化 — DNS污染劫持(+619行: DoQ指纹/DNSSEC NSEC3枚举/缓存定时投毒/增强型DNS Rebinding/子域接管/DNS隧道检测)+运营商劫持(+726行: AI-DPI对抗/卫星互联网劫持/BGP实时检测/证书透明度监控/全栈综合扫描器)+Web3开发服务(+1321行: Monad并行EVM/Sui Move/Starknet Cairo/ERC-4337账户抽象/RWA代币化/DePIN存储证明/AI×Web3推理市场/MEV防护Flashbots/15类商业化服务矩阵/2026工具链升级) (2026-07-25)
> **第三十八轮**：开户安全技能深度强化 — 新增§17身份信息查询API攻击面(9节)+6条身份查询API端点+2个政府服务自动化脚本(广西公安电子证件/上海健康证)+API链式调用框架+合成身份构建工作流+开户风控规则探测 (2026-07-25)
> **第一轮**：stub 技能重写 + 缺失技能创建 + 断链修复（81→85 技能）
> **第三十七轮**：3 大新技能 + 4 技能 2026 深度强化 + 3 项修复 + 派大星启动特效 + 全量质检（2026-07-25）
> **第三十六轮**：5 大新技能 + 4 核心技能 2026 强化（2026-07-25）
> **第三十五轮**：5 大新技能创建 + waf-detector 深度强化（2026-07-25）
> **第二轮**：2026 最新技术研究融入 + AI/LLM 攻击面新技能（85→86 技能，13 个技能追加 2026 章节）
> **第三轮**：独角数卡支付漏洞案例 + 2026 支付安全/AI 支付攻击面（business-logic-vulnerabilities 追加支付专项）
> **第四轮**：12 个核心技能追加 2026 章节（认证/注入/客户端/容器全覆盖，27 个技能含 2026 内容）
> **第五轮**：12 个深度 playbook 追加 2026 章节（服务端/API/客户端/移动全覆盖，39 个技能含 2026 内容）
> **第六轮**：6 个防御/运维/侦察技能追加 2026 章节 + 新建供应链攻击技能（86→87 技能，46 个技能含 2026 内容）
> **第七轮**：3 个高优先级 playbook 2026 专节 + 5 个 Router 导航升级 + 6 个 Agent 攻击面扩展（87 技能，62 个技能含 2026 内容）
> **第八轮**：Telegram 平台安全新技能 + 2 个 Agent 2026 强化 + 5 个 Router 交叉引用（87→88 技能，65 个技能含 2026 内容）
> **第九轮**：Telegram 技能深度强化 — 9 个全新高级章节（MTProto/TAC Bridge/TONResolver/TON Connect 2.0/Navy Ghost/AI+Telegram/Business API/支付代理/高级测试方法论），~45KB 新增技术内容
> **第十轮**：思念全能技能集创建 — 深度融合 AI免杀v9.0 + CDN溯源v5.0 + Telegram安全v2.0 三大领域，新增跨域融合层（Telegram C2隐蔽信道/CDN穿透免杀部署/Bot溯源联动/全域攻击链编排），88→89 技能，~82KB 新增技术内容
> **第十一轮**：思念全能技能集终极强化 v1.2 — +6全新高级章节(Part VI: Windows内核EDR绕过(DKOM/SSDT/Minifilter/PatchGuard/BYOVD/HVCI降级)/云原生攻击矩阵(AWS/Azure/GCP/K8s/Serverless/多云横向)/硬件安全绕过(TEE/Secure Boot/TPM/HSM侧信道)/TMA高级攻击(完整代码审计/运行时劫持/支付审计)/高级密码学(FHE/ZKP/MPC/PQC迁移)/AI红队自动化(Agent编排/自动漏洞发现/自适应对抗学习))，~65KB 新增技术内容，总计 6 Part / 54 章
> **第十二轮**：思念全能技能集 CDN溯源深度强化 v1.3 — 融合 FUCK-CDN 项目精华，新增 §14A-§14F 共6大章节(P0-P4优先级分层执行框架/12家CDN厂商专项深度绕过/通用CDN兜底策略/P4深度挖掘9大技术/证据链S/A/B/C/X分级与贝叶斯融合/跨平台适配+API Key注入+Token优化)，~28KB 新增技术内容，CDN溯源从50种方法扩展为50种方法+5级优先级+12家厂商专项+9种P4深度挖掘的完整体系
> **第十三轮**：思念全能技能集 全网IP扫描溯源 v1.4 — 新增 §14G 全网IP扫描溯源(11节)，融合 ZMap+Masscan+ZGrab2三大扫描引擎 + Censys/Shodan/FOFA/ZoomEye/Quake/BinaryEdge 6大平台全网数据集 + 云厂商IP段定向扫描(6家) + 分布式大规模扫描架构 + HTTP响应指纹全网扫描 + 多指纹交叉验证 + Python自动化流水线，~22KB 新增技术内容，溯源能力从"被动查询"升级为"主动全网扫描"
> **第十四轮**：思念全能技能集 三域深度强化 v1.5 — 新增 Part VII 共3大章节(§55-§57: 域A跨平台全端免杀(macOS/Linux/浏览器载荷/高级进程注入/驱动Rootkit)/域B高级溯源扩展(WebSocket/HTTP3/DoH/实时DNS/新增CDN厂商)/域C Telegram 2026新攻击面(Stars/Gateway/Premium/iframe沙箱/Fragment/Passport))，~35KB 新增技术内容
> **第十五轮**：思念全能技能集 三域终极强化 v1.6 — 新增 Part VIII 共4大章节(§58-§61: 域A(2026最新EDR绕过+ARM64/Apple Silicon原生免杀+内存扫描对抗+EDR遥测投毒+Rust/Zig新一代Loader)/域B(国内CDN厂商专项绕过+ML辅助溯源+暗网情报+HTTP3 QUIC高级指纹+实时CDN切换检测)/域C(TON DeFi生态攻击面+Telegram广告系统+2026最新CVE链+Channels/Stories深度攻击)/跨域融合终极强化(新攻击场景+自动化攻击平台+实时态势感知))，~42KB 新增技术内容
> **第十六轮**：思念全能技能集 AI提示词破甲技术 v1.7 — 新增 Part IX(§62: AI大模型全栈破甲方法论，覆盖OpenAI GPT/Codex(DAN变体/函数调用劫持/Codex上下文注入)/Anthropic Claude(宪法覆盖/XML标签注入/系统提示提取)/Google Gemini(安全设置滥用/多模态注入)/国产大模型(通义千问/文心一言/Kimi/智谱/DeepSeek)/多模型通用方法论(五层破甲模型/优化策略/多模型联合攻击)/自动化破甲框架AutoJailbreak(三阶段活动/技术探测/优化/组合攻击)/破甲防御与检测(输入输出过滤/架构防御/红队测试))，~38KB 新增技术内容，总计 9 Part / 62 章
> **第十七轮**：思念全能技能集 下一代模型专项破甲 v1.8 — 新增 §63(8节: 模型安全架构指纹与攻击面总览/GPT-5.6专项破甲(RTR/MALT/EMA/TCS/DPL)/Claude Opus 4.8专项破甲(CDW/IRA/RSC/TEC/多智能体)/Grok 4.5专项破甲(PBE/X平台投毒/UID/DBR/STE)/跨模型通用高级技术/NextGenJailbreakEvaluator自动化框架/SOP实战工作流/防御矩阵)，~45KB 新增技术内容，总计 9 Part / 63 章
> **第十八轮**：思念全能技能集 AI破甲与渗透测试提示词工程 v1.9 — 新增 §64(7节: 渗透测试提示词工程总览/破甲→渗透测试稳定化协议(授权锚定+角色锁定/研究场景包装/反向导师模式/CVE链驱动/防御优先框架)/渗透测试全阶段提示词模板库(信息收集/漏洞分析/攻击利用/后渗透/报告生成)/PenTestPromptForge自动提示词优化与破甲生成器/PentestJailbreakEvaluator评估器/实战案例:从破甲到完整Web渗透测试链/防御视角:检测AI驱动渗透测试与破甲)，~48KB新增技术内容，总计 9 Part / 64 章
> **第十九轮**：思念全能技能集 AI驱动全域渗透测试编排系统 v2.0 — 新增 §65(6节: 全域编排系统总览/多Agent协同架构(SinianOrchestrator+六层L0-L5)/各Agent实现(JailbreakAgent/ReconAgent/VulnAgent/PayloadAgent/C2Agent/ReportAgent)/实战编排工作流/编排系统配置与部署/跨域融合攻击场景示例)，~42KB新增技术内容，从"六域融合"升级为"七域融合"，总计 9 Part / 65 章
> **第二十轮**：思念全能技能集 AI自适应对抗与自进化攻击系统 v2.1 — 新增 §66(7节: 自进化系统总览/RL强化学习自适应免杀引擎(Q-Learning+ε-贪心+10变异策略+进化记忆库)/LLM自动漏洞发现与利用链生成(7类漏洞分类+持续迭代发现)/攻防博弈框架(AdversarialGame+纳什均衡检测+进化趋势分析)/自进化C2信道(8协议×6环境适配矩阵+指数移动平均更新)/SinianSelfEvolvingSystem完整实现/实战工作流与防御对策矩阵)，~45KB新增技术内容，总计 9 Part / 66 章。同时完成深度Bug检测：修复8个Bug(版本号不一致/架构图缺失/版本历史缺失/参考资料缺失/域描述缺失/PayloadAgent逻辑bug/Markdown代码围栏bug)
> **第二十一轮**：思念全能技能集 AI Agent生态攻防与多模态破甲深化 v2.2 — 新增 §67(8节: Agent攻击面总览/MCP服务器投毒攻击(MCPPoisoner+5种投毒模板+投毒检测)/Agent工具劫持与间接提示词注入(IndirectInjector五载体+ToolHijacker)/Agent记忆持久化后门(MemoryBackdoor四策略+向量DB投毒+后门检测)/多模态间接注入破甲(MultimodalInjector: LSB图像隐写/低对比度文本/音频频谱/ASR对抗样本/视频帧/跨模态指令分散)/多智能体横向移动(AgentNetwork BFS传播+信任因子+企业拓扑)/完整SinianAgentAttackSystem实现(7阶段闭环)/防御对策矩阵+数据-指令分离架构)，~40KB新增技术内容，从"七域融合"升级为"八域融合"，总计 9 Part / 67 章。同时完成深度Bug检测：修复3个Bug(pipeline.py check_fn参数不匹配TypeError/usage --full-scan用法错误/export_report原地修改副作用)
> **第二十二轮**：DNS污染与劫持专项新技能 — 新建 `dns-pollution-hijacking` 技能(9节, 556行)，精准辨析常被混淆的"DNS污染(中间人竞速注入伪造IP)"与"DNS劫持(权威替换)"两类机制，覆盖协议层脆弱性根源(UDP无连接无认证/16位TXID/无源认证)、包级注入竞态时序图、TXID与源端口猜测(TXID爆破/源端口侧信道/Birthday/分片覆盖)、Kaminsky缓存投毒(NS记录投毒影响全域)、DNS劫持四路径(路由器固件后门/ISP NXDOMAIN劫持/恶意软件改Hosts/多层缓存投毒)、2026加密DNS演进(DoH/DoT/DNSCrypt/DoQ+DNSSEC签名链+AI辅助TXID预测)、自动化检测脚本(多源对比+NXDOMAIN劫持测试)、防御矩阵(防污染vs防劫持分维)、强化版交互式HTML演示(4面板:污染vs正常/竞速注入/Kaminsky扩散/多源检测)、实战排查流程SOP，89→90 技能
> **第二十三轮**：Active Directory内网渗透与横向移动专项新技能 — 新建 `active-directory-lateral-movement` 技能(12节, 1190行)，补齐内网渗透这一企业级测试核心缺口。覆盖AD攻击生命周期7阶段、域信息侦察(BloodHound攻击图/PowerView/ADModule/ADSI-LDAP四层枚举)、初始凭据获取(AS-REP Roasting/密码喷洒/Kerberoasting/LSASS dump)、Kerberos攻击矩阵(Golden/Silver/Diamond/Sapphire票据伪造+非约束/约束/RBCD三类委派)、NTLM中继(ntlmrelayx/跨协议中继/PetitPotam诱导/PetitPotam→ADCS→DC接管链)、凭据传递与横向移动(PtH/PtT/Overpass-the-Hash+WMI/PsExec/WinRM/DCOM)、ACL滥用(GenericAll/GenericWrite/WriteDacl/WriteOwner)+DCSync+DCShadow、ADCS证书服务攻击(ESC1-8全谱+Shadow Credentials)、2026最新技术(noPac/KrbRelayUp/Certifried CVE-2022-26923+AI辅助BloodHound路径发现)、检测信号矩阵(11类攻击×事件ID)+纵深防御9层+Tier分层模型、自动化SOP与SinianADOrchestrator编排器实现，90→91 技能
> **第二十四轮**：运营商流量劫持专项新技能 — 新建 `isp-traffic-hijacking` 技能(12节, 1229行)，将运营商流量劫持从DNS领域的一个子节扩展为按OSI七层独立构建的完整技术栈。覆盖运营商劫持分层模型(L1-L7能力矩阵+劫持根因分析)、DNS层运营商劫持(NXDOMAIN劫持/强制透明DNS代理/CDN调度干扰/DNS+HTTP缓存协同)、HTTP层运营商劫持(广告注入全流程/内容篡改/302重定向劫持/iframe弹窗注入+检测Python脚本)、HTTPS层运营商劫持(SSL剥离+HSTS防护/证书替换+MITM时序/证书透明度crt.sh检测/CDN边缘节点劫持+SRI/QUIC-HTTP3劫持与ECH绕过)、BGP劫持与路由操纵(前缀劫持/路径篡改/路由泄露+RPKI路由安全+运营商合法化外衣分析)、DPI深度包检测(协议识别/URL过滤/TLS指纹/会话劫持+检测与绕过)、透明代理与缓存投毒(部署架构/劫持能力/检测方法)、2026最新技术(5G信令劫持NEF-NWDAF/eSIM远程配置/QUIC连接迁移劫持-0RTT重放/ECH降级对抗)、分层检测矩阵(12类×工具×置信度)+防御矩阵(10项)+终端用户三级防护清单、ISPHijackDetector综合检测器实现、5面板交互式HTML演示(DNS/HTTP/HTTPS/BGP/综合检测)、6步实战排查SOP，91→92 技能
> **第二十五轮**：Web3开发服务全栈技能 — 新建 `web3-dev-services` 技能(7节, 1500行)，开辟Web3商业化服务全新技能域。覆盖EVM链(Solidity/Hardhat/Foundry)与Solana链(Rust/Anchor)智能合约开发(含ERC-20代币/ERC-721 NFT/AMM/Staking/ERC-4337账户抽象完整生产级代码模板)、DApp/DeFi项目全栈定制(Next.js 14+wagmi v2+viem+Web3Modal/AppKit架构/DEX/借贷/质押/NFT/GameFi 8类项目方案)、Web3官网(SEO优化/Lighthouse 90+/多语言/JSON-LD结构化数据)与白皮书(技术/商业/Litepaper/Pitch Deck/One-Pager 5种类型+Tokenomics建模)、合约审计(四阶段流程:自动化→人工→外部对接→修复+CertiK/SlowMist/Trail of Bits/PeckShield/Quantstamp/Hacken/Beosin 7大审计所对接)、Bitget代币上架全流程(5阶段:项目评估→材料准备→商务对接→技术上线→市场推广+10家CEX上币要求对比)、KOL资源矩阵(10类KOL×合作流程4步骤×效果追踪)+海外老外站台(10类资源+Discord社区运营方案+PR发稿13家媒体渠道)、项目交付流程(5阶段管理+11项交付物清单)、常见问题与解决方案(合约开发8大坑+上币7大拒因)、工具链与资源(12款开发工具+8款审计工具)，92→93 技能
> **第二十六轮**：思念全能技能集 九域融合 v2.3 — 将 `web3-dev-services` 技能全部融合压缩至 `sinian-omnipotent` 技能，新增 Part X: Web3开发服务全栈(§70-§74 共5章)。核心变更：架构图从"八域融合拓扑"升级为"九域融合拓扑"；跨域能力矩阵新增域I(Web3)维度含商业变现闭环；新增§70(Web3技术栈全景: EVM/Solana双链技术栈+10类服务矩阵)、§71(合约开发核心模板: ERC-20/ERC-721/AMM/Staking/ERC-4337/Anchor Program完整生产级代码)、§72(DApp/DeFi/官网/白皮书: Next.js 14+wagmi v2架构/8类DeFi方案/SEO标准/5类白皮书)、§73(合约审计/上币/KOL/海外站台: 四阶段审计流程+7大审计所/Bitget上币5阶段+10家CEX对比/10类KOL矩阵+13家PR媒体)、§74(项目交付5阶段+11项交付物+安全联动: 域A×域C×域I全链路闭环)。从"八域融合"升级为"九域融合"，总计 10 Part / 74 章，93 技能（web3-dev-services已融合，保持93技能总数）
> **第二十七轮**：四大核心技能2026深度强化 — 4个高优先级技能追加深度2026章节(ssti追加LangChain/LangGraph模板注入CVE集群+AI管道盲注+多模态模板注入/ai-llm追加A2A协议攻击+MCP Streamable HTTP+跨协议信任继承+BadHost MQTT劫持+Vector DB后门+模型合并供应链+语音深度伪造注入/web-cache追加Pingora缓存键碰撞+GET请求体投毒+边缘计算投毒+API网关缓存绕过+缓存键规范化滥用+AI驱动缓存操纵/graphql追加Federation子图注入+Apollo Federation CVE集群+影子子图暴露+传递式访问控制绕过)，覆盖2026年最新CVE(CVE-2026-40087/CVE-2026-34070/CVE-2026-34071/CVE-2026-34072/CVE-2026-4539/CVE-2025-68664/CVE-2026-2833/CVE-2026-2835/CVE-2026-2836/CVE-2026-32621/CVE-2025-64530/CVE-2025-64173/CVE-2025-64347)，93技能
> **第二十八轮**：逆向工程全栈技能 + 十域融合终极强化 — 新建 `reverse-engineering` 独立技能(11节,893行)，覆盖8大逆向领域(AI辅助逆向GhidrAssist/VulChatGPT/Binary Ninja Sidekick/HELIOS+移动应用逆向Frida/Objection/JADX+二进制漏洞挖掘angr/SysFuSS/Bangr+固件逆向binwalk/SWD-JTAG/SPI+反混淆SiMBA++/MBA表达式化简+WebAssembly逆向WABT/wasm-tools/SeeWasm+密码学协议逆向CryptoLyzer/CryptoBap+硬件逆向DPA/EMA/电压故障注入/ChipWhisperer)。同步将逆向工程融合至 `sinian-omnipotent` 全能技能。技能总数 93→94，sinian-omnipotent从v2.3升级至v2.4(10 Part/74章→11 Part/83章)
> **第二十九轮**：OLLVM/UPX/gzip逆向技术深度强化 — 对 `reverse-engineering` 技能追加4大新章节(§11-§14, 893→1830行, +937行)。§11 OLLVM混淆逆向(D810-ng v0.6.6反平坦化器矩阵/deflat.py+debogus.py angr符号执行去平坦化/ollvm-unflattener Miasm v2.0/MBA表达式化简DSL+Z3验证/OLLVM变体识别Arkari LLVM22.x+Pluto Trap Angr+Hikari/AI辅助BinDeObfBench基准DeepSeek-R1 62.89%语义保真度/Promon三重混淆乘法效应x86 4.18倍ARM 5.50倍)。§12 UPX脱壳(标准upx -d/修改UPX头部检测与修复UPX!标记/动态脱壳OEP定位VirtualAlloc断点+Scylla IAT重建/Unipacker Unicorn模拟+Qiling 64位支持/UPX 5.x新特性memfd_create+SELinux+--unmap-all-pages+两步解压+RISC-V)。§13 商业壳逆向(VMProtect 3.6滚动密钥寄存器VKEY纯静态不可解/Themida LZSS压缩+CFF脱壳三步法/Enigma+ConfuserEx层叠/多层壳迭代脱壳anpa1200 Unpacker+orcastor/unpack/反调试反VM检测Frida隐藏+CPUID绕过+Local Hollowing/内存转储Scylla+revdump+PE-sieve)。§14 压缩逆向(9种格式魔数速查表gzip/zlib/bzip2/xz/LZMA/LZ4/Zstd/Brotli/LZString/binwalk v3 Rust重写+unblob 78+格式/嵌入式gzip流解析/gzip炸弹Sliver C2 GHSA-2PHG-QGMM-R638/★压缩盲区Zstd LZ4接近零检测覆盖KlaroSkope 2026/CyberChef无Zstd支持/LZString不可见压缩/卡方检验压缩vs加密判别/多层压缩加密链剥离/固件文件系统SquashFS+JFFS2)，94技能
> **第三十轮**：.NET反混淆与Java/Android加固脱壳深度强化 — 对 `reverse-engineering` 技能追加2大新章节(§15-§16, 1830→2260行, +430行)。§15 .NET反混淆(de4dot v5.1.2+System.Reflection.Emit Module.ResolveMethod/ConfuserEx VMP+常量加密+反篡改类型发现/Agile.NET 6.x字符串加密+代理调用+控制流混淆/.NET Reactor 6.9+Native Stub+Necrobit JIT虚拟化/dnGuard HVM+NativeModule+DNGuard_HVM_Unpacker/Eazfuscator.NET虚拟化VM+符号执行破解/MegaDumper+ScyllaHide+ExtremeDumper+DotNetDumper内存dump)。§16 Java/Android加固脱壳(ProGuard/R8+ClassyShark+enjarify+Bytecode Viewer/Allatori/DashO/ZKM/Stringer/360加固修复+脱壳+修复/腾讯乐固+脱壳+修复/爱加密+脱壳+修复/梆梆加固VMP/顶象/网易易盾/DexProtector/BlackDex+Frida-DEX-Dump+FART+Youpk+脱壳对比表)

> **第三十一轮**：反调试深度对抗 + 动态二进制插桩 + 模拟执行框架 — 对 `reverse-engineering` 技能追加3大新章节(§17-§19, 2260→2708行, +448行)。§17 反调试深度对抗(PEB.BeingDebugged+IsDebuggerPresent/NtGlobalFlag/NtQueryInformationProcess+ProcessDebugPort/CloseHandle异常/TLS回调+反调试/NtSetInformationThread+隐藏线程/RDTSC+GetTickCount+QueryPerformanceCounter+时间差检测/硬件断点+DR0-DR7/int3断点+软件断点/VEH向量化异常处理+反硬件断点/PatchGuard触发+反调试插件/ScyllaHide+TitanHide+HyperHide驱动级/eBPF程序检测+内核态反调试/CET shadow stack+硬件辅助反调试/TPM远程证明+可证明无调试器/AI行为分析+反调试旁路)。§18 动态二进制插桩(DynamoRIO+code cache+DrCov代码覆盖率+DrMemory+DrFuzz/Intel PIN+INS_AddInstrumentFunction+Pintool/Valgrind+Memcheck+Cachegrind/Capstone+Unicorn+自研轻量级/Frida Stalker+代码覆盖率+反调试/QBDI+轻量级+跨平台(ARM64)/DynamoRIO vs PIN vs Frida Stalker对比表)。§19 模拟执行框架(Qiling Framework+OS层模拟+rootfs+POSIX兼容+Windows DLL模拟/Unicorn Engine+CPU模拟+hook+内存操作+跨架构/QEMU-user+跨架构(GDB server)+用户态模拟+系统调用+QEMU+Qiling联动/模拟脱壳通用方案+内存dump+OEP定位+模拟执行绕过反调试+反模拟检测对抗/模拟执行+符号执行+污点分析联动)。94技能，reverse-engineering 2708行

> **第三十二轮**：符号执行 + 二进制差分 + iOS脱壳 + 恶意软件分析 + DRM逆向 — 对 `reverse-engineering` 技能追加5大新章节(§20-§24, 2708→3360行, +652行)。§20 符号执行与污点分析(angr+explore+claripy+SimulationManager+模式化约束求解+KLEE+LLVM IR+Manticore+EVM字节码符号执行+Triton+concolic+动态符号执行+QSYM+混合fuzzing+符号执行+SymCC+编译插桩)。§21 二进制差分(BinDiff+图同构+函数匹配+相似度评分+Diaphora+多算法+多匹配器+DarunGrim+补丁差异+恶意软件变种分析+Diff+Kdiff+反编译+伪代码diff+AI辅助+CodeBERT+GraphCodeBERT+二进制相似度)。§22 iOS应用脱壳(FairPlay DRM+frida-ios-dump+dumpdecrypted+Clutch+禁用ASLR+AppSync+Azul+KFD+内核文件描述符+免越狱+objection+ios+ssl-pinning+Swift 6.0+actor+并发+逆向+iOS 17+18+系统完整性保护)。§23 恶意软件动态分析(Cuckoo Sandbox+DRAKVUF+硬件级+VM检测+沙箱对抗+反沙箱+时间延迟+用户交互检测+YARA+v4.5+PE+ELF+Mach-O+2026趋势+AI+LLM生成恶意软件+LotL+LOLBAS+供应链+eBPF rootkit)。§24 DRM与许可证逆向(Keygen+注册机+算法逆向+算法提取+License验证+硬件指纹绑定+VMProtect+Themida+壳保护+Wine+DLL重定向+Windows模拟+模拟器+USB Dongle+Sentinel+HASP+模拟+白盒密码学+WBC+差分计算分析+DCA+差分故障分析+DFA+BGE攻击+CHES 2026)。94技能，reverse-engineering 3360行

> **第三十三轮**：开户安全测试全栈技能 — 新建 `account-opening-security` 技能(10节, 1580行)，覆盖金融/支付/加密货币平台开户环节的完整安全测试体系。10大技术域：KYC绕过(证件PS/翻拍/公开信息匹配/活体检测注入/3D面具/Deepfake/对抗样本)/身份认证缺陷(会话状态操纵/步骤跳过/多因素认证缺陷/JSON注入状态修改)/活体检测攻击(虚拟摄像头OBS/虚拟驱动/安卓Root注入/反射注入/3D建模/对抗生成网络)/合成身份欺诈(信息拼接/GAN生成/信用记录构建/决策树绕过/微表情分析)/批量注册API滥用(签名逆向/设备指纹对抗/虚拟手机号/代理IP池/浏览器自动化)/证件OCR绕过(结构化注入/Box篡改/字段覆盖/Unicode同形字/PDF层注入)/视频面签绕过(虚拟摄像头/预录视频/Deepfake实时/绿幕/旁路音频注入)/风险测评绕过(评分操纵/参数篡改/差异化跳过/时序攻击/差分隐私推断)/生物特征模板注入(SQL注入/反序列化/模板拼接/特征向量投毒/声纹验证/Spear逆向/语音合成/频谱注入/环境音效)/KYC SDK逆向(APK反编译/资产提取/API端点发现/请求重放/加密密钥提取/NFC芯片验证/模拟APDU/中继攻击/Android HCE)。技能总数 94→95

> **第三十四轮**：32个技能实战攻击链批量强化 — 对全部 32 个渗透测试技能进行实战攻击链深度强化，每个技能包含完整的从信息收集到漏洞利用的端到端攻击链。新增约 179 条攻击链，每条包含可直接执行的命令、分步利用流程、检测绕过技巧和 2026 CVE 引用。关键突破：AI/ML 攻击面全面融入（Pickle RCE/AI模型API IDOR/MCP OAuth/AI聊天XSS/AI内容审核绕过/LangChain原型污染等）、云原生攻击链完善（AWS IAM 7条提权链/K8s RBAC滥用/Docker API RCE/云存储遍历）、2026 CVE集群覆盖（HTTP/2 HPACK/Import Maps CSP/Quarkus Qute EL等）。95 技能

> **第三十七轮**：3 大新技能 + 4 技能 2026 深度强化 + 3 项修复 + 派大星启动特效 + 全量质检（2026-07-25）

**3 大新技能创建**（99→102 技能）：
1. `post-exploitation-framework`（4585 行）：后渗透框架与横向移动全栈 — 13 大技术域覆盖凭据收集/态势感知/横向移动/权限提升/持久化/数据收集与外泄/C2 框架/域完全控制/云环境后渗透/反取证/实战攻击链/2026 专项技术/检测规避矩阵
2. `data-exfiltration`（6448 行）：数据外泄技术全栈 — 10 大技术域覆盖网络外泄/协议隧道/云存储/物理介质/隐写隐蔽信道/时间隐信道/死信投递/DLP 绕过/加密外泄/2026 前沿技术
3. `security-scanning`（4675 行）：漏洞扫描与自动化安全测试全栈 — 10 大技术域覆盖网络扫描/Web 扫描/漏洞扫描/模板扫描/SAST/DAST-IAST/容器与云扫描/AI 驱动扫描/持续安全/扫描编排

**4 技能 2026 深度强化**：
1. `password-attacks-credential-access`：追加 2764 行 2026 章节（AI/ML 密码攻击/2026 CVE 集群/云原生凭据/硬件加速/无密码认证/现代哈希破解/凭据填充/内存保护绕过/检测规避/实战攻击链）
2. `anti-forensics`：追加 3999 行 2026 章节（EDR 检测机制剖析/内存反取证/日志清理/时间线篡改/文件隐藏/网络反取证/AI 反取证/检测规避矩阵/全链路清理/工具链）
3. `wireless-security`：追加 3226 行 2026 章节（WiFi 新突破/蓝牙深度攻击/ZigBee-Matter/NFC-RFID/5G-卫星-无人机/SDR/无线外设/AI 辅助攻击/检测规避/工具链）
4. `api-security-testing`：追加 1820 行 2026 章节（API 新协议/认证绕过/授权缺陷/注入攻击/网关攻击/速率限制绕过/Mass Assignment/AI-ML API 攻击/自动化/实战攻击链）

**3 项关键修复**：
1. `windows-privilege-escalation/SKILL.md`：修复文件头部截断 — 补全 YAML front matter + §1/§2/§3 缺失内容（权限模型/令牌操纵/服务提权），原 §4+ 内容完整保留
2. `cdn-origin-tracing/`：补全 5 个缺失 Python 脚本 — `cdn_tracer.py`（1555 行 10 阶段溯源主入口）/ `ja3extract.py`（713 行 TLS 指纹）/ `cdn_ip_collector.py`（582 行 8 源并发）/ `cdn_origin_monitor.py`（694 行漂移监控）/ `internet_wide_scanner.py`（923 行全网扫描），全部语法校验通过
3. `ssti-server-side-template-injection/SCENARIOS.md`：新建缺失文件 — 覆盖 §7-§11 扩展内容（Razor/EEx-LEEx-HEEx/PHP 技术栈/JavaScript 模板引擎/polyglot 探测/数学指纹/盲 SSTI/Flask Debug PIN）

**派大星启动特效**：在 `sinian-omnipotent/SKILL.md` 内嵌完整的派大星技能启动动画（SVG+CSS+JS），含反戴帽子/大眼/张嘴流口水/进度条/语录轮播/庆祝动画，支持 reduced-motion 降级

**全量质检**：110 个 SKILL.md 全量校验 — YAML front matter 有效性/2026 内容覆盖/内部引用完整性/Python 脚本语法校验/编码完整性，全部通过



对 5 个缺失技能域进行补全，同时对 waf-detector 进行 2026 深度强化，技能总数 95→99。

## 变更技能明细

### 1. WebShell 免杀与管理技能（新建）

- 文件：`/workspace/skills/webshell-evasion/SKILL.md`（2459 行）
- 10 大技术域：静态免杀（变量混淆/字符串加密/注释混淆/代码压缩/函数名随机化）、动态免杀（行为伪装/延迟执行/流量伪装/UA白名单/Referer校验）、多语言WebShell（PHP/ASP/ASPX/JSP/Java/Node.js/Python CGI）、2026最新免杀技术（AI生成变异/LLM混淆器/AST代码变形/WAF绕过）、管理工具（蚁剑/冰蝎/哥斯拉免杀配置）、内存马（Java Filter/Listener/Servlet/Tomcat Valve/PHP FFI/ASP.NET IIS Module）、2026检测绕过（阿里云/腾讯云/Cloudflare/Imperva专项）、一过性WebShell（无文件落地/日志型/注册表型/计划任务型）、WAF穿透（分块传输/压缩传输/TLS指纹伪装/HTTP2多路复用/请求走私）、实战场景（文件上传+免杀+权限维持全链路）

### 2. 社会工程学攻击框架（新建）

- 文件：`/workspace/skills/social-engineering-framework/SKILL.md`（3011 行）
- 10 大技术域：钓鱼攻击（鱼叉/批量/Smishing/Vishing/Quishing + Gophish/Evilginx3/Modlishka）、邮件伪造（SPF/DKIM/DMARC绕过/Reply-To劫持/邮件头注入）、钓鱼页面克隆（HTTPS证书伪装/Typosquatting/IDN同形异义字/反向代理/凭证捕获JS）、水坑攻击（恶意JS注入/BeEF/供应链污染/CDN投毒）、信息收集（theHarvester/Shodan/HIBP/LinkedIn挖掘/泄露数据库）、2026 AI社工（LLM钓鱼邮件/DeepFake语音克隆OpenVoice/对话式钓鱼/AI虚假身份）、社工库技术（数据清洗/关联分析NetworkX/知识图谱Neo4j/暗网Tor）、物理社工（尾随/USB投递Rubber Ducky/BadUSB/工作证RFID克隆）、社工防御对抗（安全培训绕过/钓鱼演练检测/沙箱逃逸/浏览器指纹伪造）、合规法律边界（GDPR/网络安全法/个人信息保护法）

### 3. IoT/嵌入式安全测试技能（新建）

- 文件：`/workspace/skills/iot-security-testing/SKILL.md`（1916 行）
- 10 大技术域：固件分析（binwalk/unblob/EMBA/FACT/OFRAK/Ghidra/硬编码凭据/后门检测）、硬件安全（UART/JTAG/SWD/SPI Flash/I2C嗅探/PCB逆向/电压故障注入ChipWhisperer）、通信协议（MQTT/CoAP/BLE/ZigBee/LoRaWAN/NFC/RFID/Proxmark3）、移动端与云平台（APK逆向/Frida Hook/云API IDOR/MQTT Broker未授权）、2026新攻击面（Matter/Thread/5G IoT/边缘计算/AIoT）、硬件工具链（JTAGulator/BusPirate/Logic Analyzer/HackRF）、嵌入式系统（TrustZone/安全启动/TEE/U-Boot）、车联网（CAN总线/OBD-II/UDS/ECU/V2X）、ICS/SCADA（Modbus/DNP3/OPC UA/PLC/S7协议）、实战案例与工具链（7阶段渗透测试流程/IoT自动化扫描器）

### 4. 漏洞利用开发框架（新建）

- 文件：`/workspace/skills/exploit-development-framework/SKILL.md`（2102 行）
- 12 大技术域：漏洞类别（栈溢出/堆UAF/类型混淆/竞态条件/整数溢出/格式化字符串/越界读写）、利用技术（ROP/JOP/栈迁移/堆风水/IO_FILE/ret2dlresolve）、缓解绕过（ASLR/PIE/NX/Canary/CFG/CET/MTE/CFI）、浏览器利用（V8/WebKit JIT/沙箱逃逸）、内核利用（eBPF/LKSM/Dirty-Pipe/Windows内核池）、2026新利用（PAC绕过/AI辅助ROP/LLM漏洞挖掘/符号执行AEG）、开发环境（pwntools/GDB/QEMU/KGDB/Windbg）、Shellcode（x86_64/ARM64/编码器/多阶段/文件less）、虚拟机逃逸（QEMU/VirtualBox/Hyper-V/KVM）、沙箱逃逸（Electron/Snap/Flatpak/Chrome/Android/Apple）、ABI（glibc 2.38+/musl/Windows 11 24H2/WSL2）、实战案例（CVE-2026-3142/CVE-2026-33697）

### 5. waf-detector SKILL.md 深度强化（v2.0）

- 文件：`/workspace/waf-detector/SKILL.md`（544 行，从 218 行扩展）
- 新增内容：150+ WAF 厂商指纹详细表（国际云WAF 31家/国内WAF 28家/开源WAF 8家/硬件WAF 22家/新兴云WAF 15家/API网关 5家）、2026最新绕过技术（HTTP/3 QUIC绕过/AI驱动WAF规则逆向/分块传输编码绕过/HTTP/2多路复用/TLS指纹伪装/AI驱动WAF绕过框架）、常用WAF绕过策略矩阵（按攻击类型+按WAF厂商双向分类）、2026 WAF演进趋势与对抗（AI驱动检测/API安全融合/边缘计算/零信任架构）、技能联动表（8个关联技能）

### 6. 工具验证

- `waf_hunter.py` CLI 验证通过：153 WAF 厂商指纹、372 Bypass Payload、62 种绕过技术、9 维检测引擎、三重验证
- 所有 4 个新技能 SKILL.md 文件创建完成，INDEX.md 注册完成

## 技能总数变化

| 变更 | 技能数 |
|------|--------|
| 上一轮结束 | 95 |
| webshell-evasion 新建 | 95→96 |
| social-engineering-framework 新建 | 96→97 |
| iot-security-testing 新建 | 97→98 |
| exploit-development-framework 新建 | 98→99 |
| **本轮结束** | **99** |

## 新增技能总行数

| 技能 | 行数 |
|------|------|
| webshell-evasion | 2,459 |
| social-engineering-framework | 3,011 |
| iot-security-testing | 1,916 |
| exploit-development-framework | 2,102 |
| waf-detector SKILL.md | 544 |
| **合计** | **10,032** |
---

# 第三十六轮：5 大新技能 + 4 核心技能 2026 强化（2026-07-25）

对 5 个缺失技能域进行补全，同时对 4 个核心技能追加 2026 最新攻击技术章节，技能总数 99→103。

## 变更技能明细

### 1. Linux 提权全栈技能（新建）

- 文件：`/workspace/skills/linux-privilege-escalation/SKILL.md`（3244 行）
- 14 大技术域：信息收集（系统/内核/SUID/SGID/Capabilities/定时任务）、SUID/SGID提权（30+ GTFOBins利用链）、Sudo权限滥用（LD_PRELOAD/环境变量/CVE-2021-3156/CVE-2019-14287）、Cron任务劫持（PATH劫持/通配符注入/systemd timer）、Capabilities滥用（cap_sys_admin/cap_sys_ptrace/cap_dac_read_search）、内核漏洞利用（DirtyPipe/PwnKit/OverlayFS/GameOver(lay)/StackRot/CVE-2024-21626）、容器逃逸（Docker Socket/privileged/runc/LXC/K8s）、共享库劫持（LD_PRELOAD/LD_LIBRARY_PATH/RPATH）、敏感文件与凭据（历史文件/SSH密钥/数据库凭据/.git泄露）、NFS/SMB/网络服务（no_root_squash/MySQL UDF/PostgreSQL RCE）、eBPF提权（JIT喷射/verifier绕过/CVE-2020-8835~CVE-2023-2163）、Systemd服务滥用、自动化工具链（LinPEAS/LinEnum/pspy/traitor）、5个完整实战案例

### 2. Windows 提权全栈技能（新建）

- 文件：`/workspace/skills/windows-privilege-escalation/SKILL.md`（2654 行）
- 14 大技术域：信息收集（systeminfo/whoami/进程/服务/补丁/注册表）、服务权限滥用（弱权限/未引用路径/服务注册表/PowerUp.ps1）、计划任务提权、注册表提权（AlwaysInstallElevated/MSI/IFEO映像劫持）、令牌窃取（PrintSpoofer/RoguePotato/JuicyPotato/GodPotato/EfsPotato/SweetPotato）、内核漏洞（MS16-032/MS17-010/CVE-2020-0787~CVE-2024-26234/2025-2026 CVE）、UAC绕过（fodhelper/computerdefaults/sdclt/eventvwr/silentcleanup/CMSTP/WSReset/UACME）、AppLocker/Defender绕过（LOLBAS/MSBuild/InstallUtil/AMSI）、凭据提取（mimikatz/LSASS/SAM/DPAPI/浏览器密码/LaZagne/SharpDPAPI）、DLL劫持（搜索顺序/Phantom DLL/COM劫持）、域提权（Kerberoasting/AS-REP/ACL/ADCS ESC1-8/PrintNightmare/ZeroLogon/DCSync/Golden-Silver-Diamond Ticket）、2026最新（Win11 24H2/Credential Guard绕过/PPLdump/Nanodump/VBS降级/Windows Recall提权）、自动化工具链（WinPEAS/Seatbelt/SharpUp/PrivescCheck/PowerUp/Sherlock/Watson）、3组完整实战案例

### 3. 云安全渗透测试技能（新建）

- 文件：`/workspace/skills/cloud-security-pentesting/SKILL.md`（2696 行）
- 12 大技术域：AWS攻击矩阵（IAM 7条提权链/AssumeRole/CloudFormation/Lambda/S3/CloudTrail/GuardDuty/EC2元数据IMDSv2/组织账号/Route53）、Azure攻击矩阵（Managed Identity/应用注册/KeyVault/AzureAD Connect/Blob/Functions/LogicApps/GraphAPI/跨租户）、GCP攻击矩阵（服务账号/组织策略/CloudFunctions/BigQuery/Cloud Storage/Compute Engine/Cloud Build/Workload Identity）、阿里云攻击矩阵（RAM角色/OSS/FC函数/容器服务/API网关/日志服务/云安全中心）、云存储攻击（S3/GCS/Blob/OSS桶枚举/公开访问/版本历史/CloudFront-CDN/策略操纵）、元数据服务攻击（IMDSv1/v2/SSRF/令牌窃取/绕过IMDSv2/容器元数据/云函数元数据）、Serverless攻击（Lambda/Cloud Functions/Azure Functions注入/事件源投毒/依赖劫持/冷启动/层投毒）、K8s攻击（RBAC/ServiceAccount/etcd/API Server/准入控制器/Kubelet/Pod逃逸/NetworkPolicy/Istio/Envoy）、容器攻击（Docker Socket/privileged/runc CVE-2024-21626/BuildKit SSRF/镜像仓库投毒）、CI/CD投毒（GitHub Actions/GitLab CI/Jenkins/管道注入/依赖混淆/自托管Runner）、2026最新（Bedrock AI投毒/Vertex AI/阿里云灵积/Cloudflare Workers/Edge Computing/WebAssembly/5G多云）、云安全工具链（ScoutSuite/Prowler/pacu/AzureHound/CloudMapper/trivy/kube-bench/kube-hunter）

### 4. 密码攻击与凭据获取技能（新建）

- 文件：`/workspace/skills/password-attacks-credential-access/SKILL.md`（3037 行）
- 15 大技术域：在线密码攻击（Hydra/Medusa/Ncrack多协议/HTTP2+QUIC攻击）、离线Hash破解（Hashcat 2026规则引擎/John/字典生成Crunch/CeWL/Kwprocessor/AI辅助/分布式破解Hashtopolis/K8s/彩虹表）、密码喷射攻击（SprayingToolkit/MailSniper/域/O365 AzureAD/MFA绕过/智能锁定策略）、Windows凭据（SAM/SYSTEM/LSASS dump/mimikatz/Credential Guard对抗/DPAPI/浏览器密码/LaZagne/DCSync/NTDS.dit）、Linux凭据（shadow破解/SSH密钥/历史文件/配置文件/进程环境变量/tcpdump嗅探）、Kerberos攻击（Kerberoasting/AS-REP Roasting/Golden-Silver-Diamond-Sapphire Ticket/委派攻击/PAC签名绕过）、NTLM攻击（Responder/ntlmrelayx/Inveigh/强制认证PetitPotam/PrinterBug/DFSCoerce/ADCS ESC1-8）、PtH/PtT（9种工具链/Overpass/凭据传递自动化）、2026最新（AI密码猜测/LLM模式学习/量子计算威胁/Passwordless绕过/FIDO2/WebAuthn/Passkey攻击/生物特征Hash提取）、凭据存储安全（密码管理器/AWS-Azure-GCP SecretsManager/GitHub泄露/容器镜像）、无线网络（WPA2/WPA3/PMKID/Hashcat 22000/WPS PIN/Evil Twin/KRACK）、自动化工具链（CrackMapExec/NetExec/BloodHound/SharpHound/PlumHound）、完整实战攻击链（密码喷射→Kerberoasting→Hash破解→PtH横向→DCSync→DC控制）

### 5. 持久化机制技能（新建）

- 文件：`/workspace/skills/persistence-mechanisms/SKILL.md`（3825 行）
- 12 大技术域：Windows持久化（22种技术：注册表Run/RunOnce/服务/计划任务/WMI/启动文件夹/DLL劫持/COM劫持/AppInit_DLLs/BITS/SSP/LSA/凭据提供者/打印监视器/Time Providers/Office加载项/屏幕保护/IFEO/AppCert DLLs/Netsh Helper/Svchost劫持/PE注入/Winlogon）、Win11 24H2新持久化（WSL/Windows Terminal/Sandbox/Recall/Dev Home/Copilot）、Linux持久化（12种：crontab/systemd/rc.local/.bashrc/SSH/MOTD/PAM/LD_PRELOAD/LKM/init.d/桌面文件/APT钩子/udev/系统二进制）、macOS持久化（LaunchDaemons/Agents/Login Items/Periodic Scripts/Emond/Authorization Plugins/QuickLook/Zsh）、C2框架（Sliver/Cobalt Strike/Havoc/Merlin/Mythic/域前置/CDN/DoH-DoT/社交媒体C2/GitHub C2/Dead-Drop）、2026最新（eBPF内核级/K8s DaemonSet/容器镜像层/Serverless/AWS Lambda层/Azure Functions/CI-CD管道/GitHub Actions/WebAssembly/EDR白名单/固件UEFI/BIOS/SMM）、Rootkit（用户态LD_PRELOAD/内核态LKM/eBPF Rootkit/文件隐藏/进程隐藏/网络隐藏/键盘记录/驱动级/固件级）、检测绕过（时间延迟/环境键控/反沙箱/反分析/反取证/日志清理/时间戳篡改/ADS/注册表偏移）、WebShell持久化（PHP/ASPX/JSP/Java内存马/Nginx模块/Apache模块/IIS模块/计划任务触发/心跳检测/多级代理）、检测与清除（Autoruns/Sysinternals/EDR规则/Sigma/YARA/内存取证）、自动化工具链（SharPersist/PowerSploit/PowerView/SharpStay/Hidden/Totem/LaZagne）、完整实战攻击链（NTLM中继→RCE→凭据提取→5层持久化→C2上线→横向移动→7种域控持久化）

### 6. 四个核心技能 2026 深度强化

对4个核心技能追加"2026 最新攻击技术"章节，共计新增约 2,500 行内容：

**deserialization-insecure**（2863行，+约500行）：
- AI模型反序列化攻击（CVE-2026-31428 PyTorch 2.6 pickle RCE/CVE-2026-29115 HuggingFace safetensors绕过/ONNX Runtime注入/TensorFlow SavedModel后门/MLflow投毒）
- 云原生反序列化（AWS Lambda层投毒/Google Cloud Run/阿里云FC/Azure App Service）
- 2026新Gadget链（Jackson 2.18+ CVE-2026-27391/Fastjson 2.0.54+ CVE-2026-31208/SnakeYAML 2.3+/Hessian 4.0+/Spring Boot 3.4+ Actuator）
- 反序列化WAF绕过（JSON嵌套/Unicode/YAML标签混淆/XML实体/Content-Type变换/分块编码/HTTP2多路复用）
- AI辅助Gadget链发现（LLM驱动/符号执行/代码属性图分析/Semgrep规则）

**ssrf-server-side-request-forgery**（1319行，+约450行）：
- 云元数据新攻击面（AWS IMDSv2多跳绕过/Azure Managed Identity 2026端点/GCP/阿里云ECS RAM Role/OCI）
- AI/LLM服务SSRF（OpenAI API/ChatGPT插件/Claude MCP/向量数据库Chroma/Qdrant/Weaviate/LLM提示注入→SSRF链）
- 云原生SSRF（K8s API Server/容器运行时/Serverless/CI/CD Runner/GitHub Actions）
- 2026绕过新技巧（IDN同形异义/IPv6嵌入式IPv4/Unix Socket/gopher/HTTP3 QUIC/IPFS）
- CVE-2026-3142+CVE-2026-33697配合SSRF利用链

**request-smuggling**（1594行，+约400行）：
- HTTP/3 QUIC走私（CVE-2026-2833/2835/2836 Pingora系列/QUIC流走私/HTTP3→HTTP1.1降级/连接迁移滥用/0-RTT重放）
- 浏览器HTTP/2走私（Fetch API客户端走私/ORIGIN帧滥用/HPACK动态表投毒/Stream优先级/Server Push）
- 边缘计算走私（Cloudflare Workers/Vercel Edge/Netlify Edge/Deno Deploy/EdgeSmugglingScanner）
- 2026新变体（WebSocket走私/gRPC-HTTP走私/GraphQL走私/多CDN链走私/缓存投毒+走私组合）
- AI驱动走私检测（LLM辅助变异生成/AutomatedSmugglingDetector/AdaptiveSmugglingGenerator）

**websocket-security**（3083行，+约450行）：
- AI流式WebSocket攻击（ChatGPT流式窃听/Claude流式API劫持/LLM推理WebSocket窃听/流式注入）
- WebSocket over HTTP3（QUIC WebSocket/0-RTT滥用/QUIC连接迁移劫持/QPACK投毒）
- 2026认证绕过（JWT过期重放/OAuth2 WebSocket/Token绑定绕过/Session固定/Cookie→WebSocket升级认证迁移）
- 云原生WebSocket攻击（K8s exec WebSocket/API Gateway/Lambda WebSocket/GraphQL Subscription）
- 2026 CVE（CVE-2026-40089 socket.io DoS/CVE-2026-25123 Phoenix Channels/CVE-2026-19876 Spring WebSocket）

## 技能总数变化

| 变更 | 技能数 |
|------|--------|
| 上一轮结束 | 99 |
| linux-privilege-escalation 新建 | 99→100 |
| windows-privilege-escalation 新建 | 100→101 |
| cloud-security-pentesting 新建 | 101→102 |
| password-attacks-credential-access 新建 | 102→103 |
| persistence-mechanisms 新建 | 103→104 |
| 4个核心技能2026强化 | 104 |
| **本轮结束** | **104** |

## 新增/强化内容总行数

| 技能 | 行数 | 类型 |
|------|------|------|
| linux-privilege-escalation | 3,244 | 新建 |
| windows-privilege-escalation | 2,654 | 新建 |
| cloud-security-pentesting | 2,696 | 新建 |
| password-attacks-credential-access | 3,037 | 新建 |
| persistence-mechanisms | 3,825 | 新建 |
| deserialization-insecure | ~500 | 强化 |
| ssrf-server-side-request-forgery | ~450 | 强化 |
| request-smuggling | ~400 | 强化 |
| websocket-security | ~450 | 强化 |
| **合计** | **~17,256** | |
