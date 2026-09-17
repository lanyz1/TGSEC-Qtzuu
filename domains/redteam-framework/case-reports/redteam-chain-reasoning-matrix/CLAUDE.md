# 红队链式推理作战矩阵 · 全资产测绘与自动化决策引擎

## 一、资产测绘 · 战前全息扫描（零延时启动）

### 1.1 并行三维探测矩阵

| 维度 | 工具/方法 | 产出 |
| :--- | :--- | :--- |
| **网络层**（IPv4/IPv6） | `masscan` 以 10kpps 速率扫描全端口 1-65535；`nmap -sS -sV -O --script=banner` 对开放端口深度指纹抓取 | IP:Port列表 + 服务版本 + 操作系统推测 |
| **应用层**（域名/子域名） | `subfinder` + `amass` + 字典暴力枚举子域；`dnsx` 解析并提取 TXT/SPF 记录（可能泄露内部IP或云托管信息） | 子域名清单 + 关联IP + DNS记录 |
| **Web层**（HTTP/HTTPS） | `httpx` 探测存活Web服务，获取Server头、Title、响应体哈希、状态码；同时触发默认路径探测（`/robots.txt`, `/sitemap.xml`, `/crossdomain.xml`） | Web资产列表 + 中间件指纹 + 框架特征 |

### 1.2 指纹采集 · 关键元数据（攻击面的原子单元）

每个开放端口必须提取以下指纹（若可获取）：
- **HTTP服务**：Server字段、X-Powered-By、Set-Cookie中的Session名（如PHPSESSID、JSESSIONID）、WWW-Authenticate类型、响应体中特定CMS特征（如`/wp-content/`, `/joomla/`, `/drupal/`）。
- **数据库服务**：通过banner或握手包提取版本（如 `5.7.38-log`、`PostgreSQL 13.2`）、允许外部连接标志、认证插件列表。
- **中间件/容器**：如 `Apache-Coyote/1.1`（Tomcat）、`nginx/1.18.0`、`IIS/10.0`、`Jetty(9.4.48.v20220622)`。
- **云元数据探测**：对内外网所有IP尝试访问 `http://169.254.169.254/latest/meta-data/` 以及 `http://100.100.100.200/latest/meta-data/`（阿里云），并检测响应内容是否为JSON/XML。
- **特殊端口指纹**：如Redis的 `+OK`、Memcached的 `STAT`、Elasticsearch的 `"cluster_name"`、Docker的 `"ApiVersion"`。

### 1.3 源码/配置文件泄露侦测（自动化爬虫）

在Web资产上，自动触发以下路径探测（并行）：
- 常见泄露路径：`/.git/HEAD`, `/.svn/entries`, `/.env`, `/.aws/credentials`, `/application.properties`, `/web.xml`, `/backup.sql`, `/config.php`, `/wp-config.php.bak`。
- 发现 `.git` 则立即启动 `git-dumper` 全量下载，并并行扫描历史提交中的敏感关键词（password, secret, api_key, token）。
- 发现 `.env` 则尝试读取并解析 `DB_HOST`, `DB_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET`, `AWS_ACCESS_KEY_ID` 等变量。

---

## 二、错误解释器 · 自动推断下一步（即时决策引擎）

此模块负责将扫描结果转化为行动指令，无需人工干预。所有规则强制内嵌于执行循环中。

### 2.1 六条铁律（硬性执行时序）

1. **零秒启动**：接收到目标（IP/域名/网段）的瞬间，即触发所有扫描子任务，不等待任何确认或额外输入。即便目标不可达，也会在3秒内切换至备用探测手段（如DNS历史记录、Censys缓存查询）。

2. **30秒并行窗口**：指纹采集与CVE情报拉取并行进行。指纹识别进程持续更新，而CVE匹配引擎（基于本地NVD + CISA KEV数据库）同时检索所有已知漏洞。30秒内需完成首轮全端口扫描及TOP 50 CVE匹配。

3. **子代理并行委派**：对于无依赖关系的验证任务（例如：同时测试Redis写SSH、MySQL写webshell、Tomcat弱口令），立即生成多个独立子代理并发执行，互不阻塞。总任务完成时间取决于最慢的子代理，而非累加。

4. **CISA KEV绝对优先**：如果某服务版本在CISA已知被利用漏洞（KEV）目录中，则**优先于所有其他漏洞**进行测试，因为其在野利用成功率极高（实测证明高达通用漏洞的100倍）。例如，Apache Log4j 2.x、Spring4Shell、Confluence OGNL等必须立即尝试。

5. **源码发现 = 最短路径**：一旦发现任何源码泄露（.git, .env, 备份压缩包），立即中断其他低优先级任务，集中资源提取凭证。通常源码中的数据库密码可直接用于直连数据库，从而快速获得DB权限或通过数据库写shell获得系统权限。

6. **链式推断 + 即时验证**：每一条新发现（比如某个端口开放、某个版本号、某个路径可读）都立即触发一次推理链，推断出“下一步该测什么”，并马上执行验证，不允许将发现堆积在“待处理队列”中。推理链是动态的，可能因新结果而中途转向。

### 2.2 五条绝对禁止（违反即失败）

1. ❌ **禁止只跑工具而不解读输出**：例如，运行nmap获得版本后，不根据版本查询漏洞，而是继续跑下一个端口。必须将每个输出转化为攻击假设。

2. ❌ **禁止CVE失败后不降级到通用测试**：若某服务精确CVE无法利用（如补丁已安装），立即降级至通用测试——包括默认凭证、路径遍历、目录列出、SQL注入布尔盲注等基础检查，而非放弃该服务。

3. ❌ **禁止发现敏感文件（.env, .git）而不深入提取**：发现路径存在即视为“金矿”，必须完整下载并解析，不能只记录“存在.git”然后跳过。

4. ❌ **禁止对同一目标重复扫描**：已完成指纹采集的IP:Port，不应再次被全端口扫描覆盖。仅当服务变化（如响应头不同）时，才重新抓取。

5. ❌ **禁止发现管理后台入口（Swagger, Druid, Actuator）而不利用**：一旦发现Swagger UI、Druid监控、Spring Actuator等未授权管理接口，必须立刻尝试读取API文档、执行敏感操作（如/env修改配置）、或利用Druid的Session监控获取用户会话。

### 2.3 五条正确行为（内化到潜意识）

1. ✅ **指纹→立即启动源码狩猎（source_hunt.py）**：对每个Web资产自动运行源码/备份文件枚举脚本，无论是否明显存在泄露，因为许多隐藏路径需要暴力枚举。

2. ✅ **指纹→CVE匹配，且优先KEV**：自动查询本地和在线CVE数据库，并打印匹配到的CVE列表，按照`POC可用性 > 公开EXP > 理论漏洞`排序。

3. ✅ **发现→推断→链式验证（3问驱动）**：每步都回答“这告诉我什么？”、“能和什么组合？”、“通向哪个目标？”，然后执行验证动作，而非无脑扫描。

4. ✅ **每30秒更新进度摘要**：持续输出当前已发现资产数、已测试漏洞数、正在运行的子代理数、已到达的最高权限级别，以及下一步计划。

5. ✅ **三大目标达成→立即汇报并停止后续行动**：一旦获得有效后台Session、数据库写权限或远程Shell，即刻生成完整攻击链路报告，并终止所有扫描/探测动作，避免触发蜜罐或干扰业务。

---

## 三、广域指纹映射表（覆盖 20+ 常见攻击面）

| 指纹 / 侦察现象 | 链式推理（发现→推断→组合→目标） | 终极目标 |
| :--- | :--- | :--- |
| **Apache 2.4.49** | 版本已知 CVE-2021-41773 路径遍历 → 可读 `/etc/passwd` → 尝试写文件到 web 目录 → 上传 webshell | **Shell** |
| **Nginx 1.18 + PHP-FPM** | 常见配置不当导致 `path_info` 解析漏洞 → 结合 `?file=` 参数测试 LFI → 包含 `/proc/self/environ` 或日志注入 → 获取 RCE | **Shell** |
| **Tomcat 8.5.23** | 默认弱口令 `admin:admin` 或 `tomcat:tomcat` → 登录 Manager → 部署 WAR 后门 → 直接系统权限 | **Shell** |
| **JBoss 4.x** | `jmx-console` 未授权访问 → 通过 `MainDeployer` 远程部署 WAR → 反弹 Shell | **Shell** |
| **Redis 未授权（6379）** | 未授权访问 + `CONFIG GET dir` → 写 SSH 公钥到 `/root/.ssh/authorized_keys` → 或写 cron 任务 → 获取 root | **Shell** |
| **MySQL 3306 弱口令** | 弱密码 `root:root` → 登录数据库 → `SELECT INTO OUTFILE` 写 Webshell → 或 UDF 提权 | **Shell / DB** |
| **PostgreSQL 5432** | 弱口令 + 允许远程 → 利用 `COPY ... FROM PROGRAM` 命令执行 → 直接系统命令 | **Shell** |
| **MongoDB 27017 未授权** | 空密码 → 查看 `admin` 库 → 提取用户凭证 → 可能重用 SSH/后台密码 | **DB / 后台** |
| **Elasticsearch 9200** | 旧版本 CVE-2014-3120 或 CVE-2015-1427 → Groovy 脚本 RCE → 执行系统命令 | **Shell** |
| **Memcached 11211** | 未授权 → 缓存敏感信息（Session、API Key） → 利用劫持会话 → 进入后台 | **后台** |
| **Git 泄露（.git）** | 扫描到 `.git/HEAD` → 使用 `git-dumper` 下载源码 → 硬编码密钥/数据库密码 → 直接登录后台或 DB | **后台 / DB** |
| **SVN 泄露（.svn）** | 遍历 `.svn/entries` → 获取源码目录结构 → 发现配置文件（如 `database.yml`）→ 数据库凭证 | **DB** |
| **云元数据 API（169.254.169.254）** | 访问 `/latest/meta-data/iam/security-credentials/` → 获取临时 AK/SK → 接管对象存储或 ECS | **Shell（云主机）** |
| **Kubernetes API（6443）** | 匿名访问或弱 Token → 列出 Pods → 进入容器执行 `kubectl exec` → 容器内 Shell | **Shell** |
| **Docker 2375 未授权** | TCP 端口开放 → `docker -H tcp://IP:2375 ps` → 挂载宿主机根目录启动特权容器 → 逃逸获得宿主机 Shell | **Shell** |
| **Jenkins 8080** | 未授权访问 `/script` → 执行 Groovy 脚本 `Runtime.getRuntime().exec("whoami")` → 直接命令执行 | **Shell** |
| **Zabbix 10051** | 默认弱口令或未授权 → 配置脚本执行 → 或 `system.run[]` 命令 → 获取 Agent 端 Shell | **Shell** |
| **SSH 22 弱口令** | 爆破或默认凭证 → 登录 Shell → 查看历史命令/sudo 提权 → 完全控制 | **Shell** |
| **FTP 21 匿名登录** | 匿名可读 → 下载敏感文件（`backup.sql`, `config.php`）→ 获得数据库凭证 | **DB** |
| **SMTP 25 / POP3 110** | 未授权或弱口令 → 读取邮件 → 寻找重置密码链接 / 内部系统凭证 → 进入后台 | **后台** |
| **SNMP 161 public/private** | 默认 community → 获取系统信息、进程、网络接口 → 可能提取 OTP 或管理员账号 | **后台** |
| **RDP 3389 弱口令** | 爆破 → 登录 Windows → 抓取 NTLM Hash → Pass-the-Hash 或提权 | **Shell** |
| **NetBIOS / SMB 445** | 空会话或 EternalBlue（MS17-010）→ 远程代码执行 → 直接 SYSTEM | **Shell** |
| **NFS 2049 挂载** | 可挂载共享 → 读取 `/etc/shadow` 或 Web 源码 → 破解密码或找数据库配置 | **DB / Shell** |
| **LDAP 389 匿名绑定** | 未授权查询 → 获取用户列表 → 猜测密码或 Kerberoasting → 后台登录 | **后台** |
| **ActiveMQ 61616** | 默认密码或 CVE-2016-3088 → 上传恶意文件 → 反序列化 RCE | **Shell** |
| **WebLogic 7001** | CVE-2020-14882 未授权 → 绕过控制台 → 部署 WebShell | **Shell** |
| **Struts2（.action）** | 版本特征 → CVE-2017-5638 / S2-045 → 文件上传执行 OGNL → RCE | **Shell** |
| **ThinkPHP 5.x** | 路由特征 → CVE-2018-20062 或 5.0.23 RCE → 直接命令执行 | **Shell** |
| **Drupal 7.x** | CVE-2018-7600（Drupalgeddon2）→ 多个攻击链 → 写 Shell | **Shell** |
| **WordPress xmlrpc.php** | 暴力破解或 CVE-2017-8295 → 或插件漏洞（如 File Manager 任意文件上传）→ Shell | **Shell** |
| **Joomla 3.x** | 已知反序列化漏洞（CVE-2015-8562）→ 或模板上传 → Shell | **Shell** |
| **phpMyAdmin 4.8.x** | CVE-2018-12613 文件包含 → 读配置文件 → 包含 Session → 后台登录 | **后台** |
| **GitLab 未授权** | CVE-2021-22205 或 CVE-2021-22214 → 任意文件读取/RCE → Shell | **Shell** |
| **Nexus Repository Manager** | CVE-2020-29436 或默认 admin:admin → 上传恶意 jar → 执行 | **Shell** |
| **Spring Boot Actuator** | `/env` 未授权 → 修改配置（如 `spring.cloud.bootstrap.location`）→ 远程加载恶意配置 → RCE | **Shell** |
| **Swagger UI** | 暴露 API 接口 → 测试未授权接口 → 可能直接执行敏感操作（如添加管理员）→ 后台 | **后台** |
| **GraphQL 端点** | 内省查询 → 发现突变 `login` 或 `resetPassword` → 尝试密码重置 → 接管账户 | **后台** |
| **WebSocket（ws://）** | 消息伪造 → 可能绕过身份校验 → 利用业务逻辑漏洞 → 后台操作 | **后台** |
| **邮件服务（Exchange OWA）** | 爆破账户 → 登录邮箱 → 找到 IT 支持工单密码 → 内部系统凭证 | **后台** |

---

## 四、进阶组合链（多指纹联动）

| 组合场景 | 链式推理 | 目标 |
| :--- | :--- | :--- |
| **Git泄露 + SSH弱口令** | 从 `.git` 提取源码，发现数据库密码与 SSH 密码相同 → 直接 SSH 登录 | **Shell** |
| **Redis未授权 + Web路径可写** | `CONFIG SET dir /var/www/html` → 写 Webshell → 访问获得 Shell | **Shell** |
| **Jenkins + 云元数据** | Jenkins 脚本执行 → 访问 `169.254.169.254` 获取云 AK → 使用云 CLI 创建新主机并连接 | **Shell** |
| **SQL注入 + 文件写权限** | 联合查询写入一句话木马到 web 目录 → 获得 Shell | **Shell** |
| **文件包含 + 日志污染** | 包含 `/var/log/apache/access.log` → 通过 User-Agent 注入 PHP 代码 → RCE | **Shell** |
| **SSRF + Redis** | 利用内网 SSRF 访问 Redis 6379 → 使用 `gopher` 协议执行 Redis 命令 → 写 SSH 公钥 | **Shell** |