# 红队链式推理作战矩阵

- Source report: `CLAUDE.md`
- Full report: `domains/redteam-framework/case-reports/redteam-chain-reasoning-matrix/CLAUDE.md`
- Techniques: recon
- Fused: 2026-09-17

## Key findings (distilled)

- 发现 `.env` 则尝试读取并解析 `DB_HOST`, `DB_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET`, `AWS_ACCESS_KEY_ID` 等变量。
- 秒并行窗口**：指纹采集与CVE情报拉取并行进行。指纹识别进程持续更新，而CVE匹配引擎（基于本地NVD + CISA KEV数据库）同时检索所有已知漏洞。30秒内需完成首轮全端口扫描及TOP 50 CVE匹配。
- 子代理并行委派**：对于无依赖关系的验证任务（例如：同时测试Redis写SSH、MySQL写webshell、Tomcat弱口令），立即生成多个独立子代理并发执行，互不阻塞。总任务完成时间取决于最慢的子代理，而非累加。
- CISA KEV绝对优先**：如果某服务版本在CISA已知被利用漏洞（KEV）目录中，则**优先于所有其他漏洞**进行测试，因为其在野利用成功率极高（实测证明高达通用漏洞的100倍）。例如，Apache Log4j 2.x、Spring4Shell、Confluence OGNL等必须立即尝试。
- ❌ **禁止只跑工具而不解读输出**：例如，运行nmap获得版本后，不根据版本查询漏洞，而是继续跑下一个端口。必须将每个输出转化为攻击假设。
- ❌ **禁止发现管理后台入口（Swagger, Druid, Actuator）而不利用**：一旦发现Swagger UI、Druid监控、Spring Actuator等未授权管理接口，必须立刻尝试读取API文档、执行敏感操作（如/env修改配置）、或利用Druid的Session监控获取用户会话。
- ✅ **指纹→立即启动源码狩猎（source_hunt.py）**：对每个Web资产自动运行源码/备份文件枚举脚本，无论是否明显存在泄露，因为许多隐藏路径需要暴力枚举。
- ✅ **指纹→CVE匹配，且优先KEV**：自动查询本地和在线CVE数据库，并打印匹配到的CVE列表，按照`POC可用性 > 公开EXP > 理论漏洞`排序。

## When to reuse

- 同类标签命中：recon
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
