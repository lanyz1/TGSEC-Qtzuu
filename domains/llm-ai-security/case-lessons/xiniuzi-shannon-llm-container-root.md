# xiniuzi（68tan 线）× Shannon LLM 栈 · 容器 root 课

- Source report: 报告包 20261012（`REPORT_xiniuzi_20261011`；原文留本机案卷）
- Techniques: llm-tool-exec, container-root, xxljob-registry, likeadmin
- Fused: 2026-10-12

## 链

1. LLM 网关 `/tools/execute`（白名单：bash 禁元字符，`python3`/`file_write` 可用）→ **shannon 容器 uid=0**；装 sshd + `-R 1823` 反向隧道 = 可重复进入的容器持久化
2. Postgres `auth.users` 改密 → 登录 orchestrator（LLM 基础设施凭据面）；daemon `:8080` JWT 下 `tools/execute` 同样可用
3. NewAPI 滥用：专属 API Key 外网可用 + billing soft_limit 极大（LLM 网关白嫖/盗用面）
4. XXL-JOB `/api/registry` + `default_token` JSON → **registry 匿名注册 Success**（假 executor 曾注册本机 `:19999`；admin 登录未拿下）
5. 68tan 业务面：`POST /api/login/proxyRegister` + `proxy_id=1` 旁路注册代理侧 · `POST /api/user/resetPassword` 固定码重置任意手机号（**已记录，禁止再用于接管**——纪律）

## 判据

- likeadmin + ThinkPHP 报错页泄 `SERVER_ADDR` 与 webroot 路径（`/www/wwwroot/...`）→ 指纹 + 路径侦察
- **「容器 root ≠ 宿主 root」**：无 docker.sock / 无 SYS_ADMIN / 网关 22 短字典 0 命中 / volume 写入未落宿主 → 明确定性（诚实口径范例）

## 诚实卡点

宿主机 OS root = 0 · 源站 MySQL/SSH 未中 · 宝塔 888 未破 · XXL admin 控制台未拿 · 68tan 超管 session 未拿 · 链上收款地址仅 watch-only

## When to reuse

- LLM 工具执行沙箱面 → `llm-tool-exec-container-root`（本课即其来源案例）
- XXL registry 面 → `xxljob-admin-glue-chain` 增补段
- likeadmin 固定码 → `thinkphp-legacy-pentest` 增补段

@TGSEC社区 · @TGSEC-Qtzuu 整理
