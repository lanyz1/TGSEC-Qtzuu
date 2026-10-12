# ghgc .189 主机 root 链课（RuoYi sys_job → MUDb → cron.d）

- Source report: 报告包 20261012（HA8 战役档案 `ROOT_CHAIN` / `ROOT_SHELL` / `CONTINUE_ROOT_189`；**载荷细节不录，值零入库**）
- Techniques: ruoyi-sysjob, jndi, tomcat-mudb, cron-persistence
- Fused: 2026-10-12

## 链（NEW — 全库首见组合）

1. **WAF 只查 HTTP 层** → 绕过 sys_job 白名单的正确姿势 = **直写数据库**（拿到库写权限后直接改表）
2. `job/run` 触发时**从 DB 重读任务、不再校验** → invoke_target 改写即生效
3. JNDI 注入 → **Tomcat MemoryUserDatabaseFactory（MUDb）**
4. MUDb `pathname` 参数：**`http://` 前缀 + 路径穿越 → 任意文件写**
5. 障碍处理：需先用代码生成器（gen_path）以 root 权限建出 `http:` 中间目录
6. 写入 `/etc/cron.d/*` → **root shell**
7. **坑**：cron 内容经 role 名换行注入；Tomcat 会把引号转义 → **命令不能带引号**
8. 实测障碍表：CC 链死 / Tomcat forceString 已移除 / Java 8u421 限制 → 弃 EL 路线换 MUDb
9. SSH 直连 + cron 持久化收尾

## 判据/对照

- 近亲路线：EL/JdbcRowSetImpl（见 `ruoyi-quartz-whitelist-bypass-el-rce`）vs 本链 MUDb 文件写——**后者不依赖 EL 解析器存活性**
- 前提 = 已有库写权限（本战经 TP5→MySQL + RuoYi 后台达成）
- **对手清场画像**（反例教训）：扫 /etc/cron.d、systemd、ld.so.preload、pam.d，**不碰业务目录与 rc.local/profile.d** → 持久化设计别只铺"常见路径"

## 诚实卡点

后门 v1 被清 → 重植 v2；包内**无「已清理」证据**（第三方系统残留按 IR 流程核验，不视为闭环）；结案口径 = root 未形成「耐久、授权移交」

@TGSEC社区 · @TGSEC-Qtzuu 整理
