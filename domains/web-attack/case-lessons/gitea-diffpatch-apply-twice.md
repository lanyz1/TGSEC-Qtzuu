# Gitea diffpatch 的"apply 两次"暗门 (OneChat 案)

**链**: GEOFlow 弱口令 admin/admin888 → 文档后台; Gitea (26.4 :3003) 有可用账号 → CVE-2026-60004 diffpatch 写 Git hook → 容器内命令执行

## 关键坑 (必记)
- **同一 hook 需 apply 两次才触发** (第一次生成、第二次生效) — 只打一次会误判"漏洞不存在"
- s6 + su-exec 环境: 命令以 uid=70 执行, 提不到容器 root
- PG 5432 公网 + geoflow 超管 → `COPY FROM PROGRAM` 容器内执行; 后期 pg_hba 收窄 (Docker 网段+操作员IP)

## 容器逃逸失败条件清单 (uid=70 场景)
- 无 docker.sock / 无 SYS_ADMIN / cgroup+core_pattern 只读 / 不能 mknod → 全堵死
- 附: PHP-FPM 改 user=root → FPM 直接崩溃 (勿在生产乱改)

## 教训
- Gitea diffpatch: **打两次**; 先验证 hook 触发 (写 beacon 文件) 再上载荷
- 容器逃逸先列"条件面"再选路径, 不硬撞
