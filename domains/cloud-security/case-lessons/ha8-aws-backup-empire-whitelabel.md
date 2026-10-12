# 哈希8 AWS 备份桶帝国课（白标家族总入口）

- Source report: 报告包 20261012（HA8 战役档案 `CONTINUE_ROUND` / `STATUS_NOW_20261009_aws`；值零入库）
- Techniques: s3-backup-empire, whitelabel-family, oss-takeover
- Fused: 2026-10-12

## 模式

云 AK 泄露（AWS root AK）→ **70+/74 个 S3 桶 = 白标家族备份帝国**：宝塔式备份含 MySQL dump + 整站 + jar；**单个 jar 内嵌 40+ 品牌配置** → **备份桶是比源站更完整的入口**（可替代源站取全部源码与数据面）

## 要点

- 备份桶发现法：AK 到手 → 桶清单枚举 → 命名规律（品牌/环境后缀）→ 备份结构（`exports` + dump + jar 三件套）
- 与「SaaS 备份桶全库」同族（`saas-backup-bucket-full-db-offline`）：**对象存储 = 多租户数据总入口 → 云侧 AK 是第一优先目标**
- 独立漏洞面（主报告 §50/§51）：**未授权文件上传到公开 S3** · **阿里云 OSS bucket takeover**（桶名劫持）
- AK 分级：子账号 AK → 账号级 root 升级路线（AK 能力盘点优先于单点利用）

## 对照

- `object-storage-exposure` · `anonymous-object-storage-access` · `cloud-security-audit`
- 资金侧铁律衔接：备份桶给"数据面"，链上私钥/签名机是独立边界（控制面失陷 ≠ 资金失陷）

@TGSEC社区 · @TGSEC-Qtzuu 整理
