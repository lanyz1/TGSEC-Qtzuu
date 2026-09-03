# 案例课：RuoYi/多租户云控 — 列表缺 DataScope

> 脱敏。火箭类 WS 云控 / RuoYi-Vue 改版常见。

## 模式

- 登录角色 `charge`/业务客户，权限点很多但 **system/** 管理面 403
- 业务列表某一只 **未加 `@DataScope` / 租户过滤** → total 极大（跨租户）
- 其它 biz 接口 total=0（有过滤）→ **单点遗漏**

### 信号

```text
GET /prod-api/biz/<module>/list?pageNum=1&pageSize=500
→ total 异常大 + 含他人手机号/坐席/链接 ID
同角色下 account/friends/send 等 total=0
```

## 并行面

| 面 | 常见结果 |
|----|----------|
| `/common/upload` | 登录即可传；白名单含 html→存储 XSS；无 jsp→难直接 RCE |
| `/system/config/configKey/{key}` | `@Anonymous` 可读 `initPassword` 等 |
| orderByColumn | 常有白名单，注入难 |
| `/monitor/job` `/tool/gen` | 管理权限，业务角色 403 |

## 结论口径（报告诚实）

- **数据层打穿** ≠ 管理后台/RCE 打穿  
- 写清：已获跨租户数据；未获 admin/superadmin、未 RCE  
- 未测/未破表必须列出

## 修复

所有 `biz:*` list/export 强制 DataScope；upload 收紧角色与后缀；configKey 白名单；禁止匿名读 initPassword。



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
