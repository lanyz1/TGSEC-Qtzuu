# 案例课：RuoYi-Vue-Plus — 匿名 getToken 固定会话

> 脱敏。会员 App API 前置「设备初始化」接口误绑真实会员。

## 模式

```text
GET /api/getToken   （无 Cookie/无凭据）
→ 固定 token 绑定某推广/根会员
→ Authorization: <token>  （带 Bearer 反而 401）
→ getInviteData 等一次性拖全站下线 PII
→ refreshToken 续期 7 天
```

并行：`/prod-api/v3/api-docs` 全量；demo 模块未授权；SQL 异常回显库名/Mapper。

### 指纹

RuoYi-Vue-Plus 版本条；`/api/getToken` 返回固定 `data.token`；App 头不用 Bearer。

### 修复

匿名只发无身份设备票；禁止绑定真实 memberId；关闭 api-docs/demo；统一异常。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
