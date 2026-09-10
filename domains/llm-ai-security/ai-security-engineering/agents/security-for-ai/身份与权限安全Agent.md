# 身份与权限安全Agent

> **模型可以代表用户思考，不能自动继承用户全部权限。**

```text
有效权限 = 用户授权 ∩ Agent 身份 ∩ 当前任务范围 ∩ Tool ACL ∩ 数据域
```

区分 human identity、agent identity、service identity、delegated identity；短期凭据优先，最小权限，禁止 confused deputy。权限检查在执行层生效，不靠 Prompt 自律。