# 真假分离 + 逻辑推理侦察

> 原则：先找**矛盾点与诱饵面**，再锁定**真实总后台/资金入口**。  
> 不要把「看起来像后台的壳」当成整站架构。

## 何时用

- 多套登录页、多套 `/admin`、文档与 JS 不一致  
- 演示站 / 假面板 / 静态壳 + 真 API 分离  
- 支付/TG 业务系统，正门很硬、旁门很乱  

## 步骤

```text
1. 枚举入口：www / app / admin / api / m / platform / static
2. 标「诱饵」：纯静态、文档站、过期 demo、无真实 API 的 SPA
3. 找矛盾：
   - 文档写的路径 vs JS bundle 真实 path
   - 登录成功域 vs 业务 API 域
   - 有 CSRF 的面 vs 无 token 的 JSON API
   - GET 严校验 vs POST/export/upload 松
4. 锁定「真总后台 / Crown 面」：
   - 支付 settings、TRC20/ABA、结算 QR
   - 租户管理、export、reports
   - 真鉴权中间件后面的写接口
5. 再开正逻辑或 Anti-Logic，不在诱饵面耗 80% 算力
```

## 矛盾点速查表

| 矛盾 | 含义 |
|------|------|
| 页面有 admin，API 在另一 host | 真入口在 API 域 |
| init_data 文档很严，register 可空 | 状态机旁路 |
| Bearer 文档必备，form/cookie 也能进 | 多鉴权实现不一致 |
| /admin 403，/admin/reports/export 200 | 路径级漏控 |
| 改地址字符串失败，QR 图能换 | 展示层与账务层分离 |

## 输出

- 资产表：诱饵 / 疑似真 / 已确认真  
- 优先测试队列：真后台与 Crown 相关接口在前  

下接：`redteam-framework/anti-logic-layout.md`



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
