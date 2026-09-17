# 综合渗透测试报告 — TG 运营集群(Alanyhq / Hanqi Yang)

**测试时间:** 2026-08-03 21:00 - 2026-08-04 12:00 (UTC+8)
**授权状态:** 有书面授权(统一范围)
**运营者:** Hanqi Yang(杨汉奇)/ Alanyhq Networks Ltd + 黄永军

---

## 一、运营集群资产全景

| # | 资产 | IP | 服务 | 结果 |
|---|---|---|---|---|
| A | degaeng.fyi | 192.255.193.122 | 443 TG账号管理后台(FastAPI)+ 5100 钓鱼Bot控制台(Flask) | 5100 **已控** |
| B | tg-filter.com | 43.128.113.199 | TG筛号平台(Laravel)+ 账号农场 | **漏洞链确认**(MySQL 暂宕) |
| B2 | geekapi/app.tg-filter.com | 43.156.185.4 | 同后端,DB 正常 | 口令未破 |
| C | aispeed.ai | 103.150.215.47 | 8800 TG管理后台(NiceGUI)+ 4000 LiteLLM | LiteLLM 蜜罐确认 |
| D | ts.tg-filter.com | 150.109.94.146 | Spring Boot + ClickHouse(9000) | 口令未破 |
| E | alanyhq-global.net | 101.132.153.10 | 3389 RDP | 蜜罐桩 |
| F | IM WebSocket | 47.237.9.41:9090 | cc.tg-filter.com 硬编码 | 待侦察 |

## 二、已确认攻陷/严重漏洞

### ★ 资产A:5100 Flask 钓鱼 Bot 控制台(已控)
- 默认口令 **admin/admin123** 登录成功(明文 HTTP)
- **live Telegram Bot Token** `8899102612:AAFTaqCS3QxrZUVeh0jznxRO5ZRREz3WSW8`(@TjjdjdjjGxjjjdj_BOT "检测报告"——查号/检测 bot)
- 完全控制钓鱼配置(威胁话术、跳转链接、手机号收集)
- 会话内可无验证改密码/bot_token(账户接管持久化)

### ★ 资产B:TG筛号平台 完整账号接管链(确认)
1. **公开注册**无审核 → 任意注册
2. **注册角色提权** `role:"admin"` → 直接创建 admin(无限配额)
3. **越权访问控制** → 任何用户可读全部 15144+ TG 账号 + 代理明文凭据 + API 凭据
4. **会话导出** `POST /api/accounts/batch-export` → **真实 Telegram .session(SQLite)+ tdata 目录 ZIP** → 免密登录接管账号
- 已实证下载会话文件;MySQL 当前宕机(恢复后可批量导出)

### ★ 资产C:LiteLLM 严重配置错误 + SSRF(蜜罐确认)
- **无 master key** → 未认证 POST /key/generate 铸造有效 key
- **未认证盲 SSRF** `/search_tools/test_connection` + `/cache/settings/test`
- 8.4MB spend 日志信息泄露
- 上游 Anthropic key 失效(蜜罐特征,无实际利用价值)

## 三、守住的面(诚实记录)

| 资产 | 尝试 | 结果 |
|---|---|---|
| A:443 FastAPI | 27+ 口令 + JWT 1976 组合 + 全部绕过 | 守住 |
| B:admin/super_admin | 1049+ 口令(www+geekapi) | 守住 |
| C:8800 NiceGUI | ~1570 口令 + 无技术绕过 + 无注册流 | 守住 |
| D:ts Spring Boot | 38+ 口令 + SQLi/路径绕过 | 守住 |
| 全部 SSH | 多轮口令 | 守住 |

**核心结论:运营者所有真实面板口令均为强随机值,非可猜测。**

## 四、已确认其他发现

- 运营者身份实名:Hanqi Yang(杨汉奇,DOB 2005-09)、黄永军、Alanyhq Networks Ltd(UK #12554890)、AS41255/AS208266
- 联系:+86 15372094701 / yhq20050916@gmail.com / @alanyhq
- 蜜罐识别:LiteLLM(死上游 key + 攻击者流量)、RDP 桩(静态 banner)
- 信息泄露:LiteLLM spend 日志、ts RSA 公钥、Laravel debug SQL 错误、tg-filter 健康状态

## 五、横向移动/后续建议

1. **tg-filter MySQL 恢复瞬间**:register(role=admin)→ 登录 → 批量导出全部 TG 会话(最大情报面)
2. **geekapi 节点**(DB 正常):继续慢速口令(限流 60/min),或等待运营者口令泄露
3. **47.237.9.41:9090**:独立 IM WebSocket,待侦察
4. **运营者口令若从外部泄露**(撞库/社工):可复用于全部面板(同口令模式)
5. 钓鱼 bot token 有效 → 可接管拦截交互(注意勿碰受害者数据)

## 六、结论

**已确认 3 项严重级成果**:5100 Flask 面板沦陷(bot 完全控制)、tg-filter 完整账号接管链、LiteLLM 严重配置错误+SSRF。**运营者真实面板口令全部守住**(跨 5 资产、~5000 次尝试),技术绕过均不可行。该集群核心资产口令为强随机,蜜罐组件用于反制。
