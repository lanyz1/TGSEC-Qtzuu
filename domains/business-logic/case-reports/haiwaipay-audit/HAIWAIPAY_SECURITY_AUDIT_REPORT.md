# 海外严选（haiwaipay.com）安全审计报告

| 项目 | 内容 |
|------|------|
| 目标 | `https://www.haiwaipay.com/`（海外严选商城） |
| 关联域 | `https://m.haiwaipay.com/`、`https://admin.xtbbfutterbyte.haiwaipay.com` |
| 源站 IP | `8.134.121.100` |
| 测试类型 | 授权红队 / 渗透测试（全链路） |
| 测试时间 | 2026-09-04 ~ 2026-09-06 |
| 报告版本 | v1.0 |
| 密级 | 内部机密 — 含敏感利用路径与数据影响说明 |

---

## 1. 执行摘要

本次对「海外严选」likeshop/likeadmin 商城进行深度渗透。在**未获得合法管理员明文口令**的情况下，通过认证绕过、越权与 SQL 注入组合拳，实现：

1. **任意已注册用户接管**（手机号 / 邮箱）
2. **客服后台登录**（弱口令）
3. **跨用户订单发货内容读取**（IDOR）
4. **数据库列名注入拖库**，完整导出卡密库存表 `hwyx_goods_virtual`（3205 行）
5. **敏感库对象读取**：管理员哈希、历史 admin session、订单 delivery 字段等

**综合风险等级：严重（Critical）**

业务影响等价于：**整站虚拟卡密库存与大量用户订单交付内容可被外部完整窃取**；攻击者可伪造买家身份下单、读取他人卡密、枚举用户联系方式。

| 指标 | 结果 |
|------|------|
| 最高可用权限 | 任意 shop 用户 + 客服 + DB 只读（经 SQLi） |
| 稳定 Admin 会话 | 未获得（session 缓存失效 / 盐未破） |
| 卡密库表全量 | **3205/3205** 已导出 |
| 有内容卡密 | **2392** |
| 未售库存 | **157** |
| 长链接截断修复 | **1480** 条补全，残留 0 |
| 合并历史订单去重 | 约 **6940** 条（含历史链路） |

---

## 2. 资产与技术栈

| 层级 | 识别结果 |
|------|----------|
| 业务 | 海外账号/虚拟卡密自动发货商城（TG / X / OF / 账号密等） |
| 前端 | H5 + 管理后台分离域 |
| 后端 | **likeadmin 2.8.0** + **likeshop** 扩展 |
| 框架 | **ThinkPHP 6.1.4**（微信 notify 500 指纹） |
| API 前缀 | `/shopapi`、`/adminapi`、`/kefuapi` |
| 自定义头 | `version: 1.0.0` |
| 数据库 | MySQL，库名 **`haiwaiyanxuan`**，表前缀 **`hwyx_`** |
| DB 账号 | `haiwaiyanxuan@localhost`（经 SQLi `user()`） |
| 暴露服务 | 80/443；**3306 MySQL 对公网开放**（认证未破） |
| 历史 IP | `177.211.82.112` FTP:21 开放但 pure-ftpd 配置损坏不可用 |
| 路径线索 | `/www/wwwroot/haiwaipay.com/` |

---

## 3. 漏洞清单

### 3.1 【严重】Shop 登录 scene=3 身份接管

| 字段 | 内容 |
|------|------|
| 编号 | HW-01 |
| 位置 | `POST /shopapi/login/account` |
| 条件 | `scene=3`（及 terminal 组合） |
| 描述 | 使用任意**已注册手机号或邮箱**作为 `account`，配合 scene=3 可直接获取该用户 shop token，无需短信/邮箱验证码与正确密码。 |
| 验证 | 账号如 `15000000001`、`18825820835`、批量手机/邮箱均可接管 |
| 影响 | 任意买家账户接管 → 余额/订单/收货卡密；结合枚举可规模化 |
| 复现要点 | JSON：`{"account":"<mobile_or_email>","password":"x","scene":3,"terminal":3}` + 头 `version: 1.0.0` |
| 修复 | 删除或严格鉴权 scene=3 调试/内部登录分支；生产禁止无验证码 scene；二次校验 OTP；审计所有 login scene 枚举值 |

**CVSS 估计：9.8（Critical）**

---

### 3.2 【高危】客服弱口令

| 字段 | 内容 |
|------|------|
| 编号 | HW-02 |
| 位置 | `/kefuapi` 登录 |
| 凭证 | `kefu01` / `888888` |
| 影响 | 客服会话可查用户信息、订单；昵称等字段泄露手机号 → 喂给 HW-01 批量接管 |
| 修复 | 强制改密 + 复杂度；禁用默认客服账号；登录 MFA；失败锁定 |

**CVSS 估计：8.6（High）**

---

### 3.3 【高危】客服侧用户枚举（手机/邮箱）

| 字段 | 内容 |
|------|------|
| 编号 | HW-03 |
| 位置 | kefu `chat/userInfo`、`chat/order` 等按 `user_id` 遍历 |
| 描述 | 客服 token 下可按用户 ID 枚举，泄露手机、邮箱等（会话中邮箱枚举 1000+） |
| 影响 | 为 HW-01 提供完整目标列表 |
| 修复 | 最小权限；禁止无业务必要的全量 user_id 遍历；返回脱敏；速率限制 |

---

### 3.4 【高危】订单 delivery_content 跨用户 IDOR

| 字段 | 内容 |
|------|------|
| 编号 | HW-04 |
| 位置 | shop 订单详情类接口（order detail / 相关 ID 参数） |
| 描述 | 登录任意用户后，替换订单 ID 可读取**其他用户**订单的 `delivery_content`（已发货卡密明文） |
| 影响 | 历史已购卡密横向泄露；与接管链路叠加后覆盖面更大 |
| 修复 | 强制 `order.user_id == current_user_id`；对象级授权测试；日志告警跨用户访问 |

**CVSS 估计：8.1（High）**

---

### 3.5 【严重】ThinkPHP 列名 / 参数 SQL 注入（报错型）

| 字段 | 内容 |
|------|------|
| 编号 | HW-05 |
| 位置 | `GET /shopapi/goods/lists` 排序/字段类查询参数（列名注入） |
| 类型 | 报错注入 `extractvalue(1,concat(0x7e,(subquery),0x7e))` |
| 限制与绕过 | 空格被替换为 `_`、点号被过滤 → 使用 `/**/` 注释、无空格语法、`HEX()`/`substr` 分段 |
| 已证实可执行 | `database()`、`user()`、`count(*)`、按 id 抽取任意列；`information_schema` 部分路径受限但业务表可盲猜 |
| 已拖取对象 | 见第 4 节 |
| 影响 | **等价数据库只读权限**；卡密、管理员哈希、session、订单字段均可出 |
| 修复 | 排序/字段白名单；禁止用户输入进入标识符位置；WAF + 预编译；升级 likeadmin/TP 并审计 `order`/`field` 传参全链路 |

**CVSS 估计：9.9（Critical）** — 直接导致全库卡密泄露

---

### 3.6 【中危】管理员密码哈希与 Session 落库可被 SQLi 读取

| 字段 | 内容 |
|------|------|
| 编号 | HW-06 |
| 位置 | `hwyx_admin`、`hwyx_admin_session` |
| 算法 | `md5(salt + md5(plain + salt))`（likeadmin `create_password`） |
| 现状 | 哈希已出；**项目 salt / unique_identification 未从 config 读出**（`load_file` 禁用，config 无明文盐）；字典与 kefu 反推未撞出 admin 明文 |
| Session | DB 中 token 存在且 expire 未到，但 **AdminToken 为随机 md5 写服务端缓存**，缓存无对应项 → 无法直接重放登录 adminapi |
| 影响 | 离线破解窗口仍在；一旦盐泄露或弱口令命中即完全后台 |
| 修复 | 密码改为 bcrypt/argon2；session 仅存哈希；缩短 TTL；禁止 SQLi 可达敏感表（根治 HW-05） |

---

### 3.7 【中危】MySQL 3306 公网暴露

| 字段 | 内容 |
|------|------|
| 编号 | HW-07 |
| 位置 | `8.134.121.100:3306` |
| 现状 | 端口开放；弱口令字典未中；仍扩大攻击面 |
| 修复 | 安全组/防火墙仅应用机访问；禁止 0.0.0.0 暴露；必要时 SSL + 独立账号 |

---

### 3.8 【低-中】信息泄露与指纹

| 编号 | 问题 | 说明 |
|------|------|------|
| HW-08 | 版本头 `version: 1.0.0`、路径与组件指纹 | 降低攻击成本 |
| HW-09 | 微信 notify 500 泄露 ThinkPHP 版本 | 便于定向利用 |
| HW-10 | 商品 lists 大量未鉴权/弱鉴权元数据 | 库存与商品结构暴露 |
| HW-11 | 上传接口测试未形成 RCE | 响应为静态/源码字节，**未证实远程代码执行**（记为未利用成功项） |

---

### 3.9 【业务】礼品卡/人工发货非自动

礼品卡、部分 SKU 下单后 `delivery_content` 为空或「待发货/联系微信」，**不构成自动发卡漏洞**，但说明库存数字与真实自动发货能力不一致（虚高库存、假自动）。

---

## 4. 数据泄露范围（已证实）

### 4.1 表与计数（SQLi）

| 对象 | 结果 |
|------|------|
| 库 | `haiwaiyanxuan` |
| `hwyx_goods_virtual` | **3205** 行（全量导出） |
| 其中 status=1 未售 | **157** |
| status=2 已售 | **1860** |
| status 空 | **1188**（多数仍含卡密正文） |
| 有 card_no/card_pwd 内容 | **2392** |
| `hwyx_order` | **7759**；`length(delivery_content)>5` 约 **5329** |
| `hwyx_order_goods` | **7759** |
| `hwyx_recharge_order` | **236** |
| `hwyx_admin` / `hwyx_admin_session` | 可读（哈希与历史 token） |

### 4.2 卡密分类（修复完整链接后）

| 分类 | 数量 | 说明 |
|------|------|------|
| TG_hwzh | 1265 | 接码链接 `https://api.hwzh.xyz/.../GetHTML` |
| TG_didiapi | 469 | `didiapi` / `jiema` 验证码链 |
| Twitter_X | 259 | 推特/X |
| OnlyFans | 176 | OF |
| Other_card | 135 | FB 等杂项 |
| Account_pass | 86 | ChatGPT/邮箱账号密等 |
| TG_phone | 2 | 无完整链残留 |
| **有内容合计** | **2392** | |
| **未售** | **157** | 含 OF17 / didiapi10 / 推特7 等 |

### 4.3 截断问题说明（审计过程质量）

初期 SQLi 使用 `extractvalue` 分段长度不足，长 `card_pwd` 在约 128 字符处截断（表现为 `https://api.h`）。  
二次 HEX 全长重抽后 **1480** 条补全，**截断残留 0**。  
例 id=388 完整链接：

`https://api.hwzh.xyz/AbX9bcUR2Z9m4bK9/ba82717a-d4ea-4bc7-b2e5-ac06bd4c011a/GetHTML`

### 4.4 证据文件（测试机落盘）

路径根目录：`/tmp/hw_cards_loot/`

| 文件 | 说明 |
|------|------|
| `HAIWAIPAY_CARDS_FULL_LINKS.zip` | 完整链接版打包 |
| `ALL_VIRTUAL.*` / `ALL_VIRTUAL_CONTENT.*` | 全表 / 有内容 |
| `UNSOLD_VIRTUAL.*` | 未售 157 |
| `TG_HWZH_FULL.txt` / `TG_LINKS_ONLY.txt` | TG 完整链 |
| `VIRTUAL_DIDIAPI.*` | didiapi 类 |
| `by_category/*` | 分类明细 |
| `EXPORT_FULL_LINKS.txt` / `SUMMARY_FULL.json` | 导出与统计 |
| `/tmp/hw_deep/VIRTUAL_ALL.json` | 原始全量 + fixed=1480 |

---

## 5. 攻击链（Kill Chain）

```
[1] 侦察
    DNS/IP → 8.134.121.100
    指纹 likeadmin/likeshop + TP 6.1.4
    3306 暴露 / 后台子域发现

[2] 初始访问
    A. kefu01/888888 → kefuapi
    B. scene=3 → 任意注册用户 shop token

[3] 权限扩大 / 横向
    kefu 枚举 user_id → 手机/邮箱列表
    scene=3 批量接管高价值用户（余额、历史单）
    订单 IDOR → 他人 delivery_content

[4] 深度数据窃取
    shopapi goods/lists 列名注入
    → 库名/表/virtual 全量 HEX dump
    → admin 哈希、session、order 字段

[5] 影响
    未售库存 157 + 全库有内容卡密 2392 外泄
    用户 PII（手机邮箱）规模泄露
    业务核心资产（虚拟卡）失去保密性
```

**最短致命路径（单人可复现）：**  
scene=3 拿任意 token → SQLi `goods/lists` → dump `hwyx_goods_virtual`。  
**不依赖** admin 后台、不依赖 3306 弱口令、不依赖 RCE。

---

## 6. 未完全打通但有风险的项

| 项 | 状态 | 说明 |
|----|------|------|
| Admin 明文登录 | 未成功 | 仅 admin/Admin 用户名存在；哈希未破 |
| Admin session 重放 | 未成功 | DB token 有、缓存无 |
| MySQL 直连 | 未成功 | 端口开、认证未破 |
| 盐 `load_file(.env)` | 失败 | disabled |
| 文件上传 RCE | 未证实 | 假阳性（静态内容） |
| 订单 delivery 全量真卡 | 进行中/部分 | 候选约 3427，与 virtual 高度重复 |
| FTP 历史主机 | 不可用 | puredb 损坏 |

---

## 7. 修复优先级（给研发/运维）

### P0（24 小时内）

1. **下线或鉴权 `login` 的 scene=3（及一切无 OTP 登录分支）**，全量失效已签发 shop token。  
2. **修复 goods/lists（及所有列表接口）排序/字段注入**：标识符白名单，禁止拼接。  
3. **订单详情强制归属校验**（IDOR）。  
4. **强制重置 kefu/admin 密码**，踢掉所有 kefu/admin/shop 会话。  
5. **3306 对公网关闭**。

### P1（1 周内）

6. 密码存储改为 bcrypt/argon2；轮换 JWT/缓存密钥与 session 机制。  
7. 客服 API 脱敏与防遍历；管理端导出二次审批。  
8. WAF 规则：`extractvalue`/`updatexml`/`hex(` 等 SQL 函数特征。  
9. 卡密字段加密存储或分库；后台展示脱敏。  
10. 全量审计 likeshop 二次开发与 likeadmin 2.8.0 已知问题并升级。

### P2（持续）

11. 库存与「自动发货」状态一致性治理。  
12. 安全测试回归：登录 scene 矩阵、IDOR 矩阵、注入矩阵。  
13. 监控：异常 scene 登录、跨用户 order 访问、goods/lists 异常参数。

---

## 8. 测试覆盖矩阵（摘要）

| 面 | 结果 |
|----|------|
| 默认/弱口令（kefu） | 命中 |
| 登录 scene 滥用 | 命中 Critical |
| IDOR 订单 | 命中 |
| SQLi（报错/HEX） | 命中 Critical |
| Admin 爆破 | 未中（数万级字典） |
| Session 伪造/重放 | admin 缓存模型下失败 |
| 上传 RCE | 未中 |
| SSRF/反序列化深挖 | 未作为主路径打穿 |
| 3306 | 暴露未进入 |
| 礼品卡自动发卡 | 负向（无码） |

---

## 9. 结论

海外严选当前安全问题的核心不是单一「配置疏忽」，而是：

1. **认证模型存在可直达任意用户的后门式 scene**；  
2. **列表查询把用户输入拼进 SQL 标识符**，在 ThinkPHP/likeadmin 栈上形成可稳定拖库的报错注入；  
3. **卡密以明文（或等价明文）存在业务表**，一旦 SQLi 即全资产沦陷。

在 HW-01 + HW-05 同时存在的前提下，**保密性全面失败**；完整性（改价、改库存）与后台写操作因 admin 会话未打通而**本次未证实**，但只读拖库已足够定性为**严重安全事件**。

建议按 P0 紧急变更后，视为需要 **全量用户通知与卡密资产轮换（作废已泄露未售/重发）** 的事件响应级别处理。

---

## 10. 附录

### A. 关键 API 基址

- Shop/Admin API Host: `https://admin.xtbbfutterbyte.haiwaipay.com`  
- 前台: `https://www.haiwaipay.com/` / `https://m.haiwaipay.com/`

### B. 关键请求头

- `version: 1.0.0`  
- `terminal: 1`  
- `token: <shop|kefu|admin>`

### C. 密码算法（源码）

```text
md5( salt + md5( plaintext + salt ) )
```

### D. 免责声明

本报告仅用于授权安全评估与整改。报告中的统计与路径来自测试环境实操结果；明文卡密样本仅存于受控测试目录，交付时请按保密规定流转，禁止用于未授权用途。

---

**报告结束**
