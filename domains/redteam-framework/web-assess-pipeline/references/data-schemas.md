# 数据结构定义（权威单一来源）

本文件是 WEB 应用安全评估 skill 所有数据文件的**权威结构定义**。脚本与各阶段 SOP 都以此为准，
确保同类数据跨文件结构一致。**所有键名与状态值统一用英文**；中文仅用于字段含义说明。

## 目录

- [通用约定](#通用约定)
- [枚举值映射表](#枚举值映射表)
- [index.json — 项目清单（根级）](#indexjson--项目清单根级)
- [config.json — 项目配置](#configjson--项目配置)
- [state.json — 断点状态](#statejson--断点状态)
- [sessions.json — 会话池](#sessionsjson--会话池)
- [pages.jsonl — 页面清单](#pagesjsonl--页面清单)
- [js.jsonl — JS 清单](#jsjsonl--js-清单)
- [business-chains.jsonl — 业务链清单](#business-chainsjsonl--业务链清单)
- [threats.jsonl — 威胁建模清单](#threatsjsonl--威胁建模清单)
- [url-inventory.json — URL 清单](#url-inventoryjson--url-清单)
- [mining-scope.json — 漏洞挖掘必挖清单基线](#mining-scopejson--漏洞挖掘必挖清单基线)
- [url-static-params.json — 静态请求参数基准](#url-static-paramsjson--静态请求参数基准)
- [retest-list.json — 补测清单](#retest-listjson--补测清单)
- [bypass-list.json — 绕过台账](#bypass-listjson--绕过台账)
- [permission-matrix/{id}.json — 权限验证矩阵](#permission-matrixidjson--权限验证矩阵)
- [vuln-reports.json — 漏洞报告清单](#vuln-reportsjson--漏洞报告清单)
- [reports/{vuln_id}.md — 漏洞报告](#reportsvuln_idmd--漏洞报告)
- [vuln-matrix/{id}.json — 参数漏洞矩阵](#vuln-matrixidjson--参数漏洞矩阵)
- [url-context/{id}.json — URL 关联上下文](#url-contextidjson--url-关联上下文)
- [proxy-logs/ — 代理产物](#proxy-logs--代理产物)
- [report/ — 汇总评估报告（派生产物）](#report--汇总评估报告派生产物)

---

## 通用约定

- **目录布局**：所有运行时数据在工作目录下 `pentest-data/`。根级一个 `index.json`，每个项目一个
  子目录 `pentest-data/{project-id}/`，其下放各清单文件与子目录（`pages-html/`、`js-files/`、
  `permission-matrix/`、`reports/`、`vuln-matrix/`、`url-context/`、`proxy-logs/`、`sessions/`、`tmp/`）。
- **临时文件目录 `tmp/`**：除本文件明确规定落盘路径的产物外，过程中临时生成的探测脚本、payload、中间数据
  统一放在项目目录下的 `tmp/`（`pentest-data/{project-id}/tmp/`），按需建子目录、文件名带 url-id 以避免并发冲突。
- **ID 前缀**：`pages.jsonl`→`PAGE`、`js.jsonl`→`JS`、`business-chains.jsonl`→`BC`、
  `threats.jsonl`→`THREAT`，统一 4 位补零（`PAGE0001`）。`url-inventory.json` 的 id **直接沿用**
  代理生成的 `URLxxxxx`（5 位，如 `URL00001`），不另起编号。
- **漏洞报告编号**：`VULN-VD-{URLID}-NNNN`（内嵌具体 URLID，逐 URL 归属；漏洞挖掘与威胁收敛阶段的
  补测/绕过突破均用此编号，在该 URL 内续编）。NNNN 为 4 位补零。报告号即报告文件名（`reports/{vuln_id}.md`）。
- **时间格式**：ISO 8601 带时区，如 `2026-06-28T17:49:13+08:00`（脚本用 `common.now_iso()`）。
- **notes 字段（特殊情况说明）**：每条记录都有；默认值 `"无"`。因安全边界 / 资源限制 / 程序 bug /
  其它原因无法完成既定工作时在此说明。
- **「未开展」vs「已做但没发现」**：这是贯穿全 skill 的关键区分。
  - **未开展**：该项工作还没做 → 字段留**空**（空字符串 `""` / 空数组 `[]` / `null`）。
  - **已做但没发现**：该项工作做了但没有结果 → 字段填 **`"not_found"`**（数组类字段填 `["not_found"]`
    或约定的标记，见各字段说明）。
  - 例：JS 刚下载未读 → `secrets: []`（空，未开展阅读）；读完没发现密钥 → `secrets: "not_found"`。
- **记录时机**：发现新实体（页面 / JS / 业务链 / 威胁 / URL）立即建记录，允许字段不全；完成相关操作后
  再回填。不要堆积未记录信息。
- **写入安全**：脚本写文件一律「临时文件 + 原子替换」（`common.atomic_write_json` / `dump_jsonl`）。

---

## 枚举值映射表

| 维度                                         | 中文                                           | 英文落地值                                                                          |
| -------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------- |
| 威胁优先级`priority`                       | 紧急 / 高 / 中 / 低                            | `critical` / `high` / `medium` / `low`                                      |
| 业务链走通`walkthrough_status`             | 待走通 / 部分走通 / 完整走通 / 未走通          | `pending` / `partial` / `completed` / `blocked`                             |
| 权限矩阵`permission_matrix_status`         | 待验证 / 已验证                                | `pending` / `verified`                                                          |
| 权限判断`judgment`                         | 正常 / 异常                                    | `normal` / `abnormal`                                                           |
| 威胁收敛`verification_status`              | 待收敛 / 已确认 / 已排除 / 存疑 / 被防护       | `pending` / `confirmed` / `excluded` / `doubtful` / `filtered`            |
| 漏洞挖掘完成`*_mining_done`                | 待开展 / 已完成 / 不适用                       | `pending` / `completed` / `not_applicable`                                    |
| 补测清单研判`disposition`（retest-list）   | 待研判 / 客观阻塞需补测 / 安全边界或无需测     | `pending` / `retest` / `blocked`                                              |
| 绕过台账研判`bypass_status`（bypass-list） | 待绕过 / 已专项绕过                            | `pending` / `retested`                                                          |
| 漏洞矩阵单元`status`                       | 不适用 / 已测试未发现 / 已发现 / 存疑 / 被防护 | `not_applicable` / `tested_not_found` / `found` / `doubtful` / `filtered` |
| 矩阵漏洞分类`category`（矩阵条目）         | 通用漏洞 / 业务逻辑漏洞                        | `generic` / `business_logic`                                                    |
| 报告审核`review_status`                    | 待审核 / 已通过 / 已拒绝                       | `pending_review` / `approved` / `rejected`                                    |
| 报告阶段`phase`（报告）                    | 漏洞挖掘                                       | `VD`                                                                              |
| 报告来源`source`（报告）                   | 逐 URL 挖掘产出                                | `URL`                                                                             |
| JS 下载`download_status`（js.jsonl）       | 已下载 / 开源不下载 / 下载失败                 | `downloaded` / `opensource` / `failed`                                        |
| JS 是否开源`is_opensource`                 | 是 / 否                                        | `true` / `false`                                                                |
| 登录结果`login_status`                     | 成功 / 失败                                    | `success` / `failed`                                                            |
| 项目状态`status`                           | 进行中 / 已完成                                | `in_progress` / `completed`                                                     |
| 安全等级`security_level`                   | 高 / 中 / 低                                   | `high` / `medium` / `low`                                                     |
| URL 类别`category`（沿用代理）             | 页面 / 接口 / 脚本 / 资源 / 其它 / 未知        | `page` / `api` / `js` / `resource` / `other` / `unknown`                |
| 「已做没发现」标记                           | 未发现                                         | `not_found`                                                                       |
| 阶段`phase`                                | 准备 / 广度建模 / 漏洞挖掘 / 威胁收敛          | `1` / `2` / `3` / `4`                                                       |

> `critical`（紧急）仅限**已确认存在**的漏洞（如未授权访问、AK/SK 泄露）；未确认的潜在漏洞最高 `high`。

---

## index.json — 项目清单（根级）

路径：`pentest-data/index.json`。登记所有项目，用于查重与续测。

```json
{
  "_note": "项目清单",
  "projects": [
    {
      "project_id": "www-TGSEC-com-8080",
      "target": "http://www.TGSEC.com:8080/",
      "dir": "pentest-data/www-TGSEC-com-8080",
      "created": "2026-06-28T10:00:00+08:00",
      "last_active": "2026-06-28T10:30:00+08:00",
      "phase": 1,
      "status": "in_progress"
    }
  ]
}
```

| 字段                          | 类型   | 说明                                                                              |
| ----------------------------- | ------ | --------------------------------------------------------------------------------- |
| `project_id`                | string | 仅`[a-z0-9-]`；默认由 target hostname[:port] 推导（`.`/`:`→`-`、转小写） |
| `target`                    | string | 目标根地址                                                                        |
| `dir`                       | string | 项目目录相对路径                                                                  |
| `created` / `last_active` | string | ISO8601 时间戳                                                                    |
| `phase`                     | int    | 当前阶段 1/2/3                                                                    |
| `status`                    | string | `in_progress` / `completed`                                                   |

---

## config.json — 项目配置

路径：`pentest-data/{id}/config.json`。准备阶段写入，记录目标与安全边界，全程遵守。

```json
{
  "project_id": "www-TGSEC-com-8080",
  "target": "http://www.TGSEC.com:8080/",
  "scope": ["www.TGSEC.com:8080/pentest/"],
  "exclude": ["www.TGSEC.com:8080/pentest/reset.php"],
  "scope_regex": false,
  "exclude_regex": false,
  "test_accounts": [
    {"role": "admin", "username": "admin", "password": "***", "login_url": "http://.../login"},
    {"role": "user",  "username": "u1",    "password": "***", "login_url": "http://.../login"}
  ],
  "goals": "全面测绘攻击面并完成威胁建模",
  "constraints": "仅工作时间测试",
  "work_guidelines": "1. 所有 payload 附中文注释说明测试意图。\n2. 每挖到一个高危漏洞立即同步主代理。",
  "security_level": "high",
  "proxy_port": 24304,
  "created": "2026-06-28T10:00:00+08:00",
  "notes": "无"
}
```

| 字段               | 类型     | 说明                                                                                      |
| ------------------ | -------- | ----------------------------------------------------------------------------------------- |
| `scope`          | string[] | 安全边界——允许测试的范围（域名/路径）。空=默认取 target 路径下全部                      |
| `exclude`        | string[] | 排除清单——范围内再剔除的 URL（语法同 scope，优先级更高）。空=不排除；代理记录与门禁共用 |
| `scope_regex`    | bool     | `true` 时把 `scope` 每条当正则（对完整 URL 做 search）；默认 `false`                |
| `exclude_regex`  | bool     | `true` 时把 `exclude` 每条当正则；默认 `false`                                      |
| `test_accounts`  | object[] | 测试账号；未提供则空数组（不阻塞）                                                        |
| `goals`          | string   | 目标成果                                                                                  |
| `constraints`    | string   | 用户补充的约束条件                                                                        |
| `work_guidelines`| string   | 工作守则——用户以 `# 工作守则` 标记下发的全部内容，**最高优先级**，全程所有阶段与子代理严格遵守；未设定为 `""` |
| `security_level` | string   | `high`（默认）/ `medium` / `low`，语义见 SKILL.md 安全边界                          |
| `proxy_port`     | int      | 代理监听端口（默认 24304，用户指定则以用户指定为准）；代理与探测脚本/子代理共用           |

---

## state.json — 断点状态

路径：`pentest-data/{id}/state.json`。用于中断后续跑。

```json
{
  "phase": 3,
  "phase_status": {
    "preparation": "completed",
    "breadth": "completed",
    "vuln_mining": "in_progress",
    "threat_convergence": "pending"
  },
  "gates": {
    "breadth": {
      "exit": 1,
      "blocking_count": 1,
      "hard_errors": ["[页面覆盖] ...product_detail.php（来源 pages PAGE0002）", "..."],
      "acknowledged": [
        {"match": "api/merchant/register.php", "reason_code": "captcha_unbypassable", "note": "商户注册双验证码自动化无法稳定过码，已确认接口存在"}
      ],
      "checked_at": "2026-06-28T11:00:00+08:00"
    }
  },
  "updated": "2026-06-28T11:00:00+08:00"
}
```

| 字段             | 类型   | 说明                                                                                                                                  |
| ---------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `phase`        | int    | 当前阶段 1/2/3/4                                                                                                                      |
| `phase_status` | object | 四阶段各自状态：键`preparation`/`breadth`/`vuln_mining`/`threat_convergence`，值 `pending`/`in_progress`/`completed`    |
| `gates`        | object | **门禁退出态（由 `check_*.py` 落盘，AI 不可伪造）**。键为门禁名（`breadth`/`vuln_mining`/`threat_convergence`），值见下 |

`gates.<gate>` 子字段（详见 [quality-gates.md](quality-gates.md) 「门禁退出态与放行判据」）：

| 子字段             | 类型   | 说明                                                                                                                                                                                                                                                                                     |
| ------------------ | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `exit`           | int    | 门禁脚本原始硬检查退出码（有硬错误=1）                                                                                                                                                                                                                                                   |
| `blocking_count` | int    | 未被**有效** acknowledged 覆盖的硬错误数。**放行判据 = 0**（下一阶段门禁强制校验，>0 禁止流转）                                                                                                                                                                              |
| `hard_errors`    | array  | 本次硬检查产生的全部硬错误字符串                                                                                                                                                                                                                                                         |
| `acknowledged`   | array  | 客观走不通的放行登记（AI 补），元素`{match, reason_code, note}`：`match`=唯一命中错误的子串（通常 URL）；`reason_code`∈`out_of_scope`/`system_bug`/`captcha_unbypassable`/`precondition_unmet`/`not_exist`/`accepted_residual`；`note` 必填。非法或缺 note 者不生效 |
| `checked_at`     | string | 本次门禁核验时间戳                                                                                                                                                                                                                                                                       |

> 漏洞挖掘阶段的断点续跑靠扫描 `url-inventory.json` 各 URL 的 `*_mining_done` 状态恢复（无单独游标）。

---

## sessions.json — 会话池

路径：`pentest-data/{id}/sessions.json`。已知测试账号登录后的凭证，供后续脚本/curl 带身份复用，
避免重复登录。`storage_state_file` 为 playwright `storageState` 导出文件（放 `sessions/` 子目录）。

```json
{
  "sessions": [
    {
      "session_id": "s1",
      "role": "admin",
      "username": "admin",
      "login_status": "success",
      "auth": {"cookie": "SESSION=abc...", "headers": {"Authorization": "Bearer ..."}},
      "storage_state_file": "sessions/s1-admin.json",
      "created": "2026-06-28T10:10:00+08:00",
      "notes": "无"
    },
    {
      "session_id": "s0",
      "role": "unauthenticated",
      "username": "",
      "login_status": "success",
      "auth": {},
      "storage_state_file": "",
      "created": "2026-06-28T10:10:00+08:00",
      "notes": "未登录基线，用于权限矩阵对照"
    }
  ]
}
```

| 字段                   | 类型   | 说明                                                   |
| ---------------------- | ------ | ------------------------------------------------------ |
| `role`               | string | 角色名；未登录基线用`unauthenticated`                |
| `login_status`       | string | `success` / `failed`；失败在 `notes` 记原因      |
| `auth`               | object | 供脚本带身份复用的凭证摘要（cookie / headers / token） |
| `storage_state_file` | string | playwright storageState 文件相对路径；无则`""`       |

---

## pages.jsonl — 页面清单

路径：`pentest-data/{id}/pages.jsonl`。每个页面 URL 一行。

```json
{"id":"PAGE0001","url":"http://host/user/profile","title":"个人中心","accessed_as_roles":["admin","user"],"html_file":"pages-html/PAGE0001.html","fully_parsed":true,"discovered_js":[{"src":"/js/login.js","abs_url":"http://host/js/login.js","js_id":"JS0001"}],"discovered_urls":[{"url":"http://host/api/profile","type":"api","method":"GET","status_code":200,"in_scope":true}],"interactive_elements":[{"type":"form","selector":"#profileForm","description":"修改资料表单"},{"type":"button","selector":"#saveBtn","description":"保存"}],"business_constraints":["手机号需先验证才能修改"],"notes":"无","created":"2026-06-28T10:20:00+08:00","updated":"2026-06-28T10:25:00+08:00"}
```

| 字段                           | 类型     | 说明                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                         | string   | `PAGExxxx`                                                                                                                                                                                                                                                                                                                                               |
| `url`                        | string   | 页面 URL                                                                                                                                                                                                                                                                                                                                                   |
| `title`                      | string   | 页面标题                                                                                                                                                                                                                                                                                                                                                   |
| `accessed_as_roles`          | string[] | 以哪些角色身份访问过                                                                                                                                                                                                                                                                                                                                       |
| `html_file`                  | string   | playwright 渲染后 HTML 的落盘路径`pages-html/{PAGEID}.html`；未下载留 `""`                                                                                                                                                                                                                                                                             |
| `fully_parsed`               | bool     | 是否已完整阅读并解析该页 HTML 源码；未解析为`false`                                                                                                                                                                                                                                                                                                      |
| `discovered_js`              | object[] | 每个引用 JS：`src`、`abs_url`（相对转绝对）、`js_id`（关联 js.jsonl 记录；每个引用 JS 都登记，恒非空）                                                                                                                                                                                                                                               |
| `discovered_urls`            | object[] | 发现的页面/API：`url`、`type`(`page`/`api`)、`method`、`status_code`（已访问则填，未访问留 `null`）、`in_scope`（见下）                                                                                                                                                                                                                    |
| `discovered_urls[].in_scope` | bool     | 该 URL 是否在`config.scope` 测试范围内（判定用 `common.url_in_test_scope`（已扣除 `config.exclude`），与代理记录口径一致）。**范围内(true)**：`type=page` 须有独立 `fully_parsed` 页面记录、`type=api` 须进 `url-inventory`（被真实访问）；**范围外(false)**：豁免（类比开源 JS 不下载）。缺省时门禁按 `config.scope` 现场计算 |
| `interactive_elements`       | object[] | 可交互元素：`type`(form/button/link/input/...)、`selector`、`description`                                                                                                                                                                                                                                                                            |
| `business_constraints`       | string[] | 前端校验规则与业务约束（含隐含约束）；已解析无约束填`["not_found"]`，未解析留 `[]`                                                                                                                                                                                                                                                                     |

---

## js.jsonl — JS 清单

路径：`pentest-data/{id}/js.jsonl`。**每个发现的 JS 一行**（含开源第三方库），是攻击面上「引用了哪些 JS、
是否都已阅读」的权威清单。开源库允许不下载不通读（`is_opensource=true` / `download_status=opensource` /
`local_path=""` / `fully_read=false`）；非开源 JS 下载到 `js-files/` 并全文阅读。

```json
{"id":"JS0001","source_url":"http://host/js/login.js","is_opensource":false,"download_status":"downloaded","local_path":"js-files/js-login.js","fully_read":true,"secrets":[{"name":"apiKey","value":"AKIA..."}],"discovered_urls":[{"url":"http://host/api/login","type":"api","method":"POST","status_code":200,"in_scope":true}],"business_constraints":["密码至少 8 位"],"notes":"无","created":"2026-06-28T10:30:00+08:00","updated":"2026-06-28T10:40:00+08:00"}
{"id":"JS0002","source_url":"http://host/lib/jquery.min.js","is_opensource":true,"download_status":"opensource","local_path":"","fully_read":false,"secrets":[],"discovered_urls":[],"business_constraints":[],"notes":"jQuery 开源库，不下载不通读","created":"2026-06-28T10:31:00+08:00","updated":"2026-06-28T10:31:00+08:00"}
```

| 字段                     | 类型                    | 说明                                                                                                                                                                                                                                                                           |
| ------------------------ | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`                   | string                  | `JSxxxx`                                                                                                                                                                                                                                                                     |
| `source_url`           | string                  | JS 源 URL                                                                                                                                                                                                                                                                      |
| `is_opensource`        | bool                    | 是否为开源第三方库；`true` 时允许不下载不通读                                                                                                                                                                                                                                |
| `download_status`      | string                  | `downloaded`（已下载）/ `opensource`（开源不下载）/ `failed`（下载失败，`notes` 记原因）                                                                                                                                                                               |
| `local_path`           | string                  | 本地保存路径；文件名取「路径+文件名、`/`→`-`」，如 `/js/login.js`→`js-files/js-login.js`；未下载留 `""`                                                                                                                                                            |
| `fully_read`           | bool                    | 是否已完成全文阅读；未读/开源不读为`false`（非开源且已下载必须全读为 `true`）                                                                                                                                                                                              |
| `secrets`              | array\| `"not_found"` | 硬编码密钥；未读为`[]`，读完无则 `"not_found"`                                                                                                                                                                                                                             |
| `discovered_urls`      | object[]                | 同 pages（含`in_scope` 字段，规则一致）：JS 中发现的 URL（带参访问并记状态码）。**JS 是隐藏接口重灾区**（内联/外部脚本的 fetch 端点），其范围内 discovered_urls 与 pages 侧同等治理：`type=page` 须有独立 `fully_parsed` 记录、`type=api` 须进 `url-inventory` |
| `business_constraints` | array\| `"not_found"` | 业务约束；未读为`[]`，读完无则 `"not_found"`                                                                                                                                                                                                                               |

---

## business-chains.jsonl — 业务链清单

路径：`pentest-data/{id}/business-chains.jsonl`。每个业务链一行。

```json
{"id":"BC0001","name":"商品下单-购物车结算","goal":"用户购买商品完成支付","description":"加入购物车→进入结算→选地址→下单→支付→支付成功","related_urls":["http://host/cart/add","http://host/order/create","http://host/pay"],"business_constraints":["库存>0 才能下单","优惠券在有效期内可用"],"walkthrough_status":"partial","walkthrough_detail":"走到支付环节，因 high 等级禁止资金操作未完成支付","notes":"无","created":"2026-06-28T10:50:00+08:00","updated":"2026-06-28T11:05:00+08:00"}
```

| 字段                     | 类型     | 说明                                                                                |
| ------------------------ | -------- | ----------------------------------------------------------------------------------- |
| `id`                   | string   | `BCxxxx`                                                                          |
| `name`                 | string   | 业务链名称                                                                          |
| `goal`                 | string   | 业务目标描述                                                                        |
| `description`          | string   | 完整业务流程/用户故事                                                               |
| `related_urls`         | string[] | 关联的页面/接口 URL                                                                 |
| `business_constraints` | string[] | 业务约束条件                                                                        |
| `walkthrough_status`   | string   | `pending`（待走通，默认）/ `partial` / `completed` / `blocked`(未走通)      |
| `walkthrough_detail`   | string   | 走到哪一步、哪些没走通、原因【除completed状态外，其他状态必须详细说明为什么没有走】 |

---

## threats.jsonl — 威胁建模清单

路径：`pentest-data/{id}/threats.jsonl`。每个威胁一行。广度建模阶段建立（`verification_status=pending`，
含权限矩阵验证补入的越权/未授权攻击面），威胁收敛阶段对账挖掘产出后消账更新验证状态。

```json
{"id":"THREAT0001","name":"IDOR-编辑他人订单","priority":"high","related_objects":["BC0001","http://host/order/update"],"description":"order/update 的 order_id 参数可改为他人订单 id，疑似越权编辑","verification_status":"confirmed","verification_report_id":"VULN-VD-URL00042-0001","verification_detail":"以 user02 越权编辑 user01 的订单成功，消账到挖掘阶段报告","notes":"无","created":"2026-06-28T11:10:00+08:00","updated":"2026-06-28T12:30:00+08:00"}
```

| 字段                       | 类型     | 说明                                                                                                                                                                                                             |
| -------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                     | string   | `THREATxxxx`                                                                                                                                                                                                   |
| `name`                   | string   | 自由命名，体现关键信息（如`存储型XSS-评论字段`）                                                                                                                                                               |
| `priority`               | string   | `critical`/`high`/`medium`/`low`；`critical` 仅限已确认漏洞                                                                                                                                            |
| `related_objects`        | string[] | 关联的业务链 id 或页面/接口 URL                                                                                                                                                                                  |
| `description`            | string   | 攻击意图或可能漏洞的具体描述                                                                                                                                                                                     |
| `verification_status`    | string   | 广度建模阶段`pending`；威胁收敛阶段对账挖掘产出后更新为 `confirmed`/`excluded`/`doubtful`/`filtered`（`doubtful`=客观条件或安全边界导致无法测试或无法验证危害；`filtered`=有防护经真实尝试绕不过） |
| `verification_report_id` | string   | `confirmed` 时填消账到的 `VULN-VD` 漏洞报告号（如 `VULN-VD-URL00042-0001`），否则 `""`                                                                                                                   |
| `verification_detail`    | string   | `confirmed` 简述确认结论；`excluded`/`doubtful`/`filtered` **必须**详述测试过程与排除/存疑/被防护依据（引用挖掘产出矩阵结论作证据）                                                                |

---

## url-inventory.json — URL 清单

路径：`pentest-data/{id}/url-inventory.json`。由 `build_url_inventory.py` 从代理
`proxy-logs/url_index.jsonl` 生成，id 沿用 `URLxxxxx`。漏洞挖掘阶段在此回填挖掘进度与结果。

```json
{
  "_note": "URL清单",
  "urls": [
    {
      "id": "URL00010",
      "url": "http://host/api/login",
      "category": "api",
      "methods": ["POST"],
      "param_names": ["ok", "profile.age", "username"],
      "permission_matrix_status": "verified",
      "generic_vuln_mining_done": "completed",
      "generic_vuln_mining_result": {
        "username": {"SQL注入": "VULN-VD-URL00010-0001", "XSS": "tested_not_found"}
      },
      "business_logic_mining_done": "completed",
      "business_logic_mining_result": {
        "_url_level": {"认证绕过": "doubtful"}
      },
      "notes": "无"
    },
    {
      "id": "URL00009",
      "url": "http://host/robots.txt",
      "category": "other",
      "methods": ["GET"],
      "param_names": [],
      "needs_review": true,
      "permission_matrix_status": "pending",
      "generic_vuln_mining_done": "pending",
      "generic_vuln_mining_result": "pending",
      "business_logic_mining_done": "pending",
      "business_logic_mining_result": "pending",
      "notes": "无"
    }
  ]
}
```

| 字段                                                            | 类型            | 说明                                                                                                               |
| --------------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `id` / `url` / `category` / `methods` / `param_names` | —              | 由代理`url_index.jsonl` 带入                                                                                     |
| `needs_review`                                                | bool            | 仅`category==other` 的记录有此字段=`true`，待 AI 判断是否实为页面/接口；判定后 AI 改 `category` 并去掉本字段 |
| `permission_matrix_status`                                    | string          | `pending`（默认）→ `verified`（广度建模阶段完成权限矩阵后）                                                   |
| `generic_vuln_mining_done` / `business_logic_mining_done`   | string          | `pending`（默认）/ `completed` / `not_applicable`（该 URL 所有参数与漏洞矩阵均不适用）                       |
| `*_mining_result`                                             | string\| object | 默认`"pending"`；`completed` 时为对象（见下）；`not_applicable` 时可为 `"not_applicable"`                  |

**挖掘结果对象结构**（`generic_vuln_mining_result` / `business_logic_mining_result`，`completed` 后）：
按参数维度，**仅记录有开展测试的漏洞类型**（不适用的不记）；值为：已发现→漏洞报告号，已测试未发现→
`"tested_not_found"`，存疑（客观或边界不可测）→`"doubtful"`，被防护（有防护绕不过）→`"filtered"`。
与具体参数无关、属 URL 本身的测试记在 `_url_level`。

```json
"generic_vuln_mining_result": {
  "_url_level": {"SSRF": "VULN-VD-URL00010-0002"},
  "username": {"SQL注入": "VULN-VD-URL00010-0001", "XSS": "tested_not_found", "命令注入": "doubtful", "路径穿越": "filtered"}
}
```

> 该字段是浓缩摘要，对应漏洞类型按 `generic`（通用）/ `business_logic`（业务逻辑）分别归入两个结果。
> **逐参数完整性**（每个参数都已比对并测试）以 `vuln-matrix/{id}.json` 为准——矩阵中每个参数都有条目
> （含 `not_applicable`）；漏洞挖掘门禁 `check_vuln_mining.py` 据矩阵校验，结果摘要只收录"已测试"的类型。

---

## mining-scope.json — 漏洞挖掘必挖清单基线

路径：`pentest-data/{id}/mining-scope.json`。由 `build_mining_scope.py` 在**进入漏洞挖掘阶段前**从当前
`url-inventory.json` 的全部 page/api URL 快照冻结生成，作漏洞挖掘覆盖度**硬门禁**基线：`check_vuln_mining.py`
只要求本基线内的 URL 逐个挖掘（有参数则有合规矩阵）。与 `url-inventory.json`（记录**当前**全部 URL 与挖掘进度）
职责分离——本文件是**冻结的必挖目标快照**，不随挖掘阶段代理新记录的 URL/参数变动。

**冻结与追加**：文件已存在则 `build_mining_scope.py` 不覆盖（保护基线不被 payload 副产物污染）；挖掘阶段新走通的
正规业务接口经复核后用 `build_mining_scope.py --add URLID...` 追加（取当前 inventory 的最新 `param_names`，带
`added_at`）。挖掘阶段 payload 产生的新 URL/参数（如自上传 shell 文件、注入参数）由门禁列为软复核项、不入基线。

```json
{
  "_note": "漏洞挖掘必挖清单基线（进入漏洞挖掘阶段前固化，作覆盖度硬门禁）",
  "frozen_at": "2026-07-16T10:00:00+08:00",
  "urls": [
    {"id": "URL00010", "url": "http://host/api/login", "category": "api", "param_names": ["password", "username"]},
    {"id": "URL00098", "url": "http://host/api/reset-password", "category": "api", "param_names": ["token"], "added_at": "2026-07-16T14:00:00+08:00"}
  ]
}
```

| 字段                                    | 类型     | 说明                                                                                             |
| --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------ |
| `frozen_at`                           | string   | 首次固化时间戳（ISO8601）                                                                        |
| `urls[].id` / `url` / `category` | —       | 由固化时 `url-inventory.json` 的 page/api 记录带入                                              |
| `urls[].param_names`                  | string[] | 固化时该 URL 的参数名快照——门禁按此校验矩阵参数覆盖；挖掘阶段该 URL 新出现的参数转软复核、不强制 |
| `urls[].added_at`                     | string   | 仅 `--add` 追加的条目有此字段=追加时间戳（审计）；首次固化的条目无                              |

> 覆盖度只认本基线：门禁遍历 `urls` 逐个校验挖掘完成度与矩阵覆盖；当前 `url-inventory.json` 中不在本基线的
> page/api URL（挖掘阶段新出现）转软复核，由 AI 判断 payload 副产物忽略 / 正规接口 `--add` 纳入。
> `check_breadth.py` 建模质量门禁**不消费**本文件——新触达正规接口的下载解析 / JS 登记 / 参数覆盖 / 权限矩阵等
> 建模硬错误仍由广度门禁（含漏洞挖掘门禁第 0 步重跑）负责。

---

## url-static-params.json — 静态请求参数基准

路径：`pentest-data/{id}/url-static-params.json`。由 `extract_static_params.py` 从页面内联脚本与外链 JS
**静态解析**「请求体在第 2 实参」的调用（`jsonPost/postJSON/axios.post` 等 post/put/patch 写方法）紧跟 URL
之后的**内联对象字面量顶层键**生成，作为每接口「应有参数」基准。与 `url-inventory`/`url_index` 的
`param_names`（代理**被动观测**）互补：前者是「代码里写了会发的」，后者是「真实流量里发过的」。
`check_breadth.py` 参数覆盖门禁比对二者，抓「静态可见却从未真实发送」的缺口（业务流程未走通，如 `order_time`）。

**保守·零误报**：只信 `confidence=high`（紧跟 URL 的内联 `{k:v}` 顶层键）；变量/动态拼装 body、fetch/axios-config
init 对象、含展开 `...`/计算属性 `[k]` 的对象一律跳过或标 `low`（门禁不消费）。非 JS 解析器，宁漏个别不误报。

```json
{
  "_note": "静态提取的每接口请求参数基准（内联对象字面量顶层键名）；供 check_breadth 参数覆盖门禁比对。非实测。",
  "generated_at": "2026-07-11T10:00:00+08:00",
  "parse_skipped": 0,
  "urls": [
    {
      "url": "http://host/api/user/create-order.php",
      "url_id": "URL00072",
      "methods": ["POST"],
      "static_params": [
        {"name": "order_time", "confidence": "high", "source_file": "pages-html/user-product_detail.php-user.html", "line": 338, "call": "jsonPost"}
      ]
    }
  ]
}
```

| 字段                                                  | 类型          | 说明                                                                                                               |
| ----------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `url`                                               | string        | 静态调用 URL 经`_resolve`（相对转绝对）+ `norm_url` 归一                                                       |
| `url_id`                                            | string\| null | 对齐 URLID（以`url-inventory` 为主源、代理 `url_index` 兜底）；仍对不上为 `null`（门禁跳过，无实测基准可比） |
| `methods`                                           | string[]      | 由调用函数名推断（仅展示，不参与比对）                                                                             |
| `static_params[].name`                              | string        | 请求体顶层键名                                                                                                     |
| `static_params[].confidence`                        | string        | `high`（内联字面量顶层键，门禁消费）/ `low`（含展开/计算属性，不消费）                                         |
| `static_params[].source_file` / `line` / `call` | —            | 溯源：源文件相对路径、行号、调用函数名                                                                             |
| `parse_skipped`                                     | int           | 括号配对失败被跳过的调用数（透明度指标，不影响门禁）                                                               |

> 门禁比对容忍代理 `_flatten_json` 的嵌套展平：静态顶层键 `items` 若实测以 `items.child` 出现即视为已覆盖，
> 避免嵌套数组/对象两侧口径不一致的假阳性。

---

## retest-list.json — 补测清单

路径：`pentest-data/{id}/retest-list.json`。由 `build_retest_list.py` **前向驱动**生成/更新（幂等 upsert）：
候选只来自 `pages.jsonl` / `js.jsonl` 中**已登记**的 in-scope 接口/链接（`discovered_urls` 的 type=api/page 及页面自身 url），
若其落入 `proxy-logs/failed_index.jsonl`（失败访问）且未成功纳入 `url-inventory` 即入清单。**不反向扫描 failed_index**
（避免 payload 探测 / 备份文件猜测 / 上传残留等**从未登记**的探测噪声反向卷入）——failed_index 仅作查表取 URLID/参数/状态码。
作为**研判台账**避免漏洞挖掘阶段忽略已登记却失败的接口。**失败默认视为"没走通正规业务流程"**——只 seed 候选、不代表已处置，须逐条研判填 `disposition`。

```json
{
  "_note": "补测清单（研判台账）",
  "items": [
    {
      "id": "URL00042",
      "url": "http://host/shop/api/admin/export.php",
      "category": "unknown",
      "methods": ["POST"],
      "param_names": ["id", "token"],
      "status_codes": {"403": 5, "no-response": 1},
      "disposition": "retest",
      "access_note": "该接口需先完成商家入驻并审核通过才可调用，测试账号无法满足前置条件，反复尝试仍 403",
      "mining_status": "completed",
      "mining_result": {"id": {"越权": "VULN-VD-URL00042-0001"}},
      "notes": "无"
    }
  ]
}
```

| 字段                                                                               | 类型            | 说明                                                                                                                                                                                        |
| ---------------------------------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id` / `url` / `category` / `methods` / `param_names` / `status_codes` | —              | 由代理`failed_index.jsonl` 带入（`status_codes` 为失败状态码分布，无响应记 `no-response`）                                                                                            |
| `disposition`                                                                    | string          | `pending`（默认待研判）/ `retest`（确属客观阻塞：系统 bug / 人机校验无法绕过 / 前置条件无法满足 → 交漏洞挖掘阶段补测挖掘）/ `blocked`（安全边界所限或确认无需/无法测 → 留痕不补测） |
| `access_note`                                                                    | string          | 走不通的客观现象 / 已尝试 / 原因；`disposition` 非 `pending` 时**必填**                                                                                                           |
| `mining_status`                                                                  | string          | `pending`（默认）/ `completed` / `not_applicable`；**仅 `disposition=retest` 需在漏洞挖掘阶段推进**，挖掘阶段回填                                                             |
| `mining_result`                                                                  | string\| object | 默认`"pending"`；`completed` 时为结果对象（结构同 `*_mining_result`）；`not_applicable` 时可为 `"not_applicable"`                                                                 |

> **闭环**：能经正常业务流程(playwright)走通的 URL 走通后进入 `url-inventory`，下次重跑 `build_retest_list.py`
> 即从本清单**剔除**（走常规挖掘）。`disposition=retest` 项由漏洞挖掘阶段**与 url-inventory URL 同等挖掘**并回填
> `mining_status/mining_result`；`disposition=blocked` 项留痕但不挖掘。漏洞挖掘门禁 `check_vuln_mining.py` 硬校验：
> 无 `pending` 研判、非 pending 项有 `access_note`、`retest` 项已挖掘（有参数则有合规矩阵）。

---

## bypass-list.json — 绕过台账

路径：`pentest-data/{id}/bypass-list.json`。由 `build_bypass_list.py` 汇集全部 `vuln-matrix/*.json` 中
`status=filtered`（有漏洞信号但防护绕不过）的条目生成/更新（幂等 upsert，以 `(url_id, 参数, 漏洞类型)` 为键）。
作为威胁收敛阶段**专项绕过台账**，交 `pentest-bypass-miner` 逐 URL 突破。

```json
{
  "_note": "绕过台账（威胁收敛阶段专项绕过目标）",
  "items": [
    {
      "id": "URL00064|product_no|SQL注入",
      "url_id": "URL00064",
      "url": "http://host/shop/api/merchant/product-delete.php",
      "param": "product_no",
      "vuln_type": "SQL注入",
      "category": "generic",
      "filter_probe_summary": "':放行 --:放行 OR:拦截 UNION:拦截",
      "bypass_status": "retested",
      "access_note": "多族绕过后以 ' || '1'='1 引号平衡布尔突破，见 VULN-VD-URL00064-0001",
      "notes": "无"
    }
  ]
}
```

| 字段                      | 类型   | 说明                                                                                                   |
| ------------------------- | ------ | ------------------------------------------------------------------------------------------------------ |
| `id`                    | string | `{url_id}\|{参数}\|{漏洞类型}` 复合键（`_url_level` 级条目的参数记 `_url_level`）                  |
| `url_id` / `url`      | string | 该 filtered 条目所属 URL                                                                               |
| `param` / `vuln_type` | string | filtered 条目的参数名（或`_url_level`）与漏洞类型                                                    |
| `category`              | string | `generic` / `business_logic`                                                                       |
| `filter_probe_summary`  | string | 由矩阵`filter_probe` 摘要带入（`符号:防护情况` 拼接），供绕过子代理快速定位已知防护                |
| `bypass_status`         | string | `pending`（默认待绕过）/ `retested`（已专项绕过：突破转 `found` 或仍 `filtered` 且证据已扩充） |
| `access_note`           | string | 绕过结论；`bypass_status=retested` 时**必填**——突破填报告号、仍绕不过填已试绕过族与判定      |

> **闭环**：绕过子代理突破后矩阵条目转 `found`+`report_id`，下次重跑 `build_bypass_list.py` 即从本台账**剔除**；
> 仍绕不过的保持 `filtered` 且 `filter_probe` 已扩充已试绕过族。威胁收敛门禁 `check_threat_convergence.py`
> 硬校验：每条 `bypass_status` 非 `pending`、非 pending 项有 `access_note`。

---

## permission-matrix/.json — 权限验证矩阵

路径：`pentest-data/{id}/permission-matrix/{URLxxxxx}.json`，文件名为 URL 清单的 url id。
以未登录基线与各已登录角色身份访问同一 URL，禁止跟随重定向逐条记录响应证据与越权判定。
判定按 `url_category` 分流：`api` 看 JSON 成功语义，`page` 看内容指纹与长度三锚点对比。

```json
{
  "url_id": "URL00027",
  "url": "http://host/merchant/index.php",
  "url_category": "page",
  "test_request": "GET http://host/merchant/index.php",
  "results": [
    {"role": "unauth",   "status_code": 302, "final_status": "login.php", "response_length": 0,    "body_fingerprint": " | len=0",             "session_valid": true, "judgment": "normal",   "notes": "无"},
    {"role": "user",     "status_code": 200, "final_status": "200",       "response_length": 5217, "body_fingerprint": "商户中心 | len=5217",     "session_valid": true, "judgment": "abnormal", "notes": "越权：user 访问 merchant 归属资源，响应贴近归属角色后台"},
    {"role": "merchant", "status_code": 200, "final_status": "200",       "response_length": 5226, "body_fingerprint": "商户中心 | len=5226",     "session_valid": true, "judgment": "normal",   "notes": "无"}
  ],
  "created": "2026-06-28T12:00:00+08:00",
  "updated": "2026-06-28T12:00:00+08:00"
}
```

| 字段                     | 类型     | 说明                                                                                             |
| ------------------------ | -------- | ------------------------------------------------------------------------------------------------ |
| `url_category`         | string   | 本条按哪种口径判定：`page`（HTML，内容指纹判越权）/ `api`（JSON，成功语义判越权）            |
| `test_request`         | string   | 完整测试请求（可取自`proxy-logs/requests/{id}.log` 的某条）                                    |
| `results`              | object[] | 每个角色（含未登录基线`unauth`）一条，字段见下                                                 |
| 角色`status_code`      | int      | 原始响应状态码（**禁止跟随重定向**，3xx 如实保留）                                         |
| 角色`final_status`     | string   | 禁跟随下的最终落点：3xx 时为`Location`（如 `login.php`=拦截信号），2xx 时为状态码字符串      |
| 角色`response_length`  | int      | 响应体字节数                                                                                     |
| 角色`body_fingerprint` | string   | 响应指纹：```                                                                                    |
| 角色`session_valid`    | bool     | 该角色测试时会话是否有效（整批与未登录基线一致 →`false`，其 `judgment` 不作数，须重登复测） |
| 角色`judgment`         | string   | `normal` / `abnormal`（非归属角色响应贴近归属角色成功页/接口即 `abnormal`）                |
| 角色`notes`            | string   | 判定说明；`abnormal` 写清越权角色与归属资源，`session_valid=false` 写明须重登复测            |

---

## vuln-reports.json — 漏洞报告清单

路径：`pentest-data/{id}/vuln-reports.json`。登记每份漏洞报告及其审核状态（漏洞挖掘与威胁收敛阶段的
补测/绕过突破产出均在此登记）；报告正文落在 `reports/{vuln_id}.md`。可用 `register_report.py` 分配编号并登记。

```json
{
  "_note": "漏洞报告清单",
  "reports": [
    {
      "vuln_id": "VULN-VD-URL00010-0001",
      "title": "管理后台接口未授权访问",
      "vuln_type": "越权/未授权访问",
      "severity": "critical",
      "phase": "VD",
      "source": "URL",
      "related_url_id": "URL00010",
      "related_threat_id": "THREAT0005",
      "report_file": "reports/VULN-VD-URL00010-0001.md",
      "review_status": "approved",
      "review_note": "证据真实、复现完整，通过",
      "created": "2026-06-28T12:00:00+08:00",
      "updated": "2026-06-28T13:00:00+08:00"
    }
  ]
}
```

| 字段                  | 类型   | 说明                                                       |
| --------------------- | ------ | ---------------------------------------------------------- |
| `vuln_id`           | string | 报告号 = 文件名（去`.md`）；编号规则见[通用约定](#通用约定) |
| `title`             | string | 漏洞标题                                                   |
| `vuln_type`         | string | 漏洞类型（如`注入/SQL注入`、`业务逻辑/越权`）          |
| `severity`          | string | 危害等级`critical`/`high`/`medium`/`low`           |
| `phase`             | string | `VD`（漏洞挖掘）                                         |
| `source`            | string | `URL`（逐 URL 挖掘产出，恒为 `URL`）                   |
| `related_url_id`    | string | 关联 URLID（逐 URL 归属，必填）                            |
| `related_threat_id` | string | 关联威胁 id（消账到该报告的威胁）；无则`""`              |
| `report_file`       | string | 报告 markdown 相对路径                                     |
| `review_status`     | string | `pending_review`（默认）/ `approved` / `rejected`    |
| `review_note`       | string | 审核通过或拒绝的详细理由；**拒绝时必填**             |

---

## reports/.md — 漏洞报告

路径：`pentest-data/{id}/reports/{vuln_id}.md`，文件名即报告号。正文结构见 `report-template.md`。
**「已验证危害」必须附真实的原始请求/响应片段或工具调用证据并标来源 op**；严禁幻觉式验证；
含复现步骤 + 完整可执行 payload。

---

## vuln-matrix/.json — 参数漏洞矩阵

路径：`pentest-data/{id}/vuln-matrix/{URLxxxxx}.json`，文件名为 URL id。漏洞挖掘阶段每个【有参数】URL 一个，
记录该 URL 每个参数比对并测试的漏洞矩阵；与具体参数无关、属 URL 本身的测试入 `_url_level`。

```json
{
  "url_id": "URL00010",
  "url": "http://host/api/login",
  "params": {
    "username": [
      {"vuln_type": "SQL注入", "category": "generic", "status": "found", "report_id": "VULN-VD-URL00010-0001", "filter_probe": {"空格": ["过滤", "空格被替换为空"], "&": ["过滤", "& 被替换为空"], "'": ["放行", "单引号原样进入并触发报错"]}, "checkpoint_response": {"SQL001": "符合。字符串 '..' 上下文，用 admin'AND(1=1)AND(1='1 闭合", "SQL002": "符合。布尔盲注成立，另测时间盲注确认", "SQL003": "符合。空格/& 被过滤，改用无空格 AND(1=1) 绕过"}, "tests": "username=admin'AND(1=1)AND(1='1 返回正常，admin'AND(1=2)AND(1='1 返回空", "basis": "布尔盲注成立"},
      {"vuln_type": "XSS", "category": "generic", "status": "filtered", "filter_probe": {"<": ["转义", "< 被实体编码为 <"], "script": ["拦截", "script 关键字触发 WAF 403"], "onerror": ["放行", "onerror 原样返回"]}, "checkpoint_response": {"XSS001": "符合。遍历 svg/video/a+事件、编码、嵌套，均被拦或编码", "XSS002": "符合。回显到 HTML 文本上下文，前端 innerHTML 渲染"}, "tests": "<svg/onload=alert(1)> 被实体编码；<script> 触发403；<a onmouseover>/<video onerror> 均被拦", "basis": "输入回显到 HTML 上下文（有漏洞信号），多族绕过真实尝试仍无法绕过，记被防护"},
      {"vuln_type": "命令注入", "category": "generic", "status": "not_applicable", "basis": "该参数不进入系统命令"}
    ]
  },
  "_url_level": [
    {"vuln_type": "认证绕过", "category": "business_logic", "status": "doubtful", "tests": "空密码登录返回400", "basis": "无法确认后端是否存在旁路"}
  ],
  "created": "2026-06-28T14:00:00+08:00",
  "updated": "2026-06-28T14:30:00+08:00"
}
```

| 字段                        | 类型   | 说明                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `params`                  | object | 键为参数名（覆盖`param_names` 每个参数），值为漏洞条目数组                                                                                                                                                                                                                                                                                                                                                               |
| 条目`vuln_type`           | string | 漏洞类型                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 条目`category`            | string | `generic`（通用）/ `business_logic`（业务逻辑），决定回填到哪个 `*_mining_result`                                                                                                                                                                                                                                                                                                                                    |
| 条目`status`              | string | `not_applicable` / `tested_not_found` / `found` / `doubtful`（客观或边界不可测） / `filtered`（有防护绕不过）                                                                                                                                                                                                                                                                                                    |
| 条目`report_id`           | string | `found` 时填漏洞报告号                                                                                                                                                                                                                                                                                                                                                                                                   |
| 条目`filter_probe`        | object | 过滤机制探测结果。**每个测试的符号/关键字一个 key**（单个符号或关键字，**禁止整条 payload**），值为二元数组 `[防护情况, 说明]`：`防护情况 ∈ {过滤, 拦截, 替换, 转义, 放行}`，`说明`含测试片段与现象。`category==generic` 且 `status ∈ {tested_not_found, doubtful, filtered}` **必填非空对象**；`found` / `not_applicable` 可空。key 疑似完整 payload（含空格/过长）门禁软告警交 AI 复核 |
| 条目`checkpoint_response` | object | 测试要点点对点应答（要点见[test-checkpoints.md](test-checkpoints.md)）：`KEY`=要点编号（如 `SQL001`），`VALUE`=是否符合的声明 + 为符合所做的操作。当该 `vuln_type` 有对应编号要点且 `status ∈ {tested_not_found, doubtful, filtered}` **必填**（KEY 须命中该类型编号集、值非空，不强制要点全覆盖）；`found` / `not_applicable` / 无要点类型可空                                                          |
| 条目`tests`               | string | `tested_not_found`/`doubtful`/`filtered` **必填**：测试 payload 与现象（`filtered` 含已试绕过族的 payload）；与 `checkpoint_response` 互补——`tests` 为自由文本总述，`checkpoint_response` 为逐编号结构化应答                                                                                                                                                                                         |
| 条目`basis`               | string | `tested_not_found`/`doubtful`/`filtered` **必填**：未发现 / 存疑 / 被防护的判定依据                                                                                                                                                                                                                                                                                                                            |

> `not_applicable`：该参数对该漏洞类型不适用。
> `doubtful`（存疑）：因**客观条件或安全边界约束**（环境不可复现、需带外无通道、前置条件不满足、`security_level`
> 禁止破坏性操作、`constraints` 禁访问等）导致**无法测试或无法验证危害**。
> `filtered`（被防护）：输入已到达 sink、**存在漏洞信号**（回显 / 进查询 / 触发报错 / 落库渲染），但**有过滤/防护，
> 按绕过阶梯多族真实尝试仍无法绕过**——留待后续换手法或防护变更后重点跟踪复查。
> 判定分流：*能测但被挡 → `filtered`；不能测（环境/边界/前置）→ `doubtful`；确无信号 → `tested_not_found`。*
> **通用漏洞（`generic`）状态分流指引**：`filter_probe` 探到防护（`过滤`/`拦截`/`替换`/`转义`）是潜在可绕信号的线索，由测试者判断该参数是否存在漏洞信号与绕过必要——有信号且值得绕过记 `filtered`（交威胁收敛阶段专项绕过），确无漏洞信号或无绕过价值记 `tested_not_found` 并在 `basis` 说明依据。门禁对此软复核抽查分流合理性，不作硬校验。
> 命名消歧：结果状态 `status=filtered`（被防护）与通用漏洞取证字段 `filter_probe`（过滤机制探测记录）是两个层级——
> 前者是单元格结论，后者是取证字段；`filtered` 单元格的 `filter_probe` 记「命中哪些防护、试过哪些绕过族」。
> **每个参数都必须有至少一条矩阵条目**（哪怕全部 `not_applicable`），否则挖掘门禁报错。

---

## url-context/.json — URL 关联上下文

路径：`pentest-data/{id}/url-context/{URLxxxxx}.json`，由 `extract_url_context.py` 生成。把 pages/js/
business-chains 中与该 URL 关联的整条记录聚合到一处，供漏洞挖掘子代理快速聚焦（无需通读全部清单）。

```json
{
  "url_id": "URL00010",
  "url": "http://host/api/login",
  "category": "api",
  "methods": ["POST"],
  "param_names": ["username", "password"],
  "params_file": "proxy-logs/params/URL00010.json",
  "requests_log": "proxy-logs/requests/URL00010.log",
  "related_pages": [],
  "related_js": [],
  "related_chains": [],
  "generated": "2026-06-28T13:50:00+08:00"
}
```

| 字段                               | 类型     | 说明                                                    |
| ---------------------------------- | -------- | ------------------------------------------------------- |
| `related_pages`                  | object[] | 自身 url==目标 或 discovered_urls 含目标 的页面整条记录 |
| `related_js`                     | object[] | discovered_urls 含目标 的 JS 整条记录                   |
| `related_chains`                 | object[] | related_urls 含目标 的业务链整条记录                    |
| `params_file` / `requests_log` | string   | 该 URL 代理参数详情 / 原始请求报文路径指针              |

---

## proxy-logs/ — 代理产物

路径：`pentest-data/{id}/proxy-logs/`，由 `scripts/proxy/` 代理脚本自动生成，**结构以
`scripts/proxy/README.md` 为准**，本 skill 只读取、不改写：

- `url_index.jsonl`：成功请求(2XX/3XX) URL 清单，每 URL 一行（`build_url_inventory.py` 的输入）。
  `category` 分 `page`/`api`/`js`/`resource`/`other`/`unknown`；`js` 类供广度门禁反查 `js.jsonl` 完整性。
- `failed_index.jsonl`：失败请求(4XX/5XX/无响应) URL 清单（备查，字段同上 + `status_codes`）。**门禁 `build_retest_list.py` 据此生成补测清单 `retest-list.json`（研判台账），供漏洞挖掘阶段补测，避免遗漏失败接口。**
- `requests/{URLxxxxx}.log`：该 URL 全部原始请求报文（含响应头 + 文本类响应体前若干字节预览），权限矩阵取测试请求用；
  请求头 `User-Agent`/`Sec-Fetch-*` 供广度门禁判定该页面是否经浏览器(playwright)走查；
  `--- RESPONSE BODY (preview...) ---` 段的响应体预览供漏洞挖掘快速判断端点行为、选取有效测试基线。
- `params/{URLxxxxx}.json`：该 URL 参数详情（`name`/`source`/`type`/`sample_value`），漏洞挖掘逐参数依据。

---

## report/ — 汇总评估报告（派生产物）

路径：`pentest-data/{id}/report/`，由 `build_report.py` 在报告汇总阶段生成，是**对上述数据文件与 `reports/*.md`
的派生汇总**（非数据源，不被其它脚本消费）：

- `{id}-report-{YYYYMMDD}.md`：完整报告 Markdown 源（可编辑后用 `render_report.py` 重渲染）。
- `{id}-report-{YYYYMMDD}.html`：自包含 HTML 版（内联样式，供查看/存档）。
- `{id}-report-{YYYYMMDD}.docx`：DOCX 版（供交付）。

三者内容一致，含测试概述 / 测试账号 / 攻击面测绘 / 漏洞统计 / 漏洞详情（仅 `review_status=approved`）/
威胁收敛结论 / 被防护与残余缺口 / 修复建议 / 质量门禁退出态。含完整请求响应（可能含凭据），交付前加密或内网传输。
