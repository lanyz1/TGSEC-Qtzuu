# 广度建模阶段 SOP

## 工作目标

尽可能全面地访问所有页面、业务流程和接口，发现潜在威胁，为后续漏洞验证与漏洞挖掘提供支撑。

输出四个 jsonl 清单：`pages.jsonl` / `js.jsonl` / `business-chains.jsonl` / `threats.jsonl`
（`url-inventory.json` 在质量门禁环节由脚本生成）。全部字段/枚举见 [data-schemas.md](data-schemas.md)。

> 下列五类工作**非线性执行**，按需灵活、循环开展，直到攻击面测绘完整。所有页面访问走 playwright、
> 接口探测/JS 下载走 curl，且**必须经代理**（见 [phase-preparation.md](phase-preparation.md)），由代理统一记录请求与参数。

## 工作原则

1. **合理规划和调度资源**：当你遇到比较复杂或庞大的任务时可以合理调用子代理协助你完成任务，必要时可以将工作计划落盘并逐个执行和检查。
2. **尽力而为而不是浅尝辄止**：当遇到问题或困难时要深入分析问题原因，尽力尝试不同的方案去解决，而不是马上记录问题并跳过。比如：遇到无法识别的图片验证码，可以尝试将验证码参数置空或不带参数提交看服务端是否会忽略；某个接口访问失败时检查是否是权限不对、参数错误或者缺少前置业务条件等。
3. **安全边界与工作守则**：严格遵守 `config.json` 的 `security_level`与 `work_guidelines`（用户下发的工作守则，**最高优先级**，全程遵守）。

## 记录纪律（贯穿全程）

1. **发现即记录**：遇到新页面/JS/业务链/威胁，立即建记录（允许字段不全），后续完成操作再回填。
   每个页面都要下载渲染后 HTML 并全文解析；每个发现的 JS（含开源库）都要在 `js.jsonl` 登记。
2. **记录绝对路径**：所有记录的URL必须是绝对路径，否则可能导致质量门禁校验失败。
3. **未开展 vs 已做没发现**：未做 → 字段留空（`""`/`[]`/`null`）；做了没发现 → 填 `not_found`（数组填
   `["not_found"]`）。例：JS 刚下载未读 `secrets:[]`；读完无密钥 `secrets:"not_found"`。
4. **及时更新**：每完成一步即更新对应记录，勿堆积未记录信息。
5. ID 用脚本式递增前缀（`PAGE`/`JS`/`BC`/`THREAT`，4 位补零）。

## 1. 页面走查

用浏览器以**每个角色身份**（含 unauthenticated）实际逐个访问目标的每个页面：

- `browser_navigate` 打开页面，`browser_snapshot` 枚举所有可交互元素，记入 `pages.interactive_elements`。
- 走查导航、提交表单（`browser_fill_form` / `browser_click`）、触发交互功能（弹窗、模态框、下拉、分页等）。
- 同一页面以不同角色访问，累加到 `accessed_as_roles`；注意不同角色可见元素/入口的差异。
- **每个页面都必须经浏览器走查**（走代理），门禁据代理请求日志的 `User-Agent`/`Sec-Fetch` 头反查浏览器访问；
  curl/脚本仅用于浏览器走查**之后**的补充测试，不能替代页面走查。

## 2. 页面解析

对每个页面**固化执行**以下流程，把页面引用的 JS、包含的 URL、可交互元素与约束条件完整落盘：

1. **下载渲染后 HTML**：playwright 打开并渲染页面后，取渲染后的完整 HTML 写入 `pages-html/` 目录，文件名取「路径+文件名+角色（可选）、`/`→`-`」，
   如 `user/product_detail.php`（角色：`user`） → `pages-html/user-product_detail.php-user.html`，在页面记录登记 `html_file`。
   **注意**：同一个页面如果多个角色都可以正常访问且访问后HTML结构有明显差异的情况，必须按角色分别记录 HTML 文件，否则记录默认角色的HTML文件即可。

   > **参考保存方法**：优先用 `browser_run_code_unsafe` 一步完成「取完整 HTML + 直接落盘到目标绝对路径」：
   >
   > ```js
   > async (page) => {
   >   const dp = page.waitForEvent('download', { timeout: 15000 });
   >   await page.evaluate(() => {
   >     const html = '<!DOCTYPE html>' + document.documentElement.outerHTML;
   >     const blob = new Blob([html], { type: 'text/html' });
   >     const a = document.createElement('a');
   >     a.href = URL.createObjectURL(blob); a.download = 'page.html';
   >     document.body.appendChild(a); a.click();
   >   });
   >   await (await dp).saveAs('<绝对路径>/pages-html/user-product_detail.php-user.html');
   > }
   > ```
   >
   > - `saveAs` 必须传**绝对路径**（相对路径会落到不可控的 MCP 工作目录）；`run_code_unsafe` 的 vm 沙箱**禁用 `require`/`import`**，只能用 `page` 原生 API 落盘，故走 `download.saveAs`。
   > - **兜底**（目标站 CSP 禁 `blob:` 致 download 不触发时）：用 `browser_evaluate` 取 `outerHTML` 带 `filename` 存到 MCP 输出目录——但该文件是 **JSON 编码字符串**（引号被转义、外层包一对引号），且 PowerShell 5.1 `Get-Content` 默认按 GBK 读会**中文乱码**，须还原为 UTF-8 无 BOM 的真实 HTML：
   >   ```powershell
   >   $h = ConvertFrom-Json ([System.IO.File]::ReadAllText($src))
   >   [System.IO.File]::WriteAllText($dst, $h, [System.Text.UTF8Encoding]::new($false))
   >   ```
   >
2. **全文阅读并解析**：完整阅读该 HTML 源码后置 `fully_parsed=true`——**必须逐行通读，不得只 grep 关键字**。
   页面数量多时可调度**后台子代理**专项承接（导航 → 取 HTML → 落盘 → 通读 → 回填页面记录），但**每个页面都须全文阅读**。基于解析结果完成关键信息提取：

- **源码提取（URL / JS）**：检查所有可能含 URL 的位置——A 标签、`link`/`img`/`iframe` 等标签属性、
  `<script src>`、内联 `<script>` 脚本、事件属性（`onclick`/`onload` 等）、`data-*` 与内联 JS 中的地址字面量：
  - **JS 引用** → 记入 `pages.discovered_js`（`src` / `abs_url` / `js_id`），每个引用 JS 都在 `js.jsonl` 登记（见 §3）。
  - **页面/API URL** → 记入 `pages.discovered_urls`，尝试访问并记 `status_code`；**每条都要判定并回填 `in_scope`**
    （用 `common.url_in_scope(url, config.scope)`，与代理记录口径一致）。
    - **表单提取的 URL 必须按字段构造带参请求访问**（带参才能触发真实接口行为，参数被代理记录）。
    - **相对路径转绝对**：处理引用 URL 时把相对路径拼成绝对 URL；返回 404 时先排查是否路径拼接错误，而非真不存在。
  - **范围内的 discovered_url 必须闭环（门禁硬性要求，防隐藏页面/接口漏挖）**：
    - `in_scope=true` 且 `type=page`（如从列表点进的**商品详情页**）→ **必须作为独立页面下载 HTML 并 `fully_parsed`**，
      不能只登记链接。
    - `in_scope=true` 且 `type=api` → **必须真实访问一次**让代理记录进 `url-inventory`（供漏洞挖掘阶段挖掘）。
    - `in_scope=false`（范围外，如靶场平台首页/第三方 CDN）→ 豁免，不要求解析/访问（类比开源 JS 不通读）。
- **可交互元素提取**：提取表单、按钮、链接、输入框等各类可交互元素 → `pages.interactive_elements`。
  关注 JS 中的**动态可交互元素**（模态框、弹窗、特定条件显示的按钮），可与「JS 深度阅读」一并执行。
- **约束条件提取**：解析页面所有文本（提示信息）与元素属性（校验限制类属性），记录全部前端校验规则与业务约束 → `pages.business_constraints`。
  注意**隐含约束**：如文本「优惠已过期」隐含「仅在指定时间段内可用优惠价」。

## 3. JS 深度阅读

**每个遇到的 JS 都在 `js.jsonl` 登记**（含开源第三方库），并对非开源 JS 通读深挖业务逻辑：

- **登记与判定**：遇到 JS 即建 `js.jsonl` 记录，判定 `is_opensource`：
  - **开源第三方库** → `is_opensource=true`、`download_status=opensource`、`local_path=""`、`fully_read=false`
    （允许不下载不通读）。
  - **非开源 JS** → `is_opensource=false`，用 curl（走代理）下载到 `js-files/`，文件名取「路径+文件名、`/`→`-`」，
    如 `/js/login.js` → `js-files/js-login.js`；成功 `download_status=downloaded`，失败 `download_status=failed`
    并在 `notes` 记原因。**每次遇到 JS 先查 `js-files/` 是否已下载**，避免重复。
- **全文阅读**：完整读每个已下载的非开源 JS（`fully_read=true`），记录：
  - 硬编码密钥 → `js.secrets`（读完无则 `not_found`）。
  - 发现的所有 URL → `js.discovered_urls`，**带参访问**并记 `status_code`；**每条判定并回填 `in_scope`**。
    JS 是隐藏接口重灾区（内联/外部脚本的 fetch 端点），其 discovered_urls 与页面侧**同等治理**：
    范围内 `type=api` 必须真实访问进 `url-inventory`、`type=page` 必须独立解析（门禁 `check_breadth.py` 硬校验）。
  - 业务约束→ `js.business_constraints`（读完无则 `not_found`），如
    - **前端校验代码逻辑**：js中的校验代码逻辑显式定义了业务约束条件，但是后端校验可能没有校验。
    - **提示/报错信息**：js代码中的提示/信息中可能包含业务约束条件，如“不允许使用积分”。
    - **隐含约束**：如文本「优惠已过期」隐含「仅在指定时间段内可用优惠价」。

## 4. 业务链遍历

基于对业务的理解枚举所有业务目标，拆解为具体业务流程/用户故事，**逐条走通**并记入 `business-chains.jsonl`：

- **枚举所有入口路径**，每个都走通：如登录有多入口、下单可「商品页直接结算」也可「购物车结算」，不同入口可能对应不同接口，不全走通会漏接口。
- **枚举旁支与异常路径**：增删改查全覆盖；支付中断后续付、审批被拒后重提等。
- **枚举所有业务约束条件**：结合页面/JS 清单的约束与遍历中的报错信息汇总（威胁建模的重要素材）。
- **考虑业务依赖、合理排序**：如商家先上架商品用户才能下单、先产生数据才能统计分析。
- **走完完整生命周期、不半途而止**：如交易成功→发货→退货，全面覆盖。
  - 走通情况记 `walkthrough_status`（`pending`/`partial`/`completed`/`blocked`）+ `walkthrough_detail`
  - **walkthrough_detail 记录要求**：除非完全走通业务链，否则必须详细说明为什么没有走通业务链，只接受客观原因如缺少必要的测试账号、系统功能bug、人机交互机制无法绕过（如图片验证码或短信验证码）或安全约束，不接受其他原因如同类业务链已走过、业务链太长等。
    **操作规范（必须遵守）**：业务链遍历必须使用playwright完成真实业务流程请求，不能使用curl或脚本工具直接构造请求代替真实的业务流程。

## 5. 威胁建模

上述过程中发现的**任何攻击面**即记入 `threats.jsonl`：

- 可以是具体接口/参数的疑似漏洞（如 `IDOR-编辑他人订单`），也可以是基于业务实现的攻击意图（如绕过特定业务限制）。
- `priority`：`critical` 仅限已确认漏洞（未授权访问、AK/SK 泄露等），未确认潜在漏洞最高 `high`。
- `related_objects` 关联业务链 id 或页面/接口 URL；`description` 写清攻击意图/可能漏洞。
- `verification_status` / `verification_detail` 本阶段固定 `pending`（验证留给后续流程）。

威胁建模可以包括但不限于以下维度：

| 维度                   | 深度自问                                                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------- |
| **数据流**       | 数据从哪进、经过哪些处理、到哪出。有没有地方输入原样进入了数据库/命令/模板？                                  |
| **权限边界**     | 接口有没有校验调用者角色？校验是在哪一层做的（中间件/每个接口/前端）？能不能绕过？                            |
| **资源归属**     | 对象 ID 是数字/有序吗？后端有没有校验"这个 ID 属不属于当前用户"？能不能枚举到别人的资源？                     |
| **状态变更**     | 这个操作会改变什么状态？状态转换有没有前置条件检查？能不能跳过中间状态直达终态？能不能从终态回退？            |
| **客户端可控值** | 金额、数量、概率、折扣、角色、回调 URL 这些"应该服务端决定"的值，客户端能不能传进来覆盖？                     |
| **并发场景**     | 这个操作能不能并发执行？同一资源的并发写会不会产生重复效果（双花、重复领取、超卖）？                          |
| **输出展示**     | 用户输入最终会渲染到哪个页面的哪个元素？用的是 innerHTML 还是 textContent？API 返回的 HTML 字段有没有转义？   |
| **认证与会话**   | 登录/注册/找回密码流程有没有可枚举的差异响应？Token 可不可以伪造或重放？                                      |
| **注入面**       | 输入是否进入 SQL/OS 命令/模板/XML/JSON 路径？转义是充分的吗？有没有二次处理让转义失效？                       |
| **文件操作**     | 上传：类型校验在哪里做、用什么方式、能不能绕过？路径可控吗？下载/删除：路径参数有没有穿越风险？               |
| **业务逻辑**     | 价格/数量可以是负数或 0 吗？优惠/积分/抽奖可以重复使用吗？签名验证的 key 是公开的还是私密的？状态机能逆向吗？ |

## 6. 权限矩阵验证

攻击面/URL 覆盖经门禁确认完整后（`check_breadth.py` 的 URL 覆盖检查清零、全部 page/api 已纳入
`url-inventory.json`），以**未登录基线**与**所有已有角色**身份访问每个 page/api URL，判断是否存在越权/未授权。
判定引擎统一用 `permission_probe.py`，消除各自临时写判定代码带来的口径不一与假设错误：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\permission_probe.py --project {id}
```

脚本读 `sessions.json` 各角色 cookie（登录由主代理按项目认证方式先行完成并写入会话池），逐 URL
产出标准 `permission-matrix/{id}.json`，并在 stdout 汇总**疑似越权（abnormal）清单**。其判定遵循三条铁律：

- **会话有效性先行**：某角色 cookie 若在整批 URL 上与未登录基线表现完全一致（状态码+长度），判为会话失效
  （`session_valid=false`），其判定不作数——**主代理须重新登录刷新 `sessions.json` 后重跑**，避免「会话失效被
  重定向到登录页」冒充「正确的权限拦截」而漏判越权。
- **禁止跟随重定向**：`status_code` 保留原始值（3xx 如实记录），`final_status` 记最终落点。
  **3xx→登录页 是拦截信号，200→后台是放行信号**，二者语义相反，绝不能被自动跟随抹平成同一个 200。
- **分流判定**：
  - **接口型（`api`，JSON）**：非归属角色拿到 `success` 且非 401/403 即越权。
  - **页面型（`page`，HTML）**：以未登录为「拦截锚点」、URL 归属角色为「成功锚点」，非归属角色响应的
    **内容指纹（`<title>`）与长度**贴近成功锚点、远离拦截锚点即判越权。**页面型越权返回的是 HTML 后台
    而非 JSON，绝不能用 `"success":true` 作判据**——普通用户拿到「商户中心」后台页即是垂直越权。
- 各项目认证差异（特殊 header/签名/带参接口）可由 AI 补充针对性测试，但**判定口径以本脚本三铁律为准**；
  带参接口从 `proxy-logs/requests/{id}.log` 取真实请求带参复测。脚本完成后自动置各 page/api 的
  `permission_matrix_status=verified`。
- **发现权限风险即补入威胁清单**：`judgment=abnormal`（越权/未授权，无论页面型还是接口型）逐条**补入
  `threats.jsonl`** 作为攻击面威胁——新 `THREAT` 记录，`related_objects` 指向该 URL、`description` 写清越权
  意图与涉及角色、`verification_status=pending`，交后续漏洞挖掘逐参数验证、威胁收敛阶段消账。

## 完成与流转

四个清单记录完整、权限矩阵验证完成、异常项已补入威胁清单后，进入**广度建模质量门禁**
（见 [quality-gates.md](quality-gates.md)）：`build_url_inventory.py` 生成 URL 清单 → `build_retest_list.py`
生成补测清单 → `extract_page_urls.py` 抽取页面候选 URL 供复核 → `extract_static_params.py` 提取每接口静态
请求参数基准 → `check_breadth.py` 硬检查（攻击面/URL 覆盖 + 参数覆盖清零后，跑 `permission_probe.py`、使
权限矩阵覆盖检查清零）+ AI 复核，通过并输出报告后，更新 `state.json`：
`phase=3`、`breadth=completed`、`vuln_mining=in_progress`。

**质量门禁硬校验失败常见问题及处理**：

- **页面/api未覆盖**：通常是漏访问了，但是要分析遗漏的根本原因，看看是不是某个页面没走查，某个页面或JS解析不到位，或者某个业务链遗漏了没走通，要优先补完没做到位的动作，而不是简单的构造curl进行访问。
- **请求进入了failed_index.jsonl**：通常是没有走正规的业务流程完成请求（仅通过curl构造，导致数据或权限受限无法正常访问），需要分析正常的业务链，**应该通过playwright走通正常流程进行访问**，不可通过猜测或遍历等方式强行尝试构造成功的访问。
  - **门禁流转（补测清单）**：质量门禁阶段由 `build_retest_list.py` **前向驱动**把 `pages.jsonl`/`js.jsonl` 中**已登记**的接口/链接里落入 `failed_index`、未纳入 url-inventory 的汇成补测清单 `retest-list.json`（默认 `disposition=pending`）；**不反向扫描 failed_index**（避免探测噪声）。失败**默认按"没走通业务"处置**、门禁对被发现接口保留**强告警**——须逐条研判：能走通的先用 playwright 走通（走通后自然进入 url-inventory、下次重跑本脚本即从清单剔除）。
  - **特殊情况**：确实是系统bug或人机校验机制无法绕过导致走不通的，经反复排查确认（尤其人机校验绕过）和AI复核后，置 `disposition=retest` 并填 `access_note`，交漏洞挖掘阶段补测挖掘；**基于安全边界无法走通**的置 `disposition=blocked` 并填 `access_note` 留痕、不作补测挖掘目标。
