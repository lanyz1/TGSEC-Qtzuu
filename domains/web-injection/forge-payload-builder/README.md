# Forge

不接 AI、不执行、不校验语义的确定性 payload 拼接器。

**第一次用请看 [`使用说明.md`](使用说明.md)**——这份 README 是开发者笔记。

只依赖 PyYAML。源码运行，无构建步骤。

> 原名「Payload 拼接器」。改成 Forge 是因为它做的事就是锻造：
> 把槽位、变量、绕过按顺序锻成一件成品。

## 怎么跑起来

**只依赖 PyYAML 一个包**，源码运行，无构建步骤：

```bash
python -m pip install pyyaml
```

然后二选一：

```
forge.bat                 # 终端界面（TUI），双击即可
forge-gui.vbs             # 图形界面（GUI），双击即可
```

Linux / macOS 用 `./forge.sh` 和 `./forge-gui.sh`。

**`cmd` 里 `python` 得在 PATH 上**——装 Python 时勾 "Add Python to PATH"。
启动脚本会先切到自己的目录，所以从哪调用都行。

**POSIX 启动器为什么带 `.sh`**：引擎包目录就叫 `forge/`，文件 `forge`（无扩展名）
和目录 `forge/` 在同一层无法共存。Windows 靠扩展名区分得开（`forge.bat` vs `forge/`），
所以只有 POSIX 侧需要后缀。

**GUI 为什么是 `.vbs` 而不是 `.bat`**：`.bat` 由 `cmd.exe` 执行，而 `cmd.exe`
是控制台程序，Windows 必然给它分配一个黑框；脚本里的依赖检查要跑约 1 秒，
于是双击后黑框会在屏幕上停约 1 秒才消失。`.bat` 没有办法隐藏自己的控制台。
`.vbs` 由 `wscript.exe` 执行——它是 GUI 子系统程序，不分配控制台，拉起的
子进程也全部用隐藏窗口启动，所以全程看不到黑框。

> 这里曾经还有一个 `forge-gui.bat`，给 Windows Script Host 被组策略禁用的环境兜底。
> **已删除**：它要付的代价（每次都闪 1 秒黑框）大于它兜的场景，
> 而 WSH 被禁用时直接命令行跑 `python gui.py` 同样能看到报错。

### 两个界面怎么选

| | 终端界面（TUI） | 图形界面（GUI） |
| --- | --- | --- |
| 依赖 | 无 | 需要 tkinter（标准安装自带） |
| 环境 | **SSH / 跳板机 / 无显示器** | 本机桌面 |
| 交互 | 编号菜单，不用记任何参数 | 点选 |

两个界面共用同一套引擎接口，生成逻辑一行都不重复。

> 曾经有过一个 flag 式 CLI（`gen --vuln ... --component ...`），27 个参数。
> 它和 GUI 做的是同一件事——把选择喂给引擎——只是交互方式不同，属于冗余，已删除。
> 要脚本化就直接 `import forge`，引擎那 7 个纯函数就是 API。

### 「为什么这条模板不在这里」是可点的

- **前提勾选框带影响面计数**：`页面有回显位 (57)` = 勾上会筛掉 57 条
- **「显示缺前提的」**把因缺前提被筛掉的模板灰显列出来，带上原因。
  只带前提原因的——「漏洞类型不符」那些是你自己选的筛子，塞进来只是噪音
- **选中一条灰显的** → 面板显示「它需要：页面有回显位」+ 一个**「放宽这 N 项并用它」**按钮，
  点了直接放宽并选中它

## 用法

跑起来就是菜单，不需要记任何参数：

```
 1 漏洞类型 SQL 注入 sqli        2 组件 （不限）          3 内容类型 （不限）
 4 版本     （不限）             5 输出层 原始载荷 raw, curl 命令 curl
 6 提交方式 URL 参数 query       7 绕过 无
 8 目标前提 无
--------------------------------------------------------------------------
 可用 134 条 / 共 584 条
   1) sqli.mssql.detect.version          MSSQL 版本回显
   2) sqli.mssql.union.basic             MSSQL UNION 联合查询
   ...

 编号=改字段   t=选模板   s=填参数   g=生成   q=退出
> 
```

面向使用者的完整说明见 [`使用说明.md`](使用说明.md)。

**脚本化**：不走界面，直接 `import forge`：

```python
from forge import engine

rules = engine.load_rules("data")
res = engine.generate(rules, engine.make_state(
    vuln="sqli", component="mysql", template="sqli.mysql.union.basic",
    slots={"close": "'", "cols": "3", "pos": "2"},
    bypasses=["bypass.case.alternate"], outputs=["raw", "curl"],
))
print(res["payload"])   # ' UnIoN SeLeCt 1,2,3 -- -
```

引擎对外就是那几个纯函数，GUI 和 TUI 用的都是它们。
**槽位和变量填的是 id 和原值**，不是界面上那层中文——`engine.label()` 只负责显示。

## 执行契约

```
加载数据 → 用户选择 → 过滤 → 组装 → 渲染 → 约束校验
                        │      │
                        │      ├─ 槽位填入        ← 先
                        │      ├─ 变量替换        ← 后（契约 1：必须先于一切编码/绕过）
                        │      └─ 按用户顺序 fold 绕过
                        └─ 硬排除记 reason，版本不符记 note 但不禁用
```

对应 [`Payload 生成工具方案.md`](Payload%20生成工具方案.md) 的 §4（用户选择状态模型，
「状态变化后重新计算可用模板 / 可用绕过 / 冲突项 / 失效项」）与 §10（编码 / 转义管线的分层顺序）。

## 目录

```
forge/
  engine.py    加载 / 版本比较 / 过滤 / 组装管线 / 展示标签 / 计算型占位符
  bypass.py    8 个 codec + 5 种闭类型绕过 + shell 转义
  output.py    提交方式（含 multipart）→ 请求中间态 → 渲染器 + 约束校验
  syntax.py    组装后语法校验（Python / JSON / XML / Jinja2 / PHP 序列化）
  phpser.py    PHP 序列化结构 DSL：结构你写，字节长度与元素个数工具算
  tui.py       终端界面
data/
  labels.yaml        界面展示标签（中文 + id），**只影响显示，不影响取值**
  requires.yaml      前提受控词表（42 个键）
  bypasses.yaml      绕过定义（41 条）
  sqli/mysql.yaml    MySQL 模板（36 条）
  sqli/mssql.yaml    MSSQL（29 条）
  sqli/postgresql.yaml  PostgreSQL（28 条）
  sqli/oracle.yaml   Oracle（22 条）
  sqli/sqlite.yaml   SQLite（19 条）
  rce/linux.yaml     Linux 命令注入（35 条）
  rce/windows.yaml   Windows 命令注入（16 条）
  ssti/jinja2.yaml   Jinja2（16 条，声明 syntax_lang）
  ssti/java.yaml     Freemarker / Velocity / Thymeleaf / SpEL / OGNL / Groovy（13 条）
  ssti/php.yaml      Smarty / Twig / Latte / Blade（10 条）
  ssti/python.yaml   Mako / Tornado / Django（10 条）
  ssti/node.yaml     EJS / Nunjucks / Pug / DoT / Handlebars（7 条）
  ssti/ruby.yaml     ERB / Slim / Liquid（7 条）
  ssti/generic.yaml  引擎无关探测（3 条，配对定界符）
  ssti/dotnet.yaml   Razor（3 条）
  ssti/client.yaml   AngularJS / Vue 客户端注入（3 条）
  xxe/generic.yaml   XXE（14 条，多行 XML 文档）
  ssrf/generic.yaml  SSRF（13 条，云元数据 / 协议族 / gopher / DNS 重绑定）
  traversal/generic.yaml  路径穿越（14 条）
  lfi/generic.yaml       文件包含（27 条，php://filter / 日志 / RFI / proc）
  upload/generic.yaml     文件上传（18 条，multipart）
  deser/java.yaml    Java 反序列化（20 条，文本形态）
  deser/php.yaml     PHP 对象注入（15 条，<<len()>> 与 <<phpser>> 结构定制）
  deser/python.yaml  pickle 协议 0 / yaml.load（8 条）
  deser/node.yaml    node-serialize / funcster（5 条）
  nosql/mongodb.yaml MongoDB 注入（15 条，json-body 提交）
  ldap/generic.yaml  LDAP 注入（12 条）
  xpath/generic.yaml XPath 注入（11 条）
  xss/generic.yaml   跨站脚本（24 条，content_type 是 html）
  redirect/generic.yaml  开放重定向（18 条）
  jwt/generic.yaml   JWT 攻击（20 条，none / 算法混淆 / kid / jku）
  proto/generic.yaml 原型链污染（20 条，合并污染 + gadget）
  leak/generic.yaml  敏感信息泄露（26 条，VCS / 配置凭据 / 调试端点 / 备份）
  cors/generic.yaml  CORS 配置错误（10 条，探测请求 + 受害者浏览器 PoC）
  crlf/generic.yaml  CRLF 响应头注入（15 条，拆响应头 / 拆响应体）
  csrf/generic.yaml  跨站请求伪造（22 条，自动提交表单 + JSON 接口）
golden/               29 个文件，1053 条样本
  sqli.yaml / sqli-dialects.yaml / sqli-more.yaml / mssql.yaml
  rce.yaml / ssti.yaml / ssti-engines.yaml
  other-vulns.yaml / server-more.yaml / web-more.yaml
  deser.yaml / deser-more.yaml / nosql-ldap-xpath.yaml
  xss.yaml / lfi.yaml / redirect.yaml / jwt.yaml / proto.yaml
  leak.yaml / cors.yaml / crlf.yaml / csrf.yaml        按主题分批
  coverage.yaml                        覆盖率补齐
  expansion-sqli.yaml / expansion-other.yaml           按类型扩充
  expansion-params.yaml                参数化：新槽位真的接到了 body 上
  bypasses.yaml                        41 条绕过逐条断言（含 8 个 codec）
  slot-options.yaml                    字典槽位的每个选项都覆盖到
  phpser.yaml                          PHP 结构 DSL 的样本
使用说明.md           给使用者看的（先读这个）
实战案例.md           14 个 CTF 场景的 GUI 逐步操作（入门 / 进阶 / 高级）
测试流程.md           验收时的操作步骤
模板写作规范.md       给写规则的人看的
Payload 生成工具方案.md  原始设计方案（§ 编号被上面三份文档引用）
gui.py               Tkinter GUI（stdlib，零新增依赖；最外层竖向可滚）
forge.bat                双击启动，终端界面
forge-gui.vbs            双击启动，图形界面（wscript 宿主，不闪黑框）
forge.sh / forge-gui.sh  Linux/macOS（`.sh` 见上文「POSIX 启动器为什么带 .sh」）
new_template.py      模板脚手架（生成模板 + 黄金样本骨架）
validate_rules.py    规则库离线校验（编写期，不进运行路径）
run_golden.py        黄金样本 + 渲染/前提/GUI/标签 冒烟 + 覆盖率检查
```

共 584 条模板、41 条绕过、1053 条黄金样本，覆盖 20 个漏洞类型。

## 加数据

**先读 [`模板写作规范.md`](模板写作规范.md)**——数据是这个项目的主体（行数是引擎代码的两倍），
加模板不是填空，是提供一条确认过可用的载荷。规范里写了字段语义、占位符语法、
`requires` 词表的用法、黄金样本的纪律、以及踩过的坑。

```bash
python new_template.py sqli.postgresql.union.dump --name "PostgreSQL UNION 读库名"   --ctype sql-expression
```

脚手架**只追加、不重写**已有文件，生成模板 + 黄金样本骨架。
骨架里的 `content_type` 故意留空，所以**校验会报错**——那是让你知道还没填完的信号。

- **加模板**：在 `data/<漏洞类型>/<组件>.yaml` 里加一条。id 必须以 `<漏洞类型>.<组件>.` 开头。
- **加绕过**：在 `data/bypasses.yaml` 里加一条。类型只能是 `case` / `replace` / `wrap` / `encode` / `join` 五种，**不支持自定义逻辑**。
- 加完跑 `python validate_rules.py`。

### `case` / `replace` 要开 `skip_quoted`

```yaml
- id: bypass.space.plus
  type: replace
  params: {pattern: " ", with: "+", skip_quoted: true}
```

不开的话会改到字符串字面量**里面**：`'a b'` → `'a+b'`。
语法依旧合法，语义已经错了——**这类损坏是静默的**。

实现是启发式的引号扫描（不是 parser）：片段首字符若是引号，按代码处理
（注入片段的开头引号是**闭合**上层上下文的逃逸符，不是开启引号）；之后贪心配对。
边界是"片段本身就是完整字面量"时会保护不足，失败方向是少保护而非多破坏。

校验脚本会对没开这个开关的 `case` / `replace` 告警。

### `<<len(NAME)>>` 计算型占位符

```yaml
body: 's:<<len(value)>>:"<<value>>";'
```
```bash
--var value=admin     → s:5:"admin";
--var value=管理员     → s:9:"管理员";
```

长度是**字节数**，不是字符数——`管理员` 是 3 个字符但 9 个字节，写成 `s:3:` PHP 会解析失败。
这和 HTTP 的 `Content-Length` 是同一个坑。求值发生在变量替换阶段（先于一切编码和绕过）。
变量没填时，`<<len(value)>>` 和 `<<value>>` 一起保留字面量（契约 3 的延伸）。

### 槽位有两种写法

```yaml
# 字符串型：各选项互相独立
slots:
  close: {options: ["'", '"', ""], default: "'"}
body: "<<close>> UNION SELECT 1-- -"

# 字典型：一组值必须联合选择（配对定界符、开闭标签这类）
slots:
  d:
    options:
      - {id: jinja2, open: "{{", close: "}}"}
      - {id: erb,    open: "<%=", close: "%>"}
    default: jinja2
body: "<<d.open>>7*7<<d.close>>"
```

字典型槽位**只认 `<<d.字段>>`**，裸写 `<<d>>` 会被校验脚本拦下——
拆成两个独立槽位是不行的，用户能拼出 `{{` + `%>` 这种垃圾且两边取值各自都合法。

## `requires` 前提筛选

模板的 `requires` 是**受控词表**（`data/requires.yaml`，42 个键），语义是
「载荷要生效，目标必须具备这个条件」。界面上就是**字段 8**：

```
 8 目标前提 页面有回显位、目标可出网        ← 勾 = 目标没有这个条件
```

- **默认什么都不筛**；每勾一个，可用集合只减不增
- 是**硬排除**，被排除的记原因「缺少前提：<展示名>」
- **不做正向声明**（"我确认有 X"）：那会把没声明的全筛掉，默认行为反直觉

实测（`smoke_doc` 会盯着这些数字，改了数据不改文档就会红）：sqli 默认可用 **134 条**，
勾上「没有回显 + 不报错 + 无布尔差异 + 出不了网 + 加固到位」后收窄到 **44 条**。

前提影响面最大的几条（按 **584 条全量**统计，界面上勾选框后面的 `(N)` 就是这个数）：
`已在 lhost 上起监听` 74、`目标可出网` 68、`目标加固不到位` 61、
`目标过滤存在缺陷` 58、`需要事先侦察出的目标信息` 57、`页面有回显位` 57。

`requires` 加新键要同时改 `data/requires.yaml`，否则 `validate_rules.py` 会报错。

## 展示标签（`data/labels.yaml`）

界面上字段和参数显示成「中文 + 原 id」：`闭合符 close`、`SQL 表达式 sql-expression`、
`SQL 注入 sqli`。中文是给人看的，id 才是**真正的取值**——文档、黄金样本、
报错信息、`import forge` 的脚本里用的全是 id。

标签是数据，不是代码：加一个维度、改一句中文都不用动引擎。查不到的名字
**原样显示 id**，所以新槽位不必先登记才能用。`smoke_labels` 钉住两件事：

1. 规则库里出现过的取值都得有中文——漏一个就是界面上留一句黑话
2. **标签不能漏进取值路径**——生成结果里出现「闭合符」就是灾难，黄金样本会一起红

### 标签是按维度全局的，同名会撞

`slot` / `var` 两张表是**按名字全局查**的，不区分漏洞类型。所以同一个名字
在两个类型里含义不同时，只能有一个中文：

> JWT 里想用 `sub` 表示 token 的主体声明，但 `sub` 已经被 SSRF 的
> `sub: 子域名` 占了——写 JWT 模板的人看到的是「子域名」，只能改名成 `subject`。

这是**有意的取舍**：按（漏洞类型 × 名字）建两级表能让文案更准，但每次加模板都要
多填一层，而绝大多数名字跨类型含义一致。撞名时改名字比改表结构便宜。

## 校验

```bash
python validate_rules.py   # 规则库静态检查：字段、id 前缀、占位符、互斥对称、版本语法、词表封闭性
python run_golden.py       # 逐字节比对 + 渲染冒烟 + 覆盖率检查
python run_golden.py --mutate   # 再加：逐条篡改模板 body，验证样本真的在断言
```

`validate_rules.py` 抓的是**永久性**错误——一条模板少个引号，此后每次生成都是错的。
`run_golden.py` 抓的是**静默**错误——替换时机、编码层顺序这类。

> **文档一致性也在这里查**。`smoke_doc` 会：
> 1. 断言 `使用说明.md` / 本文件里引用的数字仍然成立（模板数、绕过数、前提键数、
>    各种筛选结果数）——数据一变就红，提醒去改文档
> 2. 扫根目录所有 `.md`，揪出「教用户敲一个已删除的子命令」的句子
>    （判定规则：`python -m forge <子命令>`，邻近几行出现「已删除 / 原来 / 曾经」的算记录历史，豁免）
>
> 第 2 条的正则里**工具名是写死的**。改名时如果只改了包名没改这里，
> 检查会**静默失效**——不再报错，但也不再检查任何东西。

黄金样本只驱动引擎层，**兜不住交互层的默认值**。实现期就发生过
参数默认值给死、导致 `rce` 永远空结果，而当时全部样本仍是绿的。

加新模板后应当同时加黄金样本——不加的话 `run_golden.py` 会直接警告。
**期望值必须手写核算，不能跑一遍工具把输出粘进去**——那样只是把当前行为（含 bug）固化成规范。

`--mutate` 是更强的检查：逐条篡改模板 body，看是否**至少有一条样本会失败**。
篡改后无样本失败的模板 = 假覆盖（样本里写了这个 id 但没在断言它）。
它在本项目抓到过两次真问题——参数默认值、`skip_quoted` 的空样本。
**它是唯一能发现"测试没测到东西"的手段。**

## 已知边界

- 运行期语法校验只覆盖 Python / JSON / XML / Jinja2 / PHP 序列化。
  SQL、Shell、各模板引擎**没有可靠 parser**，输出会明确标注「无可靠 parser」，
  不会假装校验过（方案 §13「语法正确性定义」）。
  模板可声明 `syntax_lang` 显式指定语法，优先于内容类型的推导——`ssti.jinja2.*` 用了这个，
  而 `ssti.generic.*` 的引擎随槽位变，如实返回「未校验」。
- 利用层编码（绕过里的 `encode`）和传输层编码（`place.*`）会叠加出双重编码。
  这是**用户的选择，工具不拦截**，但会在提示里告知实际编码了几次。
  方案 §10 把这两层明确分开了（「必须区分：利用层编码 / 传输层编码」），
  工具的分层与它一致，只是选择不拦。
- 绕过**不做过滤，全量可选**。这一点**偏离了方案 §9**——
  §9 原本写的是「工具根据当前状态，只显示'当前可生效'的绕过」。
  实现下来发现"可生效"判不准（跨类型套用也有能用的），
  于是改成全量可选、跨类型套用时给一条提示。方案 §9 保留原样作为设计意图记录。
  「可生效」的判定只保留在**互斥提示**上（`⚠ 互斥：…`），那是确定性的。
- `slots` 可空可非空。空槽位的模板就是「不可拆分模板」，走同一条代码路径。
- 回调地址类变量（`lhost`/`lport`）**没有默认值**，漏填时保持 `<<lhost>>` 字面量。
  这是有意的：漏填应该产出一个明显不可用的串，而不是指向真实地址的串。
- **变量值落在模板的引号字面量内、且值里含同种引号时会提示**，但不代改。
  例如 `xp_cmdshell '<<cmd>>'` 里塞进 `net user's`，会在第一个引号处提前闭合字面量、截断载荷。
  SQL / PowerShell / Java / Shell 多无可靠 parser，这类损坏是静默的，所以必须提示。
  工具不替你转义（方案 §1 已确定原则：「用户选择什么，工具就按什么生成」）。
- `content_type` 描述的是**载荷文本的语法**，不是它达成的效果。MSSQL 的 `xp_cmdshell`
  载荷是 T-SQL（`sql-expression`）但效果是执行命令——按语法归档，
  理由见方案 §3 核心概念（「最终内容类型 = 系统命令」和「输出格式 = curl」不是一回事）。
  完整的内容类型枚举在方案 §7。
- **载荷是文本串，表达不了二进制**。分界不在技术之间，而在**同一门技术内部**：
  文件上传的魔术字节只收 `GIF89a` / `%PDF-1.4` / `RIFF`，不收 PNG 的 `PNG`；
  反序列化里 pickle **协议 0 是纯 ASCII 可做**，协议 2+ 不行；Java 的
  Fastjson/Jackson/XStream/XMLDecoder/SnakeYAML 都可做，JDK 原生序列化不行。
  二进制形态走外部生成器（ysoserial / phpggc）+ 数据里的外层包装模板。
  对应方案 §2「不做什么」与 §7 的内容类型枚举。
- **XML 语法校验只验良构性、不解析实体**。用 `xml.etree` 会把含 DTD 的合法 XXE 载荷
  误报为 `undefined entity`——已改用 expat 并验证对外部实体零解析（0.000s，无文件/网络访问）。
  代价是：内部子集的标记声明里出现参数实体引用这类**规范违规会被如实报出**
  （`xxe.generic.oob.exfil.inline` 就是这种，标 `theory`，照常输出只标红）。

## GUI 的三个易错点（都踩过）

1. **参数区只在「选中的模板变了」时重建**——按 template id 比对。
   每次按键都重建会打断输入（焦点丢失）。
   但清空控件字典时**必须同时清掉那个缓存键**，否则重建被跳过、参数区空掉。
2. **重新选中同一条模板必须是空操作**。上面那个 bug 就走这条路。
3. **`nametowidget(nb.tabs()[i])` 拿到的是外层 Frame，不是里面的文本框**，
   对它调 `.get()` 会 AttributeError。要自己存下文本框控件。

这三个都是**驱动 GUI 跑起来**才发现的，读代码看不出来。
`run_golden.py` 的 `smoke_gui` 把它们固化成了断言（无显示环境自动跳过）。

## 跨内容类型组合

SQL 外壳套命令载荷这类需求，界面上做两次：

1. 生成内层（比如 PowerShell 载荷），复制 `raw` 输出
2. 把漏洞类型切到 `sqli`、组件切到 `mssql`，选 `sqli.mssql.xp_cmdshell.exec`
3. 按 `s` 把内层粘贴进 `cmd` 变量

工具会提醒：

```
提示：变量 cmd 落在模板的 ' 字面量内，而值里含引号 ' —— 会提前闭合字面量、截断载荷。
     需按目标语法转义（SQL / PowerShell 写成两个引号 ''）
```

**没有做成一步完成**：那需要给嵌套模板的槽位/变量做命名空间隔离
（两层可能都有同名的 `comment` / `sep` 槽位），而分两次粘贴零成本地解决了同样的需求。
