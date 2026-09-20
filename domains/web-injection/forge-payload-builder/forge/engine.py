"""核心引擎：加载、过滤、组装（§4 执行契约）。

    1. 加载数据     启动时一次
    2. 用户选择     → GenerationState
    3. 过滤         筛出可用模板，被排除的记原因码
    4. 组装         槽位 → 变量 → 按用户顺序 fold 绕过
    5. 渲染         提交方式 → 请求中间态 → 输出形态
    6. 约束校验     提示，不拦截
"""

import glob
import os
import re

import yaml

from . import output, syntax
from .bypass import apply_bypass, quoted_spans


class RuleError(Exception):
    pass


# ---------------------------------------------------------------- 1. 加载


def load_rules(data_dir):
    """按漏洞类型分目录，文件名即 id 前缀，重复 id 直接报错。"""
    templates, bypasses, seen, requires = [], [], {}, []
    labels = {}
    for path in sorted(glob.glob(os.path.join(data_dir, "**", "*.yaml"), recursive=True)):
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        for t in doc.get("templates") or []:
            if t["id"] in seen:
                raise RuleError("重复 id: %s (%s 与 %s)" % (t["id"], seen[t["id"]], path))
            seen[t["id"]] = path
            t["_source"] = os.path.relpath(path, data_dir)
            templates.append(t)
        for b in doc.get("bypasses") or []:
            if b["id"] in seen:
                raise RuleError("重复 id: %s" % b["id"])
            seen[b["id"]] = path
            bypasses.append(b)
        requires += doc.get("requires") or []
        # 展示标签（data/labels.yaml）。分维度合并，多文件写同一维度也能并起来
        for kind, table in (doc.get("labels") or {}).items():
            labels.setdefault(kind, {}).update(table or {})

    # 空规则库必须**报错**，不能静默返回空集。
    # `data/` 被改名、或拷贝时漏了它，glob 一个文件都没匹配到——不抛的话
    # 界面会显示「0 条模板」，还会把原因说成「规则库本身可能没覆盖这个组合」，
    # 把人往「换个筛选组合试试」的方向引，而真正的问题是数据根本不在这儿。
    # tui.main 和 gui.main 都已经写好了 except 分支，等的就是这个异常。
    if not templates:
        raise RuleError("规则库为空：%s —— 检查 data/ 是否存在、是否被改名，"
                        "或拷贝是否完整" % data_dir)
    return {
        "templates": templates,
        "bypasses": bypasses,
        "requires": requires,
        # id -> 展示名。requires 是受控词表，筛选与报错都按它显示
        "requires_name": {r["id"]: r["name"] for r in requires},
        "labels": labels,
    }


# ---------------------------------------------------------------- 展示标签
# 界面显示「中文 id」，取值、文档、黄金样本里仍然是 id。
# 标签表在 data/labels.yaml，查不到就原样显示 id——这张表可以慢慢补。


def label(rules, kind, value):
    """把 id 显示成「中文 id」。没登记过标签的原样返回。"""
    if value is None:
        return None
    zh = ((rules.get("labels") or {}).get(kind) or {}).get(str(value))
    return "%s %s" % (zh, value) if zh else str(value)


def unlabel(rules, kind, text):
    """把「中文 id」还原成 id。已经是 id、或没登记过的，原样返回。

    用反查而不是 `rsplit(" ", 1)`：值是用户填的自由文本时（变量区）
    可能自带空格，按空格切会切错。
    """
    if text is None:
        return None
    text = str(text)
    for key, zh in ((rules.get("labels") or {}).get(kind) or {}).items():
        if text == "%s %s" % (zh, key):
            return key
    return text


# ---------------------------------------------------------------- 版本比较
# 单一朴素语法：">=2.4.0 <2.4.49" / ">1.0" / "*"（§15.1-2，不做生态适配）


def _vkey(v):
    parts = [p for p in re.split(r"[._\-+]", str(v).strip()) if p]
    key = [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts]
    while key and key[-1] == (0, 0, ""):
        key.pop()
    return tuple(key)


def version_match(spec, version):
    if not spec or spec == "*":
        return True
    if not version:
        return True  # 未知版本：全部显示（§11）
    have = _vkey(version)
    for clause in str(spec).split():
        m = re.match(r"^(>=|<=|>|<|=)?\s*(.+)$", clause)
        op, want = (m.group(1) or "="), _vkey(m.group(2))
        n = max(len(have), len(want))
        a = have + ((0, 0, ""),) * (n - len(have))
        b = want + ((0, 0, ""),) * (n - len(want))
        if op == ">=" and not a >= b:
            return False
        if op == "<=" and not a <= b:
            return False
        if op == ">" and not a > b:
            return False
        if op == "<" and not a < b:
            return False
        if op == "=" and a != b:
            return False
    return True


# ---------------------------------------------------------------- 3. 过滤
# 两级：
#   reason —— 硬排除（漏洞类型 / 内容类型 / 组件不符），usable=False
#   note   —— 软提示（版本不符），usable=True，**不禁用**（§11）


def filter_templates(rules, state):
    """硬排除记 reason，版本不符记 note（软标记，不禁用）。

    `state["without"]` 是用户声明「我的目标没有这些前提」的受控词表键集合。
    **用户声明事实、工具据此收窄**——和 `--component mysql` 是同一类操作，
    不违反「工具不替用户判断」。这是硬排除：用户既然说没有，展示需要它的模板就是噪音。
    """
    without = set(state.get("without") or [])
    names = rules.get("requires_name") or {}
    # 拼错的前提键必须报错，不能静默忽略——否则用户以为筛了，其实没有
    unknown = without - set(names)
    if unknown:
        raise RuleError("前提键 %s 不在词表里（见 data/requires.yaml）"
                        % "/".join(sorted(unknown)))
    out = []
    for t in rules["templates"]:
        reason = note = None
        if state.get("vuln") and state["vuln"] not in (t.get("vuln") or []):
            reason = "漏洞类型不符"
        elif state.get("content_type") and state["content_type"] not in (t.get("content_type") or []):
            reason = "内容类型不符"
        elif state.get("component") and (t.get("component") or []) and state["component"] not in t["component"]:
            reason = "组件不符"
        elif without and (set(t.get("requires") or []) & without):
            miss = sorted(set(t.get("requires") or []) & without)
            reason = "缺少前提：%s" % "/".join(names.get(m, m) for m in miss)
        elif not version_match(t.get("version"), state.get("version")):
            note = "版本不符"

        out.append({
            "id": t["id"],
            "name": t.get("name", t["id"]),
            "reason": reason,
            "note": note,
            "usable": reason is None,
            "template": t,
        })
    return out


def pick_template(rules, state, rows=None):
    """取本次要用的模板。用户指定则用指定的，否则取第一条可用的。

    `rows` 是调用方**已经算好的**过滤结果。`generate` 本来就要那一份
    （算 note、算 available），再让这里重算一遍是纯浪费——过滤 584 条
    要 192µs，而它占一次 GUI refresh 的四分之一。传进来就复用。
    """
    if rows is None:
        rows = filter_templates(rules, state)
    want = state.get("template")
    if want:
        for f in rows:
            if f["id"] == want:
                if not f["usable"]:
                    raise RuleError("模板不可用（%s）: %s" % (f["reason"], want))
                return f["template"]
        raise RuleError("模板不存在: %s" % want)
    avail = [f for f in rows if f["usable"]]
    return avail[0]["template"] if avail else None


def relax_suggestions(rules, state, limit=5):
    """§4.1 的后半句：**放宽哪个条件能看到东西**。

    对每个生效中的筛子，单独去掉它算一次可用数量，按增量排序。
    「为什么没有它」只解释了现状，「放宽哪一条」才是用户下一步能做的动作。

    实现在引擎层而不是 CLI：这是交互逻辑，GUI 要用同一份。
    """
    names = rules.get("requires_name") or {}

    def count(st):
        return sum(1 for r in filter_templates(rules, st) if r["usable"])

    base = count(state)
    if not base and not any((state.get("vuln"), state.get("content_type"),
                             state.get("component"), state.get("without"))):
        # 一个筛子都没开还是空的 —— 说明规则库本身有问题，不是筛得太紧
        return {"base": 0, "suggestions": []}

    # 描述里**不写命令行开关**——界面层有两套（TUI/GUI），写死 flag 名会过期。
    # （真过期过一次：删掉 flag CLI 之后这里还印着 --vuln。）
    cands = []
    if state.get("vuln"):
        cands.append(("去掉漏洞类型限定「%s」" % state["vuln"], {"vuln": None}))
    if state.get("component"):
        cands.append(("去掉组件限定「%s」" % state["component"], {"component": None}))
    if state.get("content_type"):
        cands.append(("去掉内容类型限定「%s」" % state["content_type"], {"content_type": None}))
    without = list(state.get("without") or [])
    for k in without:
        cands.append(("放宽前提「%s」" % names.get(k, k),
                      {"without": [x for x in without if x != k]}))

    out = []
    for desc, patch in cands:
        st = dict(state)
        st.update(patch)
        n = count(st)
        if n > base:
            out.append({"desc": desc, "gain": n - base, "total": n})
    out.sort(key=lambda x: (-x["gain"], x["desc"]))
    return {"base": base, "suggestions": out[:limit]}


def bypass_pairs(rules, state):
    """已经**同时选中**且互斥的绕过对，返回 [(a, b), ...]。

    界面不该各自从 visible_bypasses 的结果里凑——那样会把"某个**没选中**的绕过
    与已选中的互斥"也算进来，显示成「互斥：xxx」，读起来像自己和自己冲突。
    """
    chosen = list(state.get("bypasses") or [])
    s = set(chosen)
    seen, out = set(), []
    for bid in chosen:
        b = next((x for x in rules["bypasses"] if x["id"] == bid), None)
        for other in (b.get("incompatible_with") or []) if b else []:
            if other in s:
                k = tuple(sorted((bid, other)))
                if k not in seen:
                    seen.add(k)
                    out.append(k)
    return sorted(out)


def bypass_name(rules, bid):
    """绕过的**展示名**（中文）。

    绕过没有走 labels.yaml——它的中文名就写在 `bypasses.yaml` 的 `name` 字段里，
    那是规则定义的一部分，不是一层显示映射。取不到就退回 id，界面不会出现空白。

    GUI 和 TUI 都从这里取名，免得两边各写一份、万一哪天格式不一致。
    **只给中文名，不带 id**：带上 id 之后 TUI 那行会到 88 列（超 80 会折行），
    而 41 条绕过的中文名两两不重复，不带 id 也不会混淆。
    """
    b = next((x for x in rules["bypasses"] if x["id"] == bid), None)
    return (b.get("name") or bid) if b else bid


def visible_bypasses(rules, state):
    """绕过不做过滤，全量可选，只标互斥（§4.1）。"""
    chosen = set(state.get("bypasses") or [])
    out = []
    for b in rules["bypasses"]:
        bad = sorted(set(b.get("incompatible_with") or []) & chosen)
        out.append({"id": b["id"], "name": b.get("name", b["id"]), "conflict": bad or None})
    return out


# ---------------------------------------------------------------- 4. 组装


def option_id(opt):
    """槽位选项的取值键：字符串就是它本身，字典取 id。"""
    return opt["id"] if isinstance(opt, dict) else opt


def option_text(opt):
    """槽位选项的**显示**文本。

    字典选项用它自己的 `name`——`id` 是给取值和黄金样本用的短标识
    （`jinja2` / `nested` / `aws_iam`），`name` 才是给人看的那句。
    字符串选项就是它本身：`'` / `-- -` / `0x41` 是要照抄进载荷的，
    加中文反而会让人抄错。
    """
    if isinstance(opt, dict):
        return opt.get("name") or opt["id"]
    return str(opt)


def fill_slots(body, template, state):
    """4.1 槽位填入。空槽位走同一条路径（无需填充）。

    槽位选项有两种形态：

    1. **字符串** —— 值直接代入 `<<name>>`
    2. **字典** —— 一组需要**联合选择**的值，用 `<<name.字段>>` 取。
       典型场景是模板定界符：`{{ }}` / `${ }` / `<%= %>` 的开闭必须配套，
       拆成两个独立槽位会让用户拼出 `{{` + `%>` 这种垃圾且无法静态校验。

    字典选项必须带 `id`（CLI 上的取值键）和 `name`（展示名）。

    返回 (替换后的 body, 解析后的槽位值)。**第二项是权威值**——用户没填的
    取的是 default，`<<select(...)>>` 这类计算型占位符必须按它求值，
    按原始 state 查会漏掉所有默认值。

    字典槽位的**字段值**也一并记进第二项，键是 `槽位名.字段名`。
    否则 `<<select(cols,pos,src.col)>>` 里的 `src.col` 查不到，会被当成
    SQL 里的裸标识符原样输出——语法合法、语义已错，正是要防的那种静默损坏。
    """
    chosen = state.get("slots") or {}
    resolved = {}
    for name, spec in (template.get("slots") or {}).items():
        val = chosen.get(name, spec.get("default", ""))
        resolved[name] = val
        opt = next((o for o in spec["options"] if option_id(o) == val), None)
        if opt is None:
            raise RuleError("槽位 %s 的值 %r 不在 options 里" % (name, val))

        if isinstance(opt, dict):
            # 只认 <<name.字段>>；不支持裸 <<name>>（字典选项没有单一取值可代入，
            # 允许它只会制造歧义）。写了裸形式由 validate_rules.py 报错。
            for k, v in opt.items():
                if k != "id":
                    body = body.replace("<<%s.%s>>" % (name, k), str(v))
                    resolved["%s.%s" % (name, k)] = str(v)
        else:
            body = body.replace("<<%s>>" % name, opt)
    return body, resolved


# §9 的默认值清单。用户没填就有默认值的走这里；不在这张表里的（如回调地址
# lhost/lport）原样保留 <<name>>，见 substitute_vars。
VAR_DEFAULTS = {
    "host": "example.com",
    "path": "/",
    "param": "id",
    "method": "GET",
    "cmd": "whoami",
    "shell": "bash",
    "os": "linux",
}
# 这张表**只有这些键**，而且不能再往里加 `user` 这类名字：
# `<<select(cols,pos,user)>>` 的第三个参数是「先按名字查、查不到当字面量」，
# 而 Oracle 的 `user` 是个货真价实的 SQL 关键字。往这里加一个 `user`，
# 就会把 `UNION SELECT user,2,3` 静默改成 `UNION SELECT admin,2,3`——
# 语法依旧合法、语义已经错了，正是 §4 里点名的那类损坏。
# 需要默认值就走模板自己的槽位（槽位只在声明它的模板里生效，不会外溢）。


def _iter_call(body, name):
    """找出所有 `<<name(...)>>`，返回 [(start, end, 参数串)]。

    不能用正则 `<<name\\(([^)]*)\\)>>`——参数里带括号就断了
    （`pg_read_file('x')`、`concat(0x7e,version())`）。这里按括号配对扫。
    """
    out, i, tag = [], 0, "<<%s(" % name
    while True:
        j = body.find(tag, i)
        if j < 0:
            return out
        depth, k = 1, j + len(tag)
        while k < len(body) and depth:
            if body[k] == "(":
                depth += 1
            elif body[k] == ")":
                depth -= 1
            k += 1
        if depth or body[k:k + 2] != ">>":   # 括号没闭合 / 后面不是 >>
            i = j + len(tag)
            continue
        out.append((j, k + 2, body[j + len(tag):k - 1]))
        i = k + 2


def _iter_select(body):
    """找出所有 `<<select(...)>>`。"""
    return _iter_call(body, "select")


def _iter_rep(body):
    """找出所有 `<<rep(...)>>`。"""
    return _iter_call(body, "rep")


def expand_select(body, lookup):
    """展开 `<<select(cols,pos[,expr])>>` —— 生成带回显位的列清单。

    探注入的两步基础操作都靠它：

        <<select(cols,pos)>>                  cols=3 pos=1  → "1,2,3"
        <<select(cols,pos,expr)>>             cols=3 pos=2  → "1,@@version,3"
        <<select(cols,pos,pg_read_file('x'))>> cols=3 pos=2 → "1,pg_read_file('x'),3"

    - 前两个参数是**名字**（槽位或变量），值必须是数字
    - 第三个参数**先按名字查**，查不到就当字面量用。这样带包装的表达式
      （`pg_read_file('<<filepath>>')`）可以内联写，不必为它单开一个槽位。
      只按**前两个逗号**切分，所以表达式里的逗号不会切坏参数

    **任何一环没填就原样透传**（契约 3），不猜。
    但「回显位超过列数」是用户选错了，**要报出来**——静默留个占位符在载荷里
    等于给用户一个明显坏掉但没人说的串。

    返回 (展开后的 body, 问题列表)。
    """
    issues = []

    def one(args_raw):
        parts = [a.strip() for a in args_raw.split(",", 2)]
        if len(parts) not in (2, 3):
            issues.append("<<select(...)>> 只接受 2 或 3 个参数：%s" % args_raw)
            return None
        cols, pos = lookup.get(parts[0]), lookup.get(parts[1])
        if not (str(cols).isdigit() and str(pos).isdigit()):
            return None                # 没填——契约 3，原样透传
        n, p = int(cols), int(pos)
        if not 1 <= p <= n:
            issues.append("回显位 %d 超过列数 %d —— 列清单没能生成，载荷里留着占位符" % (p, n))
            return None
        expr = None
        if len(parts) == 3:
            expr = lookup.get(parts[2], parts[2])   # 名字优先，否则当字面量
            if str(expr) == "":
                return None
        return ",".join(str(expr) if (i == p and expr is not None) else str(i)
                        for i in range(1, n + 1))

    # 从后往前替换，避免前面的展开改变后面的下标
    for start, end, args in reversed(_iter_select(body)):
        got = one(args)
        if got is not None:
            body = body[:start] + got + body[end:]
    return body, issues


def _iter_phpser(body):
    """找出所有 `<<phpser(...)>>`。"""
    return _iter_call(body, "phpser")


def expand_phpser(body, lookup):
    """展开 `<<phpser(NAME)>>` —— 把不含长度的 PHP 结构描述补成合法序列化串。

    参数的取值必须来自**已声明的槽位或变量**（不像 `<<select>>` 的第三个参数
    允许写字面量）：结构描述动辄上百字符，写进 body 里没人维护得动，
    而且校验器也没法替它检查结构对不对。

    这是「必须按目标定制」那类载荷的出口：POP 链的类名、属性名、可见性、
    嵌套形状只有使用者知道，而**字节长度和元素计数**是最容易写错、
    错了又最不显眼的部分——那些交给 `forge/phpser.py`。

    名字查不到（没填）就原样透传（契约 3）；结构本身有问题则**报出来并透传**，
    绝不吐一个半截的串出去。
    """
    from . import phpser as _phpser

    issues = []
    for start, end, args_raw in reversed(_iter_phpser(body)):
        name = args_raw.strip()
        if not name:
            issues.append("<<phpser(...)>> 需要 1 个参数（结构描述所在的槽位或变量名）")
            continue
        if name not in lookup:
            continue                      # 没填——契约 3
        spec = str(lookup[name])
        if not spec.strip():
            continue
        # 结构描述里可以嵌 `<<变量>>`（POP 链里塞 `http://<<lhost>>/` 很常见）。
        # 在这里先替换掉，免得那些字符被当成字符串内容算进长度。
        for key in set(re.findall(r"<<([^<>]+)>>", spec)):
            k = key.strip()
            if k in lookup:
                spec = spec.replace("<<%s>>" % k, str(lookup[k]))
        try:
            got = _phpser.build(spec)
        except _phpser.SpecError as e:
            issues.append("<<phpser(%s)>> 的结构描述有问题：%s —— 载荷里留着占位符"
                          % (name, e))
            continue
        body = body[:start] + got + body[end:]
    return body, issues


# `<<rep>>` 的重复次数上限。没有它的话 `<<rep(99999999,x)>>` 会当场把内存吃光——
# 数据是手写的，但**手滑多打几个 0 是常事**，而这类崩溃发生在用户机器上。
MAX_REP = 100


def expand_rep(body, lookup):
    """展开 `<<rep(n,item)>>` —— 把 `item` 重复 `n` 次。

    ```
    <<rep(depth,form.seq)>>   depth=3 form.seq="....//"  →  "....//....//....//"
    <<rep(2,'a')>>                                        →  "aa"
    ```

    存在的理由：穿越序列、`../` 层级、重复的占位字符这类载荷**长度本身就是选项**
    （目标路径有几层，事先不知道）。以前只能把三个 `<<form.seq>>` 硬写在 body 里，
    用户改不了层数——而这是实打实要按目标调的一个参数。

    - `n` 与 `item` **都先按名字查**（槽位 / 变量 / 字典槽位字段），查不到就当字面量。
      `n` 求值后必须是数字，否则**原样透传**（契约 3，和 `<<select>>` 一致）
    - 超过 `MAX_REP` 报出来并原样透传，不产出半截载荷
    - 展开结果里的 `<<变量>>` 会走后面的变量替换，所以 item 可以是带占位符的串

    返回 (展开后的 body, 问题列表)。
    """
    issues = []

    def one(args_raw):
        parts = [a.strip() for a in args_raw.split(",", 1)]
        if len(parts) != 2:
            issues.append("<<rep(...)>> 只接受 2 个参数：%s" % args_raw)
            return None
        n = lookup.get(parts[0], parts[0])
        if not str(n).isdigit():
            return None                # 没填 / 不是数字——契约 3，原样透传
        n = int(n)
        if n > MAX_REP:
            issues.append("<<rep(...)>> 的重复次数 %d 超过上限 %d —— 没有展开，"
                          "载荷里留着占位符" % (n, MAX_REP))
            return None
        item = lookup.get(parts[1], parts[1])
        return str(item) * n

    for start, end, args in reversed(_iter_rep(body)):
        got = one(args)
        if got is not None:
            body = body[:start] + got + body[end:]
    return body, issues


def substitute_vars(body, state, slot_values=None):
    """4.2 变量替换 —— 契约 1：必须先于一切编码和绕过。

    契约 3：未知变量原样透传，不报错。

    **回调地址类变量（lhost/lport/domain）故意不给默认值**——保留 <<lhost>>
    字面量能保证用户没填时产出的是不可用的串，而不是指向某个真实地址的串。

    返回 (替换后的 body, 提示列表)。

    提示来自「变量落在模板的引号字面量内、而值里含同种引号」这种情况：
    `'<<cmd>>'` 里塞进 `net user's`，会在第一个引号处提前闭合字面量，**载荷被截断**。
    SQL / PowerShell / Java / Shell 大多没有可靠 parser，这类损坏是静默的，所以必须提示。
    只提示不代改——§1 决定「用户给什么就按什么生成」，工具不替用户转义。
    """
    values = dict(VAR_DEFAULTS)
    values.update(state.get("vars") or {})
    # <<select>> 的参数可以引用槽位，所以查找表要把槽位也并进来。
    # 只用于查值——槽位本身在 fill_slots 阶段已经填进 body 了，不会重复替换。
    lookup = dict(slot_values or {})
    lookup.update(values)
    body, sel_issues = expand_select(body, lookup)
    body, rep_issues = expand_rep(body, lookup)
    body, ser_issues = expand_phpser(body, lookup)
    spans = quoted_spans(body)
    # **每个占位符落在哪一段引号里，必须在替换之前一次算好。**
    # 在循环里现算会错：循环会改 body 的长度，而 spans 是替换前的偏移。
    # 只要模板里有**两个以上变量**、靠前那个替换后长度变了，靠后的就查错区间，
    # 于是「变量落在引号字面量内、值里又含引号」这条提示**静默消失**——
    # 而它报的正是「载荷会被提前截断」这种最该说出来的事。
    # （多变量模板实测踩到过：filepath 从 12 字节变 24 字节，后面那条就不再提示。）
    inside_of = {}
    for name in values:
        ph = "<<%s>>" % name
        inside_of[name] = next((body[a:b] for a, b in spans if ph in body[a:b]), None)

    notes = list(sel_issues) + list(rep_issues) + list(ser_issues)
    for name, val in values.items():
        ph = "<<%s>>" % name
        lenph = "<<len(%s)>>" % name
        if ph not in body and lenph not in body:
            continue
        if ph in body:
            inside = inside_of.get(name)
            # **只有值里含「和字面量同一对」的引号才会截断**：`'...'` 里塞进 `"`
            # 是安全的，塞进 `'` 才提前闭合。曾经这里对三个引号一视同仁地报，
            # 结果 CSRF 那种「单引号字面量里放一段 JSON」的模板一直背着一条假提示。
            if inside is not None and inside[0] in str(val):
                q = inside[0]
                notes.append(
                    "变量 %s 落在模板的 %s 字面量内，而值里含引号 %s —— 会提前闭合字面量、截断载荷。"
                    "需按目标语法转义（SQL / PowerShell / 单引号 JS 里写成两个 %s%s；"
                    "JSON 与双引号 JS 里写成 \\%s）"
                    % (name, q, q, q, q, q))
        # <<len(NAME)>> —— PHP 序列化的长度前缀是**字节**数，不是字符数。
        # 中文名 "管理员" 是 3 个字符但 9 个字节，写 s:3: 会直接解析失败。
        body = body.replace(lenph, str(len(str(val).encode("utf-8"))))
        body = body.replace(ph, str(val))
    return body, notes


def nest(body, inner, depth=0, max_depth=1):
    """`<<payload>>` 嵌套。**必须有深度上限**，否则 A 嵌 A 会无限展开（§9）。"""
    if "<<payload>>" not in body:
        return body
    if depth >= max_depth:
        raise RuleError("嵌套超过最大深度 %d" % max_depth)
    return nest(body.replace("<<payload>>", inner, 1), inner, depth + 1, max_depth)


# ---------------------------------------------------------------- 5+6. 生成


def generate(rules, state, rows=None):
    """§4 执行契约主干。返回结果字典，不做任何 I/O。

    结果里带 `rows`（本次的过滤结果）。界面要拿它画模板列表，而过滤一次
    是 192µs——**同一次调用里算两遍是纯浪费**，让调用方从结果里取。

    `rows` 也可以由调用方传进来。界面必须这么做：它得**先**过滤出列表、
    据此把选中的模板挪到一条可用的上，**然后**才生成——而过滤只依赖
    vuln / component / content_type / version / without，**不看选中的模板**，
    所以先算的那份对生成仍然有效。
    """
    if rows is None:
        rows = filter_templates(rules, state)
    tpl = pick_template(rules, state, rows)
    if tpl is None:
        return {"ok": False, "reason": "当前条件下没有可用模板",
                "available": rows, "rows": rows}

    steps, var_notes = [], []
    text = tpl["body"]
    text, slot_values = fill_slots(text, tpl, state)
    steps.append({"step": "槽位填充", "text": text})
    text, var_notes = substitute_vars(text, state, slot_values)
    steps.append({"step": "变量替换", "text": text})
    if state.get("nest"):
        text = nest(text, state["nest"])
        steps.append({"step": "嵌套", "text": text})

    applied, noop = [], []
    for bid in state.get("bypasses") or []:
        b = next((x for x in rules["bypasses"] if x["id"] == bid), None)
        if b is None:
            raise RuleError("绕过不存在: %s" % bid)
        new = apply_bypass(text, b)
        # 跑了但没变 —— 多半是顺序问题。比如「注释替代空格」排在 URL 编码之后，
        # 此时空格已经变成 %20，替换找不到目标，静默什么都不做。
        if new == text and b.get("type") != "wrap":
            noop.append(b.get("name", bid))
        text = new
        applied.append(b)
        steps.append({"step": b.get("name", bid), "text": text})

    req = output.place(text, state)
    outs = [(name, output.render(name, req, text, state)) for name in (state.get("outputs") or ["raw"])]

    content_type = (tpl.get("content_type") or [None])[0]
    note = next((r["note"] for r in rows if r["id"] == tpl["id"]), None)
    return {
        "ok": True,
        "template": tpl["id"],
        "note": note,
        "payload": text,
        "steps": steps,
        "request": req,
        "outputs": outs,
        "rows": rows,
        "checks": (var_notes
                   + (["绕过 %s 没有改变载荷 —— 可能被前一步抵消了（检查绕过顺序）"
                       % "、".join(noop)] if noop else [])
                   + output.check_constraints(text, state, applied)),
        "syntax": syntax.annotate(text, content_type, tpl.get("syntax_lang")),
    }


DEFAULTS = {
    "vuln": "sqli",
    # 内容类型与组件默认都不过滤：它们只是收窄用的筛子，不是必填项。
    # 若内容类型给死默认值，`--vuln rce` 不带 --content-type 会得到空结果。
    "content_type": None,
    "component": None,
    "submit": "query",
    "method": "GET",
    "host": "example.com",
    "path": "/",
    "param": "id",
    "shell": "bash",
    "outputs": ["raw", "encoded", "curl"],
    "bypasses": [],
    "slots": {},
    "vars": {},
    "constraints": {},
    # 用户声明「目标没有这些前提」的受控词表键，见 filter_templates
    "without": [],
}


def make_state(**kw):
    s = dict(DEFAULTS)
    s.update({k: v for k, v in kw.items() if v is not None})
    return s
