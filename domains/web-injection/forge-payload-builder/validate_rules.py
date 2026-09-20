"""规则库离线校验（§10.1 A）。

写法错误是**永久性**的：一条模板少个引号，此后每次生成都是错的。
所以这个脚本抓的是编写期错误，不进运行路径——可以慢，可以有重依赖。

    python validate_rules.py [data_dir]
"""

import glob
import os
import re
import sys

from forge import engine
from forge.bypass import BYPASS_TYPES, CODECS

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

REQUIRED = ["id", "name", "vuln", "content_type", "body"]
# 变量替换阶段认得的内置自由变量（§9）。与引擎保持同源，避免两处漂移。
BUILTIN_VARS = {"payload", "header", "cookie"} | set(engine.VAR_DEFAULTS)

errors, warnings = [], []


def resolvable(name, base, slot_fields):
    """`name` 是不是引擎查得到的东西。

    三种来源：已声明的槽位/变量（`base`）、字面量、**字典槽位的字段**。
    第三种是 `<<select(src.n,pos,src.col)>>` 这种写法要用的——
    `fill_slots` 会把字段值按 `槽位名.字段名` 记进查找表，所以引擎查得到。
    """
    if name in base:
        return True
    head, _, field = name.partition(".")
    return bool(field) and field in slot_fields.get(head, set())


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


def check_ids(templates, data_dir):
    """id 前缀必须与文件路径一致（按漏洞类型分目录、文件名即 id 前缀）。"""
    for t in templates:
        rel = t["_source"].replace(os.sep, "/")
        expect = rel[:-5].replace("/", ".") if rel.endswith(".yaml") else rel
        tid = t["id"]
        if not tid.startswith(expect + "."):
            err("id 前缀与路径不符: %s 应形如 %s.*（文件 %s）" % (tid, expect, rel))


def check_template(t, bypass_ids, vocab_ids):
    tid = t["id"]

    for f in REQUIRED:
        if not t.get(f):
            err("%s: 缺少必需字段 %s" % (tid, f))

    # ---- 槽位 ----
    slot_fields, string_slots = {}, set()
    for name, spec in (t.get("slots") or {}).items():
        opts = spec.get("options")
        if not opts:
            err("%s: 槽位 %s 没有 options" % (tid, name))
            continue
        # 逐选项处理，不要按槽位整体分支——混用时整体分支会拿到 dict 去 set() 里塞，直接崩
        keys, fields, n_dict = [], set(), 0
        for o in opts:
            if isinstance(o, dict):
                n_dict += 1
                if "id" not in o:
                    err("%s: 槽位 %s 的字典选项缺少 id" % (tid, name))
                    continue
                # `{id: null}` 在 YAML 的流式映射里**不会报错**，会静默变成 None——
                # 而 `"id" in o` 是 True，上面那道检查拦不住它。
                # 实际踩到过：取值键变成 None 之后，选它等于选了空值。
                if not isinstance(o["id"], str) or not o["id"]:
                    err("%s: 槽位 %s 的字典选项 id 必须是**非空字符串**，实际 %r"
                        % (tid, name, o["id"]))
                    continue
                keys.append(o["id"])
                fields |= set(o) - {"id"}
            else:
                keys.append(o)
        if n_dict and n_dict != len(opts):
            err("%s: 槽位 %s 的 options 混用了字符串和字典两种形态" % (tid, name))
        is_dict = n_dict > 0

        if len(set(keys)) != len(keys):
            err("%s: 槽位 %s 的 options 里有重复取值" % (tid, name))
        if spec.get("default") is not None and spec["default"] not in keys:
            err("%s: 槽位 %s 的 default=%r 不在 options 的取值里" % (tid, name, spec["default"]))

        if is_dict:
            slot_fields[name] = fields
        else:
            string_slots.add(name)

    # ---- 占位符是否有定义 ----
    # 注意：字典型槽位的名字**不**进 base，否则裸写 <<d>> 会被当成合法引用漏过去
    base = string_slots | set(t.get("vars") or []) | BUILTIN_VARS
    body = t.get("body", "")

    # <<select(cols,pos[,expr])>> 要按**括号配对**扫，不能用 [^<>]+ 的通用正则：
    # 表达式里带括号（pg_read_file('x')）就断了，会误报成一堆未声明的名字。
    for _s, _e, args_raw in engine._iter_select(body):
        parts = [a.strip() for a in args_raw.split(",", 2)]
        if len(parts) not in (2, 3):
            err("%s: <<select(%s)>> 只接受 2 或 3 个参数" % (tid, args_raw))
            continue
        # 前两个必须是「引擎查得到」的名字（它们要解析成数字）；第三个可以是名字，
        # 也可以直接写字面量（`banner`、`pg_read_file('x')`），不做检查
        for i, a in enumerate(parts[:2]):
            if not resolvable(a, base, slot_fields):
                err("%s: <<select(%s)>> 的第 %d 个参数 %r 不是已声明的槽位、变量，"
                    "也不是字典槽位的字段" % (tid, args_raw, i + 1, a))

    # <<phpser(NAME)>> 的结构描述必须来自已声明的名字（不接受字面量，
    # 理由见 engine.expand_phpser）
    for _s, _e, args_raw in engine._iter_phpser(body):
        if len([a for a in args_raw.split(",") if a.strip()]) != 1:
            err("%s: <<phpser(%s)>> 只接受 1 个参数（结构描述所在的槽位或变量名）"
                % (tid, args_raw))
            continue
        name = args_raw.strip()
        if not resolvable(name, base, slot_fields):
            err("%s: <<phpser(%s)>> 的参数 %r 不是已声明的槽位、变量或字典槽位字段"
                % (tid, args_raw, name))

    # <<rep(n,item)>> 的 n 要能解析成数字，规则同 <<select>> 的前两个参数
    for _s, _e, args_raw in engine._iter_rep(body):
        parts = [a.strip() for a in args_raw.split(",", 1)]
        if len(parts) != 2:
            err("%s: <<rep(%s)>> 只接受 2 个参数" % (tid, args_raw))
            continue
        if not resolvable(parts[0], base, slot_fields) and not parts[0].isdigit():
            err("%s: <<rep(%s)>> 的第一个参数 %r 不是已声明的槽位、变量、字典槽位字段，"
                "也不是字面量数字" % (tid, args_raw, parts[0]))

    for ph in re.findall(r"<<([^<>]+)>>", body):
        if ph in base:
            continue
        if ph.startswith("select(") or ph.startswith("rep(") or ph.startswith("phpser("):
            continue  # 已由上面的括号配对扫描处理；这里再判会漏掉参数里的表达式
        m = re.fullmatch(r"len\((.+)\)", ph)
        if m:
            # <<len(NAME)>> —— 计算型占位符，求值发生在变量替换阶段
            if m.group(1) not in base:
                err("%s: <<len(%s)>> 里的 %s 不是已声明的槽位或变量" % (tid, ph, m.group(1)))
            continue
        head, _, field = ph.partition(".")
        if head in slot_fields:
            avail = "/".join(sorted(slot_fields[head])) or "（无）"
            if not field:
                err("%s: 槽位 %s 是字典型选项，必须写成 <<%s.字段>>，可用字段：%s" % (tid, head, head, avail))
            elif field not in slot_fields[head]:
                err("%s: <<%s>> 引用了槽位 %s 不存在的字段 %r，可用字段：%s" % (tid, ph, head, field, avail))
            continue
        if head in string_slots:
            err("%s: 槽位 %s 是字符串型，只能写 <<%s>>，不能写 <<%s>>" % (tid, head, head, ph))
            continue
        err("%s: body 里的 <<%s>> 既不是槽位也不是变量" % (tid, ph))

    # 声明了 slots/vars 但 body 里没用上。
    # 注意要把**计算型占位符参数里的名字**也算进来——`<<select(cols,pos)>>` 和
    # `<<len(value)>>` 里的 cols/pos/value 是实打实被用到的，
    # 不认它们会报一堆"声明了但没用到"的假警告。
    used = set(re.findall(r"<<([^<>]+)>>", body))
    for _s, _e, args_raw in engine._iter_select(body):
        used |= {a.strip() for a in args_raw.split(",", 2)}
    for _s, _e, args_raw in engine._iter_rep(body):
        used |= {a.strip() for a in args_raw.split(",", 1)}
    for _s, _e, args_raw in engine._iter_phpser(body):
        used |= {a.strip() for a in args_raw.split(",")}
    for m in re.finditer(r"<<len\(([^)]*)\)>>", body):
        used |= {a.strip() for a in m.group(1).split(",")}

    # 槽位选项的**值里**也能嵌占位符，典型是 `<<select(cols,pos,expr)>>` 的 expr
    # 槽位选到 `group_concat(<<col>>,0x7c)`——槽位先填、变量后替换，
    # 所以嵌进去的变量占位符到下一阶段才求值，这是能通的。
    #
    # 但只允许引用**变量**：槽位之间互相引用会变成顺序依赖
    # （fill_slots 按声明顺序逐个 replace，先填的那个才不会吃掉后填的占位符），
    # 那种不确定性不该出现在数据里，直接报错。
    # 字符串选项本身就是值，字典选项取 id 以外的字段
    opt_text = " ".join(
        str(o) if not isinstance(o, dict)
        else " ".join(str(v) for k, v in o.items() if k != "id")
        for spec in (t.get("slots") or {}).values()
        for o in spec.get("options") or [])
    allowed_in_slots = set(t.get("vars") or []) | BUILTIN_VARS
    for ph in re.findall(r"<<([^<>]+)>>", opt_text):
        if ph in allowed_in_slots:
            used.add(ph)
        elif ph in string_slots or ph.partition(".")[0] in slot_fields:
            err("%s: 槽位选项的值里引用了槽位 <<%s>>——槽位之间不能互相引用"
                "（fill_slots 按声明顺序替换，结果取决于声明顺序），只能引用变量" % (tid, ph))
        else:
            err("%s: 槽位选项的值里的 <<%s>> 既不是已声明的变量，也不是内置变量" % (tid, ph))
    used_heads = {u.partition(".")[0] for u in used}
    for name in (t.get("slots") or {}):
        if name not in used_heads:
            warn("%s: 槽位 %s 声明了但 body 里没用到" % (tid, name))
    for name in (t.get("vars") or []):
        if name not in used:
            warn("%s: 变量 %s 声明了但 body 里没用到" % (tid, name))

    # ---- 互斥项 ----
    for other in t.get("incompatible_with") or []:
        if other not in bypass_ids:
            err("%s: incompatible_with 引用了不存在的 %s" % (tid, other))

    # ---- requires 必须来自受控词表 ----
    for r in t.get("requires") or []:
        if r not in vocab_ids:
            err("%s: requires 里的 %r 不在受控词表里（见 data/requires.yaml）" % (tid, r))

    # ---- 版本区间 ----
    spec = t.get("version")
    if spec and spec != "*":
        for clause in str(spec).split():
            if not re.match(r"^(>=|<=|>|<|=)?\s*\d", clause):
                err("%s: version 子句 %r 不符合朴素区间语法（§15.1-2）" % (tid, clause))

    # ---- status ----
    if t.get("status") not in (None, "golden", "lab", "theory"):
        err("%s: status 取值非法: %r" % (tid, t.get("status")))


def check_bypass(b):
    bid = b["id"]
    for f in ("id", "name", "type"):
        if not b.get(f):
            err("%s: 缺少必需字段 %s" % (bid, f))
    t = b.get("type")
    if t not in BYPASS_TYPES:
        err("%s: 未知绕过类型 %r（闭类型集只有 %s）" % (bid, t, "/".join(sorted(BYPASS_TYPES))))
        return
    p = b.get("params") or {}
    if "skip_quoted" in p and not isinstance(p["skip_quoted"], bool):
        err("%s: skip_quoted 必须是布尔值" % bid)

    if t == "encode":
        if p.get("codec") not in CODECS:
            err("%s: 未知 codec %r（可选 %s）" % (bid, p.get("codec"), "/".join(sorted(CODECS))))
    elif t == "case":
        if p.get("mode") not in ("upper", "lower", "alternate"):
            err("%s: case 的 mode 只能是 upper/lower/alternate（没有 random，会破坏确定性）" % bid)
    elif t == "replace":
        if "pattern" not in p or "with" not in p:
            err("%s: replace 需要 pattern 和 with" % bid)
    elif t == "join":
        if "separator" not in p:
            err("%s: join 需要 separator" % bid)

    # case / replace 会按 pattern 找字面量。不开 skip_quoted 就会改到字符串字面量里面：
    # `'a b'` → `'a/**/b'`，**语法依旧合法，语义已经错了**。这类损坏是静默的。
    if t in ("case", "replace") and not p.get("skip_quoted"):
        warn("%s: %s 类绕过没开 skip_quoted，会改到字符串字面量里的内容" % (bid, t))


def check_plain_scalar_hash(data_dir):
    """行内 ` #` 在 YAML 里是注释起点，会把**不加引号**的标量静默截断。

    踩过一次：`desc: Pug 的 #{} 插值里是真 JS` 被解析成 `Pug 的`——
    文件看着正常、校验也过，整段描述没了。这类损坏只能靠扫原文发现，
    解析后的结果看不出任何异常。

    只查 desc / name：这两个字段我从不写行尾注释，误报率为零；
    其他字段（requires、content_type）经常带说明性行尾注释，查了全是噪音。
    """
    for path in glob.glob(os.path.join(data_dir, "**", "*.yaml"), recursive=True):
        for i, line in enumerate(open(path, encoding="utf-8"), 1):
            m = re.match(r"^\s*(desc|name):\s+([^\s\"'|>\[{].*?)\s+#", line)
            if m:
                warn("%s:%d %s 是未加引号的标量且含「 #」，YAML 会把 # 之后当注释截掉：%r"
                     % (os.path.relpath(path, data_dir), i, m.group(1), m.group(2)))


def check_mutual(bypasses):
    """incompatible_with 必须双向一致。"""
    idx = {b["id"]: set(b.get("incompatible_with") or []) for b in bypasses}
    for bid, others in idx.items():
        for o in others:
            if o in idx and bid not in idx[o]:
                err("互斥项不对称: %s -> %s，但 %s 未回指" % (bid, o, o))


def check_coverage(templates):
    """覆盖空洞告警：某些 (漏洞类型, 内容类型) 组合完全没有模板。"""
    seen = set()
    for t in templates:
        for v in t.get("vuln") or []:
            for c in t.get("content_type") or []:
                seen.add((v, c))
    if not seen:
        warn("规则库里没有任何模板")
    return seen


def main():
    data_dir = sys.argv[1] if len(sys.argv) > 1 else DATA_DIR
    try:
        rules = engine.load_rules(data_dir)
    except Exception as e:  # noqa: BLE001
        print("加载失败：%s" % e)
        return 1

    bypass_ids = {b["id"] for b in rules["bypasses"]}
    vocab_ids = set(rules.get("requires_name") or {})
    check_ids(rules["templates"], data_dir)
    for t in rules["templates"]:
        check_template(t, bypass_ids, vocab_ids)
    for b in rules["bypasses"]:
        check_bypass(b)
    check_mutual(rules["bypasses"])
    check_plain_scalar_hash(data_dir)

    # 词表本身的完整性
    for r in rules["requires"]:
        if not r.get("id") or not r.get("name"):
            err("requires 词表项缺少 id 或 name: %r" % r)
    used = set()
    for t in rules["templates"]:
        used |= set(t.get("requires") or [])
    for r in rules["requires"]:
        if r.get("id") not in used:
            warn("requires 词表里的 %s 没有任何模板在用" % r.get("id"))
    combos = check_coverage(rules["templates"])

    for w in warnings:
        print("警告: %s" % w)
    for e in errors:
        print("错误: %s" % e)

    print()
    print("模板 %d 条，绕过 %d 条，覆盖 %d 个 (漏洞类型, 内容类型) 组合"
          % (len(rules["templates"]), len(rules["bypasses"]), len(combos)))
    print("错误 %d，警告 %d" % (len(errors), len(warnings)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
