"""模板脚手架：生成一条模板 + 对应黄金样本的骨架。

    python new_template.py sqli.postgresql.union.dump --name "PostgreSQL UNION 读库名"
    python new_template.py rce.linux.reverse.perl --name "Perl 反弹 Shell" --ctype shell-command

**只追加，不重写已有文件。** 上一轮批量改 requires 的脚本因为一个标志写错，
静默丢掉了两个文件里的全部修改——追加比往返解析安全得多，也不动注释和排版。

骨架里所有待填项都是 `TODO`，所以**校验会失败**，这是有意的：
填完 TODO 再跑 `validate_rules.py` 通过，才算一条合格的模板。

黄金样本的期望值**不会**被预填（那是 §13.2 的纪律），骨架里只有 TODO。
"""

import argparse
import datetime
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
GOLDEN_DIR = os.path.join(ROOT, "golden")

# 注释一律**独占一行**，不写行尾注释——脚手架要按行替换占位值，
# 行尾注释会让替换切坏 YAML（这一版就是这么踩的）。
TEMPLATE_STUB = """  - id: {tid}
    name: {name}
    desc: TODO 一句话说清什么时候用它、什么时候别用
    vuln: [{vuln}]
    # TODO content_type 见方案 §3 的词汇表。留空是**有意的**：
    # 校验会因此报「缺少必需字段」，填完才算一条合格的模板
    content_type: []
    component: [{component}]
    version: "*"
    body: "TODO"
    vars: []
    # TODO requires 必须来自 data/requires.yaml 的受控词表，且要写全。
    # 拿不准就翻同类模板——漏声明会被前提筛选出卖
    requires: []
    # status 取 golden / lab / theory，按实际验证程度诚实填
    status: theory
    source: 手写
    license: ""
    updated: {date}
"""

GOLDEN_STUB = """  - name: {name}
    state:
      vuln: {vuln}
      template: {tid}
      outputs: [raw]
    expect:
      # 期望值**必须手算**：读上面的 body，按方案 §7 的管线逐层推。
      # 不要跑一遍工具把输出粘回来——那会把当前行为（含 bug）固化成规范。
      payload: "TODO"
"""

FILE_HEADER = """ruleDB: v0.1.0
# {vuln} 模板。
"""

GOLDEN_HEADER = """# 黄金样本（§13.2）。期望值手写核算，不由工具反向生成。

ruleDB: v0.1.0

samples:
"""


def die(msg):
    print("错误: %s" % msg, file=sys.stderr)
    raise SystemExit(2)


def show(path):
    """相对路径优先，跨盘符时退回绝对路径。

    Windows 上 `os.path.relpath` 跨盘符会抛 ValueError——`--data` 指到别的盘
    （或测试用临时目录）时就会崩。
    """
    try:
        return os.path.relpath(path, ROOT)
    except ValueError:
        return path


def parse_id(tid):
    """`sqli.postgresql.union.dump` → ('sqli', 'postgresql')。

    前缀规则由 validate_rules.py 强制：id 必须等于「数据目录相对路径去掉 .yaml」再加后缀。
    """
    parts = tid.split(".")
    if len(parts) < 3:
        die("id 至少要有三段（<漏洞类型>.<组件>.<名称>），实际 %r" % tid)
    return parts[0], parts[1]


def pick_golden_file(golden_dir, vuln):
    """找已有的样本文件；找不到就新建 golden/<vuln>.yaml。

    样本文件**不要求**与漏洞类型一一对应（实际布局是 sqli 有几份、四类新漏洞合在
    other-vulns.yaml），所以优先复用已经装了同类样本的那一份。
    """
    named = os.path.join(golden_dir, "%s.yaml" % vuln)
    if os.path.exists(named):
        return named
    for fn in sorted(os.listdir(golden_dir)) if os.path.isdir(golden_dir) else []:
        if not fn.endswith(".yaml"):
            continue
        text = open(os.path.join(golden_dir, fn), encoding="utf-8").read()
        if re.search(r"^\s+vuln: %s\s*$" % re.escape(vuln), text, re.M):
            return os.path.join(golden_dir, fn)
    return named


def append(path, text, header=None):
    new = not os.path.exists(path)
    with open(path, "a" if not new else "w", encoding="utf-8") as f:
        if new:
            f.write(header or "")
        f.write(("\n" if not (header and new) else "") + text)
    return new


def main():
    ap = argparse.ArgumentParser(description="生成模板与黄金样本骨架")
    ap.add_argument("id", help="模板 id，如 sqli.postgresql.union.dump")
    ap.add_argument("--name", required=True, help="模板显示名")
    ap.add_argument("--ctype", help="content_type（不填则留空，等作者补）")
    ap.add_argument("--data", default=DATA_DIR, help="规则库目录")
    ap.add_argument("--golden", default=GOLDEN_DIR, help="黄金样本目录")
    args = ap.parse_args()

    data_dir, golden_dir = args.data, args.golden
    tid = args.id
    vuln, component = parse_id(tid)

    # id 唯一性 —— 加载时也会报，但在这里报能少写半个文件
    try:
        from forge import engine
        rules = engine.load_rules(data_dir)
        if any(t["id"] == tid for t in rules["templates"]):
            die("id 已存在: %s" % tid)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - 规则库本身坏了不该挡住加模板
        print("（提示：现有规则库加载失败，跳过唯一性检查：%s）" % e, file=sys.stderr)

    tpl_path = os.path.join(data_dir, vuln, "%s.yaml" % component)
    stub = TEMPLATE_STUB.format(
        tid=tid, name=args.name, vuln=vuln, component=component,
        date=datetime.date.today().isoformat(),
    )
    if args.ctype:
        # 连 TODO 注释一起换掉——留着会让人以为这项还没填
        stub = stub.replace(
            "    # TODO content_type 见方案 §3 的词汇表。留空是**有意的**：\n"
            "    # 校验会因此报「缺少必需字段」，填完才算一条合格的模板\n"
            "    content_type: []\n",
            "    content_type: [%s]\n" % args.ctype)
    created_tpl = append(tpl_path, stub, FILE_HEADER.format(vuln=vuln))

    gold_path = pick_golden_file(golden_dir, vuln)
    created_gold = append(gold_path, GOLDEN_STUB.format(name=args.name, vuln=vuln, tid=tid),
                          GOLDEN_HEADER)

    print("模板   → %s%s" % (show(tpl_path), "（新建）" if created_tpl else ""))
    print("黄金样本 → %s%s" % (show(gold_path), "（新建）" if created_gold else ""))
    print()
    print("接下来：")
    print("  1. 填模板里的 TODO（body / content_type / requires / version / status）")
    print("  2. **手算**黄金样本的期望值填进去，别跑工具粘回来")
    print("  3. python validate_rules.py    # TODO 还在的话这里会报错，是正常的")
    print("  4. python run_golden.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
