# -*- coding: utf-8 -*-
"""PHP 序列化结构 DSL —— 用户写「不带长度」的结构树，工具补齐每一个长度和计数。

存在的理由：PHP 的序列化格式里，**每一段都有一个字节长度前缀**，容器还要再声明
元素个数。手写时这两样都是静默错——长度差一个字节，`unserialize()` 直接
`Error at offset N`；`O:3:"Foo":2:{...}` 里声明两个属性却只写一个，也一样。
私有属性还要写成 `\\0类名\\0属性`，长度得把两个 NUL 一起算进去，肉眼几乎数不对。

而 POP 链的**结构**取决于目标的类：类名、属性名、可见性、嵌套形状，这些只能
由使用者提供。所以分工是——**结构你写，长度工具算**。

    O:App\\Cache{socket=O:SoapClient{uri=s:"http://x" location=s:"http://y"}}

展开成：

    O:9:"App\\Cache":1:{s:6:"socket";O:10:"SoapClient":2:{s:3:"uri";s:8:"http://x";s:8:"location";s:8:"http://y";}}

## 语法

值（空白随便加）：

| 写法 | 展开成 | 说明 |
| --- | --- | --- |
| `N` | `N;` | null |
| `b:1` / `b:0` | `b:1;` / `b:0;` | 布尔 |
| `i:123` | `i:123;` | 整数 |
| `d:1.5` | `d:1.5;` | 浮点 |
| `s:"文本"` | `s:<字节数>:"文本";` | 字符串，长度是 **UTF-8 字节数** |
| `a{...}` | `a:<项数>:{...}` | 数组 |
| `O:类名{...}` | `O:<类名字节数>:"类名":<项数>:{...}` | 对象 |

引用（POP 链里 `$obj->prop = $obj` 这类形状必须用）：

| 写法 | 展开成 | 说明 |
| --- | --- | --- |
| `&标签` | —— | 标在紧跟的那个值前面，给它起个名字。**根上也能打** |
| `r:标签` | `r:<号>;` | 指同一个对象（PHP 的对象句柄） |
| `R:标签` | `R:<号>;` | 指真引用（PHP 的 `&`） |

    &r O:A{ p=r:r }                      自引用
    O:B{ x=&o O:A{} y=r:o }              两个属性指向同一个对象
    a{ i:0=&z O:Z{} i:1=r:z i:2=r:z }    数组里重复引用同一个对象

项之间用空白分隔，键后面可以跟一个 `=` 或 `:`——纯粹为了好读，工具会忽略它：

| 键 | 用于 | 说明 |
| --- | --- | --- |
| `i:0` | 数组 | 整数键 |
| `s:"k"` | 数组 | 字符串键 |
| `name` | 对象 | public 属性 |
| `-name` | 对象 | protected，展开成 `\\0*\\0name` |
| `#name` | 对象 | private，展开成 `\\0<外层类名>\\0name` |

字符串内容里 `\\"` 是转义的双引号、`\\\\` 是转义的反斜杠；其余字符原样收下，
包括 `;` `}`——**长度前缀就是为了让内容可以原样出现**（PHP 自己不转义引号，
`serialize('a"b')` 得到的正是 `s:3:"a"b";`，所以解析靠长度而不是找引号）。

## 引用编号规则

编号是 `R:` / `r:` 要指的那个数。**规则全部由真实 PHP 实测确定**（PHP 7.0.12，
样本见 `golden/phpser.yaml` 里「引用」那一组，期望值都跟 `serialize()` 对拍过）：

1. 计数器从 1 开始，**先序**——容器先占自己的号，再递归子值
2. 每个**值**占一个号，包括 `N` 和标量
3. **键一律不占号**（数组键、属性名都一样）
4. **`R:` / `r:` 的产出本身也占一个号**。这条最容易漏：漏了的话，
   引用**之后**的每个值都会偏一号

第 4 条决定了必须**两遍走**（先把号全编出来再发射）。单遍边编边发，
遇到引用时计数器就与 PHP 不一致了。

## 边界

- 不做 `E:`（enum，PHP 8.1）、不做 `C:`（Serializable 自定义格式）。
  这两样的展开规则没有实测过，宁可不做也不猜。
- **不做「值相同就自动合并成引用」**。PHP 只在真引用（`&`）和同一对象上产出
  `R:`/`r:`，数组是值类型、拷贝会**完整写两遍**（实测过）。自动合并会产出
  PHP 自己不会产的东西。
- **只生成不解析**——解析（校验）在 `forge/syntax.py` 里，两处独立实现。
  这是有意的：生成与校验共用一份代码的话，同一个理解错误会在两边同时成立，
  校验就成了摆设。引用这块两边各写了一遍编号逻辑，就是靠这条互相兜底。
"""

import re

# 嵌套深度上限。POP 链一般不超过 10 层，给 64 足够；
# 没有上限的话一个手滑的 `O:A{O:B{O:C{` 会把 Python 的栈打爆，
# 而这是跑在用户机器上的代码。
MAX_DEPTH = 64

# 展开结果的长度上限（字节）。挡的是往 `s:"..."` 里粘一个巨大的东西。
MAX_OUT = 1 << 20

_WS = " \t\r\n"


class SpecError(ValueError):
    """结构描述本身有问题。调用方应当**原样透传**并把它当提示报出来。"""


class _Parser:
    def __init__(self, s):
        self.s = s
        self.i = 0
        self.n = len(s)

    # ---------------------------------------------------------------- 基础

    def err(self, msg):
        raise SpecError("%s（第 %d 个字符处：%r）"
                        % (msg, self.i, self.s[self.i:self.i + 12]))

    def skip_ws(self):
        while self.i < self.n and self.s[self.i] in _WS:
            self.i += 1

    def peek(self):
        return self.s[self.i] if self.i < self.n else ""

    def take(self, lit):
        if not self.s.startswith(lit, self.i):
            self.err("这里要 %r" % lit)
        self.i += len(lit)

    def number(self):
        m = re.match(r"-?\d+(?:\.\d+)?", self.s[self.i:])
        if not m:
            self.err("这里要一个数字")
        self.i += len(m.group(0))
        return m.group(0)

    def ident(self, what):
        """读一个标识符（类名或属性名）。

        终止符包含 `=`/`:`/`{`/`}` 和空白——前两个是「键后面那个纯装饰的分隔符」，
        不排除的话 `name=x` 会被整个读成标识符。
        """
        j = self.i
        while j < self.n and self.s[j] not in _WS + "{}:=#":
            j += 1
        if j == self.i:
            self.err("这里要一个%s" % what)
        got = self.s[self.i:j]
        self.i = j
        return got

    def quoted(self):
        """读一段双引号字符串，返回**解码后**的内容。

        `\\"` 是这个 DSL 自己的一层转义，与 PHP 无关——DSL 需要有个办法把引号
        写进内容里，而展开出去以后 PHP 那边靠长度前缀定位，内容里出现引号是合法的。
        不认识的转义（如命名空间里的 `\\`）原样保留。
        """
        self.take('"')
        buf = []
        while True:
            if self.i >= self.n:
                self.err("字符串没有收尾的双引号")
            c = self.s[self.i]
            if c == "\\":
                nxt = self.s[self.i + 1:self.i + 2]
                if nxt in ('"', "\\"):
                    buf.append(nxt)
                    self.i += 2
                    continue
                buf.append(c)
                self.i += 1
                continue
            if c == '"':
                self.i += 1
                return "".join(buf)
            buf.append(c)
            self.i += 1

    @staticmethod
    def slen(text):
        """**字节**数，不是字符数——和 `<<len()>>` 同一个口径。"""
        return len(text.encode("utf-8"))

    # ---------------------------------------------------------------- 值

    def value(self, depth, cls=None):
        if depth > MAX_DEPTH:
            self.err("嵌套超过 %d 层" % MAX_DEPTH)
        self.skip_ws()
        c = self.peek()
        if c == "":
            self.err("这里要一个值")
        # 引用：`r:标签` 是同一对象，`R:标签` 是真引用（&）。两者都指向
        # 前面用 `&标签` 标过的那个值，展开成它的槽位号。
        if c in "rR" and self.s.startswith(c + ":", self.i):
            marker = c
            self.i += 2
            label = self.ident("标签名")
            return ("ref", marker, label)
        if c == "N":
            self.i += 1
            return ("null",)
        if c == "b":
            self.take("b:")
            self.skip_ws()
            v = self.number()
            if v not in ("0", "1"):
                self.err("布尔只能是 b:0 或 b:1")
            return ("bool", v)
        if c == "i":
            self.take("i:")
            self.skip_ws()
            return ("int", self.number())
        if c == "d":
            self.take("d:")
            self.skip_ws()
            return ("float", self.number())
        if c == "s":
            self.take("s:")
            self.skip_ws()
            return ("str", self.quoted())
        if c == "a":
            self.i += 1
            self.skip_ws()
            return self.container(depth, is_array=True)
        if c == "O":
            self.take("O:")
            self.skip_ws()
            name = self.ident("类名")
            self.skip_ws()
            return self.container(depth, is_array=False, cls=name)
        self.err("认不出的值（只支持 N / b: / i: / d: / s: / a{ / O:类名{ / r: / R:）")

    def container(self, depth, is_array, cls=None):
        self.take("{")
        items = []
        while True:
            self.skip_ws()
            if self.peek() == "}":
                break
            if self.peek() == "":
                self.err("容器没有收尾的 }")
            items.append(self.item(depth + 1, is_array, cls))
        self.take("}")
        if is_array:
            return ("array", items)
        return ("object", cls, items)

    def item(self, depth, is_array, cls):
        if is_array:
            c = self.peek()
            if c == "i":
                self.take("i:")
                self.skip_ws()
                key = ("ikey", self.number())
            elif c == "s":
                self.take("s:")
                self.skip_ws()
                key = ("skey", self.quoted())
            else:
                self.err('数组的键要写成 i:0 或 s:"名字"')
        else:
            sigil = ""
            if self.peek() in "-#":
                sigil = self.peek()
                self.i += 1
            name = self.ident("属性名")
            if sigil == "-":
                name = "\0*\0" + name
            elif sigil == "#":
                if "/" in name:
                    # `#类名/属性` —— **显式指定 mangling 用的那个类名**。
                    # 需要它是因为私有属性的 mangled 名用的是「声明该属性的类」，
                    # 而外层 O: 写的是子类。Guzzle 那条链就是这种形状：
                    # 属性 cookies 声明在父类 CookieJar 上，对象却是 FileCookieJar。
                    # 分隔符取 `/`：PHP 标识符里不出现它，而命名空间用的是反斜杠，
                    # 所以不会和二义的类名/属性名撞上。
                    mangler, _, name = name.partition("/")
                    if not mangler or not name:
                        self.err("# 后面的写法是 类名/属性名")
                    name = "\0%s\0%s" % (mangler, name)
                else:
                    if not cls:
                        self.err("private 属性只能写在 O:类名{...} 里")
                    name = "\0%s\0%s" % (cls, name)
            key = ("pkey", name)

        self.skip_ws()
        if self.peek() in "=:":     # 装饰性的，只为好读
            self.i += 1
        label = self.opt_label()
        node = self.value(depth, cls)
        if label is not None:
            node = ("labeled", label, node)
        return (key, node)

    def opt_label(self):
        """可选的 `&标签`。标在它紧跟的那个值上，之后的 `r:标签` / `R:标签` 指回来。

        根上也能打——`$obj->p = $obj` 这种自引用链必须靠它，
        否则最外层那个对象没有名字可以指。
        """
        self.skip_ws()
        if self.peek() != "&":
            return None
        self.i += 1
        name = self.ident("标签名")
        self.skip_ws()
        return name


# ---------------------------------------------------------------- 编号与发射
#
# 编号规则**全部由真实 PHP 实测确定**（PHP 7.0.12，见 golden/phpser.yaml 的样本）：
#
#   1. 计数器从 1 开始，**先序**遍历——容器先占自己的号，再递归子值
#   2. 每个「值」占一个号，包括 N 和标量
#   3. **键一律不占号**（数组键、属性名都一样）
#   4. **`R:`/`r:` 的产出本身也占一个号**——实测：连续两个 r: 会让后面的
#      新值落到 6 号；这一条最容易漏，漏了后面所有引用号都会偏
#   5. `r:N` 指同一个对象（PHP 对象句柄），`R:N` 指真引用（&）
#
# 第 4 条决定了两遍走：先把号全编出来，再发射。单遍边编边发会在遇到引用时
# 把计数器推到与 PHP 不一致的位置。


def _number(node, ctr, labels):
    """先序编号。返回这个节点拿到的号；labels 记下「标签 -> 号」。"""
    if node[0] == "labeled":
        # 标签本身不占号，占号的是它标住的那个值
        slot = _number(node[2], ctr, labels)
        name = node[1]
        if name in labels:
            raise SpecError("标签 %r 定义了两次" % name)
        labels[name] = slot
        return slot

    slot = ctr[0]
    ctr[0] += 1
    if node[0] == "array":
        for _, val in node[1]:
            _number(val, ctr, labels)      # 键不调用 _number
    elif node[0] == "object":
        for _, val in node[2]:
            _number(val, ctr, labels)
    return slot


def _emit(node, labels):
    kind = node[0]
    if kind == "labeled":
        return _emit(node[2], labels)
    if kind == "ref":
        marker, label = node[1], node[2]
        if label not in labels:
            raise SpecError("引用了没有定义过的标签 %r（要先用 &%s 标在某个值前面）"
                            % (label, label))
        return "%s:%d;" % (marker, labels[label])
    if kind == "null":
        return "N;"
    if kind == "bool":
        return "b:%s;" % node[1]
    if kind == "int":
        return "i:%s;" % node[1]
    if kind == "float":
        return "d:%s;" % node[1]
    if kind == "str":
        return 's:%d:"%s";' % (len(node[1].encode("utf-8")), node[1])
    if kind == "array":
        body = "".join(_emit_key(k) + _emit(v, labels) for k, v in node[1])
        return "a:%d:{%s}" % (len(node[1]), body)
    body = "".join(_emit_key(k) + _emit(v, labels) for k, v in node[2])
    cls = node[1]
    return 'O:%d:"%s":%d:{%s}' % (len(cls.encode("utf-8")), cls, len(node[2]), body)


def _emit_key(key):
    kind, val = key
    if kind == "ikey":
        return "i:%s;" % val
    return 's:%d:"%s";' % (len(val.encode("utf-8")), val)


def build(spec):
    """把结构描述展开成 PHP 序列化串。结构有问题时抛 `SpecError`。"""
    p = _Parser(spec)
    root_label = p.opt_label()
    tree = p.value(0)
    if root_label is not None:
        tree = ("labeled", root_label, tree)
    p.skip_ws()
    if p.i != len(p.s):
        p.err("结构描述解析完了还有多余内容")
    labels = {}
    _number(tree, [1], labels)
    out = _emit(tree, labels)
    if len(out.encode("utf-8")) > MAX_OUT:
        raise SpecError("展开结果超过 %d 字节，多半是哪里写错了" % MAX_OUT)
    return out
