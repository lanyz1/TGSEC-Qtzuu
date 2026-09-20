"""组装后语法校验（§10.2 B）。

**只覆盖有可靠零依赖 parser 的语言**，其余明确返回「未校验」——
一个只覆盖 30% 却长得像 100% 的校验器，比没有更糟。

payload 片段本身故意不是合法的完整语法，所以每种语言要套一层
**固定的人造壳**（写死的，不是用户填的），再解析。
"""

import ast
import json
import xml.parsers.expat as expat


class _Unsupported(Exception):
    """遇到了这个校验器没有建模的语法。

    和「校验失败」是**两回事**：前者说明载荷可能是对的、只是我们没能力判，
    后者说明它一定错了。混为一谈会让用户去改一个本来正确的载荷——
    那比漏报更糟。
    """


def _parse_php_serialized(s):
    """PHP 序列化串的良构性校验。

    查的是**这一类载荷最容易静默错的三样**：
    1. 长度前缀与实际字节数是否一致（差一个字节 `unserialize()` 就炸）
    2. 容器声明的元素个数与实际写出来的个数是否一致
       （`O:3:"Foo":2:{...}` 里只写一个属性 → 报出来）
    3. 结尾是否恰好用完、括号是否配对

    只验结构，**不构造对象**：`O:` 只是个类型标记，我们不碰它指向的类，
    也不做任何反序列化。

    这是**独立于 `forge/phpser.py` 的第二份实现**（那份负责生成）。
    刻意不共用代码：如果两边共用，同一个理解错误会在生成和校验里同时成立，
    校验就变成了自我确认。
    """
    data = s.encode("utf-8")
    n = len(data)
    escaped = [0]          # 见到几处 `S:` 转义串（它们的长度前缀没法校验）
    # PHP 内部那份「第几个值」的编号，用来校验 `R:` / `r:` 指向哪里。
    # 规则**全部由真实 PHP 实测确定**，和 phpser.py 里那份是**各自独立实现**的：
    #   先序——每个值占一个号（含 N 和标量），容器先占自己的号再递归子值；
    #   键一律不占号（数组键、属性名都一样）；`R:`/`r:` 的产出本身也占一个号。
    #   合法引用区间：1 <= N < 引用自己占的那个号。
    slots = [1]

    def fail(msg, at):
        raise ValueError("%s（偏移 %d）" % (msg, at))

    def digits(i):
        j = i
        while j < n and 48 <= data[j] <= 57:
            j += 1
        if j == i:
            fail("这里要一个数字", i)
        return int(data[i:j]), j

    def expect(i, lit):
        if data[i:i + len(lit)] != lit:
            fail("这里要 %s" % lit.decode("ascii"), i)
        return i + len(lit)

    def sized_string(i):
        """`s:` 之后的 `<长度>:"<恰好这么多字节>";`。

        **靠长度定位，不靠找引号**——PHP 的序列化不转义引号
        （`serialize('a"b')` 就是 `s:3:"a"b";`），按引号找会在这里断错。
        """
        ln, i = digits(i)
        i = expect(i, b':"')
        if i + ln > n:
            fail("声明长度 %d，但后面只剩 %d 字节" % (ln, n - i), i)
        i += ln
        return expect(i, b'";')

    def value(i, depth):
        if depth > 64:
            fail("嵌套超过 64 层", i)
        if i >= n:
            fail("还差一个值，但已经到结尾了", i)
        # 每个值占一个号，先序（容器先占号再递归）。键在下面的 a: 分支里回滚。
        # 引用校验要用「引用自己占的号」，所以从**自增前**取。
        slot = slots[0]
        slots[0] += 1
        c = data[i:i + 1]
        if c == b"N":
            return expect(i, b"N;")
        if c == b"b":
            i = expect(i, b"b:")
            if data[i:i + 1] not in (b"0", b"1"):
                fail("布尔只能是 b:0 或 b:1", i)
            return expect(i + 1, b";")
        if c == b"i":
            i = expect(i, b"i:")
            j = i + 1 if data[i:i + 1] == b"-" else i
            k = j
            while k < n and data[k:k + 1].isdigit():
                k += 1
            if k == j:
                fail("整数缺少数字", j)
            return expect(k, b";")
        if c == b"d":
            i = expect(i, b"d:")
            k = i
            while k < n and (data[k:k + 1].isdigit() or data[k:k + 1] in b".eE+-"):
                k += 1
            if k == i:
                fail("浮点缺少数字", i)
            return expect(k, b";")
        if c == b"s":
            return sized_string(expect(i, b"s:"))
        if c == b"S":
            # `S:` 是**转义字符串**：unserialize() 认它（内容里可以有 `\x00` 这类
            # 原始字节的转义写法，长度逃逸类绕过就用它），但 serialize() 不产。
            # 正因为它带转义，声明长度和「从 `:"` 到 `";` 之间的原始字节数」
            # **对不上**——所以这里只扫到收尾的 `";`，不校验长度。
            # 不这么做的话，一条合法的 S: 载荷会被判 fail，那是判错。
            escaped[0] += 1
            i = expect(i, b"S:")
            _, i = digits(i)
            i = expect(i, b':"')
            j = data.find(b'";', i)
            if j < 0:
                fail("转义字符串没有收尾的 \";", i)
            return j + 2
        if c == b"a":
            cnt, i = digits(expect(i, b"a:"))
            i = expect(i, b":{")
            for _ in range(cnt):
                # 键语法上是个值（`i:0;` / `s:"k";`），但**不进 PHP 的编号**，
                # 所以把计数器回滚掉——不回滚的话后面每个引用号都会偏。
                mark = slots[0]
                i = value(i, depth + 1)
                slots[0] = mark
                i = value(i, depth + 1)
            return expect(i, b"}")
        if c == b"O":
            ln, i = digits(expect(i, b"O:"))
            i = expect(i, b':"')
            if i + ln > n:
                fail("类名声明长度 %d，但后面只剩 %d 字节" % (ln, n - i), i)
            i += ln
            cnt, i = digits(expect(i, b'":'))
            i = expect(i, b":{")
            for _ in range(cnt):
                # 属性名永远是一个 `s:` 串——注意要和 value() 里的 s 分支一样
                # 先吃掉 `s:` 再把位置交给 sized_string
                i = sized_string(expect(i, b"s:"))
                i = value(i, depth + 1)
            return expect(i, b"}")
        if c == b"E":                            # PHP 8.1 的枚举
            return sized_string(expect(i, b"E:"))
        if c in (b"R", b"r"):
            # 引用。合法区间 **1 <= N < 引用自己占的号**，全部由真实 PHP 实测：
            #   r:3（正好是自己那个号）失败 · r:2（前一个值）成功 ·
            #   r:1（容器自己）成功 · r:0 失败 · 越界/指向尚未出现的号失败。
            #
            # **不检查目标类型**：实测 `r:` 指向字符串或整数，PHP 照样
            # unserialize 成功。查了就是误报，而误报比不判更糟——用户会去
            # 改一条本来正确的载荷（这条教训 pickle 那次已经吃过一遍）。
            i = expect(i, c + b":")
            j = i + 1 if data[i:i + 1] == b"-" else i
            k = j
            while k < n and 48 <= data[k] <= 57:
                k += 1
            if k == j:
                fail("引用缺少编号", i)
            num = int(data[i:k])
            if not 1 <= num < slot:
                fail("%s:%d 指向一个还没出现的值（它自己占第 %d 个号，只能往前指）"
                     % (c.decode("ascii"), num, slot), i)
            return expect(k, b";")
        if c == b"C":
            raise _Unsupported("C: 没有建模")
        fail("认不出的类型标记 %r" % c.decode("latin-1"), i)

    end = value(0, 0)
    if end != n:
        fail("解析完了还剩 %d 字节" % (n - end), end)
    return escaped[0]


# PHP 序列化里所有合法的首个类型标记。
#   N 空 / b 布尔 / i 整数 / d 浮点 / s 字符串 / S 转义字符串 /
#   a 数组 / O 对象 / E 枚举 / C Serializable / R·r 引用
_PHP_MARKERS = {"N", "b", "i", "d", "s", "S", "a", "O", "E", "C", "R", "r"}


def _check_php_serialized(s):
    """先看**首个类型标记**，不像 PHP 序列化串就别硬判。

    `content_type: serialized` 底下不止 PHP 一种文本形态——pickle 协议 0 也是
    纯 ASCII（`cos\\nsystem\\n(S'id'\\ntR.`）。不加这道闸的话，一条完全正确的
    pickle 载荷会被判成「PHP 序列化校验未通过：认不出的类型标记 'c'」，
    而**判错比不判更糟**：用户会去改一条本来是对的载荷。
    """
    head = s.lstrip()[:1]
    if head and head not in _PHP_MARKERS:
        return "unchecked", ("看着不像 PHP 序列化串（首个类型标记是 %r），未校验" % head)
    try:
        n_escaped = _parse_php_serialized(s)
    except _Unsupported as e:
        # 不是「校验失败」，是「没能力判」——必须分开报，见 _Unsupported 的说明
        return "unchecked", "PHP 序列化串里有本工具没建模的语法（%s），未校验" % e
    except Exception as e:  # noqa: BLE001 - parser 抛什么都要转成提示
        return "fail", "PHP 序列化校验未通过：%s" % e
    if n_escaped:
        # 别说过头话：S: 的长度前缀我们确实没校验（见 value() 里那一支）
        return "ok", ("PHP 序列化校验通过（结构与元素个数对得上；串里有 %d 处 S: 转义字符串，"
                      "它们的长度前缀没有校验）" % n_escaped)
    return "ok", "PHP 序列化校验通过（长度前缀与元素个数都对得上）"


def _parse_jinja(s):
    # 延迟导入：没装 jinja2 时降级为「未校验」，而不是把工具整个拖垮
    import jinja2

    jinja2.Environment().parse(s)


def _parse_xml(s):
    """只验 XML 良构性，**不解析实体**。

    不能用 `xml.etree.ElementTree.fromstring`：它对含内部 DTD 的文档会报
    `undefined entity`，而 XXE 载荷**必然**自带 DTD 声明实体——那会把一个
    完全正确的载荷报成语法错误，比漏报更糟（用户可能因此改坏正确的东西）。

    `DefaultHandlerExpand` 让未展开的实体引用走空处理器。实测对
    `file://` / `http://` 类型的外部实体**不做任何解析**（耗时 0.000s，
    无文件读取、无网络请求）——这一点是硬要求，语法校验绝不能顺带执行载荷。

    注意：引用**完全未声明**的实体仍会报错，这是对的——那是 XML 良构性错误。
    """
    p = expat.ParserCreate()
    p.DefaultHandlerExpand = lambda data: None
    p.Parse(s, True)


# 语言 -> (人造壳包装函数, 解析函数)。壳返回包装后的完整文本。
WRAPPERS = {
    # Python 表达式直接吃；语句需要包一层函数体
    "python": (lambda s: s, lambda s: ast.parse(s, mode="eval")),
    "python-stmt": (lambda s: "def _():\n" + "\n".join("    " + l for l in s.splitlines()), ast.parse),
    "json": (lambda s: s, json.loads),
    "xml": (lambda s: s, _parse_xml),
    # 模板引擎里只有 Jinja2 有可靠 parser（Twig/Nunjucks 语法近似但不等价）
    "jinja2": (lambda s: s, _parse_jinja),
}

# 直接返回 (状态, 说明) 的校验器，不走 WRAPPERS 那套「套壳再解析」。
# PHP 序列化自己就是完整语法，不需要人造壳。
DIRECT = {
    "php-serialize": _check_php_serialized,
}

# 内容类型 -> 用哪个语言的壳。没有对应项 = 该内容类型无可靠 parser。
CONTENT_TYPE_LANG = {
    "python-expr": "python",
    "python-stmt": "python-stmt",
    "json": "json",
    "xml": "xml",
    # 序列化串目前只有 PHP 一种文本形态。pickle 协议 0 也是文本，
    # 但它的「良构」要到操作码层面才判得准，没做——如实返回未校验。
    "serialized": "php-serialize",
}


def check(payload, content_type, lang=None):
    """返回 (状态, 说明)。

    状态取值：ok / fail / unchecked。

    `lang` 优先于 `content_type`：模板可以显式声明 `syntax_lang`。
    这是给多引擎内容类型用的——比如 `template-expression` 涵盖二十来种模板引擎，
    但只有模板自己知道它产出的是哪一门语法。
    """
    lang = lang or CONTENT_TYPE_LANG.get(content_type)
    if lang is None:
        return "unchecked", "该内容类型无可靠 parser（%s）" % content_type
    if lang in DIRECT:
        return DIRECT[lang](payload)
    if lang not in WRAPPERS:
        return "unchecked", "无 %s 的可靠 parser" % lang

    wrap, parse = WRAPPERS[lang]
    try:
        parse(wrap(payload))
    except ImportError as e:  # 依赖没装 ≠ 语法错，不能混为一谈
        return "unchecked", "缺少 %s 的 parser 依赖：%s" % (lang, e)
    except Exception as e:  # noqa: BLE001 - parser 抛什么都要转成提示
        return "fail", "%s 语法校验未通过：%s" % (lang, e)
    return "ok", "%s 语法校验通过" % lang


def annotate(payload, content_type, lang=None):
    """给输出加一行校验标注（§10.2 要求每个输出都标注）。"""
    status, msg = check(payload, content_type, lang)
    return {"status": status, "message": msg}
