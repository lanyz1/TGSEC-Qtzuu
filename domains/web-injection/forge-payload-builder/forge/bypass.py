"""编码 codec + 5 种闭类型绕过 + Shell 转义（§6.2 / §8.1）。

绕过的类型集合是封闭的，加新绕过靠加数据行，不写代码。
"""

import base64
import re
from urllib.parse import quote

# ---------------------------------------------------------------- codecs


def _codec_url(s):
    return quote(s, safe="")


def _codec_url2(s):
    return quote(quote(s, safe=""), safe="")


def _codec_base64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _codec_hex(s):
    return s.encode("utf-8").hex()


def _codec_unicode(s):
    return "".join("\\u%04x" % ord(c) for c in s)


def _codec_html(s):
    return "".join("&#%d;" % ord(c) for c in s)


def _codec_gzip(s):
    """Gzip 压缩后转 Base64。

    **必须带上 Base64**：压缩结果是字节，而本工具的管线是文本。
    若直接返回字节解成的串，后续再叠 base64 会被 UTF-8 重新编码，产出错误数据。
    所以这两个 codec 的语义就是「压缩并编码」，数据里的 name 也照此写。
    """
    import gzip

    return base64.b64encode(gzip.compress(s.encode("utf-8"))).decode("ascii")


def _codec_zlib(s):
    """Deflate 压缩后转 Base64，理由同 gzip。"""
    import zlib

    return base64.b64encode(zlib.compress(s.encode("utf-8"))).decode("ascii")


CODECS = {
    "url": _codec_url,
    "url2": _codec_url2,
    "base64": _codec_base64,
    "hex": _codec_hex,
    "unicode": _codec_unicode,
    "html": _codec_html,
    "gzip": _codec_gzip,
    "zlib": _codec_zlib,
}


# ---------------------------------------------------------------- 5 种绕过


def _case(s, p):
    """大小写变换。words 为空则作用于整串。

    mode 只有 upper / lower / alternate 三种——**没有 random**，
    因为 §4.3 要求输出确定性，随机会让黄金样本失效。

    和 `_replace` 一样支持 `skip_quoted`：`'SELECT'` 这个字面量不该被改成 `'SeLeCt'`。
    """
    mode = p["mode"]
    words = p.get("words") or []

    def conv(w):
        if mode == "upper":
            return w.upper()
        if mode == "lower":
            return w.lower()
        if mode == "alternate":
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(w))
        raise ValueError("未知 case mode: %s" % mode)

    def fn(t):
        if not words:
            return conv(t)
        for w in sorted(words, key=len, reverse=True):
            t = re.sub(re.escape(w), lambda m: conv(m.group(0)), t, flags=re.IGNORECASE)
        return t

    return _outside_quotes(s, fn) if p.get("skip_quoted") else fn(s)


def _quoted_spans(s):
    """扫出成对的引号区域 [start, end)，用作 skip_quoted 的保护范围。

    **这是启发式，不是 parser。** 两条规则：

    1. **片段首字符若是引号，按代码处理。** 注入片段总是从打破上层上下文开始——
       `' UNION SELECT 1-- -` 里开头那个 `'` 是**闭合**上层引号的逃逸符，不是开启引号。
       若当成开启引号，整个后半段都会被误保护，绕过静默失效（正是本功能要解决的问题本身）。
    2. **之后贪心配对**：见到引号就找下一个未转义的同类引号，找到就整段保护，找不到当代码。

    转义支持 `\\x` 和双写 `''` / `""` 两种。

    已知会被骗的情况：片段中间出现孤立引号时配对会错位。它覆盖常见形态，不覆盖全部。
    """
    spans, i, n = [], 0, len(s)
    if n and s[0] in "'\"`":
        i = 1
    while i < n:
        c = s[i]
        if c not in "'\"`":
            i += 1
            continue
        j = i + 1
        while j < n:
            if s[j] == "\\":
                j += 2
                continue
            if s[j] == c:
                if j + 1 < n and s[j + 1] == c:  # 双写转义 '' / ""
                    j += 2
                    continue
                break
            j += 1
        if j >= n:
            i += 1  # 找不到配对，当代码
            continue
        spans.append((i, j + 1))
        i = j + 1
    return spans


# 引号扫描器也给引擎用（判断变量落在模板的哪一段里），所以给个公开名字
quoted_spans = _quoted_spans


def _outside_quotes(s, fn):
    """只对引号区域之外的部分做变换。"""
    spans, out, last = _quoted_spans(s), [], 0
    for a, b in spans:
        out.append(fn(s[last:a]))
        out.append(s[a:b])  # 引号区域原样保留
        last = b
    out.append(fn(s[last:]))
    return "".join(out)


def _replace(s, p):
    """字面替换。

    `skip_quoted: true` 时只在引号外替换——否则会改掉字符串字面量里的内容：
    `'a b'` 被空格替换绕过加工成 `'a/**/b'`，**语法依旧合法，语义已经错了**。
    """
    fn = lambda t: t.replace(p["pattern"], p["with"])  # noqa: E731
    return _outside_quotes(s, fn) if p.get("skip_quoted") else fn(s)


def _wrap(s, p):
    return p.get("prefix", "") + s + p.get("suffix", "")


def _encode(s, p):
    codec = p["codec"]
    if codec not in CODECS:
        raise ValueError("未知 codec: %s" % codec)
    return CODECS[codec](s)


def _join(s, p):
    """把 params.parts 里的字面片段与当前 payload 用 separator 连接。"""
    parts = list(p.get("parts") or []) + [s]
    return p.get("separator", ";").join(parts)


BYPASS_TYPES = {
    "case": _case,
    "replace": _replace,
    "wrap": _wrap,
    "encode": _encode,
    "join": _join,
}


def apply_bypass(text, bypass):
    """应用一条绕过。bypass 是数据里的字典。"""
    fn = BYPASS_TYPES.get(bypass["type"])
    if fn is None:
        raise ValueError("未知绕过类型: %s" % bypass["type"])
    return fn(text, bypass.get("params") or {})


# ---------------------------------------------------------------- shell 转义


def shell_quote(s, shell):
    """把字符串安全地放进 shell 命令（§8.1）。

    这是 curl / httpie 输出唯一会静默出错的地方。
    """
    if shell == "powershell":
        return "'" + s.replace("'", "''") + "'"
    if shell == "cmd":
        return '"' + s.replace('"', '""') + '"'
    # bash / zsh / sh（默认）
    return "'" + s.replace("'", "'\\''") + "'"
