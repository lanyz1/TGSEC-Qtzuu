"""编码/变形引擎 — 对 payload 应用各种绕过编码。

共 44 种编码方式，覆盖：
  - URL / 多重编码
  - HTML / 十六进制 / Base64
  - Unicode / UTF-16 / 全角
  - SQL 注释 / 关键字拆分
  - 大小写混淆
  - 空白字符变形
  - 字符串连接 / 表达式包装
  - Shell 通配符 / 空字节
"""

import base64
import random
import urllib.parse

random.seed(42)


def encode_payload(payload):
    """对一条 payload 应用所有编码变形。

    Returns:
        list of (name, encoded_string)
    """
    encodings = []

    # ── 原始 ────────────────────────────────────────
    encodings.append(("raw", payload))

    # ── URL 编码系列 ─────────────────────────────────
    encodings.append(("urlencode", urllib.parse.quote(payload)))
    encodings.append(("double_urlencode", urllib.parse.quote(urllib.parse.quote(payload))))
    encodings.append(("triple_urlencode", urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(payload)))))
    encodings.append(("percent_double", percent_double(payload)))
    encodings.append(("unicode_url", urllib.parse.quote(unicode_escape(payload))))
    encodings.append(("urlencode_twice_mixed", urlencode_selective_twice(payload)))
    encodings.append(("leading_zero_url", urlencode_leading_zeros(payload)))

    # ── HTML / 实体编码 ─────────────────────────────
    encodings.append(("html_escape", html_escape(payload)))
    encodings.append(("decimal_html", decimal_html_entity(payload)))
    encodings.append(("hex_html", hex_html_entity(payload)))

    # ── Unicode / 宽字符 ─────────────────────────────
    encodings.append(("unicode", unicode_escape(payload)))
    encodings.append(("unicode_percent", unicode_percent_encoding(payload)))
    encodings.append(("utf16_le", utf16_le_encode(payload)))
    encodings.append(("full_width", full_width_encode(payload)))

    # ── Base64 系列 ─────────────────────────────────
    encodings.append(("base64", base64.b64encode(payload.encode()).decode()))
    encodings.append(("base64_urlsafe", base64.urlsafe_b64encode(payload.encode()).decode()))

    # ── 大小写混淆 ─────────────────────────────────
    encodings.append(("swapcase", payload.swapcase()))
    encodings.append(("mixed_case", mixed_case(payload)))
    encodings.append(("case_by_word", case_by_word(payload)))
    encodings.append(("upper", payload.upper()))
    encodings.append(("lower", payload.lower()))

    # ── 注释注入 ────────────────────────────────────
    encodings.append(("inline_comment", inline_comment(payload)))
    encodings.append(("sql_comment", sql_comment_insert(payload)))
    encodings.append(("sql_nested_comment", sql_nested_comment(payload)))
    encodings.append(("sql_mysql_comment", sql_mysql_comment(payload)))
    encodings.append(("sql_hash_comment", payload + " #"))
    encodings.append(("sql_dash_comment", payload + " --"))
    encodings.append(("mid_comment_char", mid_comment_char(payload)))
    encodings.append(("comment_wrap", "/*" + payload + "*/"))

    # ── 空白字符变形 ────────────────────────────────
    encodings.append(("tab_replace", payload.replace(" ", "\t")))
    encodings.append(("newline_replace", payload.replace(" ", "\n")))
    encodings.append(("space_to_plus", payload.replace(" ", "+")))
    encodings.append(("space_to_dash", payload.replace(" ", "-")))
    encodings.append(("collapse_spaces", collapse_spaces(payload)))
    encodings.append(("newline_delimited", newline_delimited(payload)))
    encodings.append(("tab_delimited", tab_delimited(payload)))

    # ── 空字节 / 截断 ──────────────────────────────
    encodings.append(("null_byte_suffix", payload + "%00"))
    encodings.append(("null_byte_mid", null_byte_mid(payload)))

    # ── 字符串连接 / 表达式包装 ──────────────────────
    encodings.append(("concat_dots", concat_dots(payload)))
    encodings.append(("plus_concat", payload.replace(" ", "+")))
    encodings.append(("bracket_wrap", bracket_wrap(payload)))
    encodings.append(("hex_escape", hex_escape(payload)))
    encodings.append(("javascript_escape", js_escape(payload)))

    # ── Shell 通配符 ────────────────────────────────
    encodings.append(("wildcard_shell", wildcard_shell(payload)))
    encodings.append(("tilde_expand", tilde_expand(payload)))

    # ── 其他变形 ────────────────────────────────────
    encodings.append(("reverse", payload[::-1]))
    encodings.append(("trailing_spaces", payload + "    "))
    encodings.append(("overlong_utf8", overlong_utf8(payload)))

    return encodings


# ════════════════════════════════════════════════════════
# URL 编码系列
# ════════════════════════════════════════════════════════

def percent_double(s):
    """%% 双重编码 — 某些 WAF 只解码一次。"""
    return urllib.parse.quote(s).replace("%", "%%")


def urlencode_selective_twice(s):
    """选择性双重编码：只对某些字符双重编码，其他单次。"""
    result = ""
    for c in s:
        if c in "<>'\"/()":
            result += urllib.parse.quote(urllib.parse.quote(c))
        else:
            result += urllib.parse.quote(c)
    return result


def urlencode_leading_zeros(s):
    """URL 编码时使用前导零，如 %3C → %003C。"""
    result = ""
    for c in s:
        if ord(c) < 128 and c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.":
            h = hex(ord(c))[2:].upper().zfill(2)
            result += f"%00{h}"
        else:
            result += c
    return result


# ════════════════════════════════════════════════════════
# HTML / 实体编码
# ════════════════════════════════════════════════════════

def html_escape(s):
    """HTML 实体编码（命名实体）。"""
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;"))


def decimal_html_entity(s):
    """HTML 十进制实体 &#38;  &#60;  &#62;"""
    return "".join(f"&#{ord(c)};" for c in s)


def hex_html_entity(s):
    """HTML 十六进制实体 &#x26;  &#x3C;  &#x3E;"""
    return "".join(f"&#x{ord(c):x};" for c in s)


# ════════════════════════════════════════════════════════
# Unicode / 宽字符
# ════════════════════════════════════════════════════════

def unicode_escape(s):
    r"""Unicode 转义: A 格式。"""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def unicode_percent_encoding(s):
    """Unicode 百分比编码: %u0041 格式 (IIS/ASP 特定)."""
    return "".join(f"%u{ord(c):04X}" for c in s)


def utf16_le_encode(s):
    """UTF-16-LE 编码。"""
    return s.encode("utf-16-le").hex()


def full_width_encode(s):
    """全角 ASCII 字母/数字（某些 WAF 正则匹配不到半角）。"""
    result = ""
    for c in s:
        o = ord(c)
        if 0x21 <= o <= 0x7E:
            result += chr(o + 0xFEE0)
        else:
            result += c
    return result


# ════════════════════════════════════════════════════════
# 大小写混淆
# ════════════════════════════════════════════════════════

def mixed_case(s):
    """交替大小写: aLtErNaTiNg。"""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))


def case_by_word(s):
    """按单词切换大小写: SELECT → sElEcT。"""
    return "".join(c.upper() if i % 3 == 0 else c.lower() for i, c in enumerate(s))


# ════════════════════════════════════════════════════════
# 注释注入
# ════════════════════════════════════════════════════════

def inline_comment(s):
    """用 /**/ 替换空格。"""
    return s.replace(" ", "/**/")


def sql_comment_insert(s):
    """每字符间插入 /**/ 分割 SQL 关键字。"""
    return "/**/".join(s)


def sql_nested_comment(s):
    """嵌套注释 /*!*/ 包裹关键字。"""
    return "/*!" + s + "*/"


def sql_mysql_comment(s):
    """MySQL 版本注释 /*!50000*/ 前缀。"""
    return "/*!50000" + s + "*/"


def mid_comment_char(s):
    """在关键字中间插入注释: SE/**/LECT。"""
    if len(s) < 4:
        return s
    mid = len(s) // 2
    return s[:mid] + "/**/" + s[mid:]


# ════════════════════════════════════════════════════════
# 空白字符变形
# ════════════════════════════════════════════════════════

def collapse_spaces(s):
    """合并连续空格为单个。"""
    parts = s.split()
    return " ".join(parts) if parts else s


def newline_delimited(s):
    """用 %0a 分隔每个字符。"""
    return "%0a".join(s)


def tab_delimited(s):
    """用 %09 分隔每个字符。"""
    return "%09".join(s)


# ════════════════════════════════════════════════════════
# 空字节 / 截断
# ════════════════════════════════════════════════════════

def null_byte_mid(s):
    """在关键字中间插 %00 绕过 WAF 正则。"""
    if len(s) < 4:
        return s + "%00"
    # 在中间插入
    pos = len(s) // 2
    return s[:pos] + "%00" + s[pos:]


# ════════════════════════════════════════════════════════
# 字符串连接 / 表达式包装
# ════════════════════════════════════════════════════════

def concat_dots(s):
    """用 || 连接每个字符（SQL 字符串连接），如 'a'||'d'||'m'。"""
    return "||".join(f"'{c}'" for c in s if c != "'")


def bracket_wrap(s):
    """用括号或表达式包装，如 (SELECT 1 FROM users)。"""
    return "(" + s + ")"


def hex_escape(s):
    """纯十六进制拼接: 27204F52 格式。"""
    return "".join(f"{ord(c):02x}" for c in s)


def js_escape(s):
    r"""JavaScript 十六进制转义: \x27\x20\x4F\x52 格式。"""
    return "".join(f"\\x{ord(c):02x}" for c in s)


# ════════════════════════════════════════════════════════
# Shell 通配符
# ════════════════════════════════════════════════════════

def wildcard_shell(s):
    """将常见命令替换为通配符形式: cat → ???, /etc/passwd → /???/??????。"""
    result = ""
    for c in s:
        if c.isalpha():
            result += "?"
        else:
            result += c
    return result


def tilde_expand(s):
    """在路径前添加 ~ (tilde expansion)."""
    return "~" + s


# ════════════════════════════════════════════════════════
# 其他
# ════════════════════════════════════════════════════════

def overlong_utf8(s):
    """过长 UTF-8 编码（用于 / .. 等字符绕过 WAF）。"""
    result = ""
    for c in s:
        if ord(c) < 128:
            # 用 2 字节过长编码表示 ASCII 字符
            b = ord(c)
            result += f"%c0%{80 + (b >> 6):02x}%80%{b & 0x3f:02x}"
        else:
            result += c
    return result


def encode_methods():
    """返回所有编码方式名称列表。"""
    return [name for name, _ in encode_payload("test")]
