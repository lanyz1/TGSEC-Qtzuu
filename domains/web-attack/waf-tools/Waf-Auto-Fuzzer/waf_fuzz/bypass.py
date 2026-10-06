"""绕过脚本生成器。"""


def generate_bypass_script(bypass_results, target_url="", param=""):
    """从成功的 bypass 结果生成可复用的 Python 脚本。"""
    seen = set()
    uniq = []
    for r in bypass_results:
        key = (r.category, r.payload, r.encoding)
        if key not in seen:
            seen.add(key)
            uniq.append(r)

    if not uniq:
        return "#!/usr/bin/env python3\n# 未发现有效的绕过方式\nprint('No bypasses found.')\n"

    lines = [
        "#!/usr/bin/env python3",
        "# 自动生成 — WAF 绕过脚本",
        "# 使用 waf-auto-fuzzer 自动生成",
        "",
        "import sys",
        "import requests",
        "",
        "TARGET_URL = %r" % target_url,
        "PARAM_NAME = %r" % param,
        "",
        "PAYLOADS = [",
    ]

    for r in uniq:
        lines.append("    # [%s] bypassed with encoding: %s" % (r.category, r.encoding))
        lines.append("    (%r, %r)," % (r.payload, r.encoding))

    lines += [
        "    ]",
        "",
        "def encode(payload, enc_type):",
        "    import urllib.parse, base64",
        "    if enc_type == 'raw':",
        "        return payload",
        "    elif enc_type == 'urlencode':",
        "        return urllib.parse.quote(payload)",
        "    elif enc_type == 'double_urlencode':",
        "        return urllib.parse.quote(urllib.parse.quote(payload))",
        "    elif enc_type == 'base64':",
        "        return base64.b64encode(payload.encode()).decode()",
        "    elif enc_type == 'unicode':",
        "        return ''.join('\\\\u{:04x}'.format(ord(c)) for c in payload)",
        "    elif enc_type == 'swapcase':",
        "        return payload.swapcase()",
        "    elif enc_type == 'inline_comment':",
        "        return payload.replace(' ', '/**/')",
        "    elif enc_type == 'tab_replace':",
        "        return payload.replace(' ', '\\t')",
        "    elif enc_type == 'hex':",
        "        return ''.join('\\\\x{:02x}'.format(ord(c)) for c in payload)",
        "    elif enc_type == 'null_byte':",
        "        return payload + '%00'",
        "    elif enc_type == 'reverse':",
        "        return payload[::-1]",
        "    else:",
        "        return payload",
        "",
        "def main():",
        "    if not TARGET_URL:",
        "        print('Edit TARGET_URL in this script before running.')",
        "        sys.exit(1)",
        "    session = requests.Session()",
        "    for payload, enc_type in PAYLOADS:",
        "        encoded = encode(payload, enc_type)",
        "        params = {PARAM_NAME: encoded}",
        "        try:",
        "            resp = session.get(TARGET_URL, params=params, timeout=10)",
        "            print('[%d] %s [%s] => %s' % (",
        "                resp.status_code, enc_type, payload,",
        "                'BLOCKED' if resp.status_code in (403, 406) else 'SENT'",
        "            ))",
        "        except Exception as e:",
        "            print('[ERR] %s: %s' % (enc_type, e))",
        "",
        "if __name__ == '__main__':",
        "    main()",
    ]

    return "\n".join(lines)
