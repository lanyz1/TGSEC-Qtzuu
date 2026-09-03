# TencentEdgeOne (TEO) WAF JS Challenge Bypass

When TencentEdgeOne Bot Management triggers, the API returns HTTP 200 with
`Content-Type: text/html`, `Server: TencentEdgeOne`, and a ~990-byte JS payload
instead of the expected JSON. All curl/python requests get this until the correct
cookies are set.

## Detection

```
HTTP/2 200
content-type: text/html
cache-control: no-cache
set-cookie: path=/
server: TencentEdgeOne
eo-log-uuid: ...
```

Body starts with `<script>function a(a){function n(){...`.

## JS structure (as of 2026-09)

1. Array `_0x49a6` with ~11 string elements.
2. IIFE rotates the array by `(N+1)` positions (N is the second arg, e.g. `0x147` = 327 → rotate 328).
3. Lookup function `_0x649a(hex)` indexes into the rotated array.
4. Function `a(arg)` computes two values:
   - `a(0)` → `__tst_status` cookie value (sum of 3 integers from object `e`)
   - `a(1)` → `EO_Bot_Ssid=<integer>` cookie string (from inner function switch-case)
5. The script sets both cookies, then `setTimeout` refreshes the page.

## Solver (Python)

```python
import re

def solve_teo_challenge(js_body):
    """Parse TEO JS challenge and return cookie string."""
    # Extract _0x49a6 array
    m = re.search(r'var _0x49a6=\[([^\]]+)\]', js_body)
    arr = [s.strip().strip('"').strip("'") for s in m.group(1).split(',')]
    
    # Extract rotation count
    m2 = re.search(r'e\(\+\+n\)\}\)\(_0x49a6,(0x[0-9a-f]+)\)', js_body)
    rot = int(m2.group(1), 16) + 1
    for _ in range(rot):
        arr.append(arr.pop(0))
    
    # Extract integer constants from object e = {WTKkN: ..., bOYDu: ..., wyeCN: ...}
    ints = [int(x) for x in re.findall(r':\s*(\d{6,})', js_body)]
    # First 3 ints sum to __tst_status, 4th is EO_Bot_Ssid
    tst = sum(ints[:3])
    ssid = ints[3] if len(ints) > 3 else 0
    
    return f"__tst_status={tst}; EO_Bot_Ssid={ssid}"

# Usage:
# cookie = solve_teo_challenge(challenge_html)
# requests.get(url, cookies=parse_cookie(cookie))
```

## Practical notes

- The integer constants change periodically — re-solve if cookies stop working.
- Once set, cookies persist for the session (~hours).
- Include WAF cookies **alongside** the JWT Bearer token: `Cookie: __tst_status=...; EO_Bot_Ssid=...`
- If the challenge format changes (different obfuscation pattern), the regex extraction
  will need updating — but the core structure (array rotation + integer sum) has been
  stable across multiple observations.
- The solver above is heuristic; for robustness, extract named keys from the `e` object
  and resolve them through the rotated array lookup.

## Verified working example (2026-09-01)

```
__tst_status=2366206770  (1755484960 + 396114715 + 214607095)
EO_Bot_Ssid=4038656000
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
