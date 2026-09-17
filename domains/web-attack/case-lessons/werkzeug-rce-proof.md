# Werkzeug RCE 完整利用证明

- Source report: `漏洞利用完整证明报告.md`
- Full report: `domains/web-attack/case-reports/werkzeug-rce-proof/漏洞利用完整证明报告.md`
- Techniques: rce, sqli
- Fused: 2026-09-17

## Key findings (distilled)

- 💰 声誉损害: 长期且严重
- ⏱️ 5分钟内触发漏洞

## Repro snippets

```
def _process_login_payload(payload, device_id):
    """通用登录处理，返回 dict"""
    username = (payload.get('username') or '').strip()
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    password = payload.get('password') or ''
    card_code = (payload.get('card_code') or '').strip()
 
    if not card_code and (not username or not password):
        return {'success': False, 'message': '用户名和密码不能为空'}
def api_login():
    """JSON 登录接口"""
    data = request.get_json() or {}
    device_id = _get_device_id_from_request(data)
    result = _process_login_payload(data, device_id)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 
    if result.get('success'):
        # 通过 quick_login 链接完成登录/重定向
        token = result.get('redirect')
        if token:
            # ... 处理登录成功逻辑
Frame 124063152569600: __call__ (Flask核心)
Frame 124059616624016: wsgi_app 
Frame 124059616610624: wsgi_app
Frame 124059616619408: full_dispatch_request
Frame 124059616617824: full_dispatch_request
Frame 124059616622432: dispatch_request
Frame 124059616615088: api_login (第281行) ← 应用层
Frame 124059616622000: _process_login_payload (第54行) ← 最关键
```

## When to reuse

- 同类标签命中：rce, sqli
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
