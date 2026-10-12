#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VerifyChain 闭环验证层 — 把"我觉得有洞"升级成"硬证据+置信度打分"
(L3工具编排 -> L4授权自主红队 的第③块认知轴承)

核心: 红队最贵的不是"挖到", 是"验准". 一个没验准的0day拉去实战会翻车+丢信誉.
本工具提供标准化验证器:
  timing   : 时间盲注验证 — 对照组+多次采样+抖动扣除, 输出是否真延迟(防网络抖动误判)
  boolean  : 布尔盲注验证 — 真/假条件响应差异 + 多次重复一致性
  echo     : 报错/回显注入验证 — 检测SQLSTATE/报错特征
  sqlishape: 给一个"疑似SQLi"的路径, 判定是否真可注入(如sku->{$k}这类框架JSON路径)
  score    : 汇总一次攻击的验证证据, 打置信度分(0-100), 给"成立/存疑/不成立"结论

设计原则: 任何结论必须可复现; 证据不足时明确说"存疑", 绝不吹成"成立".
"""
import sys, json, time, statistics, urllib.request, urllib.error, ssl

CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

def _get(url, headers=None, timeout=25, data=None):
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if headers: h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=CTX)
        return time.time()-t0, r.status, r.read(4000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return time.time()-t0, e.code, e.read(4000).decode("utf-8", "ignore")
    except Exception as e:
        return time.time()-t0, -1, "ERR " + str(e)[:80]

def timing(base_url, payloads, rounds=3, sleep_s=5, method="GET", param="q", timeout=None):
    """时间盲注验证: 对每个payload多轮采样, 扣除基线抖动, 判定是否真延迟"""
    if timeout is None: timeout = sleep_s * 3 + 15
    # 基线采样
    base_lat = []
    for _ in range(rounds):
        dt, sc, _ = _get("%s?%s=1" % (base_url, param), timeout=timeout)
        if dt > 0: base_lat.append(dt)
        time.sleep(0.3)
    bl = statistics.median(base_lat) if base_lat else 0
    jit = (max(base_lat) - min(base_lat)) if len(base_lat) > 1 else 0
    results = []
    for p in payloads:
        lats = []
        for _ in range(rounds):
            url = "%s?%s=%s" % (base_url, param, p) if method == "GET" else base_url
            dt, sc, body = _get(url, timeout=timeout)
            lats.append(dt); time.sleep(0.4)
        med = statistics.median(lats) if lats else 0
        delta = med - bl
        # 判定: 延迟 > sleep_s*0.7 且 > 抖动*2 才算真
        real = (delta > sleep_s * 0.7) and (delta > max(jit * 2, 0.8))
        results.append({"payload": p, "median_latency": round(med, 2), "baseline": round(bl, 2),
                        "delta": round(delta, 2), "jitter": round(jit, 2), "real_delay": real,
                        "verdict": "成立" if real else "不成立"})
    return {"op": "timing", "baseline_s": round(bl, 2), "jitter_s": round(jit, 2),
            "timing_reliable": jit < 1.0, "results": results,
            "conclusion": "存在时间盲注" if any(r["real_delay"] for r in results) else "未证实时间盲注"}

def boolean(url_true, url_false, rounds=3, timeout=25):
    """布尔盲注验证: 真/假条件响应差异 + 一致性"""
    def samp(u):
        L, B = [], []
        for _ in range(rounds):
            dt, sc, body = _get(u, timeout=timeout)
            L.append(dt); B.append(len(body))
            time.sleep(0.3)
        return statistics.median(L) if L else 0, statistics.median(B) if B else 0, B
    lt, bt, bts = samp(url_true)
    lf, bf, bfs = samp(url_false)
    diff = abs(bt - bf)
    consistent = len(set(round(x/50.0) for x in bts)) == 1 and len(set(round(x/50.0) for x in bfs)) == 1
    real = diff > 20 and consistent
    return {"op": "boolean", "true_len": bt, "false_len": bf, "diff": diff,
            "consistent": consistent, "real_diff": real,
            "conclusion": "布尔盲注成立" if real else "布尔差异不可靠/不成立"}

def echo(url, timeout=25):
    """报错注入验证: 检测响应里的SQL/DB报错特征"""
    dt, sc, body = _get(url, timeout=timeout)
    sigs = ["SQLSTATE", "You have an error in your SQL", "mysql_fetch", "mysqli", "PDOException",
            "ORA-", "PostgreSQL", "SQLite", "syntax error", "Unclosed quotation", "Warning: mysql"]
    hit = [s for s in sigs if s.lower() in body.lower()]
    return {"op": "echo", "status": sc, "hit_sigs": hit, "verdict": "报错回显" if hit else "无报错泄露",
            "conclusion": "存在报错注入" if hit else "未发现报错注入"}

def score(evidence):
    """汇总验证证据, 打置信度分. evidence: [{"type":"timing"/"boolean"/"echo"/"sqlishape","real":bool,"detail":..}]"""
    s = 0; notes = []
    for e in evidence or []:
        t = e.get("type"); r = e.get("real")
        w = {"timing": 35, "boolean": 30, "echo": 25, "sqlishape": 40, "manual": 20}.get(t, 10)
        if r: s += w; notes.append("+%d %s" % (w, t))
        else: notes.append("+0 %s(未证实)" % t)
    s = min(100, s)
    if s >= 70: verdict = "成立"
    elif s >= 40: verdict = "存疑(需补证据)"
    else: verdict = "不成立"
    return {"op": "score", "confidence": s, "verdict": verdict,
            "breakdown": notes,
            "rule": "置信<40不成立; 40-70存疑; >=70成立. 未证实项不计分, 严禁把存疑吹成成立"}

def sqlishape(k, framework="laravel7"):
    """判定'疑似SQLi路径'是否真可注入: 检验框架对payload的处理
    对Laravel JSON路径(sku->{$k})类: 单引号是否被双写 => 不可注入"""
    result = {}
    if "'" in k:
        result["single_quote"] = "若框架将 ' 双写为 '' (Laravel wrapJsonPath) => 无法闭合字符串 => 不成立"
    if '"' in k:
        result["double_quote"] = "双引号在JSON路径内不闭合SQL串, 仅供JSON路径解析"
    result["framework"] = framework
    result["manual_check"] = "必须用框架的 toSql()/query-builder 打印真实SQL, 或发请求到目标观察回显/延迟"
    result["verdict"] = "需实测; 语法形态≠可利用"
    return {"op": "sqlishape", "input": k, **result}

try:
    a = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
except Exception:
    print(json.dumps({"error": "参数受损"}, ensure_ascii=False)); sys.exit(0)

op = a.get("op", "score")
if op == "timing":
    print(json.dumps(timing(a["base_url"], a["payloads"], int(a.get("rounds", 3)), float(a.get("sleep_s", 5))),
                     ensure_ascii=False, indent=1))
elif op == "boolean":
    print(json.dumps(boolean(a["url_true"], a["url_false"], int(a.get("rounds", 3))), ensure_ascii=False, indent=1))
elif op == "echo":
    print(json.dumps(echo(a["url"]), ensure_ascii=False, indent=1))
elif op == "score":
    print(json.dumps(score(a.get("evidence", [])), ensure_ascii=False, indent=1))
elif op == "sqlishape":
    print(json.dumps(sqlishape(a.get("payload", ""), a.get("framework", "laravel7")), ensure_ascii=False, indent=1))
else:
    print(json.dumps({"error": "unknown op"}, ensure_ascii=False))
