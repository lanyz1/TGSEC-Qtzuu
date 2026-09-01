---
name: oa-system-attack
description: "国产 OA/内网系统漏洞利用。当在内网发现致远(Seeyon)、泛微(Weaver/E-cology)、用友(Yonyou/NC/U8)、蓝凌(Landray)、通达(Tongda)、万户(Ezoffice)、金蝶(Kingdee)、红帆(iOffice) 等国产 OA 系统时使用。覆盖各系统的典型漏洞、默认口令、RCE 路径。国内 HW/比赛内网中高频出现，一定要使用此技能"
metadata:
  tags: "oa,seeyon,致远,泛微,weaver,ecology,用友,yonyou,nc,蓝凌,landray,通达,tongda,万户,金蝶,内网,国产系统,办公系统"
  category: "lateral"
---

# 国产 OA/内网系统漏洞利用

国内比赛内网环境几乎必有 OA 系统——它们历史漏洞多、补丁率低、权限通常较高。

## ⛔ 深入参考（必读）

- 致远/泛微/用友详细漏洞利用 → [references/oa-exploits.md](references/oa-exploits.md)
- 通达/蓝凌/其他系统漏洞利用 → [references/oa-exploits-more.md](references/oa-exploits-more.md)

---

## Phase 1: OA 系统识别

```bash
# Web 指纹识别
whatweb http://TARGET
curl -sI http://TARGET | grep -i "Server"
curl -s http://TARGET | grep -iE "seeyon|致远|weaver|ecology|泛微|yonyou|用友|tongda|通达|landray|蓝凌|ezoffice|万户"

# 常见路径指纹
curl -s http://TARGET/seeyon/           # 致远 OA
curl -s http://TARGET/weaver/           # 泛微 E-cology
curl -s http://TARGET/mobile/           # 泛微 E-mobile
curl -s http://TARGET/ispirit/          # 通达 OA
curl -s http://TARGET/sys/             # 蓝凌 OA
curl -s http://TARGET/portal/          # 用友 NC
```

## Phase 2: 系统 → 漏洞速查

### 致远 OA (Seeyon) — 漏洞最多

| 漏洞 | 路径 | 类型 |
|------|------|------|
| Session 泄露 | /seeyon/thirdpartyController.do | 任意用户登录 |
| 文件上传 | /seeyon/htmlofficeservlet | RCE |
| 反序列化 | /seeyon/autoinstall.do.css | RCE |
| SSRF | /seeyon/ajax.do | SSRF |
| SQL 注入 | /seeyon/webmail.do | SQLi |

### 泛微 OA (Weaver/E-cology) — 出现频率最高

| 漏洞 | 路径 | 类型 |
|------|------|------|
| SQL 注入 | /mobile/browser/WorkflowCenterTreeData.jsp | SQLi |
| 文件上传 | /weaver/bsh.servlet.BshServlet | RCE |
| SSRF | /ssrf/proxy | SSRF |
| 数据库配置读取 | /mobile/DBconfigReader.jsp | 信息泄露 |
| 命令执行 | /api/integration/workflowToDoc | RCE |

### 用友 NC (Yonyou) — 权限通常高

| 漏洞 | 路径 | 类型 |
|------|------|------|
| 反序列化 | /servlet/~ic/bsh.servlet.BshServlet | RCE |
| 文件上传 | /servlet/FileReceiveServlet | 任意文件上传 |
| 目录遍历 | /NCFindWeb | 信息泄露 |
| SSRF | /servlet/~uap/nc.itf.iufo.FunctionServlet | SSRF |

### 通达 OA — 入门级目标

| 漏洞 | 路径 | 类型 |
|------|------|------|
| 文件上传+包含 | /ispirit/im/upload.php + /ispirit/interface/gateway.php | RCE |
| 任意用户登录 | /logincheck_code.php | 认证绕过 |
| SQL 注入 | /general/approve_center/archive/getTableInfo.php | SQLi |

### 蓝凌 OA (Landray) — SSRF 到 RCE

| 漏洞 | 路径 | 类型 |
|------|------|------|
| SSRF → RCE | /sys/ui/extend/varkind/custom.jsp | RCE |
| 任意文件读取 | /sys/ui/extend/varkind/custom.jsp | 文件读取 |
| 反序列化 | /sys/search/sys_search_main/sysSearchMain.do | RCE |

→ 详细 payload → references

## Phase 3: 通用攻击策略

```
发现 OA 系统后:
1. 确认系统类型和版本
2. 尝试默认口令
3. 查已知 CVE / Nday
4. nuclei 扫描: nuclei -u TARGET -tags oa,seeyon,weaver,tongda
5. 手动验证高危漏洞（RCE > 文件上传 > SQLi > 信息泄露）
6. 获取 shell 后收集内网凭据
```

### 默认口令速查
| 系统 | 用户名 | 默认密码 |
|------|--------|---------|
| 致远 OA | system | system |
| 致远 OA | admin | seeyon123456 |
| 泛微 OA | sysadmin | 1 |
| 用友 NC | admin | admin |
| 通达 OA | admin | admin00 |
| 蓝凌 OA | admin | admin |
