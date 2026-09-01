# RuoYi (若依) 框架漏洞全集

> 维护者：黑骡 v1.1.0 | 最后更新：2026-07-23
> 覆盖版本：v3.0 ~ v4.8.0 | 收录 CVE：40 条

---

## 一、版本概览

| 版本 | 发布时间 | 安全状态 | 已知致命漏洞 |
|---|---|---|---|
| v3.0 ~ v3.8 | 2019-2021 | 🔴 高危 | Shiro RCE、Fastjson、Druid未授权、默认密码 |
| v4.0 ~ v4.5 | 2021-2022 | 🟠 中高危 | 文件上传RCE、SQL注入、Shiro仍存在 |
| v4.6 ~ v4.7 | 2022-2023 | 🟡 中等 | 部分SQLi、XSS、信息泄露、Shiro升级 |
| v4.7.5 ~ v4.7.9 | 2023-2024 | 🟡 中等 | SQLi(gen模块)、XSS、权限提升 |
| v4.8.0+ | 2024-2025 | 🟡 中等 | 权限提升、会话泄露、部分SQLi |

---

## 二、致命漏洞 TOP 10（按危害排序）

### 🔴 1. Shiro RememberMe 反序列化 RCE

| 项目 | 详情 |
|---|---|
| CVE | CVE-2016-4437 |
| 影响版本 | RuoYi ≤ 4.6.0（使用 Shiro < 1.7.0） |
| 危害 | **无需认证，直接 RCE** |
| 利用 | Shiro rememberMe cookie 使用 AES-CBC 加密，密钥硬编码 `kPH+bIxk5D2deZiIxcaaaA==` |
| 工具 | `java -jar ysoserial.jar CommonsBeanutils1 "cmd" > payload` → Shiro 加密 → Cookie 注入 |

**检测**：
```bash
curl -v https://target -H "Cookie: rememberMe=1" 2>&1 | grep "rememberMe=deleteMe"
# 返回 Set-Cookie: rememberMe=deleteMe → 使用 Shiro，可能存在漏洞
```

**注意**：
- RuoYi v4.6.1+ 升级了 Shiro 并随机化了密钥
- 但 v4.7.0 之前仍有很多部署使用默认密钥
- CVE-2021-38241 (RuoYi < 4.6.1)：Shiro 弱加密导致的特定反序列化

---

### 🔴 2. 文件上传 → RCE

| 项目 | 详情 |
|---|---|
| CVE | CVE-2022-32065 |
| 影响版本 | RuoYi ≤ 4.7.3 |
| 端点 | `/common/upload`（需要后台权限） |
| 危害 | 上传 JSP/WebShell → 服务器完全控制 |

**利用前提**：需要后台登录凭证

---

### 🟠 3. 代码生成 → 模板注入 RCE

| 项目 | 详情 |
|---|---|
| CVE | CVE-2024-46076, CVE-2025-0734 |
| 影响版本 | ≤ 4.8.0 |
| 端点 | `/tool/gen/createTable` |
| 危害 | SQL 注入 + 模板注入可组合利用 |

**Payload**（SQL 注入创建恶意表）：
```sql
-- 在代码生成中注入恶意 Velocity 模板
CREATE TABLE test (id INT);
-- 模板内容: #set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) ...
```

---

### 🟠 4. SQL 注入（多版本多处）

| CVE | 影响版本 | 注入点 | 认证 |
|---|---|---|---|
| CVE-2022-48114 | ≤ 4.7.5 | `/tool/gen/createTable` | ✅ 需要 |
| CVE-2023-49371 | ≤ 4.6 | `/system/dept/edit` | ✅ 需要 |
| CVE-2024-42913 | 4.7.9 | `job_id` 参数 | ✅ 需要 |
| CVE-2024-54762 | ≤ 4.7.9 | `filterKeyword` 绕过 | ✅ 需要 |
| CVE-2024-57437 | 4.8.0 | `/monitor/online/list` orderBy | ✅ 需要 |

---

### 🟠 5. 权限提升（Privilege Escalation）

| CVE | 影响版本 | 利用方式 |
|---|---|---|
| CVE-2024-57438 | 4.8.0 | 分配更高角色给自己 |
| CVE-2025-28400 | 4.8.0 | postID 参数修改 |
| CVE-2025-28401 | 4.8.0 | menuId 参数修改 |
| CVE-2025-28402 | 4.8.0 | jobId 参数修改 |
| CVE-2025-28403 | 4.8.0 | editSave 方法越权 |

**场景**：普通用户通过修改请求参数可提升至管理员。

---

### 🟡 6. 未授权配置读写（CRITICAL in practice）

| 项目 | 详情 |
|---|---|
| 无 CVE 编号 | 自定义 Controller 认证缺失 |
| 影响 | 所有自定义 `/prod-api/**` 端点可能未加认证 |
| 实战案例 | 博彩平台 `getBasicInfo` 泄露 90 字段含全部支付密钥 |
| 参考 | SecAtlas: `techniques/api-bypass/ruoyi-unauth-config-write.yaml` |

---

### 🟡 7. 任意文件下载/读取

| CVE | 影响 | 端点 |
|---|---|---|
| CVE-2023-27025 | ≤ 4.7.6 | 后台文件管理模块 |

---

### 🟡 8. XSS（多版本）

| CVE | 影响版本 | 触发点 |
|---|---|---|
| CVE-2023-52048 | 4.7.8 | `/system/notice/` |
| CVE-2024-41599 | ≤ 4.7.9 | 文件上传 → 文件名 XSS |
| CVE-2024-42900 | ≤ 4.7.9 | `createTable()` sql 参数 |

---

### 🟡 9. 弱密码 + 验证码可绕过

| 项目 | 详情 |
|---|---|
| 默认账号 | `admin / admin123` |
| 验证码 | 简单数学计算（如 `6+3=?`），OCR 可解 |
| 绕过 | 2captcha 打码平台（SecAtlas 已收录） |

---

### 🟡 10. Druid 监控未授权访问

| 项目 | 详情 |
|---|---|
| 端点 | `/druid/index.html` |
| 影响版本 | RuoYi < 4.7.0 未配置 Druid 认证 |
| 危害 | 泄露数据库连接信息、SQL 执行统计、Session 信息 |

---

## 三、常规攻击面（不限于 CVE）

### 3.1 信息泄露

| 端点 | 说明 | 认证 |
|---|---|---|
| `/swagger-ui.html` | Swagger API 文档 | 视配置 |
| `/doc.html` | Knife4j 文档 | 视配置 |
| `/v2/api-docs` | OpenAPI JSON | 视配置 |
| `/actuator` | Spring Boot Actuator | 视配置 |
| `/druid/index.html` | Druid 连接池监控 | ≤4.6 常未授权 |
| `/prod-api/` | API 欢迎页，暴露版本 | 无 |
| `/captchaImage` | 验证码（含 UUID） | 无 |

### 3.2 默认口令

```
admin / admin123    ← RuoYi 默认超级管理员
ry / 123456         ← 部分版本普通用户
```

### 3.3 认证绕过

- **Shiro 权限绕过**：`/admin/;/test` 路径绕过（Shiro < 1.6.0）
- **自定义 Controller 遗漏**：业务 Controller 未在 SecurityConfig 注册
- **JWT 密钥弱值**：使用默认密钥或简单字符串

### 3.4 反序列化

| 组件 | 说明 |
|---|---|
| Shiro | rememberMe cookie（CVE-2016-4437） |
| Fastjson | 部分 RuoYi 版本使用 Fastjson 处理 JSON |
| SnakeYAML | Spring Boot 默认 YAML 解析器 |

### 3.5 定时任务 RCE

| 端点 | 说明 |
|---|---|
| `/monitor/job` | 可添加定时任务，调用 `ruoyiTask.ryMultipleParams('java.lang.Runtime.getRuntime().exec("cmd")')` |

---

## 四、实战工具链

### 指纹识别
```bash
# 响应头特征
curl -I https://target | grep -i "ruoyi\|若依\|shiro"

# 页面特征
curl https://target | grep "ruoyi\|若依"

# API 探活
curl https://target/prod-api/
# 返回: "欢迎使用RuoYi后台管理框架"

# 版本探测
curl https://target/prod-api/login -X POST -d '{}'
# 错误信息可能泄露版本
```

### Shiro 检测
```bash
pip install shiro-detector
shiro-detector detect https://target
# 或手动: curl -v -H "Cookie: rememberMe=test" https://target
```

### 综合扫描
```
nuclei -t ~/nuclei-templates/http/ruoyi/
```

---

## 五、版本-漏洞速查表

| 目标版本 | 优先尝试 |
|---|---|
| ≤ 4.5 | Shiro RCE → 默认口令 → Druid → 文件上传 |
| 4.6 ~ 4.7.3 | 默认口令 → SQLi(gen) → 文件上传 → XSS |
| 4.7.4 ~ 4.7.9 | SQLi(gen) → 权限提升 → XSS → 信息泄露 |
| 4.8.0+ | 权限提升 → SQLi → 会话泄露 |

---

## 六、防御加固

| 优先级 | 措施 |
|---|---|
| P0 | 更改默认密码，禁用 `admin` 账号 |
| P0 | 升级 Shiro 到最新版并随机化密钥 |
| P0 | 安全配置中为所有 API 添加认证拦截 |
| P1 | 关闭 Swagger/Druid 公网暴露 |
| P1 | 验证码升级为滑块/Google reCAPTCHA |
| P1 | 升级到最新 RuoYi 版本 |
| P2 | WAF 规则拦截 `/prod-api/**` 的未授权访问 |

---

## 七、参考资源

- NVD RuoYi CVEs: https://nvd.nist.gov
- GitHub RuoYi: https://github.com/yangzongzhuan/RuoYi
- SecAtlas 技术卡: `techniques/auth/ruoyi-captcha-bypass-2captcha.yaml`
- SecAtlas 技术卡: `techniques/api-bypass/ruoyi-unauth-config-write.yaml`
- Shiro 检测: https://github.com/feihong-cs/ShiroExploit-Deprecated

---

*本文档由黑骡整理，收录于 SecAtlas 知识库。*