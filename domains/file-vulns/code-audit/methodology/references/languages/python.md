# Python Security Audit Guide

> Python 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: Python 2.x / 3.x, Flask, Django, FastAPI, Tornado 等

---

## 审计方法论

### 双轨并行框架

```
                    Python 代码安全审计
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  轨道A (50%)    │ │  轨道B (40%)    │ │  补充 (10%)     │
│  控制建模法     │ │  数据流分析法   │ │  配置+依赖审计  │
│                 │ │                 │ │                 │
│ 缺失类漏洞:     │ │ 注入类漏洞:     │ │ • 硬编码凭据    │
│ • 认证缺失      │ │ • SQL注入       │ │ • DEBUG=True    │
│ • 授权缺失      │ │ • 命令注入      │ │ • CVE依赖       │
│ • IDOR          │ │ • 代码注入      │ │                 │
│ • 竞态条件      │ │ • SSTI          │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 两轨核心公式

```
轨道A: 缺失类漏洞 = 敏感操作 - 应有控制
轨道B: 注入类漏洞 = Source → [无净化] → Sink
```

**参考文档**: `references/core/security_controls_methodology.md`, `references/core/data_flow_methodology.md`

---

# 轨道A: 控制建模法 (缺失类漏洞)

## A1. 敏感操作枚举

### 1.1 快速识别命令

```bash
# Flask/FastAPI路由 - 数据修改操作
grep -rn "@app\.route.*methods.*POST\|@app\.route.*methods.*PUT\|@app\.route.*methods.*DELETE" --include="*.py"
grep -rn "@router\.post\|@router\.put\|@router\.delete" --include="*.py"

# Django视图 - 数据修改操作
grep -rn "def post\|def put\|def delete\|def patch" --include="*.py"

# 数据访问操作 (带参数的GET)
grep -rn "@app\.route.*<.*>\|@router\.get.*{" --include="*.py"

# 批量操作
grep -rn "def export\|def download\|def batch\|def import" --include="*.py"

# 资金操作
grep -rn "transfer\|payment\|refund\|balance\|withdraw" --include="*.py"

# 外部HTTP请求
grep -rn "requests\.\|httpx\.\|urllib\.\|aiohttp\." --include="*.py"

# 文件操作
grep -rn "open(\|FileResponse\|send_file\|UploadFile" --include="*.py"

# 命令执行
grep -rn "os\.system\|subprocess\.\|os\.popen" --include="*.py"
```

### 1.2 输出模板

```markdown
## Python敏感操作清单

| # | 端点/函数 | HTTP方法 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|----------|----------|------|----------|
| 1 | /api/user/<id> | DELETE | 数据修改 | views.py:45 | 高 |
| 2 | /api/user/<id> | GET | 数据访问 | views.py:32 | 中 |
| 3 | /api/transfer | POST | 资金操作 | payment.py:56 | 严重 |
```

---

## A2. 安全控制建模

### 2.1 Python安全控制实现方式

| 控制类型 | Django | Flask | FastAPI |
|----------|--------|-------|---------|
| **认证控制** | `@login_required`, `IsAuthenticated` | `@login_required`, Flask-Login | `Depends(get_current_user)` |
| **授权控制** | `@permission_required`, DRF Permissions | `@roles_required`, Flask-Principal | `Security(scopes=[])` |
| **资源所有权** | `obj.owner == request.user` | 手动检查 | 手动检查 |
| **输入验证** | Django Forms, DRF Serializers | WTForms, Marshmallow | Pydantic Models |
| **并发控制** | `select_for_update()`, F()表达式 | SQLAlchemy with_for_update | SQLAlchemy锁 |
| **审计日志** | django-auditlog, signals | 自定义装饰器 | 中间件 |

### 2.2 控制矩阵模板 (Python)

```yaml
敏感操作: DELETE /api/user/<id>
位置: views.py:45
类型: 数据修改

应有控制:
  认证控制:
    要求: 必须登录
    Django: @login_required 或 IsAuthenticated
    Flask: @login_required
    FastAPI: Depends(get_current_user)

  授权控制:
    要求: 管理员或本人
    Django: @permission_required 或 has_perm()
    Flask: @roles_required('admin')

  资源所有权:
    要求: 非管理员只能删除自己的数据
    验证: obj.owner == request.user
```

---

## A3. 控制存在性验证

### 3.1 数据修改操作验证清单

```markdown
## 控制验证: [端点名称]

| 控制项 | 应有 | Django实现 | Flask实现 | 结果 |
|--------|------|------------|-----------|------|
| 认证控制 | 必须 | @login_required | @login_required | ✅/❌ |
| 授权控制 | 必须 | @permission_required | @roles_required | ✅/❌ |
| 资源所有权 | 必须 | obj.owner == request.user | 手动检查 | ✅/❌ |
| 输入验证 | 必须 | Serializer.is_valid() | form.validate() | ✅/❌ |

### 验证命令
```bash
# 检查装饰器
grep -B 5 "def delete\|def post\|def put" [视图文件] | grep "@login_required\|@permission_required"

# 检查资源所有权
grep -A 20 "def delete" [视图文件] | grep "owner\|user_id\|created_by"
```
```

### 3.2 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | Python检测方法 |
|----------|----------|-----|----------------|
| 无@login_required | 认证缺失 | CWE-306 | 检查视图函数装饰器 |
| 无权限检查 | 授权缺失 | CWE-862 | 检查permission装饰器 |
| 无owner比对 | IDOR | CWE-639 | 检查查询过滤条件 |
| 无select_for_update | 竞态条件 | CWE-362 | 检查资金操作事务 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞

## B1. Python Source

```python
# Flask
request.args.get('name')       # GET参数
request.form.get('name')       # POST表单
request.json                   # JSON body
request.headers.get('X-Header')
request.cookies.get('session')
request.files['file']

# Django
request.GET.get('name')
request.POST.get('name')
request.body
request.META.get('HTTP_X_HEADER')
```

## B2. Python Sink

| Sink类型 | 漏洞 | CWE | 危险函数 |
|----------|------|-----|----------|
| 命令执行 | 命令注入 | 78 | os.system, subprocess |
| 代码执行 | 代码注入 | 94 | eval, exec |
| SQL执行 | SQL注入 | 89 | cursor.execute, raw() |
| 文件操作 | 路径遍历 | 22 | open(), os.path.join |
| 反序列化 | RCE | 502 | pickle.load, yaml.load |
| 模板引擎 | SSTI | 97 | render_template_string |

## B3. Sink检测命令

## 核心危险面

Python因其动态特性和强大的内省能力，存在独特的安全挑战。关键攻击面包括：代码/命令注入、不安全反序列化、模板注入、格式化字符串漏洞。

---

## B4. Sink检测命令详细

### 命令注入检测

```python
# 高危函数清单
os.system(cmd)                    # 直接shell执行
os.popen(cmd)                     # 执行返回文件对象
os.spawn*(mode, path)             # 进程生成
subprocess.*(cmd, shell=True)     # shell=True时危险
subprocess.getoutput(cmd)         # 直接shell执行 (Python 3)
subprocess.getstatusoutput(cmd)   # 直接shell执行
commands.getoutput(cmd)           # Python 2
platform.popen(cmd)               # 间接执行向量
timeit.timeit(stmt)               # stmt可为代码字符串
pty.spawn(argv)                   # Linux 伪终端

# 危险示例
os.system('ping -n 4 %s' % ip)  # 拼接用户输入
s = subprocess.Popen('ping -n 4 ' + cmd, shell=True, stdout=subprocess.PIPE)

# subprocess 详解
# shell=False: 参数必须是列表，不经过 shell 解析
# shell=True:  调用 /bin/sh (Linux) 或 cmd.exe (Windows)，可命令注入

# 危险: shell=True
subprocess.Popen('ping -n 4 ' + cmd, shell=True)
subprocess.run('ping -n 4 ' + cmd, shell=True)
# payload: 127.0.0.1 && whoami

# 相对安全: shell=False (但仍需注意)
cmd = 'ping -n 4 %s' % shlex.quote(ip)
subprocess.run(cmd, shell=False)  # 字符串会报错，需列表
# 正确: subprocess.run(['ping', '-n', '4', ip], shell=False)

# shlex.quote() 注意事项
# shell=False 时，shlex.quote 会把参数当作单个字符串
# ping -n 4 '127.0.0.1&&whoami' → 当作单个参数
# 但如果命令本身拼接，仍有风险

# 安全替代 - 列表参数
subprocess.run(['ping', '-n', '4', ip], shell=False)
subprocess.Popen(['ping', '-n', '4', ip], shell=False, stdout=subprocess.PIPE)

# 安全替代 - 使用专用库
import ping3
ping3.ping(ip)  # 不依赖命令执行

import socket
socket.create_connection((ip, port), timeout=5)  # 端口探测

# 白名单验证
import hashlib
file_hash = request.GET.get('file_hash')
filename = File.objects.get(file_hash=file_hash).filename  # 通过 hash 查询
os.system('rm %s' % filename)  # 文件名来自数据库，但仍需注意
# 注意: 如果文件名是 "aaa;whoami;.jsp"，仍有风险!

# 审计正则
os\.system\s*\(|os\.popen\s*\(|subprocess\.(call|Popen|run|getoutput)\s*\(
shell\s*=\s*True|platform\.popen\s*\(|timeit\.timeit\s*\(|pty\.spawn\s*\(
```

---

## 代码注入检测

```python
# 高危函数
eval(expression)           # 执行表达式
exec(code)                 # 执行任意代码
compile(source, ...)       # 编译代码对象
__import__(name)           # 动态导入
execfile(filename)         # Python 2

# 利用技术
__import__('os').system('id')
__builtins__.__dict__['__import__']('os')  # 绕过import过滤
chr(111)+chr(115)  # 绕过引号 = 'os'
base64.b64decode('payload')  # 编码绕过
__import__("pbzznaqf".decode('rot_13'))  # ROT13绕过
imp.reload(os)  # 模块重载绕过
sys.modules['os'] = __import__('os')  # sys.modules恢复

# 魔术方法链
"".__class__.__bases__[0].__subclasses__()  # 类遍历
func.__globals__  # 暴露模块级变量

# 安全替代
ast.literal_eval()  # 只解析字面量
eval(expr, {"__builtins__": {}}, allowed)  # 受限命名空间
```

---

## 反序列化检测

```python
# Pickle - 最危险
pickle.loads(data) / pickle.load(file)
pickle.Unpickler(file).load()
# Pickle操作码: R(调用), i(实例化), o(构建), c(导入)
# __reduce__()/__reduce_ex__() 魔术方法自动触发

# Pickle 利用
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

e = Exploit()
payload = pickle.dumps(e)
# b'\x80\x03cnt\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'

# 反序列化触发
pickle.loads(payload)  # 执行 os.system('whoami')

# PyYAML - 高危
yaml.load(data)  # 危险! 默认不安全
# ≤5.1: !!python/object/apply 无限制执行
# >5.1: 需 Loader=yaml.Loader (仍不安全)
# yaml.FullLoader 仍有风险

# YAML payload
!!python/object/apply:os.system ['id']
!!python/object/new:os.system ['id']
!!python/object/apply:subprocess.check_output [['id']]

# 检测 payload
cp = "!!python/object/apply:subprocess.check_output [[ls]]"
yaml.load(cp)  # 执行命令

# jsonpickle - 使用 pickle 序列化
import jsonpickle

class Person:
    def __reduce__(self):
        return (__import__('os').system, ('whoami',))

admin = Person()
s = jsonpickle.encode(admin)
# '{"py/reduce": [{"py/function": "nt.system"}, {"py/tuple": ["whoami"]}]}'
jsonpickle.decode(s)  # 触发命令执行

# shelve - 基于 pickle
import shelve
file = shelve.open("test")
file['exp'] = Exploit()  # 存储时序列化
file.close()
# 读取时反序列化触发

# marshal - 序列化 code 对象
import marshal
import types

def malicious():
    import os
    os.system('whoami')

code_serialized = base64.b64encode(marshal.dumps(malicious.__code__))
code_unserialized = types.FunctionType(
    marshal.loads(base64.b64decode(code_serialized)),
    globals(),
    ''
)()  # 执行

# 安全替代
json.loads()  # 使用 JSON (只支持基本类型)
yaml.safe_load()  # 安全加载 (推荐)
yaml.load(data, Loader=yaml.SafeLoader)  # 显式指定 SafeLoader

# Pickle 安全加固 - 白名单
import io
import builtins

safe_builtins = {'range', 'complex', 'set', 'frozenset', 'slice'}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in safe_builtins:
            return getattr(builtins, name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))

def restricted_loads(s):
    return RestrictedUnpickler(io.BytesIO(s)).load()

# 审计正则
pickle\.(loads|load|Unpickler)\s*\(|yaml\.load\s*\((?!.*SafeLoader)
marshal\.(loads|load)\s*\(|shelve\.open\s*\(|jsonpickle\.decode\s*\(
```

---

## SSTI模板注入

### 各引擎特性对比

| 引擎    | 语法           | Python执行   | 风险         |
|---------|----------------|--------------|--------------|
| Jinja2  | {{ }}          | 受限         | 魔术方法链   |
| Mako    | ${} / <% %>    | 直接执行     | 无沙箱       |
| Tornado | ${} / {% %}    | %import支持  | 模块导入     |
| Django  | {{ }}          | 受限         | 标签注入     |

### Jinja2 检测与利用

```python
# 检测
{{7*7}} → 49
{{7*'7'}} → 7777777

# 利用payload
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 审计正则
render_template_string\s*\(|Template\s*\([^)]*\)\.render
```

### Mako - 直接执行Python

```python
# 语法: ${} 表达式, <% %> 代码块
<%import os; os.system('id')%>
${__import__('os').popen('id').read()}
<%! import subprocess %>${subprocess.check_output(['id'])}

# 审计正则
mako\.template\.Template\s*\(
```

### Tornado - 支持模块导入

```python
# 语法: ${} 表达式, {% %} 语句
{% import os %}${os.popen('id').read()}
${__import__('os').system('id')}

# 审计正则
tornado\.template\.Template\s*\(
```

### Django - 格式化字符串信息泄露

```python
# 危险: 格式化字符串 + format
template = "<p>user:{user}, name:%s</p>" % name  # name 可控
return HttpResponse(template.format(user=request.user))
# payload: name = "{user.password}" → 泄露密码

# 危险: 双重格式化导致信息泄露
name = request.GET.get('name')
template = "<p>user:{user}, name:%s</p>" % name
return HttpResponse(template.format(user=request.user))
# {user.password} → 读取用户密码
# {user.__init__.__globals__[__builtins__][eval]} → 获取 eval 函数

# Django 读取 SECRET_KEY 路径
{user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.user_permissions.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[auth].module.middleware.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[sessions].module.middleware.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[staticfiles].module.utils.settings.SECRET_KEY}

# format 限制
# 只支持点 (.) 和中括号 ([])，不支持括号调用
# 因此 RCE 受限，主要用于信息泄露

# 安全实现
from django.shortcuts import render
return render(request, 'template.html', {'name': name})  # 使用模板渲染

# 审计正则
\.format\s*\([^)]*request\.|['"]\s*%\s*[^'"]*\.format\s*\(
```

---

## 文件操作漏洞

```python
# 危险模式 - 文件读取
open(user_path)
file(user_path)              # Python 2
codecs.open(user_path)
io.open(user_path)
pathlib.Path(path).read_text()
pathlib.Path(path).read_bytes()
send_file(user_path)  # Flask
send_from_directory(directory, filename)  # Flask
FileResponse(open(file_path, 'rb'))  # Django

# 危险模式 - 文件删除
os.remove(user_path)
shutil.rmtree(user_path)

# 危险模式 - 文件上传
file = request.FILES.get('filename')
with open(file.name, 'wb') as f:  # 文件名未过滤
    f.write(file.read())

# 文件上传 - 缺少类型验证
file = request.files.get('filename')
upload_dir = os.path.join(os.path.dirname(__file__), 'uploadfile')
dir = os.path.join(upload_dir, file.filename)  # 未验证后缀
file.save(dir)

# Zip 解压路径遍历 (高危!)
with zipfile.ZipFile(zip_file, "r") as z:
    for fileinfo in z.infolist():
        filename = fileinfo.filename  # 可能是 ../../../etc/passwd
        outfile = os.path.join(UPLOAD_FOLDER, filename)  # 路径遍历!
        with open(outfile, 'wb') as f:
            f.write(z.read(filename))

# 构造恶意 zip
z_info = zipfile.ZipInfo(r"../__init__.py")  # 覆盖关键文件
z_file = zipfile.ZipFile("bad.zip", mode="w")
z_file.writestr(z_info, "malicious code")

# 路径遍历 payload
../../../etc/passwd
....//....//....//etc/passwd  # 绕过../过滤
..%2F..%2F..%2Fetc%2Fpasswd  # URL编码
%2e%2e%2f  # URL编码
%252e%252e%252f  # 双重编码
..\/..\/..\/etc/passwd  # 混合斜杠
local_file:///etc/passwd  # urllib绕过

# 安全实现 - 路径验证
def safe_file_access(base_dir, user_filename):
    base_dir = os.path.abspath(base_dir)
    file_path = os.path.abspath(os.path.join(base_dir, user_filename))
    if not file_path.startswith(base_dir):
        raise ValueError("Path traversal detected")
    return file_path

# 安全实现 - 文件上传 (Flask)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)  # 清理文件名
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# 安全实现 - 文件上传 (Django)
import uuid
def rename_file(filename):
    if '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS:
        ext = filename.rsplit('.', 1)[1]
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, filename)) + "." + ext
    return None

# Django FileField 验证
from django.core.validators import FileExtensionValidator
file = models.FileField(
    upload_to='documents/',
    validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc'])]
)

# 安全实现 - Zip 解压
with zipfile.ZipFile(zip_file, "r") as z:
    z.extractall(path=safe_dir)  # 使用 extractall (仍需验证路径)
    # 或手动验证每个文件路径
    for fileinfo in z.infolist():
        if '..' in fileinfo.filename or fileinfo.filename.startswith('/'):
            raise ValueError("Path traversal detected")

# 审计正则
open\s*\([^)]*request\.|send_file\s*\(|os\.remove\s*\(
codecs\.open\s*\(|pathlib\.Path\s*\(.*\)\.(read_text|read_bytes)
zipfile\.ZipFile\s*\(|\.infolist\s*\(|\.extractall\s*\(
request\.FILES|request\.files\s*\.|secure_filename
```

---

## SSRF检测

```python
# 危险函数
requests.get/post(user_url)  # 仅支持 http/https (默认)
urllib.request.urlopen(user_url)  # 支持 file:// 等协议
httpx.get(user_url)
aiohttp.ClientSession().get(url)

# pycurl - 功能强大但危险
curl = pycurl.Curl()
curl.setopt(curl.URL, user_url)  # 支持多协议
curl.setopt(curl.FOLLOWLOCATION, True)  # 自动跳转
curl.perform()

# requests 扩展协议支持
from requests_file import FileAdapter
s = requests.Session()
s.mount('file://', FileAdapter())  # 添加 file:// 支持后变危险
req = s.get(user_url)

# 协议风险
file://   → 本地文件读取
gopher:// → Redis/Memcached攻击
dict://   → 端口探测
ftp://    → 内网FTP访问
ldap://   → 目录服务访问

# IP绕过技巧
2130706433           # 十进制 = 127.0.0.1
0x7f000001           # 十六进制
0177.0.0.1           # 八进制 (注意: Python socket 不支持)
127.0.0.1.xip.io     # DNS重绑定
localhost            # 绕过 IP 黑名单
0.0.0.0              # 绕过检测
[::]                 # IPv6 loopback

# urllib 文件协议陷阱
# Windows: file://C:/Windows/win.ini  (错误: C 被当作 host)
# 正确:    file:///C:/Windows/win.ini (三个斜杠)
# Linux:   file:///etc/passwd

# 302 跳转绕过
# 外部URL → 302 → 内网IP (需检测每次跳转)

# 安全实现 1: 基础 IP 检测
import ipaddress
import socket

def is_internal_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)  # 只支持 IPv4
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except socket.gaierror:
        return True

def safe_request(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid scheme")
    if is_internal_ip(parsed.hostname):
        raise ValueError("Internal IP not allowed")
    return requests.get(url, allow_redirects=False)

# 安全实现 2: 302 跳转检测 (urllib)
class RedirectHandler(urllib.request.HTTPRedirectHandler):
    def check_url(self, url):
        hostname = urllib.parse.urlparse(url).hostname
        ip = socket.gethostbyname(hostname)
        try:
            if ipaddress.ip_address(ip).is_private:
                return True  # 私有IP
            return False  # 公有IP
        except:
            return True

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.check_url(newurl):
            return urllib.request.Request(newurl)
        else:
            raise ValueError("Internal IP in redirect")

opener = urllib.request.build_opener(RedirectHandler)
response = opener.open(url)

# 安全实现 3: Django 白名单 (谨防 CVE-2017-7233)
from django.utils.http import is_safe_url
set_url = settings.SAFE_URL
if is_safe_url(url, set_url):
    text = urllib.request.urlopen(url)
# 旧版本可利用: https:12345678 绕过 (scheme 为空但 netloc 也为空)

# IP 进制转换注意
# Python socket.getaddrinfo() 不支持非标准格式
# 0x7F.0.0.1, 0177.0.0.1 会报错 socket.gaierror
# 但浏览器解析可能支持 (django HttpResponseRedirect 跳转时)

# 审计正则
requests\.(get|post|put|delete)\s*\([^)]*request\.
urllib\.request\.urlopen\s*\([^)]*request\.
pycurl\.Curl\s*\(|curl\.setopt\s*\(.*URL
```

---

## XXE检测

### 默认不安全行为

| 库              | resolve_entities | 风险            |
|-----------------|------------------|-----------------|
| lxml            | True             | 默认解析实体    |
| xml.dom.minidom | True             | 需显式禁用      |
| xml.sax         | 依配置           | 需显式禁用      |
| defusedxml      | False            | 推荐使用        |

```python
# 危险用法
etree.parse(source)
etree.fromstring(xml_string)
minidom.parse(source)
xml.sax.parse(source, handler)

# 安全配置 - defusedxml (推荐)
from defusedxml.ElementTree import parse, fromstring

# 安全配置 - lxml
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False
)
root = etree.fromstring(xml_string, parser)

# 审计正则
etree\.(parse|fromstring|XML)\s*\(|(?<!defusedxml\.)ElementTree
```

---

## SQL注入检测

```python
# 危险模式
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute('SELECT username FROM auth_user WHERE id = %s;' %str(id))  # 字符串拼接

# Django ORM 拼接注入
User.objects.raw(f"SELECT * FROM users WHERE id = {id}")
User.objects.extra(where=[f"name = '{name}'"])
User.objects.extra(WHERE=['id='+str(id)])  # 错误: 拼接

# Django ORM 参数名可控注入 (高危!)
data = json.loads(request.body.decode())
Student.objects.filter(**data).first()  # data = {"passkey__contains":"a"}
# 利用 lookup 语法: passkey__contains, passkey__startswith 等

# Django 字典注入
dict = {'username':"admin' OR '1'='1", 'age':18}
User.objects.create(**dict)  # 字典键可控时危险

# Django 二次注入
filename = request.GET.get('url')
File.objects.create(filename=filename)  # 存入: ' or '1'='1
cur.execute("""select * from file where filename='%s'""" %(filename))  # 拼接导致注入

# SQLAlchemy 拼接
sql = "SELECT name, email from users WHERE id = %s" %str(id)
data = session.execute(sql).fetchone()

# 安全参数化
cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])  # SQLite
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # MySQL/PostgreSQL
cursor.executemany('insert into userinfo(user,pwd) values(%s,%s);', data)  # 批量插入

# Django ORM 安全
User.objects.filter(id=user_id)  # 使用标准 API
User.objects.get(id=str(id))  # 安全的 ORM
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])  # 参数化
User.objects.extra(WHERE=['id=%s'], params=[str(id)])  # 正确的 extra 用法

# SQLAlchemy 安全
user = User.query.filter(User.id == id).first()
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})

# 审计正则
execute\s*\([^)]*['"]\s*\+|execute\s*\(f['"']|execute\s*\([^)]*%s['"]\s*%
\.raw\s*\(f['"']|\.extra\s*\([^)]*where\s*=\s*\[|\.filter\s*\(\*\*
```

### ORM/Query Builder高级注入模式

```python
# ===== Django ORM 高危模式 =====

# 1. extra() 方法注入 (Critical)
# ❌ 危险: where子句字符串拼接
User.objects.extra(where=[f"status = '{status}'"])
User.objects.extra(where=["id=" + user_id])
User.objects.extra(select={'is_recent': f"created_at > '{date}'"})

# ✓ 安全: 使用参数化
User.objects.extra(where=["status = %s"], params=[status])
User.objects.extra(select={'is_recent': "created_at > %s"}, select_params=[date])

# 2. raw() 查询注入 (Critical)
# ❌ 危险: SQL拼接
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
User.objects.raw("SELECT * FROM users WHERE id = " + str(user_id))

# ✓ 安全: 参数化
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])

# 3. RawSQL 注入 (Critical)
from django.db.models import RawSQL
# ❌ 危险
User.objects.annotate(
    val=RawSQL(f"SELECT COUNT(*) FROM orders WHERE user_id = {user.id}", ())
)

# ✓ 安全
User.objects.annotate(
    val=RawSQL("SELECT COUNT(*) FROM orders WHERE user_id = %s", (user.id,))
)

# 4. 字段名注入 (High)
# ❌ 危险: 用户控制字段名
field_name = request.GET.get('sort_by')  # 用户输入: "id); DROP TABLE users; --"
User.objects.order_by(field_name)  # 危险!

# ❌ 危险: 动态lookup
lookup = request.GET.get('lookup')  # 用户输入可能包含 "__" 构造复杂查询
User.objects.filter(**{lookup: value})

# ✓ 安全: 白名单验证
ALLOWED_SORT_FIELDS = ['id', 'created_at', 'username']
if field_name in ALLOWED_SORT_FIELDS:
    User.objects.order_by(field_name)

# 5. Q对象注入 (Medium)
from django.db.models import Q
# ❌ 潜在危险: 动态构造Q对象
filter_dict = json.loads(request.body)  # {"name__contains": "admin"}
User.objects.filter(Q(**filter_dict))

# ✓ 安全: 验证键名
ALLOWED_LOOKUPS = {'name__exact', 'email__exact', 'id'}
safe_dict = {k: v for k, v in filter_dict.items() if k in ALLOWED_LOOKUPS}
User.objects.filter(Q(**safe_dict))

# 6. aggregate() / annotate() 注入
from django.db.models import Count, Sum
# ❌ 危险: 动态聚合字段
agg_field = request.GET.get('field')
User.objects.aggregate(Count(agg_field))  # 字段名可控

# ✓ 安全: 白名单
ALLOWED_AGG_FIELDS = ['orders', 'comments', 'likes']
if agg_field in ALLOWED_AGG_FIELDS:
    User.objects.aggregate(Count(agg_field))

# ===== SQLAlchemy 高危模式 =====

# 1. text() 拼接注入 (Critical)
from sqlalchemy import text
# ❌ 危险
query = text(f"SELECT * FROM users WHERE name = '{name}'")
session.execute(query)

# ❌ 危险: format拼接
query = text("SELECT * FROM users WHERE id = {}".format(user_id))
session.execute(query)

# ✓ 安全: 绑定参数
query = text("SELECT * FROM users WHERE name = :name")
session.execute(query, {"name": name})

# 2. filter() 字符串表达式注入 (High)
# ❌ 危险: 字符串WHERE子句
session.query(User).filter(f"name = '{name}'").all()

# ✓ 安全: 使用ORM表达式
session.query(User).filter(User.name == name).all()

# 3. order_by() 字符串注入 (High)
# ❌ 危险: 动态ORDER BY
sort_field = request.args.get('sort')
session.query(User).order_by(text(sort_field)).all()

# ✓ 安全: 白名单 + getattr
SORT_FIELDS = {'id': User.id, 'name': User.name}
if sort_field in SORT_FIELDS:
    session.query(User).order_by(SORT_FIELDS[sort_field]).all()

# 4. Column name injection (High)
# ❌ 危险: 动态列名
column_name = request.args.get('column')
session.query(getattr(User, column_name)).all()  # AttributeError可能,但仍危险

# ✓ 安全: 白名单映射
ALLOWED_COLUMNS = {'id': User.id, 'email': User.email}
if column_name in ALLOWED_COLUMNS:
    session.query(ALLOWED_COLUMNS[column_name]).all()

# 5. join() 字符串注入 (Medium)
# ❌ 危险
table_name = request.args.get('join_table')
session.query(User).join(table_name).all()

# ✓ 安全: 预定义join
session.query(User).join(User.profile).all()

# 6. from_statement() 注入 (Critical)
# ❌ 危险
sql = f"SELECT * FROM users WHERE created_at > '{date}'"
session.query(User).from_statement(text(sql)).all()

# ✓ 安全
sql = "SELECT * FROM users WHERE created_at > :date"
session.query(User).from_statement(text(sql)).params(date=date).all()

# ===== Peewee ORM =====
from peewee import *

# ❌ 危险: SQL拼接
query = User.raw(f"SELECT * FROM users WHERE name = '{name}'")

# ❌ 危险: 字段名注入
field = request.GET.get('field')
User.select().where(SQL(f"{field} = 'value'"))

# ✓ 安全
User.select().where(User.name == name)
User.raw("SELECT * FROM users WHERE name = ?", name)

# ===== Tortoise ORM (异步) =====
# ❌ 危险
await User.raw(f"SELECT * FROM users WHERE id = {user_id}")

# ✓ 安全
await User.filter(id=user_id)
await User.raw("SELECT * FROM users WHERE id = $1", [user_id])

# ===== Pony ORM =====
from pony.orm import *

# ❌ 危险: select拼接
select(u for u in User if f"u.name == '{name}'")  # eval()内部危险

# ✓ 安全
select(u for u in User if u.name == name)

# ===== 高级注入技术 =====

# 1. JSON字段注入 (PostgreSQL)
# ❌ 危险: JSON操作符注入
json_key = request.GET.get('key')  # 用户输入: "data'->>'password"
User.objects.filter(**{f"metadata__{json_key}": value})

# 2. 数组字段注入 (PostgreSQL)
from django.contrib.postgres.fields import ArrayField
# ❌ 危险
User.objects.filter(tags__contains=[user_input])  # 需验证user_input

# 3. 全文搜索注入 (PostgreSQL)
from django.contrib.postgres.search import SearchQuery
# ❌ 潜在危险: 搜索语法注入
SearchQuery(user_input, search_type='raw')  # 用户可注入特殊字符

# ✓ 安全: 使用plain类型
SearchQuery(user_input, search_type='plain')

# 4. 窗口函数注入
from django.db.models import Window, F
from django.db.models.functions import RowNumber
# 检查partition_by和order_by是否使用用户输入

# ===== 检测正则表达式 =====

# Django ORM危险模式
\.extra\s*\(\s*where\s*=\s*\[.*f["']|\.extra\s*\(.*\+
\.raw\s*\(\s*f["']|\.raw\s*\(.*\+|\.raw\s*\(.*%
RawSQL\s*\(\s*f["']|RawSQL\s*\(.*\+
\.order_by\s*\(.*request\.|\.filter\s*\(\*\*.*request\.

# SQLAlchemy危险模式
text\s*\(\s*f["']|text\s*\(.*\.format|text\s*\(.*\+
\.filter\s*\(\s*f["']|\.filter\s*\(.*\+
\.order_by\s*\(\s*text\(|\.from_statement\s*\(.*\+
getattr\s*\(\s*\w+\s*,\s*request\.|getattr\s*\(.*user_input

# 通用ORM注入
\.execute\s*\(\s*f["']|\.execute\s*\(.*%s["']\s*%
Column\s*\(.*request\.|Table\s*\(.*request\.
```

### ORM注入检测命令

```bash
# Django ORM高危检测
grep -rn "\.extra\s*(" --include="*.py" -A 3 | grep -E "where.*\+|where.*f['\"]|where.*%"
grep -rn "\.raw\s*(" --include="*.py" -A 2 | grep -E "f['\"]|%s['\"].*%|\+"
grep -rn "RawSQL\s*(" --include="*.py" -A 2 | grep -E "f['\"]|\+"
grep -rn "\.order_by\s*\(" --include="*.py" | grep -E "request\.|GET\.|POST\.|params"
grep -rn "\.filter\s*\(\*\*" --include="*.py" -A 1 | grep -E "request\.|json\.loads"

# SQLAlchemy高危检测
grep -rn "text\s*\(" --include="*.py" -A 2 | grep -E "f['\"]|\.format|\+|%s['\"].*%"
grep -rn "\.filter\s*\(" --include="*.py" -A 1 | grep -E "f['\"]|\+"
grep -rn "getattr\s*\(.*User" --include="*.py" | grep -E "request\.|args\.|form\."
grep -rn "from_statement" --include="*.py" -A 2 | grep -E "text.*\+|text.*f['\"]"

# 字段名/表名注入检测
grep -rn "order_by.*request\|order_by.*GET\|order_by.*args" --include="*.py"
grep -rn "annotate.*request\|aggregate.*request" --include="*.py"

# JSON/Array字段检测(PostgreSQL特有)
grep -rn "ArrayField\|JSONField\|HStoreField" --include="*.py" -A 5 | grep "request\."
```

### 安全修复检查清单

**Critical修复:**
- [ ] 所有`.raw()`和`text()`使用参数化查询
- [ ] 移除`.extra(where=[])`中的字符串拼接
- [ ] `RawSQL()`第一个参数不包含f-string或+拼接
- [ ] `.execute()`调用全部参数化

**High修复:**
- [ ] 动态字段名使用白名单验证
- [ ] ORDER BY子句字段名白名单
- [ ] `.filter(**dict)`的dict键名验证
- [ ] JSON/Array操作的用户输入验证

**Medium审查:**
- [ ] Q对象动态构造的lookup验证
- [ ] aggregate/annotate字段名验证
- [ ] 自定义Manager方法的SQL安全性
- [ ] 信号(signals)中的查询安全
```

---

## 格式化字符串漏洞

```python
# 用户控制模板时可泄露信息
template = "{name.__class__.__init__.__globals__}"
template.format(name=user_object)

# Flask读取配置
"{user.__class__.__init__.__globals__[config]}".format(user=obj)

# Django读取密码
"{user.password}".format(user=request.user)

# 安全替代
from string import Template
Template(user_template).safe_substitute(name=name)

# 验证模板
import re
if re.search(r'\{[^}]*[._\[\]]', template):
    raise ValueError("Complex format specifiers not allowed")

# 审计正则
\.format\s*\([^)]*request\.|\.format_map\s*\(
```

---

## XSS 跨站脚本

```python
# 危险: 直接输出用户输入
# Flask
name = request.args.get('name')
return Response("<p>name: %s</p>" % name)

# Django
name = request.GET.get('name')
return HttpResponse("<p>name: %s</p>" % name)

# 危险: render_template_string 拼接
template = "<p>%s</p>" % name
return render_template_string(template)  # 可能导致 XSS 和 SSTI

# 危险: mark_safe (Django)
from django.utils.safestring import mark_safe
return HttpResponse(mark_safe(f"<div>{user_input}</div>"))

# 危险: |safe 过滤器
{{ user_input|safe }}  # 模板中标记为安全

# 安全实现 - Flask
return render_template('xss.html', name=name)  # 自动转义

# 安全实现 - Django
return render(request, 'index.html', {'name': name})  # 自动转义

# 手动转义
import html
html.escape('<script>')  # '&lt;script&gt;'

from markupsafe import escape
escape('<script>alert(2)</script>')
# Markup('&lt;script&gt;alert(2)&lt;/script&gt;')

# 注意: Markup 对象不会再次转义
escape(Markup('<script>alert(2)</script>'))  # 仍是原始内容!

# 动态 URL 属性风险
<a href="{{ url }}">link</a>  # url 可能是 javascript:alert(1)
# 需验证 URL scheme

# 审计正则
Response\s*\([^)]*%|HttpResponse\s*\([^)]*%
render_template_string\s*\(|mark_safe\s*\(|\|safe\s*}}
```

---

## URL Bypass / Open Redirect

```python
# 危险: 未验证的重定向
# Flask
url = request.values.get('url')
return redirect(url)  # 任意 URL 跳转

# Django
from django.shortcuts import redirect
url = request.GET.get('url')
return redirect(url)

# 危险: 弱验证
if url.endswith('baidu.com'):
    return redirect(url)
# 绕过: evil.com?baidu.com, evil.com/baidu.com, evil.com#baidu.com

# 安全实现: 白名单
ALLOWED_DOMAINS = ['example.com', 'trust.com']

def is_safe_redirect(url):
    parsed = urlparse(url)
    return parsed.netloc in ALLOWED_DOMAINS

if is_safe_redirect(url):
    return redirect(url)

# Django is_safe_url (注意 CVE-2017-7233)
from django.utils.http import is_safe_url
if is_safe_url(url, allowed_hosts={'example.com'}):
    return redirect(url)
# 旧版本可利用: https:12345678 绕过

# 审计正则
redirect\s*\([^)]*request\.|HttpResponseRedirect\s*\(
```

---

## 弱随机数

```python
# 不安全 - 可预测 (基于 Mersenne Twister)
import random
random.random()
random.randint(a, b)
random.choice(seq)
random.seed(time.time())  # 可预测种子

# 危险场景
token = ''.join(random.choices(string.ascii_letters, k=32))  # 不安全!
session_id = random.randint(1000000, 9999999)  # 可预测
password_reset_code = random.randint(100000, 999999)  # 可暴力破解

# 安全替代 (使用 os.urandom)
import secrets
secrets.token_hex(32)        # 安全 token (十六进制)
secrets.token_urlsafe(32)    # URL 安全 token (base64)
secrets.randbelow(100)       # 安全随机整数 [0, 100)
secrets.choice(sequence)     # 安全随机选择

# 安全示例
reset_token = secrets.token_urlsafe(32)
session_id = secrets.token_hex(16)

# 审计正则
(token|secret|password|key|salt|session).*random\.(random|randint|choice|choices)
```

---

## Python审计清单

```
命令执行:
- [ ] 搜索 os.system|os.popen|subprocess.*shell=True
- [ ] 搜索 platform.popen|timeit.timeit|pty.spawn
- [ ] 检查 subprocess 参数是列表而非字符串
- [ ] 验证 shlex.quote() 使用是否正确

代码执行:
- [ ] 搜索 eval|exec|compile|__import__
- [ ] 检查 getattr/setattr 动态调用
- [ ] 搜索魔术方法链: __class__.__bases__

反序列化:
- [ ] 搜索 pickle.load|pickle.loads|pickle.Unpickler
- [ ] 搜索 yaml.load (验证 SafeLoader)
- [ ] 搜索 marshal.load|shelve.open
- [ ] 检查 jsonpickle.decode
- [ ] 验证 __reduce__ 魔术方法使用

模板注入:
- [ ] 搜索 render_template_string 拼接
- [ ] 搜索 Template().render 用户输入
- [ ] 检查 Mako/Tornado 模板使用
- [ ] 搜索 format() 双重格式化 (Django)

文件操作:
- [ ] 检查文件路径验证 (路径遍历)
- [ ] 搜索 send_file|send_from_directory|FileResponse
- [ ] 验证上传文件类型/大小限制
- [ ] 搜索 zipfile.ZipFile 解压操作
- [ ] 检查 secure_filename 使用 (Flask)
- [ ] 验证文件名是否重命名

SSRF:
- [ ] 搜索 requests.get|urllib.urlopen|pycurl 用户URL
- [ ] 检查内网IP过滤 (ipaddress.is_private)
- [ ] 验证协议限制 (http/https only)
- [ ] 检查 302 跳转处理
- [ ] 搜索 requests_file.FileAdapter (协议扩展)

XXE:
- [ ] 搜索 etree.parse|etree.fromstring
- [ ] 检查 XMLParser(resolve_entities=False)
- [ ] 推荐使用 defusedxml
- [ ] 搜索 xml.dom.minidom|xml.sax

SQL注入:
- [ ] 搜索 execute() 字符串拼接 (+, %, f"")
- [ ] 搜索 Django raw()/extra() 拼接
- [ ] 检查 filter(**dict) 参数名可控
- [ ] 验证参数化查询 (?, %s, :name)
- [ ] 检查二次注入场景

XSS:
- [ ] 搜索 Response/HttpResponse 拼接
- [ ] 搜索 mark_safe 使用
- [ ] 搜索模板 |safe 过滤器
- [ ] 检查 render_template_string 拼接

URL重定向:
- [ ] 搜索 redirect 用户输入
- [ ] 检查 URL 白名单验证
- [ ] 搜索 is_safe_url (Django CVE-2017-7233)

格式化字符串:
- [ ] 搜索 .format(.*request
- [ ] 检查 Django 双重格式化 (% + format)
- [ ] 验证模板来源

弱随机数:
- [ ] 搜索 random.* 用于 token/password/session
- [ ] 推荐使用 secrets 模块

配置安全:
- [ ] 检查 DEBUG = True (生产环境)
- [ ] 检查 SECRET_KEY 强度
- [ ] 检查 ALLOWED_HOSTS 配置
- [ ] 验证 CSRF 中间件启用
```

---

## 自动化工具

```bash
# Bandit - Python静态分析
bandit -r /path/to/project -f json
bandit -r /path/to/project --exclude tests/

# Semgrep - 多语言SAST
semgrep --config=p/python /path/to/project
semgrep --config=p/security-audit /path/to/project

# Safety - 依赖漏洞检查
safety check -r requirements.txt

# 快速grep扫描
grep -rn "os\.system\|subprocess.*shell=True" --include="*.py" .
grep -rn "eval\s*(\|exec\s*(" --include="*.py" .
grep -rn "pickle\.load\|yaml\.load" --include="*.py" .
grep -rn "render_template_string" --include="*.py" .
grep -rn "execute.*f['\"]SELECT" --include="*.py" .
```

---

## 最小 PoC 示例
```bash
# SSTI
curl "http://localhost:5000/hello?name={{7*7}}"

# Pickle 反序列化
python -c "import pickle,os; print(pickle.dumps(os.system))"

# YAML unsafe load
python - <<'PY'
import yaml
print(yaml.load("!!python/object/apply:os.system ['id']", Loader=yaml.UnsafeLoader))
PY
```

---

---

## 授权漏洞检测 (Authorization Gap) - v1.7.1

> **核心问题**: 授权漏洞是"代码缺失"，grep 无法检测"应该有但没有"的代码
> **解决方案**: 授权矩阵方法 - 从"应该是什么"出发，而非"存在什么"

### 方法论

```
❌ 旧思路 (被动检测 - 局限性大):
   搜索 @login_required 装饰器 → 检查是否存在
   问题: 存在装饰器不等于正确，可能配置错误或遗漏

✅ 新思路 (主动建模 - 系统性):
   1. 枚举所有敏感操作 (delete/update/export/download)
   2. 定义应有的权限 (谁可以操作什么)
   3. 对比实际代码，检测缺失或不一致
```

### Django 授权检测

```bash
# 步骤1: 找到所有视图的敏感操作
grep -rn "def\s\+\(delete\|update\|edit\|destroy\|export\|download\)" --include="views.py"
grep -rn "class.*\(Delete\|Update\|Destroy\)View" --include="views.py"

# 步骤2: 检查权限装饰器/Mixin存在性
for file in $(find . -name "views.py"); do
    echo "=== $file ==="
    # 检查敏感方法是否有权限检查
    grep -B 5 "def delete\|def update\|def destroy" "$file" | \
    grep -E "@permission_required|@login_required|PermissionRequiredMixin|LoginRequiredMixin"
done

# 步骤3: 对比同模块方法的权限一致性
echo "=== 权限一致性检查 ==="
grep -B 3 "def create" views.py | head -5
grep -B 3 "def delete" views.py | head -5
```

### 漏洞模式

```python
# ❌ 漏洞: delete方法缺失权限检查
class FileView(View):
    def get(self, request, file_id):
        # 有权限检查
        if not request.user.has_perm('file.view'):
            return HttpResponseForbidden()
        return serve_file(file_id)

    def delete(self, request, file_id):
        # 缺失权限检查! 任何用户都可删除
        File.objects.filter(id=file_id).delete()
        return JsonResponse({'success': True})

# ❌ 漏洞: 水平越权 - 未验证资源所有权
@login_required
def delete_document(request, doc_id):
    # 只检查登录，未验证是否是文档所有者
    Document.objects.filter(id=doc_id).delete()  # 可删除他人文档
    return redirect('documents')

# ✅ 安全: 验证资源所有权
@login_required
def delete_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    doc.delete()
    return redirect('documents')
```

### Flask 授权检测

```bash
# 找到所有路由的敏感操作
grep -rn "@.*\.route.*methods.*\['DELETE'\|'PUT'\|'POST'\]" --include="*.py"
grep -rn "def\s\+\(delete\|update\|remove\|export\)" --include="*.py"

# 检查 login_required 装饰器
grep -B 3 "def delete\|def update" --include="*.py" | grep -c "@login_required"
```

### 漏洞模式 (Flask)

```python
# ❌ 漏洞: 缺失认证检查
@app.route('/api/file/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    # 未检查登录状态
    File.query.filter_by(id=file_id).delete()
    return jsonify({'success': True})

# ❌ 漏洞: 有认证但无授权 (水平越权)
@app.route('/api/file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    # 只检查登录，未验证是否是文件所有者
    File.query.filter_by(id=file_id).delete()
    return jsonify({'success': True})

# ✅ 安全: 认证 + 授权
@app.route('/api/file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    file = File.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    db.session.delete(file)
    return jsonify({'success': True})
```

### Django REST Framework 授权检测

```bash
# 检查 ViewSet 的权限配置
grep -rn "class.*ViewSet" --include="*.py" -A 10 | grep -E "permission_classes|IsAuthenticated|IsAdminUser"

# 检查自定义动作的权限
grep -rn "@action.*detail=True" --include="*.py" -A 5 | grep "permission_classes"
```

### 漏洞模式 (DRF)

```python
# ❌ 漏洞: ViewSet 全局权限但自定义动作缺失
class FileViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]  # 全局要求登录

    @action(detail=True, methods=['post'])
    def share(self, request, pk=None):
        # 应该额外检查是否是文件所有者
        file = self.get_object()
        file.shared_with.add(request.data['user_id'])
        return Response({'status': 'shared'})

# ✅ 安全: 自定义动作有额外权限检查
class FileViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # 只返回用户自己的文件
        return File.objects.filter(owner=self.request.user)

    @action(detail=True, methods=['post'], permission_classes=[IsFileOwner])
    def share(self, request, pk=None):
        # ...
```

### 授权一致性检测脚本

```bash
#!/bin/bash
# check_auth_consistency_python.sh

echo "=== Python 授权一致性检测 ==="

# Django 项目
if [ -f "manage.py" ]; then
    echo "[Django 项目]"

    # 检查所有视图文件
    for views in $(find . -name "views.py" -type f); do
        echo ""
        echo "检查: $views"

        # 提取敏感方法
        grep -n "def\s\+\(delete\|update\|destroy\|remove\|export\)" "$views" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)
            method=$(echo "$line" | cut -d: -f2-)

            # 检查前5行是否有权限装饰器
            start=$((line_num - 5))
            [ $start -lt 1 ] && start=1

            auth_check=$(sed -n "${start},${line_num}p" "$views" | \
                grep -c "@permission_required\|@login_required\|PermissionRequiredMixin")

            if [ "$auth_check" -eq 0 ]; then
                echo "  ⚠️  第${line_num}行: $method - 缺少权限装饰器"
            else
                echo "  ✅ 第${line_num}行: $method - 有权限检查"
            fi
        done
    done
fi

# Flask 项目
if [ -f "app.py" ] || ls *.py 2>/dev/null | xargs grep -l "from flask import" >/dev/null 2>&1; then
    echo ""
    echo "[Flask 项目]"

    for pyfile in $(find . -name "*.py" -type f); do
        # 检查 DELETE/PUT 路由
        grep -n "methods=.*DELETE\|methods=.*PUT" "$pyfile" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)

            # 检查是否有 @login_required
            start=$((line_num - 3))
            [ $start -lt 1 ] && start=1

            auth_check=$(sed -n "${start},${line_num}p" "$pyfile" | grep -c "@login_required")

            if [ "$auth_check" -eq 0 ]; then
                echo "  ⚠️  $pyfile:$line_num - DELETE/PUT 路由缺少 @login_required"
            fi
        done
    done
fi
```

### 间接SSRF检测 (配置驱动)

```python
# ❌ 漏洞: 配置驱动的间接SSRF
# settings.py
API_BASE_URL = os.environ.get('API_URL', 'http://internal-api')

# views.py
def fetch_data(endpoint):
    url = settings.API_BASE_URL + endpoint  # 间接SSRF
    return requests.get(url).json()

# 检测命令
grep -rn "settings\.\w*URL\|settings\.\w*HOST\|config\.\w*url" --include="*.py"
grep -rn "os\.environ.*url\|os\.environ.*host" --include="*.py"
grep -rn "f['\"].*{.*}.*http\|\.format.*http" --include="*.py"
```

### 审计清单 (授权专项)

```
授权矩阵建模:
- [ ] 列出所有敏感操作 (CRUD + export/download)
- [ ] 定义每个操作的预期权限
- [ ] 检查实际装饰器/Mixin是否匹配预期

Django 专项:
- [ ] 检查 View 类的 permission_required
- [ ] 检查 ViewSet 的 permission_classes
- [ ] 验证 get_queryset() 是否过滤用户数据
- [ ] 检查 @action 自定义动作的权限

Flask 专项:
- [ ] 检查 DELETE/PUT 路由的 @login_required
- [ ] 验证资源所有权检查 (current_user.id)
- [ ] 检查 API Blueprint 的权限配置

水平越权防护:
- [ ] 验证所有资源操作都检查 owner/user_id
- [ ] 检查 get_object_or_404 是否包含用户过滤
- [ ] 验证批量操作的权限检查

间接注入:
- [ ] 检查 settings/config 中的 URL 配置
- [ ] 追踪环境变量中的可控值
- [ ] 验证格式化字符串构造的URL
```

---

## CSRF 安全 (CWE-352)

### 危险模式

```python
# 🔴 Django - 禁用 CSRF
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # 🔴 状态变更接口禁用 CSRF
def transfer(request):
    if request.method == 'POST':
        # 转账操作
        pass

# 🔴 Flask - 无 CSRF 保护
@app.route('/api/transfer', methods=['POST'])
def transfer():
    # 状态变更操作无 CSRF 保护
    pass

# 🔴 FastAPI - 仅依赖 CORS (不够)
@app.post("/api/transfer")
async def transfer(request: TransferRequest):
    # CORS 不能防止所有 CSRF 攻击
    pass
```

### 安全配置

```python
# Django - 确保中间件启用
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',  # 必须
    # ...
]

# 模板中使用
<form method="post">
    {% csrf_token %}
    ...
</form>

# AJAX 请求
function getCookie(name) {
    // 从 cookie 获取 csrftoken
}
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'X-CSRFToken': getCookie('csrftoken'),
    },
    body: JSON.stringify(data)
});

# Flask - 使用 Flask-WTF
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
csrf.init_app(app)

# 模板
<form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    ...
</form>

# FastAPI - 使用 starlette-csrf 或自定义
from starlette_csrf import CSRFMiddleware

app.add_middleware(
    CSRFMiddleware,
    secret="your-secret-key",
    sensitive_cookies={"session"},
)
```

### 检测命令

```bash
# 查找禁用 CSRF
rg -n "@csrf_exempt|csrf_protect.*False|WTF_CSRF_ENABLED.*False" --glob "*.py"

# 查找 POST 路由
rg -n "@app\.(post|put|delete|patch)\(|methods=.*POST" --glob "*.py"

# Django 检查中间件
rg -n "CsrfViewMiddleware" --glob "settings.py"
```

---

## 硬编码凭据 (CWE-798)

### 危险模式

```python
# 🔴 硬编码密钥
SECRET_KEY = 'my-secret-key-12345'  # 🔴

# 🔴 数据库密码
DATABASES = {
    'default': {
        'PASSWORD': 'admin123',  # 🔴
    }
}

# 🔴 API 密钥
class PaymentService:
    API_KEY = 'sk_live_xxxxxxxxxxxx'  # 🔴

    def charge(self, amount):
        requests.post(url, headers={'Authorization': f'Bearer {self.API_KEY}'})

# 🔴 AWS 凭据
import boto3
client = boto3.client(
    's3',
    aws_access_key_id='AKIA...',  # 🔴
    aws_secret_access_key='xxx',  # 🔴
)
```

### 安全配置

```python
import os
from dotenv import load_dotenv

load_dotenv()

# 从环境变量读取
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError('SECRET_KEY environment variable not set')

# Django settings.py
DATABASES = {
    'default': {
        'PASSWORD': os.environ.get('DATABASE_PASSWORD'),
    }
}

# 使用 python-decouple
from decouple import config

SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
DATABASE_URL = config('DATABASE_URL')

# AWS - 使用 IAM 角色或环境变量
import boto3
# 自动使用 AWS_ACCESS_KEY_ID 和 AWS_SECRET_ACCESS_KEY 环境变量
# 或 IAM 角色
client = boto3.client('s3')

# 使用 secrets manager
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return response['SecretString']
```

### 检测命令

```bash
# 查找硬编码密钥
rg -n "SECRET_KEY\s*=\s*['\"]|PASSWORD\s*[:=]\s*['\"]|api_key\s*=\s*['\"]" --glob "*.py" | grep -v "os\.environ\|getenv\|config\("

# 查找 AWS 凭据
rg -n "aws_access_key_id\s*=|aws_secret_access_key\s*=" --glob "*.py" | grep -v "os\.environ"

# 查找常见密钥模式
rg -n "AKIA[0-9A-Z]{16}|sk_live_|sk_test_" --glob "*.py"
```

---

## 文件上传安全 (CWE-434)

### 危险模式

```python
# 🔴 Django - 无验证
def upload(request):
    file = request.FILES['file']
    with open(f'/uploads/{file.name}', 'wb') as f:  # 🔴 路径遍历
        for chunk in file.chunks():
            f.write(chunk)

# 🔴 Flask - 无验证
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')  # 🔴 任意文件名
```

### 安全配置

```python
# Django
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
import magic

ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif']
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_file(file):
    # 1. 大小检查
    if file.size > MAX_FILE_SIZE:
        raise ValidationError('File too large')

    # 2. 扩展名检查
    ext = file.name.split('.')[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError('Invalid extension')

    # 3. 内容类型检查 (python-magic)
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    if mime not in ['image/jpeg', 'image/png', 'image/gif']:
        raise ValidationError('Invalid file type')

    return True

# Flask
from werkzeug.utils import secure_filename
import magic
import uuid

UPLOAD_FOLDER = '/uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']

    # 1. 文件名检查
    if not allowed_file(file.filename):
        return 'Invalid extension', 400

    # 2. 大小检查
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        return 'File too large', 400

    # 3. 内容类型检查
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    if mime not in ['image/jpeg', 'image/png', 'image/gif']:
        return 'Invalid file type', 400

    # 4. 安全文件名
    ext = file.filename.rsplit('.', 1)[1].lower()
    safe_name = f"{uuid.uuid4()}.{ext}"

    # 5. 保存
    file.save(os.path.join(UPLOAD_FOLDER, safe_name))
    return 'Uploaded', 200
```

---

## 竞态条件 (CWE-362)

### 危险模式

```python
# 1. Check-Then-Act (TOCTOU) - 文件操作
import os

# 危险: 检查与操作之间存在竞态窗口
def vulnerable_file_write(filename, data):
    if not os.path.exists(filename):  # 检查
        # 竞态窗口: 攻击者可以在此创建符号链接
        with open(filename, 'w') as f:   # 操作
            f.write(data)

# 安全: 使用原子操作
import tempfile
import shutil

def safe_file_write(filename, data):
    # 写入临时文件，然后原子重命名
    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(filename))
    try:
        os.write(fd, data.encode())
        os.close(fd)
        os.rename(tmp_path, filename)  # 原子操作
    except:
        os.unlink(tmp_path)
        raise

# 安全: 使用 os.O_EXCL 标志
def safe_exclusive_write(filename, data):
    try:
        fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, data.encode())
        os.close(fd)
    except FileExistsError:
        raise ValueError("File already exists")


# 2. 共享状态竞态 (多线程)
# 危险: 共享计数器
class VulnerableCounter:
    def __init__(self):
        self.count = 0

    def increment(self):
        # 非原子操作: read-modify-write
        self.count += 1  # 等同于 temp = self.count; self.count = temp + 1

# 安全: 使用锁
import threading

class SafeCounter:
    def __init__(self):
        self.count = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self.count += 1


# 3. Django ORM 竞态
# 危险: 应用层检查
def vulnerable_create_user(username):
    if not User.objects.filter(username=username).exists():
        # 竞态窗口
        User.objects.create(username=username)

# 安全: get_or_create (数据库层原子操作)
def safe_create_user(username):
    user, created = User.objects.get_or_create(
        username=username,
        defaults={'email': f'{username}@example.com'}
    )
    return user, created

# 安全: select_for_update (悲观锁)
from django.db import transaction

@transaction.atomic
def safe_transfer(from_id, to_id, amount):
    # SELECT ... FOR UPDATE
    accounts = Account.objects.select_for_update().filter(
        id__in=[from_id, to_id]
    )
    from_acc = accounts.get(id=from_id)
    to_acc = accounts.get(id=to_id)

    from_acc.balance -= amount
    to_acc.balance += amount
    from_acc.save()
    to_acc.save()

# 安全: F() 表达式 (数据库原子更新)
from django.db.models import F

def atomic_increment(product_id):
    Product.objects.filter(id=product_id).update(
        view_count=F('view_count') + 1
    )


# 4. Flask 全局状态竞态
from flask import Flask, g

app = Flask(__name__)

# 危险: 模块级可变状态
request_count = 0  # 多worker共享会出问题

@app.route('/count')
def count():
    global request_count
    request_count += 1  # 非原子，且进程间不共享
    return str(request_count)

# 安全: 使用 Redis 或数据库
import redis
r = redis.Redis()

@app.route('/count')
def safe_count():
    return str(r.incr('request_count'))  # 原子操作


# 5. asyncio 竞态
import asyncio

# 危险: 异步check-then-act
cache = {}

async def vulnerable_cache_get(key, compute_fn):
    if key not in cache:
        # 竞态窗口: 多个协程同时执行compute_fn
        cache[key] = await compute_fn()
    return cache[key]

# 安全: 使用锁
cache_locks = {}
cache_lock = asyncio.Lock()

async def safe_cache_get(key, compute_fn):
    async with cache_lock:
        if key not in cache_locks:
            cache_locks[key] = asyncio.Lock()

    async with cache_locks[key]:
        if key not in cache:
            cache[key] = await compute_fn()
        return cache[key]
```

### 检测命令

```bash
# 查找 check-then-act 模式
grep -rn "if.*exists.*:\|if.*is None.*:" --include="*.py" -A 2

# 查找全局可变状态
grep -rn "^[a-z_].*= \[\]$\|^[a-z_].*= \{\}$\|^[a-z_].*= 0$" --include="*.py"

# 查找非原子递增
grep -rn "+= 1\|-= 1" --include="*.py"

# 查找文件存在检查
grep -rn "os\.path\.exists\|os\.path\.isfile" --include="*.py"
```

---

## 参考资料

- [Ascotbe - Python代码审计](https://www.ascotbe.com/2022/09/22/Python/)
- [FreeBuf - Python代码审计汇总](https://www.freebuf.com/articles/web/404899.html)
- [HackTricks - Jinja2 SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
- [PayloadsAllTheThings - Python]([upstream-repo])

---

**版本**: 2.1
**更新日期**: 2026-02-04
**覆盖漏洞类型**: 22+ (含CWE-362竞态条件)
