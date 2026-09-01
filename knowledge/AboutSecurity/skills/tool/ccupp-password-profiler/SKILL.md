---
name: ccupp-password-profiler
description: "使用 ccupp 基于社工信息生成弱口令字典。ccupp 是中文场景下最完整的密码画像工具——输入目标的姓名、生日、电话、身份证等信息，自动生成拼音变体、日期变体、文化数字（520/1314/888）组合的密码字典。当需要对目标人员做定向弱口令爆破、社工密码猜测、或者通用弱口令字典不够用需要定制化字典时使用此技能"
metadata:
  tags: "ccupp,password,弱口令,社工,字典,密码生成,profiler,拼音,bruteforce,wordlist"
  category: "tool"
---

# ccupp 社工密码字典生成

ccupp（Chinese Common User Passwords Profiler）根据目标的个人信息智能生成密码字典——比通用字典更精准，因为大多数人的密码都包含自己的姓名、生日、电话等信息。

项目地址：https://github.com/WangYihang/ccupp

## 安装

```bash
# 方式 1: f8x 自动安装（推荐）
f8x -install ccupp

# 方式 2: 手动安装（ccupp 未发布到 PyPI，需 clone 后本地安装）
git clone https://github.com/WangYihang/ccupp.git
cd ccupp
pipx install .
```

## 快速开始

```bash
# 生成示例配置文件
ccupp init

# 交互式输入目标信息
ccupp interactive

# 从配置文件生成密码
ccupp generate -o passwords.txt
```

## 配置文件格式

创建 `config.yaml`，填入目标社工信息：

```yaml
- surname: 张
  first_name: 三
  phone_numbers:
    - '13800138000'
  identity: '110101199001011234'
  birthdate:
    - '1990'
    - '01'
    - '01'
  hometowns:
    - 北京
    - 海淀
  workplaces:
    - - 阿里巴巴
      - alibaba
  educational_institutions:
    - - 北京大学
      - pku
  accounts:
    - zhangsan
  passwords:
    - old_pass123
```

每个字段都会参与密码组合——信息越多，字典覆盖越精准。

## 生成策略与优先级

ccupp 按可能性从高到低排序输出，排在前面的密码命中率更高：

1. **旧密码变体** — 大小写/leetspeak/后缀变换（人倾向于在旧密码基础上微调）
2. **姓名+生日** — 中国用户最常见的弱口令模式（`zhangsan1990`）
3. **姓名+电话尾号** — 如 `zs8000`、`zhangsan138`
4. **双组件组合** — 任意两类信息交叉
5. **文化数字** — 组件 + 520/1314/888/666（中国特色）
6. **键盘模式** — qwerty/1qaz2wsx + 组件

## 常用参数

```bash
# 过滤密码长度（配合目标密码策略）
ccupp generate --min-length 8 --max-length 16

# 禁用某些策略（缩小字典体积）
ccupp generate --no-leetspeak --no-cultural --no-keyboard

# JSON 格式输出（便于程序处理）
ccupp generate -f json -o passwords.json

# 查看统计信息
ccupp generate --stats
```

## 实战工作流

```
收集目标信息（姓名/生日/电话/公司）
  │
  ├─ ccupp generate → 定制字典 passwords.txt
  │
  └─ 用字典爆破
     ├─ zombie -i target -s ssh -u zhangsan -P passwords.txt
     ├─ zombie -i target -s rdp -u zhangsan -P passwords.txt
     └─ hydra -l zhangsan -P passwords.txt target ssh
```

## 决策树

```
需要密码字典？
├─ 有目标个人信息 → ccupp generate（定制字典，精准命中）
├─ 无个人信息，通用场景 → SecLists/rockyou.txt
├─ 企业批量弱口令 → 公司名+年份+特殊字符（手工或脚本）
└─ 已有旧密码 → ccupp 旧密码变体策略（填入 passwords 字段）
```
