### CVE-2026-64560 LPE exploit for blazer-260705

> Warning
>
> This repository contains an experimental kernel exploit proof of concept. It may modify system files, affect device stability, cause crashes, corrupt data, or permanently damage the target system. Run it only on devices that you own or are explicitly authorized to test. Back up important data before running it. Use at your own risk.

This is a use-after-free caused by a race between POSIX process CPU timer deletion and a non-leader `exec()`. The vulnerable kernel can free an armed `struct k_itimer` while its embedded CPU timer node is still linked in the process timerqueue. Later timerqueue operations access the freed object.

The issue is assigned `CVE-2026-64560` and was fixed upstream:  
https://git.kernel.org/tip/920f893f735e92ba3a1cd9256899a186b161928d

Tested Android/Pixel build:

```text
Device: Pixel 10 Pro / blazer
Build fingerprint: google/blazer/blazer:17/CP2A.260705.006/15641320:user/release-keys
Kernel: Linux localhost 6.6.118-android15-8-g53e6e091166e-ab15266607-4k
Build date: Thu Apr 23 01:33:59 UTC 2026
```

Run the attached binary directly to disable SELinux and get a root shell.  

Success rate: >50% 
