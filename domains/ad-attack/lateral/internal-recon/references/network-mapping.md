# 内网扫描与基础设施定位

## 存活主机发现

### 快速存活探测（fscan 优先）
```bash
# fscan（推荐首选，一条命令完成存活+端口+服务+弱口令）
fscan -h 10.0.0.0/24                  # 全量扫描
fscan -h 10.0.0.0/24 -nopoc          # 只做存活+端口（更快）
fscan -h 10.0.0.0/24 -np -nopoc      # 不 ping 直接扫端口（ICMP 被禁时用）

# nmap 降级方案（fscan 不可用时）
nmap -sn 10.0.0.0/24                  # ICMP ping
nmap -PR -sn 10.0.0.0/24             # ARP 扫描（同网段最可靠）
```

### 常见内网网段
```
10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24
172.16.0.0/24, 172.16.1.0/24
192.168.1.0/24, 192.168.2.0/24
```

## 端口→服务→价值映射

| 端口 | 服务 | 攻击价值 |
|------|------|----------|
| 88 | Kerberos | **域控**（最高价值） |
| 389/636 | LDAP/LDAPS | **域控** |
| 445 | SMB | 文件共享、横向移动入口 |
| 135 | RPC | Windows 主机、WMI |
| 3389 | RDP | 远程桌面 |
| 5985/5986 | WinRM | 远程管理 |
| 1433 | MSSQL | 数据库（可能有 xp_cmdshell） |
| 3306 | MySQL | 数据库 |
| 5432 | PostgreSQL | 数据库 |
| 6379 | Redis | 无认证→RCE |
| 9200 | Elasticsearch | 无认证→数据泄露 |
| 22 | SSH | Linux 远程访问 |
| 80/443/8080 | HTTP | Web 应用 |
| 27017 | MongoDB | 无认证→数据泄露 |

## 关键基础设施定位

### 域控识别
- 开放 88+389+445 = 几乎确定是域控
- DNS 服务器 IP 通常就是域控
- `nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN`

### 数据库服务器
- 1433(MSSQL) / 3306(MySQL) / 5432(PostgreSQL) / 1521(Oracle)
- 用收集到的凭据尝试连接

### 管理系统
- 指纹识别 Web 服务（`httpx -tech-detect` / `curl -sI`）→ 发现 Jenkins/GitLab/Zabbix
- 通常有弱密码或已知漏洞
