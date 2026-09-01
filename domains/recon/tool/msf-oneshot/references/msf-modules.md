# Metasploit 常用模块速查表

按场景分类的高价值 MSF 模块，覆盖比赛中最常遇到的目标。

## Windows 远程利用

| 模块路径 | CVE/名称 | 目标 | 必须参数 |
|----------|---------|------|---------|
| `exploit/windows/smb/ms17_010_eternalblue` | MS17-010 | Win7/2008R2/2012 SMB 445 | RHOSTS, LHOST |
| `exploit/windows/smb/ms17_010_psexec` | MS17-010 变种 | Win7/2008 (更稳定) | RHOSTS, LHOST, SMBUser/Pass |
| `exploit/windows/smb/ms08_067_netapi` | MS08-067 | WinXP/2003 | RHOSTS, LHOST |
| `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` | BlueKeep | Win7/2008R2 RDP 3389 | RHOSTS, LHOST, TARGET |
| `exploit/windows/dcerpc/cve_2021_1675_printnightmare` | PrintNightmare | Win10/2016/2019 | RHOSTS, LHOST |
| `exploit/windows/smb/psexec` | PsExec | 任何 Windows (需凭据) | RHOSTS, SMBUser, SMBPass |
| `exploit/windows/winrm/winrm_script_exec` | WinRM | Win2012+ (需凭据) | RHOSTS, USERNAME, PASSWORD |

## Linux 远程利用

| 模块路径 | CVE/名称 | 目标 | 必须参数 |
|----------|---------|------|---------|
| `exploit/linux/samba/is_known_pipename` | CVE-2017-7494 | Samba 3.5.0-4.6.4 | RHOSTS, LHOST |
| `exploit/unix/ftp/vsftpd_234_backdoor` | vsftpd 2.3.4 | FTP 后门 | RHOSTS |
| `exploit/linux/http/apache_mod_cgi_bash_env_exec` | ShellShock | CGI + Bash | RHOSTS, TARGETURI |
| `exploit/linux/redis/redis_replication_cmd_exec` | Redis RCE | Redis 未授权 | RHOSTS, LHOST |
| `exploit/multi/misc/java_rmi_server` | Java RMI | 1099 端口 | RHOSTS, LHOST |

## 数据库利用

| 模块路径 | 目标 | 前提条件 |
|----------|------|---------|
| `exploit/multi/postgres/postgres_copy_from_program_cmd_exec` | PostgreSQL 9.3+ | 需要凭据 |
| `exploit/windows/mssql/mssql_payload` | MSSQL | 需要 sa 凭据 |
| `exploit/multi/mysql/mysql_udf_payload` | MySQL | 需要 root 凭据 |
| `auxiliary/admin/mssql/mssql_exec` | MSSQL xp_cmdshell | 需要 sa 凭据 |
| `auxiliary/scanner/oracle/oracle_login` | Oracle | 口令爆破 |

## Web/中间件

| 模块路径 | 目标 | 前提条件 |
|----------|------|---------|
| `exploit/multi/http/tomcat_mgr_upload` | Tomcat Manager | 需要凭据 |
| `exploit/multi/http/tomcat_jsp_upload_bypass` | Tomcat PUT | PUT 方法开启 |
| `exploit/multi/http/jboss_invoke_deploy` | JBoss | JMX Console 未授权 |
| `exploit/multi/http/jenkins_script_console` | Jenkins | Script Console 访问 |
| `exploit/unix/webapp/wp_admin_shell_upload` | WordPress | 需要管理员凭据 |
| `exploit/multi/http/apache_normalize_path_rce` | Apache 2.4.49/50 | mod_cgi 启用 |

## 扫描/检测（Auxiliary）

| 模块路径 | 用途 |
|----------|------|
| `auxiliary/scanner/smb/smb_ms17_010` | MS17-010 检测 |
| `auxiliary/scanner/smb/smb_version` | SMB 版本识别 |
| `auxiliary/scanner/ssh/ssh_login` | SSH 口令爆破 |
| `auxiliary/scanner/ftp/ftp_login` | FTP 口令爆破 |
| `auxiliary/scanner/http/tomcat_mgr_default_creds` | Tomcat 默认口令 |
| `auxiliary/scanner/mssql/mssql_login` | MSSQL 口令爆破 |
| `auxiliary/scanner/mysql/mysql_login` | MySQL 口令爆破 |
| `auxiliary/scanner/postgres/postgres_login` | PostgreSQL 口令爆破 |

## Payload 速查（msfvenom）

| 用途 | Payload | 格式 |
|------|---------|------|
| Windows 反弹 shell (staged) | `windows/x64/meterpreter/reverse_tcp` | exe |
| Windows 反弹 shell (stageless) | `windows/x64/meterpreter_reverse_tcp` | exe |
| Windows 命令执行 | `windows/x64/exec` + CMD= | exe |
| Linux 反弹 shell | `linux/x64/meterpreter/reverse_tcp` | elf |
| Linux 命令执行 | `linux/x64/exec` + CMD= | elf |
| PHP 反弹 shell | `php/meterpreter/reverse_tcp` | raw |
| JSP WAR 部署 | `java/jsp_shell_reverse_tcp` | war |
| Python | `python/meterpreter/reverse_tcp` | raw |

### Staged vs Stageless

- **Staged** (`meterpreter/reverse_tcp`)：分两阶段，体积小但需要 handler
- **Stageless** (`meterpreter_reverse_tcp`)：一次性，体积大但独立运行
- 比赛中推荐 **staged**（更稳定）

## 常见问题排查

| 症状 | 原因 | 解决 |
|------|------|------|
| Exploit completed, but no session | Payload 被杀/端口被占 | 换端口、换 payload、检查防火墙 |
| Connection refused | 目标端口未开放 | 先 nmap 确认端口开放 |
| msfconsole 启动超时 | 数据库连接慢 | 加 `--no-database` 或等待 |
| Payload 无法回连 | LHOST 错误/防火墙 | 确认 LHOST 是目标可达的 IP |
