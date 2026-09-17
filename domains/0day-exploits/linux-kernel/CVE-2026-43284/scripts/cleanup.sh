#!/usr/bin/env bash
set -euo pipefail

# Dirty Frag Kubernetes PoC — cleanup
#
# Removes the PoC Deployment, clears page cache, removes marker, and
# restarts kube-proxy to restore clean binary state.

NODE="${1:?Usage: $0 <user@node-ip>}"
KUBECTL="ssh ${NODE} sudo /root/bin/kubectl"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$SCRIPT_DIR/../deploy/poc-eks.yaml"

echo "[*] Deleting PoC Deployment ..."
cat "$MANIFEST" | ssh "$NODE" "sudo /root/bin/kubectl delete -f - --ignore-not-found" || true

echo "[*] Removing escape marker ..."
ssh "$NODE" "sudo rm -f /root/res"

echo "[*] Dropping page cache (clears corrupted pages) ..."
ssh "$NODE" "sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'"

echo "[*] Restarting kube-proxy pod to reload clean binaries ..."
NODE_NAME=$(ssh "$NODE" "hostname")
$KUBECTL delete pod -n kube-system -l k8s-app=kube-proxy --force 2>/dev/null || true

echo "[*] Cleaning up build artifacts on node ..."
ssh "$NODE" "sudo rm -rf /tmp/dirtyfrag-poc"
ssh "$NODE" "sudo nerdctl -n k8s.io rmi dirtyfrag-poc:eks 2>/dev/null" || true

echo "[+] Cleanup complete."
