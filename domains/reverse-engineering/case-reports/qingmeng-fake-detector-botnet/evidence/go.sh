#!/usr/bin/env bash
set -e

# 脚本名：build_tool.sh
# 功能：
#  1. 检测并安装 Go（自动选择 amd64 或 arm64 版本）
#  2. 检测并安装 UPX
#  3. 初始化 Go Modules 并拉取依赖
#  4. 提供静态编译 arm64 和 amd64 可执行文件，并使用 UPX 压缩

#-----------------------------
# 配置
#-----------------------------
GO_VERSION="1.22.3"
MODULE_NAME="bptoolkit"
SRC_FILE="bp.go"             # 你的 Go 程序源文件
TMP_DIR="/tmp/go_install"    # 临时下载目录

#-----------------------------
# 安装 Go 与 UPX
#-----------------------------
toolchain_install() {
    # 创建临时目录
    mkdir -p "$TMP_DIR"
    arch=$(uname -m)
    case "$arch" in
        x86_64)   GO_ARCH="amd64" ;;
        aarch64)  GO_ARCH="arm64" ;;
        *) echo "Unsupported arch: $arch"; exit 1 ;;
    esac

    # 安装 Go
    if ! command -v go &> /dev/null; then
        echo "⏬ 下载 Go ${GO_VERSION} for linux-${GO_ARCH}..."
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O "$TMP_DIR/go.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "$TMP_DIR/go.tar.gz"
        rm -rf "$TMP_DIR/go.tar.gz"
        echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        echo "✅ Go 安装完成 ($(go version))"
    else
        echo "✅ Go 已安装：$(go version)"
    fi

    # 安装 UPX
    if ! command -v upx &> /dev/null; then
        echo "⏬ 安装 UPX..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update -y
            sudo apt-get install -y upx
        elif command -v yum &> /dev/null; then
            sudo yum install -y upx
        else
            echo "⚠️ 未检测到 apt-get 或 yum，请手动安装 upx"
        fi
        echo "✅ UPX 安装完成"
    else
        echo "✅ UPX 已安装：$(upx --version | head -n1)"
    fi
}

#-----------------------------
# 初始化 Go Modules
#-----------------------------
init_modules() {
    if [ ! -f "go.mod" ]; then
        echo "📦 初始化 Go Modules（module ${MODULE_NAME}）..."
        go mod init "${MODULE_NAME}"
    fi
    echo "🔄 拉取依赖..."
    go get github.com/pkg/sftp
    go get golang.org/x/crypto/ssh
    echo "✅ 依赖已就绪"
}

#-----------------------------
# 静态编译 & UPX 压缩
#-----------------------------
build_binary() {
    local target_arch=$1
    local out_file=$2

    echo "🚀 编译目标：GOARCH=${target_arch}"
    CGO_ENABLED=0 GOOS=linux GOARCH=${target_arch} \
        go build -ldflags="-s -w" -o "${out_file}" "${SRC_FILE}"

    echo "🗜️ UPX 压缩 ${out_file}…"
    upx --lzma -9 "${out_file}"

    echo "✅ ${out_file} 编译并压缩完成"
    echo
    read -n 1 -s -r -p "按任意键返回菜单…"
}

#-----------------------------
# 菜单
#-----------------------------
menu() {
    clear
    cat << EOF
=====================================
   Go 环境 & 静态编译 一键化脚本
=====================================
1) 安装 Go & UPX
2) 编译 ARM64 二进制 (bparm64)
3) 编译 AMD64 二进制 (bpxamd64)
(直接回车退出)
=====================================
EOF
    read -p "请选择操作： " choice
    case "${choice}" in
        1)
            toolchain_install
            ;;
        2)
            toolchain_install
            init_modules
            build_binary "arm64" "bparm64"
            ;;
        3)
            toolchain_install
            init_modules
            build_binary "amd64" "bpxamd64"
            ;;
        "")
            echo "👋 退出脚本"
            exit 0
            ;;
        *)
            echo "⚠️ 无效选项，请重试"
            sleep 1
            ;;
    esac
    menu
}

#-----------------------------
# 入口
#-----------------------------
menu