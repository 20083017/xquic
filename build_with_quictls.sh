#!/bin/bash
# =============================================================================
#  xquic + quictls/openssl 完整构建脚本
#
#  用法:
#    chmod +x build_with_quictls.sh
#    ./build_with_quictls.sh          # 默认完整构建 (clone + build quictls + build xquic)
#    ./build_with_quictls.sh --skip-quictls   # 跳过 quictls 构建 (已构建过)
#    ./build_with_quictls.sh --clean          # 完全清理后重新构建
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QUICTLS_DIR="${SCRIPT_DIR}/third_party/quictls"
QUICTLS_INSTALL="${QUICTLS_DIR}/build"
BUILD_DIR="${SCRIPT_DIR}/build"

SKIP_QUICTLS=0
CLEAN=0

for arg in "$@"; do
    case $arg in
        --skip-quictls) SKIP_QUICTLS=1 ;;
        --clean)        CLEAN=1 ;;
    esac
done

NPROC=$(nproc 2>/dev/null || echo 4)

echo "=============================================="
echo "  xquic + quictls 构建脚本"
echo "=============================================="
echo "  项目目录:    ${SCRIPT_DIR}"
echo "  quictls 目录: ${QUICTLS_DIR}"
echo "  构建目录:    ${BUILD_DIR}"
echo "  并行数:      ${NPROC}"
echo "=============================================="

# ─── Step 0: 清理 (可选) ─────────────────────────────────────
if [ "$CLEAN" -eq 1 ]; then
    echo ""
    echo "[Step 0] 清理旧构建..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${QUICTLS_INSTALL}"
    echo "  清理完成"
fi

# ─── Step 1: Clone quictls/openssl ────────────────────────────
if [ "$SKIP_QUICTLS" -eq 0 ]; then
    echo ""
    echo "[Step 1] 获取 quictls/openssl 源码..."

    if [ ! -d "${QUICTLS_DIR}" ]; then
        echo "  从 GitHub 克隆 quictls/openssl (openssl-3.1.4+quic 分支)..."
        cd "${SCRIPT_DIR}/third_party"
        git clone --depth 1 --branch openssl-3.1.4+quic \
            https://github.com/quictls/openssl.git quictls
        echo "  克隆完成"
    else
        echo "  quictls 目录已存在，跳过克隆"
    fi

    # ─── Step 2: 编译 quictls/openssl ─────────────────────────
    echo ""
    echo "[Step 2] 编译 quictls/openssl..."

    cd "${QUICTLS_DIR}"

    if [ ! -f "${QUICTLS_INSTALL}/lib/libssl.a" ]; then
        echo "  运行 Configure..."
        ./Configure \
            --prefix="${QUICTLS_INSTALL}" \
            --openssldir="${QUICTLS_INSTALL}" \
            enable-tls1_3 \
            no-shared \
            no-tests \
            linux-x86_64

        echo "  编译中 (使用 ${NPROC} 个线程)..."
        make -j"${NPROC}"

        echo "  安装到 ${QUICTLS_INSTALL}..."
        make install_sw

        echo "  quictls 编译安装完成"
    else
        echo "  quictls 已编译过，跳过 (libssl.a 已存在)"
    fi
else
    echo ""
    echo "[Step 1-2] 跳过 quictls 构建 (--skip-quictls)"
fi

# ─── Step 3: 验证 quictls 安装 ────────────────────────────────
echo ""
echo "[Step 3] 验证 quictls 安装..."

if [ ! -f "${QUICTLS_INSTALL}/lib/libssl.a" ]; then
    # 尝试 lib64 路径 (某些平台)
    if [ -f "${QUICTLS_INSTALL}/lib64/libssl.a" ]; then
        QUICTLS_LIB="${QUICTLS_INSTALL}/lib64"
    else
        echo "  ❌ 错误: 找不到 quictls 的 libssl.a"
        echo "  请检查 ${QUICTLS_INSTALL}/lib/ 或 ${QUICTLS_INSTALL}/lib64/"
        exit 1
    fi
else
    QUICTLS_LIB="${QUICTLS_INSTALL}/lib"
fi

echo "  ✅ libssl.a:   ${QUICTLS_LIB}/libssl.a"
echo "  ✅ libcrypto.a: ${QUICTLS_LIB}/libcrypto.a"

# 验证 QUIC API 存在
if grep -q "SSL_set_quic_method" "${QUICTLS_INSTALL}/include/openssl/ssl.h" 2>/dev/null; then
    echo "  ✅ QUIC TLS API 已确认存在"
else
    echo "  ❌ 警告: quictls 头文件中未找到 SSL_set_quic_method"
    echo "  可能使用了错误的 openssl 分支"
fi

# ─── Step 4: 构建 xquic ──────────────────────────────────────
echo ""
echo "[Step 4] 构建 xquic (使用 quictls)..."

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "  运行 CMake..."
cmake .. \
    -DSSL_TYPE=openssl \
    -DSSL_PATH="${QUICTLS_INSTALL}" \
    -DCMAKE_BUILD_TYPE=Debug

echo ""
echo "  编译 xquic..."
make -j"${NPROC}"

echo ""
echo "=============================================="
echo "  ✅ 构建完成！"
echo "=============================================="
echo ""
echo "  产出文件:"
echo "    libxquic.so:     ${BUILD_DIR}/libxquic.so"
echo "    libxquic-static: ${BUILD_DIR}/libxquic-static.a"
echo "    test_server:     ${BUILD_DIR}/tests/test_server"
echo "    test_client:     ${BUILD_DIR}/tests/test_client"
echo ""
echo "  测试方法 (Transport 模式):"
echo "    # 终端 1 - 启动服务端"
echo "    cd ${BUILD_DIR}/tests"
echo "    ./test_server -p 8443 -c ${SCRIPT_DIR}/server.crt -k ${SCRIPT_DIR}/server.key -t"
echo ""
echo "    # 终端 2 - 启动客户端"
echo "    cd ${BUILD_DIR}/tests"
echo "    ./test_client -a 127.0.0.1 -p 8443 -t"
echo ""
echo "  测试方法 (HTTP/3 模式):"
echo "    # 终端 1 - 启动服务端"
echo "    cd ${BUILD_DIR}/tests"
echo "    ./test_server -p 8443 -c ${SCRIPT_DIR}/server.crt -k ${SCRIPT_DIR}/server.key"
echo ""
echo "    # 终端 2 - 启动客户端"
echo "    cd ${BUILD_DIR}/tests"
echo "    ./test_client -a 127.0.0.1 -p 8443"
echo "=============================================="
