#!/bin/bash
# build_seastar.sh — 使用 submodule 方式构建 xquic + seastar 集成 (quictls)
#
# 用法:
#   ./build_seastar.sh                # 默认构建
#   ./build_seastar.sh clean          # 清理后重新构建
#   ./build_seastar.sh deps           # 仅安装系统依赖 (Ubuntu/Debian)
#   ./build_seastar.sh dpdk           # 启用 Seastar_DPDK 构建 xquic_server_seastar
#
# 可选环境变量:
#   DPDK_CONFIG_FILE        参考配置文件路径，默认 third_party/seastar/dpdk-custom.conf
#   SEASTAR_DPDK_MACHINE    DPDK machine 参数，默认 native

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_seastar"
QUICTLS_SRC="${SCRIPT_DIR}/third_party/quictls"
QUICTLS_INSTALL="${QUICTLS_SRC}/build"
SEASTAR_DIR="${SCRIPT_DIR}/third_party/seastar"
NPROC=$(nproc 2>/dev/null || echo 4)
DPDK_CONFIG_FILE_DEFAULT="${SEASTAR_DIR}/dpdk-custom.conf"
DPDK_CONFIG_FILE="${DPDK_CONFIG_FILE:-${DPDK_CONFIG_FILE_DEFAULT}}"
SEASTAR_DPDK_MACHINE="${SEASTAR_DPDK_MACHINE:-native}"
ENABLE_DPDK=0

if [[ "${DPDK_CONFIG_FILE}" != /* ]]; then
    DPDK_CONFIG_FILE="${SCRIPT_DIR}/${DPDK_CONFIG_FILE}"
fi

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

install_deps_ubuntu() {
    info "安装 Seastar 系统依赖 (Ubuntu/Debian)..."
    sudo apt-get update
    sudo apt-get install -y \
        gcc g++ ninja-build ragel libhwloc-dev libnuma-dev \
        libpciaccess-dev libcrypto++-dev libboost-all-dev \
        libxml2-dev xfslibs-dev libgnutls28-dev liblz4-dev \
        libsctp-dev systemtap-sdt-dev libtool cmake \
        libyaml-cpp-dev libc-ares-dev stow libfmt-dev \
        diffutils valgrind doxygen libprotobuf-dev \
        protobuf-compiler libunwind-dev pkg-config \
        python3-pyelftools libevent-dev
    info "系统依赖安装完成"
}

install_deps_fedora() {
    info "安装 Seastar 系统依赖 (Fedora/RHEL)..."
    sudo dnf install -y \
        gcc gcc-c++ ninja-build ragel hwloc-devel numactl-devel \
        libpciaccess-devel cryptopp-devel boost-devel \
        libxml2-devel xfsprogs-devel gnutls-devel lz4-devel \
        lksctp-tools-devel systemtap-sdt-devel libtool cmake \
        yaml-cpp-devel c-ares-devel stow fmt-devel \
        diffutils valgrind doxygen protobuf-devel \
        protobuf-compiler libunwind-devel pkgconf \
        python3-pyelftools libevent-devel
    info "系统依赖安装完成"
}

check_submodules() {
    if [ ! -f "${SEASTAR_DIR}/CMakeLists.txt" ]; then
        info "初始化 Seastar submodule (SSH)..."
        cd "${SCRIPT_DIR}"
        git submodule update --init --recursive third_party/seastar
    fi
}

build_quictls() {
    if [ -f "${QUICTLS_INSTALL}/lib64/libssl.a" ] && [ -f "${QUICTLS_INSTALL}/lib64/libcrypto.a" ]; then
        info "quictls 已构建，跳过"
        return
    fi

    if [ ! -d "${QUICTLS_SRC}" ]; then
        info "克隆 quictls..."
        git clone --depth 1 --branch openssl-3.1.4+quic \
            https://github.com/quictls/openssl.git "${QUICTLS_SRC}"
    fi

    info "构建 quictls..."
    cd "${QUICTLS_SRC}"
    ./Configure --prefix="${QUICTLS_INSTALL}" --openssldir="${QUICTLS_INSTALL}" \
        no-shared no-tests no-docs
    make -j"${NPROC}"
    make install_sw
    info "quictls 构建完成: ${QUICTLS_INSTALL}"
}

build_xquic_seastar() {
    info "配置 xquic + Seastar 构建 (quictls)..."
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    # Boost 1.83 installed in /usr/local
    local BOOST_ROOT="/usr/local"
    local cmake_args=(
        -S "${SCRIPT_DIR}" -B "${BUILD_DIR}"
        -DXQC_ENABLE_SEASTAR=ON
        -DXQC_ENABLE_TESTING=ON
        -DSSL_TYPE=openssl
        -DSSL_PATH="${QUICTLS_INSTALL}"
        -DSSL_INC_PATH="${QUICTLS_INSTALL}/include"
        -DSSL_LIB_PATH="${QUICTLS_INSTALL}/lib64/libssl.a;${QUICTLS_INSTALL}/lib64/libcrypto.a"
        -DBOOST_ROOT="${BOOST_ROOT}"
        -DBoost_NO_SYSTEM_PATHS=ON
    )

    if [ "${ENABLE_DPDK}" -eq 1 ]; then
        info "启用 Seastar DPDK 构建: Seastar_DPDK=ON"
        info "DPDK reference config: ${DPDK_CONFIG_FILE}"
        if [ ! -f "${DPDK_CONFIG_FILE}" ]; then
            error "DPDK 配置参考文件不存在: ${DPDK_CONFIG_FILE}"
            exit 1
        fi
        cmake_args+=(
            -DSeastar_DPDK=ON
            -DSeastar_DPDK_MACHINE="${SEASTAR_DPDK_MACHINE}"
        )
    fi

    cmake "${cmake_args[@]}"

    info "编译 xquic_server_seastar (${NPROC} 并行)..."
    cmake --build "${BUILD_DIR}" --target xquic_server_seastar -j"${NPROC}"

    info "构建完成！可执行文件: ${BUILD_DIR}/xquic_tests/xquic_server_seastar"
}

case "${1:-build}" in
    deps)
        if command -v apt-get &>/dev/null; then
            install_deps_ubuntu
        elif command -v dnf &>/dev/null; then
            install_deps_fedora
        else
            error "不支持的包管理器，请手动安装 Seastar 依赖"
            exit 1
        fi
        ;;
    clean)
        info "清理构建目录: ${BUILD_DIR}"
        rm -rf "${BUILD_DIR}"
        check_submodules
        build_quictls
        build_xquic_seastar
        ;;
    build|"")
        check_submodules
        build_quictls
        build_xquic_seastar
        ;;
    dpdk)
        ENABLE_DPDK=1
        check_submodules
        build_quictls
        build_xquic_seastar
        ;;
    *)
        echo "用法: $0 [build|clean|deps|dpdk]"
        exit 1
        ;;
esac
