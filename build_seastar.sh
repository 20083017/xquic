#!/bin/bash
# build_seastar.sh — 使用 submodule 方式构建 xquic + seastar 集成 (quictls)
#
# 用法:
#   ./build_seastar.sh                # 默认构建
#   ./build_seastar.sh clean          # 清理后重新构建
#   ./build_seastar.sh deps           # 仅安装系统依赖 (Ubuntu/Debian)
#   ./build_seastar.sh dpdk           # 启用 Seastar_DPDK 构建 xquic_server_seastar
#   ./build_seastar.sh video          # 构建 xqc_video_receiver_seastar (FFmpeg CUDA + GL)
#
# 可选环境变量:
#   DPDK_CONFIG_FILE        参考配置文件路径，默认 third_party/seastar/dpdk-custom.conf
#   SEASTAR_DPDK_MACHINE    DPDK machine 参数，默认 native
#   BOOST_ROOT              Boost 安装前缀；build_boost 成功后自动设置
#   BOOST_PREFIX            本地构建 Boost 的安装前缀，默认 build_deps/boost-install
#   BOOST_SRC               Boost 源码目录；默认自动探测/下载
#   BOOST_VERSION           Boost 版本，默认 1.84.0
#   SKIP_BOOST_BUILD        设为 1 时只检测已有 Boost，不自动构建
#   FMT_PREFIX              fmt 安装前缀，默认 build_deps/fmt-install
#   FMT_VERSION             fmt 源码版本，默认 10.2.1
#   FFMPEG_PREFIX           FFmpeg hw 安装前缀 (video 模式)，默认 ~/ffmpeg-hw
#   SKIP_FFMPEG             video 模式：设为 1 跳过 FFmpeg 构建

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_seastar"
BUILD_DEPS_DIR="${SCRIPT_DIR}/build_deps"
QUICTLS_SRC="${SCRIPT_DIR}/third_party/quictls"
QUICTLS_INSTALL="${QUICTLS_SRC}/build"
SEASTAR_DIR="${SCRIPT_DIR}/third_party/seastar"
BOOST_VERSION="${BOOST_VERSION:-1.84.0}"
BOOST_VERSION_TAG="${BOOST_VERSION//./_}"
BOOST_INSTALL="${BOOST_PREFIX:-${BUILD_DEPS_DIR}/boost-install}"
BOOST_SRC="${BOOST_SRC:-}"
SKIP_BOOST_BUILD="${SKIP_BOOST_BUILD:-0}"
FMT_VERSION="${FMT_VERSION:-10.2.1}"
FMT_SRC="${FMT_SRC:-${BUILD_DEPS_DIR}/fmt}"
FMT_INSTALL="${FMT_PREFIX:-${BUILD_DEPS_DIR}/fmt-install}"
NPROC=$(nproc 2>/dev/null || echo 4)
DPDK_CONFIG_FILE_DEFAULT="${SEASTAR_DIR}/dpdk-custom.conf"
DPDK_CONFIG_FILE="${DPDK_CONFIG_FILE:-${DPDK_CONFIG_FILE_DEFAULT}}"
SEASTAR_DPDK_MACHINE="${SEASTAR_DPDK_MACHINE:-native}"
ENABLE_DPDK=0
ENABLE_VIDEO=0
FFMPEG_PREFIX="${FFMPEG_PREFIX:-${HOME}/ffmpeg-hw}"
SKIP_FFMPEG="${SKIP_FFMPEG:-0}"
BUILD_TARGET="xquic_server_seastar"

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
        libpciaccess-dev libcrypto++-dev \
        libxml2-dev xfslibs-dev libgnutls28-dev liblz4-dev \
        libsctp-dev systemtap-sdt-dev libtool cmake \
        libyaml-cpp-dev libc-ares-dev stow liburing-dev \
        diffutils valgrind doxygen libprotobuf-dev \
        protobuf-compiler libunwind-dev pkg-config \
        python3-pyelftools libevent-dev git \
        libglfw3-dev libegl-dev libva-dev libdrm-dev
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

boost_has_component() {
    local boost_root="$1"
    local component="$2"
    local libdir

    for libdir in "${boost_root}/lib" "${boost_root}/lib64"; do
        [[ -d "${libdir}" ]] || continue
        if compgen -G "${libdir}/libboost_${component}.so" >/dev/null \
            || compgen -G "${libdir}/libboost_${component}.a" >/dev/null \
            || compgen -G "${libdir}/libboost_${component}.so.*" >/dev/null; then
            return 0
        fi
    done
    return 1
}

boost_usable() {
    local boost_root="$1"
    local component

    [[ -f "${boost_root}/include/boost/version.hpp" ]] || return 1

    for component in \
        atomic chrono filesystem program_options system thread unit_test_framework; do
        boost_has_component "${boost_root}" "${component}" || return 1
    done
}

resolve_boost_src() {
    local candidate

    if [[ -n "${BOOST_SRC}" && -f "${BOOST_SRC}/bootstrap.sh" ]]; then
        echo "${BOOST_SRC}"
        return
    fi

    for candidate in \
        "${BUILD_DEPS_DIR}/boost_${BOOST_VERSION_TAG}" \
        "${HOME}/project/build_deps/boost_${BOOST_VERSION_TAG}" \
        "${BUILD_DEPS_DIR}/boost"; do
        if [[ -f "${candidate}/bootstrap.sh" ]]; then
            echo "${candidate}"
            return
        fi
    done
}

ensure_boost_source() {
    local src
    src="$(resolve_boost_src || true)"
    if [[ -n "${src}" ]]; then
        echo "${src}"
        return
    fi

    local archive="${BUILD_DEPS_DIR}/boost_${BOOST_VERSION_TAG}.tar.gz"
    src="${BUILD_DEPS_DIR}/boost_${BOOST_VERSION_TAG}"

    mkdir -p "${BUILD_DEPS_DIR}"
    if [[ ! -f "${src}/bootstrap.sh" ]]; then
        info "下载 Boost ${BOOST_VERSION} 源码..."
        if ! command -v wget >/dev/null 2>&1; then
            error "wget 未找到，无法下载 Boost 源码"
            exit 1
        fi
        wget -O "${archive}" \
            "https://archives.boost.io/release/${BOOST_VERSION}/source/boost_${BOOST_VERSION_TAG}.tar.gz"
        tar -xzf "${archive}" -C "${BUILD_DEPS_DIR}"
    fi

    [[ -f "${src}/bootstrap.sh" ]] || {
        error "Boost 源码不可用: ${src}"
        exit 1
    }
    echo "${src}"
}

build_boost() {
    if [[ "${SKIP_BOOST_BUILD}" -eq 1 ]]; then
        if boost_usable "$(resolve_boost_root)"; then
            info "使用已有 Boost: $(resolve_boost_root)"
            export BOOST_ROOT="$(resolve_boost_root)"
            return
        fi
        error "SKIP_BOOST_BUILD=1 但未找到可用 Boost"
        exit 1
    fi

    if boost_usable "${BOOST_INSTALL}"; then
        info "Boost 已可用: ${BOOST_INSTALL}"
        export BOOST_ROOT="${BOOST_INSTALL}"
        return
    fi

    local candidate
    for candidate in "${BOOST_INSTALL}" "${HOME}/local/boost-1.84" "/usr/local"; do
        if boost_usable "${candidate}"; then
            info "使用已有 Boost: ${candidate}"
            export BOOST_ROOT="${candidate}"
            return
        fi
    done

    local boost_src
    boost_src="$(ensure_boost_source)"
    info "构建 Boost ${BOOST_VERSION} (all libraries) -> ${BOOST_INSTALL}"

    (
        cd "${boost_src}"
        ./bootstrap.sh \
            --prefix="${BOOST_INSTALL}" \
            --with-libraries=all
        ./b2 -j"${NPROC}" \
            cxxflags="-std=c++23" \
            link=static,shared \
            threading=multi \
            install
    )

    boost_usable "${BOOST_INSTALL}" || {
        error "Boost 构建完成但不可用: ${BOOST_INSTALL}"
        exit 1
    }
    export BOOST_ROOT="${BOOST_INSTALL}"
    info "Boost 构建完成: ${BOOST_ROOT}"
}

resolve_boost_root() {
    if [[ -n "${BOOST_ROOT:-}" ]]; then
        echo "${BOOST_ROOT}"
        return
    fi

    local candidate
    for candidate in \
        "${BOOST_INSTALL}" \
        "${HOME}/local/boost-1.84" \
        "/usr/local"; do
        if boost_usable "${candidate}"; then
            echo "${candidate}"
            return
        fi
    done

    echo "${BOOST_INSTALL}"
}

resolve_boost_cmake_dir() {
    local boost_root="$1"
    local config

    if [[ -n "${Boost_DIR:-}" ]]; then
        echo "${Boost_DIR}"
        return
    fi

    for config in "${boost_root}/lib/cmake"/Boost-*; do
        if [[ -f "${config}/BoostConfig.cmake" ]]; then
            echo "${config}"
            return
        fi
    done
}

fmt_usable() {
    [[ -f "${FMT_INSTALL}/lib/cmake/fmt/fmt-config.cmake" ]] || return 1
    [[ -f "${FMT_INSTALL}/include/fmt/ostream.h" ]] || return 1
    grep -q 'ostream_formatter' "${FMT_INSTALL}/include/fmt/ostream.h" 2>/dev/null
}

build_fmt() {
    if fmt_usable; then
        info "fmt 已可用: ${FMT_INSTALL}"
        return
    fi

    if ! command -v cmake >/dev/null 2>&1; then
        error "cmake 未找到，无法构建 fmt"
        exit 1
    fi

    mkdir -p "${BUILD_DEPS_DIR}"
    if [[ ! -f "${FMT_SRC}/CMakeLists.txt" ]]; then
        info "克隆 fmt ${FMT_VERSION}..."
        git clone --depth 1 --branch "${FMT_VERSION}" \
            git@github.com:fmtlib/fmt.git "${FMT_SRC}"
    fi

    local fmt_build_dir="${FMT_SRC}/build"
    info "构建 fmt ${FMT_VERSION} -> ${FMT_INSTALL}"
    cmake -S "${FMT_SRC}" -B "${fmt_build_dir}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${FMT_INSTALL}" \
        -DBUILD_SHARED_LIBS=ON
    cmake --build "${fmt_build_dir}" -j"${NPROC}"
    cmake --install "${fmt_build_dir}"

    fmt_usable || {
        error "fmt 构建完成但不可用: ${FMT_INSTALL}"
        exit 1
    }
    info "fmt 构建完成: ${FMT_INSTALL}"
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

ffmpeg_usable() {
    [[ -f "${FFMPEG_PREFIX}/lib/pkgconfig/libavcodec.pc" ]] \
        && [[ -f "${FFMPEG_PREFIX}/lib/libavcodec.so" || -f "${FFMPEG_PREFIX}/lib/libavcodec.a" ]]
}

build_ffmpeg_hw() {
    if [[ "${SKIP_FFMPEG}" -eq 1 ]]; then
        ffmpeg_usable || {
            error "SKIP_FFMPEG=1 但 FFmpeg 不可用: ${FFMPEG_PREFIX}"
            exit 1
        }
        info "跳过 FFmpeg 构建，使用: ${FFMPEG_PREFIX}"
        return
    fi

    if ffmpeg_usable; then
        info "FFmpeg hw 已可用: ${FFMPEG_PREFIX}"
        return
    fi

    info "构建 FFmpeg CUDA/NVDEC -> ${FFMPEG_PREFIX}"
    "${SCRIPT_DIR}/scripts/build_ffmpeg_hw_linux.sh" \
        --prefix "${FFMPEG_PREFIX}" \
        --jobs "${NPROC}"
}

build_xquic_seastar() {
    info "配置 xquic + Seastar 构建 (quictls)..."
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    local boost_root
    local boost_cmake_dir
    boost_root="$(resolve_boost_root)"
    if [[ ! -f "${boost_root}/include/boost/version.hpp" ]]; then
        error "未找到 Boost，请设置 BOOST_ROOT 或安装 Boost >= 1.79"
        exit 1
    fi
    if ! boost_usable "${boost_root}"; then
        error "Boost 安装不完整: ${boost_root}"
        error "Seastar 需要 atomic chrono filesystem program_options system thread unit_test_framework"
        error "建议重新运行: bash build_seastar.sh dpdk"
        error "或手动设置: BOOST_ROOT=\"${BOOST_INSTALL}\" bash build_seastar.sh dpdk"
        exit 1
    fi
    boost_cmake_dir="$(resolve_boost_cmake_dir "${boost_root}")"

    local cmake_prefix_path="${FMT_INSTALL}:${boost_root}"
    if [[ -n "${CMAKE_PREFIX_PATH:-}" ]]; then
        cmake_prefix_path="${cmake_prefix_path}:${CMAKE_PREFIX_PATH}"
    fi

    info "使用 Boost: ${boost_root}"
    if [[ -n "${boost_cmake_dir}" ]]; then
        info "使用 Boost CMake: ${boost_cmake_dir}"
    else
        warn "未找到 BoostConfig.cmake，将回退到 FindBoost（可能产生版本警告）"
    fi
    info "使用 fmt: ${FMT_INSTALL}"

    local cmake_args=(
        -S "${SCRIPT_DIR}" -B "${BUILD_DIR}"
        -DXQC_ENABLE_SEASTAR=ON
        -DXQC_ENABLE_TESTING=ON
        -DSSL_TYPE=openssl
        -DSSL_PATH="${QUICTLS_INSTALL}"
        -DSSL_INC_PATH="${QUICTLS_INSTALL}/include"
        -DSSL_LIB_PATH="${QUICTLS_INSTALL}/lib64/libssl.a;${QUICTLS_INSTALL}/lib64/libcrypto.a"
        -DBOOST_ROOT="${boost_root}"
        -DBoost_NO_SYSTEM_PATHS=ON
        -Dfmt_DIR="${FMT_INSTALL}/lib/cmake/fmt"
        -DCMAKE_PREFIX_PATH="${cmake_prefix_path}"
    )

    if [[ -n "${boost_cmake_dir}" ]]; then
        cmake_args+=(-DBoost_DIR="${boost_cmake_dir}")
    fi

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

    if [ "${ENABLE_VIDEO}" -eq 1 ]; then
        info "启用 video receiver: LOWLATENCY_FFMPEG + HW_DECODE"
        info "FFmpeg prefix: ${FFMPEG_PREFIX}"
        export PKG_CONFIG_PATH="${FFMPEG_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
        cmake_args+=(
            -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON
            -DXQC_ENABLE_HW_DECODE=ON
        )
        BUILD_TARGET="xqc_video_receiver"
    fi

    cmake "${cmake_args[@]}"

    info "编译 ${BUILD_TARGET} (${NPROC} 并行)..."
    cmake --build "${BUILD_DIR}" --target "${BUILD_TARGET}" -j"${NPROC}"

    info "构建完成！可执行文件: ${BUILD_DIR}/xquic_tests/${BUILD_TARGET}"
    if [ "${ENABLE_VIDEO}" -eq 1 ]; then
        info "运行示例:"
        info "  export LD_LIBRARY_PATH=${FFMPEG_PREFIX}/lib:\${LD_LIBRARY_PATH:-}"
        info "  export XQC_PIN_AFFINITY=1"
        info "  ${BUILD_DIR}/xquic_tests/xqc_video_receiver --smp 1 --cpuset 0 -p 8443 --decode --display --codec hevc --hw-decode=cuda"
        info "  (symlink: xquic_tests/xqc_video_receiver_seastar)"
    fi
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
        build_boost
        build_fmt
        build_xquic_seastar
        ;;
    build|"")
        check_submodules
        build_quictls
        build_boost
        build_fmt
        build_xquic_seastar
        ;;
    dpdk)
        ENABLE_DPDK=1
        check_submodules
        build_quictls
        build_boost
        build_fmt
        build_xquic_seastar
        ;;
    video)
        ENABLE_VIDEO=1
        check_submodules
        build_quictls
        build_boost
        build_fmt
        build_ffmpeg_hw
        build_xquic_seastar
        ;;
    *)
        echo "用法: $0 [build|clean|deps|dpdk|video]"
        exit 1
        ;;
esac
