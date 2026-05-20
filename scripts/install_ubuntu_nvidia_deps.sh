#!/usr/bin/env bash
# Install Ubuntu dependencies for the Linux + NVIDIA video receive/decode/display path.
#
# This script installs build tools, xquic test dependencies, FFmpeg build
# dependencies, OpenGL/GLFW display dependencies, and optional CUDA toolkit
# packages. It does not install the NVIDIA kernel driver; install that from
# Ubuntu "Additional Drivers" or NVIDIA's CUDA repository before running E2E.

set -euo pipefail

INSTALL_CUDA=1
INSTALL_DPDK=0
INSTALL_SEASTAR=0
ASSUME_YES=1

usage() {
    cat <<'EOF'
Usage: install_ubuntu_nvidia_deps.sh [options]

Options:
  --no-cuda          Do not install nvidia-cuda-toolkit
  --with-dpdk        Also install DPDK runtime/development packages
  --with-seastar     Also install Seastar build dependencies
  --ask              Let apt prompt instead of using -y
  -h, --help         Show this help

Notes:
  - Install the NVIDIA display/compute driver separately.
  - After driver install, verify: nvidia-smi
  - The CUDA toolkit package is enough for nvcc/headers used by FFmpeg builds.
EOF
}

log() { printf '[deps] %s\n' "$*"; }
die() { printf '[deps] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cuda) INSTALL_CUDA=0; shift ;;
        --with-dpdk) INSTALL_DPDK=1; shift ;;
        --with-seastar) INSTALL_SEASTAR=1; shift ;;
        --ask) ASSUME_YES=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

if ! command -v apt-get >/dev/null 2>&1; then
    die "apt-get not found; this helper is for Ubuntu/Debian"
fi

APT_YES=()
if [[ "$ASSUME_YES" -eq 1 ]]; then
    APT_YES=(-y)
fi

BASE_PACKAGES=(
    build-essential
    ca-certificates
    cmake
    file
    git
    libevent-dev
    libgl1-mesa-dev
    libglfw3-dev
    libx11-dev
    libx264-dev
    libx265-dev
    nasm
    ninja-build
    pkg-config
    python3
    python3-pyelftools
    vainfo
    yasm
)

HW_PACKAGES=(
    libdrm-dev
    libegl-dev
    libva-dev
    libva-drm2
    mesa-utils
    mesa-va-drivers
)

PERF_PACKAGES=(
    hwloc
    libnuma-dev
    linux-tools-generic
    numactl
    pciutils
)

SEASTAR_PACKAGES=(
    diffutils
    doxygen
    gcc
    g++
    libboost-all-dev
    libc-ares-dev
    libcrypto++-dev
    libfmt-dev
    libgnutls28-dev
    libhwloc-dev
    liblz4-dev
    libpciaccess-dev
    libprotobuf-dev
    libsctp-dev
    libtool
    libunwind-dev
    libxml2-dev
    libyaml-cpp-dev
    protobuf-compiler
    ragel
    stow
    systemtap-sdt-dev
    valgrind
    xfslibs-dev
)

CUDA_PACKAGES=()
if [[ "$INSTALL_CUDA" -eq 1 ]]; then
    CUDA_PACKAGES=(nvidia-cuda-toolkit)
fi

DPDK_PACKAGES=()
if [[ "$INSTALL_DPDK" -eq 1 ]]; then
    DPDK_PACKAGES=(dpdk dpdk-dev dpdk-doc libdpdk-dev)
fi

log "apt update"
sudo apt-get update

log "install base + video pipeline packages"
sudo apt-get install "${APT_YES[@]}" \
    "${BASE_PACKAGES[@]}" \
    "${HW_PACKAGES[@]}" \
    "${PERF_PACKAGES[@]}" \
    "${CUDA_PACKAGES[@]}" \
    "${DPDK_PACKAGES[@]}"

if [[ "$INSTALL_SEASTAR" -eq 1 ]]; then
    log "install Seastar packages"
    sudo apt-get install "${APT_YES[@]}" "${SEASTAR_PACKAGES[@]}"
fi

log "dependency install complete"
if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi || true
else
    log "nvidia-smi not found; install/enable the NVIDIA driver before NVDEC E2E"
fi

if command -v nvcc >/dev/null 2>&1; then
    nvcc --version | sed 's/^/[deps] /' || true
else
    log "nvcc not found; rerun without --no-cuda or install CUDA toolkit manually"
fi
