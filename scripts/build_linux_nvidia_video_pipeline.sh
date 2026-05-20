#!/usr/bin/env bash
# Build the Linux + NVIDIA xquic video receive/decode/display pipeline.
#
# Output targets:
#   build_linux_nvidia/xquic_tests/xqc_video_receiver
#   build_linux_nvidia/xquic_tests/video_client
#   build_linux_nvidia/xquic_tests/xqc_h264_decode_smoke
#   build_linux_nvidia/xquic_tests/xqc_rtp_annexb_receiver

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build_linux_nvidia}"
FFMPEG_PREFIX="${FFMPEG_PREFIX:-$HOME/ffmpeg-hw}"
FFMPEG_SRC_ARG=()
QUICTLS_DIR="${QUICTLS_DIR:-$ROOT/third_party/quictls}"
QUICTLS_PREFIX="${QUICTLS_PREFIX:-$QUICTLS_DIR/build}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

INSTALL_DEPS=0
SKIP_QUICTLS=0
SKIP_FFMPEG=0
SKIP_XQUIC=0
NO_CUDA=0
WITH_DPDK_RX=0
WITH_CUDA_SMOKE=0
CLEAN=0

usage() {
    cat <<'EOF'
Usage: build_linux_nvidia_video_pipeline.sh [options]

Options:
  --install-deps        Run scripts/install_ubuntu_nvidia_deps.sh first
  --build-dir DIR       CMake build dir (default: build_linux_nvidia)
  --ffmpeg-prefix DIR   FFmpeg install prefix (default: ~/ffmpeg-hw)
  --ffmpeg-src DIR      Existing FFmpeg source tree
  --quictls-dir DIR     quictls source tree (default: third_party/quictls)
  --jobs N              Parallel build jobs
  --no-cuda             Build FFmpeg without CUDA/NVDEC/NVENC
  --with-dpdk-rx        Also build xqc_dpdk_rtp_rx (requires libdpdk-dev)
  --with-cuda-smoke     Also build CUDA memory + CUDA/GL interop smoke tools
  --skip-quictls        Reuse existing quictls build
  --skip-ffmpeg         Reuse existing FFmpeg build
  --skip-xquic          Only build dependencies
  --clean               Remove build dir and quictls install before build
  -h, --help            Show this help

Typical first build on Ubuntu + NVIDIA:
  bash scripts/install_ubuntu_nvidia_deps.sh
  bash scripts/build_linux_nvidia_video_pipeline.sh

Incremental rebuild after code changes:
  bash scripts/build_linux_nvidia_video_pipeline.sh --skip-quictls --skip-ffmpeg
EOF
}

log()  { printf '[linux-nvidia-build] %s\n' "$*"; }
step() { printf '\n[linux-nvidia-build] ===== %s =====\n' "$*"; }
die()  { printf '[linux-nvidia-build] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-deps) INSTALL_DEPS=1; shift ;;
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --ffmpeg-prefix) FFMPEG_PREFIX="$2"; shift 2 ;;
        --ffmpeg-src) FFMPEG_SRC_ARG=(--ffmpeg-src "$2"); shift 2 ;;
        --quictls-dir) QUICTLS_DIR="$2"; QUICTLS_PREFIX="$2/build"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --no-cuda) NO_CUDA=1; shift ;;
        --with-dpdk-rx) WITH_DPDK_RX=1; shift ;;
        --with-cuda-smoke) WITH_CUDA_SMOKE=1; shift ;;
        --skip-quictls) SKIP_QUICTLS=1; shift ;;
        --skip-ffmpeg) SKIP_FFMPEG=1; shift ;;
        --skip-xquic) SKIP_XQUIC=1; shift ;;
        --clean) CLEAN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "Linux only; macOS sender uses build_macos_video_client.sh"

mkdir -p "$BUILD_DIR" "$FFMPEG_PREFIX"
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
FFMPEG_PREFIX="$(cd "$FFMPEG_PREFIX" && pwd)"

find_quictls_libdir() {
    local d
    for d in "$QUICTLS_PREFIX/lib64" "$QUICTLS_PREFIX/lib"; do
        if [[ -f "$d/libssl.a" && -f "$d/libcrypto.a" ]]; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

archive_has_elf_members() {
    local lib="$1"
    local first
    first="$(ar -t "$lib" 2>/dev/null | grep -vE '^/?$' | head -1 || true)"
    [[ -n "$first" ]] || return 1
    ar p "$lib" "$first" 2>/dev/null | file - 2>/dev/null | grep -q 'ELF'
}

quictls_usable() {
    local libdir
    libdir="$(find_quictls_libdir 2>/dev/null || true)"
    [[ -n "$libdir" && -f "$QUICTLS_PREFIX/include/openssl/ssl.h" ]] || return 1
    archive_has_elf_members "$libdir/libssl.a" || return 1
    archive_has_elf_members "$libdir/libcrypto.a" || return 1
    grep -q "SSL_set_quic_method" "$QUICTLS_PREFIX/include/openssl/ssl.h" 2>/dev/null
}

build_quictls() {
    step "quictls"
    if quictls_usable; then
        log "reusing quictls: $QUICTLS_PREFIX"
        return 0
    fi

    if [[ ! -f "$QUICTLS_DIR/Configure" ]]; then
        log "initializing quictls submodule"
        git -C "$ROOT" submodule update --init third_party/quictls
    fi
    [[ -f "$QUICTLS_DIR/Configure" ]] || die "missing $QUICTLS_DIR/Configure"

    cd "$QUICTLS_DIR"
    ./Configure \
        --prefix="$QUICTLS_PREFIX" \
        --openssldir="$QUICTLS_PREFIX" \
        enable-tls1_3 \
        no-shared \
        no-tests
    make -j"$JOBS"
    make install_sw

    quictls_usable || die "quictls build did not expose OpenSSL QUIC API"
    log "quictls libdir: $(find_quictls_libdir)"
}

build_ffmpeg() {
    step "FFmpeg CUDA/NVDEC"
    local cuda_flags=()
    if [[ "$NO_CUDA" -eq 1 ]]; then
        cuda_flags=(--no-cuda)
    fi
    "$ROOT/scripts/build_ffmpeg_hw_linux.sh" \
        --prefix "$FFMPEG_PREFIX" \
        --jobs "$JOBS" \
        "${FFMPEG_SRC_ARG[@]}" \
        "${cuda_flags[@]}"
}

build_xquic() {
    step "xquic video targets"
    export PKG_CONFIG_PATH="$FFMPEG_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export LD_LIBRARY_PATH="$FFMPEG_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    local dpdk_cmake=()
    local dpdk_target=()
    if [[ "$WITH_DPDK_RX" -eq 1 ]]; then
        dpdk_cmake=(-DXQC_ENABLE_DPDK_RTP_RX=ON)
        dpdk_target=(xqc_dpdk_rtp_rx)
    fi
    local cuda_smoke_cmake=()
    local cuda_smoke_targets=()
    if [[ "$WITH_CUDA_SMOKE" -eq 1 ]]; then
        cuda_smoke_cmake=(-DXQC_ENABLE_CUDA_MEMORY_SMOKE=ON -DXQC_ENABLE_CUDA_GL_INTEROP_SMOKE=ON)
        cuda_smoke_targets=(xqc_cuda_memory_smoke xqc_cuda_gl_interop_smoke)
    fi

    cmake -S "$ROOT" -B "$BUILD_DIR" \
        -DSSL_PATH="$QUICTLS_PREFIX" \
        -DXQC_ENABLE_TESTING=ON \
        -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON \
        -DXQC_ENABLE_HW_DECODE=ON \
        -DXQC_ENABLE_DRM_KMS_SMOKE=ON \
        -DXQC_ENABLE_GPUDIRECT_ENV_CHECK=ON \
        -DXQC_ENABLE_NV12_MOSAIC_SMOKE=ON \
        -DXQC_ENABLE_SPSC_RING_SMOKE=ON \
        "${dpdk_cmake[@]}" \
        "${cuda_smoke_cmake[@]}" \
        -DCMAKE_BUILD_TYPE=Release

    cmake --build "$BUILD_DIR" \
        --target xqc_video_receiver video_client xqc_h264_decode_smoke xqc_rtp_annexb_receiver \
            xqc_drm_kms_smoke xqc_gpudirect_env_check xqc_nv12_mosaic_smoke \
            xqc_spsc_ring_smoke "${dpdk_target[@]}" "${cuda_smoke_targets[@]}" \
        -j"$JOBS"
}

print_summary() {
    local ffmpeg_bin="$FFMPEG_PREFIX/bin/ffmpeg"
    step "summary"
    cat <<EOF
Artifacts:
  receiver:     $BUILD_DIR/xquic_tests/xqc_video_receiver
  sender:       $BUILD_DIR/xquic_tests/video_client
  decode smoke: $BUILD_DIR/xquic_tests/xqc_h264_decode_smoke
  RTP receiver: $BUILD_DIR/xquic_tests/xqc_rtp_annexb_receiver
  DPDK RTP RX:  $BUILD_DIR/xquic_tests/xqc_dpdk_rtp_rx  (when --with-dpdk-rx)
  DRM/KMS smoke: $BUILD_DIR/xquic_tests/xqc_drm_kms_smoke
  GPUDirect check: $BUILD_DIR/xquic_tests/xqc_gpudirect_env_check
  NV12 mosaic:  $BUILD_DIR/xquic_tests/xqc_nv12_mosaic_smoke
  SPSC ring:    $BUILD_DIR/xquic_tests/xqc_spsc_ring_smoke
  CUDA memory:  $BUILD_DIR/xquic_tests/xqc_cuda_memory_smoke  (when --with-cuda-smoke)
  CUDA/GL:      $BUILD_DIR/xquic_tests/xqc_cuda_gl_interop_smoke  (when --with-cuda-smoke)
  FFmpeg:       $FFMPEG_PREFIX
  quictls:      $QUICTLS_PREFIX

Runtime env:
  export PKG_CONFIG_PATH="$FFMPEG_PREFIX/lib/pkgconfig:\${PKG_CONFIG_PATH:-}"
  export LD_LIBRARY_PATH="$FFMPEG_PREFIX/lib:\${LD_LIBRARY_PATH:-}"
  export XQC_HW_DECODE=cuda

Verify FFmpeg NVDEC:
  "$ffmpeg_bin" -hide_banner -decoders 2>/dev/null | grep -E 'h264_cuvid|hevc_cuvid'

Local E2E:
  DISPLAY=\${DISPLAY:-:0} EOS_FLAGS="--no-eos-file-decode" bash "$ROOT/scripts/wsl_video_e2e_cuda.sh"
EOF
}

step "Linux NVIDIA video pipeline build"
log "ROOT=$ROOT"
log "BUILD_DIR=$BUILD_DIR"
log "FFMPEG_PREFIX=$FFMPEG_PREFIX"
log "QUICTLS_PREFIX=$QUICTLS_PREFIX"
log "JOBS=$JOBS"

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
    deps_args=()
    if [[ "$WITH_DPDK_RX" -eq 1 ]]; then
        deps_args=(--with-dpdk)
    fi
    "$ROOT/scripts/install_ubuntu_nvidia_deps.sh" "${deps_args[@]}"
fi

if [[ "$CLEAN" -eq 1 ]]; then
    log "clean: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    log "clean: $QUICTLS_PREFIX"
    rm -rf "$QUICTLS_PREFIX"
fi

if [[ "$SKIP_QUICTLS" -eq 0 ]]; then
    build_quictls
else
    quictls_usable || die "quictls is not usable; rerun without --skip-quictls"
    log "skip quictls"
fi

if [[ "$SKIP_FFMPEG" -eq 0 ]]; then
    build_ffmpeg
else
    [[ -f "$FFMPEG_PREFIX/lib/pkgconfig/libavcodec.pc" ]] || die "FFmpeg pkg-config not found in $FFMPEG_PREFIX"
    log "skip FFmpeg"
fi

if [[ "$SKIP_XQUIC" -eq 0 ]]; then
    build_xquic
else
    log "skip xquic"
fi

print_summary
