#!/usr/bin/env bash
# macOS: build quictls + FFmpeg (HEVC send) + xquic video_client.
#
# Full build (recommended first time):
#   ./scripts/build_macos_video_client.sh
#
# After code changes (reuse quictls/ffmpeg):
#   ./scripts/build_macos_video_client.sh --skip-quictls --skip-ffmpeg
#
# Clean rebuild:
#   ./scripts/build_macos_video_client.sh --clean
#
# Log: build_macos/build_macos_video_client.log (see --no-log to disable)
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QUICTLS_DIR="${QUICTLS_DIR:-$ROOT/third_party/quictls}"
QUICTLS_PREFIX="${QUICTLS_PREFIX:-$QUICTLS_DIR/build}"
XQUIC_BUILD_DIR="${XQUIC_BUILD_DIR:-$ROOT/build_macos}"
FFMPEG_PREFIX="${FFMPEG_PREFIX:-$HOME/ffmpeg-hw}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
CMAKE_TARGET="${CMAKE_TARGET:-video_client}"

SKIP_BREW=0
SKIP_QUICTLS=0
SKIP_FFMPEG=0
SKIP_XQUIC=0
FORCE_QUICTLS=0
CLEAN=0
ENABLE_LOG=1
GEN_TEST_CLIP=0

usage() {
    cat <<'EOF'
Usage: build_macos_video_client.sh [options]

  --build-dir DIR       xquic CMake build dir (default: build_macos)
  --ffmpeg-prefix DIR   FFmpeg install prefix (default: ~/ffmpeg-hw)
  --quictls-dir DIR     quictls source tree (default: third_party/quictls)
  --jobs N              Parallel compile jobs
  --target NAME         cmake --build target (default: video_client)
  --gen-test-clip       After build, run gen_hevc_annexb.sh → build_macos/test_cam0.h265

  --skip-brew           Do not run brew install for missing deps
  --skip-quictls        Skip quictls rebuild (must already be darwin Mach-O)
  --skip-ffmpeg         Skip scripts/build_ffmpeg_hw_macos.sh
  --skip-xquic          Only deps + quictls + ffmpeg
  --force-quictls       Rebuild quictls even if libssl.a exists
  --clean               Remove build_macos and quictls/build before build
  --no-log              Do not write build_macos/build_macos_video_client.log
  -h, --help            This help

Steps:
  1. Homebrew: libevent, pkg-config, nasm, yasm, x264, x265
  2. quictls: darwin64-arm64-cc / darwin64-x86_64-cc → third_party/quictls/build
  3. FFmpeg:  scripts/build_ffmpeg_hw_macos.sh (libx265 + VideoToolbox)
  4. xquic:   cmake + video_client (PLATFORM=mac, HW_DECODE=OFF)

Runtime (each new shell):
  export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
  export DYLD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${DYLD_LIBRARY_PATH:-}"
EOF
}

log()  { printf '[macos-build] %s\n' "$*"; }
die()  { printf '[macos-build] ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n[macos-build] ===== %s =====\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) XQUIC_BUILD_DIR="$2"; shift 2 ;;
        --ffmpeg-prefix) FFMPEG_PREFIX="$2"; shift 2 ;;
        --quictls-dir) QUICTLS_DIR="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --target) CMAKE_TARGET="$2"; shift 2 ;;
        --gen-test-clip) GEN_TEST_CLIP=1; shift ;;
        --skip-brew) SKIP_BREW=1; shift ;;
        --skip-quictls) SKIP_QUICTLS=1; shift ;;
        --skip-ffmpeg) SKIP_FFMPEG=1; shift ;;
        --skip-xquic) SKIP_XQUIC=1; shift ;;
        --force-quictls) FORCE_QUICTLS=1; shift ;;
        --clean) CLEAN=1; shift ;;
        --no-log) ENABLE_LOG=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only (Linux/WSL: build_with_quictls.sh + build_ffmpeg_hw_linux.sh)"

XQUIC_BUILD_DIR="$(cd "$ROOT" && mkdir -p "$XQUIC_BUILD_DIR" && cd "$XQUIC_BUILD_DIR" && pwd)"
FFMPEG_PREFIX="$(mkdir -p "$FFMPEG_PREFIX" && cd "$FFMPEG_PREFIX" && pwd)"
LOG_FILE="$XQUIC_BUILD_DIR/build_macos_video_client.log"

if [[ "$ENABLE_LOG" -eq 1 ]]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
    log "logging to $LOG_FILE"
fi

detect_quictls_target() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        arm64)  echo "darwin64-arm64-cc" ;;
        x86_64) echo "darwin64-x86_64-cc" ;;
        *) die "unsupported CPU arch for quictls: $arch" ;;
    esac
}

# Reject Linux/WSL static libs accidentally linked on macOS (archive members like "/" "/0").
quictls_lib_usable() {
    local lib="$1"
    [[ -f "$lib" ]] || return 1
    local first
    first="$(ar -t "$lib" 2>/dev/null | head -1 || true)"
    [[ -n "$first" && "$first" != /* ]]
}

find_quictls_libdir() {
    local d
    for d in "$QUICTLS_PREFIX/lib" "$QUICTLS_PREFIX/lib64"; do
        if [[ -f "$d/libssl.a" && -f "$d/libcrypto.a" ]] \
            && quictls_lib_usable "$d/libssl.a" \
            && quictls_lib_usable "$d/libcrypto.a"; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

need_quictls_rebuild() {
    if [[ "$FORCE_QUICTLS" -eq 1 ]]; then
        return 0
    fi
    local libdir
    libdir="$(find_quictls_libdir 2>/dev/null || true)"
    [[ -z "$libdir" ]]
}

brew_install_missing() {
    [[ "$SKIP_BREW" -eq 1 ]] && return 0
    command -v brew >/dev/null 2>&1 || {
        log "Homebrew not found; install deps manually: libevent pkg-config nasm yasm x264 x265"
        return 0
    }
    local pkg missing=()
    for pkg in libevent pkg-config nasm yasm x264 x265; do
        if ! brew list "$pkg" &>/dev/null; then
            missing+=("$pkg")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "brew install ${missing[*]}"
        brew install "${missing[@]}"
    else
        log "Homebrew deps OK"
    fi
}

build_quictls() {
    step "quictls (TLS for QUIC)"
    [[ -f "$QUICTLS_DIR/Configure" ]] || die "missing $QUICTLS_DIR — run: git submodule update --init third_party/quictls"

    local target
    target="$(detect_quictls_target)"
    log "OpenSSL target: $target"
    log "install prefix: $QUICTLS_PREFIX"

    cd "$QUICTLS_DIR"
    if need_quictls_rebuild; then
        log "cleaning old quictls build (remove Linux lib64 artifacts if present)"
        make distclean >/dev/null 2>&1 || true
        rm -rf "$QUICTLS_PREFIX"

        ./Configure \
            --prefix="$QUICTLS_PREFIX" \
            --openssldir="$QUICTLS_PREFIX" \
            enable-tls1_3 \
            no-shared \
            no-tests \
            "$target"

        make -j"$JOBS"
        make install_sw
    else
        log "reusing existing darwin quictls in $QUICTLS_PREFIX"
    fi

    local libdir
    libdir="$(find_quictls_libdir)" || die "quictls install invalid — run with --force-quictls"
    log "quictls libdir: $libdir"
    log "libssl.a:   $libdir/libssl.a"
    log "libcrypto.a: $libdir/libcrypto.a"

    if ! grep -q "SSL_set_quic_method" "$QUICTLS_PREFIX/include/openssl/ssl.h" 2>/dev/null; then
        die "quictls headers missing QUIC API (wrong openssl branch?)"
    fi
    log "QUIC TLS API: OK"
}

build_ffmpeg() {
    step "FFmpeg (HEVC encode: libx265 / VideoToolbox)"
    "$ROOT/scripts/build_ffmpeg_hw_macos.sh" \
        --prefix "$FFMPEG_PREFIX" \
        --jobs "$JOBS"
}

build_xquic() {
    step "xquic ($CMAKE_TARGET)"
    local libevent_prefix=""
    if command -v brew >/dev/null 2>&1; then
        libevent_prefix="$(brew --prefix libevent 2>/dev/null || true)"
    fi
    [[ -n "$libevent_prefix" ]] || die "libevent not found — brew install libevent"

    export PKG_CONFIG_PATH="$FFMPEG_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export DYLD_LIBRARY_PATH="$FFMPEG_PREFIX/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

    cmake -S "$ROOT" -B "$XQUIC_BUILD_DIR" \
        -DPLATFORM=mac \
        -DXQC_SUPPORT_SENDMMSG_BUILD=0 \
        -DSSL_PATH="$QUICTLS_PREFIX" \
        -DXQC_ENABLE_TESTING=ON \
        -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON \
        -DXQC_ENABLE_HW_DECODE=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$libevent_prefix"

    cmake --build "$XQUIC_BUILD_DIR" --target "$CMAKE_TARGET" -j"$JOBS"

    local bin="$XQUIC_BUILD_DIR/xquic_tests/$CMAKE_TARGET"
    [[ -x "$bin" ]] || die "binary not found: $bin"
    log "built: $bin"
    file "$bin"
}

# ─── main ─────────────────────────────────────────────────────
step "macOS HEVC video client build"
log "ROOT=$ROOT"
log "XQUIC_BUILD_DIR=$XQUIC_BUILD_DIR"
log "FFMPEG_PREFIX=$FFMPEG_PREFIX"
log "QUICTLS_PREFIX=$QUICTLS_PREFIX"
log "JOBS=$JOBS"

if [[ "$CLEAN" -eq 1 ]]; then
    log "clean: $XQUIC_BUILD_DIR"
    rm -rf "$XQUIC_BUILD_DIR"
    mkdir -p "$XQUIC_BUILD_DIR"
    log "clean: $QUICTLS_PREFIX"
    rm -rf "$QUICTLS_PREFIX"
fi

brew_install_missing

if [[ "$SKIP_QUICTLS" -eq 0 ]]; then
    build_quictls
else
    if ! find_quictls_libdir >/dev/null; then
        die "quictls not usable (Linux lib64 .a?) — run without --skip-quictls or use --force-quictls"
    fi
    log "skip quictls (libdir=$(find_quictls_libdir))"
fi

if [[ "$SKIP_FFMPEG" -eq 0 ]]; then
    build_ffmpeg
else
    log "skip ffmpeg"
fi

if [[ "$SKIP_XQUIC" -eq 0 ]]; then
    build_xquic
else
    log "skip xquic"
fi

if [[ "$GEN_TEST_CLIP" -eq 1 ]]; then
    step "test HEVC clip"
    export PATH="$FFMPEG_PREFIX/bin:$PATH"
    FFMPEG_HW="$FFMPEG_PREFIX" "$ROOT/scripts/gen_hevc_annexb.sh" \
        "$XQUIC_BUILD_DIR/test_cam0.h265"
fi

step "done"
cat <<EOF

Artifacts:
  video_client:  $XQUIC_BUILD_DIR/xquic_tests/video_client
  quictls:       $QUICTLS_PREFIX
  ffmpeg:        $FFMPEG_PREFIX
  log:           ${LOG_FILE:-disabled}

Runtime (new terminal):
  export PKG_CONFIG_PATH="$FFMPEG_PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
  export DYLD_LIBRARY_PATH="$FFMPEG_PREFIX/lib:\${DYLD_LIBRARY_PATH:-}"

Generate test clip:
  export PATH="$FFMPEG_PREFIX/bin:\$PATH"
  ./scripts/gen_hevc_annexb.sh $XQUIC_BUILD_DIR/test_cam0.h265

Send to Linux receiver:
  $XQUIC_BUILD_DIR/xquic_tests/video_client -a <RECEIVER_IP> -p 8443 \\
    --cam0 $XQUIC_BUILD_DIR/test_cam0.h265 --codec hevc --fps 30

Incremental rebuild:
  ./scripts/build_macos_video_client.sh --skip-quictls --skip-ffmpeg
EOF
