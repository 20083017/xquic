#!/usr/bin/env bash
# Build FFmpeg (shared) with VAAPI + optional CUDA/NVDEC/NVENC for xquic low-latency receiver.
#
# Typical use (WSL2 / Ubuntu 22.04+ with Intel/AMD VAAPI and/or NVIDIA passthrough):
#   sudo apt install -y build-essential git pkg-config yasm nasm \
#     libva-dev libva-drm2 libdrm-dev libegl-dev libgl1-mesa-dev libx264-dev libx265-dev
#   # NVIDIA (optional): CUDA toolkit matching your driver
#   sudo apt install -y nvidia-cuda-toolkit   # or install from NVIDIA .run / cuda repo
#
# NVIDIA NVDEC (hevc_cuvid / h264_cuvid): nv-codec-headers are auto-installed when missing
#   (local prefix: ~/local/nv-codec-headers by default; override with NV_CODEC_PREFIX).
#   ./scripts/build_ffmpeg_hw_linux.sh --prefix "$HOME/ffmpeg-hw"
#
# Use your own FFmpeg tree (e.g. ~/ffmpeg or ~/FFmpeg) and apt CUDA under /usr:
#   ./scripts/build_ffmpeg_hw_linux.sh --ffmpeg-src "$HOME/ffmpeg" --prefix "$HOME/ffmpeg-hw"
#   # or omit --ffmpeg-src if ~/ffmpeg/configure exists (auto-detected)
#   # apt nvidia-cuda-toolkit: nvcc in /usr/bin, headers in /usr/include — auto-detected
#
# Point xquic at this build:
#   export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
#   cmake -S . -B build_wsl -DXQC_ENABLE_TESTING=ON \
#     -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON -DXQC_ENABLE_HW_DECODE=ON
#
# Verify decoders:
#   "$HOME/ffmpeg-hw/bin/ffmpeg" -hide_banner -decoders 2>/dev/null | grep -E 'h264_vaapi|h264_cuvid|hevc_cuvid'
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="${BUILD_ROOT:-$ROOT/build/ffmpeg-src}"
PREFIX="${PREFIX:-$HOME/ffmpeg-hw}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
FFMPEG_TAG="${FFMPEG_TAG:-n6.1.2}"
ENABLE_CUDA=1
ENABLE_VAAPI=1
ENABLE_X264=1
ENABLE_X265=1
ENABLE_PROGRAMS=1
SHARED=1
FFMPEG_SRC_OVERRIDE="${FFMPEG_SRC_OVERRIDE:-${FFMPEG_SRC:-}}"
SKIP_NV_CODEC_HEADERS=0
NV_CODEC_PREFIX="${NV_CODEC_PREFIX:-$HOME/local/nv-codec-headers}"

usage() {
    cat <<'EOF'
Usage: build_ffmpeg_hw_linux.sh [options]

  --prefix PATH       Install prefix (default: ~/ffmpeg-hw)
  --build-dir PATH    Clone directory when not using --ffmpeg-src
  --ffmpeg-src PATH   Existing FFmpeg source (e.g. ~/ffmpeg); skips git clone
  --tag TAG           Git tag to checkout (only with clone or existing git repo)
  --cuda-home PATH    Force CUDA root (default: auto: /usr/local/cuda or /usr)
  --jobs N            Parallel make jobs
  --no-cuda           Skip CUDA/NVDEC/NVENC (VAAPI-only build)
  --skip-nv-codec-headers  Do not auto-install nv-codec-headers (CUDA may lack cuvid)
  --no-vaapi          Skip VAAPI
  --no-x264           Skip libx264 encoder (H.264 test clips)
  --no-x265           Skip libx265 encoder (HEVC test clips)
  --static            Build static libs (default: shared)
  --no-programs       Do not build ffmpeg/ffprobe binaries
  -h, --help          This help

Environment:
  FFMPEG_SRC          Same as --ffmpeg-src (optional)
  CUDA_HOME           Optional hint (auto-detect prefers nvcc on PATH)
  NV_CODEC_PREFIX     Install prefix for nv-codec-headers (default: ~/local/nv-codec-headers)
  NV_CODEC_SRC        Clone dir for nv-codec-headers (default: build/ffmpeg-src/nv-codec-headers)
  PKG_CONFIG_PATH     Prepended with nv-codec + FFmpeg pkgconfig on success

Auto-detected source trees (when --ffmpeg-src omitted):
  ~/ffmpeg, ~/FFmpeg  (must contain configure)

CUDA layouts supported:
  - NVIDIA runfile:  /usr/local/cuda/{bin/nvcc,include,lib64}
  - apt toolkit:     /usr/bin/nvcc, /usr/include/cuda.h, libs in /usr/lib/x86_64-linux-gnu

After install, rebuild xquic with PKG_CONFIG_PATH set so pkg-config finds libavcodec.
EOF
}

log() { printf '[ffmpeg-build] %s\n' "$*"; }
die() { printf '[ffmpeg-build] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --build-dir) BUILD_ROOT="$2"; shift 2 ;;
        --ffmpeg-src) FFMPEG_SRC_OVERRIDE="$2"; shift 2 ;;
        --tag) FFMPEG_TAG="$2"; shift 2 ;;
        --cuda-home) CUDA_HOME="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --no-cuda) ENABLE_CUDA=0; shift ;;
        --skip-nv-codec-headers) SKIP_NV_CODEC_HEADERS=1; shift ;;
        --no-vaapi) ENABLE_VAAPI=0; shift ;;
        --no-x264) ENABLE_X264=0; shift ;;
        --no-x265) ENABLE_X265=0; shift ;;
        --static) SHARED=0; shift ;;
        --no-programs) ENABLE_PROGRAMS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

mkdir -p "$BUILD_ROOT" "$PREFIX"
PREFIX="$(cd "$PREFIX" && pwd)"

# --- CUDA detection (apt /usr vs /usr/local/cuda) ---
detect_cuda_paths() {
    NVCC_PATH=""
    CUDA_INC_DIRS=()
    CUDA_LIB_DIRS=()

    local hint="${CUDA_HOME:-}"
    if [[ -n "$hint" && -x "$hint/bin/nvcc" ]]; then
        NVCC_PATH="$hint/bin/nvcc"
    elif command -v nvcc >/dev/null 2>&1; then
        NVCC_PATH="$(command -v nvcc)"
    elif [[ -x /usr/local/cuda/bin/nvcc ]]; then
        NVCC_PATH="/usr/local/cuda/bin/nvcc"
    fi

    if [[ -z "$NVCC_PATH" ]]; then
        return 1
    fi

    log "CUDA: nvcc=$NVCC_PATH"
    nvcc --version 2>/dev/null | head -3 | sed 's/^/[ffmpeg-build]   /' || true

    # Headers: apt often installs cuda.h directly under /usr/include
    if [[ -f /usr/include/cuda.h ]]; then
        CUDA_INC_DIRS+=(/usr/include)
        log "CUDA: headers in /usr/include (apt layout)"
    fi
    local cuda_root
    cuda_root="$(dirname "$(dirname "$NVCC_PATH")")"
    if [[ -f "$cuda_root/include/cuda.h" ]]; then
        CUDA_INC_DIRS+=("$cuda_root/include")
        log "CUDA: headers in $cuda_root/include"
    fi

    # Lib dirs (dedupe)
    local d
    for d in /usr/lib/x86_64-linux-gnu "$cuda_root/lib64" "$cuda_root/lib" /usr/lib64; do
        if [[ -d "$d" ]] && { ls "$d"/libcuda.so* >/dev/null 2>&1 || ls "$d"/libcudart.so* >/dev/null 2>&1; }; then
            CUDA_LIB_DIRS+=("$d")
        fi
    done
    if [[ ${#CUDA_LIB_DIRS[@]} -eq 0 ]]; then
        for d in /usr/lib/x86_64-linux-gnu "$cuda_root/lib64" "$cuda_root/lib"; do
            [[ -d "$d" ]] && CUDA_LIB_DIRS+=("$d")
        done
    fi
    log "CUDA: lib dirs: ${CUDA_INC_DIRS[*]:-<system default>}"
    return 0
}

nv_codec_pkg_config_path() {
    local prefix="$1"
    echo "$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
}

nv_codec_headers_usable() {
    local prefix="$1"
    [[ -f "$prefix/include/ffnvcodec/nvEncodeAPI.h" ]] || return 1
    [[ -f "$prefix/lib/pkgconfig/ffnvcodec.pc" ]] || return 1
    PKG_CONFIG_PATH="$(nv_codec_pkg_config_path "$prefix")" \
        pkg-config --exists 'ffnvcodec >= 8.1.24.15' 2>/dev/null
}

export_nv_codec_pkg_config() {
    export PKG_CONFIG_PATH="$(nv_codec_pkg_config_path "$NV_CODEC_PREFIX")"
}

ffnvcodec_modversion() {
    PKG_CONFIG_PATH="$(nv_codec_pkg_config_path "$1")" \
        pkg-config --modversion ffnvcodec 2>/dev/null || echo unknown
}

ensure_nv_codec_headers() {
    local prefix src
    prefix="$(mkdir -p "$NV_CODEC_PREFIX" && cd "$NV_CODEC_PREFIX" && pwd)"
    NV_CODEC_PREFIX="$prefix"
    src="${NV_CODEC_SRC:-$BUILD_ROOT/nv-codec-headers}"

    if nv_codec_headers_usable "$NV_CODEC_PREFIX"; then
        export_nv_codec_pkg_config
        log "nv-codec-headers: OK (ffnvcodec $(ffnvcodec_modversion "$NV_CODEC_PREFIX") @ $NV_CODEC_PREFIX)"
        return 0
    fi

    if [[ "$SKIP_NV_CODEC_HEADERS" -eq 1 ]]; then
        log "nv-codec-headers: missing (--skip-nv-codec-headers; NVDEC may be unavailable)"
        return 0
    fi

    mkdir -p "$(dirname "$src")"
    if [[ ! -f "$src/Makefile" ]]; then
        log "nv-codec-headers: cloning into $src"
        git clone --depth 1 git@github.com:FFmpeg/nv-codec-headers.git "$src"
    fi
    [[ -f "$src/Makefile" ]] || die "nv-codec-headers source missing Makefile: $src"

    if [[ -f "$NV_CODEC_PREFIX/include/ffnvcodec/nvEncodeAPI.h" ]]; then
        log "nv-codec-headers: repairing install in $NV_CODEC_PREFIX"
    else
        log "nv-codec-headers: installing to $NV_CODEC_PREFIX"
    fi
    make -C "$src" install PREFIX="$NV_CODEC_PREFIX"

    nv_codec_headers_usable "$NV_CODEC_PREFIX" || die \
        "nv-codec-headers install failed (expected $NV_CODEC_PREFIX/lib/pkgconfig/ffnvcodec.pc)"

    export_nv_codec_pkg_config
    log "nv-codec-headers: ready (ffnvcodec $(ffnvcodec_modversion "$NV_CODEC_PREFIX"))"
}

if [[ "$ENABLE_CUDA" -eq 1 ]]; then
    if ! detect_cuda_paths; then
        log "CUDA not found; use --no-cuda for VAAPI-only, or: sudo apt install nvidia-cuda-toolkit"
        ENABLE_CUDA=0
    fi
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

need_cmd git
need_cmd pkg-config
need_cmd make
need_cmd gcc
need_cmd g++

resolve_ffmpeg_src_override() {
    if [[ -n "$FFMPEG_SRC_OVERRIDE" ]]; then
        return 0
    fi
    local candidate
    for candidate in "$HOME/ffmpeg" "$HOME/FFmpeg"; do
        if [[ -f "$candidate/configure" ]]; then
            FFMPEG_SRC_OVERRIDE="$candidate"
            log "auto-detected FFmpeg source: $FFMPEG_SRC_OVERRIDE"
            return 0
        fi
    done
    return 0
}

resolve_ffmpeg_src_override

if [[ -n "$FFMPEG_SRC_OVERRIDE" ]]; then
    FFMPEG_SRC="$(cd "$FFMPEG_SRC_OVERRIDE" && pwd)"
    log "using existing FFmpeg source: $FFMPEG_SRC"
    if [[ -d "$FFMPEG_SRC/.git" ]] && [[ -n "$FFMPEG_TAG" ]]; then
        log "checkout tag $FFMPEG_TAG (optional)"
        git -C "$FFMPEG_SRC" fetch --tags origin 2>/dev/null || true
        git -C "$FFMPEG_SRC" checkout "$FFMPEG_TAG" 2>/dev/null || log "skip checkout (stay on current branch)"
    fi
else
    FFMPEG_SRC="$BUILD_ROOT/FFmpeg"
    if [[ ! -d "$FFMPEG_SRC/.git" ]]; then
        log "cloning FFmpeg into $FFMPEG_SRC"
        git clone --depth 1 --branch "$FFMPEG_TAG" https://github.com/FFmpeg/FFmpeg.git "$FFMPEG_SRC"
    else
        log "updating FFmpeg ($FFMPEG_TAG)"
        git -C "$FFMPEG_SRC" fetch --tags origin
        git -C "$FFMPEG_SRC" checkout "$FFMPEG_TAG"
    fi
fi

[[ -f "$FFMPEG_SRC/configure" ]] || die "not an FFmpeg source tree: $FFMPEG_SRC (missing configure)"

cd "$FFMPEG_SRC"

# Pick CUDA-related ./configure flags for this FFmpeg version (n4.x vs n6.x differ).
append_cuda_configure_flags() {
    local help
    help="$(./configure --help 2>&1 || true)"

    export PATH="$(dirname "$NVCC_PATH"):${PATH}"

    if grep -qE '[[:space:]]--enable-cuda-nvcc[[:space:]]' <<<"$help"; then
        # FFmpeg 5+/6+: boolean flag only — nvcc must be on PATH (not --enable-cuda-nvcc=/path)
        CONFIGURE+=(--enable-cuda-nvcc)
        log "CUDA configure: --enable-cuda-nvcc (using nvcc on PATH)"
    elif grep -qE '[[:space:]]--enable-cuda[[:space:]]' <<<"$help"; then
        CONFIGURE+=(--enable-cuda)
        log "CUDA configure: --enable-cuda (legacy FFmpeg 4.x style)"
    else
        die "this FFmpeg tree has no --enable-cuda-nvcc / --enable-cuda; try --tag n6.1.2"
    fi

    for flag in cuvid nvdec nvenc; do
        if grep -qE "[[:space:]]--enable-${flag}[[:space:]]" <<<"$help"; then
            CONFIGURE+=(--enable-"$flag")
            log "CUDA configure: --enable-$flag"
        elif grep -qE "[[:space:]]--disable-${flag}[[:space:]]" <<<"$help"; then
            log "CUDA configure: $flag autodetect (FFmpeg 6.x; requires ffnvcodec / nv-codec-headers)"
        else
            log "CUDA configure: $flag not exposed by this FFmpeg configure script"
        fi
    done

    CONFIGURE+=(
        --enable-decoder=h264_cuvid
        --enable-decoder=hevc_cuvid
        --enable-bsf=h264_mp4toannexb
        --enable-bsf=hevc_mp4toannexb
    )
    log "CUDA configure: h264_cuvid/hevc_cuvid + mp4toannexb bsfs"
}

verify_cuda_configure() {
    local mak="ffbuild/config.mak"
    [[ -f "$mak" ]] || die "missing $mak after ./configure"
    local key
    for key in CONFIG_FFNVCODEC CONFIG_CUVID CONFIG_NVDEC \
        CONFIG_H264_CUVID_DECODER CONFIG_HEVC_CUVID_DECODER; do
        if grep -q "^${key}=yes\$" "$mak"; then
            log "configure OK: $key"
        else
            die "configure did not enable $key (PKG_CONFIG_PATH=${PKG_CONFIG_PATH:-<unset>}); see ffbuild/config.log"
        fi
    done
}

EXTRA_LDFLAGS=()
EXTRA_CFLAGS=(-fPIC)
CONFIGURE=(
    --prefix="$PREFIX"
    --enable-gpl
    --enable-nonfree
    --disable-debug
    --disable-stripping
)

if [[ "$SHARED" -eq 1 ]]; then
    CONFIGURE+=(--enable-shared --disable-static)
else
    CONFIGURE+=(--enable-static --disable-shared)
    EXTRA_LDFLAGS+=( -static-libgcc )
fi

if [[ "$ENABLE_PROGRAMS" -eq 1 ]]; then
    CONFIGURE+=(--enable-ffmpeg --enable-ffprobe)
else
    CONFIGURE+=(--disable-ffmpeg --disable-ffprobe)
fi

# Low-latency receiver: H.264 now; HEVC optional for future NVDEC tests
CONFIGURE+=(
    --enable-decoder=h264
    --enable-decoder=hevc
    --enable-parser=h264
    --enable-parser=hevc
    --enable-demuxer=h264
    --enable-demuxer=hevc
    --enable-protocol=file
)

if [[ "$ENABLE_X265" -eq 1 ]]; then
    if pkg-config --exists x265 2>/dev/null; then
        CONFIGURE+=(--enable-libx265)
        log "libx265: enabled (pkg-config x265 $(pkg-config --modversion x265 2>/dev/null || echo '?'))"
    else
        log "libx265: libx265-dev not found — install: sudo apt install libx265-dev"
        log "libx265: skipped (HEVC test clips need rebuild after installing x265-dev)"
    fi
fi

if [[ "$ENABLE_X264" -eq 1 ]]; then
    if pkg-config --exists x264 2>/dev/null; then
        CONFIGURE+=(--enable-libx264)
        log "libx264: enabled (generate test .h264 with bundled ffmpeg)"
    else
        log "libx264: libx264-dev not found — install it or use --no-x264 / system ffmpeg for encoding"
        die "missing libx264 (sudo apt install libx264-dev)"
    fi
fi

if [[ "$ENABLE_VAAPI" -eq 1 ]]; then
    if pkg-config --exists libva libva-drm libdrm 2>/dev/null; then
        CONFIGURE+=(
            --enable-vaapi
            --enable-libdrm
        )
        log "VAAPI: enabled (libva + libdrm found)"
    else
        log "VAAPI: requested but libva/libdrm not found — install libva-dev libva-drm2 libdrm-dev"
        die "VAAPI deps missing (use --no-vaapi to skip)"
    fi
fi

if [[ "$ENABLE_CUDA" -eq 1 ]]; then
    ensure_nv_codec_headers
    append_cuda_configure_flags
    export_nv_codec_pkg_config
    log "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
    for inc in "${CUDA_INC_DIRS[@]}"; do
        EXTRA_CFLAGS+=( "-I$inc" )
    done
    if [[ -d "$NV_CODEC_PREFIX/include" ]]; then
        EXTRA_CFLAGS+=( "-I$NV_CODEC_PREFIX/include" )
    fi
    for libd in "${CUDA_LIB_DIRS[@]}"; do
        EXTRA_LDFLAGS+=( "-L$libd" "-Wl,-rpath,$libd" )
    done
    if [[ -d "$NV_CODEC_PREFIX/lib" ]]; then
        EXTRA_LDFLAGS+=( "-L$NV_CODEC_PREFIX/lib" "-Wl,-rpath,$NV_CODEC_PREFIX/lib" )
    fi
    log "CUDA: extra flags for nvcc=$NVCC_PATH"
fi

# Re-run configure from clean state when switching flags
if [[ -f config.h ]]; then
    make distclean >/dev/null 2>&1 || true
fi

log "configure: ${CONFIGURE[*]}"
./configure \
    "${CONFIGURE[@]}" \
    --extra-cflags="${EXTRA_CFLAGS[*]}" \
    --extra-ldflags="${EXTRA_LDFLAGS[*]}"

if [[ "$ENABLE_CUDA" -eq 1 ]]; then
    verify_cuda_configure
fi

log "building ($JOBS jobs)…"
make -j"$JOBS"
make install

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

verify_decoder() {
    local name="$1"
    local required="${2:-0}"
    local cfg_key="CONFIG_$(echo "$name" | tr '[:lower:]' '[:upper:]')_DECODER"

    if [[ -f ffbuild/config.mak ]] && grep -q "^${cfg_key}=yes\$" ffbuild/config.mak; then
        log "decoder OK: $name (config.mak)"
        return 0
    fi

    if [[ -x "$PREFIX/bin/ffmpeg" ]]; then
        if LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
            "$PREFIX/bin/ffmpeg" -hide_banner -decoders 2>/dev/null | grep -Fw "$name" >/dev/null; then
            log "decoder OK: $name"
            return 0
        fi
    fi
    if [[ "$required" -eq 1 ]]; then
        die "decoder MISSING (required for CUDA/NVDEC): $name — check nv-codec-headers and re-run configure"
    fi
    log "decoder MISSING (optional): $name"
    return 1
}

verify_hwaccel() {
    local name="$1"
    if [[ -f ffbuild/config.mak ]] && grep -q "^CONFIG_CUDA=yes\$" ffbuild/config.mak; then
        log "hwaccel OK: $name (config.mak CONFIG_CUDA)"
        return 0
    fi
    if [[ -x "$PREFIX/bin/ffmpeg" ]]; then
        if LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
            "$PREFIX/bin/ffmpeg" -hide_banner -hwaccels 2>/dev/null | grep -Fw "$name" >/dev/null; then
            log "hwaccel OK: $name"
            return 0
        fi
    fi
    die "hwaccel MISSING (required for CUDA/NVDEC): $name"
}

log "install complete: $PREFIX"
log "export PKG_CONFIG_PATH=$PKG_CONFIG_PATH"

[[ "$ENABLE_VAAPI" -eq 1 ]] && verify_decoder h264_vaapi || true
[[ "$ENABLE_VAAPI" -eq 1 ]] && verify_decoder hevc_vaapi || true
if [[ "$ENABLE_CUDA" -eq 1 ]]; then
    verify_hwaccel cuda
    verify_decoder h264_cuvid 1
    verify_decoder hevc_cuvid 1
fi

if [[ "$ENABLE_PROGRAMS" -eq 1 ]]; then
    if [[ "$ENABLE_X264" -eq 1 ]] && [[ -x "$PREFIX/bin/ffmpeg" ]] \
        && "$PREFIX/bin/ffmpeg" -hide_banner -encoders 2>/dev/null | grep -q libx264; then
        log "encoder OK: libx264"
    fi
    if [[ "$ENABLE_X265" -eq 1 ]] && [[ -x "$PREFIX/bin/ffmpeg" ]] \
        && "$PREFIX/bin/ffmpeg" -hide_banner -encoders 2>/dev/null | grep -q libx265; then
        log "encoder OK: libx265"
    fi
fi

cat <<EOF

----------------------------------------------------------------------
Next: rebuild xquic against this FFmpeg

  export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
  cmake -S "$ROOT" -B "$ROOT/build_wsl" \\
    -DXQC_ENABLE_TESTING=ON \\
    -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON \\
    -DXQC_ENABLE_HW_DECODE=ON
  cmake --build "$ROOT/build_wsl" --target xqc_video_receiver video_client -j

Runtime (receiver):

  export LD_LIBRARY_PATH="$PREFIX/lib:\${LD_LIBRARY_PATH:-}"
  export XQC_HW_DECODE=auto
  ./build_wsl/xquic_tests/xqc_video_receiver ... --hw-decode=auto --decode --display

4K send (other host):

  ffmpeg -f lavfi -i testsrc=size=3840x2160:rate=30 -t 60 \\
    -c:v libx264 -preset ultrafast -profile:v high -pix_fmt yuv420p -g 30 -an \\
    -f h264 cam4k.h264
  ./video_client -a <RECEIVER_IP> -p 8443 --cam0 cam4k.h264 --fps 30
----------------------------------------------------------------------
EOF
