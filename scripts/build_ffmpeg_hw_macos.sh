#!/usr/bin/env bash
# Build FFmpeg (shared) with VideoToolbox + libx265/libx264 for macOS HEVC client (send path).
#
# Typical use (macOS 12+, Apple Silicon or Intel, Homebrew):
#   brew install pkg-config nasm yasm x264 x265
#   ./scripts/build_ffmpeg_hw_macos.sh --prefix "$HOME/ffmpeg-hw"
#
# Use your own FFmpeg tree (e.g. ~/ffmpeg or ~/FFmpeg):
#   ./scripts/build_ffmpeg_hw_macos.sh --ffmpeg-src "$HOME/ffmpeg" --prefix "$HOME/ffmpeg-hw"
#
# Point xquic at this build (macOS client — no HW decode on receiver):
#   export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
#   cmake -S . -B build_macos -DXQC_ENABLE_TESTING=ON \
#     -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON -DXQC_ENABLE_HW_DECODE=OFF
#   cmake --build build_macos --target video_client -j
#
# Generate HEVC Annex-B test clip:
#   "$HOME/ffmpeg-hw/bin/ffmpeg" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
#     -c:v libx265 -pix_fmt yuv420p -x265-params keyint=15:min-keyint=15 -an -f hevc test.h265
#
# Verify encoders:
#   "$HOME/ffmpeg-hw/bin/ffmpeg" -hide_banner -encoders 2>/dev/null | grep -E 'libx265|hevc_videotoolbox'
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="${BUILD_ROOT:-$ROOT/build/ffmpeg-src}"
PREFIX="${PREFIX:-$HOME/ffmpeg-hw}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
FFMPEG_TAG="${FFMPEG_TAG:-n6.1.2}"
ENABLE_VIDEOTOOLBOX=1
ENABLE_X264=1
ENABLE_X265=1
ENABLE_PROGRAMS=1
SHARED=1
FFMPEG_SRC_OVERRIDE="${FFMPEG_SRC_OVERRIDE:-${FFMPEG_SRC:-}}"

usage() {
    cat <<'EOF'
Usage: build_ffmpeg_hw_macos.sh [options]

  --prefix PATH       Install prefix (default: ~/ffmpeg-hw)
  --build-dir PATH    Clone directory when not using --ffmpeg-src
  --ffmpeg-src PATH   Existing FFmpeg source (e.g. ~/ffmpeg); skips git clone
  --tag TAG           Git tag to checkout (only with clone or existing git repo)
  --jobs N            Parallel make jobs
  --no-videotoolbox   Skip VideoToolbox (software x265/x264 only)
  --no-x264           Skip libx264 encoder
  --no-x265           Skip libx265 encoder (HEVC test clips)
  --static            Build static libs (default: shared)
  --no-programs       Do not build ffmpeg/ffprobe binaries
  -h, --help          This help

Environment:
  FFMPEG_SRC          Same as --ffmpeg-src (optional)
  PKG_CONFIG_PATH     Prepended with Homebrew + $PREFIX/lib/pkgconfig on success

Homebrew deps (install before build):
  brew install pkg-config nasm yasm x264 x265

Auto-detected source trees (when --ffmpeg-src omitted):
  ~/ffmpeg, ~/FFmpeg  (must contain configure)

After install, rebuild xquic with PKG_CONFIG_PATH set so pkg-config finds libavcodec.
Runtime: export DYLD_LIBRARY_PATH="$PREFIX/lib:${DYLD_LIBRARY_PATH:-}"
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
        --jobs) JOBS="$2"; shift 2 ;;
        --no-videotoolbox) ENABLE_VIDEOTOOLBOX=0; shift ;;
        --no-x264) ENABLE_X264=0; shift ;;
        --no-x265) ENABLE_X265=0; shift ;;
        --static) SHARED=0; shift ;;
        --no-programs) ENABLE_PROGRAMS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "this script is for macOS only (use build_ffmpeg_hw_linux.sh on Linux)"

mkdir -p "$BUILD_ROOT" "$PREFIX"
PREFIX="$(cd "$PREFIX" && pwd)"

# Homebrew pkg-config (x264/x265 often live under opt/*)
prepend_brew_pkg_config() {
    if ! command -v brew >/dev/null 2>&1; then
        return 0
    fi
    local brew_prefix pc
    brew_prefix="$(brew --prefix)"
    pc="${PKG_CONFIG_PATH:-}"
    for d in \
        "$brew_prefix/lib/pkgconfig" \
        "$brew_prefix/opt/x265/lib/pkgconfig" \
        "$brew_prefix/opt/x264/lib/pkgconfig" \
        "$brew_prefix/opt/ffmpeg/lib/pkgconfig"
    do
        [[ -d "$d" ]] || continue
        pc="${d}${pc:+:$pc}"
    done
    export PKG_CONFIG_PATH="$pc"
}

prepend_brew_pkg_config

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1 (brew install $2)"
}

need_cmd git git
need_cmd pkg-config pkg-config
need_cmd make make
need_cmd clang clang

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
        if ! git -C "$FFMPEG_SRC" rev-parse "$FFMPEG_TAG" >/dev/null 2>&1; then
            git -C "$FFMPEG_SRC" fetch --tags origin 2>/dev/null || true
        fi
        git -C "$FFMPEG_SRC" checkout "$FFMPEG_TAG" 2>/dev/null || log "skip checkout (stay on current branch)"
    fi
else
    FFMPEG_SRC="$BUILD_ROOT/FFmpeg"
    if [[ ! -d "$FFMPEG_SRC/.git" ]]; then
        log "cloning FFmpeg into $FFMPEG_SRC"
        git clone --depth 1 --branch "$FFMPEG_TAG" https://github.com/FFmpeg/FFmpeg.git "$FFMPEG_SRC"
    else
        log "using cloned FFmpeg at $FFMPEG_SRC (checkout $FFMPEG_TAG if needed)"
        if ! git -C "$FFMPEG_SRC" rev-parse "$FFMPEG_TAG" >/dev/null 2>&1; then
            git -C "$FFMPEG_SRC" fetch --tags origin 2>/dev/null || log "skip fetch (offline or slow network)"
        fi
        git -C "$FFMPEG_SRC" checkout "$FFMPEG_TAG" 2>/dev/null || log "stay on current checkout"
    fi
fi

[[ -f "$FFMPEG_SRC/configure" ]] || die "not an FFmpeg source tree: $FFMPEG_SRC (missing configure)"

cd "$FFMPEG_SRC"

EXTRA_LDFLAGS=()
EXTRA_CFLAGS=()
CONFIGURE=(
    --prefix="$PREFIX"
    --enable-gpl
    --enable-version3
    --disable-debug
    --disable-stripping
)

if [[ "$SHARED" -eq 1 ]]; then
    CONFIGURE+=(--enable-shared --disable-static)
else
    CONFIGURE+=(--enable-static --disable-shared)
fi

if [[ "$ENABLE_PROGRAMS" -eq 1 ]]; then
    CONFIGURE+=(--enable-ffmpeg --enable-ffprobe)
else
    CONFIGURE+=(--disable-ffmpeg --disable-ffprobe)
fi

# HEVC client send path + decode smoke (software); VideoToolbox optional HW encode
CONFIGURE+=(
    --enable-decoder=h264
    --enable-decoder=hevc
    --enable-parser=h264
    --enable-parser=hevc
    --enable-demuxer=h264
    --enable-demuxer=hevc
    --enable-muxer=hevc
    --enable-protocol=file
)

if [[ "$ENABLE_X265" -eq 1 ]]; then
    if pkg-config --exists x265 2>/dev/null; then
        CONFIGURE+=(--enable-libx265)
        log "libx265: enabled (x265 $(pkg-config --modversion x265 2>/dev/null || echo '?'))"
    else
        die "libx265 not found — install: brew install x265 (then re-run)"
    fi
fi

if [[ "$ENABLE_X264" -eq 1 ]]; then
    if pkg-config --exists x264 2>/dev/null; then
        CONFIGURE+=(--enable-libx264)
        log "libx264: enabled (x264 $(pkg-config --modversion x264 2>/dev/null || echo '?'))"
    else
        log "libx264: not found — install: brew install x264 (or use --no-x264)"
        die "missing libx264 (brew install x264)"
    fi
fi

if [[ "$ENABLE_VIDEOTOOLBOX" -eq 1 ]]; then
    # FFmpeg macOS: VideoToolbox is autodetected unless --disable-videotoolbox
    log "VideoToolbox: autodetect (default on macOS; hevc_videotoolbox when built)"
fi

# Re-run configure from clean state when switching flags
if [[ -f config.h ]]; then
    make distclean >/dev/null 2>&1 || true
fi

log "configure: ${CONFIGURE[*]}"
if [[ ${#EXTRA_CFLAGS[@]} -gt 0 || ${#EXTRA_LDFLAGS[@]} -gt 0 ]]; then
    ./configure \
        "${CONFIGURE[@]}" \
        --extra-cflags="${EXTRA_CFLAGS[*]}" \
        --extra-ldflags="${EXTRA_LDFLAGS[*]}"
else
    ./configure "${CONFIGURE[@]}"
fi

log "building ($JOBS jobs)…"
make -j"$JOBS"
make install

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

verify_encoder() {
    local name="$1"
    if [[ -x "$PREFIX/bin/ffmpeg" ]]; then
        if "$PREFIX/bin/ffmpeg" -hide_banner -encoders 2>/dev/null | grep -qE "(^|[[:space:]])${name}([[:space:]]|$)"; then
            log "encoder OK: $name"
            return 0
        fi
    fi
    log "encoder MISSING (optional): $name"
    return 1
}

log "install complete: $PREFIX"
log "export PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
log "export DYLD_LIBRARY_PATH=$PREFIX/lib:\${DYLD_LIBRARY_PATH:-}"

[[ "$ENABLE_X265" -eq 1 ]] && verify_encoder libx265 || true
[[ "$ENABLE_X264" -eq 1 ]] && verify_encoder libx264 || true
[[ "$ENABLE_VIDEOTOOLBOX" -eq 1 ]] && verify_encoder hevc_videotoolbox || true

cat <<EOF

----------------------------------------------------------------------
Next: rebuild xquic (macOS client — send HEVC, no Linux HW decode)

  export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
  export DYLD_LIBRARY_PATH="$PREFIX/lib:\${DYLD_LIBRARY_PATH:-}"
  cmake -S "$ROOT" -B "$ROOT/build_macos" \\
    -DXQC_ENABLE_TESTING=ON \\
    -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON \\
    -DXQC_ENABLE_HW_DECODE=OFF
  cmake --build "$ROOT/build_macos" --target video_client -j

Generate test HEVC clip:

  export PATH="$PREFIX/bin:\$PATH"
  ./scripts/gen_hevc_annexb.sh build_macos/test_cam0.h265

Send to receiver (Linux/WSL with hevc_cuvid):

  ./build_macos/xquic_tests/video_client -a <RECEIVER_IP> -p 8443 \\
    --cam0 build_macos/test_cam0.h265 --codec hevc --fps 30
----------------------------------------------------------------------
EOF
