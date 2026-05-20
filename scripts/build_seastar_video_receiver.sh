#!/usr/bin/env bash
# Build Seastar video receiver: xqc_video_receiver_seastar
#
# Output:
#   build_seastar/xquic_tests/xqc_video_receiver  (+ symlink xqc_video_receiver_seastar)
#
# Usage:
#   bash scripts/build_seastar_video_receiver.sh
#   bash scripts/build_seastar_video_receiver.sh --skip-ffmpeg
#   bash scripts/build_seastar_video_receiver.sh --install-deps
#
# Run after build:
#   export LD_LIBRARY_PATH=~/ffmpeg-hw/lib:$LD_LIBRARY_PATH
#   export XQC_PIN_AFFINITY=1
#   ./build_seastar/xquic_tests/xqc_video_receiver \
#     --smp 1 --cpuset 0 -p 8443 --decode --display --codec hevc --hw-decode=cuda

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DEPS=0

usage() {
    cat <<'EOF'
Usage: build_seastar_video_receiver.sh [options]

Options:
  --install-deps     apt install Seastar + video deps (sudo)
  --skip-ffmpeg      Reuse ~/ffmpeg-hw (or FFMPEG_PREFIX)
  --ffmpeg-prefix D  FFmpeg install prefix (default: ~/ffmpeg-hw)
  -h, --help         Show help

First-time build (Ubuntu + NVIDIA):
  bash scripts/install_ubuntu_nvidia_deps.sh   # optional, full GPU stack
  bash scripts/build_seastar_video_receiver.sh

Incremental (code-only) rebuild:
  SKIP_FFMPEG=1 bash scripts/build_seastar_video_receiver.sh --skip-ffmpeg
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-deps) INSTALL_DEPS=1; shift ;;
        --skip-ffmpeg) export SKIP_FFMPEG=1; shift ;;
        --ffmpeg-prefix) export FFMPEG_PREFIX="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
    exec "$ROOT/build_seastar.sh" deps
fi

exec "$ROOT/build_seastar.sh" video
