#!/usr/bin/env bash
# Shared logic for WSL video E2E (invoked by wsl_video_e2e*.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build_wsl}"
PORT="${PORT:-8443}"
CODEC="${CODEC:-hevc}"
# cuda | vaapi | off | auto — set by wrapper scripts
HW_BACKEND="${HW_BACKEND:-cuda}"

export PKG_CONFIG_PATH="${FFMPEG_HW:-$HOME/ffmpeg-hw}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="${FFMPEG_HW:-$HOME/ffmpeg-hw}/lib:${LD_LIBRARY_PATH:-}"
ENABLE_DISPLAY="${ENABLE_DISPLAY:-1}"
if [[ "$ENABLE_DISPLAY" != "0" ]]; then
  export DISPLAY="${DISPLAY:-:0}"
fi

case "$HW_BACKEND" in
  cuda)
    export XQC_HW_DECODE=cuda
    HW_FLAGS="--hw-decode=cuda"
  ;;
  vaapi)
    export XQC_HW_DECODE=vaapi
    export XQC_VA_DEVICE="${XQC_VA_DEVICE:-/dev/dri/renderD128}"
    HW_FLAGS="--hw-decode=vaapi"
  ;;
  auto)
    export XQC_HW_DECODE=auto
    HW_FLAGS="--hw-decode=auto"
  ;;
  off|software|sw)
    export XQC_HW_DECODE=off
    HW_FLAGS=""
  ;;
  *)
    echo "ERROR: HW_BACKEND must be cuda|vaapi|auto|off (got: $HW_BACKEND)" >&2
    exit 1
  ;;
esac

HW_DECODE="${HW_DECODE:-ON}"
CMAKE_HW=()
if [[ "$HW_DECODE" == "ON" && -n "$HW_FLAGS" ]]; then
  CMAKE_HW=(-DXQC_ENABLE_HW_DECODE=ON)
fi

echo "== E2E matrix: codec=$CODEC hw_backend=$HW_BACKEND DISPLAY=$DISPLAY =="

cmake -S "$ROOT" -B "$BUILD" \
  -DXQC_ENABLE_TESTING=ON \
  -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON \
  "${CMAKE_HW[@]}" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build "$BUILD" --target xqc_video_receiver video_client xqc_h264_decode_smoke -j"$(nproc)"

RECV="$BUILD/xquic_tests/xqc_video_receiver"
CLIENT="$BUILD/xquic_tests/video_client"
SMOKE="$BUILD/xquic_tests/xqc_h264_decode_smoke"
CERT="$ROOT/tests/server.crt"
KEY="$ROOT/tests/server.key"

if [[ "$CODEC" == "hevc" || "$CODEC" == "h265" ]]; then
  BITSTREAM="$BUILD/test_cam0.h265"
  RECV_CODEC="hevc"
else
  BITSTREAM="$BUILD/test_cam0.h264"
  RECV_CODEC="h264"
fi

OUT="$BUILD/video_out_${HW_BACKEND}"
mkdir -p "$OUT"

pick_ffmpeg_encoder() {
  local encoder="$1"
  local c
  for c in "${FFMPEG_HW:-$HOME/ffmpeg-hw}/bin/ffmpeg" "$(command -v ffmpeg 2>/dev/null)"; do
    [[ -x "$c" ]] || continue
    if "$c" -hide_banner -encoders 2>/dev/null | grep -qE "(^|[[:space:]])${encoder}"; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

gen_test_bitstream() {
  local out="$1"
  local enc encoder
  if [[ "$RECV_CODEC" == "hevc" ]]; then
    encoder="libx265"
  else
    encoder="libx264"
  fi
  enc="$(pick_ffmpeg_encoder "$encoder")" || {
    echo "ERROR: no ffmpeg with ${encoder}" >&2
    return 1
  }
  if [[ "$RECV_CODEC" == "hevc" ]]; then
    "$enc" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
      -c:v libx265 -pix_fmt yuv420p -x265-params keyint=15:min-keyint=15 -an -f hevc "$out"
  else
    "$enc" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
      -c:v libx264 -profile:v baseline -pix_fmt yuv420p -g 15 -an -f h264 "$out"
  fi
}

[[ -f "$BITSTREAM" ]] || gen_test_bitstream "$BITSTREAM"

echo "== smoke ($RECV_CODEC) =="
"$SMOKE" "$BITSTREAM"

DISPLAY_FLAG=""
if [[ "$ENABLE_DISPLAY" != "0" && -n "${DISPLAY:-}" ]]; then
  DISPLAY_FLAG="--display"
fi
if [[ "$DISPLAY_FLAG" == "--display" ]] && ! pkg-config --exists glfw3 2>/dev/null; then
  DISPLAY_FLAG=""
fi

EOS_FLAGS="${EOS_FLAGS:-}"

echo "== receiver: port=$PORT out=$OUT hw=$HW_BACKEND =="
"$RECV" -p "$PORT" -c "$CERT" -k "$KEY" --video-dir "$OUT" --decode $DISPLAY_FLAG \
  --codec "$RECV_CODEC" $HW_FLAGS $EOS_FLAGS &
RECV_PID=$!
sleep 1
trap 'kill "$RECV_PID" 2>/dev/null || true' EXIT

FPS="${FPS:-0}"
timeout 20 "$CLIENT" -a 127.0.0.1 -p "$PORT" --cam0 "$BITSTREAM" --codec "$RECV_CODEC" --fps "$FPS" || true
sleep 1
kill "$RECV_PID" 2>/dev/null || true
wait "$RECV_PID" 2>/dev/null || true

REC_FILE="$OUT/cam_0.$( [[ "$RECV_CODEC" == hevc ]] && echo h265 || echo h264 )"
echo "== done $OUT =="
ls -la "$OUT" || true
[[ -f "$REC_FILE" ]] && ffprobe -v error -select_streams v:0 \
  -show_entries stream=codec_name,width,height -of csv=p=0 "$REC_FILE" 2>/dev/null || true

echo ""
echo "== expect logs =="
case "$HW_BACKEND" in
  cuda)
    echo "  [hw] CUDA/NVDEC ready ... hevc=yes"
    echo "  [gl] GLX context (PBO upload, hevc_cuvid path)"
    echo "  [decode] camera codec=hevc backend=cuda+pbo"
    ;;
  vaapi)
    echo "  [hw] VAAPI ready device=..."
    echo "  [gl] EGL context (VAAPI dma-buf display)"
    echo "  [decode] camera codec=hevc backend=vaapi+egl"
    ;;
  off)
    echo "  [decode] camera codec=hevc backend=software"
    ;;
esac
