#!/usr/bin/env bash
# WSL end-to-end: video_client -> xqc_video_receiver (--decode [--display])
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build_wsl}"
PORT="${PORT:-8443}"
CODEC="${CODEC:-hevc}"

echo "== deps (Ubuntu/Debian) =="
echo "  sudo apt install -y build-essential cmake pkg-config libevent-dev \\"
echo "    libavcodec-dev libavutil-dev libswscale-dev libavformat-dev \\"
echo "    libglfw3-dev libgl1-mesa-dev libva-dev libegl-dev mesa-va-drivers \\"
echo "    libx264-dev libx265-dev"

if ! pkg-config --exists libavcodec 2>/dev/null; then
  echo "ERROR: libavcodec not found. Install ffmpeg dev packages." >&2
  exit 1
fi

echo "== configure =="
HW_DECODE="${HW_DECODE:-OFF}"
CMAKE_HW=()
if [[ "${HW_DECODE}" == "ON" ]]; then
  CMAKE_HW=(-DXQC_ENABLE_HW_DECODE=ON)
  echo "== hw decode: ON (VAAPI/CUDA HEVC+H.264) =="
fi

cmake -S "$ROOT" -B "$BUILD" \
  -DXQC_ENABLE_TESTING=ON \
  -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON \
  "${CMAKE_HW[@]}" \
  -DCMAKE_BUILD_TYPE=Release

echo "== build =="
cmake --build "$BUILD" --target xqc_video_receiver video_client xqc_h264_decode_smoke -j"$(nproc)"

RECV="$BUILD/xquic_tests/xqc_video_receiver"
CLIENT="$BUILD/xquic_tests/video_client"
SMOKE="$BUILD/xquic_tests/xqc_h264_decode_smoke"
CERT="$ROOT/tests/server.crt"
KEY="$ROOT/tests/server.key"
OUT="$BUILD/video_out"

if [[ "$CODEC" == "hevc" || "$CODEC" == "h265" ]]; then
  BITSTREAM="$BUILD/test_cam0.h265"
  RECV_CODEC="hevc"
else
  BITSTREAM="$BUILD/test_cam0.h264"
  RECV_CODEC="h264"
fi

mkdir -p "$OUT"

# Pick ffmpeg that actually has the test encoder (bundled hw first, then system).
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
  if ! enc="$(pick_ffmpeg_encoder "$encoder")"; then
    echo "ERROR: no ffmpeg with ${encoder}." >&2
    echo "  sudo apt install libx265-dev libx264-dev" >&2
    echo "  bash scripts/build_ffmpeg_hw_linux.sh --prefix \"\$HOME/ffmpeg-hw\"" >&2
    echo "  (or use CODEC=h264 if you only need H.264 E2E)" >&2
    return 1
  fi
  if [[ "$enc" != "${FFMPEG_HW:-$HOME/ffmpeg-hw}/bin/ffmpeg" ]]; then
    echo "NOTE: using $enc for test clip ($encoder); rebuild ffmpeg-hw to encode with bundled ffmpeg" >&2
  fi
  if [[ "$RECV_CODEC" == "hevc" ]]; then
    echo "== generate test HEVC ($enc) =="
    "$enc" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
      -c:v libx265 -pix_fmt yuv420p -x265-params keyint=15:min-keyint=15 -an \
      -f hevc "$out"
  else
    echo "== generate test H.264 ($enc) =="
    "$enc" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
      -c:v libx264 -profile:v baseline -pix_fmt yuv420p -g 15 -an -f h264 "$out"
  fi
}

if [[ ! -f "$BITSTREAM" ]]; then
  gen_test_bitstream "$BITSTREAM" || exit 1
fi

echo "== decode smoke (Annex-B file, codec=$RECV_CODEC) =="
"$SMOKE" "$BITSTREAM" || { echo "decode smoke failed" >&2; exit 1; }

DISPLAY_FLAG=""
if [[ "${DISPLAY:-}" != "" ]] && pkg-config --exists glfw3 2>/dev/null; then
  DISPLAY_FLAG="--display"
fi
DECODE_FLAGS="--decode"
EOS_FLAGS="${EOS_FLAGS:-}"
HW_FLAGS=""
if [[ "${HW_DECODE}" == "ON" ]]; then
  HW_FLAGS="--hw-decode=auto"
fi
echo "== start receiver (port $PORT, codec=$RECV_CODEC, hw=${HW_FLAGS:-off}) =="
"$RECV" -p "$PORT" -c "$CERT" -k "$KEY" --video-dir "$OUT" $DECODE_FLAGS $DISPLAY_FLAG \
  --codec "$RECV_CODEC" $HW_FLAGS $EOS_FLAGS &
RECV_PID=$!
sleep 1

cleanup() {
  kill "$RECV_PID" 2>/dev/null || true
}
trap cleanup EXIT

FPS="${FPS:-0}"
echo "== send video (codec=$RECV_CODEC, --fps ${FPS}) =="
timeout 20 "$CLIENT" -a 127.0.0.1 -p "$PORT" --cam0 "$BITSTREAM" --codec "$RECV_CODEC" --fps "$FPS" || true

sleep 1
kill "$RECV_PID" 2>/dev/null || true
wait "$RECV_PID" 2>/dev/null || true

echo "== done; output under $OUT =="
ls -la "$OUT" || true
if [[ "$RECV_CODEC" == "hevc" ]]; then
  REC_FILE="$OUT/cam_0.h265"
else
  REC_FILE="$OUT/cam_0.h264"
fi
if [[ -f "$REC_FILE" ]]; then
  echo "== decode check (ffprobe) =="
  ffprobe -v error -select_streams v:0 -show_entries stream=codec_name,width,height -of csv=p=0 "$REC_FILE" 2>/dev/null || true
fi

# Optional dual-stack: CODEC=h264 smoke if file exists
if [[ -f "$BUILD/test_cam0.h264" && "$RECV_CODEC" == "hevc" ]]; then
  echo "== H.264 dual-stack smoke =="
  "$SMOKE" "$BUILD/test_cam0.h264" || true
fi
