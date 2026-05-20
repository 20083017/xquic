#!/usr/bin/env bash
# Generate Annex-B HEVC test clip (design: hevc_nvenc send / hevc_cuvid receive).
#
# Usage:
#   ./scripts/gen_hevc_annexb.sh OUT.h265                    # smoke: 320x240 (default)
#   ./scripts/gen_hevc_annexb.sh --4k build_macos/cam4k.h265   # 3840x2160 @ 30fps
#   WIDTH=3840 HEIGHT=2160 FPS=30 DURATION=60 GOP=30 \
#     ./scripts/gen_hevc_annexb.sh cam4k.h265
#
# Encoder priority: hevc_nvenc (NVIDIA) → hevc_videotoolbox (macOS) → libx265 → error.
set -euo pipefail

OUT=""
PROFILE="${PROFILE:-smoke}"

usage() {
  cat <<'EOF'
Usage: gen_hevc_annexb.sh [--4k|--smoke] OUT.h265

Profiles (override with env WIDTH HEIGHT FPS DURATION GOP):
  --smoke (default)  320x240  15fps  3s   — quick local QUIC smoke test
  --4k               3840x2160 60fps 60s  GOP=60 — cross-endpoint / receiver 4K path

Examples:
  ./scripts/gen_hevc_annexb.sh build_macos/test_cam0.h265
  ./scripts/gen_hevc_annexb.sh --4k build_macos/cam4k.h265
  WIDTH=3840 HEIGHT=2160 FPS=30 DURATION=60 GOP=30 ./scripts/gen_hevc_annexb.sh cam4k.h265

Send 4K:
  ./build_macos/xquic_tests/video_client -a <IP> -p 8443 \
    --cam0 build_macos/cam4k.h265 --codec hevc --fps 60
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --4k) PROFILE=4k; shift ;;
    --smoke) PROFILE=smoke; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
      [[ -z "$OUT" ]] || { echo "ERROR: multiple output paths" >&2; exit 1; }
      OUT="$1"
      shift
      ;;
  esac
done

OUT="${OUT:-build_wsl/test_cam0.h265}"

if [[ "$PROFILE" == "4k" ]]; then
  WIDTH="${WIDTH:-3840}"
  HEIGHT="${HEIGHT:-2160}"
  FPS="${FPS:-60}"
  DURATION="${DURATION:-60}"
  GOP="${GOP:-60}"
else
  WIDTH="${WIDTH:-320}"
  HEIGHT="${HEIGHT:-240}"
  FPS="${FPS:-15}"
  DURATION="${DURATION:-3}"
  GOP="${GOP:-$FPS}"
fi

# hevc_videotoolbox / nvenc bitrate hint from resolution
vt_bitrate() {
  local px=$((WIDTH * HEIGHT))
  if (( px >= 3840 * 2160 )); then echo "35M"
  elif (( px >= 1920 * 1080 )); then echo "8M"
  else echo "2M"
  fi
}

pick_ffmpeg() {
  for c in "${FFMPEG_HW:-$HOME/ffmpeg-hw}/bin/ffmpeg" "$(command -v ffmpeg 2>/dev/null)"; do
    [[ -x "$c" ]] || continue
    echo "$c"
    return 0
  done
  return 1
}

pick_encoder() {
  local enc_ffmpeg="$1"
  if "$enc_ffmpeg" -hide_banner -encoders 2>/dev/null | grep -qE '(^|[[:space:]])hevc_nvenc'; then
    echo "hevc_nvenc"
    return 0
  fi
  if "$enc_ffmpeg" -hide_banner -encoders 2>/dev/null | grep -qE '(^|[[:space:]])hevc_videotoolbox'; then
    echo "hevc_videotoolbox"
    return 0
  fi
  if "$enc_ffmpeg" -hide_banner -encoders 2>/dev/null | grep -qE '(^|[[:space:]])libx265'; then
    echo "libx265"
    return 0
  fi
  return 1
}

ENC_FFMPEG="$(pick_ffmpeg)" || { echo "ERROR: ffmpeg not found (set FFMPEG_HW or PATH)" >&2; exit 1; }
ENC="$(pick_encoder "$ENC_FFMPEG")" || {
  echo "ERROR: need hevc_nvenc, hevc_videotoolbox, or libx265 in $ENC_FFMPEG" >&2
  exit 1
}

mkdir -p "$(dirname "$OUT")"
echo "== HEVC Annex-B profile=$PROFILE ${WIDTH}x${HEIGHT} ${FPS}fps ${DURATION}s GOP=$GOP encoder=$ENC =="
echo "== ffmpeg: $ENC_FFMPEG =="

if [[ "$ENC" == "hevc_nvenc" ]]; then
  # Align with docs/config/hevc_nvenc_low_latency.json (verify on target GPU).
  "$ENC_FFMPEG" -y -f lavfi -i "testsrc=size=${WIDTH}x${HEIGHT}:rate=${FPS}" -t "$DURATION" \
    -c:v hevc_nvenc -preset p4 -tune ll -rc cbr -b:v 35M -maxrate 40M -bufsize 80M \
    -g "$GOP" -bf 0 -rc-lookahead 0 -delay 0 -pix_fmt yuv420p -an -f hevc "$OUT"
elif [[ "$ENC" == "hevc_videotoolbox" ]]; then
  VT_BV="$(vt_bitrate)"
  "$ENC_FFMPEG" -y -f lavfi -i "testsrc=size=${WIDTH}x${HEIGHT}:rate=${FPS}" -t "$DURATION" \
    -c:v hevc_videotoolbox -b:v "$VT_BV" -g "$GOP" -bf 0 -pix_fmt yuv420p -an -f hevc "$OUT"
else
  # libx265: ultrafast for 4K test generation on CPU (macOS send path)
  x265_extra="keyint=${GOP}:min-keyint=${GOP}"
  if (( WIDTH * HEIGHT >= 3840 * 2160 )); then
    x265_extra="${x265_extra}:preset=ultrafast"
  fi
  "$ENC_FFMPEG" -y -f lavfi -i "testsrc=size=${WIDTH}x${HEIGHT}:rate=${FPS}" -t "$DURATION" \
    -c:v libx265 -pix_fmt yuv420p -x265-params "$x265_extra" -an -f hevc "$OUT"
fi

echo "== wrote $OUT =="
ls -lh "$OUT"
"$ENC_FFMPEG" -hide_banner -i "$OUT" -f null - 2>&1 | tail -5
