#!/usr/bin/env bash
# Local WSL/Linux E2E: HEVC + VAAPI (hevc_vaapi) + EGL dma-buf display.
# Intel/AMD iGPU/dGPU with /dev/dri/renderD128 — NOT for NVIDIA-only WSL.
#
#   export DISPLAY=:0
#   export XQC_VA_DEVICE=/dev/dri/renderD128
#   bash scripts/wsl_video_e2e_vaapi.sh
set -euo pipefail
export HW_DECODE=ON
export HW_BACKEND=vaapi
if [[ ! -e "${XQC_VA_DEVICE:-/dev/dri/renderD128}" ]]; then
  echo "WARN: ${XQC_VA_DEVICE:-/dev/dri/renderD128} missing — VAAPI test may fail on NVIDIA-only WSL" >&2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/wsl_video_e2e_common.sh
source "$ROOT/scripts/wsl_video_e2e_common.sh"
