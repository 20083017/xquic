#!/usr/bin/env bash
# Local WSL E2E: HEVC + CUDA/NVDEC (hevc_cuvid) + GLX/PBO display.
# NVIDIA WSL / discrete GPU — same path as cross-endpoint receive.
#
#   export DISPLAY=:0
#   bash scripts/wsl_video_e2e_cuda.sh
#
# Optional: EOS_FLAGS="--no-eos-file-decode" CODEC=hevc
set -euo pipefail
export HW_DECODE=ON
export HW_BACKEND=cuda
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/wsl_video_e2e_common.sh
source "$ROOT/scripts/wsl_video_e2e_common.sh"
