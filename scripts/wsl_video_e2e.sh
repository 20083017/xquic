#!/usr/bin/env bash
# Local WSL E2E (default: CUDA/NVDEC). For explicit backend use:
#   bash scripts/wsl_video_e2e_cuda.sh
#   bash scripts/wsl_video_e2e_vaapi.sh
set -euo pipefail
export HW_DECODE="${HW_DECODE:-ON}"
export HW_BACKEND="${HW_BACKEND:-cuda}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/wsl_video_e2e_common.sh
source "$ROOT/scripts/wsl_video_e2e_common.sh"
