# Low-latency phases (W1–W5) — code layout

Build (Windows, optional):

```cmake
-DXQC_ENABLE_TESTING=ON -DXQC_ENABLE_LOWLATENCY_PHASES=ON
```

Targets:

| Target | Phase | Role |
|--------|-------|------|
| `xqc_gpu_windows_selftest` | W1 | `NvOptimusEnablement` + `GL_VENDOR` / `GL_RENDERER` check |
| `xqc_nv12_gl_pbo_viewer` | W2 (baseline GL) | Raw NV12 file → dual PBO → NV12 textures → BT.709 limited shader + V-Sync |
| `xqc_rtp_annexb_receiver` | Roadmap P1/P2 (macOS/Linux fallback) | UDP RTP/H.264 receive → reorder → Annex-B `.h264` file |

Headers (include in your player / bridge code):

| File | Phase |
|------|-------|
| `xqc_bounded_frame_queue.hh` | W3 — mutex bounded queue, drop-oldest / pop-latest |
| `xqc_lowlatency_perf.hh` | W5 — `QueryPerformanceCounter` inter-frame timing |

Config:

| File | Phase |
|------|-------|
| `docs/config/hevc_nvenc_low_latency.json` | W4 — `hevc_nvenc` CLI template; **always** validate with `ffmpeg -h encoder=hevc_nvenc` |

**Linux + NVIDIA 主线** — Ubuntu + NVIDIA 高性能接收、NVDEC 解码、PBO 显示的构建与验证见 **[`docs/LINUX_NVIDIA_VIDEO_PIPELINE.md`](../../docs/LINUX_NVIDIA_VIDEO_PIPELINE.md)**。

**WSL / Linux E2E** — 完整步骤（自编译 FFmpeg + VAAPI/CUDA + 测试）见 **[`docs/WSL_FFMPEG_HW_BUILD_AND_TEST.md`](../../docs/WSL_FFMPEG_HW_BUILD_AND_TEST.md)**。

**macOS P1/P2 fallback** — 当前 macOS 没有 DPDK/NVDEC/DRM/KMS 路径，使用 POSIX UDP 接收和 H.264 RTP depacketize 验证协议层：

```bash
cmake -S . -B build_macos -DPLATFORM=mac -DXQC_ENABLE_TESTING=ON
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
cmake --build build_macos --target xqc_rtp_annexb_receiver -j"$JOBS"
./build_macos/xquic_tests/xqc_rtp_annexb_receiver --port 5004 --output rtp_capture.h264
```

支持 RTP/H.264 single NAL、STAP-A、FU-A。该目标用于 macOS 本机开发和码流调试；DPDK、GPUDirect、NVDEC、EGL/DRM 仍属于 Linux/NVIDIA 生产路径。

快速入口：

```bash
./scripts/build_ffmpeg_hw_linux.sh --ffmpeg-src "$HOME/FFmpeg" --prefix "$HOME/ffmpeg-hw"
export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"
cmake -S . -B build_wsl -DXQC_ENABLE_TESTING=ON -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON -DXQC_ENABLE_HW_DECODE=ON
cmake --build build_wsl --target xqc_video_receiver video_client -j$(nproc)
bash scripts/wsl_video_e2e.sh
```

- `xqc_video_receiver`: QUIC → **HEVC/H.264** stream decode (`hevc_cuvid` / `h264_cuvid`) → NV12; `--display` (GL PBO, 4K window).
- `video_client`: Annex-B over QUIC (`--cam0 file.h265 --codec hevc`).

**跨端 HEVC**：[`docs/CROSS_ENDPOINT_HEVC.md`](../../docs/CROSS_ENDPOINT_HEVC.md) · **CUDA/VAAPI 拆分**：[`docs/WSL_HW_DECODE_TEST_MATRIX.md`](../../docs/WSL_HW_DECODE_TEST_MATRIX.md)

| 脚本 | 用途 |
|------|------|
| `scripts/wsl_video_e2e_cuda.sh` | 本地 NVIDIA / 跨端收端同路径 |
| `scripts/wsl_video_e2e_vaapi.sh` | 本地 Intel/AMD VAAPI |
| `scripts/gen_hevc_annexb.sh` | 发端码流（NVENC / libx265） |

**W2 + FFmpeg NVDEC**: Linux/WSL `XQC_ENABLE_HW_DECODE` + `hevc_cuvid`; Windows player 见 `VIDEO_LOW_LATENCY_WINDOWS_DEV_PLAN.md`。

**W3 + Seastar**: do not call decode or GL from the reactor; push AU bytes into `XqcBoundedFrameQueue<std::vector<uint8_t>>` (or similar) and consume on a worker thread that owns `AVFrame` ref/unref.

**W5 affinity**: pass Seastar `--cpuset` (see Seastar docs) and set decoder thread affinity with `SetThreadAffinityMask` / `pthread_setaffinity_np` on Linux.
