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

Headers (include in your player / bridge code):

| File | Phase |
|------|-------|
| `xqc_bounded_frame_queue.hh` | W3 — mutex bounded queue, drop-oldest / pop-latest |
| `xqc_lowlatency_perf.hh` | W5 — `QueryPerformanceCounter` inter-frame timing |

Config:

| File | Phase |
|------|-------|
| `docs/config/hevc_nvenc_low_latency.json` | W4 — `hevc_nvenc` CLI template; **always** validate with `ffmpeg -h encoder=hevc_nvenc` |

**WSL / Linux E2E** — 完整步骤（自编译 FFmpeg + VAAPI/CUDA + 测试）见 **[`docs/WSL_FFMPEG_HW_BUILD_AND_TEST.md`](../../docs/WSL_FFMPEG_HW_BUILD_AND_TEST.md)**。

快速入口：

```bash
./scripts/build_ffmpeg_hw_linux.sh --ffmpeg-src "$HOME/FFmpeg" --prefix "$HOME/ffmpeg-hw"
export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"
cmake -S . -B build_wsl -DXQC_ENABLE_TESTING=ON -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON -DXQC_ENABLE_HW_DECODE=ON
cmake --build build_wsl --target xqc_video_receiver video_client -j$(nproc)
bash scripts/wsl_video_e2e.sh
```

- `xqc_video_receiver`: libevent + transport ALPN + wire parse + bounded queue + FFmpeg decode → NV12; optional `--display` (GLFW, needs WSLg / `DISPLAY`).
- `video_client`: sends Annex-B over QUIC (`--cam0 file.h264`).

**W2 + FFmpeg NVDEC (Windows)**: use vcpkg `ffmpeg` + `XQC_ENABLE_LOWLATENCY_FFMPEG`; Linux path uses software `h264` + `libswscale` → NV12.

**W3 + Seastar**: do not call decode or GL from the reactor; push AU bytes into `XqcBoundedFrameQueue<std::vector<uint8_t>>` (or similar) and consume on a worker thread that owns `AVFrame` ref/unref.

**W5 affinity**: pass Seastar `--cpuset` (see Seastar docs) and set decoder thread affinity with `SetThreadAffinityMask` / `pthread_setaffinity_np` on Linux.
