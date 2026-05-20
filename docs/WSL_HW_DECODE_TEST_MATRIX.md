# WSL / Linux 硬解测试矩阵（CUDA vs VAAPI）

HEVC (H.265) 为默认 codec；H.264 双栈见 `CODEC=h264`。

## 硬件 → 显示路径（产品规格）

| GPU 厂商 | 硬解 | 显示（**推荐 / 最佳**） |
|----------|------|-------------------------|
| **Intel / AMD** | VAAPI (`hevc_vaapi` / `h264_vaapi`) | **VAAPI + EGL + DMA-BUF**（零拷贝） |
| **NVIDIA** | CUDA / NVDEC (`hevc_cuvid` / `h264_cuvid`) | **CUDA/NVDEC + GLX + PBO**（`hwdownload` → CPU NV12 → PBO） |

不要在 NVIDIA 上强行走 VAAPI/EGL；不要在 Intel/AMD 上默认走 CUDA。

---

| 测试项 | 脚本 / 命令 | 硬件前提 | 解码器 | 显示路径 |
|--------|-------------|----------|--------|----------|
| **CUDA 本地 E2E** | `bash scripts/wsl_video_e2e_cuda.sh` | NVIDIA + WSL GPU 透传 | `hevc_cuvid` | **GLX + PBO** |
| **VAAPI 本地 E2E** | `bash scripts/wsl_video_e2e_vaapi.sh` | Intel/AMD，`/dev/dri/renderD128` | `hevc_vaapi` | **EGL + DMA-BUF** |
| **跨端 E2E** | 见 [`CROSS_ENDPOINT_HEVC.md`](CROSS_ENDPOINT_HEVC.md) | 发端 NVENC；收端 NVIDIA → CUDA | `hevc_cuvid` | **GLX + PBO** |
| 软件回退 | `HW_BACKEND=off bash scripts/wsl_video_e2e.sh` | 无 | `hevc` sw | PBO |

输出目录按后端拆分，避免互相覆盖：

- CUDA：`build_wsl/video_out_cuda/`
- VAAPI：`build_wsl/video_out_vaapi/`

---

## 1. CUDA / NVDEC（你已验证 ✅）

**适用**：WSL2 + NVIDIA（`nvidia-smi` 可用）、本机或跨端**接收端**。

```bash
cd /mnt/e/ros2/xquic
export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:$LD_LIBRARY_PATH"
export DISPLAY=:0

# 纯流式延迟（不做 EOS 文件二次解码）
export EOS_FLAGS="--no-eos-file-decode"
bash scripts/wsl_video_e2e_cuda.sh
```

**验收日志**：

```text
[decode] hw ready backend=cuda+pbo default_codec=hevc
[gl] GLX context (PBO upload, hevc_cuvid path)
[gl] display thread running
[decode] camera codec=hevc backend=cuda+pbo
[stats] stream_nv12 > 0
```

**FFmpeg 自检**：

```bash
ffmpeg -hide_banner -decoders 2>/dev/null | grep hevc_cuvid
```

**勿与 VAAPI 混测**：NVIDIA WSL 上 VAAPI 常报 `-22`，属预期；请用 `wsl_video_e2e_cuda.sh`，不要用 `auto` 代替明确后端。

---

## 2. VAAPI + EGL（Intel / AMD 收端）

**适用**：物理机 Linux 或 WSL 带 **核显/独显 VAAPI**（`ls /dev/dri/renderD*`）。

```bash
export DISPLAY=:0
export XQC_VA_DEVICE=/dev/dri/renderD128   # 按 ls /dev/dri/ 调整
bash scripts/wsl_video_e2e_vaapi.sh
```

**验收日志**：

```text
[hw] VAAPI ready device=/dev/dri/renderD128 ...
[gl] EGL context (VAAPI dma-buf display)
[decode] camera codec=hevc backend=vaapi+egl
```

**FFmpeg 自检**：

```bash
ffmpeg -hide_banner -decoders 2>/dev/null | grep hevc_vaapi
vainfo --display drm --device /dev/dri/renderD128
```

**在纯 NVIDIA WSL 上**：此用例**预期失败**，仅作负例；不要阻塞 CUDA / 跨端进度。

---

## 3. 对比表（写报告用）

| 维度 | NVIDIA：CUDA/NVDEC + GLX + PBO | Intel/AMD：VAAPI + EGL + DMA-BUF |
|------|-------------------------------|----------------------------------|
| FFmpeg 解码 | `hevc_cuvid` / `h264_cuvid` | `hevc_vaapi` / `h264_vaapi` |
| 解码输出 | GPU 帧 → `hwdownload` → CPU NV12 | GPU VAAPI 表面 |
| 显示 API | **GLX** + `GL_PIXEL_UNPACK_BUFFER` | **EGL** + `EGLImage`（dma-buf） |
| 零拷贝到 GL | 否（当前实现） | **是（最佳）** |
| WSL NVIDIA | ✅ 推荐路径 | ❌ 通常不可用（VAAPI -22） |
| CLI | `--hw-decode=cuda` | `--hw-decode=vaapi` |
| 环境变量 | `XQC_HW_DECODE=cuda` | `XQC_HW_DECODE=vaapi` |

---

## 4. 与主文档关系

| 文档 | 内容 |
|------|------|
| [`WSL_FFMPEG_HW_BUILD_AND_TEST.md`](WSL_FFMPEG_HW_BUILD_AND_TEST.md) | 编 FFmpeg、cmake、冒烟 |
| **本文** | CUDA / VAAPI **拆分**本地 E2E |
| [`CROSS_ENDPOINT_HEVC.md`](CROSS_ENDPOINT_HEVC.md) | Windows 发 → Linux 收 + 显示 |

---

## 5. 变更记录

| 日期 | 说明 |
|------|------|
| 2026-05 | 拆分 `wsl_video_e2e_cuda.sh` / `wsl_video_e2e_vaapi.sh` |
