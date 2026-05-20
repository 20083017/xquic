# WSL：自编译 FFmpeg（VAAPI/CUDA）与 xquic 视频链路验证

本文记录在 **WSL2 / Ubuntu** 上：

1. 使用仓库脚本自编译 **FFmpeg**（VAAPI + 可选 CUDA/NVDEC）  
2. 用该 FFmpeg **编译 xquic** 低延迟接收端（`xqc_video_receiver`）  
3. **本地 / 远端** 视频 QUIC 测试与结果核对  

相关脚本：

| 文件 | 作用 |
|------|------|
| [`scripts/build_ffmpeg_hw_linux.sh`](../scripts/build_ffmpeg_hw_linux.sh) | 编译安装 FFmpeg 到 `$PREFIX`（默认 `~/ffmpeg-hw`） |
| [`scripts/wsl_video_e2e.sh`](../scripts/wsl_video_e2e.sh) | 一键：cmake 构建 + 短 H.264 E2E |
| [`docs/DPDK_SEASTAR_XQUIC_ARCHITECTURE_AND_ROADMAP.md`](DPDK_SEASTAR_XQUIC_ARCHITECTURE_AND_ROADMAP.md) §2.6–2.7 | 架构与 GPU 分工 |

---

## 1. 环境前提

- **WSL2**（建议 Ubuntu 22.04+）  
- 仓库路径示例：`/mnt/e/ros2/xquic`（Windows 盘）或 `~/xquic`（Linux 家目录）  
- **显示测试**：WSLg 需设置 `DISPLAY`（如 `:0`）；无显示时可只做 `--decode` 不解 `--display`  
- **NVIDIA 硬解**：WSL2 需 [GPU 透传](https://learn.microsoft.com/en-us/windows/wsl/tutorials/gpu-compute)；`nvidia-smi` 在 WSL 内可用  
- **VAAPI**：需 `/dev/dri/renderD128` 等（Intel/AMD 核显/独显）

---

## 2. 安装系统依赖

```bash
sudo apt update
sudo apt install -y \
  build-essential git cmake pkg-config yasm nasm \
  libevent-dev \
  libglfw3-dev libgl1-mesa-dev \
  libva-dev libva-drm2 libdrm-dev libegl-dev mesa-va-drivers \
  libx264-dev libx265-dev

# 可选：CUDA 工具链（apt 布局：nvcc 在 /usr/bin，头文件在 /usr/include）
sudo apt install -y nvidia-cuda-toolkit
```

验证 CUDA（可选）：

```bash
which nvcc          # 期望：/usr/bin/nvcc
ls -l /usr/include/cuda.h
nvcc --version      # 例如 CUDA 11.5
```

---

## 3. 自编译 FFmpeg

### 3.1 准备源码

任选其一：

**A. 使用已有源码树（推荐，例如 `~/ffmpeg`）**

```bash
ls ~/ffmpeg/configure   # 必须存在（也支持 ~/FFmpeg）
```

**B. 由脚本自动 clone**

```bash
# 不指定 --ffmpeg-src 时，会 clone 到 build/ffmpeg-src/FFmpeg
```

建议版本：**n6.1.2**（与脚本默认 `--tag` 一致）：

```bash
cd ~/ffmpeg
git fetch --tags
git checkout n6.1.2    # 或保持你当前可编过的分支
```

### 3.2 执行编译脚本

在 **xquic 仓库根目录**：

```bash
cd /mnt/e/ros2/xquic    # 按你的实际路径

# 若源码在 ~/ffmpeg 且存在 configure，可省略 --ffmpeg-src（脚本会自动检测）
./scripts/build_ffmpeg_hw_linux.sh \
  --ffmpeg-src "$HOME/ffmpeg" \
  --prefix "$HOME/ffmpeg-hw"
```

常用选项：

| 选项 | 说明 |
|------|------|
| `--prefix $HOME/ffmpeg-hw` | 安装根目录 |
| `--ffmpeg-src ~/ffmpeg` | 指定已有源码，不重新 clone（省略时自动检测 `~/ffmpeg` / `~/FFmpeg`） |
| `--no-cuda` | 仅 VAAPI，不编 NVDEC/NVENC |
| `--tag n6.1.2` | 对 git 仓库尝试 checkout |
| `--jobs 8` | 并行编译线程数 |

**CUDA 说明（apt 安装）**：脚本会自动识别：

- `nvcc` → `/usr/bin/nvcc`  
- 头文件 → `/usr/include`  
- 库 → `/usr/lib/x86_64-linux-gnu`  

FFmpeg `configure` 使用 **`--enable-cuda-nvcc`**（布尔开关，**不要**写成 `--enable-cuda-nvcc=/path`）。

### 3.3 验证 FFmpeg 安装

```bash
export PATH="$HOME/ffmpeg-hw/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"

# 硬解解码器（按你启用的后端，至少应看到其一）
ffmpeg -hide_banner -decoders 2>/dev/null | grep -E 'h264_vaapi|hevc_vaapi|h264_cuvid|hevc_cuvid'

# 测试码流（H.265 默认硬解路径；H.264 双栈）
ffmpeg -hide_banner -encoders 2>/dev/null | grep -E 'libx265|libx264'

# pkg-config 应指向自编译前缀
export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
pkg-config --modversion libavcodec
pkg-config --variable=libdir libavcodec   # 应在 .../ffmpeg-hw/lib 下
```

期望示例：

```text
V..... h264_vaapi    ...  (若 VAAPI 可用)
V..... h264_cuvid    ...  (若 CUDA/NVDEC 已编入)
```

---

## 4. 编译 xquic（链接自编译 FFmpeg）

**每次新开终端** 先导出环境变量，再 cmake：

```bash
cd /mnt/e/ros2/xquic

export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"

cmake -S . -B build_wsl \
  -DXQC_ENABLE_TESTING=ON \
  -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON \
  -DXQC_ENABLE_HW_DECODE=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build_wsl --target xqc_video_receiver video_client xqc_h264_decode_smoke -j"$(nproc)"
```

产物路径：

| 二进制 | 路径 |
|--------|------|
| 接收端 | `build_wsl/xquic_tests/xqc_video_receiver` |
| 发送端 | `build_wsl/xquic_tests/video_client` |
| 解码冒烟 | `build_wsl/xquic_tests/xqc_h264_decode_smoke` |

若 `cmake` 仍找到系统 `/usr` 的 libavcodec，检查：

```bash
pkg-config --print-requires libavcodec
ls -l "$HOME/ffmpeg-hw/lib/pkgconfig/libavcodec.pc"
```

确认 `PKG_CONFIG_PATH` 中 **自编译路径在前**。

---

## 5. 测试流程

### 5.1 解码冒烟（不经过 QUIC）

使用脚本生成的或自备 Annex-B（默认 **`.h265` / HEVC 硬解**；双栈可用 `.h264`）：

```bash
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"

# HEVC（默认产品路径）
"$HOME/ffmpeg-hw/bin/ffmpeg" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
  -c:v libx265 -pix_fmt yuv420p -x265-params keyint=15:min-keyint=15 -an \
  -f hevc build_wsl/test_cam0.h265

build_wsl/xquic_tests/xqc_h264_decode_smoke build_wsl/test_cam0.h265

# H.264 双栈（可选）
"$HOME/ffmpeg-hw/bin/ffmpeg" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
  -c:v libx264 -profile:v baseline -pix_fmt yuv420p -g 15 -an \
  -f h264 build_wsl/test_cam0.h264
build_wsl/xquic_tests/xqc_h264_decode_smoke build_wsl/test_cam0.h264
```

期望（示例）：

```text
[decode_file] build_wsl/test_cam0.h265 (hevc) -> 45 frames
[smoke] decode_file=45 NV12 frames, fifo_popped=4 (queue depth 4), last 320x240
```

说明：`decode_file` 按容器自动识别 H.264/HEVC；流式路径由 `--codec` 选择解码器（`hevc_vaapi` / `hevc_cuvid` 或 `h264_*`）。

若报 `Unknown encoder libx265` / `libx264`，安装 `libx265-dev` / `libx264-dev` 后重编 FFmpeg。

### 5.2 本地 E2E（CUDA / VAAPI 拆分）

**测试矩阵全文**：[`WSL_HW_DECODE_TEST_MATRIX.md`](WSL_HW_DECODE_TEST_MATRIX.md)

| 后端 | 脚本 | 输出目录 |
|------|------|----------|
| **CUDA / NVDEC**（NVIDIA WSL，你已验证） | `bash scripts/wsl_video_e2e_cuda.sh` | `build_wsl/video_out_cuda/` |
| **VAAPI + EGL**（Intel/AMD） | `bash scripts/wsl_video_e2e_vaapi.sh` | `build_wsl/video_out_vaapi/` |
| 默认（等同 CUDA） | `bash scripts/wsl_video_e2e.sh` | `build_wsl/video_out_cuda/` |

```bash
export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"
export DISPLAY=:0
export EOS_FLAGS="--no-eos-file-decode"   # 纯流内延迟

# NVIDIA WSL — 推荐
bash scripts/wsl_video_e2e_cuda.sh

# Intel/AMD 核显/独显 — 另机或另环境
# bash scripts/wsl_video_e2e_vaapi.sh
```

H.264 双栈：`CODEC=h264 HW_BACKEND=cuda bash scripts/wsl_video_e2e_cuda.sh`

### 5.3 手动分步（便于看日志）

**终端 1 — 接收端**

```bash
cd /mnt/e/ros2/xquic
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"
export DISPLAY=:0
export XQC_HW_DECODE=cuda                     # NVIDIA WSL：固定 cuda，勿用 auto

build_wsl/xquic_tests/xqc_video_receiver \
  -p 8443 \
  -c tests/server.crt \
  -k tests/server.key \
  --video-dir ./build_wsl/video_out_cuda \
  --decode \
  --display \
  --hw-decode=cuda \
  --codec hevc \
  --no-eos-file-decode
```

启动日志关注：

```text
[hw] VAAPI ready ...          # 或 CUDA / software
[egl] dma-buf import ready    # VAAPI 零拷贝显示
[decode] stream worker started backend=vaapi+egl
[recv] listening UDP :8443 ...
```

**终端 2 — 发送端**

```bash
cd /mnt/e/ros2/xquic
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"

build_wsl/xquic_tests/video_client \
  -a 127.0.0.1 \
  -p 8443 \
  --cam0 build_wsl/test_cam0.h265 \
  --codec hevc \
  --fps 30
```

`--fps 0`：按文件内 PTS 自动 pacing；`--no-pace`：尽快发完（压 QUIC 吞吐）。

### 5.4 E2E 延迟直方图（需 `--display`）

接收端每约 2 秒打印：

```text
[e2e] (stream-only, 4K-ready path)
  recv->display: n=... avg=... ms ...
  wire_pts->display (anchored): ...
```

含义见 `tests/lowlatency/xqc_e2e_latency.hh`。

### 5.5 跨端 4K HEVC（Windows 发 → WSL/Linux 收 + 显示）

**本地 CUDA 通过后即可做跨端**。完整步骤、发端/收端分终端命令、验收清单见 **[`CROSS_ENDPOINT_HEVC.md`](CROSS_ENDPOINT_HEVC.md)**。

收端（NVIDIA）固定 **CUDA**，与本地一致：

```bash
export XQC_HW_DECODE=cuda
./build_wsl/xquic_tests/xqc_video_receiver ... --hw-decode=cuda --codec hevc --display
```

**发送端（Windows / 带 NVENC）**

```bash
WIDTH=3840 HEIGHT=2160 FPS=30 DURATION=60 bash scripts/gen_hevc_annexb.sh cam4k.h265
./build_wsl/xquic_tests/video_client -a <RECEIVER_IP> -p 8443 \
  --cam0 cam4k.h265 --codec hevc --fps 30
```

**接收端（WSL）** — `DISPLAY=:0`、`--codec hevc`、`--hw-decode=cuda`、`--display`（同 §5.3）。

显示窗口按 **3840×2160** 预配（`xqc_video_target.hh`）；码流可小于 4K，会缩放绘制。

---

## 6. 硬解后端对照（HEVC 默认 + H.264 双栈）

**硬件 → 显示（固定搭配）**

| GPU | 硬解 | 显示（推荐） |
|-----|------|--------------|
| **Intel / AMD** | VAAPI | **VAAPI + EGL + DMA-BUF**（零拷贝，最佳） |
| **NVIDIA** | CUDA / NVDEC | **CUDA/NVDEC + GLX + PBO** |

| 模式 | FFmpeg (HEVC) | 显示 | 启用 |
|------|---------------|------|------|
| NVIDIA | `hevc_cuvid` | **GLX + PBO** | `--hw-decode=cuda` |
| Intel/AMD | `hevc_vaapi` | **EGL + DMA-BUF** | `--hw-decode=vaapi` |
| 软件 | `hevc` sw | PBO | `--hw-decode=off` |
| H.264 双栈 | `h264_cuvid` / `h264_vaapi` | 同上 | `--codec h264` |

跨端收发与 Windows `hevc_nvenc` 发送说明：**[`CROSS_ENDPOINT_HEVC.md`](CROSS_ENDPOINT_HEVC.md)**。

运行时环境变量：

```bash
export XQC_HW_DECODE=auto
export XQC_VA_DEVICE=/dev/dri/renderD128
```

---

## 7. 常见问题

| 现象 | 处理 |
|------|------|
| `Unknown option "--enable-cuda-nvcc=..."` | 已修复：脚本仅用 `--enable-cuda-nvcc`，确保拉取最新 `build_ffmpeg_hw_linux.sh` |
| `local: can only be used in a function` | 同上，更新脚本后重跑 |
| cmake 仍链接系统 libavcodec | 检查 `PKG_CONFIG_PATH` 前缀是否为 `$HOME/ffmpeg-hw/lib/pkgconfig` |
| 运行时找不到 `libavcodec.so` | `export LD_LIBRARY_PATH=$HOME/ffmpeg-hw/lib:...` |
| `Unknown encoder libx264` | 安装 `sudo apt install libx264-dev` 后重编 FFmpeg；或用系统 `ffmpeg` 生成 `.h264` |
| 无 `h264_cuvid` | FFmpeg 未带 CUDA：重装 FFmpeg 且勿加 `--no-cuda`；或 WSL 无 GPU |
| 无 `h264_vaapi` | 安装 `libva-dev` / `mesa-va-drivers`；检查 `/dev/dri` |
| `[egl] ... missing` | 仅 VAAPI 路径需要 EGL；NVIDIA 用 `cuda` + GLX PBO |
| `--display failed` | `export DISPLAY=:0`；NVIDIA WSL 用 `--hw-decode=cuda`（勿强 EGL） |
| VAAPI 失败 | WSL+NVIDIA 正常；用 `XQC_HW_DECODE=cuda` |
| VAAPI 失败自动软解 | 日志 `[hw] using software`；检查驱动与 `XQC_VA_DEVICE` |
| E2E `wire_pts->display` 异常大 | 旧版未锚定 sender PTS；用当前代码 + `--no-eos-file-decode` |

---

## 8. 快速命令备忘

```bash
# --- 一次性：编 FFmpeg ---
./scripts/build_ffmpeg_hw_linux.sh --prefix "$HOME/ffmpeg-hw"
# 或显式: --ffmpeg-src "$HOME/ffmpeg"

# --- 每个 shell：环境 ---
export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"
export PATH="$HOME/ffmpeg-hw/bin:$PATH"

# --- 编 xquic ---
cmake -S . -B build_wsl -DXQC_ENABLE_TESTING=ON \
  -DXQC_ENABLE_LOWLATENCY_FFMPEG=ON -DXQC_ENABLE_HW_DECODE=ON
cmake --build build_wsl --target xqc_video_receiver video_client -j

# --- 验证 FFmpeg 硬解 ---
ffmpeg -hide_banner -decoders 2>/dev/null | grep -E 'h264_vaapi|h264_cuvid'

# --- E2E ---
export DISPLAY=:0 HW_DECODE=ON EOS_FLAGS="--no-eos-file-decode"
bash scripts/wsl_video_e2e.sh
```

---

## 9. 变更记录

| 日期 | 说明 |
|------|------|
| 2026-05 | 初版：WSL 自编译 FFmpeg + xquic HW decode + E2E/4K 测试说明 |
