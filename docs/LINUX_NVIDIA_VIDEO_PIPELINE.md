# Linux + NVIDIA 高性能视频接收/解码/显示开发指南

本文面向最终目标：在 Ubuntu + NVIDIA 平台上构建高性能网络接收、硬件解码和低延迟显示链路。当前交付聚焦 `开发路线.md` 的 P1-P6 可验证路径：

```text
QUIC/UDP receive -> H.264/HEVC Annex-B -> FFmpeg NVDEC -> NV12 -> OpenGL PBO display
```

DPDK、GPUDirect RDMA、CUDA/EGL zero-copy、DRM/KMS 和 Seastar runtime 会按独立 smoke -> 主链路接入的顺序继续推进。

## 1. 推荐平台

推荐起点：

- OS：Ubuntu 24.04 LTS，Ubuntu 22.04 也可。
- GPU：NVIDIA RTX / Ada / Ampere 系列，驱动能正常运行 `nvidia-smi`。
- CUDA：先用 `nvidia-cuda-toolkit` 满足 FFmpeg 编译；生产环境可换 NVIDIA CUDA repo。
- 显示：开发期用 X11/GLX + GLFW/PBO；DRM/KMS 直显属于 P5 后续。
- 网络：开发期先跑 QUIC/libevent 或 POSIX RTP；DPDK/NIC 绑核和 hugepage 属于 P1 后续增强。

## 2. 装机后依赖

先安装 NVIDIA 驱动，确认：

```bash
nvidia-smi
```

然后在仓库根目录安装依赖：

```bash
bash scripts/install_ubuntu_nvidia_deps.sh
```

如果暂时不安装 CUDA toolkit：

```bash
bash scripts/install_ubuntu_nvidia_deps.sh --no-cuda
```

如果要同时准备 Seastar 依赖：

```bash
bash scripts/install_ubuntu_nvidia_deps.sh --with-seastar
```

如果要编译 P1 DPDK RTP RX 工具：

```bash
bash scripts/install_ubuntu_nvidia_deps.sh --with-dpdk
```

## 3. 一键构建

首轮构建：

```bash
bash scripts/build_linux_nvidia_video_pipeline.sh
```

该脚本会构建：

- `third_party/quictls/build`：xquic 使用的 QUIC TLS。
- `$HOME/ffmpeg-hw`：带 CUDA/NVDEC/NVENC 的 FFmpeg。
- `build_linux_nvidia/xquic_tests/xqc_video_receiver`：QUIC 视频接收 + 解码 + 可选显示。
- `build_linux_nvidia/xquic_tests/video_client`：Annex-B 发送端。
- `build_linux_nvidia/xquic_tests/xqc_h264_decode_smoke`：解码冒烟。
- `build_linux_nvidia/xquic_tests/xqc_rtp_annexb_receiver`：RTP/H.264 -> Annex-B 调试接收器。
- `build_linux_nvidia/xquic_tests/xqc_drm_kms_smoke`：P5 DRM/KMS 非破坏性能力检查。
- `build_linux_nvidia/xquic_tests/xqc_gpudirect_env_check`：P6 GPUDirect RDMA 环境预检。
- `build_linux_nvidia/xquic_tests/xqc_nv12_mosaic_smoke`：P8 NV12 mosaic 合成冒烟。
- `build_linux_nvidia/xquic_tests/xqc_spsc_ring_smoke`：系统目标内存模型 SPSC lock-free ring 冒烟。

可选 CUDA 零拷贝前置工具：

- `build_linux_nvidia/xquic_tests/xqc_cuda_memory_smoke`：CUDA pinned/register/device memory 冒烟。
- `build_linux_nvidia/xquic_tests/xqc_cuda_gl_interop_smoke`：CUDA graphics resource -> OpenGL texture interop 冒烟。

增量构建：

```bash
bash scripts/build_linux_nvidia_video_pipeline.sh --skip-quictls --skip-ffmpeg
```

指定已有 FFmpeg 源码：

```bash
bash scripts/build_linux_nvidia_video_pipeline.sh --ffmpeg-src "$HOME/ffmpeg"
```

如果同时编译 P1 DPDK RTP RX：

```bash
bash scripts/build_linux_nvidia_video_pipeline.sh --with-dpdk-rx
```

如果同时编译 P4/P6 CUDA 零拷贝前置工具：

```bash
bash scripts/build_linux_nvidia_video_pipeline.sh --with-cuda-smoke
```

## 4. 运行环境变量

每个新终端建议导出：

```bash
export PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="$HOME/ffmpeg-hw/lib:${LD_LIBRARY_PATH:-}"
export XQC_HW_DECODE=cuda
```

显示测试需要：

```bash
export DISPLAY="${DISPLAY:-:0}"
```

## 5. 验证步骤

### 5.1 FFmpeg NVDEC 自检

```bash
"$HOME/ffmpeg-hw/bin/ffmpeg" -hide_banner -decoders 2>/dev/null | grep -E 'h264_cuvid|hevc_cuvid'
"$HOME/ffmpeg-hw/bin/ffmpeg" -hide_banner -encoders 2>/dev/null | grep -E 'libx264|libx265|hevc_nvenc'
```

期望至少看到：

```text
h264_cuvid
hevc_cuvid
```

### 5.2 解码冒烟

生成 HEVC Annex-B 测试码流：

```bash
mkdir -p build_linux_nvidia
"$HOME/ffmpeg-hw/bin/ffmpeg" -y -f lavfi -i testsrc=size=320x240:rate=15 -t 3 \
  -c:v libx265 -pix_fmt yuv420p -x265-params keyint=15:min-keyint=15 -an \
  -f hevc build_linux_nvidia/test_cam0.h265
```

运行解码冒烟：

```bash
build_linux_nvidia/xquic_tests/xqc_h264_decode_smoke build_linux_nvidia/test_cam0.h265
```

### 5.3 本机 E2E

纯流式延迟路径，不做 EOS 文件二次解码：

```bash
DISPLAY="${DISPLAY:-:0}" \
EOS_FLAGS="--no-eos-file-decode" \
BUILD="$PWD/build_linux_nvidia" \
bash scripts/wsl_video_e2e_cuda.sh
```

验收日志关注：

```text
[hw] CUDA/NVDEC ready
[decode] camera codec=hevc backend=cuda+pbo
[stats] stream_nv12 > 0
```

如果没有显示环境，可以先去掉显示，只验证接收和解码：

```bash
BUILD="$PWD/build_linux_nvidia" \
HW_BACKEND=cuda \
EOS_FLAGS="--no-eos-file-decode" \
ENABLE_DISPLAY=0 \
bash scripts/wsl_video_e2e_common.sh
```

### 5.4 手动分步

终端 1，接收端：

```bash
build_linux_nvidia/xquic_tests/xqc_video_receiver \
  -p 8443 \
  -c tests/server.crt \
  -k tests/server.key \
  --video-dir build_linux_nvidia/video_out_cuda \
  --decode \
  --display \
  --codec hevc \
  --hw-decode=cuda \
  --no-eos-file-decode
```

终端 2，发送端：

```bash
build_linux_nvidia/xquic_tests/video_client \
  -a 127.0.0.1 \
  -p 8443 \
  --cam0 build_linux_nvidia/test_cam0.h265 \
  --codec hevc \
  --fps 30
```

## 6. RTP P1/P2 调试入口

如果先验证普通 RTP/H.264 收包和 Annex-B 重组：

```bash
build_linux_nvidia/xquic_tests/xqc_rtp_annexb_receiver \
  --port 5004 \
  --output build_linux_nvidia/rtp_capture.h264
```

该工具支持 single NAL、STAP-A、FU-A，适合 P1/P2 协议层调试。DPDK 版 RX 会在同一输出语义上继续演进。

## 7. DPDK P1 接收入口

安装 DPDK 依赖后启用可选目标：

```bash
bash scripts/build_linux_nvidia_video_pipeline.sh --with-dpdk-rx
```

或手动启用：

```bash
cmake -S . -B build_linux_nvidia \
  -DSSL_PATH="$PWD/third_party/quictls/build" \
  -DXQC_ENABLE_TESTING=ON \
  -DXQC_ENABLE_DPDK_RTP_RX=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build_linux_nvidia --target xqc_dpdk_rtp_rx -j"$(nproc)"
```

运行前配置 hugepage，并把数据网卡绑定到 DPDK 驱动，细节见 `docs/DPDK_USAGE_GUIDE.md`。最小运行示例：

```bash
sudo sysctl -w vm.nr_hugepages=1024
sudo mkdir -p /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages || true

sudo build_linux_nvidia/xquic_tests/xqc_dpdk_rtp_rx \
  -l 0-1 -n 4 -- \
  --port-id 0 \
  --queue-id 0 \
  --udp-port 5004 \
  --dump-limit 8
```

该工具覆盖 `开发路线.md` P1 的初版能力：DPDK EAL 初始化、mbuf pool、RX queue、burst receive、VLAN/IPv4/UDP/RTP 粗解析、SSRC/payload dump、wall clock/tsc timestamp 和周期 PPS/Gbps 统计。

## 8. P5 DRM/KMS smoke

P5 的完整 direct scanout 不能贸然抢占桌面，因此当前先提供非破坏性枚举工具：

```bash
build_linux_nvidia/xquic_tests/xqc_drm_kms_smoke --device /dev/dri/card0
```

如需查看 connector、CRTC、plane 的属性：

```bash
build_linux_nvidia/xquic_tests/xqc_drm_kms_smoke --device /dev/dri/card0 --list-props
```

当前验收目标：

- 能打开 DRM card。
- 能启用 universal planes 和 atomic client cap。
- 能列出 connector、CRTC、plane 和格式。

后续再在独立工具内增加 atomic modeset、page flip 和 vsync pacing，确认不会破坏主桌面后再接入主显示链路。

## 9. P6 GPUDirect RDMA 预检

GPUDirect RDMA 依赖硬件、驱动和拓扑，先运行环境检查：

```bash
build_linux_nvidia/xquic_tests/xqc_gpudirect_env_check
```

检查项包括：

- NVIDIA kernel module 和 `/dev/nvidia*`。
- `nvidia-peermem`。
- Mellanox `mlx5_core`。
- `ib_uverbs` 与 `/dev/infiniband`。
- NVIDIA/Mellanox PCI vendor、class 和 NUMA node。
- IOMMU kernel cmdline 提示。
- `nvidia-smi topo -m`。

该工具只做环境 preflight。CUDA memory primitive 可继续运行：

```bash
build_linux_nvidia/xquic_tests/xqc_cuda_memory_smoke --bytes 16777216
```

它验证 `cudaHostAlloc`、`cudaHostRegister`、`cudaMalloc` 和 stream async copy。下一步是在该基础上增加 RDMA verbs `ibv_reg_mr` 最小实验，再进入 `nvidia-peermem` + NIC/GPU 同 root complex 的 GPU memory registration。

## 10. P4 NVIDIA CUDA/GL interop smoke

NVIDIA 当前主显示路径仍是 CUDA/NVDEC 后 hwdownload 到 CPU NV12，再经 GL PBO 上传。要闭合 CUDA surface -> EGL/GL/DRM，先验证 OpenGL texture 能被 CUDA 注册和映射：

```bash
build_linux_nvidia/xquic_tests/xqc_cuda_gl_interop_smoke --width 640 --height 360
```

有显示环境时可以加 `--visible` 打开窗口：

```bash
DISPLAY="${DISPLAY:-:0}" \
build_linux_nvidia/xquic_tests/xqc_cuda_gl_interop_smoke --width 640 --height 360 --visible
```

验收目标是 `cudaGraphicsGLRegisterImage`、`cudaGraphicsMapResources`、`cudaGraphicsSubResourceGetMappedArray` 和 `cudaMemcpy2DToArray` 全部成功。通过后再把 FFmpeg/NVDEC 的 CUDA frame surface 生命周期接到该 graphics-resource 路径。

## 11. P8 NV12 mosaic smoke

P8 当前先提供 CPU NV12 mosaic correctness baseline：

```bash
build_linux_nvidia/xquic_tests/xqc_nv12_mosaic_smoke \
  --width 320 \
  --height 240 \
  --columns 2 \
  --rows 2 \
  --output build_linux_nvidia/mosaic_2x2.nv12
```

输出为紧凑 NV12 raw frame，尺寸为 `columns * width` x `rows * height`。可以用 FFmpeg 查看：

```bash
"$HOME/ffmpeg-hw/bin/ffplay" \
  -f rawvideo -pixel_format nv12 -video_size 640x480 \
  build_linux_nvidia/mosaic_2x2.nv12
```

也可以输入真实 compact NV12 文件：

```bash
build_linux_nvidia/xquic_tests/xqc_nv12_mosaic_smoke \
  --width 1920 \
  --height 1080 \
  --columns 2 \
  --rows 2 \
  --input cam0.nv12 \
  --input cam1.nv12 \
  --input cam2.nv12 \
  --input cam3.nv12 \
  --output build_linux_nvidia/mosaic_4x1080p.nv12
```

后续会把该合成逻辑接入多 camera decode queue，并升级到 GL shader/GPU compositor。

## 12. 内存模型 SPSC ring smoke

`系统目标.md` 要求 hot path 使用 SPSC lock-free ring，避免 mutex、malloc/free、shared_ptr。当前先提供固定容量基础件和 smoke：

```bash
build_linux_nvidia/xquic_tests/xqc_spsc_ring_smoke
```

验收输出：

```text
[spsc] basic=ok wrap=ok threaded=ok
```

后续会逐步把 RTP/parser、decode/display 之间的单生产者单消费者队列迁移到该 ring 或同等无锁实现。

## 13. 开发路线映射

| 阶段 | 当前落地 | 后续升级 |
|------|----------|----------|
| P1 DPDK 接收 | POSIX UDP RTP 调试、QUIC/libevent 接收、`xqc_dpdk_rtp_rx` 初版 | RSS、多队列、硬件时间戳、DPDK RTP->AnnexB |
| P2 RTP 重组 | `xqc_rtp_annexb_receiver` H.264 single/STAP-A/FU-A | jitter buffer、丢包恢复、HEVC RTP payload |
| P3 FFmpeg/NVDEC | `xqc_video_receiver --hw-decode=cuda` | 更细粒度 NVDEC session 管理、零拷贝 surface 生命周期 |
| P4 EGL/GL Render | NVIDIA GLX + PBO 显示、`xqc_cuda_gl_interop_smoke` | NVDEC CUDA surface 接入 graphics resource、EGL/Vulkan 路径 |
| P5 DRM/KMS | `xqc_drm_kms_smoke` 非破坏性枚举 | DRM atomic modeset、direct scanout、frame pacing |
| P6 GPUDirect RDMA | `xqc_gpudirect_env_check` 环境预检、`xqc_cuda_memory_smoke` | RDMA MR、nvidia-peermem、DOCA/GPUNetIO、NIC -> GPU memory |
| P7 Seastar Runtime | 已有 `build_seastar.sh` 和 Seastar server | shard-per-core、DPDK stack、跨 shard 路由 |
| P8 Multi-stream | `xqc_nv12_mosaic_smoke` CPU NV12 合成基线 | 多路 decode queue、GPU compositor、mosaic display |

## 14. 性能调优清单

开发机先保持默认，进入性能阶段后再逐项开启：

```bash
sudo cpupower frequency-set -g performance
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.core.wmem_max=268435456
sudo sysctl -w net.core.netdev_max_backlog=250000
```

NUMA/PCIe 拓扑检查：

```bash
lspci | grep -Ei 'nvidia|ethernet|mellanox'
nvidia-smi topo -m
numactl --hardware
```

DPDK 阶段再配置 hugepage、VFIO/IOMMU、NIC 绑定和 Seastar/DPDK 参数。

## 15. 常见问题

- `nvidia-smi` 不可用：先修 NVIDIA 驱动，FFmpeg NVDEC E2E 不应继续。
- 找不到 `hevc_cuvid`：重跑 `build_ffmpeg_hw_linux.sh`，确认 `nvcc` 和 CUDA 头文件可用。
- CMake 找到系统 FFmpeg：确认 `PKG_CONFIG_PATH="$HOME/ffmpeg-hw/lib/pkgconfig:$PKG_CONFIG_PATH"` 在最前。
- `--display` 无窗口：确认 `DISPLAY`、X11/Wayland bridge、`libglfw3-dev`，无显示时先只跑 `--decode`。
- NVIDIA 上 VAAPI 报错：预期不要走 VAAPI，使用 `--hw-decode=cuda`。
