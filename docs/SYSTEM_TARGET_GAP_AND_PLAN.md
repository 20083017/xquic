# 系统目标现状对照与开发清单

本文对照 `系统目标.md` 的最终架构，梳理当前仓库实现、未完成项、开发优先级和下一步落地计划。目标平台仍以 Ubuntu + NVIDIA + Mellanox 为准。

## 1. 总体结论

`系统目标.md` 描述的是最终形态：

```text
Mellanox NIC -> GPUDirect RDMA -> GPU/DPDK RX pool -> RTP reorder
-> H264/H265 parser -> NVDEC CUDA surface -> CUDA/EGL/Vulkan -> DRM/KMS
```

当前仓库已经有“可验证开发链路”，但还不是最终零拷贝链路：

```text
POSIX/QUIC or DPDK smoke -> RTP/Annex-B or xquic video wire
-> FFmpeg NVDEC/CPU decode -> CPU NV12/PBO or VAAPI dma-buf -> GL display
```

也就是说，当前重点是可编译、可调试、可测量；最终目标要求的 NIC->GPU memory、NVDEC surface 常驻 GPU、DRM atomic direct scanout 仍需分阶段推进。

## 2. 模块对照清单

| 系统目标模块 | 当前已有 | 主要缺口 | 下一步 |
|--------------|----------|----------|--------|
| DPDK RX Engine | `xqc_dpdk_rtp_rx` 初版，支持 EAL、mbuf pool、RX queue、burst RX、RTP dump/统计 | RSS、多队列、flow steering、硬件时间戳、直接输出到 RTP engine | 在 Ubuntu+DPDK 上验证单队列，再加多 queue/RSS/队列绑核 |
| RTP Engine | `xqc_rtp_annexb_receiver` 支持 H.264 single NAL/STAP-A/FU-A 和有限 seq reorder | 时间窗 jitter buffer、packet loss 策略、HEVC RTP、可复用库化 | 抽出 parser/reorder/depacketizer 模块，供 POSIX/DPDK 共用 |
| H264/H265 Parser | `video_client` 能切 Annex-B NAL，`xqc_video_recv_process.hh` 能记录并推送 Annex-B | SPS/PPS/VPS 缓存、IDR 对齐、HEVC RTP payload、NVDEC bitstream 边界控制 | 做 codec parser 层，向 NVDEC 提供稳定 access unit |
| GPUDirect RDMA | `xqc_gpudirect_env_check` 做 nvidia-peermem/RDMA/PCI/NUMA 预检；`xqc_cuda_memory_smoke` 做 CUDA pinned/register/device memory 前置验证 | `ibv_reg_mr`、DOCA/GPUNetIO、NIC DMA->GPU | 先做最小 RDMA memory registration 实验，再接 DPDK mbuf/GPU pool |
| NVDEC Engine | FFmpeg CUDA/NVDEC 后端已有入口，`xqc_video_receiver --hw-decode=cuda` 可用 | 当前 NVIDIA 路径仍可能 hwdownload 到 CPU NV12；未管理 CUDA surface 生命周期 | 增加 NVDEC surface stats 和 zero-copy prototype |
| Render Engine | NVIDIA GLX/PBO、VAAPI/EGL dma-buf 路径已有；P8 CPU mosaic baseline 已有；`xqc_cuda_gl_interop_smoke` 提供 CUDA/GL 纹理注册前置验证 | NVDEC CUDA surface 尚未直接接入 GL/EGL；Vulkan 未实现 | 在 interop smoke 通过后，将 NVDEC CUDA surface 接入 graphics resource |
| Display Engine | `xqc_drm_kms_smoke` 可枚举 DRM/KMS 与 atomic cap | atomic modeset、page flip、direct scanout、vsync pacing 未实现 | 独立 DRM atomic smoke，避免影响桌面环境 |
| HugePage | DPDK 工具使用 mbuf pool；文档提供 hugepage 配置 | 未记录 hugepage/runtime stats 到工具输出 | DPDK RX 输出 socket/NUMA/mbuf 参数 |
| CUDA Pinned Memory | FFmpeg/CUDA 入口存在；P6 预检存在；`xqc_cuda_memory_smoke` 验证 `cudaHostAlloc`、`cudaHostRegister`、`cudaMalloc` 和 async copy | 尚未与 RDMA MR 注册或 DPDK mbuf pool 连接 | 增加 RDMA verbs MR 注册实验 |
| Zero Copy Ring | `XqcBoundedFrameQueue` 已有；新增 `xqc_spsc_ring.hh` 和 `xqc_spsc_ring_smoke` 作为 lock-free SPSC 基础件 | 尚未接入 RTP/parser 或 decode/display 主链路 | 逐步替换单生产者/单消费者热路径队列 |
| 多线程模型 | 解码线程与 reactor 分离；Seastar shard 架构存在 | Core0/1/2/3/4 固定职责、CPU isolation、no migration 未固化 | 增加 affinity/tuning 文档和 runtime 参数 |
| 延迟优化 | E2E histogram、stats、PPS/Gbps 部分已有 | NIC RX、RTP、NVDEC、render/display 分段 latency 未全链路统一 | 定义统一 timestamp schema，贯穿 RX->display |
| 目标平台 | 文档指向 Ubuntu/NVIDIA/Mellanox | 自动环境检查不完整 | 扩展 preflight：driver、topology、DPDK、DRM、CUDA、FFmpeg |

## 3. 必须完成清单

### P0：平台与可观测性

- 固化 Ubuntu 24.04 + NVIDIA driver + CUDA + FFmpeg + DPDK + libdrm 环境脚本。
- 增加统一 preflight：NVIDIA、Mellanox、DPDK、DRM、CUDA、FFmpeg、NUMA。
- 定义统一日志字段：`rx_us`、`rtp_us`、`parse_us`、`decode_us`、`display_us`、`queue_depth`、`drops`。

### P1：DPDK RX Engine

- 单队列已实现初版，需要 Linux 验证。
- 增加 RSS 多队列和 queue/core 绑定。
- 增加 mbuf pool 参数、socket id、NUMA node 输出。
- 增加硬件 timestamp 能力检查。
- 与 RTP engine 接口对齐，避免 DPDK 工具只停留在 dump。

### P2：RTP / Parser

- 抽出 RTP parser/reorder/depacketizer 为公共 header/source。
- 增加 jitter timeout 和 loss callback。
- 增加 HEVC RTP payload 支持。
- 增加 SPS/PPS/VPS 缓存与 IDR 对齐策略。

### P3：NVDEC

- 明确 `hevc_cuvid` / `h264_cuvid` 选择和失败原因。
- 每路 camera 输出 decode stats。
- 分离“GPU surface”与“CPU NV12 fallback”的统计。
- 为 CUDA interop 保留 surface 生命周期 API。

### P4/P5：Render + DRM/KMS

- 稳定 GLX/PBO 显示和 E2E latency。
- 增加 CUDA/GL interop smoke。
- 在 `xqc_drm_kms_smoke` 基础上增加 atomic modeset smoke。
- 增加 page flip / vsync pacing 统计。

### P6：GPUDirect RDMA

- 在 `xqc_gpudirect_env_check` 基础上增加 CUDA pinned memory smoke。
- 在 `xqc_cuda_memory_smoke` 通过后增加 RDMA verbs MR 注册实验。
- 增加 RDMA verbs 最小实验：`ibv_get_device_list`、PD、MR 注册。
- 再推进 `nvidia-peermem` + GPU memory registration。
- 最后接入 NIC/GPU 同 root complex 的 zero-copy RX pool。

### P7：Runtime

- Seastar POSIX/eBPF/DPDK 构建目录分离。
- 每 shard 独立队列和 stats。
- 消除热路径 malloc/mutex/shared_ptr。
- NUMA/CPU affinity 配置化。

### P8：多流扩展

- CPU NV12 mosaic baseline 已有。
- 接入真实 per-camera decode output queue。
- 增加 mosaic layout 配置。
- 升级 GL shader compositor，再升级 GPU-native compositor。

## 4. 当前实现完善方向

本轮继续优先补“可在代码侧先落地”的基础设施：

- 已新增 `xqc_spsc_ring.hh`：固定容量、单生产者单消费者、无 mutex、无动态分配。
- 已新增 `xqc_spsc_ring_smoke`：验证 push/pop、full/empty、wrap-around 和双线程生产消费。
- 后续把 decode/display 或 RTP/parser 之间的队列逐步替换成 SPSC ring。

## 5. 验收建议

Ubuntu 装好后建议按顺序验证：

```bash
bash scripts/install_ubuntu_nvidia_deps.sh --with-dpdk
bash scripts/build_linux_nvidia_video_pipeline.sh --with-dpdk-rx

build_linux_nvidia/xquic_tests/xqc_gpudirect_env_check
build_linux_nvidia/xquic_tests/xqc_drm_kms_smoke --device /dev/dri/card0
sudo build_linux_nvidia/xquic_tests/xqc_dpdk_rtp_rx -l 0-1 -n 4 -- --port-id 0 --udp-port 5004
build_linux_nvidia/xquic_tests/xqc_nv12_mosaic_smoke --width 320 --height 240 --columns 2 --rows 2
build_linux_nvidia/xquic_tests/xqc_spsc_ring_smoke
bash scripts/build_linux_nvidia_video_pipeline.sh --with-cuda-smoke
build_linux_nvidia/xquic_tests/xqc_cuda_memory_smoke --bytes 16777216
build_linux_nvidia/xquic_tests/xqc_cuda_gl_interop_smoke --width 640 --height 360
```

如果这些 smoke 全部通过，再进入 NVDEC E2E、多队列 DPDK、DRM atomic 和 GPUDirect registration。
