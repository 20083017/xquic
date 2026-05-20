# 开发路线现状对照与执行计划

本文对照 `开发路线.md` 的 P1-P8，说明当前仓库已有能力、缺口、风险和接下来开发顺序。目标平台以 Ubuntu + NVIDIA 为主，macOS 仅作为协议与构建辅助环境。

## 1. 总体判断

当前代码已经具备三条可继续推进的基础线：

- 协议调试线：`xqc_rtp_annexb_receiver` 已支持 POSIX UDP RTP/H.264 到 Annex-B。
- QUIC 媒体线：`video_client`、`xqc_video_receiver` 已支持 Annex-B over QUIC、FFmpeg 解码、NV12 队列和可选显示。
- Runtime 线：Seastar 服务端、eBPF reuseport 变体、Seastar DPDK 构建脚本已经存在。

主要缺口集中在：

- 真正的 DPDK RTP RX 工具和性能计数。
- RTP jitter buffer、丢包策略和 HEVC RTP。
- NVIDIA 侧真正 CUDA/GL 或 EGL zero-copy 显示。
- DRM/KMS direct scanout。
- GPUDirect RDMA。
- 多流 mosaic/compositor。

## 2. P1-P8 现状对照

| 阶段 | 目标 | 当前现状 | 缺口 | 下一步交付 |
|------|------|----------|------|------------|
| P1 DPDK RTP RX | hugepage、DPDK init、RX queue、packet dump、timestamp | POSIX RTP 接收器存在；Seastar DPDK 是 QUIC 服务端后端；`xqc_dpdk_rtp_rx` 已提供独立 DPDK RTP RX 初版，含 VLAN/SSRC/payload 解析 | RSS、多队列、硬件时间戳、DPDK RTP->AnnexB | 在 Ubuntu+DPDK 上编译运行 `xqc_dpdk_rtp_rx`，根据结果推进多队列 |
| P2 RTP Reorder | sequence reorder、jitter、loss、FU-A、STAP-A | `xqc_rtp_annexb_receiver` 支持 H.264 single/STAP-A/FU-A 和有限 seq reorder | 时间窗 jitter buffer、丢包策略、HEVC RTP、可复用库化 | 抽出 RTP depacketizer/reorder 模块，增加 jitter/loss 指标 |
| P3 FFmpeg/NVDEC | hwaccel、CUDA context、NVDEC decode | `xqc_h264_hw_linux.cpp`、`xqc_h264_ff_decode_worker.cpp` 已支持 CUDA/NVDEC 入口 | GPU surface 生命周期、稳定多路 session、统计和故障降级 | 强化 NVDEC backend 自检、每路 decode stats、多路压力脚本 |
| P4 EGL/GL Render | CUDA interop、OpenGL texture、EGL display | VAAPI/EGL dma-buf、NVIDIA GLX/PBO 和 `xqc_cuda_gl_interop_smoke` 前置原型存在 | NVIDIA NVDEC CUDA surface 尚未接入 graphics resource，不是真 zero-copy | 在 Ubuntu 上验证 interop smoke，再接 NVDEC surface 生命周期 |
| P5 DRM/KMS | atomic modeset、direct scanout、vsync pacing | `xqc_drm_kms_smoke` 已提供非破坏性 DRM/KMS 枚举和 atomic cap 检查 | DRM master、modeset、page flip、显示资源管理 | 在 Linux 显示环境验证后增加独立 atomic modeset smoke |
| P6 GPUDirect RDMA | NIC DMA -> GPU VRAM | `xqc_gpudirect_env_check` 已提供 nvidia-peermem、RDMA、IOMMU、PCI/NUMA/topology 预检；`xqc_cuda_memory_smoke` 已提供 CUDA memory primitive 验证 | DOCA/GPUNetIO、mbuf 与 GPU memory 映射、RDMA MR 注册实验 | 根据预检结果推进最小 RDMA/GPU memory registration |
| P7 Seastar Runtime | shard-per-core、lock-free、NUMA aware | Seastar、eBPF、DPDK 构建路径已有 | 与视频链路的多 shard 路由、NUMA/绑核、无锁热路径 | 固化 build/run 脚本，补 runtime stats 和视频路径压测 |
| P8 多流扩展 | multi-session decode、compositor、mosaic | camera_id、per-camera decoder 和 `xqc_nv12_mosaic_smoke` CPU NV12 合成基线已有，支持 synthetic 和 raw NV12 输入 | 多路同步、mosaic GL compositor、显示布局 | 接入 decode queue，升级 GL/GPU compositor |

## 3. 分阶段开发计划

### 阶段 A：P1/P2 网络入口闭合

目标：让 Linux/NVIDIA 机器上能分别验证 POSIX RTP、DPDK RTP、QUIC 视频三条入口。

交付：

- `xqc_dpdk_rtp_rx`：DPDK EAL 初始化、端口配置、RX queue、burst receive、RTP/UDP 粗过滤、packet dump、周期统计。
- `xqc_rtp_annexb_receiver`：保留 POSIX fallback，用作正确性对照。
- 文档：DPDK hugepage、绑卡、运行命令和对照测试方法。

验收：

- DPDK 模式能稳定打印 packet/byte/pps/bps/drop/bad RTP 统计。
- 同一个 RTP 流可以用 POSIX 与 DPDK 两个工具分别收包。

### 阶段 B：P2 可复用 RTP Engine

目标：把 RTP/H.264 depacketize 从 demo 工具中抽成可复用模块。

交付：

- RTP parser、reorder buffer、H.264 depacketizer、Annex-B writer 分层。
- 增加 jitter wait、gap timeout、loss counter。
- 为后续 HEVC RTP payload 预留 codec 分发接口。

验收：

- single NAL、STAP-A、FU-A、乱序、丢包样例均可输出指标。
- 热路径避免 per-packet 大量堆分配。

### 阶段 C：P3 NVDEC 稳定化

目标：保证 HEVC/H.264 通过 FFmpeg NVDEC 稳定解码，且不会阻塞 reactor。

交付：

- CUDA/NVDEC backend 自检和日志标准化。
- 每 camera decode stats：input NAL、decoded frame、drop、latency。
- `xqc_video_receiver` 的纯 decode 与 display 模式分开验证。

验收：

- `hevc_cuvid` / `h264_cuvid` 可被明确选中。
- 4K/30fps 单流稳定，随后扩展多路。

### 阶段 D：P4 显示链路

目标：先稳定 NVIDIA GLX/PBO 显示，再推进 zero-copy 原型。

交付：

- PBO path 的帧队列、drop-oldest/latest 策略、present latency 统计。
- `xqc_cuda_gl_interop_smoke`：验证 OpenGL texture 可被 CUDA graphics resource 注册、映射和写入。

验收：

- PBO 版本稳定显示并可记录 wire->display、recv->display histogram。
- zero-copy 原型能在独立 demo 中显示一帧或连续帧。

### 阶段 E：P7 Runtime 与 P8 多流

目标：把网络、多路解码、显示合成连接到更接近生产的运行时。

交付：

- Seastar POSIX/eBPF/DPDK 构建目录和运行脚本统一。
- 多 camera decode session 和 mosaic compositor。
- NUMA/CPU affinity 配置模板。

验收：

- 多流可以按 camera_id 解码、统计、显示。
- 运行时日志能清楚标识网络后端、shard、队列和 drop。

### 阶段 F：P5/P6 深水区

目标：在 P1-P4 数据稳定后进入 direct display 和 NIC->GPU zero-copy。

交付：

- DRM/KMS smoke：atomic modeset、page flip、vsync pacing。
- GPUDirect 环境检查：nvidia-peermem、IOMMU、NIC/GPU topology。
- CUDA memory smoke：`cudaHostAlloc`、`cudaHostRegister`、`cudaMalloc` 和 stream async copy。
- 最小 RDMA/GPU memory registration 实验。

验收：

- P5 能独立显示测试帧并测 present timing。
- P6 能证明 NIC/GPU memory 注册路径可行，再接入主链路。

## 4. 编译与测试分工

由代码侧提供：

- CMake option 和目标。
- Ubuntu/NVIDIA 构建脚本。
- DPDK/FFmpeg/NVDEC/显示的运行文档。
- 可复现的命令和日志字段。

由 Linux 机器验证：

- DPDK 是否能初始化端口和 RX queue。
- NVIDIA driver/CUDA/FFmpeg 是否匹配。
- GL/显示环境是否可用。
- 实际 PPS、帧率、延迟和 CPU 占用。

## 5. 当前本轮开发起点

本轮已完成首批 P1/P5/P6/P8 基础工具：

- 新增 `xqc_dpdk_rtp_rx` 作为 P1 独立 DPDK RTP RX 初版。
- 新增 `xqc_drm_kms_smoke` 作为 P5 非破坏性 DRM/KMS 能力检查。
- 新增 `xqc_gpudirect_env_check` 作为 P6 GPUDirect RDMA 环境预检。
- 新增 `xqc_cuda_memory_smoke` 作为 P6 RDMA/GPU memory registration 前置实验。
- 新增 `xqc_cuda_gl_interop_smoke` 作为 P4 NVIDIA CUDA surface -> GL texture 前置原型。
- 新增 `xqc_nv12_mosaic_smoke` 和 `xqc_nv12_mosaic.hh` 作为 P8 CPU NV12 mosaic 基线。
- P1/P5 默认不启用，避免影响没有 DPDK/libdrm 的开发环境；P6/P8 可在普通开发环境构建。
