# Seastar Runtime + DPDK + GPU Pipeline 深度架构

---

# 1. Runtime Philosophy

核心原则：

```text id="gq8w3z"
Shared Nothing
```

每个 CPU Core：

- 独立 shard
- 独立内存
- 独立 queue
- 独立 GPU stream

禁止：

- cross-core lock
- shared queue
- global mutex

---

# 2. Shard Architecture

```text id="j4np0e"
             ┌─────────────────────────┐
             │       NIC RSS           │
             └──────────┬──────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼

      Core0         Core1         Core2
    RX Queue0     RX Queue1     RX Queue2

          │             │             │
          ▼             ▼             ▼

     RTP Parser    RTP Parser    RTP Parser

          │             │             │
          ▼             ▼             ▼

      NVDEC0        NVDEC1        NVDEC2

          │             │             │
          ▼             ▼             ▼

      EGL Pipe      EGL Pipe      EGL Pipe
```

每个 shard：

```text id="lbgxxy"
RX → RTP → Decode → Render
```

独立完成。

---

# 3. 为什么不能共享 Queue

共享 queue 会导致：

- cache bouncing
- NUMA penalty
- lock contention
- scheduler migration

最终：

```text id="e1vqte"
Latency Spike
```

实时系统最大敌人：dpdk

不是平均延迟。

而是：

```text id="3dmslq"
P99 / P999 latency
```

---

# 4. Seastar Reactor Model

每核：

```cpp id="ghwdhv"
reactor::run()
```

内部：

- poll NIC
- poll GPU completion
- process RTP
- submit decode

本质：

```text id="0qmwl1"
event-driven polling
```

不是传统 epoll。

---

# 5. DPDK Memory Pool 设计

---

# 5.1 Memory Topology

```text id="3d0u5p"
HugePage
 └── mempool
      └── mbuf
```

推荐：

```text id="yih5yk"
2MB hugepage
```

避免：

```text id="0hvq0g"
4KB page
```

因为：

TLB miss 会毁掉吞吐。

---

# 5.2 NUMA Local Pool

每 NUMA：

```cpp id="1wv5na"
rte_pktmbuf_pool_create()
```

独立 pool。

禁止：

```text id="s0u9kp"
cross-numa allocation
```

---

# 5.3 Cache Aligned Mbuf

推荐：

```cpp id="j0owiu"
__rte_cache_aligned
```

避免：

```text id="opby3h"
false sharing
```

---

# 5.4 Burst Strategy

推荐：

```cpp id="31i7v1"
rte_eth_rx_burst(..., 32)
```

不要：

```cpp id="y6slm3"
burst=1
```

原因：

PCIe transaction 太贵。

---

# 6. CUDA Ring Buffer

---

# 6.1 GPU Ring Topology

```text id="g1j1n8"
CUDA Surface Ring

slot0
slot1
slot2
...
slotN
```

每个 slot：

```text id="iutpc5"
Decoded frame
```

---

# 6.2 为什么 Ring Buffer 很重要

避免：

```text id="2dr8k4"
cudaMalloc/cudaFree
```

GPU allocator latency 非常高。

---

# 6.3 Persistent Surface Pool

启动时：

一次性：

```cpp id="8ls0uv"
cuMemAlloc()
```

之后：

循环复用。

---

# 6.4 GPU Fence

同步：

```text id="baf0zi"
CUDA Event
```

不要：

```cpp id="4jv6z4"
cudaDeviceSynchronize()
```

因为会 stall 全 GPU。

---

# 7. NVDEC Session 管理

---

# 7.1 Session Model

每路视频：

```text id="6cb5vc"
CUvideodecoder
```

独立 session。

---

# 7.2 多 Session 调度

GPU 内部：

NVDEC engine 是独立硬件。

例如：

RTX A5000：

```text id="cn3ggk"
5~8 concurrent decode engines
```

---

# 7.3 Session Affinity

推荐：

```text id="s7zjlwm"
1 stream → 1 shard → 1 decoder
```

避免：

动态迁移 session。

---

# 7.4 Decode Queue

推荐：

```text id="djlwm6"
async decode submit
```

不要：

同步 decode。

---

# 8. RTP Jitter 算法

---

# 8.1 RTP 问题

UDP：

- out-of-order
- packet loss
- jitter

必须：

```text id="w5u2q0"
reorder buffer
```

---

# 8.2 Jitter Buffer

```text id="y2f3j8"
seq=1000
seq=1001
seq=1003
```

等待：

```text id="wpcw5d"
1002
```

超时后：

丢帧恢复。

---

# 8.3 自适应窗口

```text id="z4v2y0"
window = RTT variance
```

不是固定长度。

---

# 8.4 超低延迟策略

云游戏里：

宁可：

```text id="6k6hfd"
drop frame
```

也不要：

```text id="9rqf1y"
wait too long
```

---

# 9. AV1 Parser

---

# 9.1 AV1 更复杂

因为：

- OBU
- tile
- film grain
- superframe

比 H264 难很多。

---

# 9.2 推荐方案

不要自己写。

推荐：

- libdav1d
- libaom parser

---

# 9.3 GPU Decode

AV1：

推荐：

```text id="j5je07"
NVDEC AV1
```

CPU 解 AV1 非常重。

---

# 10. Vulkan Video Decode

---

# 10.1 Vulkan Video

新一代：

```text id="95y4t2"
VK_KHR_video_decode_queue
```

---

# 10.2 优势

比：

```text id="q2kkr4"
NVDEC proprietary API
```

更现代。

支持：

- decode
- compute
- render

统一 pipeline。

---

# 10.3 未来趋势

未来：

```text id="mggq7t"
CUDA + NVDEC
```

会逐渐：

转向：

```text id="6ct7s7"
Vulkan Video
```

统一图形/视频栈。

---

# 11. GPUDirect RDMA 框架

---

# 11.1 真正 Zero Copy

目标：

```text id="f4qv5j"
NIC DMA → GPU VRAM
```

绕过：

CPU RAM。

---

# 11.2 内核模块

必须：

```text id="xqzaxv"
nvidia-peermem
```

---

# 11.3 PCIe 要求

NIC 与 GPU：

必须：

```text id="x5c5tt"
same PCIe root complex
```

否则：

P2P 会失败。

---

# 11.4 Memory Registration

```cpp id="3f9b5m"
ibv_reg_mr()
cudaHostRegister()
```

---

# 11.5 真正难点

不是 API。

而是：

```text id="u1r1c6"
PCIe topology
```

和：

```text id="ncrl0q"
IOMMU mapping
```

---

# 12. DRM Atomic Pipeline

---

# 12.1 为什么不用 X11

X11：

- compositor
- copy
- vsync queue

延迟太高。

---

# 12.2 DRM/KMS

直接：

```text id="l6og2w"
page flip
```

---

# 12.3 Atomic Commit

```cpp id="0qh7sj"
drmModeAtomicCommit()
```

低 jitter。

---

# 13. 多 GPU 多 NUMA

---

# 13.1 GPU Affinity

原则：

```text id="ix8h3f"
1 NUMA ↔ 1 GPU ↔ 1 NIC
```

---

# 13.2 禁止跨 NUMA

否则：

```text id="vk3y6y"
QPI / InfinityFabric
```

延迟会暴涨。

---

# 13.3 Multi-GPU Routing

推荐：

```text id="djlwm5"
RSS hash → shard → GPU
```

静态映射。

---

# 14. Linux PREEMPT_RT

---

# 14.1 作用

降低：

- scheduler jitter
- interrupt latency

---

# 14.2 CPU Isolation

推荐：

```text id="ujzrm1"
isolcpus=
nohz_full=
rcu_nocbs=
```

---

# 14.3 IRQ Affinity

NIC IRQ：

绑定：

```text id="6mb4p2"
same NUMA core
```

---

# 14.4 禁止 C-State

BIOS：

关闭：

- C6
- deep sleep

否则：

wake latency 太高。

---

# 14.5 软件路径优化（GTX 1050 + 4K HEVC，已实现）

针对 **500ms 级 wire_pts 积压** 与 **偶发 display spike**，优先级如下（代码已落地）：

| 优先级 | 优化 | 实现位置 | 环境变量 |
|--------|------|----------|----------|
| 1 | QUIC LOW_DELAY（ack=1, 更快 loss detect） | `xqc_video_receiver.cpp`, `xqc_video_client.cpp` | `XQC_LOW_DELAY=0` 关闭 |
| 2 | 解码队列 catch-up：非 IDR 在积压时丢弃 | `xqc_video_recv_process.hh` | `XQC_DECODE_QUEUE_DROP=8` |
| 3 | NV12 队列深度 1 + display bridge 只送最新帧 | `xqc_h264_ff_decode_worker.cpp`, `xqc_video_receiver.cpp` | `XQC_NV12_QUEUE_DEPTH=1` |
| 4 | cuvid `AV_CODEC_FLAG_LOW_DELAY`（`ulMaxDisplayDelay=0`） | `xqc_h264_hw_linux.cpp` | — |
| 5 | GL 单槽 latest-wins + CUDA-GL interop (no hwdownload) | `xqc_cuda_gl_nv12.cpp`, `xqc_nv12_gl_linux.cpp` | — |

**待做（更大改动）：**

- **QUIC Datagram** 替代 Stream（避免重传队头阻塞）— 需新 sender/receiver 路径
- **CUDA-GL Interop** 替代 PBO — **已实现**（`xqc_cuda_gl_nv12.cpp`，NVDEC 帧 D2D 到 GL 纹理）
- **SPSC 无锁队列** — **已实现**（Annex-B + NV12 路径，`XqcSpscFrameQueue`）

典型运行（libevent 接收端）：

```bash
export LD_LIBRARY_PATH=~/ffmpeg-hw/lib:$LD_LIBRARY_PATH
export XQC_LOW_DELAY=1          # 默认已开
export XQC_NV12_QUEUE_DEPTH=1   # 默认
export XQC_DECODE_QUEUE_DROP=8  # 积压时丢非关键帧
./build_linux_nvidia/xquic_tests/xqc_video_receiver ... --codec hevc --hw-decode=cuda --decode --display
```

**Seastar 接收端（canonical `xqc_video_receiver`，最佳 4K 性能）**

```bash
export LD_LIBRARY_PATH=~/ffmpeg-hw/lib:$LD_LIBRARY_PATH
export XQC_PIN_AFFINITY=1
export XQC_DECODE_CPU=2         # 与网卡 IRQ 同核（见 /proc/interrupts）
export XQC_DISPLAY_CPU=4        # GL 独占另一物理核
bash scripts/build_seastar_video_receiver.sh
./build_seastar/xquic_tests/xqc_video_receiver \
  --smp 1 --cpuset 0 -p 8443 --decode --display --codec hevc --hw-decode=cuda
```

共享 decode/display/CUDA 管线：`xqc_video_receiver_pipeline.cpp`（libevent 仅在未启用 Seastar 时作 fallback）。

### 混合显卡（Intel 集显 + NVIDIA 独显）

若日志出现 `OpenGL renderer is 'Mesa Intel(R) UHD Graphics 630'` 且 `hwdownload+PBO fallback`，
说明 GL 在集显、NVDEC 在独显，CUDA-GL 零拷贝失效（显存→内存→显存）。

**对策**（程序默认会尝试设置，可用 `XQC_NVIDIA_PRIME=0` 关闭）：

```bash
export __NV_PRIME_RENDER_OFFLOAD=1
export __GLX_VENDOR_LIBRARY_NAME=nvidia
```

成功后应看到 `OpenGL renderer string: NVIDIA GeForce ...`，CUDA-GL interop 生效。

### CPU 亲和性（decode / display 线程）

| 线程 | 绑定方式 | 环境变量 |
|------|----------|----------|
| Seastar reactor（QUIC 收包） | Seastar `--cpuset N` | 与网卡 IRQ 对齐 |
| decode-thread | `pthread_setaffinity_np` | `XQC_DECODE_CPU` 或 `XQC_PIN_AFFINITY=1` |
| display-thread / bridge | `pthread_setaffinity_np` | `XQC_DISPLAY_CPU` 或 `XQC_PIN_AFFINITY=1` |

### 待做（更大改动）

- **QUIC Datagram** 替代 Stream（避免重传队头阻塞）
- **帧跳过**：NV12 SPSC depth>1 时消费端只保留最新帧（部分已由 `XQC_NV12_QUEUE_DEPTH=1` 覆盖）
