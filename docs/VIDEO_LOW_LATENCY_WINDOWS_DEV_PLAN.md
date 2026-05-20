# Windows 低延迟视频链路 — 开发计划（对齐现有代码与设计文档）

**设计规格**：[`VIDEO_LOW_LATENCY_WINDOWS_DESIGN.md`](./VIDEO_LOW_LATENCY_WINDOWS_DESIGN.md)（HEVC + NVDEC + OpenGL PBO、Optimus、2/3 PBO 策略等）。

**仓库实现索引（W1–W5 样例代码）**：[`tests/lowlatency/README.md`](../tests/lowlatency/README.md)  
**构建**：`-DXQC_ENABLE_TESTING=ON -DXQC_ENABLE_LOWLATENCY_PHASES=ON`（Windows）。

---

## 0. 对你问题的直接回答

| 说法 | 是否成立 | 说明 |
|------|----------|------|
| 先支持 **Windows 编译** | **部分成立** | 仓库里 **`xquic` 核心库**、`test_client` / `video_client` / `video_bench` 在 `tests/CMakeLists.txt` 中已有 **Windows 分支**（`getopt`、链接库列表等）。 |
| 再按 `VIDEO_LOW_LATENCY_WINDOWS_DESIGN.md` 开发 | **成立；Seastar 服务端 CMake/源码已做第一步适配** | **`xquic_server_seastar`**：Windows 下 **不再链接** `pthread`/`dl`/`m`；**`xquic_server_seastar_ebpf`** 仅 **非 Windows** 构建。`xquic_server_seastar.cpp` / **`xquic_seastar_integration.hh`** 已做 **Winsock、时钟、`mkdir`** 等可移植处理。**子模块 Seastar 仍以 Linux 为主**：在 Windows 上能否完整链接通过，取决于 **Seastar 本仓库对该平台的支持** 与本机依赖链。低延迟 **NVDEC + GL** 仍是设计中的 **新流水线**。 |

**推荐节奏**：**Windows 构建矩阵（可分档）** → **与设计 §1–§8 对齐的实现里程碑** → **每阶段可运行、可测、可回滚**。

---

## 1. 当前代码与设计文档的对应关系

| 设计文档章节 | 仓库现状 |
|--------------|----------|
| xquic + Seastar 收发包 | 已有 **`tests/xquic_server_seastar.cpp`**；**CMake + 头文件/源文件已对 Windows 做首步适配**（见下）；**`xquic_server_seastar_ebpf` 不在 Windows 上构建**。 |
| HEVC 码流、video 客户端 | 已有 **`video_client` / `video_bench`**（libevent，跨平台 CMake 较完整）。 |
| NVDEC、OpenGL、PBO、Optimus 自检 | **部分落地**：**W1** `xqc_gpu_windows_selftest`；**W2 基线** `xqc_nv12_gl_pbo_viewer`（**raw NV12 文件**，FFmpeg NVDEC 待接）。见 **`tests/lowlatency/`**。 |
| 2/3 PBO 策略模式 | **样例**：`xqc_nv12_gl_pbo_viewer --triple-pbo` 仅多分配 PBO；**动态策略类**仍待实现。 |

---

## 2. 建议分阶段开发计划（按依赖排序）

### Phase W0 — Windows 构建基线（必做）

**目标**：在 Windows 上 **稳定产出** 与设计路径相关的二进制（至少能跑通协议与压测侧）。

1. **确认矩阵**（任选一档作为 CI/nightly 最小集）  
   - **W0-A**：`xquic-static` + `test_client` + `video_client` / `video_bench`（**不**开 `XQC_ENABLE_SEASTAR`）。  
   - **W0-B**（若产品必须同进程 Seastar）：**已完成（本仓库）**：`tests/CMakeLists.txt` 中 **`xquic_server_seastar`** 在 **Windows 上不再链接** `pthread`/`dl`/`m`；**`xquic_server_seastar_ebpf`** 用 **`if(NOT CMAKE_SYSTEM_NAME MATCHES "Windows")`** 排除。**待验证**：在目标 Windows 工具链上 **`cmake -DXQC_ENABLE_SEASTAR=ON ...` 能否通过 Seastar 子工程编译与链接**（Seastar 上游以 Linux 为主，若失败可暂用 **WSL2 / Linux 服务端** 与 Windows **客户端** 组合）。  

**验收**：README 或本文档记录 **生成器（VS/Ninja）、OpenSSL/quictls 路径、一条可复制构建命令**；Windows 上 **smoke**：`test_client` 与 `video_client` 能连 **Linux 或本机** 服务端（按你现有脚本习惯）；若启用 W0-B，再增加 **`xquic_server_seastar` 能监听 UDP 并完成握手**。

---

### Phase W1 — 与设计 §3 对齐：独显与进程自检（新代码，体量小）

**目标**：任何会创建 GL / 调 NVDEC 的进程 **启动即验证** NVIDIA 路径（`NvOptimusEnablement` + 系统高性能 + `GL_VENDOR`/`GL_RENDERER`）。

**实现**：`tests/lowlatency/xqc_gpu_windows_selftest.cpp` → 目标 **`xqc_gpu_windows_selftest`**（`XQC_ENABLE_LOWLATENCY_PHASES`）。

**验收**：故意在核显优先环境下应 **日志告警或退出**（与设计一致）。

---

### Phase W2 — 与设计 §6 + §5 + §2 对齐：解码线程 + NV12 + PBO 显示（不依赖 xquic 亦可先做）

**目标**：独立 **`player`/`viewer`**（或 `video_client` 的显示分支）：  
FFmpeg **HEVC + NVDEC** → **NV12**（必要时 hwdownload）→ **2 PBO**（再扩展 **3 PBO + 策略模式**，见设计 §5）→ **全屏 + V-Sync + shader（BT.709/2020）**。

**实现（当前）**：`tests/lowlatency/xqc_nv12_gl_pbo_viewer.cpp` — **raw NV12** 一帧 → **双/三 PBO** + **GL 3.3** + **BT.709 limited** fragment；**`wglSwapIntervalEXT(1)`**；**`NvOptimusEnablement` 导出**；**§5.7** 粗测：`xqc_lowlatency_perf.hh` 打 **swap-to-swap** 周期日志。**FFmpeg NVDEC 解码**下一步替换文件输入即可。

**验收**：本地文件或 **UDP 裸流** 先跑通，再接到 xquic 流；**§5.7** 指标可手工采一版（抖动 / 端到端 / CPU）。

---

### Phase W3 — 与设计 §1 + §8 对齐：有界队列 + 与 xquic 边界

**目标**：**解码 / GL 不进 Seastar reactor**；reactor 或 libevent 回调仅 **投递 HEVC AU/包** 至 **SPSC 解码队列**；解码线程 **ref/unref `AVFrame`** 再入 **渲染队列**（设计 §1–§2）。

**实现**：`tests/lowlatency/xqc_bounded_frame_queue.hh` — **mutex + condition_variable** 有界队列，`push_drop_oldest`、`try_pop_latest`；可直接承载 **`AVFrame*`** 或 **`std::vector<uint8_t>`**（模板 `T`）。与 xquic 的 reactor 边界需在业务线程中 **接入**（本提交未改 `xquic_server_seastar.cpp` 主路径）。

**验收**：长时间跑 **无泄漏**（AddressSanitizer 或 Windows 等价工具能上的话）、**无死锁**；队列满策略符合设计（丢最旧等）。

---

### Phase W4 — 与设计 §7 对齐：`hevc_nvenc` 参数集 + 延迟对拍

**目标**：发送侧（可为 **FFmpeg 命令行** 或 **独立 encoder 模块**）固化 **`ffmpeg -h encoder=hevc_nvenc`** 核对后的 **4K 低延迟参数 JSON**；与接收侧 **NVDEC** 对称测试。

**实现**：
- `docs/config/hevc_nvenc_low_latency.json` — CLI 参数模板
- `scripts/gen_hevc_annexb.sh` — NVENC / libx265 生成 Annex-B
- **跨端操作手册**：[`CROSS_ENDPOINT_HEVC.md`](./CROSS_ENDPOINT_HEVC.md)
- Linux/WSL 收端：`xqc_video_receiver --codec hevc --hw-decode=cuda --display` + `hevc_cuvid`

**验收**：同机或双机 **RTT/丢包** 场景下记录 **E2E** 与 **卡顿主观/客观指标**；`stream_nv12 > 0` 且 WSLg 有画面；明确 **无 `av1_nvenc`** 于 1050 Ti。

---

### Phase W5 — 与设计 §4 对齐：8750H 绑核与散热遥测（可选但建议）

**目标**：Seastar **`--cpuset`**、解码线程 affinity、简单 **频率/温度/帧时间** 日志（与设计 §4–§5.7 一致）。

**实现**：`tests/lowlatency/xqc_lowlatency_perf.hh`（**QPC** 帧间隔）；**Seastar `--cpuset`** 仍为运行时参数（见 Seastar 文档）；CPU/GPU 温度频率需 **WMI/NVML** 等后续再接。

**验收**：对比 **乱绑 vs 文档化绑核** 的 **p95 帧间隔** 与 **CPU 触顶** 情况。

---

## 3. 风险与「不能单靠文档顺序开发」的点

1. **Seastar on Windows**：若 Phase W0-B 成本过高，可 **阶段内** 采用「**Windows 仅 player + libevent xquic 客户端**；Linux 跑 Seastar 服务端」验证 **公网 2/3 PBO**，再合并同进程。  
2. **FFmpeg 与 OpenGL 同卡**：需 **同一适配器** 选 device，否则设计 §3 的故障会出现。  
3. **eBPF 服务端**：**不计划**在 Windows 上复现；文档中 **Linux-only** 即可。

---

## 4. 文档维护

- 每完成一个 Phase，在本文件勾选 **验收项**，并在 `VIDEO_LOW_LATENCY_WINDOWS_DESIGN.md` 中 **仅当行为或接口变化** 时更新规格（避免双文档漂移）。  
- **版本**：与仓库变更同步；首版对应设计文档 **v1.2** 的 PBO 2/3 与策略描述。

---

**结论**：**先做好 Windows 上「你真正要交付的那条构建线」**（至少 W0-A；若要 Seastar 则 W0-B），再 **严格按设计文档的章节顺序实现解码/显示/队列/编码/绑核**，就可以有计划地推进；**不是**「只开 Windows 开关」即自动满足设计全文——**中间差一个「CMake + 新 player + 与 reactor 解耦」的显式阶段**。
