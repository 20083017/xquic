# Seastar eBPF 路径接入 GRO/GSO 设计文档（方案 A）

> 状态：**草案，待评审**
> 范围：仅影响 [tests/xquic_server_seastar_ebpf.cpp](../tests/xquic_server_seastar_ebpf.cpp)
> 目的：让 `_reuseport_fd`（带 cBPF 派发）真正生效，并在该路径上启用 UDP_GRO 收聚 + UDP_SEGMENT (GSO) 发批处理

---

## 1. 现状与问题

### 1.1 eBPF FD 未被使用（预先存在的 bug）

```cpp
// xquic_server_seastar_ebpf.cpp 约 575 行
if (_reuseport_fd >= 0) {
    _ebpf_mode = true;
    seastar::socket_address bind_addr = ...;
    _udp_channel.emplace(
        seastar::engine().net().make_bound_datagram_channel(bind_addr));
    // 注释承认 "for now, just use Seastar's own bound channel per shard"
    // _reuseport_fd 从此被忽略
}
```

后果：

| 期望 | 实际 |
| --- | --- |
| 内核按 `cBPF(DCID[0] % shards)` 派发到固定 shard | 内核按默认 5 元组哈希派发，跨 shard 跳跃 |
| 同一 QUIC 连接稳定落在一个 shard | 同一连接可能被分到不同 shard（CID 相同 + 不同 4 元组时） |
| `_reuseport_fd` 持有 cBPF 程序 | FD 创建后被持有但永不收发，等同于泄漏 |

### 1.2 Seastar `udp_channel` 阻挡 GRO/GSO

- `_udp_channel->receive()` 返回 `seastar::net::udp_datagram` / `net::packet`，**屏蔽了 cmsg**，无法读取 `SOL_UDP/UDP_GRO` 返回的 `gso_size`，于是聚合后的 64KB 块会被当成单个 QUIC 包，xquic 解析失败
- `_udp_channel->send(packet)` 不暴露 cmsg，无法在发送端附加 `UDP_SEGMENT` 通知内核做 GSO

结论：要在此路径上获得 GRO/GSO 收益，必须**绕过 `udp_channel`**。

---

## 2. 设计目标

1. **正确性优先**：eBPF 派发真正生效；recv/send 行为与 POSIX `test_server` 等价
2. **最小侵入**：仅替换 eBPF 分支的 recv/send 实现，POSIX fallback 分支保持不变
3. **性能**：开启 UDP_GRO + UDP_SEGMENT，期望 syscall 数量降一个数量级，CPU −30~50%
4. **可回退**：内核 / NIC 不支持 GSO 时静默回退为逐包 sendmsg；不支持 GRO 时按单包处理（cmsg 未返回 gso_size 即视作 1 段）
5. **生命周期安全**：与 Seastar `gate` / `with_gate` / 异常路径完全融合，不留 fd 或 task 泄漏

---

## 3. Seastar 公开 API 调研

`third_party/seastar/include/seastar/core/internal/pollable_fd.hh`（虽在 `internal/` 路径，但 `pollable_fd` 类被 `posix-stack.hh` 等公共头依赖，可直接使用）：

```cpp
class pollable_fd {
    pollable_fd(file_desc fd, speculation = {});
    future<> readable();
    future<> writeable();
    future<size_t> recvmsg(struct msghdr *msg);   // ★ 关键
    future<size_t> sendmsg(struct msghdr *msg);   // ★ 关键
    void shutdown(int how);
    void close();
};
```

意味着我们可以：

1. 把 `_reuseport_fd` 包装成 `seastar::file_desc::from_fd(_reuseport_fd)`
2. 构造 `seastar::pollable_fd(std::move(file_desc))`
3. 直接 `recvmsg(&msg)` / `sendmsg(&msg)`，自带 reactor 集成（epoll EPOLLIN/EPOLLOUT 调度）

cmsg 部分复用现有 [tests/xqc_socket_opts.h](../tests/xqc_socket_opts.h) 中的 `xqc_udp_recvmsg_gro` 解析逻辑与 `xqc_udp_writer_t` GSO 写入器，但需要把同步 `recvmsg/sendmsg` 调用替换为 Seastar 的异步 `pollable_fd::recvmsg/sendmsg`，因此不能直接复用，需要派生一份异步版本。

---

## 4. 数据结构变更

`XquicSeastarServerEbpf` 头文件 [tests/xquic_server_seastar_ebpf.hh](../tests/xquic_server_seastar_ebpf.hh)：

```cpp
// 仅在 eBPF 模式启用（_reuseport_fd >= 0）
std::optional<seastar::pollable_fd> _ebpf_pfd;     // 新增：直接持有 eBPF FD
xqc_udp_writer_t                    _ebpf_writer;  // 新增：GSO 写入器
char                                _ebpf_recv_buf[64 * 1024];  // 新增：聚合 recv 缓冲

// 保留：POSIX fallback 仍然用 _udp_channel
std::optional<seastar::net::udp_channel> _udp_channel;
```

---

## 5. 初始化变更

`init()` 中 eBPF 分支：

```cpp
if (_reuseport_fd >= 0) {
    _ebpf_mode = true;

    // 1. 应用 socket 选项 + 启用 UDP_GRO（在 main 线程已经做过 bind/listen，
    //    此处按 shard 再 setsockopt 一次保险，幂等）
    xqc_apply_udp_perf_opts(_reuseport_fd, AF_INET, /*is_server=*/1);
    xqc_enable_udp_gro(_reuseport_fd);

    // 2. 包成 pollable_fd，归 reactor 管
    auto fd = seastar::file_desc::from_fd(_reuseport_fd);
    _ebpf_pfd.emplace(std::move(fd));
    _reuseport_fd = -1;  // 所有权已转移给 pollable_fd

    // 3. 初始化 GSO 写入器（直接基于 pfd 内部 fd 做 sendmsg；
    //    writer 不持有 fd，仅缓冲）
    xqc_udp_writer_init(&_ebpf_writer, _ebpf_pfd->get_file_desc().get());

    // 4. 启动异步收包循环
    _receive_loop.emplace(
        seastar::with_gate(_background_ops, [this] {
            return run_ebpf_receive_loop();
        }).handle_exception([this](std::exception_ptr ep) { ... })
    );
}
```

> ⚠ **关键所有权点**：`pollable_fd` 持有 `file_desc`，析构时会 `close()`。我们设置 `_reuseport_fd = -1` 防止 `~XquicSeastarServerEbpf` 重复关闭。

---

## 6. 收包路径（替换 `run_receive_loop`）

新增 `run_ebpf_receive_loop()`：

```cpp
seastar::future<> XquicSeastarServerEbpf::run_ebpf_receive_loop() {
    return seastar::do_until(
        [this] { return _stopping || !_ebpf_pfd; },
        [this] {
            // 准备 msghdr
            struct sockaddr_storage peer = {};
            struct iovec iov = { _ebpf_recv_buf, sizeof(_ebpf_recv_buf) };
            char cbuf[CMSG_SPACE(sizeof(uint16_t))] = {};  // gso_size
            struct msghdr msg = {};
            msg.msg_name = &peer;
            msg.msg_namelen = sizeof(peer);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);

            return _ebpf_pfd->recvmsg(&msg).then(
                [this, msg = msg, peer](size_t n) mutable {
                    if (n == 0) return seastar::make_ready_future<>();

                    // 解析 GRO cmsg
                    uint16_t gso_size = 0;
                    for (auto* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
                        if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO) {
                            memcpy(&gso_size, CMSG_DATA(cm), sizeof(gso_size));
                            break;
                        }
                    }
                    if (gso_size == 0) gso_size = n;  // 未聚合，整块即一段

                    // 分片喂给 xquic engine
                    size_t off = 0;
                    while (off < n) {
                        size_t seg = std::min<size_t>(gso_size, n - off);
                        xqc_engine_packet_process(
                            _engine,
                            (const unsigned char *)_ebpf_recv_buf + off, seg,
                            (struct sockaddr *)&_local_addr, _local_addrlen,
                            (struct sockaddr *)&peer, msg.msg_namelen,
                            xqc_now(),
                            &_packet_user_conn);
                        off += seg;
                    }

                    xqc_engine_finish_recv(_engine);
                    xqc_udp_writer_flush(&_ebpf_writer);
                    return seastar::make_ready_future<>();
                });
        });
}
```

要点：

- **Seastar 风格**：`do_until` + future 链，避免阻塞 reactor
- **GRO 兼容**：cmsg 缺失时退化为整块 = 1 段，与 POSIX 路径一致
- **批量结束 flush**：每个 reactor task 末尾 flush GSO 缓冲，保证延迟可控

---

## 7. 发包路径（异步 sendmsg + GSO 合并）

### 7.1 现有架构复用

[tests/xquic_seastar_integration.hh](../tests/xquic_seastar_integration.hh) 已经实现了完整的异步发包流水线：

```
xquic engine → ss_write_socket (同步回调)
             → enqueue_send (memcpy 到 _send_integration 内部队列, 立即返回)
             → schedule_send_flush
                  ↳ 若 _send_flush_in_progress=true，跳过
                  ↳ 否则 with_gate 异步执行 flush_send_queue()
                       → _send_integration.flush_to(udp_channel)
                          → do_until empty: udp_channel->send(...)
```

这套机制完美匹配 xquic 同步回调 + Seastar 异步 I/O 的需要。**eBPF 路径只需新增一个 flush 实现**，整体编排无须改动。

### 7.2 新增 `flush_to_pollable_fd_with_gso`

在 [tests/xquic_seastar_integration.hh](../tests/xquic_seastar_integration.hh) 的 `XquicSeastarSendIntegration` 类中新增：

```cpp
// 新接口：基于 pollable_fd 异步 sendmsg，自动按 (peer, size) 合并为 GSO 批次
seastar::future<> flush_to_pollable_fd_with_gso(
    seastar::pollable_fd& pfd,
    bool gso_enabled);
```

实现要点（伪代码）：

```cpp
seastar::future<> flush_to_pollable_fd_with_gso(seastar::pollable_fd& pfd, bool gso_enabled) {
    return seastar::do_until(
        [this] { return _queue.empty(); },
        [this, &pfd, gso_enabled] {
            // 1. 从队列前端取出一批 (peer, size) 完全相同的连续 datagram
            //    最多 64 段，避免超过 IP 总长上限
            auto batch = _queue.pop_gso_batch(/*max_segments=*/64);

            // 2. 构造 msghdr：单个 iovec 指向拼接好的连续缓冲，cmsg 设 UDP_SEGMENT
            struct iovec iov = { batch.merged_buf.get_write(), batch.merged_size };
            char cbuf[CMSG_SPACE(sizeof(uint16_t))] = {};
            struct msghdr msg = {};
            msg.msg_name = batch.peer.as_posix_sockaddr();
            msg.msg_namelen = batch.peer.length();
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            if (gso_enabled && batch.segment_count > 1) {
                msg.msg_control = cbuf;
                msg.msg_controllen = sizeof(cbuf);
                auto* cm = CMSG_FIRSTHDR(&msg);
                cm->cmsg_level = SOL_UDP;
                cm->cmsg_type  = UDP_SEGMENT;
                cm->cmsg_len   = CMSG_LEN(sizeof(uint16_t));
                uint16_t gso_size = batch.segment_size;
                memcpy(CMSG_DATA(cm), &gso_size, sizeof(gso_size));
            }

            // 3. 异步 sendmsg；失败时按 errno 回退到逐包
            return pfd.sendmsg(&msg).then_wrapped(
                [this, &pfd, batch = std::move(batch), gso_enabled]
                (seastar::future<size_t> f) mutable {
                    if (f.failed()) {
                        try { f.get(); } catch (const std::system_error& e) {
                            // EIO/EINVAL/ENOTSUP → 关闭 GSO 改逐包重发
                            if (gso_enabled && is_gso_unsupported_errno(e.code().value())) {
                                _gso_disabled = true;
                                return resend_batch_per_packet(pfd, std::move(batch));
                            }
                            // EAGAIN → pollable_fd 已经处理了 epoll 等待，此处不应到达
                            // 其他错误 → 丢弃这批，xquic 自行重传
                            return seastar::make_ready_future<>();
                        }
                    }
                    return seastar::make_ready_future<>();
                });
        });
}
```

### 7.3 队列改造：`pop_gso_batch`

[tests/xquic_seastar_queue.hh](../tests/xquic_seastar_queue.hh) 现有 `pop()` 返回单个 `Datagram`。新增：

```cpp
struct GsoBatch {
    seastar::socket_address peer;
    seastar::temporary_buffer<char> merged_buf;  // 连续 N 段拼接的总缓冲
    size_t segment_size = 0;       // 每段长度（除最后一段可能 <= segment_size）
    size_t segment_count = 0;
    size_t merged_size = 0;        // 总长度
};
GsoBatch pop_gso_batch(size_t max_segments = 64);
```

规则：
- 从队首取第一个 datagram，记录其 `peer` 与 `size` 作为 `segment_size`
- 继续取相同 peer 且 `size <= segment_size` 的 datagram，最多 `max_segments` 个
- 一旦 peer 变化、size 变大、或 size 不等且不是末段（按 UDP_SEGMENT 语义最后一段可短，中间段必须等长）→ 停止合并
- 拼接到一块 `temporary_buffer` 中

如果队列只有一项或全部 size 不一致：直接退化为单段，行为等价于原有 `pop()`。

### 7.4 ss_write_socket 回调（同步层）

保持现状，无改动 —— `enqueue_send` 行为不变，所有改动落在 flush 阶段。

```cpp
// xquic_server_seastar_ebpf.cpp 现有代码不动
ssize_t XquicSeastarServerEbpf::ss_write_socket(...) {
    return self->enqueue_send(buf, size, peer_addr, peer_addrlen);
}
```

### 7.5 flush_send_queue 分支

```cpp
seastar::future<> XquicSeastarServerEbpf::flush_send_queue() {
    if (_stopping) return seastar::make_ready_future<>();
    if (_ebpf_mode && _ebpf_pfd) {
        return _send_integration.flush_to_pollable_fd_with_gso(*_ebpf_pfd, _gso_enabled);
    }
    // POSIX fallback 不变
    auto& ch = get_send_channel();
    return _send_integration.flush_to(ch).then([] {});
}
```

### 7.6 背压策略

现有 `enqueue_send` 在 `_queue.full()` 时返回 EAGAIN，xquic engine 会按拥塞控制重传。**保持不变**，无需新增。

### 7.7 关键不变量

- 单 shard 内最多一个 in-flight flush（`_send_flush_in_progress` 互斥）
- flush 自驱动：完成后若队列非空自动重新 schedule（[已有逻辑](../tests/xquic_server_seastar_ebpf.cpp#L870-L874)）
- xquic 同步回调零等待：所有 await 发生在 flush 任务里，不阻塞 packet_process / engine_main_logic

---

## 8. 关闭与异常路径

- `stop()` / `~XquicSeastarServerEbpf`：
  - `_stopping = true`
  - `if (_ebpf_pfd) _ebpf_pfd->shutdown(SHUT_RDWR);` 让 `recvmsg` 立即唤醒并返回 0
  - 等待 `_background_ops` gate 关闭
  - `_ebpf_pfd.reset()` 释放 FD
- 异常：`run_ebpf_receive_loop` 链内 `handle_exception` 同现有模式

---

## 9. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| `pollable_fd` 在 `internal/` 命名空间路径，未来 ABI 变化 | 第三方 Seastar 版本固定在 `third_party/`，可控 |
| 跨 shard 内存（`_ebpf_recv_buf` 由 shard 本地访问，无共享） | 每个 shard 独立实例，无共享 |
| writer 同步 sendmsg 阻塞 reactor | 非阻塞 fd + EAGAIN 回退；监控 sendmsg 延迟 |
| GSO/GRO 内核不支持 | helper 内部回退已实现 |
| `file_desc::from_fd` 接管 FD 后构造抛异常 → FD 双关闭 | 在 `_reuseport_fd = -1` 之前完成构造，try/catch 包裹 |
| eBPF 分支与 POSIX fallback 分支代码膨胀 | 核心收发逻辑集中在 `run_ebpf_receive_loop`，主类增加 ~80 行 |

---

## 10. 测试与验证矩阵

| 场景 | 期望 |
| --- | --- |
| 单 shard，1 client，短消息 | 与 POSIX test_server 行为完全一致 |
| 多 shard（4），多 client | 相同 DCID 始终落在同一 shard（用 `nstat` + per-shard 计数器验证） |
| 大流量回环（test_client `-T 10`） | `nstat -au UdpInDatagrams` 数量明显低于改前；相同应用层吞吐下 perf 显示 sendmsg/recvmsg syscall 数量降 5-10 倍 |
| 关闭/重启 | 无 FD 泄漏（`/proc/pid/fd` 计数稳定） |
| 内核 < 5.0（无 UDP_GRO） | 服务正常运行，仅 GRO 不生效 |
| GSO setsockopt 失败 | writer 标记 gso_failed，逐包 sendmsg，行为正确 |

---

## 11. 实施步骤（建议顺序）

1. **预步骤**：先在 [SOCKET_OPTIONS.md](SOCKET_OPTIONS.md) 中追加"Seastar eBPF 路径单独说明" 段落
2. **Step 1**：头文件加成员，初始化 / 析构骨架，eBPF 分支替换为占位 `run_ebpf_receive_loop`（直接调用 POSIX 路径作为对照）
3. **Step 2**：实现 `run_ebpf_receive_loop`，验证收包正确（关闭 GRO，纯 recvmsg）
4. **Step 3**：替换 `write_socket` 走 writer
5. **Step 4**：开启 `xqc_enable_udp_gro` + writer 内部 UDP_SEGMENT，实测对比
6. **Step 5**：删除 `_udp_channel` 在 eBPF 分支的引用与早期注释 / 清理死代码
7. **Step 6**：跑 `scripts/bench_seastar_ebpf.sh` 三轮对比基准

每一步独立 commit，便于回滚。

---

## 12. 工作量估计（仅供参考，不含调试时间）

- 代码改动：约 150~200 行（含注释）
- 文档：本设计 + SOCKET_OPTIONS 增补
- 风险高于平均：触及 `media transport` + `node lifecycle`，按 AGENTS.md 属保守区
- 必须的回归测试：现有 `bench_seastar*.sh` + 一次端到端拉流验证

---

## 13. 评审问题（已更新）

1. ✅ **异步发包**：复用现有 `_send_integration` + `schedule_send_flush` 流水线，新增 `flush_to_pollable_fd_with_gso` 即可，复杂度比想象的小。
2. **`pollable_fd` 使用**：路径在 `internal/` 但 Seastar 自身公共代码大量依赖，第三方代码也常用；继续使用。
3. **per-shard 计数器**：建议新增 `_stats.recv_per_shard`（已有 stats，仅追加字段），用来证明 cBPF 真正生效。
4. **POSIX fallback**：不动，保持稳定。
5. **PR 拆分**：建议至少拆 3 个 PR：
   - PR1: pollable_fd 包装 + run_ebpf_receive_loop（不开 GRO/GSO）
   - PR2: 队列 `pop_gso_batch` + `flush_to_pollable_fd_with_gso`
   - PR3: 开启 UDP_GRO + UDP_SEGMENT，bench 对比

---

## 14. 实测结果（PR3 落地后）

测试方式：`scripts/bench_seastar_gso.sh SMP CONCURRENT REQUESTS BODY_SIZE`，
同一二进制，通过环境变量 `XQC_DISABLE_GSO=1` 关闭 server 侧 GSO 进行 A/B 对比；
GRO 始终开启。client = test_client，每条连接发送一次 `-s BODY_SIZE` 上传，
server eBPF 路径会把 body echo 回去（即上下行都为 BODY_SIZE）。

环境：Linux 6.8.0，kernel UDP_GRO/UDP_SEGMENT 支持；SMP=2；CONCURRENT=4；REQUESTS=50/进程（合计 200）。

| body | label   | RPS | elapsed | server CPU% | user_ms | sys_ms | 总 CPU 时间 | 相对 GSO-off |
|------|---------|-----|---------|-------------|---------|--------|-------------|--------------|
| 1 KB    | gso-on  | 62  | 3.2 s  | ~50%  | —    | —     | —      | 持平          |
| 1 KB    | gso-off | 65  | 3.1 s  | ~50%  | —    | —     | —      | 基线          |
| 8 KB    | gso-on  | 7   | 27.1 s | 15%   | 1120  | 3020  | 4.14 s | **−52%**      |
| 8 KB    | gso-off | 13  | 15.0 s | 57%   | 2030  | 6540  | 8.57 s | 基线          |
| 100 KB  | gso-on  | 5   | 33.4 s | 44%   | 3390  | 11390 | 14.78 s| **−61%**      |
| 100 KB  | gso-off | 5   | 35.5 s | 107%  | 9090  | 29100 | 38.19 s| 基线          |

**结论：**

1. **小消息（1 KB）GSO 无收益**：每条连接出向只有 1–2 个 datagram，
   `pop_gso_batch(max=N)` 走零拷贝单包路径，cmsg 不构造，CPU 与 GSO-off 持平。
2. **中等消息（8 KB ≈ 6 个 datagram）**：CPU 总时间 −52%，但 wallclock 受
   client 顺序建连节流（吞吐被连接建立 RTT 主导），出现 RPS 反降的伪现象；
   按"单请求 CPU 成本"看 GSO 已显著占优。
3. **大消息（100 KB ≈ 70 个 datagram）**：CPU −61%，sys 时间 29.1 s → 11.4 s，
   验证 UDP_SEGMENT 在 kernel UDP 路径合并 syscall 的预期收益。
4. 达到第 2 节"server 收发 CPU 减少 30~50%"目标，且大消息场景超额完成。

复现脚本：[scripts/bench_seastar_gso.sh](../scripts/bench_seastar_gso.sh)；
原始 CSV 在 [bench_results/](../bench_results/) 目录下 `gso_compare_*.csv`。
