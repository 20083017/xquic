# Seastar QUIC Server — 演进路线

## 目标架构

### 最终目标：多核 Seastar 架构
```
Core 0: [UDP recv] → CID hash → shard 路由
Core 1: [engine_1] → connections 0-N
Core 2: [engine_2] → connections N-2N  
Core 3: [engine_3] → connections 2N-3N
...
每个 shard 独立的 xqc_engine + UDP channel
```

## 演进阶段

### Phase 1: 单核基础功能 ✅ (当前)
- [x] Seastar reactor 集成 xqc_engine
- [x] UDP 收发（XquicSeastarSendQueue）
- [x] Transport + H3 双协议支持
- [x] TLS (quictls) 握手
- [x] 连接生命周期管理
- [x] 定时器（微秒精度）
- [x] 统计计数器（5s 周期打印）

### Phase 2: 单核大文件传输 ← **当前阶段**
- [x] Echo 模式（server 回传 client 发送的数据）
- [x] 流式发送（write_notify + EAGAIN 背压）
- [x] 动态接收缓冲（realloc 自增长）
- [ ] **GB 级文件传输验证**
- [ ] **流式处理（不在内存中缓存整个文件）**
- [ ] 单连接吞吐测试
- [ ] 并发连接压测（-n 参数）

### Phase 3: 单核性能优化
- [ ] 发送队列优化（减少 vector copy）
- [ ] 零拷贝路径评估
- [ ] 内存分配优化（是否需要 buffer pool — 见下方分析）
- [ ] CPU profiling & 瓶颈分析
- [ ] 丢包 / 重传 / 拥塞控制调优

### Phase 4: 多核扩展
- [ ] Per-shard xqc_engine 实例
- [ ] CID-based shard 路由
- [ ] Core 0 作为 dispatcher（UDP recv → hash → submit_to）
- [ ] Per-shard UDP channel（避免跨核争用）
- [ ] 跨 shard 连接迁移（可选）

### Phase 5: 生产就绪
- [ ] 优雅关闭 / 热重启
- [ ] 连接限流 / 速率控制
- [ ] Metrics 导出（Prometheus）
- [ ] 配置文件支持
- [ ] 日志分级控制

---

## 内存管理分析

### 当前内存分配热点

| 分配点 | 大小 | 频率 | 生命周期 |
|--------|------|------|----------|
| `user_conn_t` | ~200B | 每连接 1 次 | 连接级 |
| `user_stream_t` | ~200B | 每流 1 次 | 流级 |
| `sockaddr_storage` | 128B | 每连接 2 次 | 连接级 |
| `recv_body` (realloc) | 可变，可达 GB | 每流 N 次 | 流级 |
| `send_body` (malloc) | 可变，可达 GB | 每流 1 次 | 流级 |
| SendQueue `vector<uchar>` | ~1200B/包 | 每包 1 次 | 极短（flush 后释放） |

### 是否需要 Buffer Pool？

#### 当前阶段（单核 + 功能验证）：**不需要**

理由：
1. **大块缓冲（recv_body/send_body）**：GB 级别的 buffer 不适合池化，因为大小不固定，
   且对于 echo 测试，这些是真正需要的应用层缓冲
2. **小对象（user_conn_t/user_stream_t）**：频率不高（每连接/每流一次），glibc malloc 
   已有 tcache 优化
3. **发送队列 Datagram**：每包一个 `vector<uchar>` copy，这是**当前最大的热点**，
   但解决方案是零拷贝而非池化

#### 什么时候需要引入 Buffer Pool？

当满足以下条件时考虑：
- **压测显示** malloc/free 占 CPU > 5%（用 perf 验证）
- **万级并发连接**，小对象分配成为瓶颈
- **多核架构下**，跨 shard 内存分配导致 false sharing

#### 推荐的替代方案（按优先级）

1. **流式处理 > 池化**：GB 级传输不应该在内存中缓存整个文件，应该改为
   流式读取文件 → 分块发送 → 释放，峰值内存控制在几 MB
2. **Seastar 的 `temporary_buffer`**：Seastar 自带引用计数的 buffer，
   已经针对 reactor 模型优化
3. **发送队列零拷贝**：用 `seastar::net::packet` 替代 `vector<uchar>` copy
4. **对象池（可选）**：如果 perf 数据证明需要，针对 user_conn_t / user_stream_t 
   做简单的 freelist 池

### 关于 bbcp BufferPool

bbcp 的 BufferPool 是为 **磁盘 I/O 双缓冲** 设计的（生产者-消费者模型），
与 QUIC 传输的需求不完全匹配：
- bbcp 场景：磁盘读 → buffer → 网络写，固定大小块
- QUIC 场景：网络收 → 协议解析 → 应用处理，变长数据

如果确实需要 buffer pool，建议：
- 用 Seastar 原生的 `memory::allocate_aligned` + freelist
- 或者简单的 slab allocator（按 4KB/64KB/1MB 分级）

---

## 文件结构

```
tests/
├── xquic_server_seastar.cpp     # 主服务器实现
├── xquic_server_seastar.hh      # 服务器头文件
├── xquic_seastar_queue.hh       # 发送队列
├── xquic_seastar_integration.hh # Seastar 集成层
├── xquic_client.cpp             # 测试客户端
├── xquic_client.h               # 客户端头文件
└── user_conn.h                  # 共享连接/流结构体
```

## 构建与测试

```bash
# 构建 server
cd build_seastar && make -j$(nproc) xquic_server_seastar

# 构建 client
cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=ON && make -j$(nproc) test_client

# 启动 server
./build_seastar/xquic_tests/xquic_server_seastar --smp 1 --cert ./server.crt --key ./server.key --port 8443

# 测试：1MB echo (transport)
./build/xquic_tests/test_client -a 127.0.0.1 -p 8443 -t -s 1048576 -E

# 测试：1MB echo (H3)
./build/xquic_tests/test_client -a 127.0.0.1 -p 8443 -s 1048576 -E

# 测试：10 并发连接
./build/xquic_tests/test_client -a 127.0.0.1 -p 8443 -t -s 1024 -n 10
```
