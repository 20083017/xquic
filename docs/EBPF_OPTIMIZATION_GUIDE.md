# Seastar xquic 服务端 eBPF 优化指南

本文档聚焦于 Seastar xquic 服务端使用的 eBPF + SO_REUSEPORT 路径，给出可直接落地的优化方法。

目标二进制：
- build_seastar/xquic_tests/xquic_server_seastar_ebpf

相关压测脚本：
- scripts/bench_seastar_ebpf.sh

## 1. 范围与目标

本文优化的关键链路如下：
1. UDP 报文到达网卡
2. Linux 内核通过 eBPF 策略选择 reuseport socket
3. Seastar 分片接收报文
4. xquic 处理 QUIC + HTTP/3

核心目标：
- 在并发场景下提升 RPS 与尾延迟表现
- 减少跨分片导致的包乱序
- 在 stress 模式下维持低失败率
- 避免回归问题（崩溃、core dump、握手超时）

## 2. 优化前基线

优化前必须先做基线采集。

命令：

```bash
cd /home/vboxuser/xquic
cmake --build build_seastar --target xquic_server_seastar_ebpf test_client -j$(nproc)
bash scripts/bench_seastar_ebpf.sh quick ebpf
bash scripts/bench_seastar_ebpf.sh standard ebpf
bash scripts/bench_seastar_ebpf.sh stress ebpf
```

至少记录以下指标：
- total_requests
- elapsed_ms
- rps
- failures
- server 各核 CPU 使用率
- 丢包情况（ss -u -i、netstat -su）

## 3. 高收益优化项（Fast Wins）

### 3.1 分片数与实际 CPU 能力对齐

当 CPU 资源受限（例如 VM 有效 vCPU 偏少）时，不要盲目提高 --smp。

建议顺序：
- 先从 --smp 1 开始
- 再验证 --smp 2
- 仅在主机 CPU 与 VM 调度稳定时再尝试 --smp 4

原因：
- 分片过多会增加调度开销与包分发竞争。

### 3.2 收发尽量保持分片本地化

对每个 shard：
- 连接状态尽量本地维护
- 尽量减少跨 shard 转发

原因：
- 跨分片转发会引入排队与 cache miss。

### 3.3 使用确定性的 reuseport 分流键

确保同一条 QUIC 连接的 eBPF 选 socket 结果稳定。

建议键优先级：
1. 基于 QUIC DCID 的映射
2. 仅在无法取到 DCID 时再退化到 5 元组

原因：
- 稳定 DCID 映射可减少握手期与 1-RTT 切换阶段的乱序。

## 4. 内核与 Socket 调优

在测试机上应用如下内核网络参数（按环境调整）：

```bash
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.core.rmem_default=262144
sudo sysctl -w net.core.wmem_default=262144
sudo sysctl -w net.core.netdev_max_backlog=250000
sudo sysctl -w net.ipv4.udp_rmem_min=16384
sudo sysctl -w net.ipv4.udp_wmem_min=16384
```

高 PPS 场景可选：

```bash
sudo sysctl -w net.core.busy_poll=50
sudo sysctl -w net.core.busy_read=50
```

验证：

```bash
sysctl net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog
netstat -su
```

重点观察：
- packet receive errors
- UDP buffer drops

## 5. Seastar 运行时调优

推荐启动模板：

```bash
./build_seastar/xquic_tests/xquic_server_seastar_ebpf \
  --port 8443 \
  --cert server.crt \
  --key server.key \
  --smp 1 \
  --reactor-backend epoll
```

再逐步扩大到：
- --smp 2（确认稳定后）

可评估的 Seastar 参数（与环境相关）：
- --task-quota-ms
- --idle-poll-time-us
- --poll-mode

说明：
- 一次只调一个参数，每次都重跑 standard + stress。

## 6. QUIC/H3 路径优化

### 6.1 回调参数安全

不要把空指针传给会直接解引用的 API。

示例：
- xqc_h3_request_recv_headers(req, &fin) 是正确用法
- xqc_h3_request_recv_headers(req, NULL) 可能触发崩溃

### 6.2 不要错误释放内部 header 指针

如果 API 返回的是内部 header 结构，除非文档明确转移所有权，否则不要调用 free()。

### 6.3 降低每请求分配开销

在热点回调中：
- 尽量复用缓冲区
- 控制临时栈对象大小
- 避免不必要的字符串拷贝

## 7. eBPF 程序策略

针对 reuseport eBPF 选路逻辑：
- 优先使用 O(1) hash + 取模计算 shard
- 避免在 eBPF 路径做复杂解析
- 控制指令数量，保持程序简洁

检查清单：
- 无无界循环
- 无不必要的高开销 helper 调用
- 同一 DCID 映射到同一 shard

## 8. 压测方法

统一使用 3 档：
- quick：连通性与基本功能检查
- standard：回归门禁
- stress：容量与失败画像

建议门禁：
- 无 crash/core dump
- 失败率 <= 1%
- 相比上一版稳定基线，RPS 回退不超过 5%

结果对比路径：
- bench_results/*.csv

## 9. 按症状排障

### 症状 A：握手正常但 RPS 低

检查：
- CPU 是否打满（top、pidstat -t）
- UDP 丢包（netstat -su）
- PTO/重传日志是否异常密集

动作：
- 降低 --smp
- 提高 socket buffer
- 检查 reuseport 映射稳定性

### 症状 B：smp=4 失败，但 smp=1/2 正常

常见原因：
- VM 调度压力大
- CPU 绑定/隔离不足
- 分片映射不稳定

动作：
- 生产配置先固定在 smp=1 或 smp=2
- 核查主机 CPU 资源分配
- 拉长 stress 时长并同时观察丢包指标

### 症状 C：stress 下偶发请求失败

检查：
- client 脚本超时参数
- 是否存在重传风暴
- server 队列压力

动作：
- 并发较高时适当增加超时预算
- 调整 netdev_max_backlog、rmem_max、wmem_max
- 临时降低客户端并发扇出，先定位瓶颈

## 10. 推荐优化流程

1. 构建干净二进制
2. 跑 quick 基线
3. 调整内核缓冲
4. 调整 --smp（1 -> 2 -> 4）
5. 跑 standard
6. 跑 stress
7. 对比 CSV 与日志级别失败原因
8. 固化最终参数并文档化

## 11. 稳定配置模板示例

建议作为起点再按环境微调：

- Server：
  - --reactor-backend epoll
  - --smp 1（若稳定可升到 --smp 2）
- Kernel：
  - 增大 UDP buffer
  - 增大 netdev backlog
- Validation：
  - standard 与 stress 的 CSV 显示无崩溃且失败率可接受

## 12. 上线前检查清单

发布前：
- [ ] standard + stress 下 server/client 无 segfault
- [ ] benchmark CSV 已归档并带时间戳
- [ ] 失败原因已分类（timeout/drop/other）
- [ ] 最终 --smp 配置已文档化
- [ ] 回滚命令已验证

回滚示例：

```bash
pkill -9 -f xquic_server_seastar
./build_seastar/xquic_tests/xquic_server_seastar_ebpf --port 8443 --cert server.crt --key server.key --smp 1 --reactor-backend epoll
```

## 13. 当前实测结果（2026-04-21）

本节基于当前本地压测产物：
- bench_results/bench_20260420_221744.csv
- bench_results/bench_20260421_104847.csv
- bench_results/bench_20260421_111636.csv

### 13.1 Standard 模式快照

| mode | smp | total_requests | elapsed_ms | rps | failures |
|---|---:|---:|---:|---:|---:|
| ebpf | 1 | 200 | 30319 | 6 | 3 |
| ebpf | 2 | 200 | 30032 | 6 | 4 |
| ebpf | 4 | 0 | 0 | 0 | FAILED |
| ebpf-fallback | 1 | 200 | 14457 | 13 | 0 |
| ebpf-fallback | 2 | 200 | 30097 | 6 | 4 |
| ebpf-fallback | 4 | 0 | 0 | 0 | FAILED |

观察：
- 当前环境下 smp=4 不稳定（两种模式都失败）。
- 在 standard 模式中，ebpf-fallback + smp=1 的 RPS 最好。

### 13.2 Stress 模式快照

| mode | smp | total_requests | elapsed_ms | rps | failures | failure_rate |
|---|---:|---:|---:|---:|---:|---:|
| ebpf | 1 | 3200 | 30198 | 105 | 16 | 0.50% |
| ebpf | 2 | 3200 | 30220 | 105 | 16 | 0.50% |
| ebpf | 4 | 0 | 0 | 0 | FAILED | n/a |
| ebpf-fallback | 1 | 3200 | 30362 | 105 | 16 | 0.50% |
| ebpf-fallback | 2 | 3200 | 30740 | 104 | 16 | 0.50% |
| ebpf-fallback | 4 | 0 | 0 | 0 | FAILED | n/a |

观察：
- smp=1/2 的 stress 吞吐稳定在约 104-105 RPS。
- 失败率维持在 0.50%，满足 <=1% 门禁。
- smp=4 依然失败，较大概率与环境/vCPU 调度限制有关。

### 13.3 端到端稳定性状态

最近一次验证状态：
- Client 单次 E2E：PASS（CLIENT_EXIT=0）
- 最新 E2E 过程中未观察到 server segmentation fault
- H3 请求生命周期完整（握手、request create、headers/body send）

## 14. 当前环境推荐运行配置

在 smp=4 被证明稳定前，建议默认配置：

- 首选：--smp 1
- 备选：--smp 2（stress 吞吐与 smp=1 接近）
- 暂不建议：--smp 4

推荐命令：

```bash
./build_seastar/xquic_tests/xquic_server_seastar_ebpf \
  --port 8443 \
  --cert server.crt \
  --key server.key \
  --smp 1 \
  --reactor-backend epoll
```

## 15. 当前数据驱动验收门槛

建议在 CI 或发布前检查中使用以下门槛：

- 稳定性：
  - E2E + standard + stress 全部无 segfault/core dump
- 吞吐：
  - smp=1 下 stress RPS >= 100
- 可靠性：
  - stress 失败率 <= 1.0%
- 配置安全：
  - 若 smp=4 连续两次失败，自动回退到 smp=1
