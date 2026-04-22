# Phase 3: Seastar + DPDK Server Prototype & Evaluation

本文档用于执行并记录 Phase 3（仅服务端 Seastar + DPDK 路线）评估结果，满足可复现要求。

## 1. 目标

在已完成 POSIX 基线后，针对服务端切换到 Seastar DPDK 路线（Seastar native stack），输出：

- 吞吐（req/s）
- 延迟（优先 p50/p95/p99，若客户端输出缺失则记录总耗时）
- CPU 占用（服务端进程）
- 并发能力（不同并发下完成/失败）

## 前置条件

- 已成功编译 Seastar 服务端：
  - build_seastar/xquic_tests/xquic_server_seastar
- 已成功编译压测客户端：
  - build/tests/test_client
- 如需构建 DPDK 版本，确保系统已安装可被 `pkg-config --modversion libdpdk` 发现的 DPDK 开发包

## 构建顺序

先构建启用 DPDK 的 Seastar 服务端，再执行 smoke 和压测。

默认构建（不启用 DPDK）：

```bash
./build_seastar.sh
```

启用 Seastar DPDK 构建：

```bash
DPDK_CONFIG_FILE=third_party/seastar/dpdk-custom.conf \
SEASTAR_DPDK_MACHINE=native \
./build_seastar.sh dpdk
```

说明：

- `build_seastar.sh dpdk` 会显式打开 `Seastar_DPDK=ON`
- `DPDK_CONFIG_FILE` 当前作为 DPDK 构建参考配置路径记录与校验，不会被 Seastar CMake 直接解析
- 实际 DPDK 发现依赖 Seastar 的 `Finddpdk.cmake`，通过系统 `pkg-config` 查找 `libdpdk`
- DPDK 环境已就绪（网卡绑定、hugepages、权限、EAL 参数等）

## 3. 一键执行

默认执行 smoke + bench + summary：

```bash
bash scripts/seastar_dpdk_server_eval.sh full
```

如果你使用外部 DPDK 配置文件：

```bash
DPDK_CONFIG_FILE=./dpdk-custom.conf \
SEASTAR_DPDK_MACHINE=native \
./build_seastar.sh dpdk

DPDK_CONFIG_FILE=./dpdk-custom.conf \
bash scripts/seastar_dpdk_server_eval.sh full
```

仅功能验证：

```bash
bash scripts/seastar_dpdk_server_eval.sh smoke
```

仅压测矩阵：

```bash
bash scripts/seastar_dpdk_server_eval.sh bench
```

## 4. 推荐参数

```bash
DPDK_CONFIG_FILE=./dpdk-custom.conf \
SERVER_EXTRA_ARGS="--dpdk-pmd --overprovisioned" \
SERVER_SMP_LIST="1 2 4" \
CONN_LIST="100 500 1000" \
TOTAL_REQS=3000 \
BODY_SIZE=1024 \
bash scripts/seastar_dpdk_server_eval.sh full
```

说明：

- NETWORK_STACK 默认 native（Seastar DPDK 路径）
- DPDK_CONFIG_FILE 对评估脚本来说默认为项目根目录下的 dpdk-custom.conf，存在则自动加载
- 对构建脚本来说建议显式指定为 third_party/seastar/dpdk-custom.conf
- SERVER_EXTRA_ARGS 用于注入你的 DPDK/EAL 参数
- 所有实验请保持与 POSIX 基线一致的连接数、包大小、smp 配置

推荐将 `dpdk-custom.conf` 写成 shell 环境文件，例如：

```bash
SERVER_EXTRA_ARGS="--dpdk-pmd --overprovisioned"
SERVER_SMP_LIST="1 2 4"
CONN_LIST="100 500 1000"
TOTAL_REQS=3000
BODY_SIZE=1024
```

## 5. 输出位置

脚本将写入：

- bench_results/dpdk_phase3_<timestamp>/results.csv
- bench_results/dpdk_phase3_<timestamp>/environment.txt
- bench_results/dpdk_phase3_<timestamp>/summary.txt
- bench_results/dpdk_phase3_<timestamp>/server_*.log
- bench_results/dpdk_phase3_<timestamp>/client_*.log

其中 environment.txt 会记录实际加载的 DPDK_CONFIG_FILE 路径。

## 6. CSV 字段说明

results.csv 列定义：

- smp
- concurrency
- total_reqs
- parallel_per_conn
- body_size
- elapsed_s
- throughput_rps
- cpu_percent
- completed
- failed
- p50
- p95
- p99

## 7. Phase 3 汇报模板

请在阶段总结中至少包含以下内容：

1. 修改内容
- 新增脚本：scripts/seastar_dpdk_server_eval.sh
- 运行参数：SMP/并发/body/请求数/DPDK 参数

2. 测试结果
- smoke 是否通过
- 功能回归结论（是否出现连接失败、崩溃、超时）

3. 压测结果
- 各 smp 与并发下吞吐、延迟、CPU、失败率
- 与 POSIX 基线同维度对比（同参数）

4. 风险与下一步
- 风险：DPDK 参数敏感、网卡绑定依赖、权限与 hugepages
- 下一步：补齐固定硬件环境下多轮测试，给出最终路线建议

## 8. 可复现性要求

- 固定硬件与系统版本
- 固定测试参数与脚本版本
- 固定 server/client 二进制版本
- 每轮保留原始 CSV 与日志
