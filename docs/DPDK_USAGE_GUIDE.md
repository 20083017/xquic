# DPDK 使用指南 — VirtualBox + Seastar QUIC Server

本文档说明如何在 VirtualBox 虚拟机中配置 DPDK 并运行 Seastar QUIC 服务端。

---

## 目录

1. [前置准备](#1-前置准备)
2. [配置 Hugepages](#2-配置-hugepages)
3. [安装 DPDK 工具包](#3-安装-dpdk-工具包)
4. [添加第二块网卡（管理口）](#4-添加第二块网卡管理口)
5. [绑定网卡到 DPDK 驱动](#5-绑定网卡到-dpdk-驱动)
6. [验证 DPDK 基本功能dpd](#6-验证-dpdk-基本功能)
7. [构建 Seastar DPDK 服务端](#7-构建-seastar-dpdk-服务端)
8. [启动 DPDK 模式服务端](#8-启动-dpdk-模式服务端)
9. [压测与对比](#9-压测与对比)
10. [恢复网卡到内核驱动](#10-恢复网卡到内核驱动)
11. [常见问题](#11-常见问题)

---

## 1. 前置准备

### 系统要求


| 项目     | 最低要求       | 推荐                 |
| ------ | ---------- | ------------------ |
| CPU 核数 | 2          | 4+                 |
| 内存     | 2 GB       | 4 GB+              |
| 网卡     | 1 块 virtio | 2 块（1 管理 + 1 DPDK） |
| 内核     | 4.4+       | 5.x+               |
| DPDK   | 21.x+      | 与 libdpdk-dev 版本一致 |


### 确认编译环境

```bash
# 确认 gcc-15 和 libdpdk-dev 可用
gcc-15 --version
pkg-config --modversion libdpdk

# 确认 Seastar DPDK 构建已完成
ls -lh build_seastar_dpdk/xquic_tests/xquic_server_seastar
```

---

## 2. 配置 Hugepages

DPDK 依赖 hugepages 进行零拷贝内存管理，**必须在运行前配置**。

### 临时配置（重启后失效）

```bash
# 分配 256 个 2MB hugepages = 512MB
sudo sysctl -w vm.nr_hugepages=256

# 验证
grep HugePages_ /proc/meminfo
# 预期:
# HugePages_Total:     256
# HugePages_Free:      256

# 挂载 hugetlbfs（如未自动挂载）
sudo mkdir -p /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages
```

### 永久配置（重启后保留）

```bash
# 写入 sysctl 配置
echo "vm.nr_hugepages=256" | sudo tee /etc/sysctl.d/90-hugepages.conf
sudo sysctl --system

# 写入 fstab
echo "nodev /dev/hugepages hugetlbfs defaults 0 0" | sudo tee -a /etc/fstab
```

### 验证

```bash
grep HugePages_ /proc/meminfo
mount | grep hugetlbfs
ls /dev/hugepages/
```

---

## 3. 安装 DPDK 工具包

```bash
# Ubuntu 22.04
sudo apt-get update
sudo apt-get install -y dpdk dpdk-dev dpdk-doc

# 验证安装
dpkg -l | grep dpdk
which dpdk-devbind.py
which dpdk-testpmd

# 如果 dpdk-devbind.py 不在 PATH 中
find /usr -name "dpdk-devbind.py" 2>/dev/null
# 常见位置: /usr/share/dpdk/usertools/dpdk-devbind.py
# 可以创建软链接:
# sudo ln -s /usr/share/dpdk/usertools/dpdk-devbind.py /usr/local/bin/dpdk-devbind.py
```

---

## 4. 添加第二块网卡（管理口）ffmpe

> **⚠️ 关键步骤**: 绑定网卡到 DPDK 后，该网卡将脱离 Linux 内核协议栈，
> 网络连接（包括 SSH）会断开。必须有第二块网卡维持管理通道。

### VirtualBox 设置

1. 关闭虚拟机
2. **设置 → 网络 → 网卡 2**:
  - 勾选「启用网络连接」
  - 连接方式: **仅主机(Host-Only)网络**（用于管理 SSH）
  - 高级 → 适配器类型: **Paravirtualized Network (virtio-net)**
3. **网卡 1** 保持原样（NAT 或桥接），这块将绑定到 DPDK
4. 启动虚拟机

### 配置管理口 IP

```bash
# 查看新网卡
ip -br link show
# 预期看到 enp0s8 或类似接口

# 配置 IP（Host-Only 网段通常是 192.168.56.x）
sudo ip addr add 192.168.56.10/24 dev enp0s8
sudo ip link set enp0s8 up

# 验证从宿主机可以 SSH
# 在宿主机: ssh vboxuser@192.168.56.10
```

### 如果只有一块网卡

如果无法添加第二块网卡，可以：

- 直接在 VirtualBox 控制台（GUI）操作，不依赖 SSH
- 或使用 `virtio-user` 虚拟设备（不绑定物理网卡），见 [Section 6](#6-验证-dpdk-基本功能)

---

## 5. 绑定网卡到 DPDK 驱动

### 加载 UIO 驱动

```bash
# 加载通用 UIO 模块
sudo modprobe uio
sudo modprobe uio_pci_generic

# 验证
lsmod | grep uio
# 预期: uio_pci_generic, uio
```

### 查看网卡状态

```bash
sudo dpdk-devbind.py --status

# 预期输出:
# Network devices using kernel driver
# ====================================
# 0000:00:03.0 'Virtio network device 1000' drv=virtio-pci ...
# 0000:00:08.0 'Virtio network device 1000' drv=virtio-pci ...  (管理口)
```

### 绑定数据口到 DPDK

```bash
# 确认要绑定的 PCI 地址（数据口，不是管理口!）
# 假设 00:03.0 是数据口，00:08.0 是管理口

# 关闭要绑定的网卡
sudo ip link set enp0s3 down

# 绑定到 uio_pci_generic
sudo dpdk-devbind.py --bind=uio_pci_generic 0000:00:03.0

# 验证
sudo dpdk-devbind.py --status
# 预期: 00:03.0 出现在 "Network devices using DPDK-compatible driver" 下
```

---

## 6. 验证 DPDK 基本功能

### 方式 A: testpmd（需要已绑定网卡）

```bash
# 基本收发测试
sudo dpdk-testpmd -l 0-1 -n 1 -- -i

# 在 testpmd 交互界面中:
testpmd> show port info 0
testpmd> start
testpmd> show port stats 0
testpmd> quit
```

### 方式 B: virtio-user（不需要绑定物理网卡）

如果不想绑定物理网卡，可以用虚拟设备测试 DPDK 运行时：

```bash
# 使用 virtio-user 虚拟网口
sudo dpdk-testpmd --no-pci \
  --vdev=net_virtio_user0,path=/dev/vhost-net,queues=1 \
  -l 0-1 -n 1 -- -i 2>&1 | head -30
```

### 方式 C: 最小验证（只检查 EAL 初始化）

```bash
# 如果有 dpdk-proc-info 工具
sudo dpdk-proc-info -- --stats

# 或写一个最小 C 程序验证 rte_eal_init
cat > /tmp/test_dpdk.c << 'EOF'
#include <stdio.h>
#include <rte_eal.h>
int main(int argc, char *argv[]) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("FAIL: rte_eal_init returned %d\n", ret);
        return 1;
    }
    printf("PASS: DPDK EAL initialized, %d lcores\n", rte_lcore_count());
    rte_eal_cleanup();
    return 0;
}
EOF
gcc-15 /tmp/test_dpdk.c -o /tmp/test_dpdk $(pkg-config --cflags --libs libdpdk) -lrte_eal
sudo /tmp/test_dpdk --no-pci -l 0
```

---

## 7. 构建 Seastar DPDK 服务端

```bash
cd /home/vboxuser/xquic

# 方式 1: 使用构建脚本
./build_seastar.sh dpdk

# 方式 2: 手动 cmake（更多控制）
mkdir -p build_seastar_dpdk && cd build_seastar_dpdk
CC=gcc-15 CXX=g++-15 cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DXQC_ENABLE_SEASTAR=ON \
  -DXQC_ENABLE_TESTING=ON \
  -DSSL_TYPE=openssl \
  -DSSL_PATH=../third_party/quictls/build \
  -DSSL_INC_PATH=../third_party/quictls/build/include \
  "-DSSL_LIB_PATH=../third_party/quictls/build/lib64/libssl.a;../third_party/quictls/build/lib64/libcrypto.a" \
  -DSeastar_DPDK=ON \
  -DSeastar_DPDK_MACHINE=native \
  -DSeastar_APPS=OFF \
  -DSeastar_DEMOS=OFF \
  -DSeastar_DOCS=OFF \
  -DSeastar_TESTING=OFF \
  -DSeastar_INSTALL=OFF \
  -DBOOST_ROOT=/usr/local

cmake --build . --target xquic_server_seastar -j$(nproc)

# 验证 DPDK 符号
nm xquic_tests/xquic_server_seastar | grep -c rte_
# 预期: > 2000
```

---

## 8. 启动 DPDK 模式服务端

### DPDK PMD 模式（完整 DPDK 网络栈）

```bash
# 需要 root 权限、hugepages 已配置、网卡已绑定到 UIO
sudo ./build_seastar_dpdk/xquic_tests/xquic_server_seastar \
  --smp 2 \
  --dpdk-pmd \
  --dpdk-port-index 0 \
  --network-stack native \
  --hugepages /dev/hugepages \
  -p 8443 \
  --cert tests/server.crt \
  --key tests/server.key
```

### POSIX 模式（DPDK 编译但使用内核网络栈）

```bash
# 不需要绑定网卡，可直接运行
./build_seastar_dpdk/xquic_tests/xquic_server_seastar \
  --smp 2 \
  -p 8443 \
  --cert tests/server.crt \
  --key tests/server.key
```

### 关键启动参数说明


| 参数                       | 说明                       | 默认值            |
| ------------------------ | ------------------------ | -------------- |
| `--smp N`                | 使用 N 个 CPU 核             | 所有核            |
| `--dpdk-pmd`             | 启用 DPDK Poll-Mode Driver | 关闭             |
| `--dpdk-port-index N`    | 使用第 N 个 DPDK 端口          | 0              |
| `--network-stack native` | 使用 Seastar 原生网络栈（含 DPDK） | posix          |
| `--hugepages PATH`       | Hugepages 挂载路径           | /dev/hugepages |
| `-p PORT`                | QUIC 监听 UDP 端口           | 8443           |
| `--cert FILE`            | TLS 证书路径                 | ./server.crt   |
| `--key FILE`             | TLS 私钥路径                 | ./server.key   |
| `-e / --echo`            | 回显模式                     | 关闭             |


---

## 9. 压测与对比

### 测试矩阵


| 配置          | 命令                                                                          |
| ----------- | --------------------------------------------------------------------------- |
| POSIX smp=1 | `./xquic_server_seastar --smp 1 -p 8443 ...`                                |
| POSIX smp=2 | `./xquic_server_seastar --smp 2 -p 8443 ...`                                |
| DPDK smp=1  | `sudo ./xquic_server_seastar --smp 1 --dpdk-pmd --network-stack native ...` |
| DPDK smp=2  | `sudo ./xquic_server_seastar --smp 2 --dpdk-pmd --network-stack native ...` |


### 客户端压测（从另一台机器或宿主机）

```bash
# 使用项目自带 demo_client 或 mini_client
./build/demo_client -a 192.168.56.10 -p 8443 -n 1000

# 或使用通用 QUIC 压测工具（如 h2load with HTTP/3）
```

### 采集指标

```bash
# CPU 占用（在服务端运行期间）
mpstat -P ALL 1 10

# 服务端内置统计（每 2 秒自动输出）
# [shard 0] conns=100 streams=200 | recv=500Mbps (50000pps) send=500Mbps (50000pps)

# perf 采样（分析热点）
sudo perf record -g -p $(pgrep xquic_server) -- sleep 10
sudo perf report
```

### 对比维度


| 指标     | 采集方式             | 单位      |
| ------ | ---------------- | ------- |
| 吞吐量    | 服务端 stats 输出     | Mbps    |
| 包速率    | 服务端 stats 输出     | pps     |
| 延迟     | 客户端 RTT 统计       | ms / μs |
| CPU 占用 | `mpstat` / `top` | %       |
| 并发连接   | 客户端参数控制          | 连接数     |


---

## 10. 恢复网卡到内核驱动

```bash
# 将网卡从 DPDK 解绑，还给内核
sudo dpdk-devbind.py --bind=virtio-pci 0000:00:03.0

# 验证
sudo dpdk-devbind.py --status
# 预期: 00:03.0 出现在 "Network devices using kernel driver" 下

# 启动网卡
sudo ip link set enp0s3 up
sudo dhclient enp0s3
```

---

## 11. 常见问题

### Q: `EAL: No free hugepages reported`

**A:** Hugepages 未配置或已被占用。

```bash
sudo sysctl -w vm.nr_hugepages=256
cat /proc/meminfo | grep HugePages_
```

### Q: `EAL: Cannot init VFIO`

**A:** VirtualBox 不支持 IOMMU。改用 `uio_pci_generic`:

```bash
sudo modprobe uio_pci_generic
sudo dpdk-devbind.py --bind=uio_pci_generic 0000:00:03.0
```

### Q: `EAL: No probed ethernet devices`

**A:** 没有网卡绑定到 DPDK 驱动。检查:

```bash
sudo dpdk-devbind.py --status
```

### Q: 绑定后 SSH 断开

**A:** 你绑定了管理口到 DPDK。通过 VirtualBox 控制台恢复:

```bash
sudo dpdk-devbind.py --bind=virtio-pci 0000:00:03.0
sudo ip link set enp0s3 up && sudo dhclient enp0s3
```

### Q: `rte_ethdev.h: No such file or directory`

**A:** DPDK 头文件路径问题，已在 Seastar 子模块中修复。确保使用修补后的 `Finddpdk.cmake`。

### Q: Seastar 服务端 DPDK 模式下无法收包

**A:** 检查:

1. hugepages 已分配: `grep HugePages_Free /proc/meminfo`
2. 网卡已绑定: `dpdk-devbind.py --status`
3. 使用了正确参数: `--dpdk-pmd --network-stack native`
4. 以 root 运行: `sudo ./xquic_server_seastar ...`

### Q: 只想测试 DPDK 编译是否正确，不想绑定网卡

**A:** 用 POSIX 模式运行 DPDK 编译的二进制即可（不加 `--dpdk-pmd`），它会使用内核网络栈，但链接了 DPDK 库。