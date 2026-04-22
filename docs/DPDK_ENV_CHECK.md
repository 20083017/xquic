# DPDK 环境检查手册

本文档用于检查当前系统是否具备运行 DPDK 的条件，适用于物理机和虚拟机（VirtualBox / KVM / VMware）。

---

## 1. 硬件与系统基本信息

```bash
# CPU 核数与型号
nproc
grep "model name" /proc/cpuinfo | head -1

# 内存
free -h

# 内核版本
uname -r

# 发行版
cat /etc/os-release | head -4
```

**要求:**
- CPU ≥ 2 核（DPDK 至少需要 1 核做 PMD 轮询）
- 内存 ≥ 2GB（需预留 hugepages）
- 内核 ≥ 4.4（推荐 5.x+，支持 VFIO）

---

## 2. 网卡信息

```bash
# 查看所有网络接口
ip -br link show

# 查看 PCI 网卡设备
lspci | grep -i net

# 查看网卡驱动
ethtool -i enp0s3 2>/dev/null | grep driver
```

**DPDK 支持的常见网卡驱动:**

| 网卡类型 | PCI 标识 | DPDK PMD 驱动 |
|---|---|---|
| Intel 82599 (ixgbe) | `8086:10fb` | `net_ixgbe` |
| Intel i40e | `8086:1572` | `net_i40e` |
| Intel E810 (ice) | `8086:1593` | `net_ice` |
| Mellanox ConnectX-4/5/6 | `15b3:*` | `net_mlx5` |
| Virtio (VM) | `1af4:1000` | `net_virtio` |
| VirtIO-net (modern) | `1af4:1041` | `net_virtio` |
| AWS ENA | `1d0f:ec20` | `net_ena` |

```bash
# 查看网卡 PCI vendor:device ID
lspci -nn | grep -i net
```

---

## 3. Hugepages 状态

```bash
# 当前 hugepages 配置
cat /proc/meminfo | grep -i huge

# 预期输出（已配置时）:
# HugePages_Total:     256
# HugePages_Free:      256
# Hugepagesize:       2048 kB

# 检查 hugetlbfs 挂载
mount | grep hugetlbfs

# 检查 /dev/hugepages 是否存在
ls -la /dev/hugepages/
```

**判断:**
- `HugePages_Total: 0` → 未配置，需要分配
- 无 hugetlbfs 挂载 → 需要挂载 `/dev/hugepages`

---

## 4. 内核模块

```bash
# 检查 UIO 模块是否已加载
lsmod | grep -E "uio|vfio"

# 检查可用的 UIO/VFIO 模块
find /lib/modules/$(uname -r) -name "uio*.ko" -o -name "vfio*.ko" 2>/dev/null

# 关键模块:
#   uio_pci_generic  — 通用 UIO 驱动（virtio 推荐）
#   vfio-pci         — VFIO 驱动（IOMMU 环境推荐，更安全）
#   igb_uio          — Intel 旧版驱动（需自行编译，不推荐）
```

**判断:**
- `uio_pci_generic.ko` 存在 → 可用于 virtio / 通用网卡
- `vfio-pci` 需要 IOMMU 支持（VirtualBox 通常不支持）

---

## 5. IOMMU / VFIO 支持

```bash
# 检查 IOMMU 是否启用
dmesg | grep -i iommu | head -5

# 检查 VFIO 设备
ls /dev/vfio/ 2>/dev/null

# 检查内核启动参数
cat /proc/cmdline | grep -o "intel_iommu=[^ ]*"
```

**判断:**
- VirtualBox 通常**不支持** IOMMU pass-through → 使用 `uio_pci_generic` 替代 `vfio-pci`
- KVM 支持 IOMMU → 可使用 `vfio-pci`

---

## 6. DPDK 工具包

```bash
# 检查 dpdk 包是否安装
dpkg -l | grep -i dpdk

# 查找 devbind 工具
which dpdk-devbind.py 2>/dev/null || find /usr -name "dpdk-devbind*" 2>/dev/null

# 查找 testpmd
which dpdk-testpmd 2>/dev/null || find /usr -name "testpmd" 2>/dev/null

# 检查 pkg-config
pkg-config --modversion libdpdk 2>/dev/null
```

**判断:**
- `libdpdk-dev` 已安装 → 编译时可用
- `dpdk` 工具包未安装 → 需要安装（提供 devbind、testpmd 等工具）

---

## 7. 一键诊断脚本

将以下内容保存为 `check_dpdk_env.sh` 并执行：

```bash
#!/bin/bash
set -u
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

echo "====== DPDK Environment Check ======"
echo "Date: $(date)"
echo "Host: $(hostname)"
echo ""

# CPU
cores=$(nproc)
[[ $cores -ge 2 ]] && pass "CPU cores: $cores" || warn "CPU cores: $cores (recommend ≥2)"

# Memory
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[[ $mem_mb -ge 2048 ]] && pass "Memory: ${mem_mb}MB" || warn "Memory: ${mem_mb}MB (recommend ≥2048MB)"

# Hugepages
hp_total=$(awk '/HugePages_Total/ {print $2}' /proc/meminfo)
[[ $hp_total -gt 0 ]] && pass "Hugepages: $hp_total" || fail "Hugepages: 0 (not configured)"

# Hugetlbfs mount
mount | grep -q hugetlbfs && pass "hugetlbfs mounted" || fail "hugetlbfs not mounted"

# Network
echo ""
echo "--- PCI Network Devices ---"
lspci -nn | grep -i net
echo ""

# UIO / VFIO
lsmod | grep -q uio && pass "UIO module loaded" || warn "UIO module not loaded"
lsmod | grep -q vfio && pass "VFIO module loaded" || warn "VFIO module not loaded"

# DPDK packages
pkg-config --exists libdpdk 2>/dev/null && pass "libdpdk-dev: $(pkg-config --modversion libdpdk)" || fail "libdpdk-dev not found"
which dpdk-devbind.py &>/dev/null && pass "dpdk-devbind.py found" || warn "dpdk-devbind.py not found (install dpdk package)"
which dpdk-testpmd &>/dev/null && pass "dpdk-testpmd found" || warn "dpdk-testpmd not found"

echo ""
echo "====== Check Complete ======"
```

---

## 8. 各环境典型结果

### VirtualBox (virtio 网卡)
| 项目 | 状态 | 说明 |
|---|---|---|
| 网卡 | virtio (`1af4:1000`) | DPDK `net_virtio` 支持 |
| IOMMU | 不支持 | 使用 `uio_pci_generic` |
| Hugepages | 需手动配置 | `sysctl vm.nr_hugepages=256` |
| 绑定驱动 | `uio_pci_generic` | `vfio-pci` 不可用 |

### KVM (virtio / SR-IOV)
| 项目 | 状态 | 说明 |
|---|---|---|
| 网卡 | virtio 或 VF pass-through | 推荐 SR-IOV VF |
| IOMMU | 支持 | 可用 `vfio-pci` |
| Hugepages | 需手动配置 | 宿主机分配 |

### 物理机 (Intel/Mellanox)
| 项目 | 状态 | 说明 |
|---|---|---|
| 网卡 | ixgbe / i40e / mlx5 | 原生高性能 |
| IOMMU | 支持 | 推荐 `vfio-pci` |
| Hugepages | 需手动配置 | 建议 1GB pages |
