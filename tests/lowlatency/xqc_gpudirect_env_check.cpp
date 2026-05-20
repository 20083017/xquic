/**
 * @file xqc_gpudirect_env_check.cpp
 * @brief Roadmap P6: GPUDirect RDMA environment preflight.
 *
 * This is a no-dependency checker. It does not attempt RDMA registration yet;
 * it verifies the Linux/NVIDIA/Mellanox prerequisites that must be true before
 * adding NIC DMA -> GPU VRAM experiments.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace {

struct Check {
    std::string name;
    bool ok = false;
    std::string detail;
};

struct PciDevice {
    std::string addr;
    std::string vendor;
    std::string device;
    std::string klass;
    std::string numa_node;
};

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) {
        s.pop_back();
    }
    size_t pos = 0;
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) {
        ++pos;
    }
    return pos == 0 ? s : s.substr(pos);
}

bool path_exists(const char* path) {
    struct stat st {};
    return stat(path, &st) == 0;
}

std::string read_file(const char* path) {
    std::ifstream in(path);
    if (!in) {
        return {};
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string read_trimmed(const std::string& path) {
    return trim(read_file(path.c_str()));
}

bool contains(const std::string& s, const char* needle) {
    return s.find(needle) != std::string::npos;
}

std::string run_cmd(const char* cmd) {
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return {};
    }
    char buf[512];
    std::string out;
    while (fgets(buf, sizeof(buf), fp)) {
        out += buf;
    }
    pclose(fp);
    return out;
}

int count_dir_entries(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        return 0;
    }
    int count = 0;
    while (dirent* ent = readdir(dir)) {
        if (std::strcmp(ent->d_name, ".") != 0 && std::strcmp(ent->d_name, "..") != 0) {
            ++count;
        }
    }
    closedir(dir);
    return count;
}

std::vector<std::string> list_pci_class_prefix(const char* prefix) {
    std::vector<std::string> devices;
    DIR* dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        return devices;
    }
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        std::string class_path = std::string("/sys/bus/pci/devices/") + ent->d_name + "/class";
        std::string cls = read_file(class_path.c_str());
        if (cls.rfind(prefix, 0) == 0) {
            devices.emplace_back(ent->d_name);
        }
    }
    closedir(dir);
    return devices;
}

std::vector<PciDevice> list_interesting_pci_devices() {
    std::vector<PciDevice> devices;
    DIR* dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        return devices;
    }
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        const std::string base = std::string("/sys/bus/pci/devices/") + ent->d_name;
        PciDevice dev;
        dev.addr = ent->d_name;
        dev.vendor = read_trimmed(base + "/vendor");
        dev.device = read_trimmed(base + "/device");
        dev.klass = read_trimmed(base + "/class");
        dev.numa_node = read_trimmed(base + "/numa_node");

        const bool is_gpu = dev.vendor == "0x10de" || dev.klass.rfind("0x030", 0) == 0;
        const bool is_nic = dev.vendor == "0x15b3" || dev.klass.rfind("0x02", 0) == 0;
        if (is_gpu || is_nic) {
            devices.push_back(dev);
        }
    }
    closedir(dir);
    return devices;
}

void add_check(std::vector<Check>& checks, const std::string& name, bool ok, const std::string& detail) {
    checks.push_back(Check{name, ok, detail});
}

void print_checks(const std::vector<Check>& checks) {
    int pass = 0;
    for (const auto& c : checks) {
        if (c.ok) {
            ++pass;
        }
        std::printf("[%s] %-24s %s\n", c.ok ? "OK" : "!!", c.name.c_str(), c.detail.c_str());
    }
    std::printf("[summary] %d/%zu checks passed\n", pass, checks.size());
}

void print_pci_devices(const std::vector<PciDevice>& devices) {
    std::printf("\n[pci devices: GPU/NIC candidates]\n");
    if (devices.empty()) {
        std::printf("  <none found under /sys/bus/pci/devices>\n");
        return;
    }
    for (const auto& dev : devices) {
        const char* kind = "other";
        if (dev.vendor == "0x10de") {
            kind = "nvidia";
        } else if (dev.vendor == "0x15b3") {
            kind = "mellanox";
        } else if (dev.klass.rfind("0x02", 0) == 0) {
            kind = "network";
        } else if (dev.klass.rfind("0x030", 0) == 0) {
            kind = "gpu";
        }
        std::printf("  %-9s addr=%s vendor=%s device=%s class=%s numa=%s\n",
            kind, dev.addr.c_str(), dev.vendor.c_str(), dev.device.c_str(),
            dev.klass.c_str(), dev.numa_node.empty() ? "unknown" : dev.numa_node.c_str());
    }
}

} // namespace

int main() {
#if !defined(__linux__)
    std::printf("[!!] GPUDirect RDMA preflight is Linux-only\n");
    return 1;
#else
    std::vector<Check> checks;

    const std::string modules = read_file("/proc/modules");
    add_check(checks, "nvidia module", contains(modules, "nvidia "),
        contains(modules, "nvidia ") ? "loaded" : "missing");
    add_check(checks, "nvidia-peermem", contains(modules, "nvidia_peermem") || contains(modules, "nvidia-peermem"),
        "required for GPUDirect RDMA peer memory");
    add_check(checks, "mlx5_core", contains(modules, "mlx5_core"),
        "Mellanox ConnectX driver");
    add_check(checks, "ib_uverbs", contains(modules, "ib_uverbs"),
        "userspace RDMA verbs");

    const bool has_nvidia_dev = path_exists("/dev/nvidiactl") || path_exists("/dev/nvidia0");
    add_check(checks, "nvidia devices", has_nvidia_dev,
        has_nvidia_dev ? "/dev/nvidia* present" : "missing /dev/nvidia*");

    const int infiniband_entries = count_dir_entries("/dev/infiniband");
    add_check(checks, "rdma devices", infiniband_entries > 0,
        infiniband_entries > 0 ? "/dev/infiniband present" : "missing /dev/infiniband");

    const auto gpus = list_pci_class_prefix("0x030");
    add_check(checks, "pci gpu", !gpus.empty(),
        !gpus.empty() ? std::to_string(gpus.size()) + " display/3d devices" : "no PCI GPU class devices");
    const auto interesting = list_interesting_pci_devices();
    bool has_mellanox = false;
    bool has_nvidia_pci = false;
    for (const auto& dev : interesting) {
        has_mellanox = has_mellanox || dev.vendor == "0x15b3";
        has_nvidia_pci = has_nvidia_pci || dev.vendor == "0x10de";
    }
    add_check(checks, "pci nvidia", has_nvidia_pci,
        has_nvidia_pci ? "NVIDIA PCI device found" : "no NVIDIA PCI vendor id found");
    add_check(checks, "pci mellanox", has_mellanox,
        has_mellanox ? "Mellanox PCI device found" : "no Mellanox vendor id found");

    const std::string cmdline = read_file("/proc/cmdline");
    const bool iommu_hint = contains(cmdline, "iommu=pt") || contains(cmdline, "intel_iommu=on")
        || contains(cmdline, "amd_iommu=on");
    add_check(checks, "iommu hint", iommu_hint,
        iommu_hint ? "kernel cmdline has IOMMU hint" : "check BIOS/IOMMU settings before DPDK/RDMA");

    std::string topo = run_cmd("nvidia-smi topo -m 2>/dev/null");
    add_check(checks, "nvidia-smi topo", !topo.empty(),
        !topo.empty() ? "available" : "nvidia-smi topo unavailable");

    print_checks(checks);
    print_pci_devices(interesting);
    if (!topo.empty()) {
        std::printf("\n[nvidia-smi topo -m]\n%s\n", topo.c_str());
    }

    std::printf("[next] For P6, verify NIC and GPU share the expected PCIe root/NUMA node, then test memory registration with nvidia-peermem loaded.\n");
    return 0;
#endif
}
