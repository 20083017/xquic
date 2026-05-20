#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

add_bashrc_line_once() {
    local line="$1"
    if ! grep -Fxq "$line" "$HOME/.bashrc"; then
        echo "$line" >> "$HOME/.bashrc"
    fi
}

echo -e "${YELLOW}--- 开始检测 NVIDIA + CUDA + EGL 开发环境 (Ubuntu 22.04) ---${NC}"

# 1. 硬件检查
if lspci | grep -i nvidia > /dev/null; then
    echo -e "${GREEN}[OK] 硬件: 检测到 NVIDIA GPU${NC}"
else
    echo -e "${RED}[ERROR] 未检测到 NVIDIA 硬件，请确认是否为显卡直通环境${NC}"
    exit 1
fi

# 2. 驱动检查
if command -v nvidia-smi &> /dev/null; then
    if DRIVER_VERSION=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null); then
        echo -e "${GREEN}[OK] 驱动: 已安装 $DRIVER_VERSION${NC}"
    else
        echo -e "${YELLOW}[WARN] 驱动命令已安装但未正常加载，请重启或检查 Secure Boot/MOK${NC}"
    fi
else
    echo -e "${RED}[MISSING] 驱动: 未安装${NC}"
    INSTALL_DRIVER=true
fi

# 3. CUDA 检查
if command -v nvcc &> /dev/null; then
    CUDA_VERSION=$(nvcc --version | grep release | awk '{print $6}' || true)
    echo -e "${GREEN}[OK] CUDA: 已检测到版本 ${CUDA_VERSION:-未知}${NC}"
elif dpkg-query -W -f='${Status}' cuda-toolkit-12-4 2>/dev/null | grep -q "install ok installed"; then
    echo -e "${GREEN}[OK] CUDA: cuda-toolkit-12-4 已安装，可能需要 source ~/.bashrc${NC}"
elif [ -d "/usr/local/cuda" ]; then
    echo -e "${GREEN}[OK] CUDA: 检测到 /usr/local/cuda，可能需要配置 PATH${NC}"
else
    echo -e "${RED}[MISSING] CUDA: 未安装${NC}"
    INSTALL_CUDA=true
fi

# 4. EGL 开发库检查 (重点针对开发环境)
EGL_LIBS=("libegl1-mesa-dev" "libgbm-dev" "libnvidia-egl-wayland-dev")
MISSING_EGL=()
for lib in "${EGL_LIBS[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$lib" 2>/dev/null | grep -q "install ok installed"; then MISSING_EGL+=("$lib"); fi
done

if [ ${#MISSING_EGL[@]} -eq 0 ]; then
    echo -e "${GREEN}[OK] EGL: 相关开发库已就绪${NC}"
else
    echo -e "${RED}[MISSING] EGL: 缺少库 ${MISSING_EGL[*]}${NC}"
    INSTALL_EGL=true
fi

# --- 构建逻辑 ---
if [ "${INSTALL_DRIVER:-}" = true ] || [ "${INSTALL_CUDA:-}" = true ] || [ "${INSTALL_EGL:-}" = true ]; then
    echo "-----------------------------------------------"
    read -r -p "检测到环境不完整，是否立即开始自动构建? (y/n) " choice || choice="n"
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        sudo apt update && sudo apt install -y wget software-properties-common

        # 安装驱动 (使用 22.04 推荐的 535/550 版本)
        if [ "${INSTALL_DRIVER:-}" = true ]; then
            echo -e "${YELLOW}正在安装 NVIDIA 官方驱动...${NC}"
            sudo ubuntu-drivers install
        fi

        # 安装 CUDA (使用 NVIDIA Ubuntu 22.04 官方仓库)
        if [ "${INSTALL_CUDA:-}" = true ]; then
            echo -e "${YELLOW}正在配置 NVIDIA 官方仓库并安装 CUDA...${NC}"
            if ! dpkg-query -W -f='${Status}' cuda-keyring 2>/dev/null | grep -q "install ok installed"; then
                CUDA_KEYRING="/tmp/cuda-keyring_1.1-1_all.deb"
                wget -O "$CUDA_KEYRING" https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
                sudo dpkg -i "$CUDA_KEYRING"
            fi
            sudo apt update
            sudo apt install -y cuda-toolkit-12-4
            
            # 写入环境变量
            add_bashrc_line_once 'export PATH=/usr/local/cuda/bin:$PATH'
            add_bashrc_line_once 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH'
        fi

        # 安装 EGL 开发环境
        if [ "${INSTALL_EGL:-}" = true ]; then
            echo -e "${YELLOW}正在安装 EGL/OpenGL 开发依赖...${NC}"
            sudo apt install -y libegl1-mesa-dev libgles2-mesa-dev libgbm-dev libnvidia-egl-wayland-dev pkg-config
        fi

        echo -e "${GREEN}--- 构建完成！ ---${NC}"
        echo -e "${YELLOW}请执行: 'source ~/.bashrc' 并重启系统以生效驱动。${NC}"
    fi
else
    echo -e "${GREEN}--- 环境已就绪，无需重复安装。 ---${NC}"
fi
