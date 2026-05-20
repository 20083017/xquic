/**
 * @file xqc_nvidia_prime_env.hh
 * @brief Force NVIDIA GLX for CUDA-GL interop on hybrid Intel+NVIDIA laptops.
 *
 * Set `XQC_NVIDIA_PRIME=0` to skip. Must run before `glfwInit()` / first GL context.
 */

#pragma once

/** Apply __GLX_VENDOR_LIBRARY_NAME=nvidia and __NV_PRIME_RENDER_OFFLOAD=1 when unset. */
void xqc_nvidia_prime_apply_for_cuda_gl();
