/**
 * @file xqc_nvidia_prime_env.cpp
 */

#include "xqc_nvidia_prime_env.hh"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

bool prime_disabled() {
    const char* e = std::getenv("XQC_NVIDIA_PRIME");
    return e && e[0]
        && (std::strcmp(e, "0") == 0 || std::strcmp(e, "false") == 0 || std::strcmp(e, "off") == 0);
}

void set_if_unset(const char* key, const char* val) {
    if (!std::getenv(key)) {
        ::setenv(key, val, 0);
    }
}

} // namespace

void xqc_nvidia_prime_apply_for_cuda_gl() {
    if (prime_disabled()) {
        return;
    }
    const bool had_glx = std::getenv("__GLX_VENDOR_LIBRARY_NAME") != nullptr;
    const bool had_offload = std::getenv("__NV_PRIME_RENDER_OFFLOAD") != nullptr;
    set_if_unset("__GLX_VENDOR_LIBRARY_NAME", "nvidia");
    set_if_unset("__NV_PRIME_RENDER_OFFLOAD", "1");
    if (!had_glx || !had_offload) {
        std::fprintf(stderr,
            "[cuda-gl] hybrid GPU: set __GLX_VENDOR_LIBRARY_NAME=nvidia __NV_PRIME_RENDER_OFFLOAD=1 "
            "(override with XQC_NVIDIA_PRIME=0)\n");
    }
}
