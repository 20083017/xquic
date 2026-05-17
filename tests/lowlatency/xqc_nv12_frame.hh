#pragma once

#include <cstdint>
#include <vector>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#endif

/**
 * How pixel memory is carried from decode thread to the GL display thread.
 *
 * - **Cpu**: packed NV12 in `data` (software decode or CUDA hwdownload).
 * - **VaapiDmaBuf**: DRM PRIME fd exported from VAAPI; GL imports via EGLImage (zero-copy).
 */
enum class XqcNv12Backing : uint8_t {
    Cpu = 0,
    VaapiDmaBuf = 1,
};

/**
 * Compact NV12 frame (CPU buffer and/or dma-buf export).
 * At 4K, CPU `data` is ~12 MiB; dma-buf avoids that copy when VAAPI+EGL is active.
 */
struct XqcNv12Frame {
    uint16_t camera_id = 0;
    int width = 0;
    int height = 0;
    XqcNv12Backing backing = XqcNv12Backing::Cpu;
    std::vector<uint8_t> data;

    /** DRM PRIME (VAAPI): single fd, NV12 layout (Y then interleaved UV). */
    int dma_fd = -1;
    uint32_t dma_stride = 0;
    uint32_t dma_offset_y = 0;
    uint32_t dma_offset_uv = 0;

    int64_t pts_us = 0;
    uint64_t recv_us = 0;
    uint64_t decode_us = 0;
    uint64_t display_us = 0;
    bool from_stream = true;
};
