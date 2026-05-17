/**
 * @file xqc_video_target.hh
 * @brief Nominal video geometry and buffer sizing for the low-latency receiver path.
 *
 * The WSL E2E test clip is 320x240, but the **display / PBO / queue** path is sized
 * for **4K (3840x2160)** so reviewers can reason about production memory and GPU upload
 * without changing code when moving to UHD streams.
 */

#pragma once

#include <cstddef>
#include <cstdint>

/** Target display / texture plane width (UHD). */
constexpr int XQC_VIDEO_TARGET_WIDTH = 3840;
/** Target display / texture plane height (UHD). */
constexpr int XQC_VIDEO_TARGET_HEIGHT = 2160;

/** NV12 bytes for one full 4K frame (Y + interleaved UV). */
constexpr std::size_t XQC_NV12_BYTES_4K =
    static_cast<std::size_t>(XQC_VIDEO_TARGET_WIDTH) * static_cast<std::size_t>(XQC_VIDEO_TARGET_HEIGHT)
    + static_cast<std::size_t>(XQC_VIDEO_TARGET_WIDTH) * static_cast<std::size_t>(XQC_VIDEO_TARGET_HEIGHT / 2);

/** NV12 byte size for arbitrary width x height (stride == width). */
inline std::size_t xqc_nv12_byte_size(int width, int height) {
    if (width <= 0 || height <= 0) {
        return 0;
    }
    return static_cast<std::size_t>(width) * static_cast<std::size_t>(height)
        + static_cast<std::size_t>(width) * static_cast<std::size_t>(height / 2);
}

/** True when frame fits the pre-provisioned 4K upload budget. */
inline bool xqc_frame_within_4k_budget(int width, int height) {
    return width > 0 && height > 0 && width <= XQC_VIDEO_TARGET_WIDTH && height <= XQC_VIDEO_TARGET_HEIGHT
        && xqc_nv12_byte_size(width, height) <= XQC_NV12_BYTES_4K;
}
