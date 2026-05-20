/**
 * @file xqc_nv12_mosaic.hh
 * @brief Roadmap P8: CPU NV12 mosaic compositor baseline.
 *
 * This is the correctness baseline for multi-stream composition. It keeps the
 * API independent from OpenGL so a later GPU compositor can be tested against
 * deterministic CPU output.
 */

#pragma once

#include "xqc_nv12_frame.hh"
#include "xqc_video_target.hh"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

struct XqcNv12MosaicLayout {
    int columns = 2;
    int rows = 2;
    int cell_width = 0;
    int cell_height = 0;
};

inline bool xqc_nv12_frame_is_compact_cpu(const XqcNv12Frame& f) {
    return f.backing == XqcNv12Backing::Cpu
        && f.width > 0
        && f.height > 0
        && (f.width % 2) == 0
        && (f.height % 2) == 0
        && f.data.size() >= xqc_nv12_byte_size(f.width, f.height);
}

inline void xqc_nv12_fill_black(XqcNv12Frame& out) {
    const std::size_t y_size = static_cast<std::size_t>(out.width) * static_cast<std::size_t>(out.height);
    const std::size_t total = xqc_nv12_byte_size(out.width, out.height);
    out.data.assign(total, 0);
    if (total > y_size) {
        std::memset(out.data.data() + y_size, 128, total - y_size);
    }
}

inline bool xqc_nv12_blit_same_size(const XqcNv12Frame& src, XqcNv12Frame& dst, int dst_x, int dst_y) {
    if (!xqc_nv12_frame_is_compact_cpu(src) || !xqc_nv12_frame_is_compact_cpu(dst)) {
        return false;
    }
    if (dst_x < 0 || dst_y < 0 || dst_x + src.width > dst.width || dst_y + src.height > dst.height) {
        return false;
    }
    if ((dst_x % 2) != 0 || (dst_y % 2) != 0) {
        return false;
    }

    const uint8_t* src_y = src.data.data();
    const uint8_t* src_uv = src.data.data()
        + static_cast<std::size_t>(src.width) * static_cast<std::size_t>(src.height);
    uint8_t* dst_y_plane = dst.data.data();
    uint8_t* dst_uv_plane = dst.data.data()
        + static_cast<std::size_t>(dst.width) * static_cast<std::size_t>(dst.height);

    const std::size_t dst_x_size = static_cast<std::size_t>(dst_x);
    const std::size_t dst_y_size = static_cast<std::size_t>(dst_y);

    for (int row = 0; row < src.height; ++row) {
        const std::size_t src_off = static_cast<std::size_t>(row) * static_cast<std::size_t>(src.width);
        const std::size_t dst_off =
            (dst_y_size + static_cast<std::size_t>(row)) * static_cast<std::size_t>(dst.width) + dst_x_size;
        std::memcpy(dst_y_plane + dst_off, src_y + src_off, static_cast<std::size_t>(src.width));
    }

    for (int row = 0; row < src.height / 2; ++row) {
        const std::size_t src_off = static_cast<std::size_t>(row) * static_cast<std::size_t>(src.width);
        const std::size_t dst_off =
            (dst_y_size / 2 + static_cast<std::size_t>(row)) * static_cast<std::size_t>(dst.width) + dst_x_size;
        std::memcpy(dst_uv_plane + dst_off, src_uv + src_off, static_cast<std::size_t>(src.width));
    }
    return true;
}

inline bool xqc_nv12_compose_mosaic_same_size(
    const std::vector<XqcNv12Frame>& inputs,
    const XqcNv12MosaicLayout& layout,
    XqcNv12Frame& out)
{
    if (layout.columns <= 0 || layout.rows <= 0 || layout.cell_width <= 0 || layout.cell_height <= 0) {
        return false;
    }
    if ((layout.cell_width % 2) != 0 || (layout.cell_height % 2) != 0) {
        return false;
    }

    out.width = layout.columns * layout.cell_width;
    out.height = layout.rows * layout.cell_height;
    out.backing = XqcNv12Backing::Cpu;
    out.camera_id = 0xffff;
    xqc_nv12_fill_black(out);

    const int capacity = layout.columns * layout.rows;
    const int count = std::min<int>(static_cast<int>(inputs.size()), capacity);
    for (int i = 0; i < count; ++i) {
        const XqcNv12Frame& src = inputs[static_cast<std::size_t>(i)];
        if (src.width != layout.cell_width || src.height != layout.cell_height) {
            return false;
        }
        const int col = i % layout.columns;
        const int row = i / layout.columns;
        if (!xqc_nv12_blit_same_size(src, out, col * layout.cell_width, row * layout.cell_height)) {
            return false;
        }
    }
    return true;
}
