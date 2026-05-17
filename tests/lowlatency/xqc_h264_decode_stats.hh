#pragma once

#include <atomic>
#include <cstdint>

/** Lock-free counters for stream-decode telemetry (read on stats thread / stderr). */
struct XqcH264DecodeStats {
    std::atomic<uint64_t> annexb_pushed{0};
    std::atomic<uint64_t> nv12_out{0};
    std::atomic<uint64_t> stream_frames{0};
    std::atomic<uint64_t> file_frames{0};
    std::atomic<uint64_t> latency_sum_us{0};
    std::atomic<uint64_t> latency_count{0};
    std::atomic<uint64_t> last_wire_pts_us{0};
    std::atomic<uint64_t> last_decode_us{0};
};

void xqc_h264_decode_stats_reset();
XqcH264DecodeStats* xqc_h264_decode_stats();
void xqc_h264_decode_stats_note_nv12(uint64_t recv_us, uint64_t decode_us, int64_t wire_pts_us, bool from_file);
