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

/** Lock-free SPSC queue telemetry (Annex-B + NV12 rings). */
struct XqcSpscQueueStats {
    std::atomic<uint64_t> annexb_push{0};
    std::atomic<uint64_t> annexb_pop{0};
    std::atomic<uint64_t> annexb_drop_oldest{0};
    std::atomic<uint64_t> nv12_push{0};
    std::atomic<uint64_t> nv12_drop_depth{0};
    std::atomic<uint64_t> nv12_drop_ring{0};
    std::atomic<uint64_t> nv12_display_pop{0};
    std::atomic<uint64_t> nv12_skipped_latest{0};
    std::atomic<uint64_t> display_submit{0};
};

void xqc_h264_decode_stats_reset();
XqcH264DecodeStats* xqc_h264_decode_stats();
XqcSpscQueueStats* xqc_spsc_queue_stats();
/** Periodic stderr line: queue depths + push/pop/drop counters (no mutex on dataplane). */
void xqc_h264_decode_log_spsc_stats();
void xqc_h264_decode_note_display_submit();
void xqc_h264_decode_stats_note_nv12(uint64_t recv_us, uint64_t decode_us, int64_t wire_pts_us, bool from_file);
