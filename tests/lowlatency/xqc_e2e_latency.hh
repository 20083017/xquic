/**
 * @file xqc_e2e_latency.hh
 * @brief End-to-end latency histogram for **pure stream** frames (wire → display).
 *
 * ## What we measure
 *
 * Two complementary deltas are recorded when a frame is **presented** (after `glfwSwapBuffers`):
 *
 * 1. **recv → display** (`recv_us` → `display_us`)
 *    Wall-clock pipeline on the receiver: QUIC/stream callback stamped `recv_us` at NAL
 *    hand-off, display thread stamps `display_us` after GPU upload + swap.
 *    This is the most reliable metric for "how long until I see pixels" on one host.
 *
 * 2. **wire PTS → display** (anchored sender timeline → `display_us`)
 *    Sender `pts_us` is usually a **paced offset** (0, 33333, … µs), not wall clock. We anchor
 *    `recv0`/`pts0` on the first stream frame per camera, estimate
 *    `sender_wall ≈ recv0 + (pts_us - pts0)`, then record `display_us - sender_wall`.
 *    Includes pacing + network + decode + GL; compare with `--fps` on the client.
 *
 * ## What we exclude
 *
 * Only frames with `XqcNv12Frame::from_stream == true` are counted (EOS `decode_file` replay
 * is excluded). Use receiver `--no-eos-file-decode` for a clean stream-only run.
 *
 * ## Threading
 *
 * `record_stream_present()` is called from the **GLFW display thread**; `print_stderr()` from
 * the libevent stats timer or shutdown. Buckets use atomics (lock-free hot path).
 */

#pragma once

#include "xqc_nv12_frame.hh"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/time.h>

/** Histogram bucket upper bounds in microseconds (last bucket is overflow). */
struct XqcE2eLatencyBuckets {
    static constexpr std::size_t kCount = 8;
    static constexpr uint64_t kMaxUs[kCount] = {
        5'000,     /* 0–5 ms   */
        10'000,    /* 5–10 ms  */
        20'000,    /* 10–20 ms */
        33'333,    /* ~20–33 ms (60 Hz frame) */
        50'000,    /* 33–50 ms */
        100'000,   /* 50–100 ms */
        200'000,   /* 100–200 ms */
        UINT64_MAX /* 200+ ms */
    };

    static const char* label(std::size_t i) {
        static const char* k[] = {"0-5", "5-10", "10-20", "20-33", "33-50", "50-100", "100-200", "200+"};
        return i < kCount ? k[i] : "?";
    }

    static std::size_t bucket_index(uint64_t delta_us) {
        for (std::size_t i = 0; i < kCount; ++i) {
            if (delta_us <= kMaxUs[i]) {
                return i;
            }
        }
        return kCount - 1;
    }
};

/** Lock-free fixed-bucket histogram + min/max/sum for one latency type. */
struct XqcLatencyHistogramSide {
    std::atomic<uint64_t> buckets[XqcE2eLatencyBuckets::kCount]{};
    std::atomic<uint64_t> samples{0};
    std::atomic<uint64_t> sum_us{0};
    std::atomic<uint64_t> min_us{UINT64_MAX};
    std::atomic<uint64_t> max_us{0};

    void record(uint64_t delta_us) {
        if (delta_us == 0 && samples.load() == 0) {
            /* allow zero */
        }
        const std::size_t b = XqcE2eLatencyBuckets::bucket_index(delta_us);
        buckets[b].fetch_add(1, std::memory_order_relaxed);
        samples.fetch_add(1, std::memory_order_relaxed);
        sum_us.fetch_add(delta_us, std::memory_order_relaxed);
        uint64_t cur_min = min_us.load(std::memory_order_relaxed);
        while (delta_us < cur_min
            && !min_us.compare_exchange_weak(cur_min, delta_us, std::memory_order_relaxed)) {
        }
        uint64_t cur_max = max_us.load(std::memory_order_relaxed);
        while (delta_us > cur_max
            && !max_us.compare_exchange_weak(cur_max, delta_us, std::memory_order_relaxed)) {
        }
    }

    void reset() {
        for (std::size_t i = 0; i < XqcE2eLatencyBuckets::kCount; ++i) {
            buckets[i].store(0, std::memory_order_relaxed);
        }
        samples.store(0, std::memory_order_relaxed);
        sum_us.store(0, std::memory_order_relaxed);
        min_us.store(UINT64_MAX, std::memory_order_relaxed);
        max_us.store(0, std::memory_order_relaxed);
    }

    void print(const char* title) const {
        const uint64_t n = samples.load(std::memory_order_relaxed);
        if (n == 0) {
            std::fprintf(stderr, "  %s: (no samples)\n", title);
            return;
        }
        const uint64_t sum = sum_us.load(std::memory_order_relaxed);
        const double avg_ms = static_cast<double>(sum) / static_cast<double>(n) / 1000.0;
        const uint64_t mn = min_us.load(std::memory_order_relaxed);
        const uint64_t mx = max_us.load(std::memory_order_relaxed);
        const double min_ms = (mn != UINT64_MAX) ? static_cast<double>(mn) / 1000.0 : 0.0;
        std::fprintf(stderr, "  %s: n=%llu avg=%.2f ms min=%.2f max=%.2f ms\n",
            title, static_cast<unsigned long long>(n), avg_ms, min_ms,
            static_cast<double>(mx) / 1000.0);
        std::fprintf(stderr, "    buckets(ms):");
        for (std::size_t i = 0; i < XqcE2eLatencyBuckets::kCount; ++i) {
            std::fprintf(stderr, " %s=%llu", XqcE2eLatencyBuckets::label(i),
                static_cast<unsigned long long>(buckets[i].load(std::memory_order_relaxed)));
        }
        std::fprintf(stderr, "\n");
    }
};

/** Anchors sender pacing timeline (pts_us) to receiver wall clock at first stream frame. */
struct XqcPtsWallAnchor {
    bool set = false;
    int64_t pts0 = 0;
    uint64_t recv0 = 0;
};

/** Pair of histograms updated on each stream frame present. */
struct XqcE2eLatencyHistogram {
    XqcLatencyHistogramSide recv_to_display;
    /** display_us - (recv0 + (pts_us - pts0)): sender PTS mapped via first-packet anchor. */
    XqcLatencyHistogramSide wire_pts_to_display;
    XqcPtsWallAnchor anchor_[16];

    void reset() {
        recv_to_display.reset();
        wire_pts_to_display.reset();
        for (auto& a : anchor_) {
            a = XqcPtsWallAnchor{};
        }
    }

    /**
     * Record latencies for one presented stream frame.
     * @param frame  Must have from_stream==true; recv_us / pts_us set by decode path.
     * @param display_us  Wall time after swap (pixels submitted to compositor).
     */
    void record_stream_present(const XqcNv12Frame& frame, uint64_t display_us) {
        if (!frame.from_stream) {
            return;
        }
        if (frame.recv_us > 0 && display_us >= frame.recv_us) {
            recv_to_display.record(display_us - frame.recv_us);
        }
        if (frame.pts_us >= 0 && frame.recv_us > 0) {
            const unsigned cam = frame.camera_id < 16 ? frame.camera_id : 0;
            XqcPtsWallAnchor& a = anchor_[cam];
            if (!a.set) {
                a.pts0 = frame.pts_us;
                a.recv0 = frame.recv_us;
                a.set = true;
            }
            const int64_t pts_delta = frame.pts_us - a.pts0;
            const uint64_t sender_wall_est = a.recv0 + static_cast<uint64_t>(pts_delta);
            if (display_us >= sender_wall_est) {
                wire_pts_to_display.record(display_us - sender_wall_est);
            }
        }
    }

    void print_stderr(const char* prefix) const {
        std::fprintf(stderr, "%s (stream-only, 4K-ready path)\n", prefix);
        recv_to_display.print("recv->display");
        wire_pts_to_display.print("wire_pts->display (anchored)");
    }
};

inline uint64_t xqc_wall_us_now() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

inline XqcE2eLatencyHistogram& xqc_e2e_latency_hist() {
    static XqcE2eLatencyHistogram g;
    return g;
}

inline void xqc_e2e_latency_reset() {
    xqc_e2e_latency_hist().reset();
}
