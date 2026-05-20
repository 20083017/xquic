/**
 * @file xqc_video_low_latency.hh
 * @brief Shared QUIC + pipeline tuning for real-time HEVC/H.264 (see seastar_runtime_dpdk_gpu_pipeline.md §693).
 */

#pragma once

#include <xquic/xquic.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>

/** QUIC transport: LOW_DELAY template unless XQC_LOW_DELAY=0. */
inline bool xqc_video_quic_low_delay_enabled() {
    const char* e = getenv("XQC_LOW_DELAY");
    if (!e || !e[0]) {
        return true;
    }
    return strcmp(e, "0") != 0 && strcmp(e, "false") != 0 && strcmp(e, "off") != 0;
}

inline xqc_conn_settings_t xqc_video_conn_settings() {
    if (xqc_video_quic_low_delay_enabled()) {
        xqc_conn_settings_t s = xqc_conn_get_conn_settings_template(XQC_CONN_SETTINGS_LOW_DELAY);
        if (s.proto_version == 0) {
            s.proto_version = XQC_VERSION_V1;
        }
        return s;
    }
    xqc_conn_settings_t s{};
    memset(&s, 0, sizeof(s));
    s.proto_version = XQC_VERSION_V1;
    return s;
}

/** Annex-B ingress queue depth before reactor drops non-keyframes (default 8). */
inline std::size_t xqc_video_decode_queue_drop_threshold() {
    const char* e = getenv("XQC_DECODE_QUEUE_DROP");
    if (!e || !e[0]) {
        return 8;
    }
    const long v = strtol(e, nullptr, 10);
    return v > 0 ? static_cast<std::size_t>(v) : 8;
}

/** NV12 queue depth for display bridge (default 1 = latest frame only). */
inline std::size_t xqc_video_nv12_queue_depth() {
    const char* e = getenv("XQC_NV12_QUEUE_DEPTH");
    if (!e || !e[0]) {
        return 1;
    }
    const long v = strtol(e, nullptr, 10);
    return v > 0 ? static_cast<std::size_t>(v) : 1;
}
