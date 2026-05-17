/**
 * Off-reactor H.264 Annex-B decode worker (bounded queue + decode thread).
 * With XQC_HAVE_FFMPEG: optional NV12 output queue for GL display thread.
 */

#pragma once

#include "xqc_h264_decode_stats.hh"
#include "xqc_nv12_frame.hh"

#include <cstddef>
#include <cstdint>

void xqc_h264_decode_worker_start();
void xqc_h264_decode_worker_stop();

void xqc_h264_decode_push_annexb(uint16_t camera_id, const uint8_t* annexb, std::size_t annexb_len);

/** Stream path: carry wire PTS + receiver timestamp for pacing / latency stats. */
void xqc_h264_decode_push_annexb_ts(uint16_t camera_id, const uint8_t* annexb, std::size_t annexb_len,
    int64_t wire_pts_us, uint64_t recv_us);

void xqc_h264_decode_enable_nv12_output(bool enable);

bool xqc_h264_decode_try_pop_nv12(XqcNv12Frame& out);

void xqc_h264_decode_flush();

void xqc_h264_decode_flush_camera(uint16_t camera_id);

/** EOS fallback: libavformat decode of recorded .h264 (FFmpeg 4.4). */
void xqc_h264_decode_file(const char* path, uint16_t camera_id);
