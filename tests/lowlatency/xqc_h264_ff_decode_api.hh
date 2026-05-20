/**
 * Off-reactor H.264 Annex-B decode worker (bounded queue + decode thread).
 * With XQC_HAVE_FFMPEG: optional NV12 output queue for GL display thread.
 */

#pragma once

#include "xqc_h264_decode_stats.hh"
#include "xqc_nv12_frame.hh"
#include "xqc_video_codec.hh"

#include <cstddef>
#include <cstdint>

void xqc_h264_decode_worker_start();
void xqc_h264_decode_worker_stop();

/** Linux: auto|vaapi|cuda|off — call before worker_start. Also env `XQC_HW_DECODE`. */
void xqc_h264_decode_configure_hw(const char* mode);

/** Default stream codec (HEVC when unset). Call before worker_start. */
void xqc_h264_decode_set_default_codec(XqcVideoCodec codec);

/** Per-camera codec (dual-stack: cam0 H.264 + cam1 HEVC). */
void xqc_h264_decode_set_camera_codec(uint16_t camera_id, XqcVideoCodec codec);

XqcVideoCodec xqc_h264_decode_camera_codec(uint16_t camera_id);

void xqc_h264_decode_push_annexb(uint16_t camera_id, const uint8_t* annexb, std::size_t annexb_len);

void xqc_h264_decode_push_annexb_ts(uint16_t camera_id, const uint8_t* annexb, std::size_t annexb_len,
    int64_t wire_pts_us, uint64_t recv_us);

/** Enable NV12 queue for display (default depth 1 via XQC_NV12_QUEUE_DEPTH). */
void xqc_h264_decode_enable_nv12_output(bool enable);

/** Pop latest NV12 (display path; drops older queued frames). */
bool xqc_h264_decode_try_pop_nv12(XqcNv12Frame& out);

/** Depth of Annex-B ingress queue (reactor catch-up). */
std::size_t xqc_h264_decode_annexb_queue_depth();

/** Depth of NV12 egress queue (display bridge). */
std::size_t xqc_h264_decode_nv12_queue_depth();

/** Pop one frame FIFO (tests / drain after decode_file). */
bool xqc_h264_decode_try_pop_nv12_fifo(XqcNv12Frame& out);

void xqc_h264_decode_flush();

void xqc_h264_decode_flush_camera(uint16_t camera_id);

/** EOS fallback: libavformat decode of recorded .h264 (FFmpeg 4.4). */
void xqc_h264_decode_file(const char* path, uint16_t camera_id);
