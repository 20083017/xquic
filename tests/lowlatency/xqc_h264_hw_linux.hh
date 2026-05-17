/**
 * @file xqc_h264_hw_linux.hh
 * @brief Linux hardware H.264 decode (VAAPI / CUDA-NVDEC) for the stream decoder.
 *
 * **VAAPI** (Intel/AMD): decode on GPU → export DRM PRIME dma-buf → EGLImage (zero-copy GL).
 * **CUDA** (NVIDIA): NVDEC via `h264_cuvid` / `hevc_cuvid` → CPU NV12 (hw decode,
 *   display still uses PBO until CUDA-EGL interop is added).
 *
 * Env:
 *   XQC_HW_DECODE=auto|vaapi|cuda|off
 *   XQC_VA_DEVICE=/dev/dri/renderD128
 */

#pragma once

#include "xqc_nv12_frame.hh"
#include "xqc_video_codec.hh"

struct AVCodec;
struct AVCodecContext;
struct AVFrame;
struct AVBufferRef;

enum class XqcHwDecodeBackend {
    Off,
    Auto,
    Software,
    Vaapi,
    Cuda,
};

/** Parse env / optional CLI override (e.g. "vaapi", "cuda", "auto", "off"). */
void xqc_h264_hw_configure(const char* mode_override);

/** Probe devices once per worker start; picks VAAPI then CUDA when mode=auto. */
XqcHwDecodeBackend xqc_h264_hw_init();

XqcHwDecodeBackend xqc_h264_hw_active_backend();

/** Human-readable label for logs (e.g. "vaapi+egl", "cuda+pbo"). */
const char* xqc_h264_hw_backend_name();

/**
 * Pick decoder + attach shared hw_device_ctx to @p ctx (VAAPI/CUDA) or software @p sw_codec.
 * @return true if avcodec_open2 succeeded.
 */
bool xqc_h264_hw_open_decoder(AVCodecContext* ctx, const AVCodec*& out_codec, XqcVideoCodec codec);

/**
 * Convert decoded @p frame to @p out (dma-buf or CPU NV12).
 * @return false if frame should be skipped or conversion failed (caller may fall back).
 */
bool xqc_h264_hw_frame_to_output(AVFrame* frame, XqcNv12Frame& out, uint16_t camera_id);

/** Close dma-buf fd / free CPU buffer when a queued frame is dropped. */
void xqc_nv12_frame_release(XqcNv12Frame& f);

/** Shared hw device (nullptr if software). Valid after xqc_h264_hw_init(). */
struct AVBufferRef;
AVBufferRef* xqc_h264_hw_device_ctx();
