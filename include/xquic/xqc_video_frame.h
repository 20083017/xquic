/**
 * @file xqc_video_frame.h
 * @brief Video streaming protocol over QUIC streams.
 *
 * Architecture (surveillance / multi-camera scenario):
 *
 *   Terminal Device (Client)                    Seastar Server
 *   ┌─────────────────────┐                    ┌──────────────────────┐
 *   │ Camera 0 (.h264)    │──QUIC stream 1──▶  │ StreamRouter         │
 *   │ Camera 1 (.h264)    │──QUIC stream 2──▶  │   ├─▶ FileStorage    │
 *   │ Control             │──QUIC stream 0──▶  │   └─▶ Subscribers    │
 *   └─────────────────────┘   (1 connection)   └──────────────────────┘
 *
 * Protocol on each video stream:
 *   [FrameHeader 16B][NAL payload N bytes] [FrameHeader][NAL payload] ...
 *
 * Control stream carries XQC_VIDEO_MSG_REGISTER once at stream open,
 * and optional XQC_VIDEO_MSG_SUBSCRIBE / UNSUBSCRIBE for viewers.
 */

#ifndef XQC_VIDEO_FRAME_H
#define XQC_VIDEO_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Frame types ─────────────────────────────────────────────── */

typedef enum {
    XQC_VIDEO_FRAME_IDR       = 0x01,   /* IDR / keyframe (contains SPS+PPS) */
    XQC_VIDEO_FRAME_P         = 0x02,   /* P-frame (predicted) */
    XQC_VIDEO_FRAME_B         = 0x03,   /* B-frame (bidirectional) */
    XQC_VIDEO_FRAME_SPS_PPS   = 0x04,   /* codec config (SPS + PPS only) */
    XQC_VIDEO_FRAME_SEI       = 0x05,   /* SEI metadata */
} xqc_video_frame_type_t;

typedef enum {
    XQC_VIDEO_FLAG_KEYFRAME   = 0x01,
    XQC_VIDEO_FLAG_EOS        = 0x02,   /* end of stream */
    XQC_VIDEO_FLAG_CONFIG     = 0x04,   /* this frame contains codec config */
} xqc_video_frame_flag_t;

/* ─── Frame header (16 bytes, network byte order) ─────────────── */

#define XQC_VIDEO_FRAME_HEADER_LEN  16

/*
 * Wire format:
 *   offset  size  field
 *   0       1     type          (xqc_video_frame_type_t)
 *   1       1     flags         (bitmask of xqc_video_frame_flag_t)
 *   2       2     camera_id     (big-endian, 0-based)
 *   4       4     payload_len   (big-endian, NAL unit size in bytes)
 *   8       8     pts_us        (big-endian, presentation timestamp µs)
 */
typedef struct {
    uint8_t     type;
    uint8_t     flags;
    uint16_t    camera_id;
    uint32_t    payload_len;
    int64_t     pts_us;
} xqc_video_frame_header_t;

/* ─── Control messages (on stream 0) ──────────────────────────── */

typedef enum {
    XQC_VIDEO_MSG_REGISTER    = 0x10,   /* device → server: "I have N cameras" */
    XQC_VIDEO_MSG_SUBSCRIBE   = 0x11,   /* viewer → server: "send me camera X of device Y" */
    XQC_VIDEO_MSG_UNSUBSCRIBE = 0x12,
    XQC_VIDEO_MSG_HEARTBEAT   = 0x13,
} xqc_video_msg_type_t;

/*
 * Register message payload (after standard frame header):
 *   offset  size  field
 *   0       2     camera_count  (big-endian)
 *   2       N     device_id     (UTF-8 string, len = payload_len - 2)
 */

/* ─── Serialization helpers ───────────────────────────────────── */

static inline void
xqc_video_write_u16_be(unsigned char *buf, uint16_t val) {
    buf[0] = (unsigned char)(val >> 8);
    buf[1] = (unsigned char)(val);
}

static inline void
xqc_video_write_u32_be(unsigned char *buf, uint32_t val) {
    buf[0] = (unsigned char)(val >> 24);
    buf[1] = (unsigned char)(val >> 16);
    buf[2] = (unsigned char)(val >> 8);
    buf[3] = (unsigned char)(val);
}

static inline void
xqc_video_write_i64_be(unsigned char *buf, int64_t val) {
    uint64_t u = (uint64_t)val;
    buf[0] = (unsigned char)(u >> 56);
    buf[1] = (unsigned char)(u >> 48);
    buf[2] = (unsigned char)(u >> 40);
    buf[3] = (unsigned char)(u >> 32);
    buf[4] = (unsigned char)(u >> 24);
    buf[5] = (unsigned char)(u >> 16);
    buf[6] = (unsigned char)(u >> 8);
    buf[7] = (unsigned char)(u);
}

static inline uint16_t
xqc_video_read_u16_be(const unsigned char *buf) {
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

static inline uint32_t
xqc_video_read_u32_be(const unsigned char *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];
}

static inline int64_t
xqc_video_read_i64_be(const unsigned char *buf) {
    uint64_t u = ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48)
               | ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32)
               | ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16)
               | ((uint64_t)buf[6] << 8)  | (uint64_t)buf[7];
    return (int64_t)u;
}

/**
 * Encode a frame header into 16-byte buffer.
 */
static inline void
xqc_video_frame_header_encode(unsigned char *buf, const xqc_video_frame_header_t *hdr) {
    buf[0] = hdr->type;
    buf[1] = hdr->flags;
    xqc_video_write_u16_be(buf + 2, hdr->camera_id);
    xqc_video_write_u32_be(buf + 4, hdr->payload_len);
    xqc_video_write_i64_be(buf + 8, hdr->pts_us);
}

/**
 * Decode a 16-byte buffer into a frame header.
 * @return 0 on success.
 */
static inline int
xqc_video_frame_header_decode(const unsigned char *buf, size_t buf_len,
                               xqc_video_frame_header_t *hdr) {
    if (buf_len < XQC_VIDEO_FRAME_HEADER_LEN) return -1;
    hdr->type        = buf[0];
    hdr->flags       = buf[1];
    hdr->camera_id   = xqc_video_read_u16_be(buf + 2);
    hdr->payload_len = xqc_video_read_u32_be(buf + 4);
    hdr->pts_us      = xqc_video_read_i64_be(buf + 8);
    return 0;
}

/**
 * Detect H.264 NAL unit type from first byte of NAL payload.
 * (payload after start code 00 00 00 01)
 */
static inline uint8_t
xqc_video_h264_nal_type(uint8_t nal_header) {
    return nal_header & 0x1F;
}

#define XQC_H264_NAL_IDR    5
#define XQC_H264_NAL_SEI    6
#define XQC_H264_NAL_SPS    7
#define XQC_H264_NAL_PPS    8

/**
 * Map H.264 NAL type to our frame type.
 */
static inline xqc_video_frame_type_t
xqc_video_h264_nal_to_frame_type(uint8_t nal_type) {
    switch (nal_type) {
    case XQC_H264_NAL_IDR: return XQC_VIDEO_FRAME_IDR;
    case XQC_H264_NAL_SPS:
    case XQC_H264_NAL_PPS: return XQC_VIDEO_FRAME_SPS_PPS;
    case XQC_H264_NAL_SEI: return XQC_VIDEO_FRAME_SEI;
    default:               return XQC_VIDEO_FRAME_P;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* XQC_VIDEO_FRAME_H */
