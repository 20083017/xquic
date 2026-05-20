/**
 * @file xqc_video_recv_process.hh
 * @brief QUIC video wire reassembly on the **reactor thread** (libevent or Seastar callback).
 *
 * ## Wire format (per packet)
 * ```
 * [ xqc_video_frame_header_t  16 bytes ][ NAL RBSP  payload_len bytes ]
 * ```
 * Recording and decode prepend Annex-B start code `00 00 00 01` before RBSP.
 *
 * ## Latency timestamps (stream path)
 * | Field | Set where | Used for |
 * |-------|-----------|----------|
 * | `hdr.pts_us` | Sender (`video_client` pacing) | wire_pts→display histogram |
 * | `recv_us` | Here, before `push_annexb_ts` | recv→display histogram |
 * | `decode_us` | Decode thread | decode-stage stats |
 * | `display_us` | GL thread after swap | E2E present time |
 *
 * ## Flags
 * @param stream_decode  Push each NAL to off-reactor decoder (real-time path).
 * @param eos_file_decode  On EOS, run `xqc_h264_decode_file` for validation (disable for pure E2E).
 */

#pragma once

#include "xqc_h264_ff_decode_api.hh"
#include "xqc_video_codec.hh"
#include "xqc_video_low_latency.hh"

#include <xquic/xqc_video_frame.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/stat.h>
#include <sys/time.h>
#else
#include <direct.h>
#endif

/** Monotonic wall clock (microseconds) for receive-side stamping. */
inline uint64_t xqc_video_recv_now_us() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

inline bool xqc_process_video_stream_buffer(
    char*& recv_body,
    size_t& recv_body_len,
    size_t& recv_body_cap,
    FILE*& recv_body_fp,
    const std::string& output_dir,
    bool stream_decode,
    bool eos_file_decode,
    XqcVideoCodec record_codec = XqcVideoCodec::HEVC)
{
    if (!recv_body || recv_body_len == 0) {
        return true;
    }

    const unsigned char* data = reinterpret_cast<const unsigned char*>(recv_body);
    size_t len = recv_body_len;
    size_t offset = 0;

    while (offset + XQC_VIDEO_FRAME_HEADER_LEN <= len) {
        xqc_video_frame_header_t hdr{};
        if (xqc_video_frame_header_decode(data + offset, len - offset, &hdr) != 0) {
            break; /* need more bytes for header */
        }
        if (offset + XQC_VIDEO_FRAME_HEADER_LEN + hdr.payload_len > len) {
            break; /* need more bytes for NAL payload */
        }

        char filename[256];
        filename[0] = '\0';
        if (!recv_body_fp) {
            std::snprintf(filename, sizeof(filename), "%s/cam_%u.%s",
                output_dir.c_str(), hdr.camera_id, xqc_video_codec_file_ext(record_codec));
#if defined(_WIN32) || defined(_WIN64)
            (void)_mkdir(output_dir.c_str());
#else
            (void)mkdir(output_dir.c_str(), 0755);
#endif
            recv_body_fp = std::fopen(filename, "wb");
            if (!recv_body_fp) {
                return false;
            }
            std::fprintf(stderr, "[video] recording camera %u -> %s\n", hdr.camera_id, filename);
        }

        static const unsigned char kStart[] = {0x00, 0x00, 0x00, 0x01};
        std::fwrite(kStart, 1, sizeof(kStart), recv_body_fp);
        std::fwrite(data + offset + XQC_VIDEO_FRAME_HEADER_LEN, 1, hdr.payload_len, recv_body_fp);

        if (stream_decode) {
            const uint64_t recv_us = xqc_video_recv_now_us();
            const uint8_t* rbsp = data + offset + XQC_VIDEO_FRAME_HEADER_LEN;
            const int rbsp_len = static_cast<int>(hdr.payload_len);
            const bool key_nal = xqc_annexb_is_key_nal(record_codec, rbsp, rbsp_len);
            const std::size_t qdepth = xqc_h264_decode_annexb_queue_depth();
            const std::size_t qdrop = xqc_video_decode_queue_drop_threshold();
            if (qdepth >= qdrop && !key_nal) {
                static std::atomic<uint64_t> dropped{0};
                const uint64_t n = dropped.fetch_add(1) + 1;
                if ((n & 127u) == 1u) {
                    std::fprintf(stderr,
                        "[video] catch-up: dropped stale NAL (queue=%zu threshold=%zu total=%llu)\n",
                        qdepth, qdrop, static_cast<unsigned long long>(n));
                }
            } else {
                std::vector<unsigned char> annexb(sizeof(kStart) + hdr.payload_len);
                std::memcpy(annexb.data(), kStart, sizeof(kStart));
                std::memcpy(annexb.data() + sizeof(kStart), rbsp, hdr.payload_len);
                xqc_h264_decode_push_annexb_ts(hdr.camera_id, annexb.data(), annexb.size(),
                    hdr.pts_us, recv_us);
            }
        }

        offset += XQC_VIDEO_FRAME_HEADER_LEN + hdr.payload_len;

        if (hdr.flags & XQC_VIDEO_FLAG_EOS) {
            std::fprintf(stderr, "[video] camera %u EOS\n", hdr.camera_id);
            if (recv_body_fp) {
                if (filename[0] == '\0') {
                    std::snprintf(filename, sizeof(filename), "%s/cam_%u.%s",
                        output_dir.c_str(), hdr.camera_id, xqc_video_codec_file_ext(record_codec));
                }
                std::fclose(recv_body_fp);
                recv_body_fp = nullptr;
                if (eos_file_decode && filename[0] != '\0') {
                    xqc_h264_decode_file(filename, hdr.camera_id);
                }
            }
            if (stream_decode) {
                xqc_h264_decode_flush_camera(hdr.camera_id);
            }
        }
    }

    if (offset > 0 && offset < len) {
        std::memmove(recv_body, recv_body + offset, len - offset);
        recv_body_len -= offset;
    } else if (offset >= len) {
        recv_body_len = 0;
    }
    return true;
}
