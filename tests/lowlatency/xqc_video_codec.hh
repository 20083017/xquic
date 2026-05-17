/**
 * @file xqc_video_codec.hh
 * @brief H.264 / HEVC (H.265) codec selection for Annex-B stream decode.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

enum class XqcVideoCodec {
    H264 = 0,
    HEVC = 1,
};

inline const char* xqc_video_codec_name(XqcVideoCodec c) {
    return c == XqcVideoCodec::HEVC ? "hevc" : "h264";
}

inline const char* xqc_video_codec_file_ext(XqcVideoCodec c) {
    return c == XqcVideoCodec::HEVC ? "h265" : "h264";
}

/** Parse CLI / env: hevc|h265|h264|auto (auto → HEVC). */
inline XqcVideoCodec xqc_video_codec_parse(const char* s, XqcVideoCodec fallback = XqcVideoCodec::HEVC) {
    if (!s || !s[0]) {
        return fallback;
    }
    if (strcmp(s, "h264") == 0 || strcmp(s, "avc") == 0) {
        return XqcVideoCodec::H264;
    }
    if (strcmp(s, "hevc") == 0 || strcmp(s, "h265") == 0 || strcmp(s, "h.265") == 0) {
        return XqcVideoCodec::HEVC;
    }
    if (strcmp(s, "auto") == 0) {
        return fallback;
    }
    return fallback;
}

/** Infer from file suffix (.h264 / .h265 / .hevc). */
inline XqcVideoCodec xqc_video_codec_from_path(const char* path, XqcVideoCodec fallback = XqcVideoCodec::HEVC) {
    if (!path) {
        return fallback;
    }
    const char* dot = strrchr(path, '.');
    if (!dot) {
        return fallback;
    }
    ++dot;
    if (strcmp(dot, "h264") == 0 || strcmp(dot, "264") == 0) {
        return XqcVideoCodec::H264;
    }
    if (strcmp(dot, "h265") == 0 || strcmp(dot, "hevc") == 0 || strcmp(dot, "265") == 0) {
        return XqcVideoCodec::HEVC;
    }
    return fallback;
}

#if defined(XQC_HAVE_FFMPEG)
extern "C" {
#include <libavcodec/avcodec.h>
}
inline enum AVCodecID xqc_video_codec_av_id(XqcVideoCodec c) {
    return c == XqcVideoCodec::HEVC ? AV_CODEC_ID_HEVC : AV_CODEC_ID_H264;
}
#endif

inline bool xqc_annexb_should_feed_nal(XqcVideoCodec codec, const uint8_t* nal, int size) {
    if (!nal || size < 1) {
        return false;
    }
    if (codec == XqcVideoCodec::HEVC) {
        if (size < 2) {
            return false;
        }
        const uint8_t t = static_cast<uint8_t>((nal[0] >> 1) & 0x3f);
        switch (t) {
        case 35: /* AUD */
        case 39:
        case 40: /* SEI */
        case 48:
        case 49: /* filler / SEI */
            return false;
        default:
            return true;
        }
    }
    const uint8_t t = static_cast<uint8_t>(nal[0] & 0x1f);
    switch (t) {
    case 6:
    case 9:
    case 10:
    case 11:
    case 12:
        return false;
    default:
        return true;
    }
}
