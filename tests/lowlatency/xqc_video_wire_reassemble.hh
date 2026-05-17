/**
 * Reassemble xquic video wire format ([16B header][payload])* from a byte stream.
 * Emits complete NAL payloads (without start code) for FFmpeg bitstream filter / parser.
 */

#pragma once

#include <xquic/xqc_video_frame.h>

#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

class XqcVideoWireReassembler {
public:
    using OnNalFn = std::function<void(const xqc_video_frame_header_t& hdr, const uint8_t* nal, size_t nal_len)>;

    explicit XqcVideoWireReassembler(OnNalFn on_nal) : _on(std::move(on_nal)) {}

    void feed(const uint8_t* data, size_t len) {
        _buf.insert(_buf.end(), data, data + len);
        drain();
    }

    void reset() { _buf.clear(); }

private:
    void drain() {
        size_t o = 0;
        while (o + XQC_VIDEO_FRAME_HEADER_LEN <= _buf.size()) {
            xqc_video_frame_header_t hdr{};
            if (xqc_video_frame_header_decode(_buf.data() + o, _buf.size() - o, &hdr) != 0) {
                break;
            }
            const size_t need = XQC_VIDEO_FRAME_HEADER_LEN + static_cast<size_t>(hdr.payload_len);
            if (o + need > _buf.size()) {
                break;
            }
            const uint8_t* nal = _buf.data() + o + XQC_VIDEO_FRAME_HEADER_LEN;
            if (_on) {
                _on(hdr, nal, hdr.payload_len);
            }
            o += need;
        }
        if (o > 0) {
            _buf.erase(_buf.begin(), _buf.begin() + static_cast<std::ptrdiff_t>(o));
        }
    }

    std::vector<uint8_t> _buf;
    OnNalFn _on;
};
