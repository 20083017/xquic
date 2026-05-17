/** Smoke test: Annex-B .h264 file -> libavformat decode -> NV12 queue. */
#include "xqc_h264_ff_decode_api.hh"
#include "xqc_h264_decode_stats.hh"
#include "xqc_video_codec.hh"

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s file.h264|file.h265\n", argv[0]);
        return 1;
    }

    xqc_h264_decode_stats_reset();
    xqc_h264_decode_enable_nv12_output(true);
    xqc_h264_decode_file(argv[1], 0);

    const uint64_t decoded = xqc_h264_decode_stats()
        ? xqc_h264_decode_stats()->file_frames.load()
        : 0;

    int popped = 0;
    XqcNv12Frame frame;
    while (xqc_h264_decode_try_pop_nv12_fifo(frame)) {
        ++popped;
    }

    const XqcVideoCodec codec = xqc_video_codec_from_path(argv[1], XqcVideoCodec::HEVC);
    std::fprintf(stderr,
        "[smoke] codec=%s decode_file=%llu NV12 frames, fifo_popped=%d (queue depth 4), last %dx%d\n",
        xqc_video_codec_name(codec),
        static_cast<unsigned long long>(decoded),
        popped, frame.width, frame.height);

    if (decoded == 0 || popped == 0) {
        return 2;
    }
    return 0;
}
