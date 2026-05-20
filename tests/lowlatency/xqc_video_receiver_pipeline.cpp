/**
 * @file xqc_video_receiver_pipeline.cpp
 */

#include "xqc_video_receiver_pipeline.hh"

#include "xqc_e2e_latency.hh"
#include "xqc_h264_decode_stats.hh"
#include "xqc_h264_ff_decode_api.hh"
#include "xqc_nvidia_prime_env.hh"
#include "xqc_thread_affinity.hh"
#include "xqc_video_target.hh"

#include "../user_conn.h"

#if defined(XQC_HAVE_GLFW)
#include "xqc_nv12_gl_linux.hh"
#endif

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

bool xqc_video_receiver_ensure_recv_cap(user_stream_t* us, std::size_t extra) {
    if (!us) {
        return false;
    }
    if (us->recv_body_len + extra <= us->recv_body_cap) {
        return true;
    }
    std::size_t need = us->recv_body_len + extra;
    std::size_t cap = us->recv_body_cap ? us->recv_body_cap : 65536;
    while (cap < need) {
        cap *= 2;
    }
    void* p = std::realloc(us->recv_body, cap);
    if (!p) {
        return false;
    }
    us->recv_body = static_cast<char*>(p);
    us->recv_body_cap = cap;
    return true;
}

void xqc_video_receiver_apply_nvidia_prime(const XqcVideoReceiverOptions& opt) {
#if defined(XQC_HAVE_HW_DECODE)
    if (!opt.display) {
        return;
    }
    if (opt.hw_decode_mode.empty()) {
        return;
    }
    if (opt.hw_decode_mode == "cuda" || opt.hw_decode_mode == "auto") {
        xqc_nvidia_prime_apply_for_cuda_gl();
    }
#else
    (void)opt;
#endif
}

void xqc_video_receiver_start_decode(const XqcVideoReceiverOptions& opt) {
    if (!opt.decode) {
        return;
    }
    if (!opt.hw_decode_mode.empty()) {
        xqc_h264_decode_configure_hw(opt.hw_decode_mode.c_str());
    }
    xqc_h264_decode_set_default_codec(opt.stream_codec);
    xqc_h264_decode_enable_nv12_output(true);
    xqc_h264_decode_worker_start();
}

void xqc_video_receiver_boot_pipeline(XqcVideoReceiverOptions& opt, XqcVideoDisplayPipeline& display,
    const char* window_title)
{
    if (!opt.decode) {
        (void)display.start(opt, window_title);
        return;
    }
    /* Configure HW backend before GL so display picks CUDA-GL vs EGL vs PBO. */
    if (!opt.hw_decode_mode.empty()) {
        xqc_h264_decode_configure_hw(opt.hw_decode_mode.c_str());
    }
    xqc_h264_decode_set_default_codec(opt.stream_codec);
    xqc_h264_decode_enable_nv12_output(true);
    /* GL + cudaGLSetGLDevice before NVDEC/CUDA init in decode worker. */
    (void)display.start(opt, window_title);
    xqc_h264_decode_worker_start();
}

void xqc_video_receiver_log_stats(const XqcVideoReceiverOptions& opt) {
    XqcH264DecodeStats* st = xqc_h264_decode_stats();
    if (!st) {
        return;
    }
    const uint64_t lat_n = st->latency_count.load();
    const uint64_t lat_sum = st->latency_sum_us.load();
    const double avg_lat_ms = lat_n ? (static_cast<double>(lat_sum) / static_cast<double>(lat_n)) / 1000.0 : 0.0;
    std::fprintf(stderr,
        "[stats] nal_in=%llu stream_nv12=%llu file_nv12=%llu avg_decode_ms=%.2f last_pts_us=%llu\n",
        static_cast<unsigned long long>(st->annexb_pushed.load()),
        static_cast<unsigned long long>(st->stream_frames.load()),
        static_cast<unsigned long long>(st->file_frames.load()),
        avg_lat_ms,
        static_cast<unsigned long long>(st->last_wire_pts_us.load()));
    xqc_h264_decode_log_spsc_stats();
#if defined(XQC_HAVE_GLFW)
    if (opt.display) {
        xqc_e2e_latency_hist().print_stderr("[e2e]");
    }
#endif
}

void xqc_video_receiver_log_e2e_final(const XqcVideoReceiverOptions& opt) {
#if defined(XQC_HAVE_GLFW)
    if (opt.display) {
        xqc_e2e_latency_hist().print_stderr("[e2e final]");
    }
#else
    (void)opt;
#endif
}

void xqc_video_receiver_stop_decode() {
    xqc_h264_decode_worker_stop();
}

#if defined(XQC_HAVE_GLFW)

namespace {

XqcNv12GlLinux g_display_gl;

} // namespace

XqcVideoDisplayPipeline::~XqcVideoDisplayPipeline() {
    join();
}

bool XqcVideoDisplayPipeline::start(XqcVideoReceiverOptions& opt, const char* window_title) {
    if (!opt.display) {
        return false;
    }
    if (!std::getenv("DISPLAY") || !std::getenv("DISPLAY")[0]) {
        std::fprintf(stderr, "[recv] DISPLAY unset; export DISPLAY=:0 or use --decode only\n");
        opt.display = false;
        return false;
    }

    xqc_video_receiver_apply_nvidia_prime(opt);

    const char* title = window_title ? window_title : "xquic video receiver";
    if (!g_display_gl.start(XQC_VIDEO_TARGET_WIDTH, XQC_VIDEO_TARGET_HEIGHT, title)) {
        std::fprintf(stderr,
            "[recv] --display failed (check DISPLAY, libglfw3, GLX vs EGL); continuing decode-only\n");
        opt.display = false;
        return false;
    }

    _gl = &g_display_gl;
    _stop = false;
    _bridge = std::thread([this] { bridge_loop(); });
    _active = true;
    return true;
}

void XqcVideoDisplayPipeline::request_stop() {
    _stop = true;
}

void XqcVideoDisplayPipeline::join() {
    request_stop();
    if (_bridge.joinable()) {
        _bridge.join();
    }
    if (_active && _gl) {
        _gl->stop();
    }
    _active = false;
    _gl = nullptr;
}

void XqcVideoDisplayPipeline::bridge_loop() {
    int decode_cpu = -1;
    int display_cpu = -1;
    xqc_resolve_pipeline_cpus(decode_cpu, display_cpu);
    (void)xqc_pin_current_thread(display_cpu >= 0 ? display_cpu : decode_cpu, "display-bridge");

    while (!_stop.load()) {
        XqcNv12Frame latest;
        bool have = false;
        while (xqc_h264_decode_try_pop_nv12(latest)) {
            have = true;
        }
        if (have && _gl) {
            _gl->submit_frame(std::move(latest));
            xqc_h264_decode_note_display_submit();
        }
        usleep(500);
    }
}

#else

XqcVideoDisplayPipeline::~XqcVideoDisplayPipeline() = default;

bool XqcVideoDisplayPipeline::start(XqcVideoReceiverOptions& opt, const char*) {
    if (opt.display) {
        std::fprintf(stderr, "[recv] built without GLFW; use --decode only or install libglfw3-dev\n");
        opt.display = false;
    }
    return false;
}

void XqcVideoDisplayPipeline::request_stop() {}
void XqcVideoDisplayPipeline::join() {}

#endif
