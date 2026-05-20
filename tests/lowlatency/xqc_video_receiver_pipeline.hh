/**
 * @file xqc_video_receiver_pipeline.hh
 * @brief Shared decode / display / CUDA-GL pipeline for video receivers (Seastar + libevent).
 */

#pragma once

#include "xqc_video_codec.hh"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

#ifdef __cplusplus
extern "C" {
#endif
typedef struct user_stream_s user_stream_t;
#ifdef __cplusplus
}
#endif

/** CLI/runtime options shared by libevent and Seastar receivers. */
struct XqcVideoReceiverOptions {
    uint16_t port = 8443;
    std::string cert_path = "tests/server.crt";
    std::string key_path = "tests/server.key";
    std::string video_dir = "./video_out";
    bool decode = false;
    bool display = false;
    bool stream_decode = true;
    bool eos_file_decode = true;
    std::string hw_decode_mode;
    XqcVideoCodec stream_codec = XqcVideoCodec::HEVC;
};

/** Grow stream reassembly buffer (shared by both reactor backends). */
bool xqc_video_receiver_ensure_recv_cap(user_stream_t* us, std::size_t extra);

/** Apply NVIDIA Prime env before GLFW when cuda/auto hw decode + display. */
void xqc_video_receiver_apply_nvidia_prime(const XqcVideoReceiverOptions& opt);

/** Start FFmpeg decode worker (idempotent with worker_start internals). */
void xqc_video_receiver_start_decode(const XqcVideoReceiverOptions& opt);

/**
 * Owns GL window + display-bridge thread (latest NV12 frame wins).
 * Off-reactor; safe to use from Seastar shard 0 startup/shutdown.
 */
class XqcVideoDisplayPipeline {
public:
    XqcVideoDisplayPipeline() = default;
    ~XqcVideoDisplayPipeline();

    XqcVideoDisplayPipeline(const XqcVideoDisplayPipeline&) = delete;
    XqcVideoDisplayPipeline& operator=(const XqcVideoDisplayPipeline&) = delete;

    /** Returns false and clears opt.display when DISPLAY/GLFW unavailable. */
    bool start(XqcVideoReceiverOptions& opt, const char* window_title);

    void request_stop();
    void join();

    bool active() const { return _active; }

private:
    void bridge_loop();

    std::atomic<bool> _stop{false};
    bool _active = false;
    std::thread _bridge;
#if defined(XQC_HAVE_GLFW)
    class XqcNv12GlLinux* _gl = nullptr;
#endif
};

/** Start display (GL/CUDA-GL first) then decode worker — required init order for NVDEC interop. */
void xqc_video_receiver_boot_pipeline(XqcVideoReceiverOptions& opt, XqcVideoDisplayPipeline& display,
    const char* window_title);

/** Periodic stderr stats + optional E2E histogram. */
void xqc_video_receiver_log_stats(const XqcVideoReceiverOptions& opt);

void xqc_video_receiver_log_e2e_final(const XqcVideoReceiverOptions& opt);

void xqc_video_receiver_stop_decode();
