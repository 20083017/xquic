#pragma once

#include "xqc_nv12_frame.hh"

#include <atomic>
#include <mutex>
#include <thread>

/**
 * @class XqcNv12GlLinux
 * @brief Dedicated GLFW thread: CPU NV12 → GPU textures → fullscreen quad (WSLg / Linux).
 *
 * **GPU usage summary** (Linux/WSL path):
 * 1. CPU holds decoded NV12 in `XqcNv12Frame::data`.
 * 2. `glMapBufferRange` on a **PIXEL_UNPACK_BUFFER** (dual PBO ping-pong) — DMA-style upload to VRAM.
 * 3. `glTexSubImage2D` from PBO into **R8** (Y) and **RG8** (UV) textures (no CPU→texture direct path).
 * 4. Fragment shader converts YUV (BT.709) to RGB; `glDrawArrays` fills the framebuffer.
 * 5. `glfwSwapBuffers` presents; `display_us` is sampled and fed to `xqc_e2e_latency_hist()`.
 *
 * Window is created at **4K** dimensions (`XQC_VIDEO_TARGET_*`) so reviewers can validate UHD PBO sizing;
 * smaller streams are scaled to the framebuffer via viewport + textured quad.
 */
class XqcNv12GlLinux {
public:
    XqcNv12GlLinux() = default;
    ~XqcNv12GlLinux();

    bool start(int initial_width, int initial_height, const char* title);
    void stop();
    void request_stop();

    /** Latest-wins: only the most recent frame is kept until the GL thread consumes it. */
    void submit_frame(XqcNv12Frame frame);

    bool running() const { return _running.load(); }

private:
    void thread_main();

    std::thread _thread;
    std::atomic<bool> _running{false};
    std::atomic<bool> _stop{false};
    int _init_w = 640;
    int _init_h = 480;
    const char* _title = "xqc_nv12";

    std::mutex _frame_mu;
    XqcNv12Frame _pending;
    bool _has_pending = false;
};
