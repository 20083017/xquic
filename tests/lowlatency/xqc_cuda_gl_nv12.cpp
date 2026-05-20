/**
 * @file xqc_cuda_gl_nv12.cpp
 * @brief CUDA-GL interop for hevc_cuvid / h264_cuvid NV12 display (no hwdownload).
 */

#include "xqc_cuda_gl_nv12.hh"
#include "xqc_video_target.hh"

#if defined(XQC_HAVE_CUDA_GL)

#include <cuda_gl_interop.h>
#include <cuda_runtime.h>

extern "C" {
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
}

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <GL/gl.h>

#include <cstdio>
#include <cstring>

bool xqc_frame_to_nv12_cpu(const AVFrame* src, uint16_t camera_id, XqcNv12Frame& out);

namespace {

bool g_ok = false;
bool g_register_failed = false;
bool g_logged_register_fail = false;
bool g_logged_fallback = false;
int g_tex_w = 0;
int g_tex_h = 0;
GLuint g_tex_y = 0;
GLuint g_tex_uv = 0;
cudaGraphicsResource* g_res_y = nullptr;
cudaGraphicsResource* g_res_uv = nullptr;

bool check_cuda(cudaError_t err, const char* what, bool log = true) {
    if (err != cudaSuccess) {
        if (log) {
            std::fprintf(stderr, "[cuda-gl] %s failed: %s\n", what, cudaGetErrorString(err));
        }
        return false;
    }
    return true;
}

void destroy_gl_textures() {
    if (g_res_y) {
        cudaGraphicsUnregisterResource(g_res_y);
        g_res_y = nullptr;
    }
    if (g_res_uv) {
        cudaGraphicsUnregisterResource(g_res_uv);
        g_res_uv = nullptr;
    }
    if (g_tex_y) {
        glDeleteTextures(1, &g_tex_y);
        g_tex_y = 0;
    }
    if (g_tex_uv) {
        glDeleteTextures(1, &g_tex_uv);
        g_tex_uv = 0;
    }
    g_tex_w = 0;
    g_tex_h = 0;
}

bool ensure_textures(int w, int h) {
    if (w <= 0 || h <= 0) {
        return false;
    }
    if (g_register_failed) {
        return false;
    }
    if (g_tex_y && g_tex_uv && w == g_tex_w && h == g_tex_h) {
        return true;
    }
    destroy_gl_textures();

    /* GL_LUMINANCE / GL_LUMINANCE_ALPHA: supported by cudaGraphicsGLRegisterImage on
     * legacy NVIDIA interop (GL_R8/RG8 in core profile often fail with cudaErrorUnknown). */
    glGenTextures(1, &g_tex_y);
    glBindTexture(GL_TEXTURE_2D, g_tex_y);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_LUMINANCE, w, h, 0, GL_LUMINANCE, GL_UNSIGNED_BYTE, nullptr);

    glGenTextures(1, &g_tex_uv);
    glBindTexture(GL_TEXTURE_2D, g_tex_uv);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_LUMINANCE_ALPHA, w / 2, h / 2, 0, GL_LUMINANCE_ALPHA,
        GL_UNSIGNED_BYTE, nullptr);

    const bool log_once = !g_logged_register_fail;
    if (!check_cuda(cudaGraphicsGLRegisterImage(&g_res_y, g_tex_y, GL_TEXTURE_2D,
            cudaGraphicsRegisterFlagsWriteDiscard),
            "cudaGraphicsGLRegisterImage Y", log_once)) {
        g_register_failed = true;
        g_logged_register_fail = true;
        destroy_gl_textures();
        return false;
    }
    if (!check_cuda(cudaGraphicsGLRegisterImage(&g_res_uv, g_tex_uv, GL_TEXTURE_2D,
            cudaGraphicsRegisterFlagsWriteDiscard),
            "cudaGraphicsGLRegisterImage UV", log_once)) {
        g_register_failed = true;
        g_logged_register_fail = true;
        destroy_gl_textures();
        return false;
    }

    g_tex_w = w;
    g_tex_h = h;
    return true;
}

bool copy_plane(cudaGraphicsResource* res, const void* src, int src_pitch, int width_bytes, int height) {
    cudaArray_t array = nullptr;
    if (!check_cuda(cudaGraphicsMapResources(1, &res, 0), "cudaGraphicsMapResources")) {
        return false;
    }
    bool ok = check_cuda(cudaGraphicsSubResourceGetMappedArray(&array, res, 0, 0),
        "cudaGraphicsSubResourceGetMappedArray");
    if (ok) {
        ok = check_cuda(cudaMemcpy2DToArray(array, 0, 0, src, static_cast<std::size_t>(src_pitch),
                         static_cast<std::size_t>(width_bytes), static_cast<std::size_t>(height),
                         cudaMemcpyDeviceToDevice),
            "cudaMemcpy2DToArray");
    }
    if (!check_cuda(cudaGraphicsUnmapResources(1, &res, 0), "cudaGraphicsUnmapResources")) {
        ok = false;
    }
    return ok;
}

} // namespace

bool xqc_cuda_gl_nv12_init() {
    g_register_failed = false;
    g_logged_register_fail = false;
    g_logged_fallback = false;

    const char* gl_vendor = reinterpret_cast<const char*>(glGetString(GL_VENDOR));
    const char* gl_renderer = reinterpret_cast<const char*>(glGetString(GL_RENDERER));
    if (gl_renderer && std::strstr(gl_renderer, "NVIDIA") == nullptr) {
        std::fprintf(stderr,
            "[cuda-gl] OpenGL renderer is '%s' (%s) — CUDA-GL interop needs NVIDIA GLX on hybrid laptops.\n"
            "[cuda-gl]   export __GLX_VENDOR_LIBRARY_NAME=nvidia\n",
            gl_renderer ? gl_renderer : "?",
            gl_vendor ? gl_vendor : "?");
    }

    int device_count = 0;
    if (!check_cuda(cudaGetDeviceCount(&device_count), "cudaGetDeviceCount") || device_count <= 0) {
        return false;
    }
    if (!check_cuda(cudaSetDevice(0), "cudaSetDevice")) {
        return false;
    }

    if (!ensure_textures(XQC_VIDEO_TARGET_WIDTH, XQC_VIDEO_TARGET_HEIGHT)) {
        g_ok = false;
        std::fprintf(stderr,
            "[cuda-gl] texture register probe failed %dx%d — hwdownload+PBO fallback on display",
            XQC_VIDEO_TARGET_WIDTH, XQC_VIDEO_TARGET_HEIGHT);
        if (gl_renderer && std::strstr(gl_renderer, "NVIDIA") == nullptr) {
            std::fprintf(stderr, " (set __GLX_VENDOR_LIBRARY_NAME=nvidia on hybrid GPU systems)");
        }
        std::fprintf(stderr, "\n");
        return false;
    }

    g_ok = true;
    std::fprintf(stderr,
        "[cuda-gl] NV12 interop ready %dx%d (NVDEC → GL LUMINANCE/LA, no hwdownload)\n",
        XQC_VIDEO_TARGET_WIDTH, XQC_VIDEO_TARGET_HEIGHT);
    return true;
}

void xqc_cuda_gl_nv12_shutdown() {
    destroy_gl_textures();
    g_ok = false;
    g_register_failed = false;
}

bool xqc_cuda_gl_nv12_available() {
    return g_ok;
}

bool xqc_cuda_gl_nv12_uses_luminance_alpha_uv() {
    return g_ok;
}

bool xqc_cuda_gl_nv12_upload_nv12(const XqcNv12Frame& frame) {
    if (!g_ok || frame.backing != XqcNv12Backing::CudaGl || !frame.cuda_frame) {
        return false;
    }
    auto* avf = static_cast<AVFrame*>(frame.cuda_frame);
    if (avf->format != AV_PIX_FMT_CUDA || !avf->data[0] || !avf->data[1]) {
        return false;
    }
    const int w = avf->width;
    const int h = avf->height;
    if (!ensure_textures(w, h)) {
        return false;
    }

    const int pitch_y = avf->linesize[0];
    const int pitch_uv = avf->linesize[1];
    const bool ok_y = copy_plane(g_res_y, avf->data[0], pitch_y, w, h);
    const bool ok_uv = copy_plane(g_res_uv, avf->data[1], pitch_uv, w, h / 2);
    return ok_y && ok_uv;
}

bool xqc_cuda_gl_nv12_fallback_to_cpu(XqcNv12Frame& frame) {
    if (frame.backing != XqcNv12Backing::CudaGl || !frame.cuda_frame) {
        return false;
    }
    if (!g_logged_fallback) {
        g_logged_fallback = true;
        std::fprintf(stderr, "[cuda-gl] falling back to hwdownload + PBO upload for display\n");
    }

    auto* avf = static_cast<AVFrame*>(frame.cuda_frame);
    AVFrame* sw = av_frame_alloc();
    if (!sw) {
        return false;
    }
    if (av_hwframe_transfer_data(sw, avf, 0) < 0) {
        av_frame_free(&sw);
        return false;
    }

    const uint16_t camera_id = frame.camera_id;
    const int64_t pts_us = frame.pts_us;
    const uint64_t recv_us = frame.recv_us;
    const uint64_t decode_us = frame.decode_us;
    const bool from_stream = frame.from_stream;

    av_frame_free(reinterpret_cast<AVFrame**>(&frame.cuda_frame));
    frame.cuda_frame = nullptr;

    if (!xqc_frame_to_nv12_cpu(sw, camera_id, frame)) {
        av_frame_free(&sw);
        return false;
    }
    frame.pts_us = pts_us;
    frame.recv_us = recv_us;
    frame.decode_us = decode_us;
    frame.from_stream = from_stream;
    av_frame_free(&sw);
    return true;
}

unsigned int xqc_cuda_gl_nv12_tex_y() {
    return g_tex_y;
}

unsigned int xqc_cuda_gl_nv12_tex_uv() {
    return g_tex_uv;
}

#else

bool xqc_cuda_gl_nv12_init() { return false; }
void xqc_cuda_gl_nv12_shutdown() {}
bool xqc_cuda_gl_nv12_upload_nv12(const XqcNv12Frame&) { return false; }
bool xqc_cuda_gl_nv12_available() { return false; }
bool xqc_cuda_gl_nv12_uses_luminance_alpha_uv() { return false; }
bool xqc_cuda_gl_nv12_fallback_to_cpu(XqcNv12Frame&) { return false; }
unsigned int xqc_cuda_gl_nv12_tex_y() { return 0; }
unsigned int xqc_cuda_gl_nv12_tex_uv() { return 0; }

#endif
