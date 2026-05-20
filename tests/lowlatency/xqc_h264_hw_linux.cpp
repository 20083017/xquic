/**
 * @file xqc_h264_hw_linux.cpp
 * @brief VAAPI / CUDA hardware decode helpers (Linux only).
 */

#include "xqc_h264_hw_linux.hh"
#include "xqc_video_target.hh"

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#if defined(XQC_HAVE_FFMPEG) && defined(XQC_HAVE_HW_DECODE)

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <libavutil/hwcontext_vaapi.h>
#include <libavutil/opt.h>
#include <libavutil/pixdesc.h>
}

#include <va/va.h>
#include <va/va_drmcommon.h>

/* Defined in xqc_h264_ff_decode_worker.cpp (CPU NV12 pack / swscale). */
bool xqc_frame_to_nv12_cpu(const AVFrame* src, uint16_t camera_id, XqcNv12Frame& out);

namespace {

XqcHwDecodeBackend g_requested = XqcHwDecodeBackend::Off;
XqcHwDecodeBackend g_active = XqcHwDecodeBackend::Software;
AVBufferRef* g_hw_device = nullptr;
char g_va_path[256] = "/dev/dri/renderD128";

XqcHwDecodeBackend parse_mode(const char* s) {
    if (!s || !s[0]) {
        return XqcHwDecodeBackend::Off;
    }
    if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) {
        return XqcHwDecodeBackend::Off;
    }
    if (strcmp(s, "auto") == 0 || strcmp(s, "1") == 0) {
        return XqcHwDecodeBackend::Auto;
    }
    if (strcmp(s, "vaapi") == 0 || strcmp(s, "va") == 0) {
        return XqcHwDecodeBackend::Vaapi;
    }
    if (strcmp(s, "cuda") == 0 || strcmp(s, "nvdec") == 0) {
        return XqcHwDecodeBackend::Cuda;
    }
    return XqcHwDecodeBackend::Off;
}

bool try_vaapi() {
    AVBufferRef* dev = nullptr;
    const int err = av_hwdevice_ctx_create(&dev, AV_HWDEVICE_TYPE_VAAPI, g_va_path, nullptr, 0);
    if (err < 0 || !dev) {
        std::fprintf(stderr, "[hw] VAAPI create failed on %s (%d)\n", g_va_path, err);
        return false;
    }
    g_hw_device = dev;
    g_active = XqcHwDecodeBackend::Vaapi;
    std::fprintf(stderr, "[hw] VAAPI ready device=%s (4K frames ctx %dx%d)\n",
        g_va_path, XQC_VIDEO_TARGET_WIDTH, XQC_VIDEO_TARGET_HEIGHT);
    return true;
}

bool try_cuda() {
    AVBufferRef* dev = nullptr;
    const int err = av_hwdevice_ctx_create(&dev, AV_HWDEVICE_TYPE_CUDA, nullptr, nullptr, 0);
    if (err < 0 || !dev) {
        std::fprintf(stderr, "[hw] CUDA/NVDEC device create failed (%d)\n", err);
        return false;
    }
    const AVCodec* h264 = avcodec_find_decoder_by_name("h264_cuvid");
    const AVCodec* hevc = avcodec_find_decoder_by_name("hevc_cuvid");
    if (!h264 && !hevc) {
        std::fprintf(stderr, "[hw] h264_cuvid/hevc_cuvid missing (FFmpeg without nvcodec)\n");
        av_buffer_unref(&dev);
        return false;
    }
    g_hw_device = dev;
    g_active = XqcHwDecodeBackend::Cuda;
    std::fprintf(stderr, "[hw] CUDA/NVDEC ready h264=%s hevc=%s (NV12 CUDA-GL interop, no hwdownload)\n",
        h264 ? "yes" : "no", hevc ? "yes" : "no");
    return true;
}

bool alloc_vaapi_frames(AVCodecContext* ctx) {
    if (!g_hw_device) {
        return false;
    }
    ctx->hw_device_ctx = av_buffer_ref(g_hw_device);
    ctx->get_format = [](AVCodecContext*, const AVPixelFormat* fmts) -> AVPixelFormat {
        for (const AVPixelFormat* p = fmts; *p != AV_PIX_FMT_NONE; ++p) {
            if (*p == AV_PIX_FMT_VAAPI) {
                return AV_PIX_FMT_VAAPI;
            }
        }
        return fmts[0];
    };

    AVBufferRef* frames_ref = av_hwframe_ctx_alloc(g_hw_device);
    if (!frames_ref) {
        return false;
    }
    auto* frames = reinterpret_cast<AVHWFramesContext*>(frames_ref->data);
    frames->format = AV_PIX_FMT_VAAPI;
    frames->sw_format = AV_PIX_FMT_NV12;
    frames->width = XQC_VIDEO_TARGET_WIDTH;
    frames->height = XQC_VIDEO_TARGET_HEIGHT;
    if (av_hwframe_ctx_init(frames_ref) < 0) {
        av_buffer_unref(&frames_ref);
        return false;
    }
    ctx->hw_frames_ctx = frames_ref;
    return true;
}

bool vaapi_export_dmabuf(AVFrame* frame, XqcNv12Frame& out, uint16_t camera_id) {
    if (!frame->hw_frames_ctx) {
        return false;
    }
    auto* hwfc = reinterpret_cast<AVHWFramesContext*>(frame->hw_frames_ctx->data);
    auto* vactx = reinterpret_cast<AVVAAPIDeviceContext*>(hwfc->device_ctx->hwctx);
    const VADisplay dpy = vactx->display;
    const auto surf = static_cast<VASurfaceID>(reinterpret_cast<uintptr_t>(frame->data[3]));

    VADRMPRIMESurfaceDescriptor desc{};
    const VAStatus st = vaExportSurfaceHandle(dpy, surf, VA_SURFACE_ATTRIB_MEM_TYPE_DRM_PRIME_2,
        VA_EXPORT_SURFACE_READ_ONLY, &desc);
    if (st != VA_STATUS_SUCCESS || desc.num_objects < 1 || desc.num_layers < 2) {
        return false;
    }

    const int fd = static_cast<int>(desc.objects[0].fd);
    if (fd < 0) {
        return false;
    }
    const int owned_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (owned_fd < 0) {
        return false;
    }

    out.camera_id = camera_id;
    out.width = frame->width;
    out.height = frame->height;
    out.backing = XqcNv12Backing::VaapiDmaBuf;
    out.data.clear();
    out.dma_fd = owned_fd;
    out.dma_stride = desc.layers[0].pitch[0];
    out.dma_offset_y = desc.layers[0].offset[0];
    out.dma_offset_uv = desc.layers[1].offset[0];
    return true;
}

bool cuda_to_gl_nv12(AVFrame* frame, XqcNv12Frame& out, uint16_t camera_id) {
    if (!frame || frame->format != AV_PIX_FMT_CUDA) {
        return false;
    }
    AVFrame* held = av_frame_alloc();
    if (!held) {
        return false;
    }
    if (av_frame_ref(held, frame) < 0) {
        av_frame_free(&held);
        return false;
    }
    out.camera_id = camera_id;
    out.width = frame->width;
    out.height = frame->height;
    out.backing = XqcNv12Backing::CudaGl;
    out.data.clear();
    out.cuda_frame = held;
    return true;
}

bool prefer_cuda_first_for_auto() {
#if defined(__linux__)
    const char* wsl = getenv("WSL_DISTRO_NAME");
    if (!wsl || !wsl[0]) {
        return false;
    }
    return access("/dev/nvidia0", F_OK) == 0 || access("/dev/dxg", F_OK) == 0;
#else
    return false;
#endif
}

} // namespace

void xqc_h264_hw_configure(const char* mode_override) {
    const char* env = getenv("XQC_HW_DECODE");
    const char* va = getenv("XQC_VA_DEVICE");
    if (va && va[0]) {
        std::snprintf(g_va_path, sizeof(g_va_path), "%s", va);
    }
    const char* mode = mode_override && mode_override[0] ? mode_override : env;
    g_requested = parse_mode(mode);
}

XqcHwDecodeBackend xqc_h264_hw_init() {
    if (g_hw_device) {
        av_buffer_unref(&g_hw_device);
        g_hw_device = nullptr;
    }
    g_active = XqcHwDecodeBackend::Software;

    if (g_requested == XqcHwDecodeBackend::Off) {
        return g_active;
    }

    if (g_requested == XqcHwDecodeBackend::Auto && prefer_cuda_first_for_auto()) {
        if (try_cuda()) {
            return g_active;
        }
        if (try_vaapi()) {
            return g_active;
        }
    } else {
        if ((g_requested == XqcHwDecodeBackend::Auto || g_requested == XqcHwDecodeBackend::Vaapi) && try_vaapi()) {
            return g_active;
        }
        if ((g_requested == XqcHwDecodeBackend::Auto || g_requested == XqcHwDecodeBackend::Cuda) && try_cuda()) {
            return g_active;
        }
    }
    if (g_requested != XqcHwDecodeBackend::Off && g_requested != XqcHwDecodeBackend::Auto) {
        std::fprintf(stderr, "[hw] requested backend unavailable, falling back to software\n");
    }
    std::fprintf(stderr, "[hw] using software H.264/HEVC decode\n");
    return XqcHwDecodeBackend::Software;
}

XqcHwDecodeBackend xqc_h264_hw_active_backend() {
    return g_active;
}

bool xqc_h264_hw_display_use_egl() {
    return g_active == XqcHwDecodeBackend::Vaapi
        || g_requested == XqcHwDecodeBackend::Vaapi;
}

bool xqc_h264_hw_display_use_cuda_gl() {
#if defined(XQC_HAVE_CUDA_GL)
    return g_active == XqcHwDecodeBackend::Cuda
        || g_requested == XqcHwDecodeBackend::Cuda;
#else
    return false;
#endif
}

const char* xqc_h264_hw_backend_name() {
    switch (g_active) {
    case XqcHwDecodeBackend::Vaapi:
        return "vaapi+egl";
    case XqcHwDecodeBackend::Cuda:
#if defined(XQC_HAVE_CUDA_GL)
        return "cuda+gl";
#else
        return "cuda+pbo";
#endif
    case XqcHwDecodeBackend::Software:
        return "software";
    default:
        return "off";
    }
}

AVBufferRef* xqc_h264_hw_device_ctx() {
    return g_hw_device;
}

bool xqc_h264_hw_open_decoder(AVCodecContext* ctx, const AVCodec*& out_codec, XqcVideoCodec codec) {
    if (!ctx) {
        return false;
    }
    const bool hevc = (codec == XqcVideoCodec::HEVC);
    if (g_active == XqcHwDecodeBackend::Vaapi) {
        out_codec = avcodec_find_decoder_by_name(hevc ? "hevc_vaapi" : "h264_vaapi");
        if (!out_codec) {
            std::fprintf(stderr, "[hw] %s_vaapi not found\n", hevc ? "hevc" : "h264");
            return false;
        }
        if (!alloc_vaapi_frames(ctx)) {
            return false;
        }
        ctx->thread_count = 1;
        return avcodec_open2(ctx, out_codec, nullptr) >= 0;
    }
    if (g_active == XqcHwDecodeBackend::Cuda) {
        out_codec = avcodec_find_decoder_by_name(hevc ? "hevc_cuvid" : "h264_cuvid");
        if (!out_codec) {
            std::fprintf(stderr, "[hw] %s_cuvid not found\n", hevc ? "hevc" : "h264");
            return false;
        }
        ctx->hw_device_ctx = av_buffer_ref(g_hw_device);
        ctx->thread_count = 1;
        ctx->max_b_frames = 0;
        ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
        ctx->extra_hw_frames = 0;
        if (avcodec_open2(ctx, out_codec, nullptr) < 0) {
            return false;
        }
        std::fprintf(stderr, "[hw] cuvid low-delay: max_b_frames=0 LOW_DELAY extra_hw_frames=0\n");
        return true;
    }
    out_codec = avcodec_find_decoder(xqc_video_codec_av_id(codec));
    if (!out_codec) {
        return false;
    }
    ctx->thread_count = 1;
    ctx->max_b_frames = 0;
    ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
    return avcodec_open2(ctx, out_codec, nullptr) >= 0;
}

bool xqc_h264_hw_frame_to_output(AVFrame* frame, XqcNv12Frame& out, uint16_t camera_id) {
    if (!frame) {
        return false;
    }
    if (g_active == XqcHwDecodeBackend::Vaapi && frame->format == AV_PIX_FMT_VAAPI) {
        return vaapi_export_dmabuf(frame, out, camera_id);
    }
    if (g_active == XqcHwDecodeBackend::Cuda && frame->format == AV_PIX_FMT_CUDA) {
#if defined(XQC_HAVE_CUDA_GL)
        return cuda_to_gl_nv12(frame, out, camera_id);
#else
        std::fprintf(stderr, "[hw] CUDA frame without XQC_HAVE_CUDA_GL — build with CUDAToolkit\n");
        return false;
#endif
    }
    if (frame->format == AV_PIX_FMT_NV12 || frame->format == AV_PIX_FMT_YUV420P) {
        return xqc_frame_to_nv12_cpu(frame, camera_id, out);
    }
    return false;
}

void xqc_nv12_frame_release(XqcNv12Frame& f) {
    if (f.backing == XqcNv12Backing::CudaGl && f.cuda_frame) {
        av_frame_free(reinterpret_cast<AVFrame**>(&f.cuda_frame));
        f.cuda_frame = nullptr;
    }
    if (f.dma_fd >= 0) {
        close(f.dma_fd);
        f.dma_fd = -1;
    }
    f.data.clear();
}

#else

void xqc_h264_hw_configure(const char*) {}
XqcHwDecodeBackend xqc_h264_hw_init() { return XqcHwDecodeBackend::Software; }
XqcHwDecodeBackend xqc_h264_hw_active_backend() { return XqcHwDecodeBackend::Software; }
bool xqc_h264_hw_display_use_egl() { return false; }
bool xqc_h264_hw_display_use_cuda_gl() { return false; }
const char* xqc_h264_hw_backend_name() { return "software"; }
bool xqc_h264_hw_open_decoder(AVCodecContext*, const AVCodec*&, XqcVideoCodec) { return false; }
bool xqc_h264_hw_frame_to_output(AVFrame*, XqcNv12Frame&, uint16_t) { return false; }
void xqc_nv12_frame_release(XqcNv12Frame&) {}
AVBufferRef* xqc_h264_hw_device_ctx() { return nullptr; }

#endif
