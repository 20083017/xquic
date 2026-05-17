/**
 * @file xqc_gl_egl_dma.cpp
 * @brief EGL_EXT_image_dma_buf_import → GL_TEXTURE_2D (NV12 Y + UV planes).
 */

#include "xqc_gl_egl_dma.hh"

#if defined(XQC_HAVE_GLFW) && defined(XQC_HAVE_HW_DECODE)

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <drm_fourcc.h>

#include <cstdio>
#include <cstring>

#ifndef EGL_LINUX_DMA_BUF_EXT
#define EGL_LINUX_DMA_BUF_EXT 0x3270
#endif
#ifndef EGL_LINUX_DRM_FOURCC_EXT
#define EGL_LINUX_DRM_FOURCC_EXT 0x3271
#endif
#ifndef EGL_DMA_BUF_PLANE0_FD_EXT
#define EGL_DMA_BUF_PLANE0_FD_EXT 0x3272
#endif
#ifndef EGL_DMA_BUF_PLANE0_OFFSET_EXT
#define EGL_DMA_BUF_PLANE0_OFFSET_EXT 0x3273
#endif
#ifndef EGL_DMA_BUF_PLANE0_PITCH_EXT
#define EGL_DMA_BUF_PLANE0_PITCH_EXT 0x3274
#endif
#ifndef EGL_DMA_BUF_PLANE1_FD_EXT
#define EGL_DMA_BUF_PLANE1_FD_EXT 0x3275
#endif
#ifndef EGL_DMA_BUF_PLANE1_OFFSET_EXT
#define EGL_DMA_BUF_PLANE1_OFFSET_EXT 0x3276
#endif
#ifndef EGL_DMA_BUF_PLANE1_PITCH_EXT
#define EGL_DMA_BUF_PLANE1_PITCH_EXT 0x3277
#endif
#ifndef EGL_NO_IMAGE_KHR
#define EGL_NO_IMAGE_KHR static_cast<EGLImageKHR>(0)
#endif
#ifndef GL_TEXTURE_2D
#define GL_TEXTURE_2D 0x0DE1
#endif

typedef void (*PFNGLBINDTEXTUREPROC)(unsigned int, unsigned int);
typedef void (*PFNGLGENTEXTURESPROC)(int, unsigned int*);
typedef void (*PFNGLEGLIMAGETARGETTEXTURE2DOESPROC)(unsigned int, void*);
typedef EGLImageKHR (*PFNEGLCREATEIMAGEKHRPROC)(EGLDisplay, EGLContext, EGLenum, EGLClientBuffer,
    const EGLint*);
typedef EGLBoolean (*PFNEGLDESTROYIMAGEKHRPROC)(EGLDisplay, EGLImageKHR);

static EGLDisplay g_egl_dpy = EGL_NO_DISPLAY;
static PFNGLEGLIMAGETARGETTEXTURE2DOESPROC g_glEGLImageTargetTexture2DOES = nullptr;
static PFNGLBINDTEXTUREPROC p_glBindTexture = nullptr;
static PFNGLGENTEXTURESPROC p_glGenTextures = nullptr;
static PFNEGLCREATEIMAGEKHRPROC p_eglCreateImageKHR = nullptr;
static PFNEGLDESTROYIMAGEKHRPROC p_eglDestroyImageKHR = nullptr;

static unsigned int g_tex_y = 0;
static unsigned int g_tex_uv = 0;
static EGLImageKHR g_img_y = EGL_NO_IMAGE_KHR;
static EGLImageKHR g_img_uv = EGL_NO_IMAGE_KHR;
static bool g_ok = false;

static EGLImageKHR create_plane_image(int fd, int w, int h, int offset, int pitch, uint32_t fourcc) {
    if (!p_eglCreateImageKHR) {
        return EGL_NO_IMAGE_KHR;
    }
    const EGLint attribs[] = {
        EGL_WIDTH, w,
        EGL_HEIGHT, h,
        EGL_LINUX_DRM_FOURCC_EXT, static_cast<EGLint>(fourcc),
        EGL_DMA_BUF_PLANE0_FD_EXT, fd,
        EGL_DMA_BUF_PLANE0_OFFSET_EXT, offset,
        EGL_DMA_BUF_PLANE0_PITCH_EXT, pitch,
        EGL_NONE,
    };
    return p_eglCreateImageKHR(g_egl_dpy, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, nullptr, attribs);
}

static void destroy_images() {
    if (!p_eglDestroyImageKHR) {
        return;
    }
    if (g_img_y != EGL_NO_IMAGE_KHR) {
        p_eglDestroyImageKHR(g_egl_dpy, g_img_y);
        g_img_y = EGL_NO_IMAGE_KHR;
    }
    if (g_img_uv != EGL_NO_IMAGE_KHR) {
        p_eglDestroyImageKHR(g_egl_dpy, g_img_uv);
        g_img_uv = EGL_NO_IMAGE_KHR;
    }
}

bool xqc_gl_egl_dma_init(GLFWwindow* win) {
    (void)win;
    g_egl_dpy = eglGetCurrentDisplay();
    if (g_egl_dpy == EGL_NO_DISPLAY) {
        std::fprintf(stderr, "[egl] eglGetCurrentDisplay failed (GLFW_EGL_CONTEXT_API + makeCurrent first)\n");
        return false;
    }

    p_eglCreateImageKHR = reinterpret_cast<PFNEGLCREATEIMAGEKHRPROC>(
        eglGetProcAddress("eglCreateImageKHR"));
    p_eglDestroyImageKHR = reinterpret_cast<PFNEGLDESTROYIMAGEKHRPROC>(
        eglGetProcAddress("eglDestroyImageKHR"));
    if (!p_eglCreateImageKHR || !p_eglDestroyImageKHR) {
        std::fprintf(stderr, "[egl] eglCreateImageKHR / eglDestroyImageKHR not available\n");
        return false;
    }

    const char* exts = eglQueryString(g_egl_dpy, EGL_EXTENSIONS);
    if (!exts || !strstr(exts, "EGL_EXT_image_dma_buf_import")) {
        std::fprintf(stderr, "[egl] EGL_EXT_image_dma_buf_import missing\n");
        return false;
    }

    g_glEGLImageTargetTexture2DOES = reinterpret_cast<PFNGLEGLIMAGETARGETTEXTURE2DOESPROC>(
        eglGetProcAddress("glEGLImageTargetTexture2DOES"));
    p_glBindTexture = reinterpret_cast<PFNGLBINDTEXTUREPROC>(eglGetProcAddress("glBindTexture"));
    p_glGenTextures = reinterpret_cast<PFNGLGENTEXTURESPROC>(eglGetProcAddress("glGenTextures"));
    if (!g_glEGLImageTargetTexture2DOES || !p_glBindTexture || !p_glGenTextures) {
        std::fprintf(stderr, "[egl] GL EGLImage entry points missing\n");
        return false;
    }
    if (!g_tex_y) {
        p_glGenTextures(1, &g_tex_y);
        p_glGenTextures(1, &g_tex_uv);
    }
    g_ok = true;
    std::fprintf(stderr, "[egl] dma-buf import ready (zero-copy NV12)\n");
    return true;
}

void xqc_gl_egl_dma_shutdown() {
    destroy_images();
    g_ok = false;
}

bool xqc_gl_egl_dma_available() {
    return g_ok;
}

bool xqc_gl_egl_dma_upload_nv12(const XqcNv12Frame& frame) {
    if (!g_ok || frame.backing != XqcNv12Backing::VaapiDmaBuf || frame.dma_fd < 0) {
        return false;
    }
    const int w = frame.width;
    const int h = frame.height;
    const int pitch = static_cast<int>(frame.dma_stride);
    const int fd = frame.dma_fd;

    destroy_images();

    g_img_y = create_plane_image(fd, w, h, static_cast<int>(frame.dma_offset_y), pitch, DRM_FORMAT_R8);
    g_img_uv = create_plane_image(fd, w / 2, h / 2, static_cast<int>(frame.dma_offset_uv), pitch,
        DRM_FORMAT_GR88);

    if (g_img_y == EGL_NO_IMAGE_KHR || g_img_uv == EGL_NO_IMAGE_KHR) {
        std::fprintf(stderr, "[egl] eglCreateImageKHR failed\n");
        destroy_images();
        return false;
    }

    p_glBindTexture(GL_TEXTURE_2D, g_tex_y);
    g_glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, g_img_y);
    p_glBindTexture(GL_TEXTURE_2D, g_tex_uv);
    g_glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, g_img_uv);
    return true;
}

unsigned int xqc_gl_egl_tex_y() {
    return g_tex_y;
}

unsigned int xqc_gl_egl_tex_uv() {
    return g_tex_uv;
}

#else

bool xqc_gl_egl_dma_init(void*) { return false; }
void xqc_gl_egl_dma_shutdown() {}
bool xqc_gl_egl_dma_available() { return false; }
bool xqc_gl_egl_dma_upload_nv12(const XqcNv12Frame&) { return false; }
unsigned int xqc_gl_egl_tex_y() { return 0; }
unsigned int xqc_gl_egl_tex_uv() { return 0; }

#endif
