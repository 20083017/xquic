/**
 * @file xqc_nv12_gl_linux.cpp
 * @brief Linux/WSL display path — OpenGL 3.3 NV12 upload via dual PBO + shader compositing.
 *
 * See class comment in `xqc_nv12_gl_linux.hh` for the CPU/GPU split. This file intentionally
 * does **not** use CUDA/NVDEC/VAAPI: decoding happens in `xqc_h264_ff_decode_worker.cpp`.
 */

#include "xqc_nv12_gl_linux.hh"

#include "xqc_e2e_latency.hh"
#include "xqc_pbo_dynamic_manager.hh"
#include "xqc_video_target.hh"
#if defined(XQC_HAVE_HW_DECODE)
#include "xqc_gl_egl_dma.hh"
#include "xqc_h264_hw_linux.hh"
#include "xqc_nvidia_prime_env.hh"
#include "xqc_thread_affinity.hh"
#if defined(XQC_HAVE_CUDA_GL)
#include "xqc_cuda_gl_nv12.hh"
#endif
#endif

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <GL/gl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef GL_R8
#define GL_R8 0x8229
#endif
#ifndef GL_RG8
#define GL_RG8 0x822B
#endif
#ifndef GL_RED
#define GL_RED 0x1903
#endif
#ifndef GL_RG
#define GL_RG 0x8227
#endif
#ifndef GL_PIXEL_UNPACK_BUFFER
#define GL_PIXEL_UNPACK_BUFFER 0x88EC
#endif
#ifndef GL_STREAM_DRAW
#define GL_STREAM_DRAW 0x88E0
#endif
#ifndef GL_MAP_WRITE_BIT
#define GL_MAP_WRITE_BIT 0x0002
#endif
#ifndef GL_MAP_INVALIDATE_BUFFER_BIT
#define GL_MAP_INVALIDATE_BUFFER_BIT 0x0008
#endif
#ifndef GL_UNPACK_ROW_LENGTH
#define GL_UNPACK_ROW_LENGTH 0x0CF2
#endif

using GLsizeiptr = ptrdiff_t;
using GLintptr = ptrdiff_t;
using GLbitfield = unsigned int;

typedef void (*PFNGLGenTextures)(GLsizei, GLuint*);
typedef void (*PFNGLBindTexture)(GLenum, GLuint);
typedef void (*PFNGLTexParameteri)(GLenum, GLenum, GLint);
typedef void (*PFNGLTexStorage2D)(GLenum, GLsizei, GLenum, GLsizei, GLsizei);
typedef void (*PFNGLActiveTexture)(GLenum);
typedef void (*PFNGLPixelStorei)(GLenum, GLint);
typedef void (*PFNGLTexSubImage2D)(GLenum, GLint, GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, const void*);
typedef void (*PFNGLGenBuffers)(GLsizei, GLuint*);
typedef void (*PFNGLBindBuffer)(GLenum, GLuint);
typedef void (*PFNGLBufferData)(GLenum, GLsizeiptr, const void*, GLenum);
typedef void* (*PFNGLMapBufferRange)(GLenum, GLintptr, GLsizeiptr, GLbitfield);
typedef GLboolean (*PFNGLUnmapBuffer)(GLenum);
typedef GLuint (*PFNGLCreateShader)(GLenum);
typedef void (*PFNGLShaderSource)(GLuint, GLsizei, const char* const*, const GLint*);
typedef void (*PFNGLCompileShader)(GLuint);
typedef void (*PFNGLGetShaderiv)(GLuint, GLenum, GLint*);
typedef GLuint (*PFNGLCreateProgram)(void);
typedef void (*PFNGLAttachShader)(GLuint, GLuint);
typedef void (*PFNGLLinkProgram)(GLuint);
typedef void (*PFNGLGetProgramiv)(GLuint, GLenum, GLint*);
typedef void (*PFNGLUseProgram)(GLuint);
typedef GLint (*PFNGLGetUniformLocation)(GLuint, const char*);
typedef void (*PFNGLUniform1i)(GLint, GLint);
typedef void (*PFNGLGenVertexArrays)(GLsizei, GLuint*);
typedef void (*PFNGLBindVertexArray)(GLuint);
typedef void (*PFNGLEnableVertexAttribArray)(GLuint);
typedef void (*PFNGLVertexAttribPointer)(GLuint, GLint, GLenum, GLboolean, GLsizei, const void*);
typedef void (*PFNGLDrawArrays)(GLenum, GLint, GLsizei);

#define GL_PROC(type, name) static type p_##name = nullptr

GL_PROC(PFNGLGenTextures, glGenTextures);
GL_PROC(PFNGLBindTexture, glBindTexture);
GL_PROC(PFNGLTexParameteri, glTexParameteri);
GL_PROC(PFNGLTexStorage2D, glTexStorage2D);
GL_PROC(PFNGLActiveTexture, glActiveTexture);
GL_PROC(PFNGLPixelStorei, glPixelStorei);
GL_PROC(PFNGLTexSubImage2D, glTexSubImage2D);
GL_PROC(PFNGLGenBuffers, glGenBuffers);
GL_PROC(PFNGLBindBuffer, glBindBuffer);
GL_PROC(PFNGLBufferData, glBufferData);
GL_PROC(PFNGLMapBufferRange, glMapBufferRange);
GL_PROC(PFNGLUnmapBuffer, glUnmapBuffer);
GL_PROC(PFNGLCreateShader, glCreateShader);
GL_PROC(PFNGLShaderSource, glShaderSource);
GL_PROC(PFNGLCompileShader, glCompileShader);
GL_PROC(PFNGLGetShaderiv, glGetShaderiv);
GL_PROC(PFNGLCreateProgram, glCreateProgram);
GL_PROC(PFNGLAttachShader, glAttachShader);
GL_PROC(PFNGLLinkProgram, glLinkProgram);
GL_PROC(PFNGLGetProgramiv, glGetProgramiv);
GL_PROC(PFNGLUseProgram, glUseProgram);
GL_PROC(PFNGLGetUniformLocation, glGetUniformLocation);
GL_PROC(PFNGLUniform1i, glUniform1i);
GL_PROC(PFNGLGenVertexArrays, glGenVertexArrays);
GL_PROC(PFNGLBindVertexArray, glBindVertexArray);
GL_PROC(PFNGLEnableVertexAttribArray, glEnableVertexAttribArray);
GL_PROC(PFNGLVertexAttribPointer, glVertexAttribPointer);
GL_PROC(PFNGLDrawArrays, glDrawArrays);

#define LOAD_GL(name) p_##name = reinterpret_cast<decltype(p_##name)>(glfwGetProcAddress(#name))

static bool load_gl() {
    LOAD_GL(glGenTextures);
    LOAD_GL(glBindTexture);
    LOAD_GL(glTexParameteri);
    LOAD_GL(glTexStorage2D);
    LOAD_GL(glActiveTexture);
    LOAD_GL(glPixelStorei);
    LOAD_GL(glTexSubImage2D);
    LOAD_GL(glGenBuffers);
    LOAD_GL(glBindBuffer);
    LOAD_GL(glBufferData);
    LOAD_GL(glMapBufferRange);
    LOAD_GL(glUnmapBuffer);
    LOAD_GL(glCreateShader);
    LOAD_GL(glShaderSource);
    LOAD_GL(glCompileShader);
    LOAD_GL(glGetShaderiv);
    LOAD_GL(glCreateProgram);
    LOAD_GL(glAttachShader);
    LOAD_GL(glLinkProgram);
    LOAD_GL(glGetProgramiv);
    LOAD_GL(glUseProgram);
    LOAD_GL(glGetUniformLocation);
    LOAD_GL(glUniform1i);
    LOAD_GL(glGenVertexArrays);
    LOAD_GL(glBindVertexArray);
    LOAD_GL(glEnableVertexAttribArray);
    LOAD_GL(glVertexAttribPointer);
    LOAD_GL(glDrawArrays);
    return p_glGenTextures && p_glTexSubImage2D && p_glMapBufferRange && p_glCreateProgram;
}

static const char kVs[] = R"(#version 330 core
layout(location = 0) in vec2 a_pos;
out vec2 v_uv;
void main() {
    v_uv = a_pos * 0.5 + 0.5;
    gl_Position = vec4(a_pos, 0.0, 1.0);
})";

static const char kFs[] = R"(#version 330 core
in vec2 v_uv;
out vec4 fragColor;
uniform sampler2D u_texY;
uniform sampler2D u_texUV;
uniform int u_uv_la;
vec3 yuv709(vec3 yuv) {
    yuv = vec3(yuv.x - 16.0/255.0, yuv.y - 0.5, yuv.z - 0.5);
    mat3 m = mat3(1.16438356, 1.16438356, 1.16438356,
                  0.0, -0.21324894, 2.11240179,
                  1.79274107, -0.53290933, 0.0);
    return clamp(m * yuv, 0.0, 1.0);
}
void main() {
    float y = texture(u_texY, v_uv).r;
    vec4 uv_s = texture(u_texUV, v_uv);
    vec2 uv = u_uv_la != 0 ? uv_s.ra : uv_s.rg;
    fragColor = vec4(yuv709(vec3(y, uv.x, uv.y)), 1.0);
})";

static GLuint build_program() {
    auto compile = [](GLenum type, const char* src) -> GLuint {
        GLuint s = p_glCreateShader(type);
        p_glShaderSource(s, 1, &src, nullptr);
        p_glCompileShader(s);
        GLint ok = 0;
        p_glGetShaderiv(s, 0x8B81, &ok);
        return ok ? s : 0;
    };
    GLuint vs = compile(0x8B31, kVs);
    GLuint fs = compile(0x8B30, kFs);
    if (!vs || !fs) {
        return 0;
    }
    GLuint prog = p_glCreateProgram();
    p_glAttachShader(prog, vs);
    p_glAttachShader(prog, fs);
    p_glLinkProgram(prog);
    GLint ok = 0;
    p_glGetProgramiv(prog, 0x8B82, &ok);
    return ok ? prog : 0;
}

XqcNv12GlLinux::~XqcNv12GlLinux() {
    stop();
}

bool XqcNv12GlLinux::start(int initial_width, int initial_height, const char* title) {
    if (_running.load()) {
        return true;
    }
    _init_w = initial_width > 0 ? initial_width : 640;
    _init_h = initial_height > 0 ? initial_height : 480;
    _title = title ? title : "xqc_nv12";
    _stop = false;
    _thread = std::thread([this] { thread_main(); });
    for (int i = 0; i < 200 && !_running.load(); ++i) {
        usleep(10000);
    }
    return _running.load();
}

void XqcNv12GlLinux::request_stop() {
    _stop = true;
}

void XqcNv12GlLinux::stop() {
    _stop = true;
    if (_thread.joinable()) {
        _thread.join();
    }
    _running = false;
}

void XqcNv12GlLinux::submit_frame(XqcNv12Frame frame) {
    std::lock_guard<std::mutex> lk(_frame_mu);
#if defined(XQC_HAVE_HW_DECODE)
    if (_has_pending && _pending.backing == XqcNv12Backing::CudaGl) {
        xqc_nv12_frame_release(_pending);
    }
#endif
    _pending = std::move(frame);
    _has_pending = true;
}

void XqcNv12GlLinux::thread_main() {
#if defined(XQC_HAVE_HW_DECODE)
    if (xqc_h264_hw_display_use_cuda_gl()) {
        xqc_nvidia_prime_apply_for_cuda_gl();
    }
    int decode_cpu = -1;
    int display_cpu = -1;
    xqc_resolve_pipeline_cpus(decode_cpu, display_cpu);
    (void)xqc_pin_current_thread(display_cpu, "display");
#endif
    if (!glfwInit()) {
        std::fprintf(stderr, "[gl] glfwInit failed (DISPLAY=%s)\n", getenv("DISPLAY") ? getenv("DISPLAY") : "");
        return;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
#if defined(XQC_HAVE_HW_DECODE)
    /* EGL for VAAPI dma-buf; GLX + CUDA-GL interop for NVDEC (no CPU PBO on CUDA path). */
    if (xqc_h264_hw_display_use_egl()) {
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
        glfwWindowHint(GLFW_CONTEXT_CREATION_API, GLFW_EGL_CONTEXT_API);
        std::fprintf(stderr, "[gl] EGL context (VAAPI dma-buf display)\n");
    } else if (xqc_h264_hw_display_use_cuda_gl()) {
        /* Compat profile: cudaGraphicsGLRegisterImage needs legacy LUMINANCE formats on many drivers. */
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_COMPAT_PROFILE);
        std::fprintf(stderr, "[gl] GLX compat context (CUDA-GL interop, hevc_cuvid path)\n");
    } else {
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
        std::fprintf(stderr, "[gl] GLX context (PBO upload, software NV12)\n");
    }
#else
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#endif

    GLFWwindow* win = glfwCreateWindow(_init_w, _init_h, _title, nullptr, nullptr);
    if (!win) {
        std::fprintf(stderr, "[gl] glfwCreateWindow failed\n");
        glfwTerminate();
        return;
    }
    glfwMakeContextCurrent(win);
    glfwSwapInterval(1);
    if (!load_gl()) {
        std::fprintf(stderr, "[gl] GL 3.3 entry points missing\n");
        glfwDestroyWindow(win);
        glfwTerminate();
        return;
    }
#if defined(XQC_HAVE_HW_DECODE)
    (void)xqc_gl_egl_dma_init(win);
#if defined(XQC_HAVE_CUDA_GL)
    if (xqc_h264_hw_display_use_cuda_gl()) {
        (void)xqc_cuda_gl_nv12_init();
    }
#endif
#endif

    GLuint prog = build_program();
    if (!prog) {
        glfwDestroyWindow(win);
        glfwTerminate();
        return;
    }

    GLuint vao = 0, vbo = 0;
    p_glGenVertexArrays(1, &vao);
    p_glBindVertexArray(vao);
    const float quad[] = {-1, -1, 1, -1, -1, 1, 1, 1};
    p_glGenBuffers(1, &vbo);
    p_glBindBuffer(0x8892, vbo);
    p_glBufferData(0x8892, sizeof(quad), quad, 0x88E4);
    p_glEnableVertexAttribArray(0);
    p_glVertexAttribPointer(0, 2, 0x1406, 0, 0, nullptr);

    GLint locY = p_glGetUniformLocation(prog, "u_texY");
    GLint locUV = p_glGetUniformLocation(prog, "u_texUV");
    GLint locUvLa = p_glGetUniformLocation(prog, "u_uv_la");
    p_glUseProgram(prog);
    p_glUniform1i(locY, 0);
    p_glUniform1i(locUV, 1);
    p_glUniform1i(locUvLa, 0);

    GLuint texY = 0, texUV = 0;
    p_glGenTextures(1, &texY);
    p_glGenTextures(1, &texUV);

    XqcPboCountStrategy pbo_strategy(XqcPboMode::Dual);
    const int n_pbos = pbo_strategy.buffer_count();
    std::vector<GLuint> pbos(static_cast<size_t>(n_pbos));
    p_glGenBuffers(n_pbos, pbos.data());

    int tex_w = 0, tex_h = 0;
    size_t pbo_sz = 0;
    int cur_pbo = 0;

    _running = true;
    std::fprintf(stderr, "[gl] display thread running\n");

    while (!glfwWindowShouldClose(win) && !_stop.load()) {
        XqcNv12Frame frame;
        {
            std::lock_guard<std::mutex> lk(_frame_mu);
            if (_has_pending) {
                frame = std::move(_pending);
                _has_pending = false;
            }
        }

        bool drew_frame = false;
        bool drew_egl = false;
        bool drew_cuda_gl = false;
        if (frame.width > 0 && frame.height > 0) {
            const int w = frame.width;
            const int h = frame.height;
            if (!xqc_frame_within_4k_budget(w, h)) {
                std::fprintf(stderr, "[gl] frame %dx%d exceeds 4K budget %dx%d\n",
                    w, h, XQC_VIDEO_TARGET_WIDTH, XQC_VIDEO_TARGET_HEIGHT);
            }
#if defined(XQC_HAVE_HW_DECODE)
#if defined(XQC_HAVE_CUDA_GL)
            if (frame.backing == XqcNv12Backing::CudaGl) {
                if (xqc_cuda_gl_nv12_upload_nv12(frame)) {
                    tex_w = w;
                    tex_h = h;
                    drew_frame = true;
                    drew_cuda_gl = true;
                } else if (xqc_cuda_gl_nv12_fallback_to_cpu(frame)) {
                    /* fall through to PBO path below */
                }
            }
            if (!drew_frame)
#endif
            if (frame.backing == XqcNv12Backing::VaapiDmaBuf && xqc_gl_egl_dma_upload_nv12(frame)) {
                tex_w = w;
                tex_h = h;
                drew_frame = true;
                drew_egl = true;
            } else
#endif
            if (!frame.data.empty()) {
            const size_t need = xqc_nv12_byte_size(w, h);
            if (frame.data.size() >= need) {
                drew_frame = true;
                if (w != tex_w || h != tex_h) {
                    tex_w = w;
                    tex_h = h;
                    pbo_sz = need;
                    p_glBindTexture(0x0DE1, texY);
                    p_glTexParameteri(0x0DE1, 0x2801, 0x2601);
                    p_glTexParameteri(0x0DE1, 0x2800, 0x2601);
                    p_glTexStorage2D(0x0DE1, 1, GL_R8, w, h);
                    p_glBindTexture(0x0DE1, texUV);
                    p_glTexParameteri(0x0DE1, 0x2801, 0x2601);
                    p_glTexParameteri(0x0DE1, 0x2800, 0x2601);
                    p_glTexStorage2D(0x0DE1, 1, GL_RG8, w / 2, h / 2);
                    for (int i = 0; i < n_pbos; ++i) {
                        p_glBindBuffer(GL_PIXEL_UNPACK_BUFFER, pbos[static_cast<size_t>(i)]);
                        p_glBufferData(GL_PIXEL_UNPACK_BUFFER, static_cast<GLsizeiptr>(pbo_sz), nullptr, GL_STREAM_DRAW);
                    }
                }
                p_glBindBuffer(GL_PIXEL_UNPACK_BUFFER, pbos[static_cast<size_t>(cur_pbo)]);
                void* map = p_glMapBufferRange(GL_PIXEL_UNPACK_BUFFER, 0, static_cast<GLsizeiptr>(pbo_sz),
                    GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT);
                if (map) {
                    std::memcpy(map, frame.data.data(), pbo_sz);
                    p_glUnmapBuffer(GL_PIXEL_UNPACK_BUFFER);
                }
                p_glPixelStorei(0x0CF1, 1);
                p_glPixelStorei(GL_UNPACK_ROW_LENGTH, w);
                p_glBindTexture(0x0DE1, texY);
                p_glTexSubImage2D(0x0DE1, 0, 0, 0, w, h, GL_RED, 0x1401, nullptr);
                p_glPixelStorei(GL_UNPACK_ROW_LENGTH, w / 2);
                p_glBindTexture(0x0DE1, texUV);
                p_glTexSubImage2D(0x0DE1, 0, 0, 0, w / 2, h / 2, GL_RG, 0x1401,
                    reinterpret_cast<const void*>(static_cast<uintptr_t>(w) * static_cast<uintptr_t>(h)));
                p_glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
                p_glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
                cur_pbo = (cur_pbo + 1) % n_pbos;
            }
            }
        }

#if defined(XQC_HAVE_HW_DECODE)
        if (frame.backing == XqcNv12Backing::CudaGl) {
            xqc_nv12_frame_release(frame);
        }
#endif

        int fbw = 0, fbh = 0;
        glfwGetFramebufferSize(win, &fbw, &fbh);
        glViewport(0, 0, fbw, fbh);
        glClearColor(0.05f, 0.05f, 0.08f, 1.f);
        glClear(0x00004000);
        if (tex_w > 0) {
            p_glActiveTexture(0x84C0);
#if defined(XQC_HAVE_HW_DECODE)
#if defined(XQC_HAVE_CUDA_GL)
            p_glBindTexture(0x0DE1, drew_cuda_gl ? xqc_cuda_gl_nv12_tex_y()
                : (drew_egl ? xqc_gl_egl_tex_y() : texY));
#else
            p_glBindTexture(0x0DE1, drew_egl ? xqc_gl_egl_tex_y() : texY);
#endif
#else
            p_glBindTexture(0x0DE1, texY);
#endif
            p_glActiveTexture(0x84C1);
#if defined(XQC_HAVE_HW_DECODE)
#if defined(XQC_HAVE_CUDA_GL)
            p_glBindTexture(0x0DE1, drew_cuda_gl ? xqc_cuda_gl_nv12_tex_uv()
                : (drew_egl ? xqc_gl_egl_tex_uv() : texUV));
#else
            p_glBindTexture(0x0DE1, drew_egl ? xqc_gl_egl_tex_uv() : texUV);
#endif
#else
            p_glBindTexture(0x0DE1, texUV);
#endif
            p_glUseProgram(prog);
            p_glUniform1i(locUvLa, drew_cuda_gl && xqc_cuda_gl_nv12_uses_luminance_alpha_uv() ? 1 : 0);
            p_glBindVertexArray(vao);
            p_glDrawArrays(0x0005, 0, 4);
        }
        glfwSwapBuffers(win);
        glfwPollEvents();

        /* E2E sample point: after swap — closest proxy to "visible" in WSLg/X11. */
        if (drew_frame) {
            frame.display_us = xqc_wall_us_now();
            xqc_e2e_latency_hist().record_stream_present(frame, frame.display_us);
        }
    }

    _running = false;
#if defined(XQC_HAVE_HW_DECODE)
#if defined(XQC_HAVE_CUDA_GL)
    xqc_cuda_gl_nv12_shutdown();
#endif
    xqc_gl_egl_dma_shutdown();
#endif
    glfwDestroyWindow(win);
    glfwTerminate();
    std::fprintf(stderr, "[gl] display thread exit\n");
}
