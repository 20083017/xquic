/**
 * Phase W2 — NV12 + dual PBO + BT.709 limited shader + V-Sync (design §5).
 * Windows + WGL minimal loader (no GLFW). Input: raw NV12 file (Y then UV).
 *
 * Usage: xqc_nv12_gl_pbo_viewer <width> <height> <path.nv12> [--triple-pbo]
 *   Frame size = width*height + width*(height/2) bytes per frame; file is one or more frames (plays first).
 */

#if !defined(_WIN32) && !defined(_WIN64)
#include <cstdio>
int main() {
    std::puts("xqc_nv12_gl_pbo_viewer is only built on Windows in this tree.");
    return 0;
}
#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <windowsx.h>

#include <GL/gl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>

#include "xqc_lowlatency_perf.hh"
#include "xqc_pbo_dynamic_manager.hh"

extern "C" __declspec(dllexport) unsigned long NvOptimusEnablement = 0x00000001;

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
#ifndef GL_TEXTURE0
#define GL_TEXTURE0 0x84C0
#endif
#ifndef GL_TEXTURE1
#define GL_TEXTURE1 0x84C1
#endif
#ifndef GL_ARRAY_BUFFER
#define GL_ARRAY_BUFFER 0x8892
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
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#ifndef GL_FRAGMENT_SHADER
#define GL_FRAGMENT_SHADER 0x8B30
#endif
#ifndef GL_VERTEX_SHADER
#define GL_VERTEX_SHADER 0x8B31
#endif
#ifndef GL_COMPILE_STATUS
#define GL_COMPILE_STATUS 0x8B81
#endif
#ifndef GL_LINK_STATUS
#define GL_LINK_STATUS 0x8B82
#endif
#ifndef GL_INFO_LOG_LENGTH
#define GL_INFO_LOG_LENGTH 0x8B84
#endif
#ifndef GL_TRIANGLE_STRIP
#define GL_TRIANGLE_STRIP 0x0005
#endif
#ifndef WGL_CONTEXT_MAJOR_VERSION_ARB
#define WGL_CONTEXT_MAJOR_VERSION_ARB 0x2091
#endif
#ifndef WGL_CONTEXT_MINOR_VERSION_ARB
#define WGL_CONTEXT_MINOR_VERSION_ARB 0x2092
#endif
#ifndef WGL_CONTEXT_PROFILE_MASK_ARB
#define WGL_CONTEXT_PROFILE_MASK_ARB 0x9126
#endif
#ifndef WGL_CONTEXT_CORE_PROFILE_BIT_ARB
#define WGL_CONTEXT_CORE_PROFILE_BIT_ARB 0x00000001
#endif

typedef unsigned int GLbitfield;

typedef void(APIENTRY* PFN_glEnableVertexAttribArray)(GLuint);
typedef void(APIENTRY* PFN_glVertexAttribPointer)(GLuint, GLint, GLenum, GLboolean, GLsizei, const void*);
typedef void(APIENTRY* PFN_glViewport)(GLint, GLint, GLsizei, GLsizei);
typedef void(APIENTRY* PFN_glClear)(GLbitfield);

typedef ptrdiff_t GLintptr;
typedef ptrdiff_t GLsizeiptr;
typedef char GLchar;

typedef GLuint(APIENTRY* PFN_glCreateShader)(GLenum);
typedef void(APIENTRY* PFN_glShaderSource)(GLuint, GLsizei, const GLchar* const*, const GLint*);
typedef void(APIENTRY* PFN_glCompileShader)(GLuint);
typedef void(APIENTRY* PFN_glGetShaderiv)(GLuint, GLenum, GLint*);
typedef void(APIENTRY* PFN_glGetShaderInfoLog)(GLuint, GLsizei, GLsizei*, GLchar*);
typedef GLuint(APIENTRY* PFN_glCreateProgram)(void);
typedef void(APIENTRY* PFN_glAttachShader)(GLuint, GLuint);
typedef void(APIENTRY* PFN_glLinkProgram)(GLuint);
typedef void(APIENTRY* PFN_glGetProgramiv)(GLuint, GLenum, GLint*);
typedef void(APIENTRY* PFN_glGetProgramInfoLog)(GLuint, GLsizei, GLsizei*, GLchar*);
typedef void(APIENTRY* PFN_glDeleteShader)(GLuint);
typedef void(APIENTRY* PFN_glUseProgram)(GLuint);
typedef GLint(APIENTRY* PFN_glGetUniformLocation)(GLuint, const GLchar*);
typedef void(APIENTRY* PFN_glUniform1i)(GLint, GLint);
typedef void(APIENTRY* PFN_glGenVertexArrays)(GLsizei, GLuint*);
typedef void(APIENTRY* PFN_glBindVertexArray)(GLuint);
typedef void(APIENTRY* PFN_glDrawArrays)(GLenum, GLint, GLsizei);
typedef void(APIENTRY* PFN_glGenBuffers)(GLsizei, GLuint*);
typedef void(APIENTRY* PFN_glBindBuffer)(GLenum, GLuint);
typedef void(APIENTRY* PFN_glBufferData)(GLenum, GLsizeiptr, const void*, GLenum);
typedef void*(APIENTRY* PFN_glMapBufferRange)(GLenum, GLintptr, GLsizeiptr, GLbitfield);
typedef GLboolean(APIENTRY* PFN_glUnmapBuffer)(GLenum);
typedef void(APIENTRY* PFN_glGenTextures)(GLsizei, GLuint*);
typedef void(APIENTRY* PFN_glBindTexture)(GLenum, GLuint);
typedef void(APIENTRY* PFN_glTexParameteri)(GLenum, GLenum, GLint);
typedef void(APIENTRY* PFN_glTexStorage2D)(GLenum, GLsizei, GLenum, GLsizei, GLsizei);
typedef void(APIENTRY* PFN_glActiveTexture)(GLenum);
typedef void(APIENTRY* PFN_glPixelStorei)(GLenum, GLint);
typedef void(APIENTRY* PFN_glTexSubImage2D)(GLenum, GLint, GLint, GLint, GLsizei, GLsizei, GLenum, GLenum,
    const void*);
typedef HGLRC(WINAPI* PFN_wglCreateContextAttribsARB)(HDC, HGLRC, const int*);
typedef BOOL(APIENTRY* PFN_wglSwapIntervalEXT)(int);

#define WGLPROC(name) static PFN_##name p_##name = nullptr
WGLPROC(glCreateShader);
WGLPROC(glShaderSource);
WGLPROC(glCompileShader);
WGLPROC(glGetShaderiv);
WGLPROC(glGetShaderInfoLog);
WGLPROC(glCreateProgram);
WGLPROC(glAttachShader);
WGLPROC(glLinkProgram);
WGLPROC(glGetProgramiv);
WGLPROC(glGetProgramInfoLog);
WGLPROC(glDeleteShader);
WGLPROC(glUseProgram);
WGLPROC(glGetUniformLocation);
WGLPROC(glUniform1i);
WGLPROC(glGenVertexArrays);
WGLPROC(glBindVertexArray);
WGLPROC(glDrawArrays);
WGLPROC(glGenBuffers);
WGLPROC(glBindBuffer);
WGLPROC(glBufferData);
WGLPROC(glMapBufferRange);
WGLPROC(glUnmapBuffer);
WGLPROC(glGenTextures);
WGLPROC(glBindTexture);
WGLPROC(glTexParameteri);
WGLPROC(glTexStorage2D);
WGLPROC(glActiveTexture);
WGLPROC(glPixelStorei);
WGLPROC(glTexSubImage2D);
static PFN_wglCreateContextAttribsARB p_wglCreateContextAttribsARB = nullptr;
static PFN_wglSwapIntervalEXT p_wglSwapIntervalEXT = nullptr;
WGLPROC(glEnableVertexAttribArray);
WGLPROC(glVertexAttribPointer);
WGLPROC(glViewport);
WGLPROC(glClear);

static void* get_gl_proc(const char* name) {
    void* p = reinterpret_cast<void*>(wglGetProcAddress(name));
    if (!p || p == reinterpret_cast<void*>(-1) || p == reinterpret_cast<void*>(1) || p == reinterpret_cast<void*>(2)) {
        p = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("opengl32.dll"), name));
    }
    return p;
}

#define LOAD(n) p_##n = reinterpret_cast<PFN_##n>(get_gl_proc(#n))

static bool load_gl3(HDC hdc) {
    (void)hdc;
    LOAD(glCreateShader);
    LOAD(glShaderSource);
    LOAD(glCompileShader);
    LOAD(glGetShaderiv);
    LOAD(glGetShaderInfoLog);
    LOAD(glCreateProgram);
    LOAD(glAttachShader);
    LOAD(glLinkProgram);
    LOAD(glGetProgramiv);
    LOAD(glGetProgramInfoLog);
    LOAD(glDeleteShader);
    LOAD(glUseProgram);
    LOAD(glGetUniformLocation);
    LOAD(glUniform1i);
    LOAD(glGenVertexArrays);
    LOAD(glBindVertexArray);
    LOAD(glDrawArrays);
    LOAD(glGenBuffers);
    LOAD(glBindBuffer);
    LOAD(glBufferData);
    LOAD(glMapBufferRange);
    LOAD(glUnmapBuffer);
    LOAD(glGenTextures);
    LOAD(glBindTexture);
    LOAD(glTexParameteri);
    LOAD(glTexStorage2D);
    LOAD(glActiveTexture);
    LOAD(glPixelStorei);
    LOAD(glTexSubImage2D);
    LOAD(glEnableVertexAttribArray);
    LOAD(glVertexAttribPointer);
    LOAD(glViewport);
    LOAD(glClear);
    return p_glCreateShader && p_glShaderSource && p_glCompileShader && p_glCreateProgram && p_glLinkProgram
        && p_glGenVertexArrays && p_glGenBuffers && p_glMapBufferRange && p_glGenTextures && p_glTexStorage2D
        && p_glTexSubImage2D && p_glEnableVertexAttribArray && p_glVertexAttribPointer && p_glViewport && p_glClear;
}

static GLuint compile_shader(GLenum type, const char* src) {
    GLuint s = p_glCreateShader(type);
    const GLchar* glsrc = reinterpret_cast<const GLchar*>(src);
    p_glShaderSource(s, 1, &glsrc, nullptr);
    p_glCompileShader(s);
    GLint ok = 0;
    p_glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        GLint len = 0;
        p_glGetShaderiv(s, GL_INFO_LOG_LENGTH, &len);
        std::vector<GLchar> log(static_cast<size_t>(len) + 1);
        p_glGetShaderInfoLog(s, len, nullptr, log.data());
        std::fprintf(stderr, "shader compile failed: %s\n", log.data());
        return 0;
    }
    return s;
}

static const char kVs[] = R"(
#version 330 core
layout(location = 0) in vec2 a_pos;
out vec2 v_uv;
void main() {
    v_uv = a_pos * 0.5 + 0.5;
    gl_Position = vec4(a_pos, 0.0, 1.0);
}
)";

static const char kFs[] = R"(
#version 330 core
in vec2 v_uv;
out vec4 fragColor;
uniform sampler2D u_texY;
uniform sampler2D u_texUV;
vec3 yuvToRgb709Limited(vec3 yuv) {
    yuv = vec3(yuv.x - 16.0/255.0, yuv.y - 0.5, yuv.z - 0.5);
    mat3 m = mat3(
         1.16438356,  1.16438356, 1.16438356,
         0.0,          -0.21324894, 2.11240179,
         1.79274107,  -0.53290933, 0.0
    );
    return clamp(m * yuv, 0.0, 1.0);
}
void main() {
    float y = texture(u_texY, v_uv).r;
    vec2 uv = texture(u_texUV, v_uv).rg;
    fragColor = vec4(yuvToRgb709Limited(vec3(y, uv.x, uv.y)), 1.0);
}
)";

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(h, m, w, l);
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <width> <height> <path.nv12> [--triple-pbo] [--pbo dual|triple|auto]\n", argv[0]);
        return 1;
    }
    const int width = std::atoi(argv[1]);
    const int height = std::atoi(argv[2]);
    const char* path = argv[3];
    XqcPboMode pbo_mode = XqcPboMode::Dual;
    for (int i = 4; i < argc; ++i) {
        if (std::strcmp(argv[i], "--triple-pbo") == 0) {
            pbo_mode = XqcPboMode::Triple;
        } else if (std::strcmp(argv[i], "--pbo") == 0 && i + 1 < argc) {
            ++i;
            if (std::strcmp(argv[i], "triple") == 0) {
                pbo_mode = XqcPboMode::Triple;
            } else if (std::strcmp(argv[i], "dual") == 0) {
                pbo_mode = XqcPboMode::Dual;
            } else if (std::strcmp(argv[i], "auto") == 0) {
                pbo_mode = XqcPboMode::Auto;
            }
        }
    }
    XqcPboCountStrategy pbo_strategy(pbo_mode);
    if (width <= 0 || height <= 0 || (height & 1)) {
        std::fprintf(stderr, "width/height must be positive and height even\n");
        return 1;
    }
    const size_t frame_bytes = static_cast<size_t>(width) * static_cast<size_t>(height)
        + static_cast<size_t>(width) * static_cast<size_t>(height / 2);
    std::vector<unsigned char> nv12(frame_bytes);
    {
        std::ifstream f(path, std::ios::binary);
        if (!f.read(reinterpret_cast<char*>(nv12.data()), static_cast<std::streamsize>(frame_bytes))) {
            std::fprintf(stderr, "read %zu bytes from %s failed\n", frame_bytes, path);
            return 1;
        }
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"xqc_nv12_viewer";
    RegisterClassW(&wc);
    RECT r{0, 0, width, height};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW | WS_VISIBLE, FALSE);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"xqc_nv12_gl_pbo_viewer", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top, nullptr, nullptr, wc.hInstance, nullptr);
    HDC hdc = GetDC(hwnd);

    PIXELFORMATDESCRIPTOR pfd{};
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cDepthBits = 24;
    SetPixelFormat(hdc, ChoosePixelFormat(hdc, &pfd), &pfd);
    HGLRC rc0 = wglCreateContext(hdc);
    wglMakeCurrent(hdc, rc0);
    p_wglCreateContextAttribsARB =
        reinterpret_cast<PFN_wglCreateContextAttribsARB>(wglGetProcAddress("wglCreateContextAttribsARB"));
    p_wglSwapIntervalEXT = reinterpret_cast<PFN_wglSwapIntervalEXT>(wglGetProcAddress("wglSwapIntervalEXT"));
    const int attribs[] = {WGL_CONTEXT_MAJOR_VERSION_ARB, 3, WGL_CONTEXT_MINOR_VERSION_ARB, 3,
        WGL_CONTEXT_PROFILE_MASK_ARB, WGL_CONTEXT_CORE_PROFILE_BIT_ARB, 0};
    HGLRC rc = p_wglCreateContextAttribsARB ? p_wglCreateContextAttribsARB(hdc, nullptr, attribs) : rc0;
    if (rc && rc != rc0) {
        wglMakeCurrent(nullptr, nullptr);
        wglDeleteContext(rc0);
        wglMakeCurrent(hdc, rc);
    }
    if (!load_gl3(hdc)) {
        std::fprintf(stderr, "OpenGL 3.3 entry points missing\n");
        return 1;
    }
    if (p_wglSwapIntervalEXT) {
        p_wglSwapIntervalEXT(1);
    }

    GLuint vao = 0, vbo = 0;
    p_glGenVertexArrays(1, &vao);
    p_glBindVertexArray(vao);
    const float quad[] = {-1, -1, 1, -1, -1, 1, 1, 1};
    p_glGenBuffers(1, &vbo);
    p_glBindBuffer(GL_ARRAY_BUFFER, vbo);
    p_glBufferData(GL_ARRAY_BUFFER, sizeof(quad), quad, GL_STATIC_DRAW);
    p_glEnableVertexAttribArray(0);
    p_glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, nullptr);

    GLuint vs = compile_shader(GL_VERTEX_SHADER, kVs);
    GLuint fs = compile_shader(GL_FRAGMENT_SHADER, kFs);
    GLuint prog = p_glCreateProgram();
    p_glAttachShader(prog, vs);
    p_glAttachShader(prog, fs);
    p_glLinkProgram(prog);
    GLint lnk = 0;
    p_glGetProgramiv(prog, GL_LINK_STATUS, &lnk);
    if (!lnk) {
        std::fprintf(stderr, "program link failed\n");
        return 1;
    }
    p_glDeleteShader(vs);
    p_glDeleteShader(fs);
    p_glUseProgram(prog);
    GLint locY = p_glGetUniformLocation(prog, "u_texY");
    GLint locUV = p_glGetUniformLocation(prog, "u_texUV");
    p_glUniform1i(locY, 0);
    p_glUniform1i(locUV, 1);

    GLuint texY = 0, texUV = 0;
    p_glGenTextures(1, &texY);
    p_glGenTextures(1, &texUV);
    p_glBindTexture(GL_TEXTURE_2D, texY);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    p_glTexStorage2D(GL_TEXTURE_2D, 1, GL_R8, width, height);
    p_glBindTexture(GL_TEXTURE_2D, texUV);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    p_glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    p_glTexStorage2D(GL_TEXTURE_2D, 1, GL_RG8, width / 2, height / 2);

    const int n_pbos = pbo_strategy.buffer_count();
    std::vector<GLuint> pbos(static_cast<size_t>(n_pbos));
    p_glGenBuffers(n_pbos, pbos.data());
    const size_t pbo_sz = frame_bytes;
    for (int i = 0; i < n_pbos; ++i) {
        p_glBindBuffer(GL_PIXEL_UNPACK_BUFFER, pbos[static_cast<size_t>(i)]);
        p_glBufferData(GL_PIXEL_UNPACK_BUFFER, static_cast<GLsizeiptr>(pbo_sz), nullptr, GL_STREAM_DRAW);
    }

    std::fprintf(stderr, "[W2] PBO count=%d (--triple-pbo | --pbo dual|triple|auto)\n", n_pbos);
    /* upload frame 0 into first PBO */
    int cur_pbo = 0;
    p_glBindBuffer(GL_PIXEL_UNPACK_BUFFER, pbos[static_cast<size_t>(cur_pbo)]);
    void* m = p_glMapBufferRange(GL_PIXEL_UNPACK_BUFFER, 0, static_cast<GLsizeiptr>(pbo_sz),
        GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT);
    if (m) {
        std::memcpy(m, nv12.data(), pbo_sz);
        p_glUnmapBuffer(GL_PIXEL_UNPACK_BUFFER);
    }
    p_glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    p_glPixelStorei(GL_UNPACK_ROW_LENGTH, width);
    p_glBindTexture(GL_TEXTURE_2D, texY);
    p_glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RED, GL_UNSIGNED_BYTE, nullptr);
    p_glPixelStorei(GL_UNPACK_ROW_LENGTH, width / 2);
    p_glBindTexture(GL_TEXTURE_2D, texUV);
    p_glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width / 2, height / 2, GL_RG, GL_UNSIGNED_BYTE,
        reinterpret_cast<const void*>(static_cast<uintptr_t>(width) * static_cast<uintptr_t>(height)));
    p_glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    p_glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);

    MSG msg;
    bool running = true;
    XqcFrameTimer frame_timer;
    int frame_idx = 0;
    while (running) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                running = false;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        p_glViewport(0, 0, width, height);
        p_glClear(0x00004000 /* GL_COLOR_BUFFER_BIT */);
        p_glActiveTexture(GL_TEXTURE0);
        p_glBindTexture(GL_TEXTURE_2D, texY);
        p_glActiveTexture(GL_TEXTURE1);
        p_glBindTexture(GL_TEXTURE_2D, texUV);
        p_glUseProgram(prog);
        p_glBindVertexArray(vao);
        p_glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
        SwapBuffers(hdc);
        const int64_t dt_us = frame_timer.tick_us();
        if (dt_us >= 0) {
            pbo_strategy.note_frame_period_us(dt_us);
        }
        if (++frame_idx % 120 == 0 && dt_us >= 0) {
            std::fprintf(stderr, "[W5] approx frame period %lld us (swap-to-swap)\n", static_cast<long long>(dt_us));
        }
        Sleep(16);
    }

    wglMakeCurrent(nullptr, nullptr);
    wglDeleteContext(rc);
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

#endif
