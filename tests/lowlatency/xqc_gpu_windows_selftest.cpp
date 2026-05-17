/**
 * Phase W1 — Windows NVIDIA path self-check (design §3).
 *
 * - Exports NvOptimusEnablement for the loader.
 * - Creates a minimal WGL context and prints GL_VENDOR / GL_RENDERER.
 * - Exit code: 0 = vendor string contains "NVIDIA", 2 = not NVIDIA (Optimus on iGPU etc.), 1 = fatal.
 *
 * Usage: xqc_gpu_windows_selftest [--strict]
 *   --strict  exit with code 2 if NVIDIA string not detected (default: warn only, still exit 0).
 */

#if !defined(_WIN32) && !defined(_WIN64)
int main() { return 0; }
#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <windowsx.h>

#include <GL/gl.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

extern "C" __declspec(dllexport) unsigned long NvOptimusEnablement = 0x00000001;

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(h, m, w, l);
}

static bool contains_nvidia(const char* s) {
    if (!s) {
        return false;
    }
    std::string t(s);
    for (auto& c : t) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return t.find("nvidia") != std::string::npos;
}

int main(int argc, char** argv) {
    bool strict = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--strict") == 0) {
            strict = true;
        }
    }

    std::fprintf(stderr,
        "[W1] Reminder: also set Windows Settings -> Display -> Graphics -> this exe -> High performance (NVIDIA).\n");

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"xqc_gpu_selftest_cls";
    if (!RegisterClassW(&wc)) {
        std::fprintf(stderr, "[W1] RegisterClassW failed: %lu\n", GetLastError());
        return 1;
    }

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"xqc_gpu_selftest", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 64, 64, nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) {
        std::fprintf(stderr, "[W1] CreateWindowExW failed: %lu\n", GetLastError());
        return 1;
    }

    HDC hdc = GetDC(hwnd);
    if (!hdc) {
        std::fprintf(stderr, "[W1] GetDC failed\n");
        DestroyWindow(hwnd);
        return 1;
    }

    PIXELFORMATDESCRIPTOR pfd{};
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cDepthBits = 24;
    pfd.iLayerType = PFD_MAIN_PLANE;

    int pf = ChoosePixelFormat(hdc, &pfd);
    if (!pf || !SetPixelFormat(hdc, pf, &pfd)) {
        std::fprintf(stderr, "[W1] ChoosePixelFormat/SetPixelFormat failed: %lu\n", GetLastError());
        ReleaseDC(hwnd, hdc);
        DestroyWindow(hwnd);
        return 1;
    }

    HGLRC rc = wglCreateContext(hdc);
    if (!rc || !wglMakeCurrent(hdc, rc)) {
        std::fprintf(stderr, "[W1] wglCreateContext/wglMakeCurrent failed: %lu\n", GetLastError());
        ReleaseDC(hwnd, hdc);
        DestroyWindow(hwnd);
        return 1;
    }

    const char* vendor = reinterpret_cast<const char*>(glGetString(GL_VENDOR));
    const char* renderer = reinterpret_cast<const char*>(glGetString(GL_RENDERER));
    std::fprintf(stderr, "[W1] GL_VENDOR   : %s\n", vendor ? vendor : "(null)");
    std::fprintf(stderr, "[W1] GL_RENDERER : %s\n", renderer ? renderer : "(null)");

    bool ok = contains_nvidia(vendor) || contains_nvidia(renderer);
    if (!ok) {
        std::fprintf(stderr,
            "[W1] WARNING: GL strings do not look like NVIDIA discrete GPU. "
            "FFmpeg NVDEC + this GL context may incur cross-GPU copies on Optimus.\n");
    }

    wglMakeCurrent(nullptr, nullptr);
    wglDeleteContext(rc);
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    if (!ok && strict) {
        std::fprintf(stderr, "[W1] --strict: exiting with code 2.\n");
        return 2;
    }
    return 0;
}

#endif /* Windows */
