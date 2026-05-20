/**
 * @file xqc_cuda_gl_interop_smoke.cpp
 * @brief P4 prototype: register an OpenGL texture with CUDA and update it.
 *
 * This is the smallest NVIDIA CUDA -> GL interop proof. It does not depend on
 * FFmpeg/NVDEC yet; once this succeeds on Ubuntu, decoded CUDA surfaces can be
 * connected to the same graphics-resource path instead of CPU NV12/PBO upload.
 */

#include <cuda_gl_interop.h>
#include <cuda_runtime.h>

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <GL/gl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#ifndef GL_RGBA8
#define GL_RGBA8 0x8058
#endif

namespace {

struct Options {
    int width = 640;
    int height = 360;
    bool visible = false;
};

void usage(const char* argv0) {
    std::printf("Usage: %s [--width N] [--height N] [--visible]\n", argv0);
}

bool parse_int(const char* s, int& out) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (!s || !s[0] || (end && *end) || v <= 0 || v > 8192) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--width") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], opt.width)) {
                return false;
            }
        } else if (std::strcmp(a, "--height") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], opt.height)) {
                return false;
            }
        } else if (std::strcmp(a, "--visible") == 0) {
            opt.visible = true;
        } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
            usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return true;
}

bool check_cuda(cudaError_t err, const char* what) {
    if (err != cudaSuccess) {
        std::fprintf(stderr, "[cuda-gl] %s failed: %s\n", what, cudaGetErrorString(err));
        return false;
    }
    return true;
}

void make_rgba_pattern(std::vector<unsigned char>& rgba, int width, int height) {
    rgba.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4);
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            const std::size_t off = (static_cast<std::size_t>(y) * static_cast<std::size_t>(width)
                + static_cast<std::size_t>(x)) * 4;
            rgba[off + 0] = static_cast<unsigned char>((x * 255) / width);
            rgba[off + 1] = static_cast<unsigned char>((y * 255) / height);
            rgba[off + 2] = 128;
            rgba[off + 3] = 255;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    int device_count = 0;
    if (!check_cuda(cudaGetDeviceCount(&device_count), "cudaGetDeviceCount") || device_count <= 0) {
        return 1;
    }
    if (!check_cuda(cudaSetDevice(0), "cudaSetDevice")) {
        return 1;
    }

    if (!glfwInit()) {
        std::fprintf(stderr, "[cuda-gl] glfwInit failed (DISPLAY=%s)\n", getenv("DISPLAY") ? getenv("DISPLAY") : "");
        return 1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    if (!opt.visible) {
        glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);
    }

    GLFWwindow* win = glfwCreateWindow(opt.width, opt.height, "xqc_cuda_gl_interop_smoke", nullptr, nullptr);
    if (!win) {
        std::fprintf(stderr, "[cuda-gl] glfwCreateWindow failed\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(win);

    GLuint tex = 0;
    glGenTextures(1, &tex);
    glBindTexture(GL_TEXTURE_2D, tex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, opt.width, opt.height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);

    cudaGraphicsResource* resource = nullptr;
    bool ok = check_cuda(cudaGraphicsGLRegisterImage(&resource, tex, GL_TEXTURE_2D,
                             cudaGraphicsRegisterFlagsWriteDiscard),
        "cudaGraphicsGLRegisterImage");

    std::vector<unsigned char> rgba;
    make_rgba_pattern(rgba, opt.width, opt.height);
    unsigned char* dev = nullptr;
    if (ok) {
        ok = ok && check_cuda(cudaMalloc(reinterpret_cast<void**>(&dev), rgba.size()), "cudaMalloc");
        ok = ok && check_cuda(cudaMemcpy(dev, rgba.data(), rgba.size(), cudaMemcpyHostToDevice), "cudaMemcpy H2D");
    }

    cudaArray_t array = nullptr;
    if (ok) {
        ok = ok && check_cuda(cudaGraphicsMapResources(1, &resource, 0), "cudaGraphicsMapResources");
        ok = ok && check_cuda(cudaGraphicsSubResourceGetMappedArray(&array, resource, 0, 0),
            "cudaGraphicsSubResourceGetMappedArray");
        ok = ok && check_cuda(cudaMemcpy2DToArray(array, 0, 0, dev,
                             static_cast<std::size_t>(opt.width) * 4,
                             static_cast<std::size_t>(opt.width) * 4,
                             static_cast<std::size_t>(opt.height),
                             cudaMemcpyDeviceToDevice),
            "cudaMemcpy2DToArray");
        ok = ok && check_cuda(cudaGraphicsUnmapResources(1, &resource, 0), "cudaGraphicsUnmapResources");
    }

    if (opt.visible && ok) {
        glClear(GL_COLOR_BUFFER_BIT);
        glfwSwapBuffers(win);
        glfwPollEvents();
    }

    if (dev) {
        cudaFree(dev);
    }
    if (resource) {
        cudaGraphicsUnregisterResource(resource);
    }
    glDeleteTextures(1, &tex);
    glfwDestroyWindow(win);
    glfwTerminate();

    std::printf("[cuda-gl] texture=%dx%d interop=%s\n", opt.width, opt.height, ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
