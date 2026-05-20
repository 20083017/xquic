/**
 * @file xqc_cuda_memory_smoke.cpp
 * @brief P6 preflight: CUDA pinned/registered/device memory smoke test.
 *
 * This does not perform GPUDirect RDMA. It validates the memory primitives that
 * the later NIC -> GPU path depends on: pinned host allocation, registering an
 * existing host buffer, device allocation, and async copies on a CUDA stream.
 */

#include <cuda_runtime.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

struct Options {
    std::size_t bytes = 16 * 1024 * 1024;
};

void usage(const char* argv0) {
    std::printf("Usage: %s [--bytes N]\n", argv0);
}

bool parse_size(const char* s, std::size_t& out) {
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s, &end, 10);
    if (!s || !s[0] || (end && *end) || v == 0) {
        return false;
    }
    out = static_cast<std::size_t>(v);
    return true;
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--bytes") == 0 && i + 1 < argc) {
            if (!parse_size(argv[++i], opt.bytes)) {
                return false;
            }
        } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
            usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return true;
}

bool check(cudaError_t err, const char* what) {
    if (err != cudaSuccess) {
        std::fprintf(stderr, "[cuda-memory] %s failed: %s\n", what, cudaGetErrorString(err));
        return false;
    }
    return true;
}

void fill_pattern(unsigned char* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = static_cast<unsigned char>((i * 131u + 17u) & 0xffu);
    }
}

bool verify_pattern(const unsigned char* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char expect = static_cast<unsigned char>((i * 131u + 17u) & 0xffu);
        if (p[i] != expect) {
            std::fprintf(stderr, "[cuda-memory] verify mismatch at %zu got=%u expect=%u\n",
                i, static_cast<unsigned>(p[i]), static_cast<unsigned>(expect));
            return false;
        }
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    int device_count = 0;
    if (!check(cudaGetDeviceCount(&device_count), "cudaGetDeviceCount") || device_count <= 0) {
        return 1;
    }
    if (!check(cudaSetDevice(0), "cudaSetDevice")) {
        return 1;
    }

    cudaDeviceProp prop{};
    if (check(cudaGetDeviceProperties(&prop, 0), "cudaGetDeviceProperties")) {
        std::printf("[cuda-memory] device=0 name=%s unifiedAddressing=%d asyncEngineCount=%d\n",
            prop.name, prop.unifiedAddressing, prop.asyncEngineCount);
    }

    cudaStream_t stream = nullptr;
    if (!check(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreateWithFlags")) {
        return 1;
    }

    unsigned char* pinned = nullptr;
    unsigned char* device = nullptr;
    std::vector<unsigned char> pageable(opt.bytes);
    std::vector<unsigned char> roundtrip(opt.bytes);

    bool ok = true;
    ok = ok && check(cudaHostAlloc(reinterpret_cast<void**>(&pinned), opt.bytes, cudaHostAllocPortable), "cudaHostAlloc");
    ok = ok && check(cudaMalloc(reinterpret_cast<void**>(&device), opt.bytes), "cudaMalloc");

    fill_pattern(pageable.data(), pageable.size());
    ok = ok && check(cudaHostRegister(pageable.data(), pageable.size(), cudaHostRegisterPortable), "cudaHostRegister");

    if (ok) {
        std::memcpy(pinned, pageable.data(), opt.bytes);
        ok = ok && check(cudaMemcpyAsync(device, pinned, opt.bytes, cudaMemcpyHostToDevice, stream), "H2D pinned async copy");
        ok = ok && check(cudaMemcpyAsync(roundtrip.data(), device, opt.bytes, cudaMemcpyDeviceToHost, stream), "D2H pageable async copy");
        ok = ok && check(cudaStreamSynchronize(stream), "cudaStreamSynchronize");
        ok = ok && verify_pattern(roundtrip.data(), roundtrip.size());
    }

    cudaHostUnregister(pageable.data());
    if (device) {
        cudaFree(device);
    }
    if (pinned) {
        cudaFreeHost(pinned);
    }
    cudaStreamDestroy(stream);

    std::printf("[cuda-memory] bytes=%zu result=%s\n", opt.bytes, ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
