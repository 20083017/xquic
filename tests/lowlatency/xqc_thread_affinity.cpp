/**
 * @file xqc_thread_affinity.cpp
 */

#include "xqc_thread_affinity.hh"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

namespace {

bool env_truthy(const char* v) {
    return v && v[0] && std::strcmp(v, "0") != 0 && std::strcmp(v, "false") != 0 && std::strcmp(v, "off") != 0;
}

bool env_is_auto(const char* v) {
    return v && (std::strcmp(v, "auto") == 0 || std::strcmp(v, "AUTO") == 0);
}

} // namespace

int xqc_cpu_from_env(const char* env_name) {
    if (!env_name) {
        return -1;
    }
    const char* e = std::getenv(env_name);
    if (!e || !e[0]) {
        return -1;
    }
    char* end = nullptr;
    const long v = std::strtol(e, &end, 10);
    if (end && *end) {
        return -1;
    }
#if defined(__linux__)
    if (v < 0 || v >= CPU_SETSIZE) {
        return -1;
    }
#else
    if (v < 0) {
        return -1;
    }
#endif
    return static_cast<int>(v);
}

bool xqc_pin_affinity_enabled() {
    const char* e = std::getenv("XQC_PIN_AFFINITY");
    return env_truthy(e) || env_is_auto(e);
}

void xqc_resolve_pipeline_cpus(int& decode_cpu, int& display_cpu) {
    decode_cpu = xqc_cpu_from_env("XQC_DECODE_CPU");
    display_cpu = xqc_cpu_from_env("XQC_DISPLAY_CPU");

    if (decode_cpu < 0 && xqc_pin_affinity_enabled()) {
        decode_cpu = 1;
    }
    if (display_cpu < 0 && xqc_pin_affinity_enabled()) {
        display_cpu = 2;
    }
}

XqcCpuPinResult xqc_pin_current_thread(int cpu, const char* role) {
    XqcCpuPinResult out;
    if (cpu < 0) {
        return out;
    }
#if defined(__linux__)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(static_cast<unsigned>(cpu), &cpuset);
    const int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    out.cpu = cpu;
    out.ok = (rc == 0);
    std::fprintf(stderr, "[affinity] %s → CPU %d (%s)\n", role ? role : "thread", cpu,
        out.ok ? "ok" : "failed");
#else
    (void)role;
    out.cpu = cpu;
    out.ok = false;
    std::fprintf(stderr, "[affinity] %s: pthread affinity not supported on this OS\n", role ? role : "thread");
#endif
    return out;
}

void xqc_log_pipeline_affinity_layout(unsigned reactor_shard, int reactor_cpu_hint) {
    int decode_cpu = -1;
    int display_cpu = -1;
    xqc_resolve_pipeline_cpus(decode_cpu, display_cpu);
    std::fprintf(stderr,
        "[affinity] reactor shard=%u cpuset_hint=%d | decode_cpu=%d display_cpu=%d "
        "(set XQC_DECODE_CPU / XQC_DISPLAY_CPU or XQC_PIN_AFFINITY=1)\n",
        reactor_shard, reactor_cpu_hint, decode_cpu, display_cpu);
}
