/**
 * Phase W5 — lightweight frame timing for §5.7 style measurements (Windows QPC).
 * Optional: combine with OS / vendor tools for CPU frequency and GPU telemetry.
 */

#pragma once

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <cstdint>

struct XqcFrameTimer {
#if defined(_WIN32) || defined(_WIN64)
    LARGE_INTEGER freq{};
    LARGE_INTEGER prev{};
    bool ok = false;

    XqcFrameTimer() {
        ok = QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&prev);
    }

    /** Microseconds since last tick (or since construction for first call). */
    int64_t tick_us() {
        if (!ok) {
            return -1;
        }
        LARGE_INTEGER now{};
        QueryPerformanceCounter(&now);
        const double us =
            (now.QuadPart - prev.QuadPart) * 1000000.0 / static_cast<double>(freq.QuadPart);
        prev = now;
        return static_cast<int64_t>(us);
    }
#else
    bool ok = false;
    XqcFrameTimer() {
        ok = false;
    }
    int64_t tick_us() {
        return -1;
    }
#endif
};
