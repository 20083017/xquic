/**
 * @file xqc_spsc_ring_smoke.cpp
 * @brief Smoke test for XqcSpscRing.
 */

#include "xqc_spsc_ring.hh"

#include <cstdio>
#include <thread>

namespace {

bool check_basic() {
    XqcSpscRing<int, 8> ring;
    if (!ring.empty() || ring.full() || ring.size() != 0 || ring.usable_capacity() != 7) {
        return false;
    }
    for (int i = 0; i < 7; ++i) {
        if (!ring.push(i)) {
            return false;
        }
    }
    if (!ring.full() || ring.push(99)) {
        return false;
    }
    for (int i = 0; i < 7; ++i) {
        int v = -1;
        if (!ring.pop(v) || v != i) {
            return false;
        }
    }
    int v = -1;
    return ring.empty() && !ring.pop(v);
}

bool check_wrap() {
    XqcSpscRing<int, 4> ring;
    for (int round = 0; round < 1000; ++round) {
        if (!ring.push(round * 3 + 0) || !ring.push(round * 3 + 1) || !ring.push(round * 3 + 2)) {
            return false;
        }
        if (!ring.full()) {
            return false;
        }
        for (int i = 0; i < 3; ++i) {
            int v = -1;
            if (!ring.pop(v) || v != round * 3 + i) {
                return false;
            }
        }
    }
    return ring.empty();
}

bool check_threaded() {
    constexpr int kCount = 100000;
    XqcSpscRing<int, 1024> ring;
    long long sum = 0;

    std::thread producer([&] {
        for (int i = 1; i <= kCount; ++i) {
            while (!ring.push(i)) {
                std::this_thread::yield();
            }
        }
    });

    std::thread consumer([&] {
        for (int i = 1; i <= kCount; ++i) {
            int v = 0;
            while (!ring.pop(v)) {
                std::this_thread::yield();
            }
            sum += v;
        }
    });

    producer.join();
    consumer.join();

    const long long expect = (static_cast<long long>(kCount) * static_cast<long long>(kCount + 1)) / 2;
    return sum == expect && ring.empty();
}

} // namespace

int main() {
    const bool basic = check_basic();
    const bool wrap = check_wrap();
    const bool threaded = check_threaded();
    std::printf("[spsc] basic=%s wrap=%s threaded=%s\n",
        basic ? "ok" : "fail",
        wrap ? "ok" : "fail",
        threaded ? "ok" : "fail");
    return basic && wrap && threaded ? 0 : 1;
}
