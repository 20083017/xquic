/**
 * @file xqc_spsc_frame_queue.hh
 * @brief SPSC ring with drop-oldest and pop-latest helpers for video decode queues.
 */

#pragma once

#include "xqc_spsc_ring.hh"

#include <cstddef>
#include <utility>

template <typename T, std::size_t Capacity>
class XqcSpscFrameQueue {
public:
    using ReleaseFn = void (*)(T&);

    bool push_drop_oldest(T value, ReleaseFn release = nullptr) {
        if (ring_.push(std::move(value))) {
            return true;
        }
        T dropped;
        if (ring_.pop(dropped) && release) {
            release(dropped);
        }
        return ring_.push(std::move(value));
    }

    bool try_pop(T& out) {
        return ring_.pop(out);
    }

    bool try_pop_latest(T& out, ReleaseFn release = nullptr) {
        if (!ring_.pop(out)) {
            return false;
        }
        T newer;
        while (ring_.pop(newer)) {
            if (release) {
                release(out);
            }
            out = std::move(newer);
        }
        return true;
    }

    std::size_t size() const {
        return ring_.size();
    }

    bool empty() const {
        return ring_.empty();
    }

    void reset() {
        ring_.reset();
    }

    constexpr std::size_t usable_capacity() const {
        return ring_.usable_capacity();
    }

private:
    XqcSpscRing<T, Capacity> ring_;
};
