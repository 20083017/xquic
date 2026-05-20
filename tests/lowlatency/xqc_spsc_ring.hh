/**
 * @file xqc_spsc_ring.hh
 * @brief Fixed-capacity single-producer/single-consumer ring for hot paths.
 *
 * Design constraints from 系统目标.md:
 * - no heap allocation after construction
 * - no mutex in dataplane
 * - cache-aligned producer/consumer cursors
 *
 * Capacity must be a power of two. One slot is intentionally left unused so
 * full and empty states are distinguishable with only read/write indices.
 */

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <utility>

template <typename T, std::size_t Capacity>
class XqcSpscRing {
    static_assert(Capacity >= 2, "SPSC ring capacity must be at least 2");
    static_assert((Capacity & (Capacity - 1)) == 0, "SPSC ring capacity must be a power of two");

public:
    XqcSpscRing() = default;
    XqcSpscRing(const XqcSpscRing&) = delete;
    XqcSpscRing& operator=(const XqcSpscRing&) = delete;

    bool push(const T& value) {
        const std::size_t w = write_.value.load(std::memory_order_relaxed);
        const std::size_t next = increment(w);
        if (next == read_.value.load(std::memory_order_acquire)) {
            return false;
        }
        storage_[w] = value;
        write_.value.store(next, std::memory_order_release);
        return true;
    }

    bool push(T&& value) {
        const std::size_t w = write_.value.load(std::memory_order_relaxed);
        const std::size_t next = increment(w);
        if (next == read_.value.load(std::memory_order_acquire)) {
            return false;
        }
        storage_[w] = std::move(value);
        write_.value.store(next, std::memory_order_release);
        return true;
    }

    bool pop(T& out) {
        const std::size_t r = read_.value.load(std::memory_order_relaxed);
        if (r == write_.value.load(std::memory_order_acquire)) {
            return false;
        }
        out = std::move(storage_[r]);
        read_.value.store(increment(r), std::memory_order_release);
        return true;
    }

    bool empty() const {
        return read_.value.load(std::memory_order_acquire) == write_.value.load(std::memory_order_acquire);
    }

    bool full() const {
        const std::size_t w = write_.value.load(std::memory_order_acquire);
        return increment(w) == read_.value.load(std::memory_order_acquire);
    }

    std::size_t size() const {
        const std::size_t r = read_.value.load(std::memory_order_acquire);
        const std::size_t w = write_.value.load(std::memory_order_acquire);
        return (w - r) & kMask;
    }

    constexpr std::size_t usable_capacity() const {
        return Capacity - 1;
    }

    /** Reset indices (call only when producer and consumer are quiesced). */
    void reset() {
        read_.value.store(0, std::memory_order_release);
        write_.value.store(0, std::memory_order_release);
    }

private:
    static constexpr std::size_t kMask = Capacity - 1;

    static constexpr std::size_t increment(std::size_t value) {
        return (value + 1) & kMask;
    }

    struct alignas(64) Cursor {
        std::atomic<std::size_t> value{0};
    };

    std::array<T, Capacity> storage_{};
    Cursor read_;
    Cursor write_;
};
