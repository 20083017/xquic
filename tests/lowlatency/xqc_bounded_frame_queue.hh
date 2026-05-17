/**
 * Phase W3 — bounded frame queue (design §1): mutex + condition_variable.
 *
 * - Single logical producer / consumer (caller must not violate).
 * - drop_oldest_then_push: on full, pop front (release_fn) until space, then push.
 * - try_pop_latest: drain to last element (release_fn on skipped).
 *
 * For strict lock-free SPSC later, profile this path first then replace internals.
 */

#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <utility>

template <typename T>
class XqcBoundedFrameQueue {
public:
    using ReleaseFn = std::function<void(T&)>;

    explicit XqcBoundedFrameQueue(std::size_t capacity, ReleaseFn release_fn = {})
        : _cap(capacity), _release(std::move(release_fn)) {}

    void set_release_fn(ReleaseFn fn) {
        std::lock_guard<std::mutex> lk(_mu);
        _release = std::move(fn);
    }

    void push_drop_oldest(T v) {
        std::lock_guard<std::mutex> lk(_mu);
        while (_q.size() >= _cap) {
            T old = std::move(_q.front());
            _q.pop_front();
            if (_release) {
                _release(old);
            }
        }
        _q.push_back(std::move(v));
        _cv.notify_one();
    }

    bool try_push(T v) {
        std::lock_guard<std::mutex> lk(_mu);
        if (_q.size() >= _cap) {
            return false;
        }
        _q.push_back(std::move(v));
        _cv.notify_one();
        return true;
    }

    bool wait_pop(T& out, std::unique_lock<std::mutex>& lk) {
        _cv.wait(lk, [this] { return !_q.empty() || _closed; });
        if (_q.empty()) {
            return false;
        }
        out = std::move(_q.front());
        _q.pop_front();
        return true;
    }

    bool try_pop(T& out) {
        std::lock_guard<std::mutex> lk(_mu);
        if (_q.empty()) {
            return false;
        }
        out = std::move(_q.front());
        _q.pop_front();
        return true;
    }

    bool try_pop_latest(T& out) {
        std::lock_guard<std::mutex> lk(_mu);
        if (_q.empty()) {
            return false;
        }
        while (_q.size() > 1) {
            T old = std::move(_q.front());
            _q.pop_front();
            if (_release) {
                _release(old);
            }
        }
        out = std::move(_q.front());
        _q.pop_front();
        return true;
    }

    std::mutex& mutex() { return _mu; }
    void close() {
        std::lock_guard<std::mutex> lk(_mu);
        _closed = true;
        _cv.notify_all();
    }
    bool closed() const {
        std::lock_guard<std::mutex> lk(_mu);
        return _closed;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lk(_mu);
        return _q.size();
    }

private:
    std::size_t _cap;
    ReleaseFn _release;
    mutable std::mutex _mu;
    std::condition_variable _cv;
    std::deque<T> _q;
    bool _closed = false;
};
