#pragma once

#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>
#include <cstddef>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <utility>

class XquicSeastarSendQueue {
public:
    static constexpr size_t kDefaultCapacity = 4096;

    struct Datagram {
        seastar::socket_address peer;
        seastar::temporary_buffer<char> payload;
    };

    explicit XquicSeastarSendQueue(size_t capacity = kDefaultCapacity)
        : _capacity(capacity) {
    }

    bool empty() const {
        return _queue.empty();
    }

    bool full() const {
        return _queue.size() >= _capacity;
    }

    size_t size() const {
        return _queue.size();
    }

    void clear() {
        _queue.clear();
    }

    /// Single memcpy into temporary_buffer; no further copies in flush_to.
    bool push(seastar::socket_address peer, const unsigned char *payload, size_t payload_len) {
        if (full()) {
            return false;
        }
        if (payload == nullptr && payload_len != 0) {
            return false;
        }

        seastar::temporary_buffer<char> buf(payload_len);
        if (payload_len != 0) {
            std::memcpy(buf.get_write(), payload, payload_len);
        }

        _queue.push_back(Datagram{
            std::move(peer),
            std::move(buf),
        });
        return true;
    }

    Datagram pop() {
        if (_queue.empty()) {
            throw std::logic_error("pop called on empty XquicSeastarSendQueue");
        }

        Datagram datagram = std::move(_queue.front());
        _queue.pop_front();
        return datagram;
    }

    /*
     * Coalesce consecutive datagrams that go to the same peer and have the
     * same payload size into one merged buffer suitable for sendmsg with
     * UDP_SEGMENT (GSO).
     *
     * Stops at the first datagram whose peer differs OR whose size differs
     * from the first datagram's size. UDP_SEGMENT requires equal-sized
     * segments (except optionally the last); we keep the simpler invariant
     * "all equal" to avoid edge cases — most QUIC bursts naturally produce
     * runs of same-size packets.
     *
     * If gso_enabled is false, callers should pass max_segments=1 so this
     * behaves identically to pop().
     */
    struct GsoBatch {
        seastar::socket_address peer;
        seastar::temporary_buffer<char> merged_buf;
        size_t segment_size = 0;
        size_t segment_count = 0;
    };

    GsoBatch pop_gso_batch(size_t max_segments) {
        GsoBatch batch;
        if (_queue.empty() || max_segments == 0) {
            return batch;
        }

        Datagram first = pop();
        batch.peer = first.peer;
        batch.segment_size = first.payload.size();
        batch.segment_count = 1;

        if (max_segments == 1 || _queue.empty()) {
            // Fast path: just hand back the first datagram's buffer as-is
            // (zero-copy). No merge needed.
            batch.merged_buf = std::move(first.payload);
            return batch;
        }

        // Pre-allocate worst-case merged buffer
        seastar::temporary_buffer<char> merged(max_segments * batch.segment_size);
        std::memcpy(merged.get_write(), first.payload.get(), batch.segment_size);
        size_t total = batch.segment_size;

        while (batch.segment_count < max_segments && !_queue.empty()) {
            const Datagram& peek = _queue.front();
            if (peek.payload.size() != batch.segment_size) break;
            const auto& pa = peek.peer.as_posix_sockaddr();
            const auto& fa = batch.peer.as_posix_sockaddr();
            if (pa.sa_family != fa.sa_family) break;
            socklen_t plen = peek.peer.length();
            if (plen != batch.peer.length()) break;
            if (std::memcmp(&pa, &fa, plen) != 0) break;

            Datagram d = pop();
            std::memcpy(merged.get_write() + total, d.payload.get(), d.payload.size());
            total += d.payload.size();
            batch.segment_count++;
        }

        merged.trim(total);
        batch.merged_buf = std::move(merged);
        return batch;
    }

private:
    size_t _capacity;
    std::deque<Datagram> _queue;
};
