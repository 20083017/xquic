#pragma once

#include "xquic_seastar_queue.hh"

#include <seastar/core/future.hh>
#include <seastar/core/internal/pollable_fd.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>

#include <cerrno>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/uio.h>

/* UDP_SEGMENT (kernel ≥4.18) — define if libc headers don't provide it. */
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

class XquicSeastarSendIntegration {
public:
    explicit XquicSeastarSendIntegration(size_t queue_capacity = XquicSeastarSendQueue::kDefaultCapacity)
        : _queue(queue_capacity) {
    }

    void clear() {
        _queue.clear();
    }

    bool empty() const {
        return _queue.empty();
    }

    ssize_t enqueue_write(const unsigned char *buf, size_t size,
                          const struct sockaddr *peer_addr, socklen_t peer_addrlen) {
        if (_queue.full()) {
            errno = EAGAIN;
            return -1;
        }

        if (buf == nullptr && size != 0) {
            errno = EINVAL;
            return -1;
        }

        try {
            if (!_queue.push(sockaddr_to_socket_address(peer_addr, peer_addrlen), buf, size)) {
                errno = EINVAL;
                return -1;
            }
            return static_cast<ssize_t>(size);

        } catch (const std::bad_alloc&) {
            errno = ENOMEM;
            return -1;

        } catch (...) {
            errno = EINVAL;
            return -1;
        }
    }

    seastar::future<> flush_to(seastar::net::udp_channel& udp_channel) {
        return seastar::do_until([this] {
            return _queue.empty();
        }, [this, &udp_channel] {
            XquicSeastarSendQueue::Datagram datagram = _queue.pop();
            // Zero-copy: temporary_buffer moves directly into packet
            return udp_channel.send(datagram.peer, seastar::net::packet(std::move(datagram.payload)));
        });
    }

    /*
     * eBPF path: send via pollable_fd::sendmsg, optionally batching consecutive
     * same-peer same-size datagrams into a single UDP_SEGMENT (GSO) syscall.
     *
     * gso_enabled=false  -> behaves like one-sendmsg-per-datagram (PR1 behavior)
     * gso_enabled=true   -> coalesces up to 64 segments per syscall
     *
     * Errors (including EIO/EINVAL/ENOTSUP from kernel/NIC not supporting GSO)
     * are swallowed; xquic engine retransmits as needed. The caller should
     * disable gso_enabled if it observes such errors (handled in PR3).
     */
    seastar::future<> flush_to_pollable_fd_with_gso(
        seastar::pollable_fd& pfd, bool& gso_enabled) {
        return seastar::do_until([this] {
            return _queue.empty();
        }, [this, &pfd, &gso_enabled] {
            const size_t max_segments = gso_enabled ? 64 : 1;

            struct SendCtx {
                XquicSeastarSendQueue::GsoBatch batch;
                struct sockaddr_storage ss;
                socklen_t slen;
                struct iovec iov;
                char cbuf[CMSG_SPACE(sizeof(uint16_t))];
                struct msghdr msg;
                bool used_gso = false;
            };
            auto ctx = std::make_unique<SendCtx>();
            ctx->batch = _queue.pop_gso_batch(max_segments);
            if (ctx->batch.segment_count == 0) {
                return seastar::make_ready_future<>();
            }
            ctx->slen = ctx->batch.peer.length();
            std::memset(&ctx->ss, 0, sizeof(ctx->ss));
            std::memcpy(&ctx->ss, &ctx->batch.peer.as_posix_sockaddr(), ctx->slen);
            ctx->iov.iov_base = ctx->batch.merged_buf.get_write();
            ctx->iov.iov_len = ctx->batch.merged_buf.size();
            std::memset(&ctx->msg, 0, sizeof(ctx->msg));
            ctx->msg.msg_name = &ctx->ss;
            ctx->msg.msg_namelen = ctx->slen;
            ctx->msg.msg_iov = &ctx->iov;
            ctx->msg.msg_iovlen = 1;

            if (gso_enabled && ctx->batch.segment_count > 1) {
                std::memset(ctx->cbuf, 0, sizeof(ctx->cbuf));
                ctx->msg.msg_control = ctx->cbuf;
                ctx->msg.msg_controllen = sizeof(ctx->cbuf);
                auto* cm = CMSG_FIRSTHDR(&ctx->msg);
                cm->cmsg_level = SOL_UDP;
                cm->cmsg_type = UDP_SEGMENT;
                cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
                uint16_t gso_size = static_cast<uint16_t>(ctx->batch.segment_size);
                std::memcpy(CMSG_DATA(cm), &gso_size, sizeof(gso_size));
                ctx->used_gso = true;
            }

            auto* msg_ptr = &ctx->msg;
            return pfd.sendmsg(msg_ptr).then_wrapped(
                [ctx = std::move(ctx), &gso_enabled](seastar::future<size_t> f) mutable {
                    if (f.failed()) {
                        try {
                            std::rethrow_exception(f.get_exception());
                        } catch (const std::system_error& e) {
                            int err = e.code().value();
                            /* If GSO triggered the failure, disable it for
                             * the rest of the run. xquic engine will
                             * retransmit lost packets. */
                            if (ctx->used_gso &&
                                (err == EIO || err == EINVAL ||
                                 err == ENOTSUP || err == EOPNOTSUPP)) {
                                gso_enabled = false;
                            }
                        } catch (...) {
                            /* swallow */
                        }
                    }
                    return seastar::make_ready_future<>();
                });
        });
    }

private:
    static seastar::socket_address sockaddr_to_socket_address(const struct sockaddr *addr, socklen_t len) {
        if (addr == nullptr) {
            throw std::invalid_argument("null sockaddr");
        }

        if (addr->sa_family == AF_INET) {
            if (len < static_cast<socklen_t>(sizeof(sockaddr_in))) {
                throw std::invalid_argument("invalid sockaddr_in length");
            }
            return seastar::socket_address(*reinterpret_cast<const sockaddr_in*>(addr));
        }

        if (addr->sa_family == AF_INET6) {
            if (len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
                throw std::invalid_argument("invalid sockaddr_in6 length");
            }
            return seastar::socket_address(*reinterpret_cast<const sockaddr_in6*>(addr));
        }

        throw std::invalid_argument("unsupported sockaddr family");
    }

    XquicSeastarSendQueue _queue;
};
