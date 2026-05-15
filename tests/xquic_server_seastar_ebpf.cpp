/**
 * xquic_server_seastar_ebpf.cpp — POSIX + eBPF Seastar QUIC server
 *
 * Phase 4 evaluation variant: uses SO_REUSEPORT + cBPF to distribute
 * incoming QUIC packets to per-shard sockets based on DCID[0].
 *
 * Key difference from the DPDK variant:
 *   - Every shard has its own bound UDP socket (via SO_REUSEPORT).
 *   - A classic BPF program steers packets at the kernel level.
 *   - No cross-shard submit_to() for packet routing.
 *   - Falls back to shard-0-only POSIX mode if eBPF attach fails.
 *
 * Build:
 *   cmake -DXQC_ENABLE_SEASTAR=ON -DXQC_ENABLE_SEASTAR_EBPF=ON ...
 *   cmake --build . --target xquic_server_seastar_ebpf
 */
#include "xquic_server_seastar_ebpf.hh"

#include "platform.h"
#include "user_conn.h"
#include "xqc_socket_opts.h"
#include <xquic/xqc_video_frame.h>
#include <sys/stat.h>

#include <algorithm>
#include <seastar/core/app-template.hh>
#include <seastar/core/sharded.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/abort_source.hh>
#include <seastar/core/signal.hh>
#include <seastar/core/smp.hh>
#include <csignal>

#include <boost/program_options.hpp>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <new>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace bpo = boost::program_options;

namespace {

using XqcHeadersPtr = std::unique_ptr<xqc_http_headers_t, decltype(&std::free)>;
constexpr char kTransportAlpn[] = "transport";
constexpr size_t kTransportFrameHeaderLen = 5;
constexpr size_t kTransportPreviewLimit = 128;
constexpr size_t kStreamBufferChunk = 64 * 1024;

enum TransportDemoFrameType : uint8_t {
    XQC_TRANSPORT_DEMO_FRAME_HELLO = 0x01,
    XQC_TRANSPORT_DEMO_FRAME_MESSAGE = 0x02,
    XQC_TRANSPORT_DEMO_FRAME_METADATA = 0x03,
    XQC_TRANSPORT_DEMO_FRAME_STATUS = 0x80,
    XQC_TRANSPORT_DEMO_FRAME_RESULT = 0x81,
    XQC_TRANSPORT_DEMO_FRAME_INFO = 0x82,
    XQC_TRANSPORT_DEMO_FRAME_ERROR = 0xff,
};

struct TransportDemoRequest {
    bool has_message = false;
    size_t frame_count = 0;
    std::string hello;
    std::string message;
    std::string metadata;
    std::string error;
};

const char kH3StatusName[] = ":status";
const char kH3StatusValue[] = "200";
const char kH3ContentLengthName[] = "content-length";
const char kH3ContentTypeName[] = "content-type";
const char kH3ContentTypeValue[] = "text/plain";

#include <sys/time.h>

uint64_t xqc_now_us() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

void socket_address_to_sockaddr(const seastar::socket_address& src,
                                struct sockaddr_storage& dst, socklen_t& len) {
    std::memset(&dst, 0, sizeof(dst));
    if (src.family() == AF_INET) {
        std::memcpy(&dst, &src.as_posix_sockaddr_in(), sizeof(sockaddr_in));
        len = sizeof(sockaddr_in);
        return;
    }
    if (src.family() == AF_INET6) {
        std::memcpy(&dst, &src.as_posix_sockaddr_in6(), sizeof(sockaddr_in6));
        len = sizeof(sockaddr_in6);
        return;
    }
    throw std::invalid_argument("unsupported socket family");
}

bool copy_conn_address(xqc_connection_t *conn, user_conn_t *user_conn, bool peer) {
    auto addr = std::unique_ptr<sockaddr_storage, decltype(&std::free)>(
        static_cast<sockaddr_storage*>(std::calloc(1, sizeof(sockaddr_storage))), &std::free);
    if (!addr) return false;
    socklen_t addr_len = 0;
    xqc_int_t ret = peer
        ? xqc_conn_get_peer_addr(conn, reinterpret_cast<sockaddr*>(addr.get()), sizeof(sockaddr_storage), &addr_len)
        : xqc_conn_get_local_addr(conn, reinterpret_cast<sockaddr*>(addr.get()), sizeof(sockaddr_storage), &addr_len);
    if (ret != XQC_OK) return false;
    if (peer) {
        std::free(user_conn->peer_addr);
        user_conn->peer_addr = reinterpret_cast<sockaddr*>(addr.release());
        user_conn->peer_addrlen = addr_len;
    } else {
        std::free(user_conn->local_addr);
        user_conn->local_addr = reinterpret_cast<sockaddr*>(addr.release());
        user_conn->local_addrlen = addr_len;
    }
    return true;
}

void release_user_conn(user_conn_t *user_conn) {
    if (user_conn == nullptr) return;
    std::free(user_conn->peer_addr);
    user_conn->peer_addr = nullptr;
    user_conn->peer_addrlen = 0;
    std::free(user_conn->local_addr);
    user_conn->local_addr = nullptr;
    user_conn->local_addrlen = 0;
}

void release_user_stream(user_stream_t *user_stream) {
    if (user_stream == nullptr) return;
    std::free(user_stream->send_body);
    user_stream->send_body = nullptr;
    user_stream->send_body_len = 0;
    user_stream->send_offset = 0;
    user_stream->send_body_max = 0;
    user_stream->send_fin_pending = 0;
    std::free(user_stream->recv_body);
    user_stream->recv_body = nullptr;
    user_stream->recv_body_len = 0;
    user_stream->recv_body_cap = 0;
    if (user_stream->recv_body_fp != nullptr) {
        std::fclose(user_stream->recv_body_fp);
        user_stream->recv_body_fp = nullptr;
    }
}

size_t round_up_stream_capacity(size_t required) {
    const size_t remainder = required % kStreamBufferChunk;
    if (remainder == 0) {
        return std::max(required, kStreamBufferChunk);
    }
    const size_t padding = kStreamBufferChunk - remainder;
    if (required > std::numeric_limits<size_t>::max() - padding) {
        return 0;
    }
    return required + padding;
}

void clear_send_buffer(user_stream_t *user_stream) {
    std::free(user_stream->send_body);
    user_stream->send_body = nullptr;
    user_stream->send_body_len = 0;
    user_stream->send_offset = 0;
    user_stream->send_body_max = 0;
    user_stream->send_fin_pending = 0;
}

bool has_pending_send(const user_stream_t *user_stream) {
    return user_stream != nullptr
        && (user_stream->send_offset < user_stream->send_body_len || user_stream->send_fin_pending);
}

bool ensure_stream_send_capacity(user_stream_t *user_stream, size_t extra_len) {
    if (user_stream->send_body_len + extra_len <= user_stream->send_body_max) return true;
    const size_t required = user_stream->send_body_len + extra_len;
    size_t new_cap = user_stream->send_body_max == 0 ? round_up_stream_capacity(required) : user_stream->send_body_max;
    if (new_cap == 0) return false;
    while (new_cap < required) {
        const size_t growth = std::max(new_cap / 2, kStreamBufferChunk);
        if (new_cap > std::numeric_limits<size_t>::max() - growth) return false;
        new_cap += growth;
    }
    void *new_buf = std::realloc(user_stream->send_body, new_cap);
    if (new_buf == nullptr) return false;
    user_stream->send_body = static_cast<char*>(new_buf);
    user_stream->send_body_max = new_cap;
    return true;
}

bool append_send_payload(user_stream_t *user_stream, const unsigned char *data, size_t data_len, bool fin) {
    if (data_len > 0) {
        if (!ensure_stream_send_capacity(user_stream, data_len)) return false;
        std::memcpy(user_stream->send_body + user_stream->send_body_len, data, data_len);
        user_stream->send_body_len += data_len;
    }
    if (fin) user_stream->send_fin_pending = 1;
    return true;
}

std::string format_socket_address(const sockaddr *addr, socklen_t addr_len) {
    if (addr == nullptr) return "unknown";
    char host[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    if (addr->sa_family == AF_INET && addr_len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *a = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &a->sin_addr, host, sizeof(host));
        port = ntohs(a->sin_port);
    } else if (addr->sa_family == AF_INET6 && addr_len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto *a = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof(host));
        port = ntohs(a->sin6_port);
    } else {
        return "unknown";
    }
    return std::string(host) + ":" + std::to_string(port);
}

bool ensure_stream_recv_capacity(user_stream_t *user_stream, size_t extra_len) {
    if (user_stream->recv_body_len + extra_len <= user_stream->recv_body_cap) return true;
    const size_t required = user_stream->recv_body_len + extra_len;
    size_t new_cap = user_stream->recv_body_cap == 0 ? round_up_stream_capacity(required) : user_stream->recv_body_cap;
    if (new_cap == 0) return false;
    while (new_cap < required) {
        const size_t growth = std::max(new_cap / 2, kStreamBufferChunk);
        if (new_cap > std::numeric_limits<size_t>::max() - growth) return false;
        new_cap += growth;
    }
    void *new_buf = std::realloc(user_stream->recv_body, new_cap);
    if (new_buf == nullptr) return false;
    user_stream->recv_body = static_cast<char*>(new_buf);
    user_stream->recv_body_cap = new_cap;
    return true;
}

bool append_stream_payload(user_stream_t *user_stream, const unsigned char *data, size_t data_len) {
    if (!ensure_stream_recv_capacity(user_stream, data_len)) return false;
    std::memcpy(user_stream->recv_body + user_stream->recv_body_len, data, data_len);
    user_stream->recv_body_len += data_len;
    return true;
}

void write_u32_be(unsigned char *out, uint32_t value) {
    out[0] = static_cast<unsigned char>((value >> 24) & 0xff);
    out[1] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[3] = static_cast<unsigned char>(value & 0xff);
}

size_t transport_frame_size(size_t payload_len) {
    return kTransportFrameHeaderLen + payload_len;
}

char *append_transport_frame(char *out, uint8_t type, const char *data, size_t len) {
    out[0] = static_cast<char>(type);
    write_u32_be(reinterpret_cast<unsigned char*>(out + 1), static_cast<uint32_t>(len));
    if (len > 0) {
        std::memcpy(out + kTransportFrameHeaderLen, data, len);
    }
    return out + kTransportFrameHeaderLen + len;
}

xqc_int_t drain_stream_send_buffer(xqc_stream_t *stream, user_stream_t *user_stream) {
    if (stream == nullptr || user_stream == nullptr) return -1;
    while (user_stream->send_offset < user_stream->send_body_len) {
        const size_t remaining = user_stream->send_body_len - user_stream->send_offset;
        const ssize_t sent = xqc_stream_send(
            stream,
            reinterpret_cast<unsigned char*>(user_stream->send_body + user_stream->send_offset),
            remaining,
            user_stream->send_fin_pending ? 1 : 0);
        if (sent == -XQC_EAGAIN) return 0;
        if (sent < 0) return -1;
        user_stream->send_offset += static_cast<size_t>(sent);
        user_stream->total_sent += static_cast<size_t>(sent);
    }
    if (user_stream->send_fin_pending && user_stream->send_body_len == 0) {
        const ssize_t sent = xqc_stream_send(stream, nullptr, 0, 1);
        if (sent == -XQC_EAGAIN) return 0;
        if (sent < 0) return -1;
    }
    clear_send_buffer(user_stream);
    return 0;
}

xqc_int_t drain_h3_send_buffer(xqc_h3_request_t *req, user_stream_t *user_stream) {
    if (req == nullptr || user_stream == nullptr) return -1;
    while (user_stream->send_offset < user_stream->send_body_len) {
        const size_t remaining = user_stream->send_body_len - user_stream->send_offset;
        const ssize_t sent = xqc_h3_request_send_body(
            req,
            reinterpret_cast<unsigned char*>(user_stream->send_body + user_stream->send_offset),
            remaining,
            user_stream->send_fin_pending ? 1 : 0);
        if (sent == -XQC_EAGAIN) return 0;
        if (sent < 0) return -1;
        user_stream->send_offset += static_cast<size_t>(sent);
        user_stream->total_sent += static_cast<size_t>(sent);
    }
    if (user_stream->send_fin_pending && user_stream->send_body_len == 0) {
        const ssize_t sent = xqc_h3_request_send_body(req, nullptr, 0, 1);
        if (sent == -XQC_EAGAIN) return 0;
        if (sent < 0) return -1;
    }
    clear_send_buffer(user_stream);
    return 0;
}

uint32_t read_u32_be(const unsigned char *data) {
    return (static_cast<uint32_t>(data[0]) << 24)
        | (static_cast<uint32_t>(data[1]) << 16)
        | (static_cast<uint32_t>(data[2]) << 8)
        | static_cast<uint32_t>(data[3]);
}

void append_u32_be(std::string& out, uint32_t value) {
    out.push_back(static_cast<char>((value >> 24) & 0xff));
    out.push_back(static_cast<char>((value >> 16) & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

void append_transport_frame(std::string& out, uint8_t type, const char *data, size_t len) {
    out.push_back(static_cast<char>(type));
    append_u32_be(out, static_cast<uint32_t>(len));
    if (len > 0) out.append(data, len);
}

void append_transport_frame(std::string& out, uint8_t type, const std::string& payload) {
    append_transport_frame(out, type, payload.data(), payload.size());
}

bool parse_transport_demo_request(const char *data, size_t len, TransportDemoRequest& request) {
    size_t offset = 0;
    while (offset < len) {
        if (len - offset < kTransportFrameHeaderLen) { request.error = "incomplete frame header"; return false; }
        const uint8_t type = static_cast<uint8_t>(data[offset]);
        const uint32_t payload_len = read_u32_be(reinterpret_cast<const unsigned char*>(data + offset + 1));
        offset += kTransportFrameHeaderLen;
        if (len - offset < payload_len) { request.error = "truncated frame payload"; return false; }
        const char *payload = data + offset;
        request.frame_count++;
        switch (type) {
        case XQC_TRANSPORT_DEMO_FRAME_HELLO:    request.hello.assign(payload, payload_len); break;
        case XQC_TRANSPORT_DEMO_FRAME_MESSAGE:  request.message.append(payload, payload_len); request.has_message = true; break;
        case XQC_TRANSPORT_DEMO_FRAME_METADATA: request.metadata.append(payload, payload_len); break;
        default: request.error = "unknown frame type: " + std::to_string(type); return false;
        }
        offset += payload_len;
    }
    if (!request.has_message) { request.error = "missing MESSAGE frame"; return false; }
    return true;
}

bool build_framed_response(xqc_stream_t *stream, user_stream_t *user_stream) {
    if (user_stream == nullptr || user_stream->user_conn == nullptr) return false;
    TransportDemoRequest request;
    const bool ok = parse_transport_demo_request(user_stream->recv_body, user_stream->recv_body_len, request);
    const std::string peer = format_socket_address(user_stream->user_conn->peer_addr, user_stream->user_conn->peer_addrlen);
    const std::string status = ok ? std::string("ok") : request.error;
    std::string stream_id_str = stream ? std::to_string(xqc_stream_id(stream)) : "h3";
    std::string info = "stream_id=" + stream_id_str + "\n"
        "peer=" + peer + "\n"
        "request_bytes=" + std::to_string(user_stream->recv_body_len) + "\n"
        "request_frames=" + std::to_string(request.frame_count) + "\n";
    const size_t status_len = status.size();
    const size_t info_len = info.size();
    const size_t result_len = ok ? request.message.size() : 0;
    if (status_len > std::numeric_limits<uint32_t>::max()
        || info_len > std::numeric_limits<uint32_t>::max()
        || result_len > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    const size_t total_size = transport_frame_size(status_len)
        + transport_frame_size(info_len)
        + (ok ? transport_frame_size(result_len) : 0);
    clear_send_buffer(user_stream);
    if (!ensure_stream_send_capacity(user_stream, total_size)) return false;
    char *cursor = user_stream->send_body;
    cursor = append_transport_frame(cursor,
        ok ? XQC_TRANSPORT_DEMO_FRAME_STATUS : XQC_TRANSPORT_DEMO_FRAME_ERROR,
        status.data(), status_len);
    cursor = append_transport_frame(cursor, XQC_TRANSPORT_DEMO_FRAME_INFO, info.data(), info_len);
    if (ok) {
        cursor = append_transport_frame(cursor, XQC_TRANSPORT_DEMO_FRAME_RESULT, request.message.data(), result_len);
    }
    user_stream->send_body_len = total_size;
    user_stream->send_offset = 0;
    user_stream->send_fin_pending = 1;
    return true;
}

bool process_video_frames(user_stream_t *user_stream, const std::string &output_dir) {
    if (!user_stream || !user_stream->recv_body || user_stream->recv_body_len == 0) {
        return true;
    }
    const unsigned char *data = reinterpret_cast<const unsigned char*>(user_stream->recv_body);
    size_t len = user_stream->recv_body_len;
    size_t offset = 0;
    while (offset + XQC_VIDEO_FRAME_HEADER_LEN <= len) {
        xqc_video_frame_header_t hdr;
        if (xqc_video_frame_header_decode(data + offset, len - offset, &hdr) != 0) break;
        if (offset + XQC_VIDEO_FRAME_HEADER_LEN + hdr.payload_len > len) break;
        if (!user_stream->recv_body_fp) {
            mkdir(output_dir.c_str(), 0755);
            char filename[256];
            snprintf(filename, sizeof(filename), "%s/cam_%u.h264", output_dir.c_str(), hdr.camera_id);
            user_stream->recv_body_fp = fopen(filename, "wb");
            if (!user_stream->recv_body_fp) {
                std::cerr << "[video] Cannot open " << filename << ": " << strerror(errno) << std::endl;
                return false;
            }
            std::cout << "[video] Recording camera " << hdr.camera_id << " to " << filename << std::endl;
        }
        const unsigned char start_code[] = {0x00, 0x00, 0x00, 0x01};
        fwrite(start_code, 1, sizeof(start_code), user_stream->recv_body_fp);
        fwrite(data + offset + XQC_VIDEO_FRAME_HEADER_LEN, 1, hdr.payload_len, user_stream->recv_body_fp);
        offset += XQC_VIDEO_FRAME_HEADER_LEN + hdr.payload_len;
        if (hdr.flags & XQC_VIDEO_FLAG_EOS) {
            std::cout << "[video] Camera " << hdr.camera_id << " EOS received" << std::endl;
            fclose(user_stream->recv_body_fp);
            user_stream->recv_body_fp = nullptr;
        }
    }
    if (offset > 0 && offset < len) {
        std::memmove(user_stream->recv_body, user_stream->recv_body + offset, len - offset);
        user_stream->recv_body_len -= offset;
    } else if (offset >= len) {
        user_stream->recv_body_len = 0;
    }
    return true;
}

} // namespace

/* ═══════════════════════════════════════════════════════════════════
 *  XquicSeastarServerEbpf — POSIX + eBPF reuseport implementation
 * ═══════════════════════════════════════════════════════════════════ */

XquicSeastarServerEbpf::XquicSeastarServerEbpf()
    : _engine_timer([this]() { on_engine_timer_expire(); })
    , _engine(nullptr)
    , _send_integration()
    , _packet_user_conn()
    , _port(0)
    , _stopping(false)
    , _send_flush_in_progress(false)
    , _echo_mode(false)
    , _video_mode(false)
    , _ebpf_mode(false)
    , _fallback_posix(false)
    , _reuseport_fd(-1) {
    _packet_user_conn.server = this;
}

XquicSeastarServerEbpf::~XquicSeastarServerEbpf() {
    if (_engine != nullptr) {
        xqc_engine_destroy(_engine);
        _engine = nullptr;
    }
}

void XquicSeastarServerEbpf::init_xquic_engine() {
    xqc_platform_init_env();

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        throw std::runtime_error("xqc_engine_get_default_config failed");
    }
    config.cfg_log_level = XQC_LOG_DEBUG;
    config.cid_negotiate = 1;

    xqc_engine_ssl_config_t ssl_config;
    std::memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.cert_file = _cert_path.data();
    ssl_config.private_key_file = _key_path.data();
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cb;
    std::memset(&engine_cb, 0, sizeof(engine_cb));
    engine_cb.set_event_timer = XquicSeastarServerEbpf::ss_set_event_timer;
    engine_cb.cid_generate_cb = XquicSeastarServerEbpf::ss_cid_generate;
    engine_cb.log_callbacks.xqc_log_write_err = [](xqc_log_level_t lvl, const void *buf, size_t size, void *) {
        (void)lvl;
        std::fwrite(buf, 1, size, stderr);
        std::fputc('\n', stderr);
    };

    xqc_transport_callbacks_t transport_cbs;
    std::memset(&transport_cbs, 0, sizeof(transport_cbs));
    transport_cbs.server_accept = XquicSeastarServerEbpf::ss_server_accept;
    transport_cbs.write_socket = XquicSeastarServerEbpf::ss_write_socket;
    transport_cbs.conn_update_cid_notify = XquicSeastarServerEbpf::ss_conn_update_cid_notify;

    _engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_config, &engine_cb, &transport_cbs, this);
    if (_engine == nullptr) {
        throw std::runtime_error("xqc_engine_create failed");
    }

    xqc_app_proto_callbacks_t transport_ap_cbs;
    std::memset(&transport_ap_cbs, 0, sizeof(transport_ap_cbs));
    transport_ap_cbs.conn_cbs.conn_create_notify = XquicSeastarServerEbpf::ss_conn_create_notify;
    transport_ap_cbs.conn_cbs.conn_close_notify = XquicSeastarServerEbpf::ss_conn_close_notify;
    transport_ap_cbs.stream_cbs.stream_create_notify = XquicSeastarServerEbpf::ss_stream_create_notify;
    transport_ap_cbs.stream_cbs.stream_write_notify = XquicSeastarServerEbpf::ss_stream_write_notify;
    transport_ap_cbs.stream_cbs.stream_read_notify = XquicSeastarServerEbpf::ss_stream_read_notify;
    transport_ap_cbs.stream_cbs.stream_close_notify = XquicSeastarServerEbpf::ss_stream_close_notify;
    if (xqc_engine_register_alpn(_engine, kTransportAlpn, sizeof(kTransportAlpn) - 1, &transport_ap_cbs, nullptr) != XQC_OK) {
        throw std::runtime_error("xqc_engine_register_alpn failed");
    }

    xqc_h3_callbacks_t h3_cbs;
    std::memset(&h3_cbs, 0, sizeof(h3_cbs));
    h3_cbs.h3c_cbs.h3_conn_create_notify = XquicSeastarServerEbpf::ss_h3_conn_create_notify;
    h3_cbs.h3c_cbs.h3_conn_close_notify = XquicSeastarServerEbpf::ss_h3_conn_close_notify;
    h3_cbs.h3r_cbs.h3_request_create_notify = XquicSeastarServerEbpf::ss_h3_request_create_notify;
    h3_cbs.h3r_cbs.h3_request_write_notify = XquicSeastarServerEbpf::ss_h3_request_write_notify;
    h3_cbs.h3r_cbs.h3_request_read_notify = XquicSeastarServerEbpf::ss_h3_request_read_notify;
    h3_cbs.h3r_cbs.h3_request_close_notify = XquicSeastarServerEbpf::ss_h3_request_close_notify;

    if (xqc_h3_ctx_init(_engine, &h3_cbs) != XQC_OK) {
        throw std::runtime_error("xqc_h3_ctx_init failed");
    }
}

seastar::future<> XquicSeastarServerEbpf::start_service(uint16_t port, const std::string& cert_path,
                                                         const std::string& key_path, bool echo_mode,
                                                         bool video_mode, const std::string& video_output_dir) {
    _echo_mode = echo_mode;
    _video_mode = video_mode;
    _video_output_dir = video_output_dir;
    try {
        _port = port;
        _cert_path = cert_path;
        _key_path = key_path;
        _stopping = false;
        _send_integration.clear();
        _packet_user_conn = {.server = this};

        init_xquic_engine();

        unsigned shard_count = seastar::smp::count;

        /*
         * eBPF reuseport mode:
         *   - Each shard receives a pre-created socket FD from main().
         *   - Wrap FD into Seastar's udp_channel using make_bound_datagram_channel.
         *   - Each shard has its own recv + send path. No cross-shard routing.
         *
         * Fallback POSIX mode (if _reuseport_fd == -1):
         *   - Same as original: shard 0 receives, routes via submit_to.
         */
        if (_reuseport_fd >= 0) {
            /* eBPF mode: take ownership of the pre-created reuseport FD via
             * Seastar's pollable_fd. This bypasses udp_channel entirely so we
             * have direct recvmsg/sendmsg control (and access to msg_control
             * for UDP_GRO/UDP_SEGMENT in later PRs). */
            _ebpf_mode = true;
            _fallback_posix = false;

            /* Cache local bind address for engine_packet_process. recvmsg
             * without IP_PKTINFO doesn't return the local addr, so we
             * synthesize it from the bound port. */
            std::memset(&_ebpf_local_addr, 0, sizeof(_ebpf_local_addr));
            auto* la4 = reinterpret_cast<struct sockaddr_in*>(&_ebpf_local_addr);
            la4->sin_family = AF_INET;
            la4->sin_addr.s_addr = htonl(INADDR_ANY);
            la4->sin_port = htons(_port);
            _ebpf_local_addrlen = sizeof(struct sockaddr_in);

            /* Wrap raw FD into pollable_fd. file_desc takes ownership and
             * will close() on destruction; we set _reuseport_fd = -1 to
             * prevent any double-close from external paths. */
            int fd = _reuseport_fd;
            _reuseport_fd = -1;

            /* PR3: enable UDP_GRO so recvmsg returns coalesced chunks with
             * SOL_UDP/UDP_GRO cmsg providing per-segment size. Apply
             * perf opts again in case the FD was created without them
             * (idempotent setsockopt). */
            xqc_apply_udp_perf_opts(fd, AF_INET, /*is_server=*/1);
            int gro_ret = xqc_enable_udp_gro(fd);
            _gso_enabled = (gro_ret == 0);  /* If GRO works, GSO usually does too */

            /* Bench knob: allow disabling GSO at runtime to compare CPU/throughput.
             * Set XQC_DISABLE_GSO=1 (or any non-empty non-"0" value) to force off. */
            if (const char* env = std::getenv("XQC_DISABLE_GSO");
                env && env[0] && !(env[0] == '0' && env[1] == '\0')) {
                _gso_enabled = false;
                std::cout << "[shard " << seastar::this_shard_id()
                          << "] GSO disabled via XQC_DISABLE_GSO" << std::endl;
            }

            _ebpf_pfd.emplace(seastar::file_desc::from_fd(fd));

            _receive_loop.emplace(
                seastar::with_gate(_background_ops, [this] {
                    return run_ebpf_receive_loop();
                }).handle_exception([this](std::exception_ptr ep) {
                    if (_stopping) return seastar::make_ready_future<>();
                    return seastar::make_exception_future<>(ep);
                })
            );
        } else {
            /* Fallback: original shard-0-only POSIX mode */
            _ebpf_mode = false;
            _fallback_posix = true;

            if (seastar::this_shard_id() == 0) {
                seastar::socket_address bind_addr = seastar::make_ipv4_address(seastar::ipv4_addr(port));
                _udp_channel.emplace(seastar::engine().net().make_bound_datagram_channel(bind_addr));

                _receive_loop.emplace(
                    seastar::with_gate(_background_ops, [this] {
                        return run_receive_loop();
                    }).handle_exception([this](std::exception_ptr ep) {
                        if (_stopping) return seastar::make_ready_future<>();
                        return seastar::make_exception_future<>(ep);
                    })
                );
            } else {
                /* Non-shard-0 in fallback: unbound send channel */
                _udp_channel.emplace(seastar::engine().net().make_unbound_datagram_channel(AF_INET));
            }
        }

        /* Stats printer — all shards */
        _stats_prev = {};
        _stats_timer.set_callback([this] { print_stats(); });
        _stats_timer.arm_periodic(std::chrono::seconds(2));

        std::cout << "[shard " << seastar::this_shard_id() << "] XQUIC engine initialized"
                  << (_ebpf_mode ? " [eBPF reuseport]" : " [POSIX fallback]")
                  << " recv+send"
                  << " (UDP port " << _port << ")"
                  << std::endl;
        return seastar::make_ready_future<>();

    } catch (...) {
        if (_udp_channel) {
            _udp_channel->close();
            _udp_channel.reset();
        }
        if (_ebpf_pfd) {
            try { _ebpf_pfd->shutdown(SHUT_RDWR); } catch (...) {}
            _ebpf_pfd.reset();
        }
        /* If init() failed before transferring _reuseport_fd into
         * _ebpf_pfd, close it here to avoid a leak. */
        if (_reuseport_fd >= 0) {
            ::close(_reuseport_fd);
            _reuseport_fd = -1;
        }
        if (_engine != nullptr) {
            xqc_engine_destroy(_engine);
            _engine = nullptr;
        }
        return seastar::make_exception_future<>(std::current_exception());
    }
}

seastar::future<> XquicSeastarServerEbpf::stop() {
    if (_stopping) return seastar::make_ready_future<>();
    _stopping = true;
    _engine_timer.cancel();
    _stats_timer.cancel();

    if (_udp_channel) {
        _udp_channel->shutdown_input();
        _udp_channel->shutdown_output();
    }
    if (_ebpf_pfd) {
        /* Wake up any pending recvmsg/sendmsg so the receive loop exits. */
        try { _ebpf_pfd->shutdown(SHUT_RDWR); } catch (...) {}
    }

    seastar::future<> receive_loop = seastar::make_ready_future<>();
    if (_receive_loop.has_value()) {
        receive_loop = std::move(_receive_loop.value());
        _receive_loop.reset();
    }

    return std::move(receive_loop)
        .handle_exception([this](std::exception_ptr ep) {
            if (_stopping) return seastar::make_ready_future<>();
            return seastar::make_exception_future<>(ep);
        })
        .then([this] { return _background_ops.close(); })
        .then([this] {
            _send_integration.clear();
            if (_udp_channel) {
                _udp_channel->close();
                _udp_channel.reset();
            }
            if (_ebpf_pfd) {
                _ebpf_pfd.reset();  /* file_desc dtor closes the fd */
            }
            if (_engine != nullptr) {
                xqc_engine_destroy(_engine);
                _engine = nullptr;
            }
            return seastar::make_ready_future<>();
        });
}

seastar::future<> XquicSeastarServerEbpf::run_receive_loop() {
    return seastar::repeat([this]() {
        if (_stopping || !_udp_channel) {
            return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
        }
        return _udp_channel->receive().then([this](seastar::net::udp_datagram datagram) {
            on_datagram(datagram);
            return seastar::stop_iteration::no;
        }).handle_exception([this](std::exception_ptr ep) {
            if (_stopping) {
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
            }
            try {
                std::rethrow_exception(ep);
            } catch (const std::exception& ex) {
                std::cerr << "[xquic-ebpf] receive loop exception: " << ex.what() << std::endl;
            } catch (...) {
                std::cerr << "[xquic-ebpf] receive loop unknown exception" << std::endl;
            }
            return seastar::make_exception_future<seastar::stop_iteration>(ep);
        });
    });
}

/*
 * eBPF mode receive loop: bypasses udp_channel and uses pollable_fd::recvmsg
 * directly so we can read SOL_UDP/UDP_GRO ancillary data and split coalesced
 * receives into per-QUIC-packet slices.
 */
seastar::future<> XquicSeastarServerEbpf::run_ebpf_receive_loop() {
    return seastar::repeat([this]() {
        if (_stopping || !_ebpf_pfd) {
            return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
        }

        struct RecvCtx {
            char buf[64 * 1024];
            struct sockaddr_storage peer;
            struct iovec iov;
            char cbuf[CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(64)];  // gso + padding
            struct msghdr msg;
        };
        auto ctx = std::make_unique<RecvCtx>();
        std::memset(&ctx->peer, 0, sizeof(ctx->peer));
        ctx->iov.iov_base = ctx->buf;
        ctx->iov.iov_len = sizeof(ctx->buf);
        std::memset(&ctx->cbuf, 0, sizeof(ctx->cbuf));
        std::memset(&ctx->msg, 0, sizeof(ctx->msg));
        ctx->msg.msg_name = &ctx->peer;
        ctx->msg.msg_namelen = sizeof(ctx->peer);
        ctx->msg.msg_iov = &ctx->iov;
        ctx->msg.msg_iovlen = 1;
        ctx->msg.msg_control = ctx->cbuf;
        ctx->msg.msg_controllen = sizeof(ctx->cbuf);

        auto* msg_ptr = &ctx->msg;
        return _ebpf_pfd->recvmsg(msg_ptr).then_wrapped(
            [this, ctx = std::move(ctx)](seastar::future<size_t> f) mutable {
                if (_stopping) {
                    return seastar::stop_iteration::yes;
                }
                if (f.failed()) {
                    try {
                        std::rethrow_exception(f.get_exception());
                    } catch (const std::exception& ex) {
                        std::cerr << "[xquic-ebpf] recvmsg: " << ex.what() << std::endl;
                    } catch (...) {
                        std::cerr << "[xquic-ebpf] recvmsg unknown exception" << std::endl;
                    }
                    return seastar::stop_iteration::no;
                }
                size_t n = f.get();
                if (n == 0) {
                    return seastar::stop_iteration::no;
                }
                if (_engine == nullptr) {
                    return seastar::stop_iteration::no;
                }

                /* Parse SOL_UDP/UDP_GRO cmsg for per-segment size; if absent,
                 * the whole buffer is one packet. */
                uint16_t gso_size = 0;
                for (struct cmsghdr* cm = CMSG_FIRSTHDR(&ctx->msg); cm != nullptr;
                     cm = CMSG_NXTHDR(&ctx->msg, cm)) {
                    if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO) {
                        std::memcpy(&gso_size, CMSG_DATA(cm), sizeof(gso_size));
                        break;
                    }
                }
                if (gso_size == 0 || gso_size > n) {
                    gso_size = static_cast<uint16_t>(n);
                }

                _stats.packets_recv++;
                _stats.bytes_recv += n;

                socklen_t peer_len = ctx->msg.msg_namelen;
                size_t off = 0;
                while (off < n) {
                    size_t seg = std::min<size_t>(gso_size, n - off);
                    process_packet_local(
                        reinterpret_cast<const unsigned char*>(ctx->buf) + off, seg,
                        ctx->peer, peer_len,
                        _ebpf_local_addr, _ebpf_local_addrlen);
                    off += seg;
                }

                return seastar::stop_iteration::no;
            });
    });
}

void XquicSeastarServerEbpf::on_datagram(seastar::net::udp_datagram& datagram) {
    if (_engine == nullptr) return;

    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;
    socklen_t peer_len = 0;
    socklen_t local_len = 0;

    try {
        socket_address_to_sockaddr(datagram.get_src(), peer_addr, peer_len);
    } catch (const std::exception& ex) {
        std::cerr << "[xquic-ebpf] failed to get peer address: " << ex.what() << std::endl;
        return;
    }

    try {
        socket_address_to_sockaddr(datagram.get_dst(), local_addr, local_len);
    } catch (...) {
        std::memset(&local_addr, 0, sizeof(local_addr));
        auto *addr4 = reinterpret_cast<struct sockaddr_in*>(&local_addr);
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = htonl(INADDR_ANY);
        addr4->sin_port = htons(_port);
        local_len = sizeof(struct sockaddr_in);
    }

    seastar::net::packet& packet = datagram.get_data();
    _stats.packets_recv++;
    _stats.bytes_recv += packet.len();

    unsigned shard_count = seastar::smp::count;

    for (auto& frag : packet.fragments()) {
        const unsigned char *data = reinterpret_cast<const unsigned char*>(frag.base);
        size_t len = frag.size;

        if (_ebpf_mode) {
            /*
             * eBPF mode: kernel already routed this packet to the correct
             * shard's socket. Process locally — no cross-shard dispatch needed.
             */
            process_packet_local(data, len, peer_addr, peer_len, local_addr, local_len);
        } else if (_fallback_posix && shard_count > 1 && seastar::this_shard_id() == 0) {
            /*
             * Fallback POSIX mode: shard 0 routes to target shard.
             */
            unsigned target = route_packet_to_shard(data, len);
            if (target != 0) {
                _stats.packets_routed++;
                auto buf = seastar::temporary_buffer<char>(frag.base, len);
                auto pa = peer_addr;
                auto pl = peer_len;
                auto la = local_addr;
                auto ll = local_len;
                (void)seastar::smp::submit_to(target, [this, buf = std::move(buf), pa, pl, la, ll]() mutable {
                    auto &local = _distributed->local();
                    local.deliver_packet(std::move(buf), pa, pl, la, ll);
                });
                continue;
            }
            process_packet_local(data, len, peer_addr, peer_len, local_addr, local_len);
        } else {
            process_packet_local(data, len, peer_addr, peer_len, local_addr, local_len);
        }
    }

    xqc_engine_finish_recv(_engine);
    schedule_send_flush();
}

unsigned XquicSeastarServerEbpf::route_packet_to_shard(const unsigned char *data, size_t len) {
    unsigned shard_count = seastar::smp::count;
    if (shard_count <= 1 || len == 0) return 0;

    xqc_cid_t dcid, scid;
    std::memset(&dcid, 0, sizeof(dcid));
    std::memset(&scid, 0, sizeof(scid));

    xqc_int_t rc = xqc_packet_parse_cid(&dcid, &scid, 8, data, len);
    if (rc == XQC_OK && dcid.cid_len > 0) {
        return dcid.cid_buf[0] % shard_count;
    }
    return 0;
}

void XquicSeastarServerEbpf::process_packet_local(const unsigned char *data, size_t len,
                                                    struct sockaddr_storage& peer_addr, socklen_t peer_len,
                                                    struct sockaddr_storage& local_addr, socklen_t local_len) {
    xqc_int_t rc = xqc_engine_packet_process(_engine, data, len,
                              reinterpret_cast<struct sockaddr*>(&local_addr), local_len,
                              reinterpret_cast<struct sockaddr*>(&peer_addr), peer_len,
                              xqc_now_us(), &_packet_user_conn);
    (void)rc;
}

void XquicSeastarServerEbpf::deliver_packet(seastar::temporary_buffer<char> data,
                                             struct sockaddr_storage peer_addr, socklen_t peer_len,
                                             struct sockaddr_storage local_addr, socklen_t local_len) {
    if (_engine == nullptr || _stopping) return;
    _stats.packets_recv++;
    _stats.bytes_recv += data.size();
    xqc_engine_packet_process(_engine,
                              reinterpret_cast<const unsigned char*>(data.get()), data.size(),
                              reinterpret_cast<struct sockaddr*>(&local_addr), local_len,
                              reinterpret_cast<struct sockaddr*>(&peer_addr), peer_len,
                              xqc_now_us(), &_packet_user_conn);
    xqc_engine_finish_recv(_engine);
    schedule_send_flush();
}

seastar::net::udp_channel& XquicSeastarServerEbpf::get_send_channel() {
    if (_udp_channel) return *_udp_channel;
    throw std::runtime_error("no send channel available on shard " + std::to_string(seastar::this_shard_id()));
}

void XquicSeastarServerEbpf::on_engine_timer_expire() {
    if (_engine != nullptr) {
        xqc_engine_main_logic(_engine);
        schedule_send_flush();
    }
}

ssize_t XquicSeastarServerEbpf::enqueue_send(const unsigned char *buf, size_t size,
                                              const struct sockaddr *peer_addr, socklen_t peer_addrlen) {
    if (_stopping) {
        errno = ESHUTDOWN;
        return -1;
    }

    ssize_t queued = _send_integration.enqueue_write(buf, size, peer_addr, peer_addrlen);
    if (queued < 0) return -1;

    try {
        schedule_send_flush();
        _stats.packets_sent++;
        _stats.bytes_sent += size;
        return queued;
    } catch (...) {
        errno = EINVAL;
        return -1;
    }
}

void XquicSeastarServerEbpf::schedule_send_flush() {
    if (_stopping || _send_flush_in_progress || _send_integration.empty()) return;
    if (_ebpf_mode) {
        if (!_ebpf_pfd) return;
    } else {
        if (!_udp_channel) return;
    }

    _send_flush_in_progress = true;
    (void)seastar::with_gate(_background_ops, [this] {
        return flush_send_queue();
    }).handle_exception([this](std::exception_ptr ep) {
        try {
            std::rethrow_exception(ep);
        } catch (const std::exception& ex) {
            std::cerr << "Seastar eBPF send flush failed: " << ex.what() << std::endl;
        } catch (...) {
            std::cerr << "Seastar eBPF send flush failed with unknown exception" << std::endl;
        }
        _send_integration.clear();
        return seastar::make_ready_future<>();
    }).finally([this] {
        _send_flush_in_progress = false;
        if (!_stopping && !_send_integration.empty()) {
            schedule_send_flush();
        }
    });
}

seastar::future<> XquicSeastarServerEbpf::flush_send_queue() {
    if (_stopping) return seastar::make_ready_future<>();
    try {
        if (_ebpf_mode && _ebpf_pfd) {
            /* PR3: GSO-aware flush; helper will reset _gso_enabled to false
             * if the kernel/NIC reports unsupported on first failure. */
            return _send_integration.flush_to_pollable_fd_with_gso(
                *_ebpf_pfd, _gso_enabled);
        }
        auto& ch = get_send_channel();
        return _send_integration.flush_to(ch).then([] {});
    } catch (const std::exception& ex) {
        std::cerr << "[xquic-ebpf] flush_send_queue: " << ex.what() << std::endl;
        return seastar::make_ready_future<>();
    }
}

void XquicSeastarServerEbpf::send_h3_response(user_stream_t *user_stream) {
    if (user_stream == nullptr || user_stream->h3_request == nullptr) return;
    xqc_h3_request_t *req = static_cast<xqc_h3_request_t*>(user_stream->h3_request);

    char content_length_buf[32];
    int cl_len = snprintf(content_length_buf, sizeof(content_length_buf), "%zu", user_stream->send_body_len);

    xqc_http_header_t resp_headers[] = {
        { {.iov_base = const_cast<char*>(kH3StatusName), .iov_len = sizeof(kH3StatusName) - 1},
          {.iov_base = const_cast<char*>(kH3StatusValue), .iov_len = sizeof(kH3StatusValue) - 1}, 0 },
        { {.iov_base = const_cast<char*>(kH3ContentTypeName), .iov_len = sizeof(kH3ContentTypeName) - 1},
          {.iov_base = const_cast<char*>(kH3ContentTypeValue), .iov_len = sizeof(kH3ContentTypeValue) - 1}, 0 },
        { {.iov_base = const_cast<char*>(kH3ContentLengthName), .iov_len = sizeof(kH3ContentLengthName) - 1},
          {.iov_base = content_length_buf, .iov_len = static_cast<size_t>(cl_len)}, 0 },
    };
    xqc_http_headers_t response_headers = {
        .headers = resp_headers,
        .count = sizeof(resp_headers) / sizeof(resp_headers[0]),
    };
    if (!user_stream->header_sent) {
        xqc_h3_request_send_headers(req, &response_headers, 0);
        user_stream->header_sent = 1;
        _stats.h3_responses++;
    }

    if (drain_h3_send_buffer(req, user_stream) < 0) {
        std::cerr << "[xquic-ebpf] send_h3_response: send body failed" << std::endl;
    }
}

/* ─── xquic callbacks ─────────────────────────────────────────── */

int XquicSeastarServerEbpf::on_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                                              const xqc_cid_t *cid, void *user_data) {
    (void)engine; (void)user_data;
    try {
        auto u_conn = std::make_unique<user_conn_t>();
        u_conn->server = this;
        if (cid != nullptr) u_conn->cid = *cid;
        if (!copy_conn_address(conn, u_conn.get(), true) || !copy_conn_address(conn, u_conn.get(), false)) {
            release_user_conn(u_conn.get());
            return -1;
        }
        _stats.conns_accepted++;
        xqc_conn_set_transport_user_data(conn, u_conn.release());
        return 0;
    } catch (const std::bad_alloc&) {
        return -1;
    }
}

void XquicSeastarServerEbpf::on_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                                        const xqc_cid_t *new_cid, void *user_data) {
    (void)conn; (void)retire_cid;
    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn != nullptr && new_cid != nullptr) u_conn->cid = *new_cid;
}

int XquicSeastarServerEbpf::on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                                    void *user_data, void *conn_proto_data) {
    (void)conn; (void)cid; (void)conn_proto_data;
    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn != nullptr) {
        u_conn->server = this;
    }
    return 0;
}

int XquicSeastarServerEbpf::on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                                   void *user_data, void *conn_proto_data) {
    (void)conn; (void)cid; (void)conn_proto_data;
    auto u_conn = std::unique_ptr<user_conn_t>(static_cast<user_conn_t*>(user_data));
    if (u_conn) {
        _stats.conns_closed++;
        release_user_conn(u_conn.get());
    }
    return 0;
}

xqc_int_t XquicSeastarServerEbpf::on_stream_create_notify(xqc_stream_t *stream, void *user_data) {
    (void)user_data;
    auto user_stream = std::make_unique<user_stream_t>();
    std::memset(user_stream.get(), 0, sizeof(user_stream_t));
    user_stream->stream = stream;
    user_stream->server = this;
    auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
    user_stream->user_conn = u_conn;
    user_stream->start_time = xqc_now_us();
    _stats.streams_created++;
    xqc_stream_set_user_data(stream, user_stream.release());
    return 0;
}

xqc_int_t XquicSeastarServerEbpf::on_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    auto *user_stream = static_cast<user_stream_t*>(user_data);
    if (user_stream == nullptr || !has_pending_send(user_stream)) return 0;
    return drain_stream_send_buffer(stream, user_stream);
}

xqc_int_t XquicSeastarServerEbpf::on_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    auto *user_stream = static_cast<user_stream_t*>(user_data);
    if (user_stream == nullptr) {
        user_stream = static_cast<user_stream_t*>(std::calloc(1, sizeof(user_stream_t)));
        if (user_stream == nullptr) return -1;
        user_stream->stream = stream;
        user_stream->server = this;
        user_stream->user_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        user_stream->start_time = xqc_now_us();
        xqc_stream_set_user_data(stream, user_stream);
        _stats.streams_created++;
    }

    if (has_pending_send(user_stream)) {
        const xqc_int_t pending_rc = drain_stream_send_buffer(stream, user_stream);
        if (pending_rc != 0 || has_pending_send(user_stream)) return pending_rc;
    }

    unsigned char buf[65536];
    unsigned char fin = 0;
    while (true) {
        ssize_t read = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (read <= 0) break;
        user_stream->total_recvd += static_cast<size_t>(read);

        if (_video_mode) {
            if (!append_stream_payload(user_stream, buf, static_cast<size_t>(read))) return -1;
            process_video_frames(user_stream, _video_output_dir);
            _stats.video_bytes_recvd += static_cast<size_t>(read);
        } else if (_echo_mode) {
            size_t offset = 0;
            while (offset < static_cast<size_t>(read)) {
                const int send_fin = fin ? 1 : 0;
                const ssize_t sent = xqc_stream_send(stream, buf + offset, static_cast<size_t>(read) - offset, send_fin);
                if (sent == -XQC_EAGAIN) {
                    if (!append_send_payload(user_stream, buf + offset, static_cast<size_t>(read) - offset, send_fin != 0)) {
                        return -1;
                    }
                    return 0;
                }
                if (sent < 0) return -1;
                offset += static_cast<size_t>(sent);
                user_stream->total_sent += static_cast<size_t>(sent);
            }
        } else {
            if (!append_stream_payload(user_stream, buf, static_cast<size_t>(read))) return -1;
        }

        if (fin) {
            if (!_echo_mode && !_video_mode) {
                if (!build_framed_response(stream, user_stream)) return -1;
                return drain_stream_send_buffer(stream, user_stream);
            }
            if (_video_mode) {
                _stats.video_streams_finished++;
            }
            break;
        }
    }
    return 0;
}

xqc_int_t XquicSeastarServerEbpf::on_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    (void)stream;
    auto user_stream = std::unique_ptr<user_stream_t>(static_cast<user_stream_t*>(user_data));
    if (user_stream) {
        _stats.streams_closed++;
        release_user_stream(user_stream.get());
    }
    return 0;
}

/* ─── H3 callbacks ────────────────────────────────────────────── */

int XquicSeastarServerEbpf::on_h3_request_create_notify(xqc_h3_request_t *req, void *strm_user_data) {
    auto *user_stream = static_cast<user_stream_t*>(std::calloc(1, sizeof(user_stream_t)));
    if (user_stream == nullptr) return -1;
    user_stream->h3_request = req;
    user_stream->is_h3 = 1;
    user_stream->server = this;
    auto *u_conn = static_cast<user_conn_t*>(xqc_h3_get_conn_user_data_by_request(req));
    user_stream->user_conn = u_conn;
    user_stream->start_time = xqc_now_us();
    xqc_h3_request_set_user_data(req, user_stream);
    _stats.h3_requests++;
    return 0;
}

int XquicSeastarServerEbpf::on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    (void)conn; (void)cid; (void)user_data;
    return 0;
}

int XquicSeastarServerEbpf::on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    (void)conn; (void)cid; (void)user_data;
    return 0;
}

xqc_int_t XquicSeastarServerEbpf::on_h3_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    auto *user_stream = static_cast<user_stream_t*>(user_data);
    if (user_stream == nullptr) return 0;

    if (has_pending_send(user_stream)) return drain_h3_send_buffer(req, user_stream);
    return 0;
}

xqc_int_t XquicSeastarServerEbpf::on_h3_request_read_notify(xqc_h3_request_t *req,
                                                              xqc_request_notify_flag_t flag, void *user_data) {
    auto *user_stream = static_cast<user_stream_t*>(user_data);
    if (user_stream == nullptr) return -1;

    if (has_pending_send(user_stream)) {
        const xqc_int_t pending_rc = drain_h3_send_buffer(req, user_stream);
        if (pending_rc != 0 || has_pending_send(user_stream)) return pending_rc;
    }

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        uint8_t fin = 0;
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(req, &fin);
        (void)headers;
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char body[65536];
        unsigned char fin = 0;
        while (true) {
            ssize_t read = xqc_h3_request_recv_body(req, body, sizeof(body), &fin);
            if (read <= 0) break;
            user_stream->total_recvd += static_cast<size_t>(read);

            if (_echo_mode) {
                size_t offset = 0;
                while (offset < static_cast<size_t>(read)) {
                    const int send_fin = fin ? 1 : 0;
                    const ssize_t sent = xqc_h3_request_send_body(req, body + offset, static_cast<size_t>(read) - offset, send_fin);
                    if (sent == -XQC_EAGAIN) {
                        if (!append_send_payload(user_stream, body + offset, static_cast<size_t>(read) - offset, send_fin != 0)) {
                            return -1;
                        }
                        return 0;
                    }
                    if (sent < 0) return -1;
                    offset += static_cast<size_t>(sent);
                    user_stream->total_sent += static_cast<size_t>(sent);
                }
            } else {
                if (!append_stream_payload(user_stream, body, static_cast<size_t>(read))) return -1;
            }

            if (fin) {
                if (!_echo_mode) {
                    if (!build_framed_response(nullptr, user_stream)) return -1;
                    send_h3_response(user_stream);
                }
                break;
            }
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        if (_echo_mode) {
            xqc_h3_request_send_body(req, nullptr, 0, 1);
        } else {
            if (!build_framed_response(nullptr, user_stream)) return -1;
            send_h3_response(user_stream);
        }
    }

    return 0;
}

xqc_int_t XquicSeastarServerEbpf::on_h3_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    (void)req;
    auto user_stream = std::unique_ptr<user_stream_t>(static_cast<user_stream_t*>(user_data));
    release_user_stream(user_stream.get());
    return 0;
}

/* ─── Static callback trampolines ─────────────────────────────── */

ssize_t XquicSeastarServerEbpf::ss_cid_generate(const xqc_cid_t *ori_cid, uint8_t *cid_buf,
                                                  size_t cid_buflen, void *engine_user_data) {
    (void)ori_cid; (void)engine_user_data;
    if (cid_buflen < 1) return -1;
    unsigned shard_id = seastar::this_shard_id();
    cid_buf[0] = static_cast<uint8_t>(shard_id);
    return 1;
}

void XquicSeastarServerEbpf::ss_set_event_timer(xqc_msec_t wake_after, void *user_data) {
    auto* server = static_cast<XquicSeastarServerEbpf*>(user_data);
    if (server == nullptr) return;
    server->_engine_timer.cancel();
    server->_engine_timer.arm(std::chrono::microseconds(wake_after));
}

ssize_t XquicSeastarServerEbpf::ss_write_socket(const unsigned char *buf, size_t size,
                                                  const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                                                  void *user_conn) {
    auto* u_conn = static_cast<user_conn_t*>(user_conn);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    if (server == nullptr) {
        errno = EINVAL;
        return -1;
    }
    return server->enqueue_send(buf, size, peer_addr, peer_addrlen);
}

int XquicSeastarServerEbpf::ss_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                                               const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_server_accept(engine, conn, cid, user_data);
}

void XquicSeastarServerEbpf::ss_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                                         const xqc_cid_t *new_cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    if (server != nullptr) server->on_conn_update_cid_notify(conn, retire_cid, new_cid, user_data);
}

int XquicSeastarServerEbpf::ss_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                                    void *user_data, void *conn_proto_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_conn_create_notify(conn, cid, user_data, conn_proto_data);
}

int XquicSeastarServerEbpf::ss_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                                   void *user_data, void *conn_proto_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    return server == nullptr ? 0 : server->on_conn_close_notify(conn, cid, user_data, conn_proto_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_stream_create_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServerEbpf*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) server = static_cast<XquicSeastarServerEbpf*>(u_conn->server);
    }
    return server == nullptr ? -1 : server->on_stream_create_notify(stream, user_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServerEbpf*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) server = static_cast<XquicSeastarServerEbpf*>(u_conn->server);
    }
    return server == nullptr ? -1 : server->on_stream_write_notify(stream, user_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServerEbpf*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) server = static_cast<XquicSeastarServerEbpf*>(u_conn->server);
    }
    return server == nullptr ? -1 : server->on_stream_read_notify(stream, user_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServerEbpf*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) server = static_cast<XquicSeastarServerEbpf*>(u_conn->server);
    }
    return server == nullptr ? 0 : server->on_stream_close_notify(stream, user_data);
}

int XquicSeastarServerEbpf::ss_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_h3_conn_create_notify(conn, cid, user_data);
}

int XquicSeastarServerEbpf::ss_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_conn_close_notify(conn, cid, user_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_h3_request_create_notify(xqc_h3_request_t *req, void *strm_user_data) {
    auto* u_conn = static_cast<user_conn_t*>(xqc_h3_get_conn_user_data_by_request(req));
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServerEbpf*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_h3_request_create_notify(req, strm_user_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_h3_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServerEbpf*>(user_stream->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_request_write_notify(req, user_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_h3_request_read_notify(xqc_h3_request_t *req,
                                                              xqc_request_notify_flag_t flag, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServerEbpf*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_h3_get_conn_user_data_by_request(req));
        if (u_conn != nullptr) server = static_cast<XquicSeastarServerEbpf*>(u_conn->server);
    }
    return server == nullptr ? -1 : server->on_h3_request_read_notify(req, flag, user_data);
}

xqc_int_t XquicSeastarServerEbpf::ss_h3_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServerEbpf*>(user_stream->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_request_close_notify(req, user_data);
}

/* ─── Stats ────────────────────────────────────────────────────── */

void XquicSeastarServerEbpf::print_stats() {
    auto &s = _stats;
    auto &p = _stats_prev;
    uint64_t d_bytes_recv = s.bytes_recv - p.bytes_recv;
    uint64_t d_bytes_sent = s.bytes_sent - p.bytes_sent;
    uint64_t d_pkts_recv = s.packets_recv - p.packets_recv;
    uint64_t d_pkts_sent = s.packets_sent - p.packets_sent;
    uint64_t active_conns = s.conns_accepted - s.conns_closed;
    uint64_t active_streams = s.streams_created - s.streams_closed;
    double recv_mbps = d_bytes_recv * 8.0 / 2.0 / 1e6;
    double send_mbps = d_bytes_sent * 8.0 / 2.0 / 1e6;

    std::cout << "[shard " << seastar::this_shard_id()
              << (_ebpf_mode ? " eBPF" : " POSIX") << "] conns=" << active_conns
              << " streams=" << active_streams
              << " total_accepted=" << s.conns_accepted
              << " | recv=" << recv_mbps << "Mbps (" << d_pkts_recv/2 << "pps)"
              << " send=" << send_mbps << "Mbps (" << d_pkts_sent/2 << "pps)";
    if (!_ebpf_mode && seastar::this_shard_id() == 0 && s.packets_routed > p.packets_routed) {
        std::cout << " routed=" << (s.packets_routed - p.packets_routed)/2 << "/s";
    }
    if (_video_mode) {
        uint64_t d_video = s.video_bytes_recvd - p.video_bytes_recvd;
        std::cout << " | video=" << d_video/2/1024 << "KB/s"
                  << " finished=" << s.video_streams_finished;
    }
    std::cout << std::endl;
    _stats_prev = s;
}

/* ═══════════════════════════════════════════════════════════════════
 *  main() — Creates reuseport sockets + attaches eBPF BEFORE Seastar
 *           starts its reactors, then distributes FDs to each shard.
 * ═══════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv) {
    seastar::app_template app;
    app.add_options()
        ("port,p", bpo::value<uint16_t>()->default_value(8443), "UDP port")
        ("cert", bpo::value<std::string>()->default_value("./server.crt"), "TLS certificate path")
        ("key", bpo::value<std::string>()->default_value("./server.key"), "TLS private key path")
        ("echo,e", bpo::bool_switch()->default_value(false), "Enable streaming echo mode")
        ("video,v", bpo::bool_switch()->default_value(false), "Enable video stream receiver mode")
        ("video-dir", bpo::value<std::string>()->default_value("./video_out"), "Output directory for recorded .h264 files")
        ("no-ebpf", bpo::bool_switch()->default_value(false), "Disable eBPF reuseport (fallback to shard-0 POSIX mode)");

    return app.run_deprecated(argc, argv, [&app] {
        auto& config = app.configuration();
        auto port = config["port"].as<uint16_t>();
        auto cert = config["cert"].as<std::string>();
        auto key = config["key"].as<std::string>();
        auto echo = config["echo"].as<bool>();
        auto video = config["video"].as<bool>();
        auto vdir = config["video-dir"].as<std::string>();
        auto no_ebpf = config["no-ebpf"].as<bool>();

        unsigned shard_count = seastar::smp::count;

        /*
         * Phase 1: Create SO_REUSEPORT sockets and attach eBPF program.
         * This happens on the Seastar app thread before shard reactors
         * are fully active, so we can safely create all sockets here.
         */
        std::shared_ptr<XquicEbpfReuseport> ebpf_dispatch;
        bool ebpf_ok = false;

        if (!no_ebpf && shard_count > 1) {
            try {
                ebpf_dispatch = std::make_shared<XquicEbpfReuseport>(shard_count);
                for (unsigned i = 0; i < shard_count; ++i) {
                    ebpf_dispatch->create_reuseport_socket(port, i);
                }
                ebpf_dispatch->attach_cbpf();
                ebpf_ok = true;
                std::cout << "[main] eBPF reuseport enabled: " << shard_count
                          << " sockets on port " << port << std::endl;
            } catch (const std::exception& ex) {
                std::cerr << "[main] eBPF reuseport failed: " << ex.what()
                          << " — falling back to shard-0 POSIX mode" << std::endl;
                ebpf_dispatch.reset();
                ebpf_ok = false;
            }
        } else if (shard_count <= 1) {
            std::cout << "[main] Single shard mode — eBPF not needed" << std::endl;
        } else {
            std::cout << "[main] eBPF disabled by --no-ebpf flag" << std::endl;
        }

        static seastar::sharded<XquicSeastarServerEbpf> server;

        /*
         * Register sharded::stop() as an at_exit handler.
         *
         * Why not .finally(server.stop()) on the main future chain?
         *   The default SIGINT/SIGTERM handler installed by app_template
         *   calls seastar::engine().exit(), which abruptly tears the
         *   reactor down without necessarily letting an outstanding
         *   keep_doing()'s .finally() run on a reactor thread. The
         *   sharded<> object is then destroyed from the static destructor
         *   on the main thread, where _instances is still non-empty,
         *   firing assert(_instances.empty()) and SIGABRT'ing the process.
         *
         *   engine().at_exit() callbacks are explicitly run and awaited
         *   by the reactor *before* it returns from app.run(), so
         *   server.stop() is guaranteed to complete and clear _instances
         *   prior to any static destruction.
         *
         * NOTE: ebpf_dispatch->fds() are NOT closed in the cleanup
         * handler. Per-shard XquicSeastarServerEbpf::init() wraps each
         * FD into a seastar::pollable_fd which takes ownership; the
         * file_desc destructor closes them. Closing again here would be
         * a double-close (and may close an unrelated recycled fd).
         */
        seastar::engine().at_exit([] {
            return server.stop();
        });

        /*
         * Explicit shutdown waiter.
         *
         * We previously used keep_doing(sleep(24h)) to keep the main
         * future alive — but seastar::sleep() returns a future that
         * will not resolve until its timer fires, even after
         * engine().exit() flips _stopping. As a result the outer
         * future never returned, at_exit() callbacks never ran, and
         * sharded<>::~sharded() asserted on a still-populated
         * _instances vector during static destruction.
         *
         * Instead we wait on an abortable source. SIGINT/SIGTERM
         * handlers request_abort() on it; sleep_abortable() returns
         * with sleep_aborted, the chain unwinds normally, then
         * at_exit runs server.stop() and the reactor exits cleanly.
         *
         * app_template installs a SIGINT handler by default, but we
         * register both signals here so the abort source — not just
         * the reactor — is notified, and so SIGTERM (used by bench
         * scripts) is honoured.
         */
        static seastar::abort_source shutdown_as;
        seastar::handle_signal(SIGINT, [] {
            std::cerr << "[main] SIGINT received" << std::endl;
            if (!shutdown_as.abort_requested()) {
                shutdown_as.request_abort();
            }
        });
        seastar::handle_signal(SIGTERM, [] {
            std::cerr << "[main] SIGTERM received" << std::endl;
            if (!shutdown_as.abort_requested()) {
                shutdown_as.request_abort();
            }
        });

        return server.start().then([port, cert, key, echo, video, vdir, ebpf_ok, ebpf_dispatch] {
            return server.invoke_on_all([port, cert, key, echo, video, vdir, ebpf_ok, ebpf_dispatch]
                                        (XquicSeastarServerEbpf &s) {
                s.set_distributed(&server);

                if (ebpf_ok && ebpf_dispatch) {
                    unsigned shard_id = seastar::this_shard_id();
                    s.set_reuseport_fd(ebpf_dispatch->fds()[shard_id]);
                }

                return s.start_service(port, cert, key, echo, video, vdir);
            });
        }).then([ebpf_dispatch] {
            (void)ebpf_dispatch;  /* keep handle alive until shutdown */
            std::cout << "Seastar XQUIC eBPF server ready (" << seastar::smp::count << " shards)" << std::endl;
            return seastar::sleep_abortable(std::chrono::hours(24 * 365), shutdown_as)
                .handle_exception_type([] (const seastar::sleep_aborted &) {
                    std::cout << "[main] shutdown signal received, stopping..." << std::endl;
                });
        });
    });
}
