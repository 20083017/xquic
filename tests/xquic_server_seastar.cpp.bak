#include "xquic_server_seastar.hh"

#include "platform.h"
#include "user_conn.h"
#include <xquic/xqc_video_frame.h>
#include <sys/stat.h>

#include <algorithm>
#include <seastar/core/app-template.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>

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
#include <stdexcept>
#include <utility>

namespace bpo = boost::program_options;

namespace {

using XqcHeadersPtr = std::unique_ptr<xqc_http_headers_t, decltype(&std::free)>;
constexpr char kTransportAlpn[] = "transport";
constexpr size_t kTransportFrameHeaderLen = 5;
constexpr size_t kTransportPreviewLimit = 128;

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
    /* Must use gettimeofday to match xquic's internal xqc_now() clock source */
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
    if (!addr) {
        return false;
    }

    socklen_t addr_len = 0;
    xqc_int_t ret = peer
        ? xqc_conn_get_peer_addr(conn, reinterpret_cast<sockaddr*>(addr.get()), sizeof(sockaddr_storage), &addr_len)
        : xqc_conn_get_local_addr(conn, reinterpret_cast<sockaddr*>(addr.get()), sizeof(sockaddr_storage), &addr_len);
    if (ret != XQC_OK) {
        return false;
    }

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
    if (user_conn == nullptr) {
        return;
    }

    std::free(user_conn->peer_addr);
    user_conn->peer_addr = nullptr;
    user_conn->peer_addrlen = 0;
    std::free(user_conn->local_addr);
    user_conn->local_addr = nullptr;
    user_conn->local_addrlen = 0;
}

void release_user_stream(user_stream_t *user_stream) {
    if (user_stream == nullptr) {
        return;
    }

    std::free(user_stream->send_body);
    user_stream->send_body = nullptr;
    user_stream->send_body_len = 0;
    user_stream->send_offset = 0;
    std::free(user_stream->recv_body);
    user_stream->recv_body = nullptr;
    user_stream->recv_body_len = 0;
    user_stream->recv_body_cap = 0;
    if (user_stream->recv_body_fp != nullptr) {
        std::fclose(user_stream->recv_body_fp);
        user_stream->recv_body_fp = nullptr;
    }
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
    if (user_stream->recv_body_len + extra_len <= user_stream->recv_body_cap) {
        return true;
    }
    size_t new_cap = user_stream->recv_body_cap == 0 ? 65536 : user_stream->recv_body_cap;
    while (new_cap < user_stream->recv_body_len + extra_len) {
        new_cap *= 2;
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

    std::string response;
    append_transport_frame(response,
        ok ? XQC_TRANSPORT_DEMO_FRAME_STATUS : XQC_TRANSPORT_DEMO_FRAME_ERROR,
        ok ? std::string("ok") : request.error);

    std::string stream_id_str = stream ? std::to_string(xqc_stream_id(stream)) : "h3";
    std::string info = "stream_id=" + stream_id_str + "\n"
        "peer=" + peer + "\n"
        "request_bytes=" + std::to_string(user_stream->recv_body_len) + "\n"
        "request_frames=" + std::to_string(request.frame_count) + "\n";
    append_transport_frame(response, XQC_TRANSPORT_DEMO_FRAME_INFO, info);

    // Echo the message back as result
    if (ok) {
        append_transport_frame(response, XQC_TRANSPORT_DEMO_FRAME_RESULT, request.message);
    }

    auto buffer = static_cast<char*>(std::malloc(response.size()));
    if (!buffer) return false;
    std::memcpy(buffer, response.data(), response.size());
    std::free(user_stream->send_body);
    user_stream->send_body = buffer;
    user_stream->send_body_len = response.size();
    user_stream->send_offset = 0;
    return true;
}

/* ─── Video stream receiver ───────────────────────────────────── */

/**
 * Process video frame data accumulated in user_stream->recv_body.
 * Parses [16B header][payload] frames and writes NAL payloads to
 * an Annex-B .h264 file.  Uses recv_body as a reassembly buffer.
 *
 * recv_body_fp is opened lazily on first frame.
 */
bool process_video_frames(user_stream_t *user_stream, const std::string &output_dir) {
    if (!user_stream || !user_stream->recv_body || user_stream->recv_body_len == 0) {
        return true; /* nothing to process */
    }

    const unsigned char *data = reinterpret_cast<const unsigned char*>(user_stream->recv_body);
    size_t len = user_stream->recv_body_len;
    size_t offset = 0;

    while (offset + XQC_VIDEO_FRAME_HEADER_LEN <= len) {
        xqc_video_frame_header_t hdr;
        if (xqc_video_frame_header_decode(data + offset, len - offset, &hdr) != 0) {
            break; /* incomplete header — wait for more data */
        }

        if (offset + XQC_VIDEO_FRAME_HEADER_LEN + hdr.payload_len > len) {
            break; /* incomplete payload — wait for more data */
        }

        /* Open output file lazily: output_dir/cam_<camera_id>.h264 */
        if (!user_stream->recv_body_fp) {
            mkdir(output_dir.c_str(), 0755);
            char filename[256];
            snprintf(filename, sizeof(filename), "%s/cam_%u.h264",
                     output_dir.c_str(), hdr.camera_id);
            user_stream->recv_body_fp = fopen(filename, "wb");
            if (!user_stream->recv_body_fp) {
                std::cerr << "[video] Cannot open " << filename << ": " << strerror(errno) << std::endl;
                return false;
            }
            std::cout << "[video] Recording camera " << hdr.camera_id
                      << " to " << filename << std::endl;
        }

        /* Write Annex-B start code + NAL payload */
        const unsigned char start_code[] = {0x00, 0x00, 0x00, 0x01};
        fwrite(start_code, 1, sizeof(start_code), user_stream->recv_body_fp);
        fwrite(data + offset + XQC_VIDEO_FRAME_HEADER_LEN, 1, hdr.payload_len,
               user_stream->recv_body_fp);

        offset += XQC_VIDEO_FRAME_HEADER_LEN + hdr.payload_len;

        if (hdr.flags & XQC_VIDEO_FLAG_EOS) {
            std::cout << "[video] Camera " << hdr.camera_id << " EOS received" << std::endl;
            fclose(user_stream->recv_body_fp);
            user_stream->recv_body_fp = nullptr;
        }
    }

    /* Compact: remove consumed bytes from recv_body */
    if (offset > 0 && offset < len) {
        std::memmove(user_stream->recv_body, user_stream->recv_body + offset, len - offset);
        user_stream->recv_body_len -= offset;
    } else if (offset >= len) {
        user_stream->recv_body_len = 0;
    }

    return true;
}

} // namespace

XquicSeastarServer::XquicSeastarServer()
    : _engine_timer([this]() { on_engine_timer_expire(); })
    , _engine(nullptr)
    , _send_integration()
    , _packet_user_conn()
    , _port(0)
    , _stopping(false)
    , _send_flush_in_progress(false)
    , _echo_mode(false)
    , _video_mode(false) {
    _packet_user_conn.server = this;
}

XquicSeastarServer::~XquicSeastarServer() {
    if (_engine != nullptr) {
        xqc_engine_destroy(_engine);
        _engine = nullptr;
    }
}

void XquicSeastarServer::init_xquic_engine() {
    xqc_platform_init_env();

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        throw std::runtime_error("xqc_engine_get_default_config failed");
    }
    config.cfg_log_level = XQC_LOG_DEBUG;

    xqc_engine_ssl_config_t ssl_config;
    std::memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.cert_file = _cert_path.data();
    ssl_config.private_key_file = _key_path.data();
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cb;
    std::memset(&engine_cb, 0, sizeof(engine_cb));
    engine_cb.set_event_timer = XquicSeastarServer::ss_set_event_timer;
    engine_cb.log_callbacks.xqc_log_write_err = [](xqc_log_level_t lvl, const void *buf, size_t size, void *) {
        (void)lvl;
        std::fwrite(buf, 1, size, stderr);
        std::fputc('\n', stderr);
    };

    xqc_transport_callbacks_t transport_cbs;
    std::memset(&transport_cbs, 0, sizeof(transport_cbs));
    transport_cbs.server_accept = XquicSeastarServer::ss_server_accept;
    transport_cbs.write_socket = XquicSeastarServer::ss_write_socket;
    transport_cbs.conn_update_cid_notify = XquicSeastarServer::ss_conn_update_cid_notify;

    _engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_config, &engine_cb, &transport_cbs, this);
    if (_engine == nullptr) {
        throw std::runtime_error("xqc_engine_create failed");
    }

    xqc_app_proto_callbacks_t transport_ap_cbs;
    std::memset(&transport_ap_cbs, 0, sizeof(transport_ap_cbs));
    transport_ap_cbs.conn_cbs.conn_create_notify = XquicSeastarServer::ss_conn_create_notify;
    transport_ap_cbs.conn_cbs.conn_close_notify = XquicSeastarServer::ss_conn_close_notify;
    transport_ap_cbs.stream_cbs.stream_create_notify = XquicSeastarServer::ss_stream_create_notify;
    transport_ap_cbs.stream_cbs.stream_write_notify = XquicSeastarServer::ss_stream_write_notify;
    transport_ap_cbs.stream_cbs.stream_read_notify = XquicSeastarServer::ss_stream_read_notify;
    transport_ap_cbs.stream_cbs.stream_close_notify = XquicSeastarServer::ss_stream_close_notify;
    if (xqc_engine_register_alpn(_engine, kTransportAlpn, sizeof(kTransportAlpn) - 1, &transport_ap_cbs, nullptr) != XQC_OK) {
        throw std::runtime_error("xqc_engine_register_alpn failed");
    }

    xqc_h3_callbacks_t h3_cbs;
    std::memset(&h3_cbs, 0, sizeof(h3_cbs));
    h3_cbs.h3c_cbs.h3_conn_create_notify = XquicSeastarServer::ss_h3_conn_create_notify;
    h3_cbs.h3c_cbs.h3_conn_close_notify = XquicSeastarServer::ss_h3_conn_close_notify;
    h3_cbs.h3r_cbs.h3_request_write_notify = XquicSeastarServer::ss_h3_request_write_notify;
    h3_cbs.h3r_cbs.h3_request_read_notify = XquicSeastarServer::ss_h3_request_read_notify;
    h3_cbs.h3r_cbs.h3_request_close_notify = XquicSeastarServer::ss_h3_request_close_notify;

    if (xqc_h3_ctx_init(_engine, &h3_cbs) != XQC_OK) {
        throw std::runtime_error("xqc_h3_ctx_init failed");
    }
}

seastar::future<> XquicSeastarServer::start(uint16_t port, const std::string& cert_path, const std::string& key_path,
                                            bool echo_mode, bool video_mode, const std::string& video_output_dir) {
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

        seastar::socket_address bind_addr = seastar::make_ipv4_address(seastar::ipv4_addr(port));
        _udp_channel.emplace(seastar::engine().net().make_bound_datagram_channel(bind_addr));

        _receive_loop.emplace(
            seastar::with_gate(_background_ops, [this] {
                return run_receive_loop();
            }).handle_exception([this](std::exception_ptr ep) {
                if (_stopping) {
                    return seastar::make_ready_future<>();
                }
                return seastar::make_exception_future<>(ep);
            })
        );

        /* Start periodic stats printer (every 2 seconds) */
        _stats_prev = {};
        _stats_timer.set_callback([this] { print_stats(); });
        _stats_timer.arm_periodic(std::chrono::seconds(2));

        std::cout << "Seastar XQUIC server listening on UDP port " << _port << std::endl;
        return seastar::make_ready_future<>();

    } catch (...) {
        if (_udp_channel) {
            _udp_channel->close();
            _udp_channel.reset();
        }
        if (_engine != nullptr) {
            xqc_engine_destroy(_engine);
            _engine = nullptr;
        }
        return seastar::make_exception_future<>(std::current_exception());
    }
}

seastar::future<> XquicSeastarServer::stop() {
    if (_stopping) {
        return seastar::make_ready_future<>();
    }

    _stopping = true;
    _engine_timer.cancel();
    _stats_timer.cancel();

    if (_udp_channel) {
        _udp_channel->shutdown_input();
        _udp_channel->shutdown_output();
    }

    seastar::future<> receive_loop = seastar::make_ready_future<>();
    if (_receive_loop.has_value()) {
        receive_loop = std::move(_receive_loop.value());
        _receive_loop.reset();
    }

    return std::move(receive_loop)
        .handle_exception([this](std::exception_ptr ep) {
            if (_stopping) {
                return seastar::make_ready_future<>();
            }
            return seastar::make_exception_future<>(ep);
        })
        .then([this] {
            return _background_ops.close();
        })
        .then([this] {
            _send_integration.clear();
            if (_udp_channel) {
                _udp_channel->close();
                _udp_channel.reset();
            }
            if (_engine != nullptr) {
                xqc_engine_destroy(_engine);
                _engine = nullptr;
            }
            return seastar::make_ready_future<>();
        });
}

seastar::future<> XquicSeastarServer::run_receive_loop() {
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
                std::cerr << "[xquic] receive loop exception: " << ex.what() << std::endl;
            } catch (...) {
                std::cerr << "[xquic] receive loop unknown exception" << std::endl;
            }
            return seastar::make_exception_future<seastar::stop_iteration>(ep);
        });
    });
}

void XquicSeastarServer::on_datagram(seastar::net::udp_datagram& datagram) {
    if (_engine == nullptr) {
        return;
    }

    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;
    socklen_t peer_len = 0;
    socklen_t local_len = 0;

    try {
        socket_address_to_sockaddr(datagram.get_src(), peer_addr, peer_len);
    } catch (const std::exception& ex) {
        std::cerr << "[xquic] failed to get peer address: " << ex.what() << std::endl;
        return;
    }

    // Seastar POSIX stack may not provide destination address via get_dst().
    // Fall back to the server's own bind address.
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
    // std::cout << "[xquic] recv " << packet.len() << " bytes from "
              // << datagram.get_src() << std::endl;

    for (auto& frag : packet.fragments()) {
        xqc_int_t rc = xqc_engine_packet_process(_engine,
                                  reinterpret_cast<const unsigned char*>(frag.base),
                                  frag.size,
                                  reinterpret_cast<struct sockaddr*>(&local_addr),
                                  local_len,
                                  reinterpret_cast<struct sockaddr*>(&peer_addr),
                                  peer_len,
                                  xqc_now_us(),
                                  &_packet_user_conn);
        // std::cout << "[xquic] packet_process rc=" << rc << " frag_size=" << frag.size << std::endl;
    }

    xqc_engine_finish_recv(_engine);
    // std::cout << "[xquic] finish_recv done, send_queue_empty=" << _send_integration.empty() << std::endl;
    schedule_send_flush();
}

void XquicSeastarServer::on_engine_timer_expire() {
    if (_engine != nullptr) {
        // std::cout << "[xquic] engine_timer_expire" << std::endl;
        xqc_engine_main_logic(_engine);
        schedule_send_flush();
    }
}

ssize_t XquicSeastarServer::enqueue_send(const unsigned char *buf, size_t size,
                                         const struct sockaddr *peer_addr, socklen_t peer_addrlen) {
    if (_stopping || !_udp_channel) {
        std::cerr << "[xquic] enqueue_send: stopping or no channel" << std::endl;
        errno = ESHUTDOWN;
        return -1;
    }

    ssize_t queued = _send_integration.enqueue_write(buf, size, peer_addr, peer_addrlen);
    // std::cout << "[xquic] enqueue_send: size=" << size << " queued=" << queued
              // << " queue_empty=" << _send_integration.empty() << std::endl;
    if (queued < 0) {
        std::cerr << "[xquic] enqueue_send: enqueue_write failed" << std::endl;
        return -1;
    }

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

void XquicSeastarServer::schedule_send_flush() {
    if (_stopping || !_udp_channel || _send_flush_in_progress || _send_integration.empty()) {
        return;
    }

    // std::cout << "[xquic] schedule_send_flush: starting flush" << std::endl;
    _send_flush_in_progress = true;
    (void)seastar::with_gate(_background_ops, [this] {
        return flush_send_queue();
    }).handle_exception([this](std::exception_ptr ep) {
        try {
            std::rethrow_exception(ep);
        } catch (const std::exception& ex) {
            std::cerr << "Seastar send flush failed: " << ex.what() << std::endl;
        } catch (...) {
            std::cerr << "Seastar send flush failed with unknown exception" << std::endl;
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

seastar::future<> XquicSeastarServer::flush_send_queue() {
    if (_stopping || !_udp_channel) {
        return seastar::make_ready_future<>();
    }

    // std::cout << "[xquic] flush_send_queue: flushing" << std::endl;
    return _send_integration.flush_to(*_udp_channel).then([] {
        // std::cout << "[xquic] flush_send_queue: done" << std::endl;
    });
}

void XquicSeastarServer::send_h3_response(user_stream_t *user_stream) {
    if (user_stream == nullptr || user_stream->h3_request == nullptr) {
        return;
    }

    xqc_h3_request_t *req = static_cast<xqc_h3_request_t*>(user_stream->h3_request);

    // Send headers with content-length
    char content_length_buf[32];
    int cl_len = snprintf(content_length_buf, sizeof(content_length_buf), "%zu", user_stream->send_body_len);

    xqc_http_header_t resp_headers[] = {
        {
            {.iov_base = const_cast<char*>(kH3StatusName), .iov_len = sizeof(kH3StatusName) - 1},
            {.iov_base = const_cast<char*>(kH3StatusValue), .iov_len = sizeof(kH3StatusValue) - 1},
            0
        },
        {
            {.iov_base = const_cast<char*>(kH3ContentTypeName), .iov_len = sizeof(kH3ContentTypeName) - 1},
            {.iov_base = const_cast<char*>(kH3ContentTypeValue), .iov_len = sizeof(kH3ContentTypeValue) - 1},
            0
        },
        {
            {.iov_base = const_cast<char*>(kH3ContentLengthName), .iov_len = sizeof(kH3ContentLengthName) - 1},
            {.iov_base = content_length_buf, .iov_len = static_cast<size_t>(cl_len)},
            0
        },
    };
    xqc_http_headers_t response_headers = {
        .headers = resp_headers,
        .count = sizeof(resp_headers) / sizeof(resp_headers[0]),
    };
    xqc_h3_request_send_headers(req, &response_headers, 0);
    user_stream->header_sent = 1;
    _stats.h3_responses++;

    // Send body with FIN
    if (user_stream->send_body && user_stream->send_body_len > 0) {
        xqc_h3_request_send_body(req,
            reinterpret_cast<unsigned char*>(user_stream->send_body),
            user_stream->send_body_len, 1);
        user_stream->total_sent += user_stream->send_body_len;
        std::free(user_stream->send_body);
        user_stream->send_body = nullptr;
        user_stream->send_body_len = 0;
    } else {
        xqc_h3_request_send_body(req, nullptr, 0, 1);
    }
}

int XquicSeastarServer::on_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                                         const xqc_cid_t *cid, void *user_data) {
    (void)engine;
    (void)user_data;

    // std::cout << "[xquic] server_accept called" << std::endl;

    try {
        auto u_conn = std::make_unique<user_conn_t>();
        u_conn->server = this;
        if (cid != nullptr) {
            u_conn->cid = *cid;
        }
        if (!copy_conn_address(conn, u_conn.get(), true) || !copy_conn_address(conn, u_conn.get(), false)) {
            std::cerr << "[xquic] server_accept: copy_conn_address failed" << std::endl;
            release_user_conn(u_conn.get());
            return -1;
        }
        _stats.conns_accepted++;
        xqc_conn_set_transport_user_data(conn, u_conn.release());
        // std::cout << "[xquic] server_accept: connection accepted" << std::endl;
        return 0;

    } catch (const std::bad_alloc&) {
        std::cerr << "[xquic] server_accept: bad_alloc" << std::endl;
        return -1;
    }
}

void XquicSeastarServer::on_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                                   const xqc_cid_t *new_cid, void *user_data) {
    (void)conn;
    (void)retire_cid;
    // std::cout << "[xquic] conn_update_cid_notify" << std::endl;

    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn != nullptr && new_cid != nullptr) {
        u_conn->cid = *new_cid;
    }
}

int XquicSeastarServer::on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                              void *user_data, void *conn_proto_data) {
    (void)conn;
    (void)conn_proto_data;
    // std::cout << "[xquic] conn_create_notify user_data=" << user_data << std::endl;

    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn == nullptr) {
        std::cerr << "[xquic] conn_create_notify: user_data is NULL!" << std::endl;
        return -1;
    }

    if (cid != nullptr) {
        u_conn->cid = *cid;
    }
    return 0;
}

int XquicSeastarServer::on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                             void *user_data, void *conn_proto_data) {
    (void)conn;
    (void)cid;
    (void)conn_proto_data;
    // std::cout << "[xquic] conn_close_notify" << std::endl;
    _stats.conns_closed++;

    auto u_conn = std::unique_ptr<user_conn_t>(static_cast<user_conn_t*>(user_data));
    release_user_conn(u_conn.get());
    return 0;
}

xqc_int_t XquicSeastarServer::on_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *user_stream = static_cast<user_stream_t*>(user_data);
    if (stream == nullptr || user_stream == nullptr || user_stream->send_body == nullptr) {
        return 0;
    }

    // Drain pending send buffer
    while (user_stream->send_offset < user_stream->send_body_len) {
        const size_t remaining = user_stream->send_body_len - user_stream->send_offset;
        // In framed mode, set FIN on last byte; in echo mode, FIN is set per-chunk in read_notify
        int fin_flag = _echo_mode ? 0 : 1;
        const ssize_t sent = xqc_stream_send(stream,
            reinterpret_cast<unsigned char*>(user_stream->send_body + user_stream->send_offset), remaining, fin_flag);
        if (sent == -XQC_EAGAIN) {
            return 0;
        }
        if (sent < 0) {
            std::cerr << "[xquic] stream_write_notify: send error=" << sent << std::endl;
            return -1;
        }

        user_stream->send_offset += static_cast<size_t>(sent);
        user_stream->total_sent += static_cast<size_t>(sent);
    }

    // Pending buffer fully drained, free it
    std::free(user_stream->send_body);
    user_stream->send_body = nullptr;
    user_stream->send_body_len = 0;
    user_stream->send_offset = 0;

    return 0;
}

xqc_int_t XquicSeastarServer::on_stream_create_notify(xqc_stream_t *stream, void *user_data) {
    (void)user_data;
    // std::cout << "[xquic] stream_create_notify: stream_id=" << xqc_stream_id(stream) << std::endl;
    try {
        auto owned_stream = std::make_unique<user_stream_t>();
        owned_stream->server = this;
        owned_stream->stream = stream;
        owned_stream->user_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        xqc_stream_set_user_data(stream, owned_stream.get());
        owned_stream.release();
        _stats.streams_created++;
        return 0;

    } catch (const std::bad_alloc&) {
        std::cerr << "[xquic] stream_create_notify: bad_alloc" << std::endl;
        return -1;
    }
}

xqc_int_t XquicSeastarServer::on_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *user_stream = static_cast<user_stream_t*>(user_data);
    if (stream == nullptr || user_stream == nullptr) {
        std::cerr << "[xquic] stream_read_notify: null stream or user_stream" << std::endl;
        return -1;
    }

    unsigned char body[65536];
    unsigned char fin = 0;

    if (_video_mode) {
        // ── Video mode: accumulate data, parse video frame headers, write .h264 ──
        while (true) {
            ssize_t read = xqc_stream_recv(stream, body, sizeof(body), &fin);
            if (read == -XQC_EAGAIN || read == 0) break;
            if (read < 0) {
                std::cerr << "[xquic] stream_read_notify(video): recv error=" << read << std::endl;
                return -1;
            }

            append_stream_payload(user_stream, body, static_cast<size_t>(read));
            user_stream->total_recvd += static_cast<size_t>(read);
            _stats.video_bytes_recvd += static_cast<size_t>(read);

            if (!process_video_frames(user_stream, _video_output_dir)) {
                return -1;
            }

            if (fin) {
                /* Flush any remaining buffered data */
                process_video_frames(user_stream, _video_output_dir);
                user_stream->recv_fin = 1;
                _stats.video_streams_finished++;
                std::cout << "[video] Stream finished, total_recvd="
                          << user_stream->total_recvd << std::endl;
            }
        }
    } else if (_echo_mode) {
        // ── Streaming echo: read chunks and immediately send them back ──
        while (true) {
            ssize_t read = xqc_stream_recv(stream, body, sizeof(body), &fin);
            if (read == -XQC_EAGAIN || read == 0) {
                break;
            }
            if (read < 0) {
                std::cerr << "[xquic] stream_read_notify: recv error=" << read << std::endl;
                return -1;
            }

            user_stream->total_recvd += static_cast<size_t>(read);

            int send_fin = fin ? 1 : 0;
            size_t offset = 0;
            while (offset < static_cast<size_t>(read)) {
                ssize_t sent = xqc_stream_send(stream,
                    body + offset, static_cast<size_t>(read) - offset, send_fin);
                if (sent == -XQC_EAGAIN) {
                    size_t remaining = static_cast<size_t>(read) - offset;
                    char *buf = static_cast<char*>(std::realloc(user_stream->send_body,
                        user_stream->send_body_len + remaining));
                    if (!buf) return -1;
                    std::memcpy(buf + user_stream->send_body_len, body + offset, remaining);
                    user_stream->send_body = buf;
                    user_stream->send_body_len += remaining;
                    goto done_reading;
                }
                if (sent < 0) {
                    std::cerr << "[xquic] stream_read_notify: send error=" << sent << std::endl;
                    return -1;
                }
                offset += static_cast<size_t>(sent);
                user_stream->total_sent += static_cast<size_t>(sent);
            }

            if (fin) {
                user_stream->recv_fin = 1;
            }
        }
    } else {
        // ── Framed protocol: accumulate full request, then build response ──
        while (true) {
            ssize_t read = xqc_stream_recv(stream, body, sizeof(body), &fin);
            if (read == -XQC_EAGAIN || read == 0) {
                break;
            }
            if (read < 0) {
                std::cerr << "[xquic] stream_read_notify: recv error=" << read << std::endl;
                return -1;
            }

            append_stream_payload(user_stream, body, static_cast<size_t>(read));
            user_stream->total_recvd += static_cast<size_t>(read);

            if (fin) {
                user_stream->recv_fin = 1;
                // Build framed response and trigger send
                build_framed_response(stream, user_stream);
                on_stream_write_notify(stream, user_data);
            }
        }
    }

done_reading:
    return 0;
}

xqc_int_t XquicSeastarServer::on_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    // std::cout << "[xquic] stream_close_notify: stream_id=" << xqc_stream_id(stream) << std::endl;
    (void)stream;
    _stats.streams_closed++;

    auto user_stream = std::unique_ptr<user_stream_t>(static_cast<user_stream_t*>(user_data));
    release_user_stream(user_stream.get());
    return 0;
}

int XquicSeastarServer::on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    // std::cout << "[xquic] h3_conn_create_notify" << std::endl;
    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn == nullptr) {
        std::cerr << "[xquic] h3_conn_create_notify: user_data is NULL!" << std::endl;
        return -1;
    }

    u_conn->h3 = 1;
    u_conn->h3_conn = conn;
    if (cid != nullptr) {
        u_conn->cid = *cid;
    }
    xqc_h3_conn_set_user_data(conn, u_conn);
    return 0;
}

int XquicSeastarServer::on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    (void)conn;
    (void)cid;
    // std::cout << "[xquic] h3_conn_close_notify" << std::endl;
    auto u_conn = std::unique_ptr<user_conn_t>(static_cast<user_conn_t*>(user_data));
    release_user_conn(u_conn.get());
    return 0;
}

xqc_int_t XquicSeastarServer::on_h3_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    if (!_echo_mode) {
        // Framed mode: retry sending if previous send hit flow control
        user_stream_t *user_stream = static_cast<user_stream_t*>(user_data);
        if (user_stream && user_stream->send_body && user_stream->send_body_len > 0) {
            send_h3_response(user_stream);
        }
    }
    return 0;
}

xqc_int_t XquicSeastarServer::on_h3_request_read_notify(xqc_h3_request_t *req,
                                                        xqc_request_notify_flag_t flag, void *user_data) {
    _stats.h3_requests++;
    user_stream_t *user_stream = static_cast<user_stream_t*>(user_data);
    if (user_stream == nullptr) {
        try {
            auto owned_stream = std::make_unique<user_stream_t>();
            owned_stream->server = this;
            owned_stream->h3_request = req;
            owned_stream->is_h3 = 1;
            user_stream = owned_stream.get();
            xqc_h3_request_set_user_data(req, user_stream);
            owned_stream.release();

        } catch (const std::bad_alloc&) {
            return -1;
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        XqcHeadersPtr headers(xqc_h3_request_recv_headers(req, nullptr), &std::free);

        if (_echo_mode) {
            // Streaming: send headers immediately (no content-length)
            if (!user_stream->header_sent) {
                xqc_http_header_t resp_headers[] = {
                    {
                        {.iov_base = const_cast<char*>(kH3StatusName), .iov_len = sizeof(kH3StatusName) - 1},
                        {.iov_base = const_cast<char*>(kH3StatusValue), .iov_len = sizeof(kH3StatusValue) - 1},
                        0
                    },
                    {
                        {.iov_base = const_cast<char*>(kH3ContentTypeName), .iov_len = sizeof(kH3ContentTypeName) - 1},
                        {.iov_base = const_cast<char*>(kH3ContentTypeValue), .iov_len = sizeof(kH3ContentTypeValue) - 1},
                        0
                    },
                };
                xqc_http_headers_t response_headers = {
                    .headers = resp_headers,
                    .count = sizeof(resp_headers) / sizeof(resp_headers[0]),
                };
                xqc_h3_request_send_headers(req, &response_headers, 0);
                user_stream->header_sent = 1;
                _stats.h3_responses++;
            }
        }
        // Framed mode: headers will be sent in send_h3_response after body is accumulated
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char body[65536];
        unsigned char fin = 0;
        while (true) {
            ssize_t read = xqc_h3_request_recv_body(req, body, sizeof(body), &fin);
            if (read <= 0) {
                break;
            }
            user_stream->total_recvd += static_cast<size_t>(read);

            if (_echo_mode) {
                // Streaming echo
                xqc_h3_request_send_body(req, body, static_cast<size_t>(read), fin ? 1 : 0);
                user_stream->total_sent += static_cast<size_t>(read);
            } else {
                // Framed: accumulate body
                append_stream_payload(user_stream, body, static_cast<size_t>(read));
            }

            if (fin) {
                if (!_echo_mode) {
                    // Build framed response and send
                    build_framed_response(nullptr, user_stream);
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
            build_framed_response(nullptr, user_stream);
            send_h3_response(user_stream);
        }
    }

    return 0;
}

xqc_int_t XquicSeastarServer::on_h3_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    (void)req;
    // std::cout << "[xquic] h3_request_close_notify" << std::endl;
    auto user_stream = std::unique_ptr<user_stream_t>(static_cast<user_stream_t*>(user_data));
    release_user_stream(user_stream.get());
    return 0;
}

void XquicSeastarServer::ss_set_event_timer(xqc_msec_t wake_after, void *user_data) {
    auto* server = static_cast<XquicSeastarServer*>(user_data);
    if (server == nullptr) {
        return;
    }

    // std::cout << "[xquic] set_event_timer: wake_after=" << wake_after << "us" << std::endl;
    server->_engine_timer.cancel();
    server->_engine_timer.arm(std::chrono::microseconds(wake_after));
}

ssize_t XquicSeastarServer::ss_write_socket(const unsigned char *buf, size_t size,
                                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                                            void *user_conn) {
    auto* u_conn = static_cast<user_conn_t*>(user_conn);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    if (server == nullptr) {
        std::cerr << "[xquic] write_socket: server is null (u_conn=" << u_conn << ")" << std::endl;
        errno = EINVAL;
        return -1;
    }

    ssize_t ret = server->enqueue_send(buf, size, peer_addr, peer_addrlen);
    // std::cout << "[xquic] write_socket: size=" << size << " ret=" << ret << std::endl;
    return ret;
}

int XquicSeastarServer::ss_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                                         const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_server_accept(engine, conn, cid, user_data);
}

void XquicSeastarServer::ss_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                                   const xqc_cid_t *new_cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    if (server != nullptr) {
        server->on_conn_update_cid_notify(conn, retire_cid, new_cid, user_data);
    }
}

int XquicSeastarServer::ss_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                              void *user_data, void *conn_proto_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_conn_create_notify(conn, cid, user_data, conn_proto_data);
}

int XquicSeastarServer::ss_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                             void *user_data, void *conn_proto_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? 0 : server->on_conn_close_notify(conn, cid, user_data, conn_proto_data);
}

xqc_int_t XquicSeastarServer::ss_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? -1 : server->on_stream_write_notify(stream, user_data);
}

xqc_int_t XquicSeastarServer::ss_stream_create_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? -1 : server->on_stream_create_notify(stream, user_data);
}

xqc_int_t XquicSeastarServer::ss_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? -1 : server->on_stream_read_notify(stream, user_data);
}

xqc_int_t XquicSeastarServer::ss_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? 0 : server->on_stream_close_notify(stream, user_data);
}

int XquicSeastarServer::ss_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_h3_conn_create_notify(conn, cid, user_data);
}

int XquicSeastarServer::ss_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_conn_close_notify(conn, cid, user_data);
}

xqc_int_t XquicSeastarServer::ss_h3_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_request_write_notify(req, user_data);
}

xqc_int_t XquicSeastarServer::ss_h3_request_read_notify(xqc_h3_request_t *req,
                                                        xqc_request_notify_flag_t flag, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;

    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_h3_get_conn_user_data_by_request(req));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }

    return server == nullptr ? -1 : server->on_h3_request_read_notify(req, flag, user_data);
}

xqc_int_t XquicSeastarServer::ss_h3_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_request_close_notify(req, user_data);
}

void XquicSeastarServer::print_stats() {
    auto &s = _stats;
    auto &p = _stats_prev;

    uint64_t d_bytes_recv = s.bytes_recv - p.bytes_recv;
    uint64_t d_bytes_sent = s.bytes_sent - p.bytes_sent;
    uint64_t d_pkts_recv = s.packets_recv - p.packets_recv;
    uint64_t d_pkts_sent = s.packets_sent - p.packets_sent;
    uint64_t active_conns = s.conns_accepted - s.conns_closed;
    uint64_t active_streams = s.streams_created - s.streams_closed;

    /* rates are per 2s interval, convert to per-second */
    double recv_mbps = d_bytes_recv * 8.0 / 2.0 / 1e6;
    double send_mbps = d_bytes_sent * 8.0 / 2.0 / 1e6;

    std::cout << "[stats] conns=" << active_conns
              << " streams=" << active_streams
              << " total_accepted=" << s.conns_accepted
              << " | recv=" << recv_mbps << "Mbps (" << d_pkts_recv/2 << "pps)"
              << " send=" << send_mbps << "Mbps (" << d_pkts_sent/2 << "pps)";
    if (_video_mode) {
        uint64_t d_video = s.video_bytes_recvd - p.video_bytes_recvd;
        std::cout << " | video=" << d_video/2/1024 << "KB/s"
                  << " finished=" << s.video_streams_finished;
    }
    std::cout << std::endl;

    _stats_prev = s;
}

int main(int argc, char **argv) {
    seastar::app_template app;
    app.add_options()
        ("port,p", bpo::value<uint16_t>()->default_value(8443), "UDP port")
        ("cert,c", bpo::value<std::string>()->default_value("./server.crt"), "TLS certificate path")
        ("key,k", bpo::value<std::string>()->default_value("./server.key"), "TLS private key path")
        ("echo,e", bpo::bool_switch()->default_value(false), "Enable streaming echo mode (default: framed protocol)")
        ("video,v", bpo::bool_switch()->default_value(false), "Enable video stream receiver mode")
        ("video-dir", bpo::value<std::string>()->default_value("./video_out"), "Output directory for recorded .h264 files");

    return app.run_deprecated(argc, argv, [&app] {
        auto& config = app.configuration();
        auto server = std::make_unique<XquicSeastarServer>();

        return server->start(config["port"].as<uint16_t>(),
                             config["cert"].as<std::string>(),
                             config["key"].as<std::string>(),
                             config["echo"].as<bool>(),
                             config["video"].as<bool>(),
                             config["video-dir"].as<std::string>())
            .then([server = std::move(server)]() mutable {
                // Keep the sample server alive until the Seastar app shuts down.
                return seastar::keep_doing([] {
                        return seastar::sleep(std::chrono::hours(24));
                    })
                    .finally([server = std::move(server)]() mutable {
                        return server->stop();
                    });
            });
    });
}
