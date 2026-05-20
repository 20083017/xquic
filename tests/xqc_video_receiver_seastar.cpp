/**
 * @file xqc_video_receiver_seastar.cpp
 * @brief Canonical video receiver — Seastar QUIC reactor + shared decode/display/CUDA pipeline.
 *
 * Build: bash scripts/build_seastar_video_receiver.sh
 * Run:
 *   export LD_LIBRARY_PATH=~/ffmpeg-hw/lib:$LD_LIBRARY_PATH
 *   export XQC_PIN_AFFINITY=1
 *   ./build_seastar/xquic_tests/xqc_video_receiver --smp 1 --cpuset 0 \
 *     -p 8443 --decode --display --codec hevc --hw-decode=cuda
 */

#include <cerrno>

#include "platform.h"
#include "user_conn.h"
#include "xquic_seastar_integration.hh"

#include "lowlatency/xqc_video_low_latency.hh"
#include "lowlatency/xqc_video_receiver_pipeline.hh"
#include "lowlatency/xqc_video_recv_process.hh"
#include "lowlatency/xqc_thread_affinity.hh"

#include <xquic/xquic.h>
#include <xquic/xqc_video_frame.h>

#include <seastar/core/app-template.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/smp.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/api.hh>

#include <boost/program_options.hpp>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

namespace bpo = boost::program_options;

extern "C" {
extern xqc_timestamp_pt xqc_realtime_timestamp;
}

namespace {

constexpr char kTransportAlpn[] = "transport";

XqcVideoReceiverOptions g_opt;
XqcVideoDisplayPipeline g_display;

uint64_t now_us() {
    return static_cast<uint64_t>(xqc_realtime_timestamp());
}

void socket_address_to_storage(const seastar::socket_address& src, struct sockaddr_storage& dst,
    socklen_t& len)
{
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

class XqcVideoReceiverSeastar {
public:
    XqcVideoReceiverSeastar()
        : _engine_timer([this] { on_engine_timer(); })
        , _stats_timer([this] { on_stats_timer(); }) {}

    seastar::future<> start() {
        if (seastar::this_shard_id() != 0) {
            co_return;
        }

        xqc_platform_init_env();
        xqc_log_pipeline_affinity_layout(seastar::this_shard_id(), xqc_cpu_from_env("XQC_REACTOR_CPU"));

        xqc_video_receiver_boot_pipeline(g_opt, g_display, "xquic HEVC 4K (Seastar)");

        init_engine();

        seastar::socket_address bind_addr = seastar::make_ipv4_address(seastar::ipv4_addr(g_opt.port));
        _udp = seastar::engine().net().make_bound_datagram_channel(bind_addr);

        if (g_opt.decode) {
            _stats_timer.arm_periodic(std::chrono::seconds(2));
        }

        std::fprintf(stderr,
            "[recv] Seastar reactor UDP :%u decode=%d codec=%s stream=%d eos_file=%d display=%d dir=%s\n",
            static_cast<unsigned>(g_opt.port), g_opt.decode ? 1 : 0, xqc_video_codec_name(g_opt.stream_codec),
            g_opt.stream_decode ? 1 : 0, g_opt.eos_file_decode ? 1 : 0, g_opt.display ? 1 : 0,
            g_opt.video_dir.c_str());

        _recv_loop = seastar::with_gate(_gate, [this] { return recv_loop(); });
        co_return;
    }

    seastar::future<> stop() {
        if (seastar::this_shard_id() != 0) {
            co_return;
        }
        _stopping = true;
        _engine_timer.cancel();
        _stats_timer.cancel();
        co_await _gate.close();
        if (_engine) {
            xqc_engine_destroy(_engine);
            _engine = nullptr;
        }
        g_display.join();
        xqc_video_receiver_log_e2e_final(g_opt);
        xqc_video_receiver_stop_decode();
        co_return;
    }

    void deliver_packet(seastar::temporary_buffer<char> data, seastar::socket_address peer,
        seastar::socket_address local)
    {
        if (!_engine || _stopping) {
            return;
        }
        struct sockaddr_storage peer_ss{};
        struct sockaddr_storage local_ss{};
        socklen_t peer_len = 0;
        socklen_t local_len = 0;
        socket_address_to_storage(peer, peer_ss, peer_len);
        socket_address_to_storage(local, local_ss, local_len);

        xqc_engine_packet_process(_engine, reinterpret_cast<unsigned char*>(data.get_write()), data.size(),
            reinterpret_cast<sockaddr*>(&local_ss), local_len,
            reinterpret_cast<sockaddr*>(&peer_ss), peer_len, now_us(), &_packet_conn);
        xqc_engine_finish_recv(_engine);
        schedule_send_flush();
    }

private:
    void init_engine() {
        xqc_config_t config;
        if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) != XQC_OK) {
            throw std::runtime_error("xqc_engine_get_default_config failed");
        }
        config.cfg_log_level = XQC_LOG_WARN;

        xqc_engine_ssl_config_t ssl{};
        ssl.cert_file = g_opt.cert_path.data();
        ssl.private_key_file = g_opt.key_path.data();

        xqc_engine_callback_t ecb{};
        ecb.set_event_timer = &XqcVideoReceiverSeastar::ss_set_event_timer;

        xqc_transport_callbacks_t tcb{};
        tcb.server_accept = &XqcVideoReceiverSeastar::ss_server_accept;
        tcb.write_socket = &XqcVideoReceiverSeastar::ss_write_socket;

        _engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl, &ecb, &tcb, this);
        if (!_engine) {
            throw std::runtime_error("xqc_engine_create failed");
        }

        xqc_conn_callbacks_t conn_cbs{};
        conn_cbs.conn_create_notify = &XqcVideoReceiverSeastar::ss_conn_create;
        conn_cbs.conn_close_notify = &XqcVideoReceiverSeastar::ss_conn_close;

        xqc_stream_callbacks_t stream_cbs{};
        stream_cbs.stream_create_notify = &XqcVideoReceiverSeastar::ss_stream_create;
        stream_cbs.stream_read_notify = &XqcVideoReceiverSeastar::ss_stream_read;
        stream_cbs.stream_write_notify = &XqcVideoReceiverSeastar::ss_stream_write;
        stream_cbs.stream_close_notify = &XqcVideoReceiverSeastar::ss_stream_close;

        xqc_app_proto_callbacks_t ap{};
        ap.conn_cbs = conn_cbs;
        ap.stream_cbs = stream_cbs;

        if (xqc_engine_register_alpn(_engine, kTransportAlpn, sizeof(kTransportAlpn) - 1, &ap, nullptr) != XQC_OK) {
            throw std::runtime_error("xqc_engine_register_alpn failed");
        }

        if (xqc_video_quic_low_delay_enabled()) {
            xqc_conn_settings_t low = xqc_video_conn_settings();
            xqc_server_set_conn_settings(_engine, &low);
            std::fprintf(stderr, "[recv] QUIC LOW_DELAY transport (set XQC_LOW_DELAY=0 to disable)\n");
        }

        _packet_conn.server = this;
    }

    seastar::future<> recv_loop() {
        while (!_stopping) {
            seastar::net::udp_datagram dgram = co_await _udp.receive();
            seastar::socket_address peer = dgram.get_src();
            seastar::socket_address local;
            try {
                local = dgram.get_dst();
            } catch (...) {
                local = seastar::make_ipv4_address(seastar::ipv4_addr(g_opt.port));
            }
            for (auto& buf : dgram.get_buffers()) {
                deliver_packet(std::move(buf), peer, local);
            }
        }
    }

    void on_engine_timer() {
        if (_engine) {
            xqc_engine_main_logic(_engine);
            schedule_send_flush();
        }
    }

    void on_stats_timer() {
        xqc_video_receiver_log_stats(g_opt);
    }

    void schedule_send_flush() {
        if (_stopping || _send_flush || _send.empty()) {
            return;
        }
        _send_flush = true;
        (void)seastar::with_gate(_gate, [this] {
            return _send.flush_to(_udp).finally([this] {
                _send_flush = false;
                if (!_stopping && !_send.empty()) {
                    schedule_send_flush();
                }
            });
        });
    }

    ssize_t enqueue_send(const unsigned char* buf, size_t size, const struct sockaddr* peer, socklen_t peer_len) {
        return _send.enqueue_write(buf, size, peer, peer_len);
    }

    int on_accept(xqc_connection_t* conn, const xqc_cid_t* cid, void*) {
        auto* u = static_cast<user_conn_t*>(std::calloc(1, sizeof(user_conn_t)));
        if (!u) {
            return -1;
        }
        if (cid) {
            std::memcpy(&u->cid, cid, sizeof(*cid));
        }
        u->server = this;
        xqc_conn_set_transport_user_data(conn, u);
        std::fprintf(stderr, "[recv] connection accepted\n");
        return 0;
    }

    xqc_int_t on_stream_create(xqc_stream_t* stream, void*) {
        auto* us = static_cast<user_stream_t*>(std::calloc(1, sizeof(user_stream_t)));
        if (!us) {
            return -1;
        }
        us->stream = stream;
        us->server = this;
        us->user_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        xqc_stream_set_user_data(stream, us);
        std::fprintf(stderr, "[recv] stream created id=%llu\n",
            static_cast<unsigned long long>(xqc_stream_id(stream)));
        return 0;
    }

    xqc_int_t on_stream_read(xqc_stream_t* stream, void* user_data) {
        auto* us = static_cast<user_stream_t*>(user_data);
        if (!us) {
            return -1;
        }
        unsigned char body[65536];
        unsigned char fin = 0;
        while (true) {
            ssize_t read = xqc_stream_recv(stream, body, sizeof(body), &fin);
            if (read == -XQC_EAGAIN || read == 0) {
                break;
            }
            if (read < 0) {
                return -1;
            }
            if (!xqc_video_receiver_ensure_recv_cap(us, static_cast<std::size_t>(read))) {
                return -1;
            }
            std::memcpy(us->recv_body + us->recv_body_len, body, static_cast<std::size_t>(read));
            us->recv_body_len += static_cast<std::size_t>(read);
            us->total_recvd += static_cast<std::size_t>(read);

            if (!xqc_process_video_stream_buffer(us->recv_body, us->recv_body_len, us->recv_body_cap,
                    us->recv_body_fp, g_opt.video_dir, g_opt.decode && g_opt.stream_decode,
                    g_opt.decode && g_opt.eos_file_decode, g_opt.stream_codec)) {
                return -1;
            }
            if (fin) {
                std::fprintf(stderr, "[recv] stream FIN total=%zu\n", us->total_recvd);
            }
        }
        return 0;
    }

    static void ss_set_event_timer(xqc_msec_t wake_after, void* user_data) {
        auto* self = static_cast<XqcVideoReceiverSeastar*>(user_data);
        if (!self) {
            return;
        }
        self->_engine_timer.cancel();
        self->_engine_timer.arm(std::chrono::microseconds(wake_after));
    }

    static ssize_t ss_write_socket(const unsigned char* buf, size_t size, const struct sockaddr* peer,
        socklen_t peer_len, void* user_conn)
    {
        auto* u = static_cast<user_conn_t*>(user_conn);
        auto* self = u ? static_cast<XqcVideoReceiverSeastar*>(u->server) : nullptr;
        return self ? self->enqueue_send(buf, size, peer, peer_len) : -1;
    }

    static int ss_server_accept(xqc_engine_t*, xqc_connection_t* conn, const xqc_cid_t* cid, void* user_data) {
        auto* u = static_cast<user_conn_t*>(user_data);
        auto* self = (u && u->server) ? static_cast<XqcVideoReceiverSeastar*>(u->server) : nullptr;
        return self ? self->on_accept(conn, cid, user_data) : -1;
    }

    static int ss_conn_create(xqc_connection_t*, const xqc_cid_t*, void* user_data, void*) {
        return user_data ? 0 : -1;
    }

    static int ss_conn_close(xqc_connection_t*, const xqc_cid_t*, void* user_data, void*) {
        if (user_data) {
            std::free(user_data);
        }
        return 0;
    }

    static xqc_int_t ss_stream_create(xqc_stream_t* stream, void*) {
        auto* u = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        auto* self = (u && u->server) ? static_cast<XqcVideoReceiverSeastar*>(u->server) : nullptr;
        return self ? self->on_stream_create(stream, nullptr) : -1;
    }

    static xqc_int_t ss_stream_read(xqc_stream_t* stream, void* user_data) {
        auto* us = static_cast<user_stream_t*>(user_data);
        auto* self = us ? static_cast<XqcVideoReceiverSeastar*>(us->server) : nullptr;
        return self ? self->on_stream_read(stream, user_data) : -1;
    }

    static xqc_int_t ss_stream_write(xqc_stream_t*, void*) { return 0; }

    static xqc_int_t ss_stream_close(xqc_stream_t*, void* user_data) {
        auto* us = static_cast<user_stream_t*>(user_data);
        if (us) {
            if (us->recv_body_fp) {
                std::fclose(us->recv_body_fp);
            }
            std::free(us->recv_body);
            std::free(us);
        }
        return 0;
    }

    seastar::gate _gate;
    seastar::timer<> _engine_timer;
    seastar::timer<> _stats_timer;
    seastar::net::udp_channel _udp;
    seastar::future<> _recv_loop = seastar::make_ready_future<>();
    XquicSeastarSendIntegration _send;
    xqc_engine_t* _engine = nullptr;
    user_conn_t _packet_conn{};
    bool _stopping = false;
    bool _send_flush = false;
};

void parse_options(bpo::variables_map& cfg) {
    g_opt.port = cfg["port"].as<uint16_t>();
    g_opt.cert_path = cfg["cert"].as<std::string>();
    g_opt.key_path = cfg["key"].as<std::string>();
    g_opt.video_dir = cfg["video-dir"].as<std::string>();
    g_opt.decode = cfg["decode"].as<bool>();
    g_opt.display = cfg["display"].as<bool>();
    if (g_opt.display) {
        g_opt.decode = true;
    }
    g_opt.stream_decode = !cfg["no-stream-decode"].as<bool>();
    g_opt.eos_file_decode = !cfg["no-eos-file-decode"].as<bool>();
    if (cfg.count("hw-decode")) {
        g_opt.hw_decode_mode = cfg["hw-decode"].as<std::string>();
    }
    g_opt.stream_codec = xqc_video_codec_parse(cfg["codec"].as<std::string>().c_str(), XqcVideoCodec::HEVC);
}

} // namespace

int main(int argc, char** argv) {
    seastar::app_template app;
    app.add_options()
        ("port,p", bpo::value<uint16_t>()->default_value(8443), "UDP listen port")
        ("cert", bpo::value<std::string>()->default_value("tests/server.crt"), "TLS certificate")
        ("key", bpo::value<std::string>()->default_value("tests/server.key"), "TLS private key")
        ("video-dir", bpo::value<std::string>()->default_value("./video_out"), "Recorded elementary stream output dir")
        ("decode", bpo::bool_switch()->default_value(false), "Enable FFmpeg decode worker")
        ("display", bpo::bool_switch()->default_value(false), "GL display (implies decode)")
        ("no-stream-decode", bpo::bool_switch()->default_value(false), "Disable live stream decode")
        ("no-eos-file-decode", bpo::bool_switch()->default_value(false), "Disable EOS file replay decode")
        ("hw-decode", bpo::value<std::string>()->implicit_value("auto"), "HW decode: auto|vaapi|cuda|off")
        ("codec", bpo::value<std::string>()->default_value("hevc"), "Stream codec hevc|h264");

    return app.run_deprecated(argc, argv, [&app] {
        parse_options(app.configuration());

        auto receiver = std::make_shared<XqcVideoReceiverSeastar>();
        if (seastar::smp::count > 1) {
            std::fprintf(stderr,
                "[recv] warning: prefer --smp 1 for video receiver (shard 0 owns decode/display)\n");
        }

        return receiver->start().then([receiver] {
            return seastar::keep_doing([receiver] {
                (void)receiver;
                return seastar::sleep(std::chrono::hours(24));
            });
        }).finally([receiver] {
            return receiver->stop();
        });
    });
}
