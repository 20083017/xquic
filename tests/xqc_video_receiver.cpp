/**
 * @file xqc_video_receiver.cpp
 * @brief Legacy libevent video receiver (fallback when Seastar is not enabled).
 *
 * For best 4K latency use the Seastar build:
 *   bash scripts/build_seastar_video_receiver.sh
 *   ./build_seastar/xquic_tests/xqc_video_receiver --smp 1 --cpuset 0 ...
 */

#include "lowlatency/xqc_video_receiver_pipeline.hh"
#include "lowlatency/xqc_video_recv_process.hh"
#include "lowlatency/xqc_video_low_latency.hh"

#include "platform.h"
#include "user_conn.h"
#include "xqc_socket_opts.h"

#include <xquic/xquic.h>
#include <xquic/xqc_video_frame.h>

#include <event2/event.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <string>
#include <unistd.h>

namespace {

XqcVideoReceiverOptions g_opt;
XqcVideoDisplayPipeline g_display;

xqc_engine_t* g_engine = nullptr;
event_base* g_eb = nullptr;
event* g_ev_engine = nullptr;
event* g_ev_listen = nullptr;
event* g_ev_stats = nullptr;
int g_listen_fd = -1;
xqc_udp_writer_t g_writer{};

static uint64_t now_us() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

extern "C" {

static void rv_engine_timer(int, short, void*) {
    if (g_engine) {
        xqc_engine_main_logic(g_engine);
    }
    xqc_udp_writer_flush(&g_writer);
}

static void rv_set_timer(xqc_msec_t wake_after, void*) {
    if (!g_ev_engine) {
        return;
    }
    struct timeval tv;
    tv.tv_sec = static_cast<long>(wake_after / 1000);
    tv.tv_usec = static_cast<long>((wake_after % 1000) * 1000);
    event_add(g_ev_engine, &tv);
}

static ssize_t rv_write_socket(const unsigned char* buf, size_t size,
    const struct sockaddr* peer, socklen_t peer_len, void* user_conn)
{
    (void)user_conn;
    if (g_listen_fd < 0) {
        return -1;
    }
    return xqc_udp_writer_enqueue(&g_writer, buf, size, peer, peer_len);
}

static int rv_accept(xqc_engine_t*, xqc_connection_t* conn, const xqc_cid_t* cid, void*) {
    auto* u = static_cast<user_conn_t*>(calloc(1, sizeof(user_conn_t)));
    if (!u) {
        return -1;
    }
    if (cid) {
        memcpy(&u->cid, cid, sizeof(*cid));
    }
    u->socket = g_listen_fd;
    xqc_conn_set_transport_user_data(conn, u);
    std::fprintf(stderr, "[recv] connection accepted\n");
    return 0;
}

static int rv_conn_create(xqc_connection_t*, const xqc_cid_t*, void* user_data, void*) {
    return user_data ? 0 : -1;
}

static int rv_conn_close(xqc_connection_t*, const xqc_cid_t*, void* user_data, void*) {
    free(user_data);
    return 0;
}

static xqc_int_t rv_stream_create(xqc_stream_t* stream, void*) {
    auto* us = static_cast<user_stream_t*>(calloc(1, sizeof(user_stream_t)));
    if (!us) {
        return -1;
    }
    us->stream = stream;
    us->user_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
    xqc_stream_set_user_data(stream, us);
    std::fprintf(stderr, "[recv] stream created id=%llu\n",
        static_cast<unsigned long long>(xqc_stream_id(stream)));
    return 0;
}

static xqc_int_t rv_stream_read(xqc_stream_t* stream, void* user_data) {
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
        memcpy(us->recv_body + us->recv_body_len, body, static_cast<size_t>(read));
        us->recv_body_len += static_cast<size_t>(read);
        us->total_recvd += static_cast<size_t>(read);

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

static xqc_int_t rv_stream_write(xqc_stream_t*, void*) { return 0; }

static xqc_int_t rv_stream_close(xqc_stream_t*, void* user_data) {
    auto* us = static_cast<user_stream_t*>(user_data);
    if (us) {
        if (us->recv_body_fp) {
            fclose(us->recv_body_fp);
        }
        free(us->recv_body);
        free(us);
    }
    return 0;
}

static void rv_socket_cb(int, short, void*) {
    unsigned char buf[64 * 1024];
    xqc_udp_recv_segments_t segs;
    for (;;) {
        ssize_t n = xqc_udp_recvmsg_gro(g_listen_fd, buf, sizeof(buf), &segs);
        if (n <= 0) {
            break;
        }
        user_conn_t temp{};
        temp.socket = g_listen_fd;
        const struct sockaddr* peer = reinterpret_cast<const struct sockaddr*>(&segs.peer);
        socklen_t peer_len = segs.peer_len;
        const struct sockaddr* local = segs.local_len
            ? reinterpret_cast<const struct sockaddr*>(&segs.local) : peer;
        socklen_t local_len = segs.local_len ? segs.local_len : peer_len;

        const unsigned char* seg;
        size_t seg_len;
        XQC_UDP_FOR_EACH_SEG(seg, seg_len, &segs) {
            xqc_engine_packet_process(g_engine, seg, seg_len,
                const_cast<struct sockaddr*>(local), local_len,
                const_cast<struct sockaddr*>(peer), peer_len, now_us(), &temp);
        }
    }
    if (g_engine) {
        xqc_engine_finish_recv(g_engine);
    }
    xqc_udp_writer_flush(&g_writer);
}

static void rv_stats_timer(int, short, void*) {
    xqc_video_receiver_log_stats(g_opt);
    if (g_ev_stats) {
        struct timeval tv {2, 0};
        event_add(g_ev_stats, &tv);
    }
}

} /* extern "C" */

static int init_engine() {
    std::fprintf(stderr, "[recv] libevent receiver (use Seastar build for best 4K performance)\n");

    xqc_platform_init_env();
    g_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_listen_fd < 0) {
        return -1;
    }
    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    xqc_apply_udp_perf_opts(g_listen_fd, AF_INET, 1);
    xqc_enable_udp_gro(g_listen_fd);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_opt.port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(g_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        return -1;
    }
    fcntl(g_listen_fd, F_SETFL, O_NONBLOCK);
    xqc_udp_writer_init(&g_writer, g_listen_fd);

    g_eb = event_base_new();
    g_ev_listen = event_new(g_eb, g_listen_fd, EV_READ | EV_PERSIST, rv_socket_cb, nullptr);
    event_add(g_ev_listen, nullptr);
    g_ev_engine = event_new(g_eb, -1, 0, rv_engine_timer, nullptr);

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) != XQC_OK) {
        return -1;
    }
    config.cfg_log_level = XQC_LOG_WARN;

    xqc_engine_ssl_config_t ssl{};
    memset(&ssl, 0, sizeof(ssl));
    ssl.cert_file = const_cast<char*>(g_opt.cert_path.c_str());
    ssl.private_key_file = const_cast<char*>(g_opt.key_path.c_str());

    xqc_engine_callback_t ecb{};
    ecb.set_event_timer = rv_set_timer;

    xqc_transport_callbacks_t tcb{};
    tcb.server_accept = rv_accept;
    tcb.write_socket = rv_write_socket;

    g_engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl, &ecb, &tcb, nullptr);
    if (!g_engine) {
        return -1;
    }

    xqc_conn_callbacks_t conn_cbs{};
    conn_cbs.conn_create_notify = rv_conn_create;
    conn_cbs.conn_close_notify = rv_conn_close;

    xqc_stream_callbacks_t stream_cbs{};
    stream_cbs.stream_create_notify = rv_stream_create;
    stream_cbs.stream_read_notify = rv_stream_read;
    stream_cbs.stream_write_notify = rv_stream_write;
    stream_cbs.stream_close_notify = rv_stream_close;

    xqc_app_proto_callbacks_t ap{};
    ap.conn_cbs = conn_cbs;
    ap.stream_cbs = stream_cbs;

    if (xqc_engine_register_alpn(g_engine, "transport", 9, &ap, nullptr) != XQC_OK) {
        return -1;
    }

    if (xqc_video_quic_low_delay_enabled()) {
        xqc_conn_settings_t low = xqc_video_conn_settings();
        xqc_server_set_conn_settings(g_engine, &low);
        std::fprintf(stderr, "[recv] QUIC LOW_DELAY transport (set XQC_LOW_DELAY=0 to disable)\n");
    }

    xqc_video_receiver_boot_pipeline(g_opt, g_display, "xquic HEVC 4K (libevent)");

    if (g_opt.decode) {
        g_ev_stats = event_new(g_eb, -1, 0, rv_stats_timer, nullptr);
        struct timeval tv {2, 0};
        event_add(g_ev_stats, &tv);
    }

    std::fprintf(stderr,
        "[recv] listening UDP :%u cert=%s decode=%d codec=%s stream=%d eos_file=%d display=%d dir=%s\n",
        g_opt.port, g_opt.cert_path.c_str(), g_opt.decode ? 1 : 0,
        xqc_video_codec_name(g_opt.stream_codec),
        g_opt.stream_decode ? 1 : 0, g_opt.eos_file_decode ? 1 : 0,
        g_opt.display ? 1 : 0, g_opt.video_dir.c_str());
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    static struct option opts[] = {
        {"port", required_argument, nullptr, 'p'},
        {"cert", required_argument, nullptr, 'c'},
        {"key", required_argument, nullptr, 'k'},
        {"video-dir", required_argument, nullptr, 'd'},
        {"decode", no_argument, nullptr, 1},
        {"display", no_argument, nullptr, 2},
        {"no-stream-decode", no_argument, nullptr, 3},
        {"no-eos-file-decode", no_argument, nullptr, 4},
        {"hw-decode", optional_argument, nullptr, 5},
        {"codec", required_argument, nullptr, 6},
        {nullptr, 0, nullptr, 0},
    };

    int o;
    while ((o = getopt_long(argc, argv, "p:c:k:", opts, nullptr)) != -1) {
        switch (o) {
        case 'p': g_opt.port = static_cast<uint16_t>(atoi(optarg)); break;
        case 'c': g_opt.cert_path = optarg; break;
        case 'k': g_opt.key_path = optarg; break;
        case 'd': g_opt.video_dir = optarg; break;
        case 1: g_opt.decode = true; break;
        case 2: g_opt.display = true; g_opt.decode = true; break;
        case 3: g_opt.stream_decode = false; break;
        case 4: g_opt.eos_file_decode = false; break;
        case 5: g_opt.hw_decode_mode = (optarg && optarg[0]) ? optarg : "auto"; break;
        case 6: g_opt.stream_codec = xqc_video_codec_parse(optarg, XqcVideoCodec::HEVC); break;
        default:
            std::fprintf(stderr,
                "usage: %s -p PORT -c cert.crt -k key.key [--decode] [--display]\n"
                "       [--no-stream-decode] [--no-eos-file-decode]\n"
                "       [--hw-decode[=auto|vaapi|cuda|off]] [--codec hevc|h264] [--video-dir DIR]\n",
                argv[0]);
            return 1;
        }
    }

    if (init_engine() != 0) {
        std::fprintf(stderr, "init failed\n");
        return 1;
    }
    event_base_dispatch(g_eb);

    if (g_ev_stats) {
        event_free(g_ev_stats);
    }
    g_display.join();
    xqc_video_receiver_log_e2e_final(g_opt);
    xqc_video_receiver_stop_decode();
    if (g_engine) {
        xqc_engine_destroy(g_engine);
    }
    return 0;
}
