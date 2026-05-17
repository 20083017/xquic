/**
 * @file xqc_video_receiver.cpp
 * @brief WSL/Linux video receiver: QUIC → wire parse → stream decode → optional 4K GL display.
 *
 * **Pure stream E2E latency** (wire PTS → display histogram):
 *   ./xqc_video_receiver ... --decode --display --no-eos-file-decode
 *   ./video_client ... --cam0 clip.h265 --codec hevc --fps 30
 *
 * Histogram is printed every 2s and on exit (`xqc_e2e_latency_hist`). Requires `--display`
 * (samples taken after `glfwSwapBuffers` on the display thread).
 *
 * Display window is provisioned at **3840x2160** (`xqc_video_target.hh`); test vectors may be smaller.
 */

#include "lowlatency/xqc_h264_ff_decode_api.hh"
#include "lowlatency/xqc_video_codec.hh"
#include "lowlatency/xqc_e2e_latency.hh"
#include "lowlatency/xqc_h264_decode_stats.hh"
#include "lowlatency/xqc_video_target.hh"
#if defined(XQC_HAVE_GLFW)
#include "lowlatency/xqc_nv12_gl_linux.hh"
#endif
#include "lowlatency/xqc_video_recv_process.hh"

#include "platform.h"
#include "user_conn.h"
#include "xqc_socket_opts.h"

#include <xquic/xquic.h>
#include <xquic/xqc_video_frame.h>

#include <event2/event.h>

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <string>
#include <thread>
#include <unistd.h>

namespace {

struct ReceiverCtx {
    xqc_engine_t* engine = nullptr;
    event_base* eb = nullptr;
    event* ev_engine = nullptr;
    int listen_fd = -1;
    event* ev_listen = nullptr;
    xqc_udp_writer_t writer{};
    std::string cert_path = "tests/server.crt";
    std::string key_path = "tests/server.key";
    std::string video_dir = "./video_out";
    int port = 8443;
    bool decode = false;
    bool display = false;
    bool stream_decode = true;
    bool eos_file_decode = true;
    const char* hw_decode_mode = nullptr;
    XqcVideoCodec stream_codec = XqcVideoCodec::HEVC;
    event* ev_stats = nullptr;
    std::atomic<bool> stopping{false};
#if defined(XQC_HAVE_GLFW)
    XqcNv12GlLinux gl;
    std::thread display_bridge;
#endif
};

ReceiverCtx g_ctx;

static uint64_t now_us() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

static bool ensure_recv_cap(user_stream_t* us, size_t extra) {
    if (us->recv_body_len + extra <= us->recv_body_cap) {
        return true;
    }
    size_t need = us->recv_body_len + extra;
    size_t cap = us->recv_body_cap ? us->recv_body_cap : 65536;
    while (cap < need) {
        cap *= 2;
    }
    void* p = std::realloc(us->recv_body, cap);
    if (!p) {
        return false;
    }
    us->recv_body = static_cast<char*>(p);
    us->recv_body_cap = cap;
    return true;
}

#if defined(XQC_HAVE_GLFW)
/**
 * Bridges decode thread → GL thread without blocking the reactor.
 * Pops from `XqcBoundedFrameQueue` (depth 4); latest frame wins under load.
 * E2E timestamps are completed in `XqcNv12GlLinux` after GPU present.
 */
static void display_bridge_loop() {
    while (!g_ctx.stopping.load()) {
        XqcNv12Frame f;
        if (xqc_h264_decode_try_pop_nv12(f)) {
            g_ctx.gl.submit_frame(std::move(f));
        }
        usleep(3000);
    }
}
#endif

extern "C" {

static void rv_engine_timer(int, short, void*) {
    if (g_ctx.engine) {
        xqc_engine_main_logic(g_ctx.engine);
    }
    xqc_udp_writer_flush(&g_ctx.writer);
}

static void rv_set_timer(xqc_msec_t wake_after, void*) {
    if (!g_ctx.ev_engine) {
        return;
    }
    struct timeval tv;
    tv.tv_sec = static_cast<long>(wake_after / 1000);
    tv.tv_usec = static_cast<long>((wake_after % 1000) * 1000);
    event_add(g_ctx.ev_engine, &tv);
}

static ssize_t rv_write_socket(const unsigned char* buf, size_t size,
    const struct sockaddr* peer, socklen_t peer_len, void* user_conn)
{
    auto* u = static_cast<user_conn_t*>(user_conn);
    if (!u || g_ctx.listen_fd < 0) {
        return -1;
    }
    (void)u;
    return xqc_udp_writer_enqueue(&g_ctx.writer, buf, size, peer, peer_len);
}

static int rv_accept(xqc_engine_t*, xqc_connection_t* conn, const xqc_cid_t* cid, void*) {
    auto* u = static_cast<user_conn_t*>(calloc(1, sizeof(user_conn_t)));
    if (!u) {
        return -1;
    }
    if (cid) {
        memcpy(&u->cid, cid, sizeof(*cid));
    }
    u->socket = g_ctx.listen_fd;
    xqc_conn_set_transport_user_data(conn, u);
    std::fprintf(stderr, "[recv] connection accepted\n");
    return 0;
}

static int rv_conn_create(xqc_connection_t*, const xqc_cid_t*, void* user_data, void*) {
    if (!user_data) {
        return -1;
    }
    return 0;
}

static int rv_conn_close(xqc_connection_t*, const xqc_cid_t*, void* user_data, void*) {
    free(user_data);
    return 0;
}

static xqc_int_t rv_stream_create(xqc_stream_t* stream, void* user_data) {
    (void)user_data;
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
        if (!ensure_recv_cap(us, static_cast<size_t>(read))) {
            return -1;
        }
        memcpy(us->recv_body + us->recv_body_len, body, static_cast<size_t>(read));
        us->recv_body_len += static_cast<size_t>(read);
        us->total_recvd += static_cast<size_t>(read);

        if (!xqc_process_video_stream_buffer(
                us->recv_body, us->recv_body_len, us->recv_body_cap, us->recv_body_fp,
                g_ctx.video_dir, g_ctx.decode && g_ctx.stream_decode, g_ctx.decode && g_ctx.eos_file_decode,
                g_ctx.stream_codec)) {
            return -1;
        }
        if (fin) {
            std::fprintf(stderr, "[recv] stream FIN total=%zu\n", us->total_recvd);
        }
    }
    return 0;
}

static xqc_int_t rv_stream_write(xqc_stream_t*, void*) {
    return 0;
}

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
        ssize_t n = xqc_udp_recvmsg_gro(g_ctx.listen_fd, buf, sizeof(buf), &segs);
        if (n <= 0) {
            break;
        }
        user_conn_t temp{};
        temp.socket = g_ctx.listen_fd;
        const struct sockaddr* peer = reinterpret_cast<const struct sockaddr*>(&segs.peer);
        socklen_t peer_len = segs.peer_len;
        const struct sockaddr* local = segs.local_len
            ? reinterpret_cast<const struct sockaddr*>(&segs.local) : peer;
        socklen_t local_len = segs.local_len ? segs.local_len : peer_len;

        const unsigned char* seg;
        size_t seg_len;
        XQC_UDP_FOR_EACH_SEG(seg, seg_len, &segs) {
            xqc_engine_packet_process(g_ctx.engine, seg, seg_len,
                const_cast<struct sockaddr*>(local), local_len,
                const_cast<struct sockaddr*>(peer), peer_len,
                now_us(), &temp);
        }
    }
    if (g_ctx.engine) {
        xqc_engine_finish_recv(g_ctx.engine);
    }
    xqc_udp_writer_flush(&g_ctx.writer);
}

static void rv_stats_timer(int, short, void*) {
    XqcH264DecodeStats* st = xqc_h264_decode_stats();
    if (!st) {
        return;
    }
    const uint64_t pushed = st->annexb_pushed.load();
    const uint64_t stream_f = st->stream_frames.load();
    const uint64_t file_f = st->file_frames.load();
    const uint64_t lat_n = st->latency_count.load();
    const uint64_t lat_sum = st->latency_sum_us.load();
    const double avg_lat_ms = lat_n ? (static_cast<double>(lat_sum) / static_cast<double>(lat_n)) / 1000.0 : 0.0;
    std::fprintf(stderr,
        "[stats] nal_in=%llu stream_nv12=%llu file_nv12=%llu avg_decode_ms=%.2f last_pts_us=%llu\n",
        static_cast<unsigned long long>(pushed),
        static_cast<unsigned long long>(stream_f),
        static_cast<unsigned long long>(file_f),
        avg_lat_ms,
        static_cast<unsigned long long>(st->last_wire_pts_us.load()));
#if defined(XQC_HAVE_GLFW)
    if (g_ctx.display) {
        xqc_e2e_latency_hist().print_stderr("[e2e]");
    }
#endif
    if (g_ctx.ev_stats) {
        struct timeval tv {2, 0};
        event_add(g_ctx.ev_stats, &tv);
    }
}

} /* extern "C" */

static int init_engine() {
    xqc_platform_init_env();
    g_ctx.listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_ctx.listen_fd < 0) {
        return -1;
    }
    int opt = 1;
    setsockopt(g_ctx.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    xqc_apply_udp_perf_opts(g_ctx.listen_fd, AF_INET, 1);
    xqc_enable_udp_gro(g_ctx.listen_fd);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(g_ctx.port));
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(g_ctx.listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        return -1;
    }
    fcntl(g_ctx.listen_fd, F_SETFL, O_NONBLOCK);
    xqc_udp_writer_init(&g_ctx.writer, g_ctx.listen_fd);

    g_ctx.eb = event_base_new();
    g_ctx.ev_listen = event_new(g_ctx.eb, g_ctx.listen_fd, EV_READ | EV_PERSIST, rv_socket_cb, nullptr);
    event_add(g_ctx.ev_listen, nullptr);
    g_ctx.ev_engine = event_new(g_ctx.eb, -1, 0, rv_engine_timer, nullptr);

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) != XQC_OK) {
        return -1;
    }
    config.cfg_log_level = XQC_LOG_WARN;

    xqc_engine_ssl_config_t ssl{};
    memset(&ssl, 0, sizeof(ssl));
    ssl.cert_file = const_cast<char*>(g_ctx.cert_path.c_str());
    ssl.private_key_file = const_cast<char*>(g_ctx.key_path.c_str());

    xqc_engine_callback_t ecb{};
    ecb.set_event_timer = rv_set_timer;

    xqc_transport_callbacks_t tcb{};
    tcb.server_accept = rv_accept;
    tcb.write_socket = rv_write_socket;

    g_ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl, &ecb, &tcb, nullptr);
    if (!g_ctx.engine) {
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

    if (xqc_engine_register_alpn(g_ctx.engine, "transport", 9, &ap, nullptr) != XQC_OK) {
        return -1;
    }

    if (g_ctx.decode) {
        if (g_ctx.hw_decode_mode) {
            xqc_h264_decode_configure_hw(g_ctx.hw_decode_mode);
        }
        xqc_h264_decode_set_default_codec(g_ctx.stream_codec);
        xqc_h264_decode_enable_nv12_output(true);
        xqc_h264_decode_worker_start();
        g_ctx.ev_stats = event_new(g_ctx.eb, -1, 0, rv_stats_timer, nullptr);
        struct timeval tv {2, 0};
        event_add(g_ctx.ev_stats, &tv);
    }
#if defined(XQC_HAVE_GLFW)
    if (g_ctx.display) {
        if (!g_ctx.gl.start(XQC_VIDEO_TARGET_WIDTH, XQC_VIDEO_TARGET_HEIGHT, "xquic video 4K (WSL)")) {
            std::fprintf(stderr, "[recv] --display failed; continuing decode-only\n");
            g_ctx.display = false;
        } else {
            g_ctx.display_bridge = std::thread(display_bridge_loop);
        }
    }
#else
    if (g_ctx.display) {
        std::fprintf(stderr, "[recv] built without GLFW; use --decode only or install libglfw3-dev\n");
        g_ctx.display = false;
    }
#endif

    std::fprintf(stderr,
        "[recv] listening UDP :%d cert=%s decode=%d codec=%s stream=%d eos_file=%d display=%d dir=%s\n",
        g_ctx.port, g_ctx.cert_path.c_str(), g_ctx.decode ? 1 : 0,
        xqc_video_codec_name(g_ctx.stream_codec),
        g_ctx.stream_decode ? 1 : 0, g_ctx.eos_file_decode ? 1 : 0,
        g_ctx.display ? 1 : 0, g_ctx.video_dir.c_str());
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
        case 'p': g_ctx.port = atoi(optarg); break;
        case 'c': g_ctx.cert_path = optarg; break;
        case 'k': g_ctx.key_path = optarg; break;
        case 'd': g_ctx.video_dir = optarg; break;
        case 1: g_ctx.decode = true; break;
        case 2: g_ctx.display = true; g_ctx.decode = true; break;
        case 3: g_ctx.stream_decode = false; break;
        case 4: g_ctx.eos_file_decode = false; break;
        case 5:
            g_ctx.hw_decode_mode = (optarg && optarg[0]) ? optarg : "auto";
            break;
        case 6:
            g_ctx.stream_codec = xqc_video_codec_parse(optarg, XqcVideoCodec::HEVC);
            break;
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
    event_base_dispatch(g_ctx.eb);

    g_ctx.stopping = true;
    if (g_ctx.ev_stats) {
        event_free(g_ctx.ev_stats);
        g_ctx.ev_stats = nullptr;
    }
#if defined(XQC_HAVE_GLFW)
    if (g_ctx.display_bridge.joinable()) {
        g_ctx.display_bridge.join();
    }
    g_ctx.gl.stop();
#endif
#if defined(XQC_HAVE_GLFW)
    if (g_ctx.display) {
        xqc_e2e_latency_hist().print_stderr("[e2e final]");
    }
#endif
    xqc_h264_decode_worker_stop();
    if (g_ctx.engine) {
        xqc_engine_destroy(g_ctx.engine);
    }
    return 0;
}
