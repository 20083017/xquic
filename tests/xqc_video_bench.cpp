/**
 * @file xqc_video_bench.cpp
 * @brief Video streaming benchmark client.
 *
 * Creates N concurrent QUIC connections, each sending the same .h264 file
 * on a transport stream. Measures throughput, connection completion rate,
 * and latency. Supports repeated rounds (-r) for sustained load.
 *
 * Usage:
 *   ./video_bench -a 127.0.0.1 -p 8443 --cam0 test_cam0.h264 -n 100 -r 3
 *
 * Build: linked with libxquic + libevent
 */

#include "user_conn.h"
#include <xquic/xquic.h>
#include <xquic/xqc_video_frame.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <getopt.h>

#include <vector>
#include <string>
#include <atomic>
#include <algorithm>
#include <numeric>

/* ─── Globals ──────────────────────────────────────────────────── */

static uint64_t now_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

/* NAL unit extracted from Annex-B stream */
struct nal_unit_t {
    uint8_t *data;
    size_t   len;
    int64_t  pts_us;
    xqc_video_frame_type_t type;
    uint8_t  flags;
};

/* Per-connection bench state */
struct bench_conn_t {
    user_conn_t        *u_conn;
    xqc_stream_t       *stream;
    int                 conn_idx;

    /* NAL sending state */
    size_t              nal_index;
    uint8_t            *send_buf;
    size_t              send_buf_len;
    size_t              send_buf_offset;
    int                 finished;
    int                 closed;

    /* Timing */
    uint64_t            start_us;
    uint64_t            handshake_us;
    uint64_t            finish_us;
    size_t              total_sent;

    /* Back-pointer */
    void               *bench;  /* BenchContext* */
};

struct BenchContext {
    xqc_engine_t       *engine;
    event_base         *ev_base;
    event              *ev_engine;
    event              *ev_stats;

    std::string         server_ip;
    int                 port;
    int                 num_conns;
    int                 num_rounds;
    int                 current_round;

    /* Shared NAL data (read-only after load) */
    std::vector<nal_unit_t> nals;
    size_t              file_bytes; /* total bytes per stream (header+payload) */

    /* Connections */
    std::vector<bench_conn_t*> conns;

    /* Stats */
    int                 conns_created;
    int                 conns_handshaked;
    int                 conns_completed;
    int                 conns_failed;
    uint64_t            round_start_us;
    std::vector<uint64_t> latencies_us; /* per-connection total time */
    bool                finished;
};

static BenchContext g_ctx;

/* ─── H.264 Annex-B Parser ────────────────────────────────────── */

static const uint8_t* find_start_code(const uint8_t *data, size_t len, int *sc_len) {
    for (size_t i = 0; i + 2 < len; i++) {
        if (data[i] == 0 && data[i+1] == 0) {
            if (data[i+2] == 1) { *sc_len = 3; return data + i + 3; }
            if (i + 3 < len && data[i+2] == 0 && data[i+3] == 1) { *sc_len = 4; return data + i + 4; }
        }
    }
    return NULL;
}

static bool load_h264_file(const std::string &path, std::vector<nal_unit_t> &out_nals, size_t &out_total) {
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp) { fprintf(stderr, "Cannot open %s: %s\n", path.c_str(), strerror(errno)); return false; }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    auto *buf = static_cast<uint8_t*>(malloc(file_size));
    if (!buf) { fclose(fp); return false; }
    if ((long)fread(buf, 1, file_size, fp) != file_size) { free(buf); fclose(fp); return false; }
    fclose(fp);

    const uint8_t *end = buf + file_size;
    int sc_len = 0;
    const uint8_t *nal_start = find_start_code(buf, file_size, &sc_len);
    if (!nal_start) { free(buf); return false; }

    int64_t pts = 0;
    const int64_t frame_dur = 33333;
    out_total = 0;

    while (nal_start < end) {
        int next_sc_len = 0;
        const uint8_t *next = find_start_code(nal_start, end - nal_start, &next_sc_len);
        const uint8_t *nal_end = next ? (next - next_sc_len) : end;
        size_t nal_len = nal_end - nal_start;

        if (nal_len > 0) {
            nal_unit_t nal;
            nal.data = static_cast<uint8_t*>(malloc(nal_len));
            memcpy(nal.data, nal_start, nal_len);
            nal.len = nal_len;
            nal.pts_us = pts;

            uint8_t nal_type = xqc_video_h264_nal_type(nal.data[0]);
            nal.type = xqc_video_h264_nal_to_frame_type(nal_type);
            nal.flags = 0;
            if (nal_type == XQC_H264_NAL_IDR) nal.flags |= XQC_VIDEO_FLAG_KEYFRAME;
            if (nal_type == XQC_H264_NAL_SPS || nal_type == XQC_H264_NAL_PPS) nal.flags |= XQC_VIDEO_FLAG_CONFIG;
            if (nal_type != XQC_H264_NAL_SPS && nal_type != XQC_H264_NAL_PPS && nal_type != XQC_H264_NAL_SEI)
                pts += frame_dur;

            out_total += XQC_VIDEO_FRAME_HEADER_LEN + nal_len;
            out_nals.push_back(nal);
        }
        if (!next) break;
        nal_start = next;
    }

    free(buf);
    printf("Loaded %s: %zu NALs, %zu bytes/stream\n", path.c_str(), out_nals.size(), out_total);
    return true;
}

/* ─── Send buffer preparation ─────────────────────────────────── */

static void prepare_send_buf(bench_conn_t *bc) {
    if (bc->nal_index >= g_ctx.nals.size()) return;
    const nal_unit_t &nal = g_ctx.nals[bc->nal_index];

    free(bc->send_buf);
    bc->send_buf_len = XQC_VIDEO_FRAME_HEADER_LEN + nal.len;
    bc->send_buf = static_cast<uint8_t*>(malloc(bc->send_buf_len));

    xqc_video_frame_header_t hdr;
    hdr.type = nal.type;
    hdr.flags = nal.flags;
    if (bc->nal_index == g_ctx.nals.size() - 1) hdr.flags |= XQC_VIDEO_FLAG_EOS;
    hdr.camera_id = (uint16_t)(bc->conn_idx % 65536);
    hdr.payload_len = (uint32_t)nal.len;
    hdr.pts_us = nal.pts_us;

    xqc_video_frame_header_encode(bc->send_buf, &hdr);
    memcpy(bc->send_buf + XQC_VIDEO_FRAME_HEADER_LEN, nal.data, nal.len);
    bc->send_buf_offset = 0;
}

static void send_data(bench_conn_t *bc) {
    if (!bc || !bc->stream || bc->finished) return;

    while (true) {
        if (bc->send_buf && bc->send_buf_offset >= bc->send_buf_len) {
            bc->nal_index++;
            if (bc->nal_index >= g_ctx.nals.size()) {
                bc->finished = 1;
                bc->finish_us = now_us();
                g_ctx.conns_completed++;
                uint64_t lat = bc->finish_us - bc->start_us;
                g_ctx.latencies_us.push_back(lat);
                /* Close connection after all data sent */
                if (bc->u_conn && g_ctx.engine) {
                    xqc_conn_close(g_ctx.engine, &bc->u_conn->cid);
                }
                return;
            }
            prepare_send_buf(bc);
        }
        if (!bc->send_buf) return;

        size_t remaining = bc->send_buf_len - bc->send_buf_offset;
        int fin = (bc->nal_index == g_ctx.nals.size() - 1) ? 1 : 0;

        ssize_t sent = xqc_stream_send(bc->stream,
            bc->send_buf + bc->send_buf_offset, remaining, fin);
        if (sent == -XQC_EAGAIN) return;
        if (sent < 0) {
            bc->finished = 1;
            g_ctx.conns_failed++;
            return;
        }
        bc->send_buf_offset += (size_t)sent;
        bc->total_sent += (size_t)sent;
    }
}

/* ─── Check if round is done ──────────────────────────────────── */

static void check_round_done();
static void start_round();

static void check_round_done() {
    if (g_ctx.finished) return;
    int done = g_ctx.conns_completed + g_ctx.conns_failed;
    if (done < g_ctx.num_conns) return;

    /* Cancel stats timer */
    if (g_ctx.ev_stats) event_del(g_ctx.ev_stats);

    uint64_t elapsed = now_us() - g_ctx.round_start_us;
    double elapsed_s = elapsed / 1e6;
    uint64_t total_bytes = (uint64_t)g_ctx.conns_completed * g_ctx.file_bytes;
    double throughput_mbps = (total_bytes * 8.0) / elapsed_s / 1e6;

    printf("\n══════ Round %d/%d Complete ══════\n", g_ctx.current_round, g_ctx.num_rounds);
    printf("  Connections: %d created, %d completed, %d failed\n",
           g_ctx.conns_created, g_ctx.conns_completed, g_ctx.conns_failed);
    printf("  Time: %.3f s\n", elapsed_s);
    printf("  Throughput: %.2f Mbps (%.2f MB/s)\n", throughput_mbps, throughput_mbps / 8.0);
    printf("  Bytes/conn: %zu\n", g_ctx.file_bytes);

    if (!g_ctx.latencies_us.empty()) {
        std::sort(g_ctx.latencies_us.begin(), g_ctx.latencies_us.end());
        size_t n = g_ctx.latencies_us.size();
        uint64_t sum = 0;
        for (auto v : g_ctx.latencies_us) sum += v;
        printf("  Latency (ms): avg=%.1f p50=%.1f p95=%.1f p99=%.1f max=%.1f\n",
               sum / (double)n / 1000.0,
               g_ctx.latencies_us[n / 2] / 1000.0,
               g_ctx.latencies_us[(size_t)(n * 0.95)] / 1000.0,
               g_ctx.latencies_us[(size_t)(n * 0.99)] / 1000.0,
               g_ctx.latencies_us[n - 1] / 1000.0);
    }
    printf("══════════════════════════════\n\n");

    /* Clean up connections */
    for (auto *bc : g_ctx.conns) {
        if (bc->u_conn) {
            if (bc->u_conn->ev_socket) { event_free(bc->u_conn->ev_socket); bc->u_conn->ev_socket = NULL; }
            if (bc->u_conn->fd >= 0) close(bc->u_conn->fd);
            free(bc->u_conn->peer_addr);
            free(bc->u_conn);
        }
        free(bc->send_buf);
        free(bc);
    }
    g_ctx.conns.clear();

    /* Next round? */
    g_ctx.current_round++;
    if (g_ctx.current_round <= g_ctx.num_rounds) {
        start_round();
    } else {
        printf("Benchmark complete.\n");
        g_ctx.finished = true;
        event_base_loopbreak(g_ctx.ev_base);
    }
}

/* ─── C Trampolines ───────────────────────────────────────────── */

extern "C" {

static void bench_engine_timer_cb(int fd, short what, void *arg) {
    (void)fd; (void)what; (void)arg;
    if (g_ctx.engine) xqc_engine_main_logic(g_ctx.engine);
}

static void bench_stats_cb(int fd, short what, void *arg) {
    (void)fd; (void)what; (void)arg;
    int done = g_ctx.conns_completed + g_ctx.conns_failed;
    uint64_t elapsed = now_us() - g_ctx.round_start_us;
    printf("[bench] %.1fs: %d/%d done (%d ok, %d fail), handshaked=%d\n",
           elapsed / 1e6, done, g_ctx.num_conns,
           g_ctx.conns_completed, g_ctx.conns_failed, g_ctx.conns_handshaked);

    /* Re-arm periodic stats */
    struct timeval tv = {2, 0};
    event_add(g_ctx.ev_stats, &tv);
}

static void bench_set_event_timer(xqc_msec_t wake_after, void *ud) {
    (void)ud;
    if (g_ctx.ev_engine) {
        struct timeval tv;
        tv.tv_sec = wake_after / 1000000;
        tv.tv_usec = wake_after % 1000000;
        event_add(g_ctx.ev_engine, &tv);
    }
}

static ssize_t bench_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *pa, socklen_t palen, void *uc)
{
    auto *u = static_cast<user_conn_t*>(uc);
    if (!u || u->fd < 0) return -1;
    return sendto(u->fd, buf, size, 0, pa, palen);
}

static void bench_socket_cb(int fd, short what, void *arg) {
    (void)fd;
    auto *u_conn = static_cast<user_conn_t*>(arg);
    if (!(what & EV_READ) || !u_conn || !g_ctx.engine) return;

    unsigned char buf[65536];
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;

    while (1) {
        peer_addrlen = sizeof(peer_addr);
        ssize_t n = recvfrom(u_conn->fd, buf, sizeof(buf), 0,
            (struct sockaddr*)&peer_addr, &peer_addrlen);
        if (n <= 0) break;
        xqc_engine_packet_process(g_ctx.engine, buf, n,
            u_conn->peer_addr, u_conn->peer_addrlen,
            (struct sockaddr*)&peer_addr, peer_addrlen,
            now_us(), u_conn);
    }
    xqc_engine_finish_recv(g_ctx.engine);
}

static int bench_conn_create(xqc_connection_t*, const xqc_cid_t*, void*, void*) { return 0; }

static int bench_conn_close(xqc_connection_t *conn, const xqc_cid_t *cid, void *ud, void *cpd) {
    (void)conn; (void)cid; (void)cpd;
    auto *u_conn = static_cast<user_conn_t*>(ud);
    if (!u_conn) return 0;

    /* Find bench_conn and mark closed */
    auto *bc = static_cast<bench_conn_t*>(u_conn->client);
    if (bc && !bc->finished && !bc->closed) {
        bc->closed = 1;
        bc->finished = 1;
        g_ctx.conns_failed++;
    }
    if (bc) bc->closed = 1;
    check_round_done();
    return 0;
}

static void bench_handshake(xqc_connection_t *conn, void *ud, void *cpd) {
    (void)conn; (void)cpd;
    auto *u_conn = static_cast<user_conn_t*>(ud);
    if (!u_conn) return;
    auto *bc = static_cast<bench_conn_t*>(u_conn->client);
    if (!bc) return;

    bc->handshake_us = now_us();
    g_ctx.conns_handshaked++;

    /* Create stream and start sending */
    xqc_stream_t *stream = xqc_stream_create(g_ctx.engine, &u_conn->cid, NULL, bc);
    if (!stream) {
        fprintf(stderr, "[bench] conn %d: stream create failed\n", bc->conn_idx);
        bc->finished = 1;
        g_ctx.conns_failed++;
        check_round_done();
        return;
    }
    bc->stream = stream;
    prepare_send_buf(bc);
    send_data(bc);
}

static xqc_int_t bench_stream_write(xqc_stream_t *s, void *ud) {
    (void)s;
    auto *bc = static_cast<bench_conn_t*>(ud);
    if (bc) send_data(bc);
    check_round_done();
    return 0;
}

static xqc_int_t bench_stream_read(xqc_stream_t *s, void *ud) {
    (void)ud;
    unsigned char buf[4096];
    unsigned char fin = 0;
    while (xqc_stream_recv(s, buf, sizeof(buf), &fin) > 0) {}
    return 0;
}

static xqc_int_t bench_stream_close(xqc_stream_t *s, void *ud) {
    (void)s;
    auto *bc = static_cast<bench_conn_t*>(ud);
    if (bc) {
        bc->stream = NULL;
        if (!bc->finished) {
            bc->finished = 1;
            g_ctx.conns_failed++;
        }
    }
    check_round_done();
    return 0;
}

static int bench_accept(xqc_engine_t*, xqc_connection_t*, const xqc_cid_t*, void*) { return 0; }
static void bench_refuse(xqc_engine_t*, xqc_connection_t*, const xqc_cid_t*, void*) {}
static ssize_t bench_stateless_reset(const unsigned char*, size_t,
    const struct sockaddr*, socklen_t, const struct sockaddr*, socklen_t, void*) { return -1; }
static void bench_keylog(const xqc_cid_t*, const char*, void*) {}

} /* extern "C" */

/* ─── Start a round of connections ────────────────────────────── */

static void start_round() {
    printf("\n══════ Starting Round %d/%d: %d connections ══════\n",
           g_ctx.current_round, g_ctx.num_rounds, g_ctx.num_conns);

    g_ctx.conns_created = 0;
    g_ctx.conns_handshaked = 0;
    g_ctx.conns_completed = 0;
    g_ctx.conns_failed = 0;
    g_ctx.finished = false;
    g_ctx.latencies_us.clear();
    g_ctx.round_start_us = now_us();

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_ctx.port);
    inet_pton(AF_INET, g_ctx.server_ip.c_str(), &addr.sin_addr);

    for (int i = 0; i < g_ctx.num_conns; i++) {
        auto *bc = static_cast<bench_conn_t*>(calloc(1, sizeof(bench_conn_t)));
        bc->conn_idx = i;
        bc->bench = &g_ctx;
        bc->start_us = now_us();

        auto *u_conn = static_cast<user_conn_t*>(calloc(1, sizeof(user_conn_t)));
        u_conn->client = bc; /* bench_conn_t stored here for trampoline access */
        u_conn->peer_addr = static_cast<struct sockaddr*>(malloc(sizeof(addr)));
        memcpy(u_conn->peer_addr, &addr, sizeof(addr));
        u_conn->peer_addrlen = sizeof(addr);

        u_conn->fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (u_conn->fd < 0) {
            fprintf(stderr, "[bench] socket() failed: %s\n", strerror(errno));
            free(u_conn->peer_addr); free(u_conn); free(bc);
            g_ctx.conns_failed++;
            continue;
        }
        fcntl(u_conn->fd, F_SETFL, O_NONBLOCK);

        u_conn->ev_socket = event_new(g_ctx.ev_base, u_conn->fd, EV_READ | EV_PERSIST, bench_socket_cb, u_conn);
        event_add(u_conn->ev_socket, NULL);

        xqc_conn_settings_t conn_settings;
        memset(&conn_settings, 0, sizeof(conn_settings));
        conn_settings.proto_version = XQC_VERSION_V1;

        xqc_conn_ssl_config_t ssl_config;
        memset(&ssl_config, 0, sizeof(ssl_config));

        const xqc_cid_t *cid = xqc_connect(g_ctx.engine, &conn_settings, NULL, 0,
            g_ctx.server_ip.c_str(), 1, &ssl_config,
            (struct sockaddr*)&addr, sizeof(addr), "transport", u_conn);

        if (!cid) {
            fprintf(stderr, "[bench] conn %d: xqc_connect failed\n", i);
            event_free(u_conn->ev_socket);
            close(u_conn->fd);
            free(u_conn->peer_addr); free(u_conn); free(bc);
            g_ctx.conns_failed++;
            continue;
        }

        memcpy(&u_conn->cid, cid, sizeof(*cid));
        bc->u_conn = u_conn;
        g_ctx.conns.push_back(bc);
        g_ctx.conns_created++;
    }

    printf("[bench] Created %d connections\n", g_ctx.conns_created);

    /* Start periodic stats timer */
    struct timeval tv = {2, 0};
    event_add(g_ctx.ev_stats, &tv);
}

/* ─── main ─────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    g_ctx.server_ip = "127.0.0.1";
    g_ctx.port = 8443;
    g_ctx.num_conns = 10;
    g_ctx.num_rounds = 1;

    std::string cam_file;

    static struct option long_opts[] = {
        {"ip",     required_argument, 0, 'a'},
        {"port",   required_argument, 0, 'p'},
        {"num",    required_argument, 0, 'n'},
        {"rounds", required_argument, 0, 'r'},
        {"cam0",   required_argument, 0, '0'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "a:p:n:r:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a': g_ctx.server_ip = optarg; break;
        case 'p': g_ctx.port = atoi(optarg); break;
        case 'n': g_ctx.num_conns = atoi(optarg); break;
        case 'r': g_ctx.num_rounds = atoi(optarg); break;
        case '0': cam_file = optarg; break;
        }
    }

    if (cam_file.empty()) {
        fprintf(stderr, "Usage: %s -a <ip> -p <port> -n <conns> -r <rounds> --cam0 <file.h264>\n", argv[0]);
        return 1;
    }

    if (!load_h264_file(cam_file, g_ctx.nals, g_ctx.file_bytes)) return 1;

    printf("Video Benchmark: %d connections x %d rounds, server=%s:%d\n",
           g_ctx.num_conns, g_ctx.num_rounds, g_ctx.server_ip.c_str(), g_ctx.port);

    /* libevent */
    g_ctx.ev_base = event_base_new();
    g_ctx.ev_engine = event_new(g_ctx.ev_base, -1, 0, bench_engine_timer_cb, NULL);
    g_ctx.ev_stats = event_new(g_ctx.ev_base, -1, 0, bench_stats_cb, NULL);

    /* xquic engine */
    xqc_engine_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));

    xqc_engine_callback_t engine_cbs;
    memset(&engine_cbs, 0, sizeof(engine_cbs));
    engine_cbs.set_event_timer = bench_set_event_timer;
    engine_cbs.keylog_cb = bench_keylog;
    engine_cbs.log_callbacks.xqc_log_write_err = [](xqc_log_level_t, const void*, size_t, void*) {};
    engine_cbs.log_callbacks.xqc_log_write_stat = [](xqc_log_level_t, const void*, size_t, void*) {};

    xqc_transport_callbacks_t tcbs;
    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.write_socket    = bench_write_socket;
    tcbs.server_accept   = bench_accept;
    tcbs.server_refuse   = bench_refuse;
    tcbs.stateless_reset = bench_stateless_reset;
    tcbs.save_token      = [](const unsigned char*, uint32_t, void*) {};
    tcbs.save_session_cb = [](const char*, size_t, void*) {};
    tcbs.save_tp_cb      = [](const char*, size_t, void*) {};

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) != XQC_OK) return 1;
    config.cfg_log_level = XQC_LOG_WARN; /* Reduce noise during bench */

    g_ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl_cfg, &engine_cbs, &tcbs, NULL);
    if (!g_ctx.engine) { fprintf(stderr, "Failed to create engine\n"); return 1; }

    /* Register ALPN */
    xqc_app_proto_callbacks_t ap_cbs;
    memset(&ap_cbs, 0, sizeof(ap_cbs));
    ap_cbs.conn_cbs.conn_create_notify = bench_conn_create;
    ap_cbs.conn_cbs.conn_close_notify = bench_conn_close;
    ap_cbs.conn_cbs.conn_handshake_finished = bench_handshake;
    ap_cbs.stream_cbs.stream_write_notify = bench_stream_write;
    ap_cbs.stream_cbs.stream_read_notify = bench_stream_read;
    ap_cbs.stream_cbs.stream_close_notify = bench_stream_close;

    if (xqc_engine_register_alpn(g_ctx.engine, "transport", 9, &ap_cbs, NULL) != XQC_OK) {
        fprintf(stderr, "Failed to register ALPN\n"); return 1;
    }

    /* Start first round */
    g_ctx.current_round = 1;
    start_round();

    /* Run event loop */
    event_base_dispatch(g_ctx.ev_base);

    /* Cleanup */
    for (auto &n : g_ctx.nals) free(n.data);
    if (g_ctx.ev_stats) event_free(g_ctx.ev_stats);
    if (g_ctx.ev_engine) event_free(g_ctx.ev_engine);
    if (g_ctx.engine) xqc_engine_destroy(g_ctx.engine);
    if (g_ctx.ev_base) event_base_free(g_ctx.ev_base);

    return 0;
}
