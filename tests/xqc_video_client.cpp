/**
 * @file xqc_video_client.cpp
 * @brief Video streaming client implementation.
 *
 * Reads .h264 Annex-B files, splits into NAL units, wraps each with
 * xqc_video_frame_header_t (16B), and sends on QUIC transport streams.
 *
 * Build: linked with libxquic + libevent
 */

#include "xqc_video_client.h"
#include "user_conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <time.h>
#include <iostream>
#include <getopt.h>

/* ─── Helpers ──────────────────────────────────────────────────── */

static uint64_t now_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

/* ─── C Trampolines ───────────────────────────────────────────── */

extern "C" {

static void vc_engine_timer_cb(int fd, short what, void *arg) {
    (void)fd; (void)what;
    if (arg) static_cast<XqcVideoClient*>(arg)->on_engine_timer();
}

static void vc_socket_cb(int fd, short what, void *arg) {
    (void)fd;
    auto *u_conn = static_cast<user_conn_t*>(arg);
    if (u_conn && u_conn->client)
        static_cast<XqcVideoClient*>(u_conn->client)->on_socket_event(fd, what, u_conn);
}

static void vc_set_event_timer(xqc_msec_t wake_after, void *ud) {
    if (ud) static_cast<XqcVideoClient*>(ud)->set_event_timer(wake_after);
}

static ssize_t vc_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *pa, socklen_t palen, void *uc)
{
    auto *u = static_cast<user_conn_t*>(uc);
    if (u && u->client)
        return static_cast<XqcVideoClient*>(u->client)->write_socket(buf, size, pa, palen, u);
    return -1;
}

static void vc_keylog(const xqc_cid_t*, const char*, void*) {}

static int vc_accept(xqc_engine_t*, xqc_connection_t*, const xqc_cid_t*, void*) { return 0; }
static void vc_refuse(xqc_engine_t*, xqc_connection_t*, const xqc_cid_t*, void*) {}

/* Transport callbacks */
static int vc_conn_create(xqc_connection_t*, const xqc_cid_t*, void*, void*) { return 0; }

static int vc_conn_close(xqc_connection_t *conn, const xqc_cid_t *cid, void *ud, void *cpd) {
    auto *u_conn = static_cast<user_conn_t*>(ud);
    if (u_conn && u_conn->client)
        static_cast<XqcVideoClient*>(u_conn->client)->on_conn_close_notify(conn, cid, ud, cpd);
    return 0;
}

static void vc_handshake(xqc_connection_t *conn, void *ud, void *cpd) {
    auto *u_conn = static_cast<user_conn_t*>(ud);
    if (u_conn && u_conn->client)
        static_cast<XqcVideoClient*>(u_conn->client)->on_conn_handshake_finished(conn, ud, cpd);
}

static xqc_int_t vc_stream_write(xqc_stream_t *s, void *ud) {
    auto *cam = static_cast<camera_stream_t*>(ud);
    if (cam && cam->u_stream && cam->u_stream->client)
        return static_cast<XqcVideoClient*>(cam->u_stream->client)->on_stream_write_notify(s, ud);
    return 0;
}

static xqc_int_t vc_stream_read(xqc_stream_t *s, void *ud) {
    auto *cam = static_cast<camera_stream_t*>(ud);
    if (cam && cam->u_stream && cam->u_stream->client)
        return static_cast<XqcVideoClient*>(cam->u_stream->client)->on_stream_read_notify(s, ud);
    return 0;
}

static xqc_int_t vc_stream_close(xqc_stream_t *s, void *ud) {
    auto *cam = static_cast<camera_stream_t*>(ud);
    if (cam && cam->u_stream && cam->u_stream->client)
        return static_cast<XqcVideoClient*>(cam->u_stream->client)->on_stream_close_notify(s, ud);
    return 0;
}

static ssize_t vc_stateless_reset(const unsigned char*, size_t,
    const struct sockaddr*, socklen_t,
    const struct sockaddr*, socklen_t, void*) { return -1; }

} /* extern "C" */

/* ─── H.264 Annex-B Parser ────────────────────────────────────── */

/**
 * Find next start code (00 00 01 or 00 00 00 01) in buffer.
 * Returns pointer to first byte after start code, or NULL.
 */
static const uint8_t* find_start_code(const uint8_t *data, size_t len, int *sc_len) {
    for (size_t i = 0; i + 2 < len; i++) {
        if (data[i] == 0 && data[i+1] == 0) {
            if (data[i+2] == 1) {
                *sc_len = 3;
                return data + i + 3;
            }
            if (i + 3 < len && data[i+2] == 0 && data[i+3] == 1) {
                *sc_len = 4;
                return data + i + 4;
            }
        }
    }
    return NULL;
}

bool XqcVideoClient::load_h264_file(const std::string &path, uint16_t camera_id,
                                     std::vector<nal_unit_t> &out_nals)
{
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open %s: %s\n", path.c_str(), strerror(errno));
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    auto *buf = static_cast<uint8_t*>(malloc(file_size));
    if (!buf) { fclose(fp); return false; }
    if (fread(buf, 1, file_size, fp) != (size_t)file_size) {
        free(buf); fclose(fp); return false;
    }
    fclose(fp);

    /* Split by start codes */
    const uint8_t *p = buf;
    const uint8_t *end = buf + file_size;
    int sc_len = 0;

    /* Find first start code */
    const uint8_t *nal_start = find_start_code(p, end - p, &sc_len);
    if (!nal_start) {
        free(buf);
        return false;
    }

    int64_t pts = 0;
    const int64_t frame_duration_us = 33333; /* ~30 fps */

    while (nal_start < end) {
        /* Find next start code to determine NAL end */
        int next_sc_len = 0;
        const uint8_t *next_nal = find_start_code(nal_start, end - nal_start, &next_sc_len);

        const uint8_t *nal_end;
        if (next_nal) {
            /* Back up past the start code of the next NAL */
            nal_end = next_nal - next_sc_len;
        } else {
            nal_end = end;
        }

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

            /* Only increment PTS for slice NALs (not SPS/PPS/SEI) */
            if (nal_type != XQC_H264_NAL_SPS && nal_type != XQC_H264_NAL_PPS && nal_type != XQC_H264_NAL_SEI) {
                pts += frame_duration_us;
            }

            out_nals.push_back(nal);
        }

        if (!next_nal) break;
        nal_start = next_nal;
    }

    free(buf);
    printf("Loaded %s: %zu NAL units, camera_id=%u\n", path.c_str(), out_nals.size(), camera_id);
    return true;
}

void XqcVideoClient::free_nals(std::vector<nal_unit_t> &nals) {
    for (auto &n : nals) {
        free(n.data);
        n.data = NULL;
    }
    nals.clear();
}

/* ─── Prepare send buffer for current NAL ─────────────────────── */

static void prepare_send_buf(camera_stream_t *cam) {
    if (cam->nal_index >= cam->nals.size()) return;

    const nal_unit_t &nal = cam->nals[cam->nal_index];

    /* Free previous buffer */
    free(cam->send_buf);

    cam->send_buf_len = XQC_VIDEO_FRAME_HEADER_LEN + nal.len;
    cam->send_buf = static_cast<uint8_t*>(malloc(cam->send_buf_len));

    /* Encode header */
    xqc_video_frame_header_t hdr;
    hdr.type = nal.type;
    hdr.flags = nal.flags;
    /* Mark last NAL as EOS */
    if (cam->nal_index == cam->nals.size() - 1) {
        hdr.flags |= XQC_VIDEO_FLAG_EOS;
    }
    hdr.camera_id = cam->camera_id;
    hdr.payload_len = (uint32_t)nal.len;
    hdr.pts_us = nal.pts_us;

    xqc_video_frame_header_encode(cam->send_buf, &hdr);
    memcpy(cam->send_buf + XQC_VIDEO_FRAME_HEADER_LEN, nal.data, nal.len);

    cam->send_buf_offset = 0;
}

/* ─── XqcVideoClient Implementation ──────────────────────────── */

XqcVideoClient::XqcVideoClient()
    : engine_(nullptr), event_base_(nullptr), ev_engine_(nullptr),
      server_ip_("127.0.0.1"), port_(8443), device_id_("device-001"),
      num_cameras_(0), u_conn_(nullptr)
{
    memset(cameras_, 0, sizeof(cameras_));
}

XqcVideoClient::~XqcVideoClient() {
    for (int i = 0; i < 2; i++) {
        free(cameras_[i].send_buf);
        free_nals(cameras_[i].nals);
    }
    if (engine_) xqc_engine_destroy(engine_);
    if (ev_engine_) event_free(ev_engine_);
    if (event_base_) event_base_free(event_base_);
}

int XqcVideoClient::init(int argc, char *argv[]) {
    /* Parse args */
    static struct option long_opts[] = {
        {"ip",       required_argument, 0, 'a'},
        {"port",     required_argument, 0, 'p'},
        {"cam0",     required_argument, 0, '0'},
        {"cam1",     required_argument, 0, '1'},
        {"device",   required_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "a:p:d:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a': server_ip_ = optarg; break;
        case 'p': port_ = atoi(optarg); break;
        case '0': cam_files_[0] = optarg; break;
        case '1': cam_files_[1] = optarg; break;
        case 'd': device_id_ = optarg; break;
        }
    }

    /* Count cameras */
    num_cameras_ = 0;
    for (int i = 0; i < 2; i++) {
        if (!cam_files_[i].empty()) {
            if (!load_h264_file(cam_files_[i], i, cameras_[i].nals)) {
                fprintf(stderr, "Failed to load camera %d file: %s\n", i, cam_files_[i].c_str());
                return -1;
            }
            cameras_[i].camera_id = i;
            num_cameras_++;
        }
    }

    if (num_cameras_ == 0) {
        fprintf(stderr, "Usage: %s -a <ip> -p <port> --cam0 <file.h264> [--cam1 <file.h264>]\n", argv[0]);
        return -1;
    }

    printf("Video client: %d camera(s), device=%s, server=%s:%d\n",
           num_cameras_, device_id_.c_str(), server_ip_.c_str(), port_);

    /* libevent */
    event_base_ = event_base_new();
    ev_engine_ = event_new(event_base_, -1, 0, vc_engine_timer_cb, this);

    /* xquic engine */
    xqc_engine_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));

    xqc_engine_callback_t engine_cbs;
    memset(&engine_cbs, 0, sizeof(engine_cbs));
    engine_cbs.set_event_timer = vc_set_event_timer;
    engine_cbs.keylog_cb = vc_keylog;
    engine_cbs.log_callbacks.xqc_log_write_err = [](xqc_log_level_t, const void *buf, size_t size, void*) {
        fprintf(stderr, "XQC: %.*s\n", (int)size, (const char*)buf);
    };
    engine_cbs.log_callbacks.xqc_log_write_stat = [](xqc_log_level_t, const void *buf, size_t size, void*) {};

    xqc_transport_callbacks_t tcbs;
    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.write_socket       = vc_write_socket;
    tcbs.server_accept      = vc_accept;
    tcbs.server_refuse      = vc_refuse;
    tcbs.stateless_reset    = vc_stateless_reset;
    tcbs.save_token         = [](const unsigned char*, uint32_t, void*) {};
    tcbs.save_session_cb    = [](const char*, size_t, void*) {};
    tcbs.save_tp_cb         = [](const char*, size_t, void*) {};

    xqc_conn_callbacks_t conn_cbs;
    memset(&conn_cbs, 0, sizeof(conn_cbs));
    conn_cbs.conn_create_notify         = vc_conn_create;
    conn_cbs.conn_close_notify          = vc_conn_close;
    conn_cbs.conn_handshake_finished    = vc_handshake;

    xqc_stream_callbacks_t stream_cbs;
    memset(&stream_cbs, 0, sizeof(stream_cbs));
    stream_cbs.stream_write_notify = vc_stream_write;
    stream_cbs.stream_read_notify  = vc_stream_read;
    stream_cbs.stream_close_notify = vc_stream_close;

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) != XQC_OK) {
        return -1;
    }

    engine_ = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl_cfg, &engine_cbs, &tcbs, this);
    if (!engine_) {
        fprintf(stderr, "Failed to create xquic engine\n");
        return -1;
    }

    /* Register transport protocol with stream callbacks */
    xqc_app_proto_callbacks_t ap_cbs;
    memset(&ap_cbs, 0, sizeof(ap_cbs));
    ap_cbs.conn_cbs   = conn_cbs;
    ap_cbs.stream_cbs = stream_cbs;

    if (xqc_engine_register_alpn(engine_, "transport", 9, &ap_cbs, NULL) != XQC_OK) {
        fprintf(stderr, "Failed to register ALPN\n");
        return -1;
    }

    return 0;
}

user_conn_t* XqcVideoClient::create_connection() {
    auto *u_conn = static_cast<user_conn_t*>(calloc(1, sizeof(user_conn_t)));
    u_conn->client = this;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    inet_pton(AF_INET, server_ip_.c_str(), &addr.sin_addr);

    u_conn->peer_addr = static_cast<struct sockaddr*>(malloc(sizeof(addr)));
    memcpy(u_conn->peer_addr, &addr, sizeof(addr));
    u_conn->peer_addrlen = sizeof(addr);

    u_conn->fd = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(u_conn->fd, F_SETFL, O_NONBLOCK);

    u_conn->ev_socket = event_new(event_base_, u_conn->fd, EV_READ | EV_PERSIST, vc_socket_cb, u_conn);
    event_add(u_conn->ev_socket, NULL);

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.proto_version = XQC_VERSION_V1;

    xqc_conn_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));

    const xqc_cid_t *cid = xqc_connect(engine_, &conn_settings, NULL, 0,
        server_ip_.c_str(), 1, &ssl_config,
        (struct sockaddr*)&addr, sizeof(addr), "transport", u_conn);
    if (!cid) {
        fprintf(stderr, "xqc_connect failed\n");
        free(u_conn->peer_addr);
        close(u_conn->fd);
        free(u_conn);
        return NULL;
    }
    memcpy(&u_conn->cid, cid, sizeof(*cid));
    return u_conn;
}

void XqcVideoClient::create_camera_streams(user_conn_t *u_conn) {
    for (int i = 0; i < 2; i++) {
        if (cameras_[i].nals.empty()) continue;

        auto *u_stream = static_cast<user_stream_t*>(calloc(1, sizeof(user_stream_t)));
        u_stream->client = this;
        u_stream->user_conn = u_conn;
        u_stream->start_time = now_us();

        cameras_[i].u_stream = u_stream;
        cameras_[i].nal_index = 0;
        cameras_[i].finished = 0;

        xqc_stream_t *stream = xqc_stream_create(engine_, &u_conn->cid, NULL, &cameras_[i]);
        if (!stream) {
            fprintf(stderr, "Failed to create stream for camera %d\n", i);
            free(u_stream);
            continue;
        }
        cameras_[i].stream = stream;
        u_stream->stream = stream;

        printf("Created stream for camera %d, %zu NAL units\n", i, cameras_[i].nals.size());

        /* Prepare first NAL and start sending */
        prepare_send_buf(&cameras_[i]);
        send_camera_data(&cameras_[i]);
    }
}

void XqcVideoClient::send_camera_data(camera_stream_t *cam) {
    if (!cam || !cam->stream || cam->finished) return;

    while (true) {
        /* If current send_buf is exhausted, move to next NAL */
        if (cam->send_buf && cam->send_buf_offset >= cam->send_buf_len) {
            cam->nal_index++;
            if (cam->nal_index >= cam->nals.size()) {
                /* All NALs sent — close stream with FIN */
                cam->finished = 1;
                printf("Camera %u: all %zu NALs sent, total=%zu bytes\n",
                       cam->camera_id, cam->nals.size(),
                       cam->u_stream ? cam->u_stream->total_sent : 0);
                return;
            }
            prepare_send_buf(cam);
        }

        if (!cam->send_buf) return;

        size_t remaining = cam->send_buf_len - cam->send_buf_offset;
        int fin = (cam->nal_index == cam->nals.size() - 1) ? 1 : 0;

        ssize_t sent = xqc_stream_send(cam->stream,
            cam->send_buf + cam->send_buf_offset, remaining, fin);

        if (sent == -XQC_EAGAIN) {
            return; /* write_notify will call us again */
        }
        if (sent < 0) {
            fprintf(stderr, "Camera %u: send error=%zd\n", cam->camera_id, sent);
            cam->finished = 1;
            return;
        }

        cam->send_buf_offset += (size_t)sent;
        if (cam->u_stream) cam->u_stream->total_sent += (size_t)sent;
    }
}

void XqcVideoClient::on_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data) {
    (void)conn; (void)conn_proto_data;
    printf("Video client: handshake finished, creating camera streams\n");
    auto *u_conn = static_cast<user_conn_t*>(user_data);
    create_camera_streams(u_conn);
}

void XqcVideoClient::on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data) {
    (void)conn; (void)cid; (void)conn_proto_data;
    printf("Video client: connection closed\n");
    if (event_base_) event_base_loopbreak(event_base_);
}

xqc_int_t XqcVideoClient::on_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    (void)stream;
    auto *cam = static_cast<camera_stream_t*>(user_data);
    if (cam) send_camera_data(cam);
    return 0;
}

xqc_int_t XqcVideoClient::on_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    (void)user_data;
    /* Client doesn't expect data back for video push */
    unsigned char buf[4096];
    unsigned char fin = 0;
    while (xqc_stream_recv(stream, buf, sizeof(buf), &fin) > 0) {}
    return 0;
}

xqc_int_t XqcVideoClient::on_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    (void)stream;
    auto *cam = static_cast<camera_stream_t*>(user_data);
    if (cam) {
        printf("Camera %u stream closed, sent=%zu bytes\n",
               cam->camera_id, cam->u_stream ? cam->u_stream->total_sent : 0);
        free(cam->u_stream);
        cam->u_stream = nullptr;
        cam->stream = nullptr;
    }
    return 0;
}

int XqcVideoClient::start(int argc, char *argv[]) {
    if (init(argc, argv) != 0) return -1;
    u_conn_ = create_connection();
    if (!u_conn_) return -1;
    run();
    return 0;
}

void XqcVideoClient::run() {
    if (event_base_) event_base_dispatch(event_base_);
}

void XqcVideoClient::set_event_timer(xqc_msec_t wake_after) {
    if (ev_engine_) {
        struct timeval tv;
        tv.tv_sec = wake_after / 1000000;
        tv.tv_usec = wake_after % 1000000;
        event_add(ev_engine_, &tv);
    }
}

ssize_t XqcVideoClient::write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, user_conn_t *u_conn)
{
    if (!u_conn || u_conn->fd < 0) return -1;
    return sendto(u_conn->fd, buf, size, 0, peer_addr, peer_addrlen);
}

void XqcVideoClient::on_engine_timer() {
    if (engine_) xqc_engine_main_logic(engine_);
}

void XqcVideoClient::on_socket_event(int fd, short what, user_conn_t *u_conn) {
    (void)fd;
    if (what & EV_READ) process_socket_read(u_conn);
}

void XqcVideoClient::process_socket_read(user_conn_t *u_conn) {
    if (!u_conn || !engine_) return;

    unsigned char buf[65536];
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;

    while (1) {
        peer_addrlen = sizeof(peer_addr);
        ssize_t n = recvfrom(u_conn->fd, buf, sizeof(buf), 0,
            (struct sockaddr*)&peer_addr, &peer_addrlen);
        if (n <= 0) break;
        xqc_engine_packet_process(engine_, buf, n,
            u_conn->peer_addr, u_conn->peer_addrlen,
            (struct sockaddr*)&peer_addr, peer_addrlen,
            now_us(), u_conn);
    }
    xqc_engine_finish_recv(engine_);
}

/* ─── main ─────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    XqcVideoClient client;
    return client.start(argc, argv);
}
