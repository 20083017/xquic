/**
 * @file xqc_video_client.h
 * @brief Video streaming client — reads .h264 / .h265 Annex-B files and pushes
 *        them over QUIC transport streams using xqc_video_frame protocol.
 *
 * Usage:
 *   ./video_client -a 127.0.0.1 -p 8443 --cam0 cam0.h265 [--codec hevc] [--fps 30]
 */

#ifndef XQC_VIDEO_CLIENT_H
#define XQC_VIDEO_CLIENT_H

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_video_frame.h>
#include "lowlatency/xqc_video_codec.hh"
#include "user_conn.h"
#include <string>
#include <vector>

/* NAL unit extracted from Annex-B stream */
struct nal_unit_t {
    uint8_t            *data;       /* raw NAL bytes (no start code) */
    size_t              len;
    int64_t             pts_us;
    xqc_video_frame_type_t type;
    uint8_t             flags;
};

/* Per-camera state — each camera is one QUIC stream */
struct camera_stream_t {
    user_stream_t      *u_stream;
    xqc_stream_t       *stream;
    uint16_t            camera_id;
    XqcVideoCodec       codec;

    std::vector<nal_unit_t> nals;
    size_t              nal_index;
    int64_t             pace_us;

    uint8_t            *send_buf;
    size_t              send_buf_len;
    size_t              send_buf_offset;
    int                 finished;
};

class XqcVideoClient {
public:
    XqcVideoClient();
    ~XqcVideoClient();

    int  init(int argc, char *argv[]);
    int  start(int argc, char *argv[]);
    void run();

    void on_engine_timer();
    void on_pace_tick();
    void on_socket_event(int fd, short what, user_conn_t *u_conn);
    void process_socket_read(user_conn_t *u_conn);
    void set_event_timer(xqc_msec_t wake_after);
    ssize_t write_socket(const unsigned char *buf, size_t size,
                         const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                         user_conn_t *u_conn);

    void on_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data);
    void on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);
    xqc_int_t on_stream_write_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_read_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_close_notify(xqc_stream_t *stream, void *user_data);

    user_conn_t* create_connection();
    void create_camera_streams(user_conn_t *u_conn);
    void send_camera_data(camera_stream_t *cam);
    void try_send_camera_once(camera_stream_t *cam);

    static bool load_annexb_file(const std::string &path, uint16_t camera_id,
        XqcVideoCodec codec, std::vector<nal_unit_t> &out_nals, int64_t pts_step_us);
    static bool load_h264_file(const std::string &path, uint16_t camera_id,
                               std::vector<nal_unit_t> &out_nals, int64_t pts_step_us);
    static void reassign_pts(std::vector<nal_unit_t> &nals, int64_t pts_step_us, XqcVideoCodec codec);
    static int64_t infer_pace_us(const std::vector<nal_unit_t> &nals, int target_fps, XqcVideoCodec codec);
    static void free_nals(std::vector<nal_unit_t> &nals);

private:
    void schedule_pace_timer();

    xqc_engine_t       *engine_;
    event_base         *event_base_;
    event              *ev_engine_;
    event              *ev_pace_;

    std::string         server_ip_;
    int                 port_;
    std::string         device_id_;

    std::string         cam_files_[2];
    camera_stream_t     cameras_[2];
    int                 num_cameras_;

    user_conn_t        *u_conn_;

    bool                decode_preview_;
    bool                paced_send_;
    int                 target_fps_;
    int64_t             pace_us_;
    XqcVideoCodec       default_codec_;
};

#endif /* XQC_VIDEO_CLIENT_H */
