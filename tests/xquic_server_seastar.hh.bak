#pragma once

#include "user_conn.h"
#include "xquic_seastar_integration.hh"

#include <seastar/core/future.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/api.hh>
#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>
#include <xquic/xqc_video_frame.h>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

class XquicSeastarServer {
public:
    XquicSeastarServer();
    ~XquicSeastarServer();

    seastar::future<> start(uint16_t port, const std::string& cert_path, const std::string& key_path,
                            bool echo_mode = false, bool video_mode = false,
                            const std::string& video_output_dir = "./video_out");
    seastar::future<> stop();

private:
    std::optional<seastar::net::udp_channel> _udp_channel;
    std::optional<seastar::future<>> _receive_loop;
    seastar::gate _background_ops;
    seastar::timer<> _engine_timer;
    xqc_engine_t* _engine;
    XquicSeastarSendIntegration _send_integration;
    user_conn_t _packet_user_conn;
    std::string _cert_path;
    std::string _key_path;
    uint16_t _port;
    bool _stopping;
    bool _send_flush_in_progress;
    bool _echo_mode;  // true: streaming echo, false: framed protocol
    bool _video_mode; // true: video stream receiver (write .h264 files)
    std::string _video_output_dir; // directory for saved .h264 files

    // Statistics for benchmarking
    struct Stats {
        uint64_t conns_accepted = 0;
        uint64_t conns_closed = 0;
        uint64_t streams_created = 0;
        uint64_t streams_closed = 0;
        uint64_t h3_requests = 0;
        uint64_t h3_responses = 0;
        uint64_t packets_recv = 0;
        uint64_t packets_sent = 0;
        uint64_t bytes_recv = 0;
        uint64_t bytes_sent = 0;
        uint64_t video_bytes_recvd = 0;
        uint64_t video_streams_finished = 0;
    } _stats;
    seastar::timer<> _stats_timer;
    Stats _stats_prev;
    void print_stats();

    void init_xquic_engine();
    seastar::future<> run_receive_loop();
    void on_datagram(seastar::net::udp_datagram& datagram);
    void on_engine_timer_expire();
    ssize_t enqueue_send(const unsigned char *buf, size_t size,
                         const struct sockaddr *peer_addr, socklen_t peer_addrlen);
    void schedule_send_flush();
    seastar::future<> flush_send_queue();
    void send_h3_response(user_stream_t *user_stream);
    int on_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data);
    void on_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                   const xqc_cid_t *new_cid, void *user_data);
    int on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                              void *user_data, void *conn_proto_data);
    int on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                             void *user_data, void *conn_proto_data);
    xqc_int_t on_stream_create_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_write_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_read_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_close_notify(xqc_stream_t *stream, void *user_data);

    int on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    int on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    xqc_int_t on_h3_request_write_notify(xqc_h3_request_t *req, void *user_data);
    xqc_int_t on_h3_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data);
    xqc_int_t on_h3_request_close_notify(xqc_h3_request_t *req, void *user_data);

    static void ss_set_event_timer(xqc_msec_t wake_after, void *user_data);
    static ssize_t ss_write_socket(const unsigned char *buf, size_t size,
                                   const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                                   void *user_conn);
    static int ss_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data);
    static void ss_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                          const xqc_cid_t *new_cid, void *user_data);
    static int ss_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                     void *user_data, void *conn_proto_data);
    static int ss_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                    void *user_data, void *conn_proto_data);
    static xqc_int_t ss_stream_create_notify(xqc_stream_t *stream, void *user_data);
    static xqc_int_t ss_stream_write_notify(xqc_stream_t *stream, void *user_data);
    static xqc_int_t ss_stream_read_notify(xqc_stream_t *stream, void *user_data);
    static xqc_int_t ss_stream_close_notify(xqc_stream_t *stream, void *user_data);
    static int ss_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    static int ss_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    static xqc_int_t ss_h3_request_write_notify(xqc_h3_request_t *req, void *user_data);
    static xqc_int_t ss_h3_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data);
    static xqc_int_t ss_h3_request_close_notify(xqc_h3_request_t *req, void *user_data);
};
