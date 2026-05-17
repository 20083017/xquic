#pragma once

#include "user_conn.h"
#include "xquic_seastar_integration.hh"

#include <seastar/core/distributed.hh>
#include <seastar/core/future.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/sharded.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/api.hh>
#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>
#include <xquic/xqc_video_frame.h>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

/**
 * Multi-core Seastar QUIC server using seastar::distributed<>.
 *
 * Architecture (per-shard reactor model):
 *   Every shard: own UDP channel (bound), own receive loop, own send path.
 *   POSIX mode:  shard 0 receives all traffic, routes via DCID to target shard.
 *                Each shard sends directly via its own unbound UDP channel.
 *   Native/DPDK: every shard gets its own bound channel; Seastar distributes
 *                incoming packets across shards automatically.
 *
 * CID routing: cid_generate_cb embeds shard_id in CID[0] for O(1) dispatch.
 * Initial packets (unknown CID / long header) are handled on receiving shard.
 */
class XquicSeastarServer {
public:
    XquicSeastarServer();
    ~XquicSeastarServer();

    /* Called by seastar::distributed<>::start() on each shard */
    seastar::future<> start_service(uint16_t port, const std::string& cert_path, const std::string& key_path,
                                    bool echo_mode, bool video_mode, const std::string& video_output_dir,
                                    bool video_decode_off_reactor);
    seastar::future<> stop();

    /* Set the distributed<> back-pointer (called once on each shard after start) */
    void set_distributed(seastar::distributed<XquicSeastarServer> *dist) { _distributed = dist; }

    /* Cross-shard packet delivery: invoked on target shard via submit_to */
    void deliver_packet(seastar::temporary_buffer<char> data,
                        struct sockaddr_storage peer_addr, socklen_t peer_len,
                        struct sockaddr_storage local_addr, socklen_t local_len);

private:
    std::optional<seastar::net::udp_channel> _udp_channel;       /* per-shard: bound (shard 0) or unbound (others, POSIX) */
    std::optional<seastar::net::udp_channel> _send_channel;      /* per-shard: dedicated send channel (POSIX non-shard-0) */
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
    bool _echo_mode;
    bool _video_mode;
    bool _video_decode_off_reactor;
    std::string _video_output_dir;
    bool _native_stack;   /* true when using Seastar native/DPDK net stack */
    seastar::distributed<XquicSeastarServer> *_distributed = nullptr;

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
        uint64_t packets_routed = 0;
    } _stats;
    seastar::timer<> _stats_timer;
    Stats _stats_prev;
    void print_stats();

    void init_xquic_engine();
    seastar::future<> run_receive_loop();
    void on_datagram(seastar::net::udp_datagram& datagram);
    void process_packet_local(const unsigned char *data, size_t len,
                              struct sockaddr_storage& peer_addr, socklen_t peer_len,
                              struct sockaddr_storage& local_addr, socklen_t local_len);
    unsigned route_packet_to_shard(const unsigned char *data, size_t len);
    void on_engine_timer_expire();
    seastar::net::udp_channel& get_send_channel();
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

    static ssize_t ss_cid_generate(const xqc_cid_t *ori_cid, uint8_t *cid_buf,
                                   size_t cid_buflen, void *engine_user_data);
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
