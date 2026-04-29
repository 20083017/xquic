#pragma once

#include "user_conn.h"
#include "xquic_seastar_integration.hh"
#include "xquic_ebpf_reuseport.h"

#include <seastar/core/distributed.hh>
#include <seastar/core/future.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/internal/pollable_fd.hh>
#include <seastar/core/posix.hh>
#include <seastar/core/reactor.hh>
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
 * POSIX + eBPF Seastar QUIC server — Phase 4 evaluation variant.
 *
 * Architecture:
 *   Every shard: binds its own UDP socket to the same port via SO_REUSEPORT.
 *   A classic BPF program (SO_ATTACH_REUSEPORT_CBPF) is attached to steer
 *   incoming packets to the correct socket/shard based on QUIC DCID[0].
 *
 *   This is a POSIX-only approach that achieves per-shard receive without
 *   DPDK or cross-shard submit_to() overhead:
 *     - Kernel distributes packets to the correct shard at socket level.
 *     - Each shard has its own bound socket: both recv and send.
 *     - No shard-0 bottleneck, no unbound send channels.
 *     - CID generation embeds shard_id in CID[0] (same as DPDK variant).
 *
 *   Fallback: if SO_ATTACH_REUSEPORT_CBPF fails (old kernel, no CAP),
 *   degrades to the original shard-0-only POSIX mode.
 *
 * Comparison targets:
 *   - DPDK mode: zero-copy NIC → userspace, best for high-throughput.
 *   - eBPF mode: kernel-level steering, no NIC driver changes, easier to deploy.
 *   - Plain POSIX: shard-0 bottleneck, baseline for comparison.
 */
class XquicSeastarServerEbpf {
public:
    XquicSeastarServerEbpf();
    ~XquicSeastarServerEbpf();

    seastar::future<> start_service(uint16_t port, const std::string& cert_path, const std::string& key_path,
                                    bool echo_mode, bool video_mode, const std::string& video_output_dir);
    seastar::future<> stop();

    void set_distributed(seastar::distributed<XquicSeastarServerEbpf> *dist) { _distributed = dist; }

    /**
     * Set the pre-created reuseport file descriptors.
     * Called on shard 0 before start_service.  Shard 0 creates all sockets
     * from the main thread (before Seastar reactors start), then distributes
     * FDs to each shard via invoke_on().
     */
    void set_reuseport_fd(int fd) { _reuseport_fd = fd; }

    /* Cross-shard packet delivery fallback (only used in degraded POSIX mode) */
    void deliver_packet(seastar::temporary_buffer<char> data,
                        struct sockaddr_storage peer_addr, socklen_t peer_len,
                        struct sockaddr_storage local_addr, socklen_t local_len);

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
    bool _echo_mode;
    bool _video_mode;
    std::string _video_output_dir;
    bool _ebpf_mode;    /* true if eBPF reuseport is active */
    bool _fallback_posix;  /* true if degraded to shard-0-only POSIX */
    int _reuseport_fd;  /* pre-created reuseport socket fd, or -1 */
    /*
     * In eBPF mode, _reuseport_fd is wrapped into _ebpf_pfd and the FD
     * ownership is transferred (we set _reuseport_fd = -1 after wrap).
     * recvmsg/sendmsg go through this pollable_fd directly, bypassing
     * Seastar's udp_channel and giving us access to msg_control (cmsg).
     */
    std::optional<seastar::pollable_fd> _ebpf_pfd;
    struct sockaddr_storage _ebpf_local_addr {};
    socklen_t _ebpf_local_addrlen = 0;
    bool _gso_enabled = false;       /* set to true in init() after setsockopt success;
                                       cleared on first kernel/NIC unsupported error */
    seastar::distributed<XquicSeastarServerEbpf> *_distributed = nullptr;

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
    seastar::future<> run_ebpf_receive_loop();
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
    int on_h3_request_create_notify(xqc_h3_request_t *req, void *strm_user_data);
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
    static xqc_int_t ss_h3_request_create_notify(xqc_h3_request_t *req, void *strm_user_data);
    static xqc_int_t ss_h3_request_write_notify(xqc_h3_request_t *req, void *user_data);
    static xqc_int_t ss_h3_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data);
    static xqc_int_t ss_h3_request_close_notify(xqc_h3_request_t *req, void *user_data);
};
