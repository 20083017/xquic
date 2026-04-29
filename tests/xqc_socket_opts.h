/*
 * xqc_socket_opts.h — shared UDP socket tuning helpers for tests/.
 *
 * Applies a conservative set of optimizations that are safe to combine
 * with xquic's existing recvfrom()/sendto() based I/O paths:
 *
 *   - SO_RCVBUF / SO_SNDBUF (large kernel buffers, with privileged FORCE fallback)
 *   - IP_MTU_DISCOVER = IP_PMTUDISC_DO  / IPV6 counterpart
 *       Required by RFC 9000: QUIC datagrams must NOT be IP-fragmented.
 *       Sets DF=1 on every packet; oversize sends fail with EMSGSIZE so
 *       xquic's PMTUD logic can react instead of silently fragmenting.
 *   - IP_RECVERR / IPV6_RECVERR
 *       Surfaces ICMP "Frag Needed" via the error queue so PMTU updates
 *       are observable; also lets us drain MSG_ERRQUEUE on EMSGSIZE.
 *   - IP_PKTINFO / IPV6_RECVPKTINFO
 *       When bound to 0.0.0.0/::, lets the application learn the actual
 *       local destination IP from cmsg, important for multi-IP hosts.
 *
 * Intentionally NOT enabled here:
 *   - UDP_GRO / UDP_SEGMENT — both require recvmsg()/sendmsg() with cmsg
 *     and a packet-slicing loop in the application; enabling without that
 *     would feed xquic a single oversized buffer and break parsing.
 *   - SO_REUSEPORT — only meaningful when multiple sockets share the port.
 *     Callers that need it set it themselves (see xquic_ebpf_reuseport.h).
 *
 * All helpers are defensive: failures of optional optimizations are logged
 * (when a logger is supplied) but never fatal. Only socket() / bind() level
 * errors propagate to the caller.
 */

#ifndef XQC_SOCKET_OPTS_H
#define XQC_SOCKET_OPTS_H

#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifndef UDP_GRO
#define UDP_GRO 104  /* Linux >= 5.0 */
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103  /* Linux >= 4.18 */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Default size: 4 MiB. Most systems cap at net.core.{r,w}mem_max — we try
 * SO_*BUFFORCE (root only) before settling for whatever the kernel allowed. */
#ifndef XQC_UDP_DEFAULT_BUF_BYTES
#define XQC_UDP_DEFAULT_BUF_BYTES (4 * 1024 * 1024)
#endif

static inline void
xqc_set_udp_buffers(int fd, int bufsize)
{
    /* Try the privileged "FORCE" variants first; fall back to the regular
     * setsockopt which is silently capped by the kernel sysctl ceiling. */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize)) < 0) {
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize)) < 0) {
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }
}

/* Enforce DF on outbound packets (required by QUIC) and let the kernel
 * surface ICMP PMTU updates via the error queue. Family is derived from
 * the bound socket family; pass AF_INET / AF_INET6 / AF_UNSPEC (auto). */
static inline void
xqc_set_udp_pmtud(int fd, int family)
{
    int on = 1;
    int v4_disc = IP_PMTUDISC_DO;
#ifdef IPV6_PMTUDISC_DO
    int v6_disc = IPV6_PMTUDISC_DO;
#endif

    if (family == AF_INET || family == AF_UNSPEC) {
        (void)setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &v4_disc, sizeof(v4_disc));
        (void)setsockopt(fd, IPPROTO_IP, IP_RECVERR,      &on,      sizeof(on));
    }
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_RECVERR)
    if (family == AF_INET6 || family == AF_UNSPEC) {
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &v6_disc, sizeof(v6_disc));
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR,      &on,      sizeof(on));
    }
#endif
}

/* Receive ancillary data with the actual local IP / ifindex. Only useful
 * when bound to wildcard addresses (INADDR_ANY / in6addr_any). Caller must
 * use recvmsg() and parse cmsg to take advantage of it. */
static inline void
xqc_set_udp_pktinfo(int fd, int family)
{
    int on = 1;
    if (family == AF_INET || family == AF_UNSPEC) {
        (void)setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    }
#ifdef IPV6_RECVPKTINFO
    if (family == AF_INET6 || family == AF_UNSPEC) {
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
    }
#endif
}

/* Convenience: apply the full safe-for-xquic set with default buffer size.
 *   server=1 → also enables IP_PKTINFO (likely bound to wildcard).
 *   server=0 → client; PKTINFO is not needed (connected sockets / explicit dst).
 */
static inline void
xqc_apply_udp_perf_opts(int fd, int family, int server)
{
    xqc_set_udp_buffers(fd, XQC_UDP_DEFAULT_BUF_BYTES);
    xqc_set_udp_pmtud(fd, family);
    if (server) {
        xqc_set_udp_pktinfo(fd, family);
    }

    /* UDP_GRO and UDP_SEGMENT are NOT toggled here: enabling either
     * requires a recvmsg()/sendmsg() data path that understands the
     * cmsg-driven segment slicing. Call xqc_enable_udp_gro() and use
     * the xqc_udp_writer / xqc_udp_recvmsg_gro helpers below from
     * call sites that have been migrated. */
}

/* ------------------------------------------------------------------ */
/* GRO / GSO data-path helpers (Linux only)                            */
/* ------------------------------------------------------------------ */

/* Enable UDP_GRO on the socket so the kernel coalesces consecutive
 * datagrams from the same flow into a single recvmsg() return. The
 * caller MUST use xqc_udp_recvmsg_gro() (or equivalent) and slice the
 * returned buffer by the per-message gso_size, otherwise xquic will
 * receive an oversized buffer and fail to parse. Returns 0 on success
 * (or if the option is unavailable but the socket is otherwise OK), -1
 * on hard failure. */
static inline int
xqc_enable_udp_gro(int fd)
{
    int on = 1;
    if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &on, sizeof(on)) < 0) {
        /* Old kernel (< 5.0) — not fatal, just no GRO. */
        return 0;
    }
    return 0;
}

/* Receive descriptor for a (possibly GRO-coalesced) datagram batch. */
typedef struct xqc_udp_recv_segments_s {
    unsigned char          *base;          /* points into caller buffer */
    size_t                  total_len;     /* bytes in base */
    size_t                  segment_size;  /* per-segment size; 0 = single dgram */
    struct sockaddr_storage peer;
    socklen_t               peer_len;
    struct sockaddr_storage local;         /* from IP_PKTINFO; zeroed if absent */
    socklen_t               local_len;
    int                     ifindex;       /* from IP_PKTINFO; 0 if absent */
} xqc_udp_recv_segments_t;

/* Iterate segments of a GRO batch. Usage:
 *   const unsigned char *seg; size_t seg_len;
 *   XQC_UDP_FOR_EACH_SEG(seg, seg_len, &segs) { ... }
 */
#define XQC_UDP_FOR_EACH_SEG(seg, seg_len, segs)                              \
    for (size_t _xqc_off = 0,                                                 \
                _xqc_step = ((segs)->segment_size                             \
                                ? (segs)->segment_size                        \
                                : (segs)->total_len);                         \
         _xqc_off < (segs)->total_len &&                                      \
         ((seg) = (segs)->base + _xqc_off,                                    \
          (seg_len) = (((segs)->total_len - _xqc_off) < _xqc_step             \
                          ? ((segs)->total_len - _xqc_off)                    \
                          : _xqc_step),                                       \
          1);                                                                 \
         _xqc_off += _xqc_step)

/* recvmsg() one datagram (possibly GRO-coalesced) into `buf`. Fills
 * `out` with peer/local/ifindex/segment_size. Returns the number of
 * bytes received, 0 if no data, -1 with errno on error. */
static inline ssize_t
xqc_udp_recvmsg_gro(int fd, unsigned char *buf, size_t cap,
                    xqc_udp_recv_segments_t *out)
{
    char           cbuf[CMSG_SPACE(sizeof(uint16_t))           /* UDP_GRO */
                       + CMSG_SPACE(sizeof(struct in_pktinfo))
                       + CMSG_SPACE(sizeof(struct in6_pktinfo))
                       + CMSG_SPACE(sizeof(int))];
    struct iovec   iov;
    struct msghdr  msg;

    iov.iov_base = buf;
    iov.iov_len  = cap;

    memset(out, 0, sizeof(*out));
    out->peer_len  = sizeof(out->peer);
    out->local_len = 0;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name       = &out->peer;
    msg.msg_namelen    = out->peer_len;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    ssize_t n = recvmsg(fd, &msg, 0);
    if (n <= 0) return n;

    out->base       = buf;
    out->total_len  = (size_t)n;
    out->peer_len   = msg.msg_namelen;
    out->segment_size = 0;

    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm != NULL;
         cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == IPPROTO_UDP && cm->cmsg_type == UDP_GRO) {
            uint16_t gso = 0;
            memcpy(&gso, CMSG_DATA(cm), sizeof(gso));
            out->segment_size = gso;
        } else if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(cm), sizeof(pi));
            struct sockaddr_in *la = (struct sockaddr_in *)&out->local;
            la->sin_family = AF_INET;
            la->sin_addr   = pi.ipi_addr;
            out->local_len = sizeof(*la);
            out->ifindex   = pi.ipi_ifindex;
#ifdef IPV6_PKTINFO
        } else if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo p6;
            memcpy(&p6, CMSG_DATA(cm), sizeof(p6));
            struct sockaddr_in6 *la = (struct sockaddr_in6 *)&out->local;
            la->sin6_family = AF_INET6;
            la->sin6_addr   = p6.ipi6_addr;
            out->local_len  = sizeof(*la);
            out->ifindex    = (int)p6.ipi6_ifindex;
#endif
        }
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Send-side coalescer using UDP_SEGMENT (GSO).                        */
/* Pending packets to a single peer with identical size are accumulated.*/
/* On peer/size mismatch, full buffer, or explicit flush, one          */
/* sendmsg() with a UDP_SEGMENT cmsg dispatches the whole batch.       */
/* Falls back to per-packet sendmsg() if UDP_SEGMENT is unsupported.   */
/* ------------------------------------------------------------------ */

#ifndef XQC_UDP_WRITER_CAP
/* 64 packets * 1500 bytes ≈ 96 KiB; fits comfortably under typical
 * GSO max segments (Linux: UDP_MAX_SEGMENTS = 64 historically). */
#define XQC_UDP_WRITER_CAP (64u * 1500u)
#endif

#ifndef XQC_UDP_WRITER_MAX_SEGMENTS
#define XQC_UDP_WRITER_MAX_SEGMENTS 64u
#endif

typedef struct xqc_udp_writer_s {
    int                     fd;
    int                     gso_enabled;     /* attempt UDP_SEGMENT */
    int                     gso_failed;      /* 1 → fallback per-packet forever */
    size_t                  total_len;
    size_t                  segment_size;    /* 0 → empty */
    unsigned                segment_count;
    struct sockaddr_storage peer;
    socklen_t               peer_len;
    unsigned char           buf[XQC_UDP_WRITER_CAP];
} xqc_udp_writer_t;

static inline void
xqc_udp_writer_init(xqc_udp_writer_t *w, int fd)
{
    memset(w, 0, sizeof(*w));
    w->fd = fd;
    w->gso_enabled = 1;
}

static inline void
xqc_udp_writer_set_gso(xqc_udp_writer_t *w, int enabled)
{
    w->gso_enabled = enabled ? 1 : 0;
}

/* Returns 0 on success or sendmsg's positive byte count for the batch
 * that was just flushed (treat both as "ok"); -1 on hard error.       */
static inline ssize_t
xqc_udp_writer_flush(xqc_udp_writer_t *w)
{
    if (w->total_len == 0) return 0;

    struct iovec iov;
    iov.iov_base = w->buf;
    iov.iov_len  = w->total_len;

    char cbuf[CMSG_SPACE(sizeof(uint16_t))];
    memset(cbuf, 0, sizeof(cbuf));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = &w->peer;
    msg.msg_namelen = w->peer_len;
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    int use_gso = (w->gso_enabled && !w->gso_failed && w->segment_count > 1);
    if (use_gso) {
        msg.msg_control    = cbuf;
        msg.msg_controllen = CMSG_SPACE(sizeof(uint16_t));
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = IPPROTO_UDP;
        cm->cmsg_type  = UDP_SEGMENT;
        cm->cmsg_len   = CMSG_LEN(sizeof(uint16_t));
        uint16_t gso   = (uint16_t)w->segment_size;
        memcpy(CMSG_DATA(cm), &gso, sizeof(gso));
    }

    ssize_t n = sendmsg(w->fd, &msg, 0);
    if (n < 0 && use_gso && (errno == EIO || errno == EINVAL || errno == ENOTSUP)) {
        /* Kernel/NIC doesn't accept UDP_SEGMENT — degrade to per-packet
         * sendmsg from now on. Replay this batch one segment at a time. */
        w->gso_failed = 1;
        size_t off = 0;
        while (off < w->total_len) {
            size_t seg = (w->total_len - off) < w->segment_size
                             ? (w->total_len - off)
                             : w->segment_size;
            struct iovec siov = { w->buf + off, seg };
            struct msghdr smsg;
            memset(&smsg, 0, sizeof(smsg));
            smsg.msg_name    = &w->peer;
            smsg.msg_namelen = w->peer_len;
            smsg.msg_iov     = &siov;
            smsg.msg_iovlen  = 1;
            ssize_t r = sendmsg(w->fd, &smsg, 0);
            if (r < 0) {
                w->total_len = w->segment_size = 0;
                w->segment_count = 0;
                return -1;
            }
            off += seg;
        }
        n = (ssize_t)w->total_len;
    }

    w->total_len = 0;
    w->segment_size = 0;
    w->segment_count = 0;
    w->peer_len = 0;
    return n;
}

/* Enqueue one packet to be sent to peer. Triggers a flush when the peer
 * changes, the per-packet size differs from the current batch, the
 * buffer is full, or the segment limit is hit. Returns the number of
 * bytes accepted (== size on success), -1 on hard error.              */
static inline ssize_t
xqc_udp_writer_enqueue(xqc_udp_writer_t *w,
                       const unsigned char *buf, size_t size,
                       const struct sockaddr *peer, socklen_t peer_len)
{
    if (size == 0 || size > XQC_UDP_WRITER_CAP) return -1;

    int peer_changed = (w->total_len > 0) &&
                       (w->peer_len != peer_len ||
                        memcmp(&w->peer, peer, peer_len) != 0);
    /* GSO requires uniform segment size for all but the last packet of
     * the batch — so any size change triggers a flush. */
    int size_changed = (w->total_len > 0) && (size != w->segment_size);
    int would_overflow = (w->total_len + size) > XQC_UDP_WRITER_CAP;
    int seg_limit = w->segment_count >= XQC_UDP_WRITER_MAX_SEGMENTS;

    if (peer_changed || size_changed || would_overflow || seg_limit) {
        if (xqc_udp_writer_flush(w) < 0) return -1;
    }

    if (w->total_len == 0) {
        memcpy(&w->peer, peer, peer_len);
        w->peer_len      = peer_len;
        w->segment_size  = size;
    }
    memcpy(w->buf + w->total_len, buf, size);
    w->total_len     += size;
    w->segment_count += 1;
    return (ssize_t)size;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* XQC_SOCKET_OPTS_H */
