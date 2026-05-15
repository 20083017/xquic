# Socket Options Notes for xquic Test Servers/Clients

> Companion notes to [tests/xqc_socket_opts.h](../tests/xqc_socket_opts.h).
> Decisions about which socket options are enabled by default and why.

## 1. Default-on options (POSIX / eBPF stack only)

| Option | Why |
|---|---|
| `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` 4 MiB (fallback `SO_*BUF`) | Absorb bursts; FORCE bypasses `net.core.{r,w}mem_max` when run as root |
| `IP_MTU_DISCOVER = IP_PMTUDISC_DO` (+ IPv6 counterpart) | RFC 9000 forbids IP fragmentation; sets DF=1 so PMTUD works |
| `IP_RECVERR` (+ IPv6 counterpart) | Surfaces ICMP "Frag Needed" via the error queue |
| `IP_PKTINFO` / `IPV6_RECVPKTINFO` (server only) | Recover real local dst IP for wildcard binds |

## 2. `IP_TOS` / `IPV6_TCLASS` — explicitly NOT enabled

### Background
`IP_TOS` writes the 8-bit TOS field of the IPv4 header (IPv6: `IPV6_TCLASS`):

```
 0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
|     DSCP (6 bits)     | ECN(2)|
+---+---+---+---+---+---+---+---+
```

- DSCP: QoS class (EF/AF/CSx/BE)
- ECN: Explicit Congestion Notification (Not-ECT / ECT(0) / ECT(1) / CE)

### Why we do NOT default-set it

1. **DSCP is policy, not performance.** Public Internet backbones overwhelmingly bleach (zero) DSCP at AS boundaries. It only matters inside controlled fabrics (DC, SD-WAN, enterprise WAN with QoS). Tagging EF/CS6 without coordination provides zero benefit and may be dropped by middleboxes.
2. **ECN must be per-packet, not socket-default.** QUIC ECN (RFC 9002 §B / draft-ietf-quic-transport ECN section) requires:
   - sender tags individual packets ECT(0)/ECT(1) via `sendmsg` cmsg `IP_TOS`
   - receiver reads received TOS via `IP_RECVTOS` cmsg
   - receiver feeds counts back into ACK frames (ECN counts)
   `setsockopt(IP_TOS, ...)` sets a *socket-wide default* and cannot drive the protocol logic correctly.
3. **xquic does not currently implement ECN.** A search of `src/` shows no `IP_TOS` / `ECN` / `ect` handling. Setting the option would have no protocol effect.
4. **Wrong layer for prioritization.** Per-stream priority within QUIC is already handled by H3/QPACK priorities and by congestion control; DSCP would only matter outside the host.

### When it WOULD make sense (not now)

- Self-managed DC fabric / SD-WAN with real DSCP-aware queues
- Distinguishing signaling vs media at the network egress
- xquic gains real ECN support (then ECN bits are managed via cmsg per packet, not via this socket option)

### How to add it later (do not do this now)

Add an opt-in helper in `tests/xqc_socket_opts.h` and expose via CLI (e.g. `--dscp 46`):

```c
static inline void
xqc_set_udp_dscp(int fd, int family, uint8_t dscp /* 0..63 */)
{
    int tos = (int)(dscp << 2);  /* low 2 bits reserved for ECN */
    if (family == AF_INET || family == AF_UNSPEC) {
        (void)setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    }
#ifdef IPV6_TCLASS
    if (family == AF_INET6 || family == AF_UNSPEC) {
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
    }
#endif
}
```

ECN handling stays the responsibility of the QUIC engine — do not bake it
into this helper.

## 3. `UDP_GRO` / `UDP_SEGMENT` — enabled when path uses `recvmsg`/`sendmsg`

See [tests/xqc_socket_opts.h](../tests/xqc_socket_opts.h) helpers
`xqc_enable_udp_gro` / `xqc_udp_recv_gro` / `xqc_udp_send_gso`. They are
*only* enabled on call-sites that have been migrated to `recvmsg`/`sendmsg`
with the segment-slicing loop, otherwise xquic would receive a coalesced
buffer and fail to parse.

DPDK + Seastar (native stack) does NOT use any of these — use Seastar /
DPDK device offload knobs there.
