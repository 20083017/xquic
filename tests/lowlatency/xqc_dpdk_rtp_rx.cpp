/**
 * @file xqc_dpdk_rtp_rx.cpp
 * @brief Roadmap P1: DPDK UDP/RTP receive smoke tool.
 *
 * This target is intentionally independent from xquic. It validates the Linux
 * dataplane prerequisites before wiring DPDK into the video pipeline:
 * hugepages, EAL init, port/queue setup, burst RX, packet dump, and timestamps.
 */

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <inttypes.h>
#include <netinet/in.h>
#include <string>
#include <sys/time.h>

namespace {

constexpr uint16_t kDefaultPortId = 0;
constexpr uint16_t kDefaultQueueId = 0;
constexpr uint16_t kDefaultUdpPort = 5004;
constexpr uint16_t kDefaultBurst = 64;
constexpr uint16_t kRxDesc = 1024;
constexpr uint16_t kTxDesc = 1024;
constexpr unsigned kMbufCount = 8192;
constexpr unsigned kMbufCache = 256;
constexpr uint16_t kDumpBytes = 64;

volatile sig_atomic_t g_stop = 0;

struct Options {
    uint16_t port_id = kDefaultPortId;
    uint16_t queue_id = kDefaultQueueId;
    uint16_t udp_port = kDefaultUdpPort;
    uint16_t burst = kDefaultBurst;
    uint64_t dump_limit = 8;
    uint32_t stats_interval_ms = 1000;
    bool promiscuous = true;
};

struct Stats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t rtp_packets = 0;
    uint64_t non_rtp_packets = 0;
    uint64_t dumped = 0;
    uint64_t rx_empty = 0;
    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
};

struct ParsedPacket {
    bool is_ipv4_udp = false;
    bool is_rtp = false;
    uint8_t vlan_depth = 0;
    uint8_t src_ip[4] = {};
    uint8_t dst_ip[4] = {};
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t seq = 0;
    uint32_t rtp_ts = 0;
    uint32_t ssrc = 0;
    uint32_t rtp_payload_len = 0;
    uint8_t payload_type = 0;
    uint8_t marker = 0;
};

void on_signal(int) {
    g_stop = 1;
}

void usage(const char* argv0) {
    std::printf(
        "Usage: %s [EAL args...] -- [options]\n"
        "\n"
        "Options:\n"
        "  --port-id N             DPDK port id (default: 0)\n"
        "  --queue-id N            RX queue id (default: 0)\n"
        "  --udp-port N            RTP UDP destination port filter (default: 5004)\n"
        "  --burst N               RX burst size, max 256 (default: 64)\n"
        "  --dump-limit N          Dump first N RTP packets (default: 8)\n"
        "  --stats-interval-ms N   Stats print interval (default: 1000)\n"
        "  --no-promisc            Do not enable promiscuous mode\n"
        "  -h, --help              Show this help\n"
        "\n"
        "Example:\n"
        "  sudo %s -l 0-1 -n 4 -- --port-id 0 --queue-id 0 --udp-port 5004\n",
        argv0, argv0);
}

bool parse_u16(const char* s, uint16_t& out) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (!s || !s[0] || (end && *end) || v < 0 || v > 65535) {
        return false;
    }
    out = static_cast<uint16_t>(v);
    return true;
}

bool parse_u32(const char* s, uint32_t& out) {
    char* end = nullptr;
    const unsigned long v = std::strtoul(s, &end, 10);
    if (!s || !s[0] || (end && *end) || v > UINT32_MAX) {
        return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
}

bool parse_u64(const char* s, uint64_t& out) {
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s, &end, 10);
    if (!s || !s[0] || (end && *end)) {
        return false;
    }
    out = static_cast<uint64_t>(v);
    return true;
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--port-id") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], opt.port_id)) {
                return false;
            }
        } else if (std::strcmp(a, "--queue-id") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], opt.queue_id)) {
                return false;
            }
        } else if (std::strcmp(a, "--udp-port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], opt.udp_port) || opt.udp_port == 0) {
                return false;
            }
        } else if (std::strcmp(a, "--burst") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], opt.burst) || opt.burst == 0 || opt.burst > 256) {
                return false;
            }
        } else if (std::strcmp(a, "--dump-limit") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], opt.dump_limit)) {
                return false;
            }
        } else if (std::strcmp(a, "--stats-interval-ms") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], opt.stats_interval_ms) || opt.stats_interval_ms == 0) {
                return false;
            }
        } else if (std::strcmp(a, "--no-promisc") == 0) {
            opt.promiscuous = false;
        } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
            usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return true;
}

uint64_t now_us() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24)
        | (static_cast<uint32_t>(p[1]) << 16)
        | (static_cast<uint32_t>(p[2]) << 8)
        | static_cast<uint32_t>(p[3]);
}

bool is_vlan_ether_type(uint16_t ether_type) {
    return ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100;
}

bool parse_packet(struct rte_mbuf* mbuf, uint16_t udp_port, ParsedPacket& out) {
    const uint8_t* data = rte_pktmbuf_mtod(mbuf, const uint8_t*);
    const uint32_t len = rte_pktmbuf_pkt_len(mbuf);
    if (len < sizeof(rte_ether_hdr)) {
        return false;
    }

    const auto* eth = reinterpret_cast<const rte_ether_hdr*>(data);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    size_t off = sizeof(rte_ether_hdr);
    while (is_vlan_ether_type(ether_type)) {
        if (len < off + 4) {
            return false;
        }
        ether_type = read_be16(data + off + 2);
        off += 4;
        ++out.vlan_depth;
    }
    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return false;
    }

    if (len < off + sizeof(rte_ipv4_hdr)) {
        return false;
    }
    const auto* ip = reinterpret_cast<const rte_ipv4_hdr*>(data + off);
    const uint8_t ihl = static_cast<uint8_t>((ip->version_ihl & 0x0f) * 4);
    if (ihl < sizeof(rte_ipv4_hdr) || len < off + ihl + sizeof(rte_udp_hdr)) {
        return false;
    }
    if (ip->next_proto_id != IPPROTO_UDP) {
        return false;
    }
    std::memcpy(out.src_ip, &ip->src_addr, sizeof(out.src_ip));
    std::memcpy(out.dst_ip, &ip->dst_addr, sizeof(out.dst_ip));

    off += ihl;
    const auto* udp = reinterpret_cast<const rte_udp_hdr*>(data + off);
    out.is_ipv4_udp = true;
    out.src_port = rte_be_to_cpu_16(udp->src_port);
    out.dst_port = rte_be_to_cpu_16(udp->dst_port);
    if (out.dst_port != udp_port) {
        return true;
    }

    off += sizeof(rte_udp_hdr);
    if (len < off + 12) {
        return true;
    }
    const uint8_t* rtp = data + off;
    if ((rtp[0] >> 6) != 2) {
        return true;
    }
    const bool has_extension = (rtp[0] & 0x10) != 0;
    const uint8_t csrc_count = rtp[0] & 0x0f;
    size_t rtp_header_len = 12 + static_cast<size_t>(csrc_count) * 4;
    if (len < off + rtp_header_len) {
        return true;
    }
    if (has_extension) {
        if (len < off + rtp_header_len + 4) {
            return true;
        }
        const uint16_t ext_words = read_be16(rtp + rtp_header_len + 2);
        rtp_header_len += 4 + static_cast<size_t>(ext_words) * 4;
        if (len < off + rtp_header_len) {
            return true;
        }
    }

    out.is_rtp = true;
    out.marker = static_cast<uint8_t>((rtp[1] & 0x80) != 0);
    out.payload_type = static_cast<uint8_t>(rtp[1] & 0x7f);
    out.seq = read_be16(rtp + 2);
    out.rtp_ts = read_be32(rtp + 4);
    out.ssrc = read_be32(rtp + 8);
    out.rtp_payload_len = static_cast<uint32_t>(len - off - rtp_header_len);
    return true;
}

void print_ipv4(const uint8_t ip[4]) {
    std::printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void dump_packet(struct rte_mbuf* mbuf, const ParsedPacket& parsed, uint64_t wall_us, uint64_t tsc) {
    const uint8_t* data = rte_pktmbuf_mtod(mbuf, const uint8_t*);
    const uint32_t len = rte_pktmbuf_pkt_len(mbuf);
    const uint16_t n = len < kDumpBytes ? static_cast<uint16_t>(len) : kDumpBytes;

    std::printf("[dpdk-rx] dump wall_us=%" PRIu64 " tsc=%" PRIu64
                " len=%u vlan=%u ",
        wall_us, tsc, len, parsed.vlan_depth);
    print_ipv4(parsed.src_ip);
    std::printf(":%u -> ", parsed.src_port);
    print_ipv4(parsed.dst_ip);
    std::printf(":%u rtp=%u pt=%u marker=%u seq=%u rtp_ts=%" PRIu32
                " ssrc=0x%08" PRIx32 " payload=%" PRIu32 " bytes=",
        parsed.dst_port, parsed.is_rtp ? 1 : 0,
        parsed.payload_type, parsed.marker, parsed.seq, parsed.rtp_ts,
        parsed.ssrc, parsed.rtp_payload_len);
    for (uint16_t i = 0; i < n; ++i) {
        std::printf("%02x", data[i]);
        if (i + 1 < n) {
            std::printf(" ");
        }
    }
    std::printf("\n");
}

void print_stats(const Stats& stats, uint64_t elapsed_us, uint64_t interval_us,
    uint64_t interval_packets, uint64_t interval_bytes)
{
    const double pps = interval_us > 0
        ? static_cast<double>(interval_packets) * 1000000.0 / static_cast<double>(interval_us)
        : 0.0;
    const double gbps = interval_us > 0
        ? static_cast<double>(interval_bytes) * 8.0 * 1000000.0
            / static_cast<double>(interval_us) / 1000000000.0
        : 0.0;
    std::printf("[dpdk-rx] elapsed=%.3fs packets=%" PRIu64 " rtp=%" PRIu64
                " non_rtp=%" PRIu64 " bytes=%" PRIu64 " pps=%.0f gbps=%.3f empty=%" PRIu64 "\n",
        static_cast<double>(elapsed_us) / 1000000.0,
        stats.packets, stats.rtp_packets, stats.non_rtp_packets, stats.bytes,
        pps, gbps, stats.rx_empty);
}

int init_port(uint16_t port_id, uint16_t queue_id, rte_mempool* mbuf_pool, bool promiscuous) {
    if (!rte_eth_dev_is_valid_port(port_id)) {
        std::fprintf(stderr, "[dpdk-rx] invalid port id %u\n", port_id);
        return -1;
    }

    rte_eth_conf port_conf{};
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    int rc = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
    if (rc < 0) {
        std::fprintf(stderr, "[dpdk-rx] rte_eth_dev_configure failed: %d\n", rc);
        return rc;
    }

    rte_eth_dev_info dev_info{};
    rc = rte_eth_dev_info_get(port_id, &dev_info);
    if (rc != 0) {
        std::fprintf(stderr, "[dpdk-rx] rte_eth_dev_info_get failed: %d\n", rc);
        return rc;
    }

    rte_eth_rxconf rx_conf = dev_info.default_rxconf;
    rc = rte_eth_rx_queue_setup(port_id, queue_id, kRxDesc,
        rte_eth_dev_socket_id(port_id), &rx_conf, mbuf_pool);
    if (rc < 0) {
        std::fprintf(stderr, "[dpdk-rx] rte_eth_rx_queue_setup failed: %d\n", rc);
        return rc;
    }

    rc = rte_eth_dev_start(port_id);
    if (rc < 0) {
        std::fprintf(stderr, "[dpdk-rx] rte_eth_dev_start failed: %d\n", rc);
        return rc;
    }

    if (promiscuous) {
        rc = rte_eth_promiscuous_enable(port_id);
        if (rc != 0) {
            std::fprintf(stderr, "[dpdk-rx] promiscuous enable failed: %d\n", rc);
            return rc;
        }
    }

    rte_ether_addr mac{};
    rc = rte_eth_macaddr_get(port_id, &mac);
    if (rc == 0) {
        std::printf("[dpdk-rx] port=%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
            port_id,
            mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
            mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
    }

    (void)kTxDesc;
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    const int eal_argc = rte_eal_init(argc, argv);
    if (eal_argc < 0) {
        rte_exit(EXIT_FAILURE, "EAL init failed\n");
    }
    argc -= eal_argc;
    argv += eal_argc;

    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        rte_eal_cleanup();
        return 2;
    }

    std::printf("[dpdk-rx] port=%u queue=%u udp_port=%u burst=%u dump_limit=%" PRIu64 "\n",
        opt.port_id, opt.queue_id, opt.udp_port, opt.burst, opt.dump_limit);

    rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("xqc_dpdk_rtp_rx_mbufs",
        kMbufCount, kMbufCache, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "cannot create mbuf pool\n");
    }

    if (init_port(opt.port_id, opt.queue_id, mbuf_pool, opt.promiscuous) != 0) {
        rte_eal_cleanup();
        return 1;
    }

    rte_mbuf* bufs[256];
    Stats stats{};
    const uint64_t start_us = now_us();
    uint64_t last_us = start_us;

    while (!g_stop) {
        const uint16_t nb_rx = rte_eth_rx_burst(opt.port_id, opt.queue_id, bufs, opt.burst);
        if (nb_rx == 0) {
            ++stats.rx_empty;
            if ((stats.rx_empty & 0xfffff) == 0) {
                const uint64_t idle_us = now_us();
                if (idle_us - last_us >= static_cast<uint64_t>(opt.stats_interval_ms) * 1000ULL) {
                    print_stats(stats, idle_us - start_us, idle_us - last_us,
                        stats.packets - stats.last_packets, stats.bytes - stats.last_bytes);
                    stats.last_packets = stats.packets;
                    stats.last_bytes = stats.bytes;
                    last_us = idle_us;
                }
            }
            continue;
        }

        const uint64_t wall_us = now_us();
        const uint64_t tsc = rte_get_tsc_cycles();
        for (uint16_t i = 0; i < nb_rx; ++i) {
            rte_mbuf* mbuf = bufs[i];
            ParsedPacket parsed{};
            const uint32_t len = rte_pktmbuf_pkt_len(mbuf);
            ++stats.packets;
            stats.bytes += len;

            if (parse_packet(mbuf, opt.udp_port, parsed) && parsed.is_rtp) {
                ++stats.rtp_packets;
                if (stats.dumped < opt.dump_limit) {
                    dump_packet(mbuf, parsed, wall_us, tsc);
                    ++stats.dumped;
                }
            } else {
                ++stats.non_rtp_packets;
            }

            rte_pktmbuf_free(mbuf);
        }

        if (wall_us - last_us >= static_cast<uint64_t>(opt.stats_interval_ms) * 1000ULL) {
            const uint64_t interval_packets = stats.packets - stats.last_packets;
            const uint64_t interval_bytes = stats.bytes - stats.last_bytes;
            print_stats(stats, wall_us - start_us, wall_us - last_us, interval_packets, interval_bytes);
            stats.last_packets = stats.packets;
            stats.last_bytes = stats.bytes;
            last_us = wall_us;
        }
    }

    const uint64_t end_us = now_us();
    print_stats(stats, end_us - start_us, end_us - last_us,
        stats.packets - stats.last_packets, stats.bytes - stats.last_bytes);

    rte_eth_dev_stop(opt.port_id);
    rte_eth_dev_close(opt.port_id);
    rte_eal_cleanup();
    return 0;
}
