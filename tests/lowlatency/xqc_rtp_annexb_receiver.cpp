/**
 * @file xqc_rtp_annexb_receiver.cpp
 * @brief macOS/Linux Phase 1/2 fallback: UDP RTP(H.264) receive -> Annex-B file.
 *
 * This is intentionally a POSIX-socket receiver. The roadmap's DPDK/NVDEC path is
 * Linux/NVIDIA specific; this target keeps RTP ingest and H.264 depacketization
 * buildable on macOS so the protocol path can be exercised locally.
 */

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr size_t kMaxRtpPacket = 2048;
constexpr uint16_t kDefaultPort = 5004;
constexpr uint16_t kMaxReorderDepth = 128;
constexpr uint8_t kNalStapA = 24;
constexpr uint8_t kNalFuA = 28;
constexpr uint8_t kNalMask = 0x1f;
constexpr uint8_t kFuStart = 0x80;
constexpr uint8_t kFuEnd = 0x40;

volatile sig_atomic_t g_stop = 0;

struct Options {
    uint16_t port = kDefaultPort;
    std::string output = "rtp_capture.h264";
    uint16_t camera_id = 0;
    bool verbose = false;
};

struct RtpPacket {
    uint16_t seq = 0;
    uint32_t timestamp = 0;
    bool marker = false;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

struct Stats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t nals = 0;
    uint64_t lost = 0;
    uint64_t out_of_order = 0;
    uint64_t bad = 0;
};

void on_signal(int) {
    g_stop = 1;
}

uint64_t now_us() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000ULL + static_cast<uint64_t>(tv.tv_usec);
}

void usage(const char* argv0) {
    std::fprintf(stderr,
        "Usage: %s [--port N] [--output file.h264] [--camera-id N] [--verbose]\n"
        "\n"
        "Receives RTP/H.264 over UDP and writes Annex-B H.264.\n"
        "Supported payloads: single NAL, STAP-A, FU-A.\n",
        argv0);
}

bool parse_u16(const char* s, uint16_t& out) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (!s[0] || (end && *end) || v < 0 || v > 65535) {
        return false;
    }
    out = static_cast<uint16_t>(v);
    return true;
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], opt.port) || opt.port == 0) {
                return false;
            }
        } else if (std::strcmp(a, "--output") == 0 && i + 1 < argc) {
            opt.output = argv[++i];
        } else if (std::strcmp(a, "--camera-id") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], opt.camera_id)) {
                return false;
            }
        } else if (std::strcmp(a, "--verbose") == 0) {
            opt.verbose = true;
        } else if (std::strcmp(a, "-h") == 0 || std::strcmp(a, "--help") == 0) {
            usage(argv[0]);
            std::exit(0);
        } else {
            return false;
        }
    }
    return !opt.output.empty();
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

uint16_t seq_distance(uint16_t from, uint16_t to) {
    return static_cast<uint16_t>(to - from);
}

bool parse_rtp(const uint8_t* data, size_t len, RtpPacket& out) {
    if (len < 12) {
        return false;
    }
    const uint8_t version = data[0] >> 6;
    if (version != 2) {
        return false;
    }
    const bool has_padding = (data[0] & 0x20) != 0;
    const bool has_extension = (data[0] & 0x10) != 0;
    const uint8_t csrc_count = data[0] & 0x0f;
    size_t off = 12 + static_cast<size_t>(csrc_count) * 4;
    if (off > len) {
        return false;
    }
    if (has_extension) {
        if (off + 4 > len) {
            return false;
        }
        const uint16_t ext_words = read_be16(data + off + 2);
        off += 4 + static_cast<size_t>(ext_words) * 4;
        if (off > len) {
            return false;
        }
    }
    size_t payload_end = len;
    if (has_padding) {
        const uint8_t pad = data[len - 1];
        if (pad == 0 || pad > len - off) {
            return false;
        }
        payload_end -= pad;
    }
    if (off >= payload_end) {
        return false;
    }

    out.seq = read_be16(data + 2);
    out.timestamp = read_be32(data + 4);
    out.marker = (data[1] & 0x80) != 0;
    out.payload = data + off;
    out.payload_len = payload_end - off;
    return true;
}

bool write_annexb(FILE* fp, const uint8_t* nal, size_t len) {
    static const uint8_t kStartCode[] = {0x00, 0x00, 0x00, 0x01};
    return std::fwrite(kStartCode, 1, sizeof(kStartCode), fp) == sizeof(kStartCode)
        && std::fwrite(nal, 1, len, fp) == len;
}

class H264Depacketizer {
public:
    explicit H264Depacketizer(FILE* fp, bool verbose) : fp_(fp), verbose_(verbose) {}

    bool push(const RtpPacket& pkt, Stats& stats) {
        if (!pkt.payload || pkt.payload_len == 0) {
            ++stats.bad;
            return false;
        }
        const uint8_t nal_header = pkt.payload[0];
        const uint8_t nal_type = nal_header & kNalMask;
        if (nal_type >= 1 && nal_type <= 23) {
            return emit(pkt.payload, pkt.payload_len, stats);
        }
        if (nal_type == kNalStapA) {
            return handle_stap_a(pkt.payload, pkt.payload_len, stats);
        }
        if (nal_type == kNalFuA) {
            return handle_fu_a(pkt.payload, pkt.payload_len, stats);
        }
        if (verbose_) {
            std::fprintf(stderr, "[rtp] skip unsupported H.264 packetization type=%u\n", nal_type);
        }
        ++stats.bad;
        return false;
    }

private:
    bool emit(const uint8_t* nal, size_t len, Stats& stats) {
        if (!write_annexb(fp_, nal, len)) {
            std::perror("write");
            return false;
        }
        ++stats.nals;
        return true;
    }

    bool handle_stap_a(const uint8_t* payload, size_t len, Stats& stats) {
        size_t off = 1;
        bool ok = true;
        while (off + 2 <= len) {
            const uint16_t nal_len = read_be16(payload + off);
            off += 2;
            if (nal_len == 0 || off + nal_len > len) {
                ++stats.bad;
                return false;
            }
            ok = emit(payload + off, nal_len, stats) && ok;
            off += nal_len;
        }
        if (off != len) {
            ++stats.bad;
            return false;
        }
        return ok;
    }

    bool handle_fu_a(const uint8_t* payload, size_t len, Stats& stats) {
        if (len < 2) {
            ++stats.bad;
            return false;
        }
        const uint8_t fu_indicator = payload[0];
        const uint8_t fu_header = payload[1];
        const bool start = (fu_header & kFuStart) != 0;
        const bool end = (fu_header & kFuEnd) != 0;
        const uint8_t reconstructed = static_cast<uint8_t>((fu_indicator & 0xe0) | (fu_header & kNalMask));

        if (start) {
            fu_buffer_.clear();
            fu_buffer_.push_back(reconstructed);
        } else if (fu_buffer_.empty()) {
            ++stats.lost;
            ++stats.bad;
            return false;
        }
        fu_buffer_.insert(fu_buffer_.end(), payload + 2, payload + len);
        if (end) {
            const bool ok = emit(fu_buffer_.data(), fu_buffer_.size(), stats);
            fu_buffer_.clear();
            return ok;
        }
        return true;
    }

    FILE* fp_ = nullptr;
    bool verbose_ = false;
    std::vector<uint8_t> fu_buffer_;
};

class RtpReorder {
public:
    bool push(const uint8_t* data, size_t len, H264Depacketizer& depay, Stats& stats) {
        RtpPacket pkt{};
        if (!parse_rtp(data, len, pkt)) {
            ++stats.bad;
            return true;
        }
        ++stats.packets;
        stats.bytes += len;

        if (!started_) {
            started_ = true;
            expected_ = pkt.seq;
        }
        const uint16_t dist = seq_distance(expected_, pkt.seq);
        if (dist == 0) {
            if (!consume(pkt, depay, stats)) {
                return false;
            }
            ++expected_;
            return drain_ready(depay, stats);
        }
        if (dist < 0x8000) {
            pending_[pkt.seq] = std::vector<uint8_t>(data, data + len);
            if (pending_.size() > kMaxReorderDepth) {
                ++stats.lost;
                ++expected_;
                return drain_ready(depay, stats);
            }
            return true;
        }

        ++stats.out_of_order;
        return true;
    }

private:
    bool drain_ready(H264Depacketizer& depay, Stats& stats) {
        while (true) {
            const auto it = pending_.find(expected_);
            if (it == pending_.end()) {
                return true;
            }
            RtpPacket pkt{};
            if (parse_rtp(it->second.data(), it->second.size(), pkt)) {
                if (!consume(pkt, depay, stats)) {
                    return false;
                }
            } else {
                ++stats.bad;
            }
            pending_.erase(it);
            ++expected_;
        }
    }

    bool consume(const RtpPacket& pkt, H264Depacketizer& depay, Stats& stats) {
        (void)pkt;
        return depay.push(pkt, stats);
    }

    bool started_ = false;
    uint16_t expected_ = 0;
    std::map<uint16_t, std::vector<uint8_t>> pending_;
};

int make_udp_socket(uint16_t port) {
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    FILE* fp = std::fopen(opt.output.c_str(), "wb");
    if (!fp) {
        std::perror(opt.output.c_str());
        return 1;
    }

    const int fd = make_udp_socket(opt.port);
    if (fd < 0) {
        std::perror("bind");
        std::fclose(fp);
        return 1;
    }

    std::fprintf(stderr, "[rtp] listening UDP :%u camera=%u -> %s\n",
        opt.port, opt.camera_id, opt.output.c_str());

    Stats stats{};
    RtpReorder reorder;
    H264Depacketizer depay(fp, opt.verbose);
    uint64_t last_report = now_us();
    std::vector<uint8_t> buf(kMaxRtpPacket);

    while (!g_stop) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{};
        tv.tv_sec = 1;
        const int rc = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::perror("select");
            break;
        }
        if (rc > 0 && FD_ISSET(fd, &rfds)) {
            sockaddr_storage peer{};
            socklen_t peer_len = sizeof(peer);
            const ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                reinterpret_cast<sockaddr*>(&peer), &peer_len);
            if (n > 0 && !reorder.push(buf.data(), static_cast<size_t>(n), depay, stats)) {
                break;
            }
        }
        const uint64_t t = now_us();
        if (t - last_report >= 2000000ULL) {
            std::fprintf(stderr,
                "[rtp] packets=%llu nals=%llu bytes=%llu lost=%llu bad=%llu ooo=%llu\n",
                static_cast<unsigned long long>(stats.packets),
                static_cast<unsigned long long>(stats.nals),
                static_cast<unsigned long long>(stats.bytes),
                static_cast<unsigned long long>(stats.lost),
                static_cast<unsigned long long>(stats.bad),
                static_cast<unsigned long long>(stats.out_of_order));
            last_report = t;
        }
    }

    std::fprintf(stderr,
        "[rtp] done packets=%llu nals=%llu bytes=%llu lost=%llu bad=%llu ooo=%llu\n",
        static_cast<unsigned long long>(stats.packets),
        static_cast<unsigned long long>(stats.nals),
        static_cast<unsigned long long>(stats.bytes),
        static_cast<unsigned long long>(stats.lost),
        static_cast<unsigned long long>(stats.bad),
        static_cast<unsigned long long>(stats.out_of_order));
    close(fd);
    std::fclose(fp);
    return 0;
}
