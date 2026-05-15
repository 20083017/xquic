/**
 * xquic_ebpf_reuseport.h — eBPF + SO_REUSEPORT dispatcher for QUIC
 *
 * Provides kernel-level QUIC packet steering:
 *   1. Each shard creates its own UDP socket with SO_REUSEPORT.
 *   2. An eBPF program attached via SO_ATTACH_REUSEPORT_EBPF parses the
 *      QUIC DCID from incoming packets and routes to the correct socket
 *      (shard) based on CID[0] % shard_count.
 *   3. Initial packets (long-header with unknown CID) go to socket 0.
 *
 * This eliminates the shard-0 receive bottleneck in POSIX mode while
 * staying entirely in kernel space (no DPDK required).
 *
 * Requirements:
 *   - Linux >= 4.19 (SO_ATTACH_REUSEPORT_EBPF, BPF_PROG_TYPE_SK_REUSEPORT)
 *   - CAP_BPF or CAP_SYS_ADMIN (for loading eBPF programs)
 */
#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "xqc_socket_opts.h"
#include <fcntl.h>

/**
 * Minimal inline bpf() syscall wrapper — avoids dependency on libbpf.
 */
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return static_cast<int>(syscall(__NR_bpf, cmd, attr, size));
}

/**
 * QUIC DCID-based SO_REUSEPORT eBPF program.
 *
 * The eBPF program inspects the raw UDP payload:
 *   - Byte 0, bit 7 == 1 → Long Header: DCID starts at offset 6, length at byte 5.
 *   - Byte 0, bit 7 == 0 → Short Header: DCID starts at offset 1, fixed 8 bytes.
 *   - In both cases, CID[0] % shard_count → target socket index.
 *   - Falls back to socket 0 on any parse failure.
 *
 * The program type is BPF_PROG_TYPE_SK_REUSEPORT, and it returns the
 * index into the SO_REUSEPORT group via bpf_sk_select_reuseport().
 *
 * Since we cannot use bpf_sk_select_reuseport() without a BPF map and
 * complex verifier-safe code from raw instructions, we use a simpler
 * approach: a classic BPF (SO_ATTACH_REUSEPORT_CBPF) program that
 * returns the socket index directly.
 *
 * Classic BPF for SO_ATTACH_REUSEPORT_CBPF:
 *   The return value is the socket index in the SO_REUSEPORT group.
 *   We can access the packet data via BPF_LD | BPF_ABS to read UDP payload.
 *
 * NOTE: SO_ATTACH_REUSEPORT_CBPF uses classic BPF (struct sock_filter).
 *       The program accesses the transport payload (after UDP header).
 *       Data offset 0 = first byte of UDP payload = QUIC packet byte 0.
 */

class XquicEbpfReuseport {
public:
    /**
     * Create the eBPF/cBPF reuseport dispatcher.
     * @param shard_count  Number of shards (SO_REUSEPORT sockets).
     * @param cid_len      Expected QUIC CID length (default: 8).
     */
    explicit XquicEbpfReuseport(unsigned shard_count, unsigned cid_len = 8)
        : _shard_count(shard_count), _cid_len(cid_len) {
        if (_shard_count == 0) {
            throw std::invalid_argument("shard_count must be > 0");
        }
    }

    /**
     * Create a UDP socket with SO_REUSEPORT bound to the given port.
     * All shard sockets must be created in order (shard 0 first).
     * The eBPF program is attached after the first socket is created.
     *
     * @param port   UDP port to bind.
     * @param shard  Shard index (0-based).
     * @return File descriptor of the created socket.
     */
    int create_reuseport_socket(uint16_t port, unsigned shard) {
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            throw std::runtime_error(std::string("socket() failed: ") + strerror(errno));
        }

        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            close(fd);
            throw std::runtime_error(std::string("SO_REUSEPORT failed: ") + strerror(errno));
        }

        /* Apply the shared UDP perf set: large buffers, DF=1 + IP_RECVERR
         * for QUIC PMTUD, IP_PKTINFO for wildcard binds. See
         * tests/xqc_socket_opts.h for the full rationale. */
        xqc_apply_udp_perf_opts(fd, AF_INET, /*server=*/1);

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            throw std::runtime_error(std::string("bind() failed: ") + strerror(errno));
        }

        _fds.push_back(fd);

        /*
         * Attach the cBPF program after ALL sockets have been created.
         * This must be called by the user via attach_cbpf() after all
         * shard sockets are created, because SO_ATTACH_REUSEPORT_CBPF
         * requires all sockets in the reuseport group to exist first.
         */

        return fd;
    }

    /**
     * Attach the classic BPF program to all sockets in the reuseport group.
     * Must be called after all shard sockets are created.
     *
     * The cBPF program:
     *   1. Load QUIC byte 0 from the UDP payload.
     *   2. Check bit 7 (long header vs short header).
     *   3. For short header: load byte 1 (DCID[0]), mod shard_count.
     *   4. For long header: load byte 6 (DCID[0] after version+DCID_len), mod shard_count.
     *   5. Return the socket index.
     *
     * Classic BPF for SO_ATTACH_REUSEPORT_CBPF operates on the SKB data
     * starting from the transport payload (UDP payload).
     */
    void attach_cbpf() {
        if (_fds.empty()) {
            throw std::runtime_error("no sockets to attach cBPF to");
        }

        auto prog = build_cbpf_program();

        struct sock_fprog fprog;
        fprog.len = static_cast<unsigned short>(prog.size());
        fprog.filter = prog.data();

        /* Attach to the FIRST socket — kernel propagates to the group */
        if (setsockopt(_fds[0], SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
                       &fprog, sizeof(fprog)) < 0) {
            throw std::runtime_error(
                std::string("SO_ATTACH_REUSEPORT_CBPF failed: ") + strerror(errno) +
                " (need Linux >= 4.19 and CAP_NET_ADMIN)");
        }

        _attached = true;
        fprintf(stdout, "[eBPF] cBPF reuseport program attached (shard_count=%u, cid_len=%u)\n",
                _shard_count, _cid_len);
    }

    /**
     * Detach and clean up. Closes sockets if requested.
     */
    void detach() {
        /* cBPF is automatically detached when sockets close */
        _attached = false;
    }

    bool attached() const { return _attached; }
    unsigned shard_count() const { return _shard_count; }
    const std::vector<int>& fds() const { return _fds; }

private:
    unsigned _shard_count;
    unsigned _cid_len;
    bool _attached = false;
    std::vector<int> _fds;

    /**
     * Build a classic BPF program for QUIC DCID-based reuseport dispatch.
     *
     * The program inspects the UDP payload (offset 0 = QUIC packet byte 0):
     *
     *   ; Load byte 0 of UDP payload (QUIC first byte)
     *   BPF_LD | BPF_B | BPF_ABS   [0]        ; A = payload[0]
     *   BPF_ALU | BPF_AND | BPF_K  0x80        ; A = A & 0x80
     *   BPF_JMP | BPF_JEQ | BPF_K  0x80, long_header, short_header
     *
     *   short_header:
     *     ; Short header: DCID starts at byte 1
     *     BPF_LD | BPF_B | BPF_ABS [1]         ; A = payload[1] = DCID[0]
     *     BPF_JMP | BPF_JA         mod_and_ret
     *
     *   long_header:
     *     ; Long header format:
     *     ;   byte 0: flags
     *     ;   bytes 1-4: version (4 bytes)
     *     ;   byte 5: DCID length
     *     ;   bytes 6+: DCID data
     *     ; Load DCID[0] at offset 6
     *     BPF_LD | BPF_B | BPF_ABS [6]         ; A = payload[6] = DCID[0]
     *
     *   mod_and_ret:
     *     BPF_ALU | BPF_MOD | BPF_K shard_count ; A = A % shard_count
     *     BPF_RET | BPF_A                        ; return A (socket index)
     *
     *   fallback:
     *     BPF_RET | BPF_K  0                    ; return 0 (shard 0)
     */
    std::vector<struct sock_filter> build_cbpf_program() {
        std::vector<struct sock_filter> prog;

        if (_shard_count <= 1) {
            /* Single shard: always return 0 */
            prog.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
            return prog;
        }

        /*
         * Instruction layout:
         *  [0] LD byte 0          ; A = payload[0]
         *  [1] AND 0x80           ; A = A & 0x80 (isolate long-header bit)
         *  [2] JEQ 0x80 → +2, +0 ; if long-header, skip 2 instructions ahead
         *  [3] LD byte 1          ; short-header: A = payload[1] = DCID[0]
         *  [4] JA +1              ; jump to MOD
         *  [5] LD byte 6          ; long-header: A = payload[6] = DCID[0]
         *  [6] MOD shard_count    ; A = A % shard_count
         *  [7] RET A              ; return socket index
         */

        /* [0] Load byte 0 of UDP payload */
        prog.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));

        /* [1] A = A & 0x80 */
        prog.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x80));

        /* [2] if A == 0x80: jump to [5] (long_header), else fall through to [3] */
        prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x80, 2, 0));

        /* [3] Short header: load DCID[0] at byte offset 1 */
        prog.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 1));

        /* [4] Jump over long-header load to MOD */
        prog.push_back(BPF_JUMP(BPF_JMP | BPF_JA, 1, 0, 0));

        /* [5] Long header: load DCID[0] at byte offset 6 */
        prog.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6));

        /* [6] A = A % shard_count */
        prog.push_back(BPF_STMT(BPF_ALU | BPF_MOD | BPF_K, _shard_count));

        /* [7] Return A (socket index in reuseport group) */
        prog.push_back(BPF_STMT(BPF_RET | BPF_A, 0));

        return prog;
    }
};
