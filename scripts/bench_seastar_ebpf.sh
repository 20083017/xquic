#!/bin/bash
# Seastar XQUIC — POSIX + eBPF vs DPDK vs plain POSIX benchmark
# Usage: ./scripts/bench_seastar_ebpf.sh [test_level] [mode]
#   test_level: quick | standard | stress (default: standard)
#   mode:       ebpf | posix | all (default: all)
#
# Runs the eBPF reuseport server variant and compares with plain POSIX.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
EBPF_SERVER_BIN="$ROOT_DIR/build_seastar/xquic_tests/xquic_server_seastar_ebpf"
POSIX_SERVER_BIN="$ROOT_DIR/build_seastar/xquic_tests/xquic_server_seastar"
CLIENT_BIN="$ROOT_DIR/build_seastar/xquic_tests/test_client"
CERT="$ROOT_DIR/server.crt"
KEY="$ROOT_DIR/server.key"
PORT=8443
TEST_LEVEL="${1:-standard}"
MODE="${2:-all}"
RESULTS_DIR="$ROOT_DIR/bench_results"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[BENCH]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
hdr()  { echo -e "\n${BOLD}═══ $* ═══${NC}\n"; }

cleanup() {
    log "Cleaning up..."
    pkill -9 -f xquic_server_seastar 2>/dev/null || true
    pkill -9 -f test_client 2>/dev/null || true
    wait 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

mkdir -p "$RESULTS_DIR"

check_prereqs() {
    local missing=0
    if [ ! -x "$CLIENT_BIN" ]; then
        fail "Client binary not found: $CLIENT_BIN"
        missing=1
    fi
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        fail "Certificate or key not found"
        missing=1
    fi
    if [[ "$MODE" == "all" || "$MODE" == "ebpf" ]]; then
        if [ ! -x "$EBPF_SERVER_BIN" ]; then
            fail "eBPF server binary not found: $EBPF_SERVER_BIN"
            fail "Build with: cmake --build build_seastar --target xquic_server_seastar_ebpf"
            missing=1
        fi
    fi
    if [[ "$MODE" == "all" || "$MODE" == "posix" ]]; then
        if [ ! -x "$POSIX_SERVER_BIN" ]; then
            fail "POSIX server binary not found: $POSIX_SERVER_BIN"
            missing=1
        fi
    fi
    if [ $missing -eq 1 ]; then exit 1; fi
}

get_test_params() {
    case "$TEST_LEVEL" in
        quick)
            CONCURRENT=1
            REQUESTS=10
            DURATION=5
            SMP_COUNTS="1 2"
            ;;
        standard)
            CONCURRENT=4
            REQUESTS=50
            DURATION=10
            SMP_COUNTS="1 2 4"
            ;;
        stress)
            CONCURRENT=16
            REQUESTS=200
            DURATION=30
            SMP_COUNTS="1 2 4"
            ;;
        *)
            fail "Unknown test level: $TEST_LEVEL (use quick|standard|stress)"
            exit 1
            ;;
    esac
}

start_server() {
    local server_bin="$1"
    local smp="$2"
    local extra_args="${3:-}"
    local logfile="$4"

    cleanup
    sleep 1

    cd "$ROOT_DIR"
    $server_bin \
        --port "$PORT" \
        --cert "$CERT" \
        --key "$KEY" \
        --smp "$smp" \
        --reactor-backend epoll \
        $extra_args \
        2>"$logfile" &
    SERVER_PID=$!

    sleep 3
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        fail "Server failed to start. Log:"
        tail -20 "$logfile"
        return 1
    fi
    ok "Server started (PID=$SERVER_PID, smp=$smp)"
    return 0
}

run_client_test() {
    local label="$1"
    local smp="$2"
    local result_file="$3"

    log "Running client test: $label (concurrent=$CONCURRENT, requests=$REQUESTS)"
    cd "$ROOT_DIR"

    local start_time=$(date +%s%N)

    # Run multiple concurrent clients with timeout (connections may idle)
    local pids=()
    local client_timeout=30
    for i in $(seq 1 $CONCURRENT); do
        timeout "$client_timeout" $CLIENT_BIN -a 127.0.0.1 -p $PORT -s 1024 -n $REQUESTS -c \
            2>/dev/null &
        pids+=($!)
    done

    # Wait for all clients
    local failures=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            failures=$((failures + 1))
        fi
    done

    local end_time=$(date +%s%N)
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local total_requests=$((CONCURRENT * REQUESTS))
    local rps=0
    if [ $elapsed_ms -gt 0 ]; then
        rps=$((total_requests * 1000 / elapsed_ms))
    fi

    echo "$label,smp=$smp,$total_requests,$elapsed_ms,$rps,$failures" >> "$result_file"

    if [ $failures -eq 0 ]; then
        ok "$label: ${total_requests} requests in ${elapsed_ms}ms (${rps} req/s)"
    else
        warn "$label: ${total_requests} requests, ${failures} client failures, ${elapsed_ms}ms (${rps} req/s)"
    fi
}

collect_server_stats() {
    local logfile="$1"
    if [ -f "$logfile" ]; then
        grep "\[shard" "$logfile" | tail -10
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  Main benchmark flow
# ═══════════════════════════════════════════════════════════════════

check_prereqs
get_test_params

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_CSV="$RESULTS_DIR/bench_${TIMESTAMP}.csv"
echo "mode,smp,total_requests,elapsed_ms,rps,failures" > "$RESULT_CSV"

hdr "POSIX + eBPF vs Plain POSIX Benchmark"
log "Test level: $TEST_LEVEL | Mode: $MODE"
log "Results: $RESULT_CSV"

# ─── eBPF mode benchmarks ─────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "ebpf" ]]; then
    hdr "eBPF Reuseport Mode"

    for smp in $SMP_COUNTS; do
        log "Testing eBPF mode with smp=$smp..."
        LOGFILE="$RESULTS_DIR/ebpf_smp${smp}.log"

        if start_server "$EBPF_SERVER_BIN" "$smp" "" "$LOGFILE"; then
            run_client_test "ebpf" "$smp" "$RESULT_CSV"
            sleep 2
            collect_server_stats "$LOGFILE"
        else
            fail "eBPF server failed to start with smp=$smp"
            echo "ebpf,smp=$smp,0,0,0,FAILED" >> "$RESULT_CSV"
        fi
        cleanup
    done

    # Also test fallback (eBPF binary with --no-ebpf)
    hdr "eBPF Binary — Fallback POSIX Mode (--no-ebpf)"
    for smp in $SMP_COUNTS; do
        log "Testing eBPF fallback with smp=$smp..."
        LOGFILE="$RESULTS_DIR/ebpf_fallback_smp${smp}.log"

        if start_server "$EBPF_SERVER_BIN" "$smp" "--no-ebpf" "$LOGFILE"; then
            run_client_test "ebpf-fallback" "$smp" "$RESULT_CSV"
            sleep 2
            collect_server_stats "$LOGFILE"
        else
            fail "eBPF fallback server failed with smp=$smp"
            echo "ebpf-fallback,smp=$smp,0,0,0,FAILED" >> "$RESULT_CSV"
        fi
        cleanup
    done
fi

# ─── Plain POSIX mode benchmarks ──────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "posix" ]]; then
    hdr "Plain POSIX Mode (Original Server)"

    for smp in $SMP_COUNTS; do
        log "Testing POSIX mode with smp=$smp..."
        LOGFILE="$RESULTS_DIR/posix_smp${smp}.log"

        if start_server "$POSIX_SERVER_BIN" "$smp" "" "$LOGFILE"; then
            run_client_test "posix" "$smp" "$RESULT_CSV"
            sleep 2
            collect_server_stats "$LOGFILE"
        else
            fail "POSIX server failed to start with smp=$smp"
            echo "posix,smp=$smp,0,0,0,FAILED" >> "$RESULT_CSV"
        fi
        cleanup
    done
fi

# ─── Summary ──────────────────────────────────────────────────
hdr "Benchmark Results Summary"
echo ""
printf "%-20s %-8s %-12s %-12s %-10s %-8s\n" "MODE" "SMP" "REQUESTS" "TIME(ms)" "REQ/S" "FAILS"
printf "%-20s %-8s %-12s %-12s %-10s %-8s\n" "----" "---" "--------" "--------" "-----" "-----"
tail -n +2 "$RESULT_CSV" | while IFS=',' read -r mode smp reqs time rps fails; do
    printf "%-20s %-8s %-12s %-12s %-10s %-8s\n" "$mode" "$smp" "$reqs" "$time" "$rps" "$fails"
done
echo ""
ok "Full results: $RESULT_CSV"
