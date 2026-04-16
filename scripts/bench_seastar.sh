#!/bin/bash
# Seastar XQUIC Server - Single Core Benchmark Script
# Usage: ./scripts/bench_seastar.sh [test_level]
#   test_level: quick | standard | stress (default: standard)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SERVER_BIN="$ROOT_DIR/build_seastar/xquic_tests/xquic_server_seastar"
CLIENT_BIN="$ROOT_DIR/build/tests/test_client"
CERT="$ROOT_DIR/server.crt"
KEY="$ROOT_DIR/server.key"
PORT=8443
TEST_LEVEL="${1:-standard}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[BENCH]${NC} $*"; }
ok()  { echo -e "${GREEN}[  OK ]${NC} $*"; }
fail(){ echo -e "${RED}[FAIL]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }

cleanup() {
    log "Cleaning up..."
    pkill -9 -f xquic_server_seastar 2>/dev/null || true
    pkill -9 -f test_client 2>/dev/null || true
    wait 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

check_prereqs() {
    if [ ! -x "$SERVER_BIN" ]; then
        fail "Server binary not found: $SERVER_BIN"
        exit 1
    fi
    if [ ! -x "$CLIENT_BIN" ]; then
        fail "Client binary not found: $CLIENT_BIN"
        exit 1
    fi
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        fail "Certificate or key not found"
        exit 1
    fi
}

start_server() {
    log "Starting Seastar XQUIC server on port $PORT (single core)..."
    cleanup
    sleep 1

    cd "$ROOT_DIR"
    "$SERVER_BIN" \
        --port "$PORT" \
        --cert "$CERT" \
        --key "$KEY" \
        --smp 1 \
        --reactor-backend epoll \
        2>"$ROOT_DIR/bench_server.log" &
    SERVER_PID=$!

    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        fail "Server failed to start. Log:"
        tail -20 "$ROOT_DIR/bench_server.log"
        exit 1
    fi
    ok "Server started (PID=$SERVER_PID)"
}

wait_for_stats() {
    # Wait for a stats line to appear in server log
    local timeout=${1:-10}
    for i in $(seq 1 $timeout); do
        if grep -q '\[STATS\]' "$ROOT_DIR/bench_server.log" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

run_single_connection_test() {
    log "=== Test 1: Single Connection (H3) ==="
    local start_time=$(date +%s%N)

    "$CLIENT_BIN" -a 127.0.0.1 -p "$PORT" -s 1024 2>/dev/null &
    local cpid=$!
    wait "$cpid" 2>/dev/null
    local rc=$?

    local end_time=$(date +%s%N)
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))

    if [ $rc -eq 0 ]; then
        ok "Single H3 connection completed in ${elapsed_ms}ms"
    else
        fail "Single connection failed (rc=$rc)"
        return 1
    fi
}

run_sequential_connections() {
    local count=$1
    log "=== Test 2: Sequential Connections ($count connections) ==="
    local start_time=$(date +%s%N)
    local success=0
    local failed=0

    for i in $(seq 1 $count); do
        "$CLIENT_BIN" -a 127.0.0.1 -p "$PORT" -s 256 2>/dev/null &
        local cpid=$!
        if wait "$cpid" 2>/dev/null; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
    done

    local end_time=$(date +%s%N)
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local rate=0
    if [ $elapsed_ms -gt 0 ]; then
        rate=$(( success * 1000 / elapsed_ms ))
    fi

    ok "Sequential: $success/$count succeeded, ${failed} failed, ${elapsed_ms}ms total, ~${rate} conn/s"
}

run_parallel_connections() {
    local count=$1
    local batch_size=$2
    log "=== Test 3: Parallel Connections ($count total, $batch_size concurrent) ==="
    local start_time=$(date +%s%N)
    local success=0
    local failed=0
    local launched=0

    while [ $launched -lt $count ]; do
        local batch_pids=()
        local this_batch=0

        while [ $this_batch -lt $batch_size ] && [ $launched -lt $count ]; do
            "$CLIENT_BIN" -a 127.0.0.1 -p "$PORT" -s 256 2>/dev/null &
            batch_pids+=($!)
            launched=$((launched + 1))
            this_batch=$((this_batch + 1))
        done

        for pid in "${batch_pids[@]}"; do
            if wait "$pid" 2>/dev/null; then
                success=$((success + 1))
            else
                failed=$((failed + 1))
            fi
        done
    done

    local end_time=$(date +%s%N)
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local rate=0
    if [ $elapsed_ms -gt 0 ]; then
        rate=$(( success * 1000 / elapsed_ms ))
    fi

    ok "Parallel: $success/$count succeeded, ${failed} failed, ${elapsed_ms}ms total, ~${rate} conn/s"
}

run_sustained_load() {
    local duration=$1
    local concurrency=$2
    log "=== Test 4: Sustained Load (${duration}s, ${concurrency} concurrent) ==="

    # Clear stats log
    > "$ROOT_DIR/bench_server.log"

    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local total_launched=0
    local total_success=0
    local total_failed=0

    while [ $(date +%s) -lt $end_time ]; do
        local batch_pids=()
        for i in $(seq 1 $concurrency); do
            "$CLIENT_BIN" -a 127.0.0.1 -p "$PORT" -s 512 2>/dev/null &
            batch_pids+=($!)
            total_launched=$((total_launched + 1))
        done

        for pid in "${batch_pids[@]}"; do
            if wait "$pid" 2>/dev/null; then
                total_success=$((total_success + 1))
            else
                total_failed=$((total_failed + 1))
            fi
        done
    done

    local actual_duration=$(( $(date +%s) - start_time ))
    local rate=0
    if [ $actual_duration -gt 0 ]; then
        rate=$((total_success / actual_duration))
    fi

    ok "Sustained: ${total_success}/${total_launched} succeeded over ${actual_duration}s, ~${rate} conn/s"

    # Print server stats
    log "Server stats from log:"
    grep '\[STATS\]' "$ROOT_DIR/bench_server.log" | tail -5
}

print_summary() {
    echo ""
    echo "================================================================="
    echo "  Seastar XQUIC Single-Core Benchmark Summary"
    echo "================================================================="
    echo "  Server: $SERVER_BIN"
    echo "  Client: $CLIENT_BIN"
    echo "  Mode:   Single core (--smp 1)"
    echo "  Level:  $TEST_LEVEL"
    echo "================================================================="
    echo ""
}

# =========================================================================
# Main
# =========================================================================

check_prereqs
print_summary
start_server

case "$TEST_LEVEL" in
    quick)
        run_single_connection_test
        run_sequential_connections 10
        run_parallel_connections 20 5
        ;;
    standard)
        run_single_connection_test
        run_sequential_connections 50
        run_parallel_connections 100 10
        run_parallel_connections 200 20
        run_sustained_load 15 10
        ;;
    stress)
        run_single_connection_test
        run_sequential_connections 100
        run_parallel_connections 200 20
        run_parallel_connections 500 50
        run_sustained_load 30 20
        run_sustained_load 60 50
        ;;
    *)
        fail "Unknown test level: $TEST_LEVEL (use: quick, standard, stress)"
        exit 1
        ;;
esac

echo ""
log "Final server stats:"
grep '\[STATS\]' "$ROOT_DIR/bench_server.log" 2>/dev/null | tail -5 || warn "No stats lines found"
echo ""
ok "Benchmark complete!"
