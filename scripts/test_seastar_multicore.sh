#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# test_seastar_multicore.sh — 多核 Seastar QUIC 服务端单元测试
#
# 功能验证:
#   1. smp=1 单核 video 模式 — 基线功能验证
#   2. smp=2 多核 video 模式 — 验证 CID 路由 + 跨 shard 通信
#   3. smp=4 多核 video 模式 — 验证更多核心的扩展性
#   4. smp=2 echo 模式    — 验证多核 echo 回显
#   5. smp=2 framed 模式  — 验证多核 framed 协议
#
# 用法: bash scripts/test_seastar_multicore.sh [--skip-build]
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SERVER="$ROOT_DIR/build_seastar/xquic_tests/xquic_server_seastar"
VIDEO_CLIENT="$ROOT_DIR/build/xquic_tests/video_client"
VIDEO_BENCH="$ROOT_DIR/build/xquic_tests/video_bench"
TEST_H264="$ROOT_DIR/test_cam0.h264"
TEST_H264_LARGE="$ROOT_DIR/test_cam0_large.h264"
CERT="$ROOT_DIR/server.crt"
KEY="$ROOT_DIR/server.key"
VIDEO_OUT="$ROOT_DIR/video_out_test"
PORT=18443  # 使用非默认端口避免冲突

PASS=0
FAIL=0
SKIP=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { ((PASS++)); echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { ((FAIL++)); echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

cleanup() {
    pkill -9 -f "xquic_server_seastar.*$PORT" 2>/dev/null || true
    rm -rf "$VIDEO_OUT" 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

wait_server_ready() {
    local tries=0
    while ! ss -ulnp 2>/dev/null | grep -q ":$PORT "; do
        sleep 0.5
        ((tries++))
        if [ $tries -ge 20 ]; then
            echo "Server failed to start on port $PORT"
            return 1
        fi
    done
    return 0
}

start_server() {
    local smp=$1; shift
    local extra_args="$@"
    cleanup
    rm -rf "$VIDEO_OUT"; mkdir -p "$VIDEO_OUT"
    log_info "Starting server: smp=$smp $extra_args"
    "$SERVER" --smp "$smp" --cert "$CERT" --key "$KEY" -p "$PORT" $extra_args &>/dev/null &
    if ! wait_server_ready; then
        log_fail "Server start (smp=$smp)"
        return 1
    fi
    log_info "Server ready (smp=$smp)"
    return 0
}

stop_server() {
    pkill -9 -f "xquic_server_seastar.*$PORT" 2>/dev/null || true
    sleep 1
}

# ─── Pre-flight checks ───────────────────────────────────────────
echo "════════════════════════════════════════════════════════"
echo "  Seastar Multi-Core QUIC Server — Unit Tests"
echo "════════════════════════════════════════════════════════"

if [ "${1:-}" != "--skip-build" ]; then
    log_info "Building..."
    (cd "$ROOT_DIR/build_seastar" && make xquic_server_seastar -j$(nproc) 2>&1 | tail -3)
    (cd "$ROOT_DIR/build" && cmake --build . --target video_bench video_client -j$(nproc) 2>&1 | tail -3)
fi

for f in "$SERVER" "$VIDEO_BENCH" "$TEST_H264" "$CERT" "$KEY"; do
    if [ ! -f "$f" ]; then
        echo "Missing: $f"
        exit 1
    fi
done

# ─── Test 1: smp=1 video — baseline ─────────────────────────────
test_video_single_conn() {
    local smp=$1
    local label="smp=$smp video single-conn"
    if ! start_server "$smp" "--video --video-dir $VIDEO_OUT"; then
        return
    fi

    local output
    output=$("$VIDEO_BENCH" -a 127.0.0.1 -p "$PORT" -n 1 -r 1 --cam0 "$TEST_H264" 2>&1 || true)
    if echo "$output" | grep -q "1 completed, 0 failed"; then
        log_pass "$label"
    else
        log_fail "$label"
        echo "$output" | tail -5
    fi
    stop_server
}

# ─── Test 2: smp=N video multi-connection ────────────────────────
test_video_multi_conn() {
    local smp=$1
    local conns=$2
    local label="smp=$smp video ${conns}-conns"
    if ! start_server "$smp" "--video --video-dir $VIDEO_OUT"; then
        return
    fi

    local output
    output=$("$VIDEO_BENCH" -a 127.0.0.1 -p "$PORT" -n "$conns" -r 1 --cam0 "$TEST_H264" 2>&1 || true)
    local completed
    completed=$(echo "$output" | grep -oP '\d+ completed' | head -1 | grep -oP '\d+')
    local failed
    failed=$(echo "$output" | grep -oP '\d+ failed' | head -1 | grep -oP '\d+')

    if [ -n "$completed" ] && [ "$completed" -ge "$((conns * 80 / 100))" ]; then
        log_pass "$label (completed=$completed/$conns, failed=${failed:-0})"
    else
        log_fail "$label (completed=${completed:-0}/$conns, failed=${failed:-?})"
        echo "$output" | grep -E 'Round|Latency|Throughput' | head -5
    fi
    stop_server
}

# ─── Test 3: smp=N echo mode ────────────────────────────────────
test_echo_mode() {
    local smp=$1
    local label="smp=$smp echo mode"
    if ! start_server "$smp" "--echo"; then
        return
    fi

    # Use video_bench with small file — echo server just receives, client finishes after send
    local output
    output=$("$VIDEO_BENCH" -a 127.0.0.1 -p "$PORT" -n 5 -r 1 --cam0 "$TEST_H264" 2>&1 || true)
    if echo "$output" | grep -q "completed"; then
        local completed
        completed=$(echo "$output" | grep -oP '\d+ completed' | head -1 | grep -oP '\d+')
        if [ -n "$completed" ] && [ "$completed" -ge 1 ]; then
            log_pass "$label (completed=$completed/5)"
        else
            log_fail "$label"
        fi
    else
        log_fail "$label"
    fi
    stop_server
}

# ─── Test 4: smp=N framed mode (default) ────────────────────────
test_framed_mode() {
    local smp=$1
    local label="smp=$smp framed (default) mode"
    if ! start_server "$smp" ""; then
        return
    fi

    # Basic connectivity test — framed needs proper framed client,
    # but video_bench can verify at least TLS handshake + stream creation
    local output
    output=$("$VIDEO_BENCH" -a 127.0.0.1 -p "$PORT" -n 3 -r 1 --cam0 "$TEST_H264" 2>&1 || true)
    if echo "$output" | grep -q "completed"; then
        local completed
        completed=$(echo "$output" | grep -oP '\d+ completed' | head -1 | grep -oP '\d+')
        if [ -n "$completed" ] && [ "$completed" -ge 1 ]; then
            log_pass "$label (completed=$completed/3)"
        else
            log_fail "$label"
        fi
    else
        log_fail "$label"
    fi
    stop_server
}

# ─── Test 5: shard routing verification ──────────────────────────
test_shard_routing() {
    local smp=$1
    local conns=$2
    local label="smp=$smp shard-routing ${conns}-conns"
    if ! start_server "$smp" "--video --video-dir $VIDEO_OUT"; then
        return
    fi

    local output
    output=$("$VIDEO_BENCH" -a 127.0.0.1 -p "$PORT" -n "$conns" -r 1 --cam0 "$TEST_H264" 2>&1 || true)
    local completed
    completed=$(echo "$output" | grep -oP '\d+ completed' | head -1 | grep -oP '\d+')

    # With proper shard routing, multi-core should complete more connections
    # than the ~48/12s rate we saw with single-core TLS bottleneck
    if [ -n "$completed" ] && [ "$completed" -ge "$((conns * 70 / 100))" ]; then
        log_pass "$label (completed=$completed/$conns)"
    else
        log_fail "$label (completed=${completed:-0}/$conns — possible routing issue)"
        echo "$output" | grep -E 'Round|Latency|bench' | tail -5
    fi
    stop_server
}

# ─── Run all tests ───────────────────────────────────────────────
echo ""
echo "── Baseline: smp=1 ──────────────────────────────────────"
test_video_single_conn 1
test_video_multi_conn 1 10

echo ""
echo "── Multi-core: smp=2 ────────────────────────────────────"
test_video_single_conn 2
test_video_multi_conn 2 10
test_video_multi_conn 2 50
test_echo_mode 2
test_framed_mode 2

echo ""
echo "── Multi-core: smp=4 ────────────────────────────────────"
test_video_single_conn 4
test_video_multi_conn 4 10
test_video_multi_conn 4 50
test_shard_routing 4 100

echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}PASS=$PASS${NC}  ${RED}FAIL=$FAIL${NC}  SKIP=$SKIP"
echo "════════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
