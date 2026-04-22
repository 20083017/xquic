#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# bench_seastar_multicore.sh — 多核 Seastar QUIC 服务端压测
#
# 自动执行矩阵压测:
#   SMP:  1, 2, 4
#   并发: 10, 100, 500
#   文件: small (24KB), large (381KB)
#
# 输出 CSV 格式结果，方便后续分析和图表绘制。
#
# 用法:
#   bash scripts/bench_seastar_multicore.sh [--skip-build] [--quick]
#   --quick: 只测 smp=1,2 + conns=10,100
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SERVER="$ROOT_DIR/build_seastar/xquic_tests/xquic_server_seastar"
VIDEO_BENCH="$ROOT_DIR/build/xquic_tests/video_bench"
TEST_H264_SMALL="$ROOT_DIR/test_cam0.h264"
TEST_H264_LARGE="$ROOT_DIR/test_cam0_large.h264"
CERT="$ROOT_DIR/server.crt"
KEY="$ROOT_DIR/server.key"
VIDEO_OUT="$ROOT_DIR/video_out_bench"
PORT=18444
RESULTS_DIR="$ROOT_DIR/bench_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CSV_FILE="$RESULTS_DIR/bench_${TIMESTAMP}.csv"

QUICK=false

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --quick) QUICK=true ;;
    esac
done

# ─── Config ──────────────────────────────────────────────────────
if $QUICK; then
    SMP_LIST=(1 2)
    CONN_LIST=(10 100)
    FILE_LIST=("$TEST_H264_SMALL")
    FILE_LABELS=("small")
else
    SMP_LIST=(1 2 4)
    CONN_LIST=(10 100 500)
    FILE_LIST=("$TEST_H264_SMALL" "$TEST_H264_LARGE")
    FILE_LABELS=("small_24KB" "large_381KB")
fi

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

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
        if [ $tries -ge 20 ]; then return 1; fi
    done
    return 0
}

start_server() {
    local smp=$1
    cleanup
    rm -rf "$VIDEO_OUT"; mkdir -p "$VIDEO_OUT"
    "$SERVER" --smp "$smp" --cert "$CERT" --key "$KEY" -p "$PORT" --video --video-dir "$VIDEO_OUT" &>/dev/null &
    if ! wait_server_ready; then
        log_info "FAILED to start server smp=$smp"
        return 1
    fi
    return 0
}

stop_server() {
    pkill -9 -f "xquic_server_seastar.*$PORT" 2>/dev/null || true
    sleep 1
}

# ─── Pre-flight ──────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════════"
echo "  Seastar Multi-Core QUIC Server — Benchmark Suite"
echo "════════════════════════════════════════════════════════════"
echo ""

if [ "${SKIP_BUILD:-false}" != "true" ]; then
    log_info "Building..."
    (cd "$ROOT_DIR/build_seastar" && make xquic_server_seastar -j$(nproc) 2>&1 | tail -2)
    (cd "$ROOT_DIR/build" && cmake --build . --target video_bench -j$(nproc) 2>&1 | tail -2)
fi

# Generate large file if missing
if [ ! -f "$TEST_H264_LARGE" ]; then
    log_info "Generating large test H.264 file..."
    ffmpeg -y -f lavfi -i testsrc=duration=10:size=640x480:rate=30 \
        -pix_fmt yuv420p -c:v libx264 -profile:v baseline -level 3.0 \
        -b:v 500k -g 30 -an "$TEST_H264_LARGE" 2>/dev/null
fi

mkdir -p "$RESULTS_DIR"

# ─── CSV header ──────────────────────────────────────────────────
echo "smp,conns,file,file_bytes,completed,failed,time_s,throughput_mbps,avg_ms,p50_ms,p95_ms,p99_ms,max_ms" > "$CSV_FILE"

# ─── Run benchmark matrix ────────────────────────────────────────
total_tests=$(( ${#SMP_LIST[@]} * ${#CONN_LIST[@]} * ${#FILE_LIST[@]} ))
current=0

echo ""
printf "%-5s %-6s %-12s | %-6s %-6s %-8s %-10s %-8s %-8s %-8s %-8s\n" \
    "SMP" "CONNS" "FILE" "OK" "FAIL" "TIME(s)" "MBPS" "AVG" "P50" "P95" "P99"
echo "──────────────────────────────────────────────────────────────────────────────────────"

for smp in "${SMP_LIST[@]}"; do
    if ! start_server "$smp"; then
        log_info "Skip smp=$smp — server start failed"
        continue
    fi

    for fi_idx in "${!FILE_LIST[@]}"; do
        h264="${FILE_LIST[$fi_idx]}"
        flabel="${FILE_LABELS[$fi_idx]}"
        file_bytes=$(wc -c < "$h264")

        for conns in "${CONN_LIST[@]}"; do
            ((current++))

            # Run benchmark
            output=$("$VIDEO_BENCH" -a 127.0.0.1 -p "$PORT" -n "$conns" -r 1 --cam0 "$h264" 2>&1 || true)

            # Parse results
            completed=$(echo "$output" | grep -oP '\d+ completed' | head -1 | grep -oP '\d+' || echo "0")
            failed=$(echo "$output" | grep -oP '\d+ failed' | head -1 | grep -oP '\d+' || echo "0")
            time_s=$(echo "$output" | grep -oP 'Time: \K[\d.]+' | head -1 || echo "0")
            throughput=$(echo "$output" | grep -oP 'Throughput: \K[\d.]+' | head -1 || echo "0")
            avg_ms=$(echo "$output" | grep -oP 'avg=\K[\d.]+' | head -1 || echo "0")
            p50_ms=$(echo "$output" | grep -oP 'p50=\K[\d.]+' | head -1 || echo "0")
            p95_ms=$(echo "$output" | grep -oP 'p95=\K[\d.]+' | head -1 || echo "0")
            p99_ms=$(echo "$output" | grep -oP 'p99=\K[\d.]+' | head -1 || echo "0")
            max_ms=$(echo "$output" | grep -oP 'max=\K[\d.]+' | head -1 || echo "0")

            # CSV
            echo "$smp,$conns,$flabel,$file_bytes,$completed,$failed,$time_s,$throughput,$avg_ms,$p50_ms,$p95_ms,$p99_ms,$max_ms" >> "$CSV_FILE"

            # Console
            printf "%-5s %-6s %-12s | %-6s %-6s %-8s %-10s %-8s %-8s %-8s %-8s\n" \
                "$smp" "$conns" "$flabel" "$completed" "$failed" "$time_s" "$throughput" "$avg_ms" "$p50_ms" "$p95_ms" "$p99_ms"

            # Brief pause between tests
            sleep 1
        done
    done

    stop_server
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "  ${GREEN}Benchmark complete!${NC}"
echo "  Results: $CSV_FILE"
echo "════════════════════════════════════════════════════════════"
echo ""

# ─── Summary: compare smp scaling ────────────────────────────────
echo "── Scaling Summary (100 conns, large file if available) ──"
echo ""
if [ -f "$CSV_FILE" ]; then
    printf "%-5s %-10s %-8s %-8s %-10s %-8s\n" "SMP" "Completed" "Failed" "Time(s)" "Mbps" "Avg(ms)"
    echo "─────────────────────────────────────────────────────"
    # Pick 100-conn rows (prefer large file)
    while IFS=, read -r smp conns file fbytes comp fail t tp avg p50 p95 p99 mx; do
        [ "$conns" = "100" ] || continue
        printf "%-5s %-10s %-8s %-8s %-10s %-8s\n" "$smp" "$comp" "$fail" "$t" "$tp" "$avg"
    done < <(tail -n +2 "$CSV_FILE" | sort -t, -k1n -k3r | awk -F, '!seen[$1]++')
fi
