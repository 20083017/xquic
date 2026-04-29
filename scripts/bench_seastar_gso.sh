#!/usr/bin/env bash
# bench_seastar_gso.sh — 对比 xquic_server_seastar_ebpf 在 GSO 开/关 两种配置下的
#                         CPU 占用与吞吐 (RPS)。
#
# 思路：使用同一份 ebpf server 二进制，通过环境变量 XQC_DISABLE_GSO 切换
#       UDP_SEGMENT 发送路径；客户端使用 test_client 并发 N 路、每路 M 个请求。
#
# 用法： scripts/bench_seastar_gso.sh [smp] [concurrent] [requests]
#   默认: smp=2 concurrent=4 requests=200

set -u

SMP="${1:-2}"
CONCURRENT="${2:-4}"
REQUESTS="${3:-200}"
BODY_SIZE="${4:-${BODY_SIZE:-1024}}"  # bytes per request body (server response is fixed-tiny; -s is client upload size)
PORT="${PORT:-8443}"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_BIN="$ROOT_DIR/build_seastar/xquic_tests/xquic_server_seastar_ebpf"
CLIENT_BIN="$ROOT_DIR/build_seastar/xquic_tests/test_client"
CERT="${CERT:-$ROOT_DIR/server.crt}"
KEY="${KEY:-$ROOT_DIR/server.key}"
RESULTS_DIR="$ROOT_DIR/bench_results"
mkdir -p "$RESULTS_DIR"

TS=$(date +%Y%m%d_%H%M%S)
CSV="$RESULTS_DIR/gso_compare_${TS}.csv"
echo "label,smp,concurrent,requests,total_requests,elapsed_ms,rps,client_failures,server_cpu_pct,server_user_ms,server_sys_ms,server_rss_kb" > "$CSV"

log()  { echo -e "\033[36m[*]\033[0m $*"; }
ok()   { echo -e "\033[32m[+]\033[0m $*"; }
fail() { echo -e "\033[31m[!]\033[0m $*" >&2; }

cleanup() {
    pkill -9 -f xquic_server_seastar_ebpf 2>/dev/null || true
    pkill -9 -f test_client 2>/dev/null || true
    sleep 0.5
}
trap cleanup EXIT

[[ -x "$SERVER_BIN" ]] || { fail "server bin missing: $SERVER_BIN"; exit 1; }
[[ -x "$CLIENT_BIN" ]] || { fail "client bin missing: $CLIENT_BIN"; exit 1; }
[[ -f "$CERT" && -f "$KEY" ]] || { fail "cert/key missing under build_seastar/xquic_tests/"; exit 1; }

# --------- 读 /proc/<pid>/stat 拿 utime/stime（单位 jiffies） ---------
read_proc_stat() {
    local pid="$1"
    [[ -r "/proc/$pid/stat" ]] || { echo "0 0"; return; }
    # 字段 14=utime 15=stime；comm 可能含括号，所以从右起取更稳：
    awk '{ for(i=NF;i>0;i--){a[NF-i+1]=$i} ; print a[NF-13], a[NF-14] }' "/proc/$pid/stat"
}
read_proc_rss_kb() {
    local pid="$1"
    awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0
}

CLK_TCK=$(getconf CLK_TCK)

run_one() {
    local label="$1"      # gso-on / gso-off
    local env_var="$2"    # 空 或 "XQC_DISABLE_GSO=1"

    cleanup
    local logfile="$RESULTS_DIR/gso_${label}_smp${SMP}.log"

    log "Starting server: $label (smp=$SMP)"
    # shellcheck disable=SC2086
    env $env_var "$SERVER_BIN" \
        --port "$PORT" --cert "$CERT" --key "$KEY" \
        --smp "$SMP" --reactor-backend epoll \
        2>"$logfile" &
    local spid=$!

    sleep 3
    if ! kill -0 "$spid" 2>/dev/null; then
        fail "server failed to start ($label)"
        tail -20 "$logfile"
        echo "$label,$SMP,$CONCURRENT,$REQUESTS,0,0,0,FAILED,0,0,0,0" >> "$CSV"
        return
    fi
    ok "server pid=$spid"

    # 采样起点
    read u0 s0 < <(read_proc_stat "$spid")
    local t0_ns=$(date +%s%N)

    # 跑客户端
    local pids=()
    for i in $(seq 1 "$CONCURRENT"); do
        timeout 60 "$CLIENT_BIN" -a 127.0.0.1 -p "$PORT" -s "$BODY_SIZE" -n "$REQUESTS" -c \
            >/dev/null 2>&1 &
        pids+=($!)
    done
    local fails=0
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || fails=$((fails+1))
    done

    local t1_ns=$(date +%s%N)
    read u1 s1 < <(read_proc_stat "$spid")
    local rss=$(read_proc_rss_kb "$spid")

    local elapsed_ms=$(( (t1_ns - t0_ns) / 1000000 ))
    local total=$(( CONCURRENT * REQUESTS ))
    local rps=0
    [[ $elapsed_ms -gt 0 ]] && rps=$(( total * 1000 / elapsed_ms ))

    local du=$(( u1 - u0 ))
    local ds=$(( s1 - s0 ))
    local user_ms=$(( du * 1000 / CLK_TCK ))
    local sys_ms=$(( ds * 1000 / CLK_TCK ))
    local cpu_pct=0
    [[ $elapsed_ms -gt 0 ]] && cpu_pct=$(( (user_ms + sys_ms) * 100 / elapsed_ms ))

    echo "$label,$SMP,$CONCURRENT,$REQUESTS,$total,$elapsed_ms,$rps,$fails,$cpu_pct,$user_ms,$sys_ms,$rss" >> "$CSV"
    ok "$label: $total reqs in ${elapsed_ms}ms => ${rps} rps | CPU ${cpu_pct}% (u=${user_ms}ms s=${sys_ms}ms) RSS=${rss}KB fails=$fails"

    # GSO 状态确认（来自 server 日志）
    grep -E "GSO disabled|UDP_GRO|UDP_SEGMENT" "$logfile" | head -5 || true

    # 收尾
    kill -TERM "$spid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
    sleep 1
}

echo "=== xquic Seastar eBPF: GSO on vs off ==="
echo "smp=$SMP concurrent=$CONCURRENT requests=$REQUESTS port=$PORT"
echo "results -> $CSV"
echo ""

run_one "gso-on"  ""
run_one "gso-off" "XQC_DISABLE_GSO=1"

echo ""
echo "=== Summary ==="
column -t -s, "$CSV"
echo ""
ok "Saved: $CSV"
