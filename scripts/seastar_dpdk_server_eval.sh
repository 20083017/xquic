#!/bin/bash
# Seastar + DPDK server evaluation script (Phase 3)
#
# Goal:
# - Run server-side prototype with Seastar native stack (DPDK path)
# - Execute smoke test and benchmark matrix
# - Export reproducible metrics: throughput, latency (client-side elapsed), CPU usage, concurrency
#
# Usage:
#   bash scripts/seastar_dpdk_server_eval.sh smoke
#   bash scripts/seastar_dpdk_server_eval.sh bench
#   bash scripts/seastar_dpdk_server_eval.sh full
#
# Important env vars:
#   DPDK_CONFIG_FILE    shell-style config file, e.g. ./third_party/seastar/dpdk-custom.conf
#   SERVER_EXTRA_ARGS   extra Seastar args for DPDK (quoted string)
#   SERVER_SMP_LIST     smp list, e.g. "1 2 4"
#   CONN_LIST           concurrency list, e.g. "50 200 500"
#   TOTAL_REQS          requests per run, default 2000
#   BODY_SIZE           request body bytes, default 1024
#   SERVER_PORT         default 8443
#   SERVER_ADDR         default 127.0.0.1
#
# Example:
#   DPDK_CONFIG_FILE=./third_party/seastar/dpdk-custom.conf \
#   SERVER_EXTRA_ARGS="--dpdk-pmd --overprovisioned" \
#   SERVER_SMP_LIST="1 2 4" CONN_LIST="100 500 1000" \
#   bash scripts/seastar_dpdk_server_eval.sh full

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DPDK_CONFIG_FILE="${DPDK_CONFIG_FILE:-${PROJECT_DIR}/third_party/seastar/dpdk-custom.conf}"

load_config_file() {
    local config_file="$1"

    if [ ! -f "${config_file}" ]; then
        return 0
    fi

    log_info "loading config file: ${config_file}"
    set -a
    # shellcheck disable=SC1090
    . "${config_file}"
    set +a
}

load_config_file "${DPDK_CONFIG_FILE}"

SERVER_BIN="${PROJECT_DIR}/build_seastar/xquic_tests/xquic_server_seastar"
CLIENT_BIN="${PROJECT_DIR}/build/tests/test_client"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1}"
SERVER_PORT="${SERVER_PORT:-8443}"
CERT_FILE="${PROJECT_DIR}/server.crt"
KEY_FILE="${PROJECT_DIR}/server.key"

SERVER_SMP_LIST="${SERVER_SMP_LIST:-1 2 4}"
CONN_LIST="${CONN_LIST:-50 200 500}"
TOTAL_REQS="${TOTAL_REQS:-2000}"
BODY_SIZE="${BODY_SIZE:-1024}"
PARALLEL_PER_CONN="${PARALLEL_PER_CONN:-1}"

# DPDK path in Seastar typically uses native stack.
NETWORK_STACK="${NETWORK_STACK:-native}"
SERVER_EXTRA_ARGS="${SERVER_EXTRA_ARGS:-}"

RESULTS_DIR="${PROJECT_DIR}/bench_results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${RESULTS_DIR}/dpdk_phase3_${TIMESTAMP}"
CSV_FILE="${RUN_DIR}/results.csv"
SUMMARY_FILE="${RUN_DIR}/summary.txt"
ENV_FILE="${RUN_DIR}/environment.txt"

SERVER_PID=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

require_bin() {
    if [ ! -x "$1" ]; then
        log_fail "binary not found or not executable: $1"
        exit 1
    fi
}

collect_environment() {
    mkdir -p "${RUN_DIR}"
    {
        echo "date=$(date -Is)"
        echo "kernel=$(uname -r)"
        echo "hostname=$(hostname)"
        echo "cpu_model=$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)"
        echo "cpu_cores=$(nproc 2>/dev/null || echo unknown)"
        echo "server_addr=${SERVER_ADDR}"
        echo "server_port=${SERVER_PORT}"
        echo "network_stack=${NETWORK_STACK}"
        echo "server_smp_list=${SERVER_SMP_LIST}"
        echo "conn_list=${CONN_LIST}"
        echo "total_reqs=${TOTAL_REQS}"
        echo "body_size=${BODY_SIZE}"
        echo "parallel_per_conn=${PARALLEL_PER_CONN}"
        echo "server_extra_args=${SERVER_EXTRA_ARGS}"
        echo "dpdk_config_file=${DPDK_CONFIG_FILE}"
    } > "${ENV_FILE}"
}

stop_server() {
    if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    pkill -9 -f "xquic_server_seastar.*${SERVER_PORT}" 2>/dev/null || true
    SERVER_PID=""
}

cleanup() {
    stop_server
}
trap cleanup EXIT

start_server() {
    local smp="$1"
    local server_log="${RUN_DIR}/server_smp${smp}.log"

    stop_server
    mkdir -p "${RUN_DIR}"

    local extra_args=()
    if [ -n "${SERVER_EXTRA_ARGS}" ]; then
        # shellcheck disable=SC2206
        extra_args=( ${SERVER_EXTRA_ARGS} )
    fi

    log_info "starting seastar server smp=${smp}, stack=${NETWORK_STACK}"
    "${SERVER_BIN}" \
        --port "${SERVER_PORT}" \
        --cert "${CERT_FILE}" \
        --key "${KEY_FILE}" \
        --smp "${smp}" \
        --network-stack "${NETWORK_STACK}" \
        "${extra_args[@]}" \
        > "${server_log}" 2>&1 &

    SERVER_PID=$!

    # Readiness: process alive + quick client request succeeds.
    local tries=0
    while [ "${tries}" -lt 20 ]; do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            log_fail "server exited early (smp=${smp})"
            tail -n 60 "${server_log}" || true
            return 1
        fi

        if "${CLIENT_BIN}" \
            -a "${SERVER_ADDR}" -p "${SERVER_PORT}" \
            -n 1 -G -s 0 -l e \
            -o "${RUN_DIR}/clog_ready_smp${smp}" \
            > "${RUN_DIR}/ready_smp${smp}.log" 2>&1; then
            log_ok "server ready (pid=${SERVER_PID}, smp=${smp})"
            return 0
        fi

        tries=$((tries + 1))
        sleep 0.5
    done

    log_fail "server readiness timeout (smp=${smp})"
    tail -n 60 "${server_log}" || true
    return 1
}

capture_cpu_percent() {
    local pid="$1"

    if command -v pidstat >/dev/null 2>&1; then
        # %CPU from avg line, sampled for 3 seconds
        pidstat -u -p "${pid}" 1 3 2>/dev/null | awk '
            /^Average:/ && $2 ~ /^[0-9]+$/ { cpu=$8 }
            END { if (cpu == "") cpu="0"; print cpu }
        '
        return
    fi

    if command -v top >/dev/null 2>&1; then
        top -b -n 1 -p "${pid}" 2>/dev/null | awk 'NR>7 {print $9; exit}'
        return
    fi

    echo "0"
}

run_single_bench() {
    local smp="$1"
    local conns="$2"

    local client_log="${RUN_DIR}/client_smp${smp}_c${conns}.log"
    local start_ns end_ns elapsed_ms elapsed_s throughput_rps cpu_percent

    start_ns=$(date +%s%N)
    "${CLIENT_BIN}" \
        -a "${SERVER_ADDR}" \
        -p "${SERVER_PORT}" \
        -n "${TOTAL_REQS}" \
        -P "${PARALLEL_PER_CONN}" \
        -b "${conns}" \
        -B "${conns}" \
        -s "${BODY_SIZE}" \
        -c b \
        -l e \
        -o "${RUN_DIR}/clog_smp${smp}_c${conns}" \
        > "${client_log}" 2>&1 || true
    end_ns=$(date +%s%N)

    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    elapsed_s=$(awk -v ms="${elapsed_ms}" 'BEGIN { printf "%.3f", ms/1000.0 }')
    throughput_rps=$(awk -v req="${TOTAL_REQS}" -v ms="${elapsed_ms}" 'BEGIN { if (ms>0) printf "%.1f", (req*1000.0)/ms; else print "0" }')
    cpu_percent=$(capture_cpu_percent "${SERVER_PID}")

    # best-effort parsing from test_client output
    local completed failed p50 p95 p99
    completed=$(grep -oE '[0-9]+ completed' "${client_log}" | head -1 | awk '{print $1}' || echo "0")
    failed=$(grep -oE '[0-9]+ failed' "${client_log}" | head -1 | awk '{print $1}' || echo "0")
    p50=$(grep -oE 'p50=[0-9.]+(ms|us)?' "${client_log}" | head -1 | cut -d'=' -f2 || echo "NA")
    p95=$(grep -oE 'p95=[0-9.]+(ms|us)?' "${client_log}" | head -1 | cut -d'=' -f2 || echo "NA")
    p99=$(grep -oE 'p99=[0-9.]+(ms|us)?' "${client_log}" | head -1 | cut -d'=' -f2 || echo "NA")

    echo "${smp},${conns},${TOTAL_REQS},${PARALLEL_PER_CONN},${BODY_SIZE},${elapsed_s},${throughput_rps},${cpu_percent},${completed},${failed},${p50},${p95},${p99}" >> "${CSV_FILE}"

    printf "%-5s %-7s %-10s %-9s %-9s %-8s\n" \
        "${smp}" "${conns}" "${throughput_rps}" "${cpu_percent}" "${completed}" "${failed}"
}

run_smoke() {
    log_info "run smoke test on DPDK/native server"
    start_server 1
    if "${CLIENT_BIN}" \
        -a "${SERVER_ADDR}" -p "${SERVER_PORT}" \
        -n 5 -P 1 -s 512 -l d \
        -o "${RUN_DIR}/clog_smoke" \
        > "${RUN_DIR}/smoke.log" 2>&1; then
        log_ok "smoke test passed"
    else
        log_fail "smoke test failed"
        tail -n 50 "${RUN_DIR}/smoke.log" || true
        return 1
    fi
    stop_server
}

run_bench_matrix() {
    log_info "run benchmark matrix"
    echo "smp,concurrency,total_reqs,parallel_per_conn,body_size,elapsed_s,throughput_rps,cpu_percent,completed,failed,p50,p95,p99" > "${CSV_FILE}"

    printf "%-5s %-7s %-10s %-9s %-9s %-8s\n" "SMP" "CONN" "RPS" "CPU(%)" "DONE" "FAIL"
    printf "%-5s %-7s %-10s %-9s %-9s %-8s\n" "-----" "-------" "----------" "---------" "---------" "--------"

    for smp in ${SERVER_SMP_LIST}; do
        if ! start_server "${smp}"; then
            log_warn "skip smp=${smp} due to startup failure"
            continue
        fi

        for conns in ${CONN_LIST}; do
            run_single_bench "${smp}" "${conns}"
            sleep 1
        done

        stop_server
    done
}

write_summary() {
    {
        echo "Phase 3 DPDK server evaluation summary"
        echo "run_dir=${RUN_DIR}"
        echo "csv=${CSV_FILE}"
        echo "env=${ENV_FILE}"
        echo ""
        echo "Top throughput rows:"
        awk -F, 'NR==1 {next} {print $0}' "${CSV_FILE}" | sort -t, -k7,7nr | head -5
    } > "${SUMMARY_FILE}"

    log_ok "summary generated: ${SUMMARY_FILE}"
    log_ok "raw csv generated: ${CSV_FILE}"
}

show_help() {
    cat <<EOF
Usage: $0 <smoke|bench|full|help>

Commands:
  smoke   start DPDK/native server and run quick functional test
  bench   run benchmark matrix and export CSV
  full    smoke + bench + summary
  help    show this help

Env examples:
    DPDK_CONFIG_FILE=./third_party/seastar/dpdk-custom.conf
  SERVER_EXTRA_ARGS="--dpdk-pmd --overprovisioned"
  SERVER_SMP_LIST="1 2 4"
  CONN_LIST="100 500 1000"
  TOTAL_REQS=3000
  BODY_SIZE=4096

Config file format:
    SERVER_EXTRA_ARGS="--dpdk-pmd --overprovisioned"
    SERVER_SMP_LIST="1 2 4"
    CONN_LIST="100 500 1000"
EOF
}

main() {
    local cmd="${1:-full}"
    case "${cmd}" in
        smoke)
            require_bin "${SERVER_BIN}"
            require_bin "${CLIENT_BIN}"
            mkdir -p "${RUN_DIR}"
            collect_environment
            run_smoke
            ;;
        bench)
            require_bin "${SERVER_BIN}"
            require_bin "${CLIENT_BIN}"
            mkdir -p "${RUN_DIR}"
            collect_environment
            run_bench_matrix
            write_summary
            ;;
        full)
            require_bin "${SERVER_BIN}"
            require_bin "${CLIENT_BIN}"
            mkdir -p "${RUN_DIR}"
            collect_environment
            run_smoke
            run_bench_matrix
            write_summary
            ;;
        help|-h|--help)
            show_help
            ;;
        *)
            log_fail "unknown command: ${cmd}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
