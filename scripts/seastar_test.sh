#!/bin/bash
# Seastar XQUIC Server — 功能测试 & 压测脚本
#
# 用法:
#   ./scripts/seastar_test.sh [test|bench|stress] [options]
#
# 子命令:
#   test   — 基本功能测试（单连接、多连接、并发请求）
#   bench  — 性能压测（可配置连接速率和总请求数）
#   stress — 极限压力测试（高并发、长时间）
#
# 依赖:
#   - build_seastar/xquic_tests/xquic_server_seastar  (Seastar 服务器)
#   - build/tests/test_client                          (xquic 测试客户端)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# === 默认配置 ===
SERVER_BIN="${PROJECT_DIR}/build_seastar/xquic_tests/xquic_server_seastar"
CLIENT_BIN="${PROJECT_DIR}/build/tests/test_client"
SERVER_ADDR="127.0.0.1"
SERVER_PORT=8443
CERT_FILE="${PROJECT_DIR}/server.crt"
KEY_FILE="${PROJECT_DIR}/server.key"
LOG_DIR="${PROJECT_DIR}/test_logs"
SERVER_PID=""

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# === 服务器管理 ===
start_server() {
    local log_level="${1:-info}"
    mkdir -p "${LOG_DIR}"

    # 清理残留进程
    pkill -9 -f xquic_server_seastar 2>/dev/null || true
    sleep 1

    log_info "启动 Seastar XQUIC 服务器 (port=${SERVER_PORT})..."
    "${SERVER_BIN}" \
        --port "${SERVER_PORT}" \
        --cert "${CERT_FILE}" \
        --key "${KEY_FILE}" \
        --smp 1 \
        --network-stack posix \
        > "${LOG_DIR}/server_stdout.log" 2> "${LOG_DIR}/server_stderr.log" &
    SERVER_PID=$!

    # 等待服务器就绪
    local retries=0
    while ! ss -ulnp 2>/dev/null | grep -q ":${SERVER_PORT}" ; do
        sleep 0.5
        retries=$((retries + 1))
        if [ $retries -gt 20 ]; then
            log_fail "服务器启动超时"
            cat "${LOG_DIR}/server_stderr.log" | tail -20
            exit 1
        fi
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            log_fail "服务器进程退出"
            cat "${LOG_DIR}/server_stderr.log" | tail -20
            exit 1
        fi
    done
    log_ok "服务器已启动 (PID=${SERVER_PID})"
}

stop_server() {
    if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        log_info "停止服务器 (PID=${SERVER_PID})..."
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    pkill -9 -f xquic_server_seastar 2>/dev/null || true
    SERVER_PID=""
}

cleanup() {
    stop_server
}
trap cleanup EXIT

# === 运行单个客户端测试 ===
# run_client <test_name> <extra_args...>
run_client() {
    local test_name="$1"
    shift
    local client_log="${LOG_DIR}/client_${test_name}.log"

    log_info "运行测试: ${test_name}"
    local start_time
    start_time=$(date +%s%N)

    if "${CLIENT_BIN}" \
        -a "${SERVER_ADDR}" \
        -p "${SERVER_PORT}" \
        -l d \
        -o "${LOG_DIR}/clog_${test_name}" \
        "$@" \
        > "${client_log}" 2>&1; then
        local end_time
        end_time=$(date +%s%N)
        local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
        log_ok "${test_name}: 成功 (${elapsed_ms}ms)"
        return 0
    else
        local rc=$?
        log_fail "${test_name}: 失败 (exit_code=${rc})"
        tail -10 "${client_log}" 2>/dev/null || true
        return 1
    fi
}

# === 功能测试 ===
run_functional_tests() {
    log_info "====== 功能测试 ======"
    local passed=0
    local failed=0
    local total=0

    start_server

    # 测试 1: 单请求 H3 GET
    total=$((total + 1))
    if run_client "h3_single_get" -n 1 -G -s 0; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # 测试 2: 单请求 H3 POST (1KB body)
    total=$((total + 1))
    if run_client "h3_single_post_1k" -n 1 -s 1024; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # 测试 3: 多请求串行 (5个请求)
    total=$((total + 1))
    if run_client "h3_serial_5req" -n 5 -s 512; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # 测试 4: 并行请求 (同一连接上 3 个并行流)
    total=$((total + 1))
    if run_client "h3_parallel_3stream" -n 3 -P 3 -s 256; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # 测试 5: 大 body (64KB)
    total=$((total + 1))
    if run_client "h3_large_body_64k" -n 1 -s 65536; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    # 测试 6: 多连接并发 (3个独立客户端进程)
    total=$((total + 1))
    log_info "运行测试: multi_conn_3_parallel"
    local pids=()
    local multi_ok=true
    for i in 1 2 3; do
        "${CLIENT_BIN}" \
            -a "${SERVER_ADDR}" -p "${SERVER_PORT}" \
            -n 2 -s 512 -l d \
            -o "${LOG_DIR}/clog_multi_${i}" \
            > "${LOG_DIR}/client_multi_${i}.log" 2>&1 &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        if ! wait "${pid}"; then
            multi_ok=false
        fi
    done
    if $multi_ok; then
        log_ok "multi_conn_3_parallel: 成功"
        passed=$((passed + 1))
    else
        log_fail "multi_conn_3_parallel: 失败"
        failed=$((failed + 1))
    fi

    # 测试 7: Transport 层协议 (非 H3)
    total=$((total + 1))
    if run_client "transport_single" -n 1 -T 1 -s 256; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi

    stop_server

    echo ""
    log_info "====== 功能测试结果 ======"
    echo -e "  总计: ${total}  ${GREEN}通过: ${passed}${NC}  ${RED}失败: ${failed}${NC}"
    echo ""

    return $failed
}

# === 性能压测 ===
run_benchmark() {
    local conn_rate="${1:-50}"       # 每秒新建连接数
    local max_conns="${2:-200}"      # 最大并发连接数
    local total_reqs="${3:-1000}"    # 总请求数
    local parallel="${4:-1}"         # 每连接并行请求数
    local body_size="${5:-1024}"     # 请求 body 大小

    log_info "====== 性能压测 ======"
    log_info "参数: conn_rate=${conn_rate}/s  max_conns=${max_conns}  total_reqs=${total_reqs}  parallel=${parallel}  body=${body_size}B"

    start_server

    local client_log="${LOG_DIR}/client_bench.log"
    local start_time
    start_time=$(date +%s%N)

    "${CLIENT_BIN}" \
        -a "${SERVER_ADDR}" \
        -p "${SERVER_PORT}" \
        -n "${total_reqs}" \
        -P "${parallel}" \
        -b "${conn_rate}" \
        -B "${max_conns}" \
        -s "${body_size}" \
        -c b \
        -l e \
        -o "${LOG_DIR}/clog_bench" \
        > "${client_log}" 2>&1 || true

    local end_time
    end_time=$(date +%s%N)
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local elapsed_s=$(echo "scale=2; ${elapsed_ms} / 1000" | bc)
    local rps="N/A"
    if [ "${elapsed_ms}" -gt 0 ]; then
        rps=$(echo "scale=1; ${total_reqs} * 1000 / ${elapsed_ms}" | bc)
    fi

    echo ""
    log_info "====== 压测结果 ======"
    echo "  总耗时:     ${elapsed_s}s"
    echo "  总请求数:   ${total_reqs}"
    echo "  吞吐量:     ${rps} req/s"
    echo "  连接速率:   ${conn_rate}/s"
    echo "  最大并发:   ${max_conns}"
    echo "  Body 大小:  ${body_size}B"
    echo ""

    # 提取服务器端统计
    if [ -f "${LOG_DIR}/server_stderr.log" ]; then
        local accept_count
        accept_count=$(grep -c "server_accept called" "${LOG_DIR}/server_stdout.log" 2>/dev/null || echo 0)
        local conn_close_count
        conn_close_count=$(grep -c "conn_close_notify\|h3_conn_close_notify" "${LOG_DIR}/server_stdout.log" 2>/dev/null || echo 0)
        echo "  服务器统计:"
        echo "    accept 次数:  ${accept_count}"
        echo "    关闭连接数:   ${conn_close_count}"
    fi
    echo ""

    stop_server
}

# === 极限压力测试 ===
run_stress_test() {
    local duration="${1:-30}"  # 秒
    local conn_rate="${2:-100}"
    local max_conns="${3:-500}"

    log_info "====== 极限压力测试 ======"
    log_info "参数: duration=${duration}s  conn_rate=${conn_rate}/s  max_conns=${max_conns}"

    start_server

    local total_reqs=$((conn_rate * duration))
    local client_log="${LOG_DIR}/client_stress.log"
    local start_time
    start_time=$(date +%s%N)

    # 多进程并发压力
    local num_procs=4
    local reqs_per_proc=$((total_reqs / num_procs))
    local pids=()

    for i in $(seq 1 "${num_procs}"); do
        "${CLIENT_BIN}" \
            -a "${SERVER_ADDR}" \
            -p "${SERVER_PORT}" \
            -n "${reqs_per_proc}" \
            -P 5 \
            -b "${conn_rate}" \
            -B "${max_conns}" \
            -s 512 \
            -c b \
            -l e \
            -F "${duration}" \
            -o "${LOG_DIR}/clog_stress_${i}" \
            > "${LOG_DIR}/client_stress_${i}.log" 2>&1 &
        pids+=($!)
    done

    log_info "已启动 ${num_procs} 个客户端进程: ${pids[*]}"

    # 监控服务器状态
    local monitor_interval=5
    local elapsed=0
    while [ $elapsed -lt "${duration}" ]; do
        sleep "${monitor_interval}"
        elapsed=$((elapsed + monitor_interval))

        # 检查服务器是否存活
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            log_fail "服务器在 ${elapsed}s 时崩溃!"
            break
        fi

        local active_clients=0
        for pid in "${pids[@]}"; do
            if kill -0 "${pid}" 2>/dev/null; then
                active_clients=$((active_clients + 1))
            fi
        done
        log_info "[${elapsed}s/${duration}s] 服务器存活, 活跃客户端: ${active_clients}/${num_procs}"
    done

    # 等待所有客户端完成
    local stress_ok=true
    for pid in "${pids[@]}"; do
        wait "${pid}" 2>/dev/null || stress_ok=false
    done

    local end_time
    end_time=$(date +%s%N)
    local elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local elapsed_s=$(echo "scale=2; ${elapsed_ms} / 1000" | bc)

    echo ""
    log_info "====== 压力测试结果 ======"
    echo "  实际耗时:     ${elapsed_s}s"
    echo "  目标请求数:   ${total_reqs} (${num_procs} 进程 × ${reqs_per_proc})"
    echo "  客户端进程:   ${num_procs}"
    if $stress_ok; then
        log_ok "压力测试通过 — 服务器保持稳定"
    else
        log_warn "部分客户端异常退出 (可能因超时)"
    fi

    # 服务器统计
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
        log_ok "服务器仍在运行 (PID=${SERVER_PID})"
    else
        log_fail "服务器已退出"
    fi

    local accept_count
    accept_count=$(grep -c "server_accept called" "${LOG_DIR}/server_stdout.log" 2>/dev/null || echo 0)
    echo "  总 accept 次数: ${accept_count}"
    echo ""

    stop_server
}

# === 帮助 ===
show_help() {
    cat <<EOF
用法: $0 <command> [options]

命令:
  test                             基本功能测试
  bench [rate] [max] [reqs] [par] [body]
                                   性能压测
                                   rate:  每秒连接数 (默认 50)
                                   max:   最大并发连接 (默认 200)
                                   reqs:  总请求数 (默认 1000)
                                   par:   每连接并行请求数 (默认 1)
                                   body:  body 大小字节 (默认 1024)
  stress [duration] [rate] [max]   极限压力测试
                                   duration: 持续秒数 (默认 30)
                                   rate:     每秒连接数 (默认 100)
                                   max:      最大并发连接 (默认 500)
  help                             显示此帮助

示例:
  $0 test                          运行功能测试
  $0 bench 100 500 5000            100/s 速率, 最大500连接, 5000请求
  $0 bench 20 50 100 3 4096        低速率, 3并行流, 4KB body
  $0 stress 60 200 1000            60秒极限压测

环境变量:
  SERVER_PORT    服务器端口 (默认 8443)
  SERVER_ADDR    服务器地址 (默认 127.0.0.1)
EOF
}

# === 主入口 ===
main() {
    # 检查二进制文件
    if [ ! -x "${SERVER_BIN}" ]; then
        log_fail "服务器二进制不存在: ${SERVER_BIN}"
        log_info "请先构建: cd build_seastar && cmake --build . --target xquic_server_seastar"
        exit 1
    fi
    if [ ! -x "${CLIENT_BIN}" ]; then
        log_fail "客户端二进制不存在: ${CLIENT_BIN}"
        log_info "请先构建: cd build && make test_client"
        exit 1
    fi

    # 覆盖端口
    SERVER_PORT="${SERVER_PORT:-8443}"
    SERVER_ADDR="${SERVER_ADDR:-127.0.0.1}"

    mkdir -p "${LOG_DIR}"

    local cmd="${1:-help}"
    shift || true

    case "${cmd}" in
        test)
            run_functional_tests
            ;;
        bench)
            run_benchmark "$@"
            ;;
        stress)
            run_stress_test "$@"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_fail "未知命令: ${cmd}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
