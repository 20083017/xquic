#!/usr/bin/env bash
# run_xquic_server.sh — Auto-detect the best xquic server stack and launch it.
#
# Selection priority (when --mode=auto):
#   1. DPDK + Seastar  (requires hugepages > 0 AND DPDK binary built)
#   2. eBPF + Seastar  (requires Linux >= 4.19 AND ebpf binary built)
#   3. POSIX baseline  (always works as long as demo_server is built)
#
# Usage:
#   ./scripts/run_xquic_server.sh [--mode auto|posix|ebpf|dpdk] [--port N]
#                                 [--smp N] [--dry-run] [-- extra args ...]
#
# Anything after `--` is appended verbatim to the chosen server's command line.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
MODE="auto"
PORT="8443"
SMP=""
DRY_RUN=0
EXTRA_ARGS=()

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

POSIX_BIN="build/demo/demo_server"
EBPF_BIN="build_seastar/xquic_tests/xquic_server_seastar_ebpf"
DPDK_BIN="build_seastar_dpdk/xquic_tests/xquic_server_seastar"

CERT_FILE="server.crt"
KEY_FILE="server.key"
LOG_DIR="logs"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '[run-xquic] %s\n' "$*"; }
warn() { printf '[run-xquic][WARN] %s\n' "$*" >&2; }
die()  { printf '[run-xquic][ERR ] %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,15p' "$0"
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while (($#)); do
    case "$1" in
        --mode)    MODE="${2:?}"; shift 2 ;;
        --mode=*)  MODE="${1#*=}"; shift ;;
        --port)    PORT="${2:?}"; shift 2 ;;
        --port=*)  PORT="${1#*=}"; shift ;;
        --smp)     SMP="${2:?}"; shift 2 ;;
        --smp=*)   SMP="${1#*=}"; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        --)        shift; EXTRA_ARGS=("$@"); break ;;
        *)         die "Unknown argument: $1 (use --help)" ;;
    esac
done

case "$MODE" in
    auto|posix|ebpf|dpdk) ;;
    *) die "Invalid --mode: $MODE (auto|posix|ebpf|dpdk)" ;;
esac

# ---------------------------------------------------------------------------
# Capability probes
# ---------------------------------------------------------------------------
have_posix() { [[ -x "$POSIX_BIN" ]]; }
have_ebpf_bin() { [[ -x "$EBPF_BIN" ]]; }
have_dpdk_bin() { [[ -x "$DPDK_BIN" ]]; }

have_certs() { [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; }

# Linux >= 4.19 (cBPF reuseport + decent eBPF support)
kernel_ge_4_19() {
    local kver major minor
    kver="$(uname -r | cut -d- -f1)"
    major="${kver%%.*}"
    minor="${kver#*.}"; minor="${minor%%.*}"
    [[ "$major" -gt 4 ]] || { [[ "$major" -eq 4 && "$minor" -ge 19 ]]; }
}

ebpf_supported() {
    kernel_ge_4_19 || return 1
    # Best-effort kernel config probe (non-fatal if unreadable)
    if [[ -r "/boot/config-$(uname -r)" ]]; then
        grep -q '^CONFIG_BPF=y' "/boot/config-$(uname -r)" || return 1
    fi
    return 0
}

hugepages_total() {
    awk '/^HugePages_Total/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0
}

dpdk_ready() {
    have_dpdk_bin || return 1
    local hp
    hp="$(hugepages_total)"
    [[ "${hp:-0}" -gt 0 ]] || return 1
    # Linked against DPDK? (DPDK is statically linked, so check full symbol table)
    nm "$DPDK_BIN" 2>/dev/null | grep -q ' rte_eal_init' || return 1
    return 0
}

# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------
detect_mode() {
    if dpdk_ready;       then echo dpdk;  return; fi
    if have_ebpf_bin && ebpf_supported; then echo ebpf;  return; fi
    if have_posix;       then echo posix; return; fi
    echo none
}

print_env_report() {
    log "Environment summary:"
    log "  posix bin : $([[ -x $POSIX_BIN ]] && echo OK || echo MISSING) ($POSIX_BIN)"
    log "  ebpf  bin : $([[ -x $EBPF_BIN  ]] && echo OK || echo MISSING) ($EBPF_BIN)"
    log "  dpdk  bin : $([[ -x $DPDK_BIN  ]] && echo OK || echo MISSING) ($DPDK_BIN)"
    log "  certs     : $(have_certs && echo OK || echo MISSING) ($CERT_FILE / $KEY_FILE)"
    log "  kernel    : $(uname -r) ($(kernel_ge_4_19 && echo '>=4.19' || echo '<4.19'))"
    log "  ebpf cfg  : $(ebpf_supported && echo OK || echo 'not detected')"
    log "  hugepages : $(hugepages_total) page(s)"
    log "  dpdk ready: $(dpdk_ready && echo OK || echo NO)"
}

# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------
mkdir -p "$LOG_DIR"

build_posix_cmd() {
    have_posix || die "POSIX server not built: $POSIX_BIN (run cmake build first)"
    have_certs || warn "server.crt/server.key not found in $REPO_ROOT (demo_server expects them in cwd)"
    CMD=("$POSIX_BIN" -p "$PORT" -L "$LOG_DIR" -l i)
    CMD+=("${EXTRA_ARGS[@]}")
}

build_ebpf_cmd() {
    have_ebpf_bin || die "eBPF server not built: $EBPF_BIN"
    have_certs    || die "Missing $CERT_FILE / $KEY_FILE"
    CMD=("$EBPF_BIN" --port "$PORT" --cert "$CERT_FILE" --key "$KEY_FILE")
    [[ -n "$SMP" ]] && CMD+=(--smp "$SMP")
    CMD+=("${EXTRA_ARGS[@]}")
    if ! ebpf_supported; then
        warn "kernel/eBPF probe failed; binary will fall back to POSIX shard-0 internally"
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        warn "not running as root; eBPF attach may require CAP_NET_ADMIN/CAP_BPF — fallback will engage on failure"
    fi
}

build_dpdk_cmd() {
    have_dpdk_bin || die "DPDK server not built: $DPDK_BIN"
    have_certs    || die "Missing $CERT_FILE / $KEY_FILE"
    if [[ "$(hugepages_total)" -le 0 ]]; then
        die "DPDK requires hugepages: sudo sysctl -w vm.nr_hugepages=256"
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        warn "DPDK PMD typically requires root; consider re-running with sudo"
    fi
    CMD=("$DPDK_BIN"
         --port "$PORT"
         --cert "$CERT_FILE"
         --key "$KEY_FILE"
         --dpdk-pmd
         --dpdk-port-index 0
         --network-stack native)
    [[ -n "$SMP" ]] && CMD+=(--smp "$SMP")
    CMD+=("${EXTRA_ARGS[@]}")
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
print_env_report

if [[ "$MODE" == "auto" ]]; then
    MODE="$(detect_mode)"
    [[ "$MODE" == "none" ]] && die "no usable server binary found; build with cmake first"
    log "auto-selected mode: $MODE"
else
    log "mode (forced): $MODE"
fi

case "$MODE" in
    posix) build_posix_cmd ;;
    ebpf)  build_ebpf_cmd  ;;
    dpdk)  build_dpdk_cmd  ;;
    *)     die "unreachable mode: $MODE" ;;
esac

log "launching: ${CMD[*]}"
if (( DRY_RUN )); then
    log "(dry-run; not executing)"
    exit 0
fi
exec "${CMD[@]}"
