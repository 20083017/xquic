/**
 * @file xqc_thread_affinity.hh
 * @brief Pin decode / display / bridge threads for 4K pipeline (see seastar_runtime doc §14.5).
 *
 * Seastar reactor affinity: pass `--cpuset N` (or a comma list) on the Seastar binary.
 * Off-reactor threads: `XQC_DECODE_CPU`, `XQC_DISPLAY_CPU`, or `XQC_PIN_AFFINITY=1` defaults.
 */

#pragma once

#include <cstdint>

struct XqcCpuPinResult {
    bool ok = false;
    int cpu = -1;
};

/** Parse `XQC_DECODE_CPU` / `XQC_DISPLAY_CPU`; returns -1 when unset or invalid. */
int xqc_cpu_from_env(const char* env_name);

/** True when `XQC_PIN_AFFINITY` is 1, on, or auto (default off). */
bool xqc_pin_affinity_enabled();

/**
 * Resolve decode and display CPU indices.
 * Explicit env vars win; when `XQC_PIN_AFFINITY` is on, defaults decode=1 display=2.
 */
void xqc_resolve_pipeline_cpus(int& decode_cpu, int& display_cpu);

/** Pin the calling thread; no-op when cpu < 0. */
XqcCpuPinResult xqc_pin_current_thread(int cpu, const char* role);

/** Log layout after Seastar reactor is up (shard id + resolved off-reactor CPUs). */
void xqc_log_pipeline_affinity_layout(unsigned reactor_shard, int reactor_cpu_hint);
