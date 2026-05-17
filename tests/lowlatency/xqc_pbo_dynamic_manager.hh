/**
 * Phase W2/W5 — choose 2 vs 3 PBO ring size (design §5).
 * Minimal policy: fixed dual/triple from CLI, or "auto" that bumps to 3 when
 * swap-to-swap period spikes (simple heuristic; tune after profiling).
 */

#pragma once

#include <algorithm>
#include <cstdint>

enum class XqcPboMode {
    Dual,
    Triple,
    Auto,
};

class XqcPboCountStrategy {
public:
    explicit XqcPboCountStrategy(XqcPboMode mode) : _mode(mode), _n(mode == XqcPboMode::Triple ? 3 : 2) {}

    /** Current GL PBO ring size (2 or 3). */
    int buffer_count() const { return _n; }

    /** Call once per presented frame with swap-to-swap period in microseconds. */
    void note_frame_period_us(int64_t period_us) {
        if (_mode != XqcPboMode::Auto) {
            return;
        }
        if (period_us < 0) {
            return;
        }
        /* ~30fps baseline 33.3ms; if we often exceed ~1.5x, prefer triple buffering. */
        constexpr int64_t kLooseUs = 50000;
        if (period_us > kLooseUs) {
            _over_budget++;
        } else {
            _over_budget = std::max(0, _over_budget - 1);
        }
        if (_over_budget >= 3) {
            _n = 3;
        } else if (_over_budget == 0) {
            _n = 2;
        }
    }

private:
    XqcPboMode _mode;
    int _n;
    int _over_budget = 0;
};
