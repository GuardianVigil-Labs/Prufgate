"""PrufGate Anti-Reward-Hacking & Test Integrity Engine."""

from prufgate.anti_reward_hacking.test_integrity import (
    Finding,
    is_test_file,
    run_self_check,
    scan_diff_for_reward_hacking,
    scan_test_file,
)

__all__ = [
    "Finding",
    "is_test_file",
    "run_self_check",
    "scan_diff_for_reward_hacking",
    "scan_test_file",
]
