"""PrufGate Diff-Scoped Agent Tampering & Guardrail Bypass Detector (Engine 3)."""

from prufgate.diff_guard.tamper_detector import (
    DiffHunk,
    Finding,
    parse_unified_diff,
    run_self_check,
    scan_diff_for_tampering,
)

__all__ = [
    "DiffHunk",
    "Finding",
    "parse_unified_diff",
    "run_self_check",
    "scan_diff_for_tampering",
]
