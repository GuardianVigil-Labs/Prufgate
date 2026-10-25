"""Fuzz the unified-diff parsers: an attacker controls the diff of the pull request being gated."""

import sys
import tempfile

import atheris

with atheris.instrument_imports():
    from prufgate.anti_reward_hacking.test_integrity import scan_diff_for_reward_hacking
    from prufgate.diff_guard.tamper_detector import parse_unified_diff
    from prufgate.review.reviewer import parse_diff_hunks

_ROOT = tempfile.mkdtemp()


def TestOneInput(data: bytes) -> None:
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(len(data))
    parse_unified_diff(text)
    parse_diff_hunks(text)
    scan_diff_for_reward_hacking(text, repo_root=_ROOT)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
