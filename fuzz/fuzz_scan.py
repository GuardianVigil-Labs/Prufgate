"""Fuzz the source and test scanners with arbitrary file contents."""

import sys

import atheris

with atheris.instrument_imports():
    from prufgate.anti_fabrication import detector
    from prufgate.anti_reward_hacking.test_integrity import scan_test_file

_SUFFIXES = [".py", ".js", ".ts", ".tsx", ".go", ".java", ".rb", ".rs"]
detector.apply_settings({})


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    suffix = fdp.PickValueInList(_SUFFIXES)
    text = fdp.ConsumeUnicodeNoSurrogates(len(data))
    detector.scan_text("src/module" + suffix, suffix, text)
    scan_test_file("tests/test_module" + suffix, text)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
