"""Fuzz .prufgate/config.yaml loading: any file is either a valid config or a ConfigError."""

import os
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    from prufgate.config import ConfigError, PrufGateConfig

_DIR = tempfile.mkdtemp()
_PATH = os.path.join(_DIR, "config.yaml")


def TestOneInput(data: bytes) -> None:
    with open(_PATH, "wb") as f:
        f.write(data)
    try:
        PrufGateConfig.load(_DIR, explicit_path=_PATH).to_detector_settings()
    except ConfigError:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
