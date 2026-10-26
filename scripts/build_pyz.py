#!/usr/bin/env python3
"""Build prufgate.pyz: a single-file zipapp that needs only Python 3.9+.

    python3 scripts/build_pyz.py [--out build/prufgate.pyz] [--pyyaml-sdist PATH]

It holds what the wheel installs: the `prufgate` package (Python files only;
the wheel ships no other package data), LICENSE and NOTICE, plus the pure-Python
PyYAML from its sdist. PyYAML runs without its C extension: `yaml/__init__.py`
falls back to the pure loaders when `yaml._yaml` cannot be imported.

The PyYAML version and hashes come from requirements.txt (hash-locked). The
sdist is downloaded from PyPI (network access needed) unless --pyyaml-sdist or
PRUFGATE_PYYAML_SDIST names a local copy; either way its SHA-256 must be one of
the locked hashes, or the build stops.

Reproducible: entries are sorted, every timestamp is SOURCE_DATE_EPOCH (default
1980-01-01, the earliest a zip can store), modes are fixed. The same inputs and
zlib give a byte-identical file.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHEBANG = b"#!/usr/bin/env python3\n"
MAIN = b"import sys\n\nfrom prufgate.cli import main\n\nsys.exit(main())\n"
ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z
SDIST_URL = "https://files.pythonhosted.org/packages/source/p/pyyaml/pyyaml-{v}.tar.gz"


class BuildError(Exception):
    pass


def locked_pyyaml(requirements: Path) -> tuple[str, set[str]]:
    """(version, allowed sha256 hashes) of PyYAML in a hash-locked requirements file."""
    m = re.search(r"^pyyaml==(\S+)((?:\s*\\\n\s+--hash=sha256:[0-9a-f]{64})+)", requirements.read_text(), re.M | re.I)
    if not m:
        raise BuildError(f"{requirements.name}: no hash-locked pyyaml== entry")
    return m.group(1), set(re.findall(r"sha256:([0-9a-f]{64})", m.group(2)))


def fetch_sdist(version: str) -> bytes:
    with urllib.request.urlopen(SDIST_URL.format(v=version), timeout=60) as r:  # noqa: S310 -- fixed https URL on PyPI
        return r.read()


def pyyaml_files(sdist: bytes, version: str, hashes: set[str]) -> dict[str, bytes]:
    digest = hashlib.sha256(sdist).hexdigest()
    if digest not in hashes:
        raise BuildError(f"PyYAML {version} sdist sha256 {digest} is not in requirements.txt")
    prefix = f"pyyaml-{version}/"
    out: dict[str, bytes] = {}
    # Read members in memory: nothing from the archive is written to disk.
    with tarfile.open(fileobj=io.BytesIO(sdist), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            if not member.isfile() or not name.startswith(prefix):
                continue
            rel = name[len(prefix):]
            # lib/yaml/*.py -> yaml/*.py; its LICENSE -> yaml/LICENSE
            if re.fullmatch(r"lib/yaml/[a-z_]+\.py|LICENSE", rel):
                out["yaml/" + rel.rsplit("/", 1)[-1]] = tar.extractfile(member).read()
    if "yaml/__init__.py" not in out or "yaml/LICENSE" not in out:
        raise BuildError("PyYAML sdist has no lib/yaml package or LICENSE")
    return out


def prufgate_files() -> dict[str, bytes]:
    out = {
        p.relative_to(ROOT).as_posix(): p.read_bytes()
        for p in (ROOT / "prufgate").rglob("*.py")
        if "__pycache__" not in p.parts
    }
    for name in ("LICENSE", "NOTICE"):
        out[name] = (ROOT / name).read_bytes()
    out["__main__.py"] = MAIN
    return out


def build(out: Path, sdist: bytes | None = None, requirements: Path = ROOT / "requirements.txt") -> Path:
    version, hashes = locked_pyyaml(requirements)
    files = prufgate_files()
    files.update(pyyaml_files(sdist if sdist is not None else fetch_sdist(version), version, hashes))
    epoch = max(int(os.environ.get("SOURCE_DATE_EPOCH") or ZIP_EPOCH), ZIP_EPOCH)
    stamp = time.gmtime(epoch)[:6]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3  # Unix, whatever the build host
            zf.writestr(info, files[name], compresslevel=9)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(SHEBANG + buf.getvalue())
    out.chmod(0o755)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ROOT / "build" / "prufgate.pyz")
    ap.add_argument("--pyyaml-sdist", type=Path, default=os.environ.get("PRUFGATE_PYYAML_SDIST") or None,
                    help="local PyYAML sdist (still hash-checked); default: download from PyPI")
    args = ap.parse_args(argv)
    try:
        out = build(args.out, args.pyyaml_sdist.read_bytes() if args.pyyaml_sdist else None)
    except (BuildError, OSError) as exc:
        print(f"build_pyz: {exc}", file=sys.stderr)
        return 2
    print(f"{hashlib.sha256(out.read_bytes()).hexdigest()}  {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
