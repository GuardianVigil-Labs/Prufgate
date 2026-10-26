"""scripts/build_pyz.py: the single-file zipapp attached to each release.

Downloads the hash-locked PyYAML sdist from PyPI once, unless
PRUFGATE_PYYAML_SDIST names a local copy. With no network and no local copy
the build tests are skipped; a hash mismatch or a build error still fails.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("build_pyz", ROOT / "scripts" / "build_pyz.py")
build_pyz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_pyz)


class BuildPyz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        version, _ = build_pyz.locked_pyyaml(ROOT / "requirements.txt")
        local = os.environ.get("PRUFGATE_PYYAML_SDIST")
        if local:
            cls.sdist = Path(local).read_bytes()
        else:
            try:
                cls.sdist = build_pyz.fetch_sdist(version)
            except OSError as exc:  # URLError, timeouts, DNS: no network
                cls.tmp.cleanup()
                raise unittest.SkipTest(
                    f"PyYAML {version} sdist could not be downloaded ({exc.__class__.__name__}: {exc}); "
                    "set PRUFGATE_PYYAML_SDIST to a local copy to run these tests offline"
                ) from exc
        cls.pyz = build_pyz.build(cls.dir / "a" / "prufgate.pyz", cls.sdist)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_pyz(self, *args):
        # -I: no user site, no PYTHONPATH, so PyYAML comes from the pyz.
        return subprocess.run([sys.executable, "-I", str(self.pyz), *args], cwd=self.dir,
                              capture_output=True, text=True, timeout=300)

    def test_version_runs_from_another_directory(self):
        r = self.run_pyz("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), f"prufgate {build_pyz_version()}")

    def test_check_uses_the_bundled_pure_python_yaml(self):
        ws = self.dir / "ws"
        (ws / ".prufgate").mkdir(parents=True)
        (ws / ".prufgate" / "config.yaml").write_text("version: [unclosed\n")
        r = self.run_pyz("check", str(ws))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)  # a bad config fails closed
        probe = subprocess.run([sys.executable, "-I", "-c",
                                "import sys; sys.path.insert(0, sys.argv[1]); import yaml; "
                                "print(yaml.__version__, yaml.__with_libyaml__, yaml.__file__)", str(self.pyz)],
                               capture_output=True, text=True)
        ver, libyaml, path = probe.stdout.split()
        self.assertEqual((ver, libyaml), (build_pyz.locked_pyyaml(ROOT / "requirements.txt")[0], "False"))
        self.assertTrue(path.startswith(str(self.pyz)), path)

    def test_two_builds_are_byte_identical(self):
        again = build_pyz.build(self.dir / "b" / "prufgate.pyz", self.sdist)
        self.assertEqual(hashlib.sha256(again.read_bytes()).hexdigest(),
                         hashlib.sha256(self.pyz.read_bytes()).hexdigest())

    def test_source_date_epoch_sets_every_timestamp(self):
        old = os.environ.get("SOURCE_DATE_EPOCH")
        os.environ["SOURCE_DATE_EPOCH"] = "1700000000"  # 2023-11-14T22:13:20Z
        try:
            out = build_pyz.build(self.dir / "c" / "prufgate.pyz", self.sdist)
        finally:
            if old is None:
                os.environ.pop("SOURCE_DATE_EPOCH")
            else:
                os.environ["SOURCE_DATE_EPOCH"] = old
        with zipfile.ZipFile(out) as zf:
            self.assertEqual({i.date_time for i in zf.infolist()}, {(2023, 11, 14, 22, 13, 20)})
        with zipfile.ZipFile(self.pyz) as zf:
            self.assertEqual({i.date_time for i in zf.infolist()}, {(1980, 1, 1, 0, 0, 0)})

    def test_contents_are_sorted_and_only_the_runtime(self):
        with zipfile.ZipFile(self.pyz) as zf:
            names = zf.namelist()
        self.assertEqual(names, sorted(names))
        self.assertIn("__main__.py", names)
        self.assertIn("prufgate/cli.py", names)
        self.assertIn("prufgate/anti_fabrication/packs/cti.py", names)
        self.assertIn("yaml/LICENSE", names)
        for name in names:
            self.assertFalse(name.startswith(("tests/", "docs/", "scripts/", "fuzz/", "runners/", ".")), name)
            self.assertNotIn("__pycache__", name)
            self.assertNotIn("hygiene", name)
            self.assertNotIn("private", name.lower())
            self.assertTrue(name.startswith(("prufgate/", "yaml/")) or name in {"__main__.py", "LICENSE", "NOTICE"}, name)
        self.assertTrue(self.pyz.read_bytes().startswith(b"#!/usr/bin/env python3\n"))

    def test_the_real_sdist_with_one_byte_added_is_refused(self):
        with self.assertRaises(build_pyz.BuildError):
            build_pyz.build(self.dir / "d" / "prufgate.pyz", self.sdist + b"\0")
        self.assertFalse((self.dir / "d" / "prufgate.pyz").exists())


def fake_sdist(version: str) -> bytes:
    """A tiny invented PyYAML sdist: the layout the build reads, nothing else."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("lib/yaml/__init__.py", b"__version__ = 'fake'\n"), ("LICENSE", b"fake\n")):
            info = tarfile.TarInfo(f"pyyaml-{version}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class SdistHashCheck(unittest.TestCase):
    """No network: a fake sdist and a requirements file of our own."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.version = build_pyz.locked_pyyaml(ROOT / "requirements.txt")[0]
        self.sdist = fake_sdist(self.version)

    def requirements(self, digest: str) -> Path:
        path = self.dir / "requirements.txt"
        path.write_text(f"pyyaml=={self.version} \\\n    --hash=sha256:{digest}\n")
        return path

    def test_a_fake_sdist_is_refused_by_the_locked_hashes(self):
        out = self.dir / "a" / "prufgate.pyz"
        with self.assertRaisesRegex(build_pyz.BuildError, "is not in requirements.txt"):
            build_pyz.build(out, self.sdist)
        self.assertFalse(out.exists())

    def test_the_same_sdist_builds_when_its_hash_is_locked(self):
        # Control: the refusal above is the hash check, not a malformed sdist.
        out = build_pyz.build(self.dir / "b" / "prufgate.pyz", self.sdist,
                              self.requirements(hashlib.sha256(self.sdist).hexdigest()))
        with zipfile.ZipFile(out) as zf:
            self.assertEqual(zf.read("yaml/__init__.py"), b"__version__ = 'fake'\n")

    def test_a_wrong_locked_hash_is_refused(self):
        out = self.dir / "c" / "prufgate.pyz"
        with self.assertRaises(build_pyz.BuildError):
            build_pyz.build(out, self.sdist, self.requirements("0" * 64))
        self.assertFalse(out.exists())


def build_pyz_version() -> str:
    import re
    return re.search(r'__version__ = "([^"]+)"', (ROOT / "prufgate/__init__.py").read_text()).group(1)


class ReleaseShipsThePyz(unittest.TestCase):
    def setUp(self):
        self.jobs = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))["jobs"]

    def test_build_job_builds_and_uploads_it(self):
        steps = self.jobs["build"]["steps"]
        self.assertTrue(any("scripts/build_pyz.py" in st.get("run", "") for st in steps))
        self.assertTrue(any(st.get("with", {}).get("name") == "pyz" for st in steps if "upload-artifact" in st.get("uses", "")))

    def test_release_attests_sums_and_attaches_it(self):
        steps = self.jobs["release"]["steps"]
        self.assertTrue(any(st.get("with", {}).get("name") == "pyz" and st["with"].get("path") == "dist/"
                            for st in steps if "download-artifact" in st.get("uses", "")))
        attest = [st for st in steps if st.get("uses", "").startswith("actions/attest@")]
        self.assertTrue(any(st["with"].get("subject-path") == "dist/*" for st in attest))
        for st in attest:
            self.assertRegex(st["uses"], r"@[0-9a-f]{40}$")
        runs = "\n".join(st.get("run", "") for st in steps)
        self.assertIn("sha256sum -- *", runs)          # dist/* holds the pyz
        self.assertIn("dist/*.pyz", runs)              # its .intoto.jsonl bundle
        self.assertIn("gh release create", runs)

