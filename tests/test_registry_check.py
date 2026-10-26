"""Issue #41: registry check for dependencies added in a diff. No test touches the network:
every lookup goes through a fake fetcher."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from prufgate.config import ConfigError, PrufGateConfig
from prufgate.contract_guard import main, registry_check, scan_contract_guard
from prufgate.contract_guard.registry_check import (
    RegistryError,
    check_new_dependencies,
    registry_url,
    typosquat_of,
)


def git(ws: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(ws), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   check=True, capture_output=True)


NOW = 1_800_000_000.0
DAY = 86400


def iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class FakeRegistry:
    """URL -> (status, body). Unknown URLs answer 404; `calls` records each request."""

    def __init__(self, answers: dict[str, tuple[int, object]]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, bytes | None]:
        self.calls.append(url)
        assert "User-Agent" in headers and "Authorization" not in headers
        status, body = self.answers.get(url, (404, b""))
        if isinstance(body, Exception):
            raise body
        return status, body if isinstance(body, bytes) else json.dumps(body).encode()


def npm_doc(created: float) -> dict:
    return {"versions": {"1.0.0": {}}, "time": {"created": iso(created)}}


OLD = NOW - 3000 * DAY


def repo(base: dict[str, str], head: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    ws = Path(tmp.name)
    git(ws, "init", "-q", "-b", "main")
    for name, text in base.items():
        (ws / name).write_text(text, encoding="utf-8")
    (ws / "README.md").write_text("x\n", encoding="utf-8")
    git(ws, "add", "-A")
    git(ws, "commit", "-qm", "base")
    for name, text in head.items():
        (ws / name).write_text(text, encoding="utf-8")
    return tmp


def pkg(**deps: str) -> str:
    return json.dumps({"name": "demo-app", "dependencies": deps})


class UrlBuilding(unittest.TestCase):
    def test_each_registry(self) -> None:
        self.assertEqual(registry_url("npm", "left-pad"), "https://registry.npmjs.org/left-pad")
        self.assertEqual(registry_url("npm", "@acme/widget"), "https://registry.npmjs.org/@acme%2Fwidget")
        self.assertEqual(registry_url("pypi", "Python_Dateutil"), "https://pypi.org/simple/python-dateutil/")
        self.assertEqual(registry_url("crates", "serde_json"), "https://crates.io/api/v1/crates/serde_json")
        self.assertEqual(
            registry_url("go", "github.com/Example/Mod"), "https://proxy.golang.org/github.com/!example/!mod/@v/list"
        )


class Typosquat(unittest.TestCase):
    def test_near_misses_flagged(self) -> None:
        self.assertEqual(typosquat_of("npm", "lodahs"), "lodash")  # swapped letters
        self.assertEqual(typosquat_of("npm", "cross_env"), "cross-env")  # - versus _
        self.assertEqual(typosquat_of("pypi", "reqeusts"), "requests")
        self.assertEqual(typosquat_of("crates", "tokoi"), "tokio")
        self.assertEqual(typosquat_of("pypi", "beautifulsoup5"), "beautifulsoup4")

    def test_real_names_not_flagged(self) -> None:
        self.assertIsNone(typosquat_of("npm", "preact"))  # popular itself
        self.assertIsNone(typosquat_of("pypi", "python_dateutil"))  # the same PyPI project
        self.assertIsNone(typosquat_of("crates", "serde-json"))  # crates.io treats - and _ alike
        self.assertIsNone(typosquat_of("npm", "ms"))  # too short to judge
        self.assertIsNone(typosquat_of("npm", "fastify"))


class Findings(unittest.TestCase):
    def setUp(self) -> None:
        self.cache_dir = tempfile.TemporaryDirectory()
        self.cache = Path(self.cache_dir.name) / "registry.json"

    def tearDown(self) -> None:
        self.cache_dir.cleanup()

    def run_check(self, ws: Path, fake: FakeRegistry, **kw) -> list:
        return check_new_dependencies(ws, None, fetch=fake, cache_file=self.cache, now=NOW, **kw)

    def test_npm_findings(self) -> None:
        fake = FakeRegistry(
            {
                "https://registry.npmjs.org/react": (200, npm_doc(OLD)),
                "https://registry.npmjs.org/fresh-widget": (200, npm_doc(NOW - 3 * DAY)),
                "https://registry.npmjs.org/lodahs": (200, npm_doc(OLD)),
                "https://registry.npmjs.org/gone-pkg": (200, {"time": {"unpublished": {}}}),
            }
        )
        with repo({"package.json": pkg(react="19.0.0")}, {"package.json": pkg(
            react="19.0.0", **{"fresh-widget": "1.0.0", "lodahs": "1.0.0", "prufgate-nonexistent-zz9": "1.0.0",
                               "gone-pkg": "1.0.0", "local-lib": "file:../lib", "fork": "user/repo"}
        )}) as tmp:
            findings = self.run_check(Path(tmp), fake)
        got = sorted((f.rule, f.text, f.severity) for f in findings)
        self.assertEqual(
            got,
            [
                ("dependency-not-on-registry", "gone-pkg", "P0"),
                ("dependency-not-on-registry", "prufgate-nonexistent-zz9", "P0"),
                ("dependency-recently-published", "fresh-widget", "P1"),
                ("dependency-typosquat", "lodahs", "P1"),
            ],
        )
        self.assertNotIn("https://registry.npmjs.org/react", fake.calls)  # declared at the base
        self.assertTrue(all(f.path == "package.json" and f.line == 1 for f in findings))

    def test_pypi_crates_go(self) -> None:
        fake = FakeRegistry(
            {
                "https://pypi.org/simple/fresh-tool/": (200, {"files": [{"upload-time": iso(NOW - 2 * DAY)}]}),
                "https://pypi.org/simple/old-tool/": (200, {"files": [{"upload-time": iso(OLD)}]}),
                "https://crates.io/api/v1/crates/tokoi": (200, {"crate": {"created_at": iso(OLD)}}),
                "https://proxy.golang.org/github.com/example/real/@v/list": (200, b"v1.0.0\n"),
                "https://proxy.golang.org/github.com/example/ghost/@v/list": (410, b"not found"),
            }
        )
        head = {
            "requirements.txt": "old-tool==1.0\nfresh_tool>=2\n-r other.txt\ngit+https://example.com/x.git\n",
            "Cargo.toml": '[package]\nname = "demo"\n\n[dependencies]\ntokoi = "1"\nmine = { path = "../mine" }\n'
            "phantom-crate = \"0.1\"\n",
            "go.mod": "module example.com/demo\n\nrequire (\n\tgithub.com/example/real v1.0.0\n"
            "\tgithub.com/example/ghost v0.1.0\n)\n",
        }
        with repo({}, head) as tmp:
            findings = self.run_check(Path(tmp), fake)
        got = sorted((f.rule, f.text, f.path) for f in findings)
        self.assertEqual(
            got,
            [
                ("dependency-not-on-registry", "github.com/example/ghost", "go.mod"),
                ("dependency-not-on-registry", "phantom-crate", "Cargo.toml"),
                ("dependency-recently-published", "fresh-tool", "requirements.txt"),
                ("dependency-typosquat", "tokoi", "Cargo.toml"),
            ],
        )
        lines = {f.text: f.line for f in findings}
        self.assertEqual((lines["fresh-tool"], lines["github.com/example/ghost"]), (2, 5))

    def test_cache_hit_and_expiry(self) -> None:
        fake = FakeRegistry({"https://registry.npmjs.org/new-thing": (200, npm_doc(OLD))})
        with repo({"package.json": pkg()}, {"package.json": pkg(**{"new-thing": "1"})}) as tmp:
            ws = Path(tmp)
            self.assertEqual(self.run_check(ws, fake), [])
            self.assertEqual(self.run_check(ws, fake), [])
            self.assertEqual(len(fake.calls), 1)  # second run served from the cache
            check_new_dependencies(ws, None, fetch=fake, cache_file=self.cache, now=NOW + 2 * DAY)
            self.assertEqual(len(fake.calls), 2)  # expired, looked up again
            self.assertFalse((ws / ".cache").exists())

    def test_a_cache_entry_from_the_future_is_not_fresh(self) -> None:
        fake = FakeRegistry({})
        self.cache.write_text(json.dumps({"npm:ghost-thing": {"exists": True, "created": OLD, "at": NOW * 10}}))
        with repo({"package.json": pkg()}, {"package.json": pkg(**{"ghost-thing": "1"})}) as tmp:
            findings = self.run_check(Path(tmp), fake)
        self.assertEqual([(f.rule, f.text) for f in findings], [("dependency-not-on-registry", "ghost-thing")])

    def test_an_excluded_manifest_does_not_hide_the_same_name_elsewhere(self) -> None:
        fake = FakeRegistry({})
        with repo({}, {}) as tmp:
            ws = Path(tmp)
            for d in ("aaa", "zzz"):
                (ws / d).mkdir()
                (ws / d / "package.json").write_text(pkg(**{"ghost-thing": "1"}))
            findings = self.run_check(ws, fake)
        self.assertEqual(sorted(f.path for f in findings), ["aaa/package.json", "zzz/package.json"])
        self.assertEqual(len(fake.calls), 1)  # the second manifest is served from the cache

    def test_cache_never_written_into_repo(self) -> None:
        fake = FakeRegistry({"https://registry.npmjs.org/new-thing": (200, npm_doc(OLD))})
        with repo({"package.json": pkg()}, {"package.json": pkg(**{"new-thing": "1"})}) as tmp:
            ws = Path(tmp)
            check_new_dependencies(ws, None, fetch=fake, cache_file=ws / "c" / "registry.json", now=NOW)
            self.assertFalse((ws / "c").exists())

    def test_lookup_failure_fails_closed(self) -> None:
        for answer in ((503, b""), (429, b""), (0, OSError("network unreachable")), (200, b"<html>")):
            fake = FakeRegistry({"https://registry.npmjs.org/new-thing": answer})
            with repo({"package.json": pkg()}, {"package.json": pkg(**{"new-thing": "1"})}) as tmp:
                with self.assertRaises(RegistryError):
                    self.run_check(Path(tmp), fake)
                self.assertEqual(self.run_check(Path(tmp), fake, offline_ok=True), [])

    def test_lookup_bound(self) -> None:
        fake = FakeRegistry({})
        with repo({"package.json": pkg()}, {"package.json": pkg(a1="1", a2="1", a3="1")}) as tmp:
            with self.assertRaises(RegistryError):
                self.run_check(Path(tmp), fake, max_lookups=2)
        self.assertEqual(len(fake.calls), 2)

    def test_no_git_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text(pkg(x="1"), encoding="utf-8")
            with self.assertRaises(RegistryError):
                self.run_check(Path(tmp), FakeRegistry({}))


class Wiring(unittest.TestCase):
    def test_off_by_default(self) -> None:
        with repo({"package.json": pkg()}, {"package.json": pkg(**{"prufgate-nonexistent-zz9": "1"})}) as tmp:
            with mock.patch.object(registry_check, "default_fetch", side_effect=AssertionError("network")):
                findings = scan_contract_guard(Path(tmp), config=PrufGateConfig())
        self.assertFalse([f for f in findings if f.rule.startswith("dependency-")])

    def test_enabled_failure_exits_2(self) -> None:
        with repo({"package.json": pkg()}, {"package.json": pkg(**{"new-thing": "1"})}) as tmp:
            ws = Path(tmp)
            (ws / ".prufgate.yaml").write_text("registry_check: true\n", encoding="utf-8")
            with tempfile.TemporaryDirectory() as cache, mock.patch.dict("os.environ", {"XDG_CACHE_HOME": cache}), \
                    mock.patch.object(registry_check, "default_fetch", side_effect=OSError("offline")):
                self.assertEqual(main([f"--workspace={ws}"]), 2)
                (ws / ".prufgate.yaml").write_text("registry_check: {offline_ok: true}\n", encoding="utf-8")
                self.assertEqual(main([f"--workspace={ws}"]), 0)

    def test_enabled_finding_exits_1(self) -> None:
        with repo({"package.json": pkg()}, {"package.json": pkg(**{"prufgate-nonexistent-zz9": "1"})}) as tmp:
            ws = Path(tmp)
            with tempfile.TemporaryDirectory() as cache, mock.patch.dict(
                "os.environ", {"XDG_CACHE_HOME": cache, "PRUFGATE_REGISTRY_CHECK": "1"}
            ), mock.patch.object(registry_check, "default_fetch", FakeRegistry({})):
                self.assertEqual(main([f"--workspace={ws}"]), 1)

    def test_config_validation(self) -> None:
        for bad in ("registry_check: yes-please\n", "registry_check: {offline: true}\n",
                    "registry_check: {max_lookups: -1}\n", "registry_check: {offline_ok: 1}\n"):
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / ".prufgate.yaml").write_text(bad, encoding="utf-8")
                with self.assertRaises(ConfigError, msg=bad):
                    PrufGateConfig.load(tmp)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".prufgate.yaml").write_text("registry_check: {max_age_days: 7}\n", encoding="utf-8")
            cfg = PrufGateConfig.load(tmp)
            self.assertEqual((cfg.registry_check, cfg.registry_offline_ok, cfg.registry_max_age_days), (True, False, 7))


if __name__ == "__main__":
    unittest.main()
