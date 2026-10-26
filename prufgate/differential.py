"""`prufgate verify --differential`: run the base branch's tests against the head code.

A test deleted or weakened so the branch passes fails again when its base version
runs on the new code. This is the one PrufGate command that EXECUTES code from the
repository under review (its tests), so it never runs as part of `check`, the
batteries, the MCP server, the API or the hooks, and it refuses to start unless the
operator opts in with `--allow-run-tests` or `PRUFGATE_ALLOW_RUN_TESTS=1`. Run it
only in a sandbox or a disposable CI job.

How it works:
1. The comparison base is `git merge-base <base> HEAD`, so tests added to the base branch
   after the fork are not run against a head that never saw them. Any worktree a killed
   earlier run left behind is removed.
2. `git worktree add --detach` puts HEAD (committed) in a temporary directory; the
   user's checkout is never touched.
3. The head's own tests run there. If they fail, the comparison is inconclusive (exit 2).
4. Every process the run left behind is killed and the worktree is reset to HEAD, so
   nothing step 3 wrote or started survives. Then the test run is made the base's:
   every file of the test run (test files, conftest and other helpers, files under test
   directories, test-runner configuration; see `part_of_test_run`) is written in its
   base version, and those the base did not have are removed. In `package.json` only
   the test runner keys and the test scripts are restored.
5. The tests run again. The code is head's and the tests are base's, so a failure is a
   base test that the head code no longer satisfies.
6. The worktree is always removed, also on a timeout, SIGTERM or SIGINT.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prufgate.diff_guard.fake_exit import TEST_DIR_NAMES, is_test_harness
from prufgate.repo_runner import OPT_IN_ENV, head_worktree, opted_in  # noqa: F401  (re-exported)
from prufgate.repo_runner import RunError as DifferentialError
from prufgate.repo_runner import env as _env
from prufgate.repo_runner import git as _git
from prufgate.repo_runner import run_command as _run

RULE = "differential-base-tests-fail"
DEFAULT_TIMEOUT = 600
PYTEST_MARKERS = ("pytest.ini", "conftest.py")
TMP_PREFIX = "prufgate-differential-"
# Files that decide what a test run collects or how it judges, besides the tests themselves.
RUNNER_CONFIG_RE = re.compile(
    r"(?:^|/)(?:pytest\.ini|pyproject\.toml|setup\.cfg|tox\.ini|package\.json"
    r"|(?:vite|vitest)\.(?:config|workspace)\.[\w.-]+|vitest\.workspace\.\w+|\.mocharc\.[\w.]+)$",
    re.IGNORECASE,
)
# package.json keys restored from the base; head keeps everything else (dependencies, "type", ...).
_PKG_RUNNER_KEYS = ("jest", "mocha", "ava", "vitest", "c8", "nyc")
_PKG_TEST_SCRIPT_RE = re.compile(r"^(?:pre|post)?test(?:$|:)")


@dataclass
class Result:
    findings: list[dict[str, Any]] = field(default_factory=list)
    overlaid: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)


def part_of_test_run(path: str) -> bool:
    """A test file, a file that sets up or configures the test run, or any file under a test directory."""
    parts = path.lower().split("/")
    return (
        is_test_harness(path)
        or bool(RUNNER_CONFIG_RE.search(path))
        or any(d in TEST_DIR_NAMES or d in ("testdata", "specs") for d in parts[:-1])
    )


def detect_test_command(root: Path, junit: Path) -> list[str] | None:
    """pytest, then `npm test`, then `go test ./...`, each only on clear evidence."""
    pyproject = root / "pyproject.toml"
    setup_cfg = root / "setup.cfg"
    tox_ini = root / "tox.ini"
    if (
        any((root / m).is_file() for m in PYTEST_MARKERS)
        or (pyproject.is_file() and "[tool.pytest" in pyproject.read_text(encoding="utf-8", errors="ignore"))
        or (setup_cfg.is_file() and "[tool:pytest]" in setup_cfg.read_text(encoding="utf-8", errors="ignore"))
        or (tox_ini.is_file() and "[pytest]" in tox_ini.read_text(encoding="utf-8", errors="ignore"))
    ):
        return [sys.executable, "-m", "pytest", "-q", f"--junitxml={junit}"]
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            scripts = json.loads(pkg.read_text(encoding="utf-8")).get("scripts") or {}
        except (ValueError, AttributeError):
            scripts = {}
        test = scripts.get("test") if isinstance(scripts, dict) else None
        # npm init writes a test script that only fails: that is not a test suite.
        if isinstance(test, str) and test.strip() and "no test specified" not in test:
            return ["npm", "test"]
    if (root / "go.mod").is_file():
        return ["go", "test", "./..."]
    return None


def failing_tests(junit: Path, files: list[str]) -> list[tuple[str, str]]:
    """(test id, file) for each failed or errored test case in a JUnit XML report. Without a
    `file` attribute the file is the one of `files` whose module path starts the class name."""
    try:
        tree = ET.parse(junit)
    except (OSError, ET.ParseError):
        return []
    out = []
    for case in tree.iter("testcase"):
        if case.find("failure") is None and case.find("error") is None:
            continue
        cls, name = case.get("classname", ""), case.get("name", "")
        path = case.get("file") or next(
            (f for f in files if f.endswith(".py") and (cls + ".").startswith(f[:-3].replace("/", ".") + ".")), ""
        )
        out.append((f"{cls}::{name}" if cls else name, path))
    return out


def _tree(root: Path, rev: str) -> dict[str, tuple[bytes, bytes]]:
    """{path: (mode, blob id)} of the regular files in `rev` that are part of the test run."""
    out = {}
    for entry in _git(root, "ls-tree", "-r", "-z", "--end-of-options", rev, binary=True).split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        mode, kind, obj = meta.split()
        path = raw_path.decode("utf-8", "surrogateescape")
        # Regular blobs only: no symlinks, no submodules.
        if kind == b"blob" and mode != b"120000" and part_of_test_run(path):
            out[path] = (mode, obj)
    return out


def _package_json(head: bytes, base: bytes) -> bytes:
    """Head's package.json with the base's test runner keys and test scripts."""
    try:
        h, b = json.loads(head), json.loads(base)
    except ValueError:
        return base
    if not isinstance(h, dict) or not isinstance(b, dict):
        return base
    for key in _PKG_RUNNER_KEYS:
        h.pop(key, None)
        if key in b:
            h[key] = b[key]
    hs = h.get("scripts") if isinstance(h.get("scripts"), dict) else {}
    bs = b.get("scripts") if isinstance(b.get("scripts"), dict) else {}
    hs = {k: v for k, v in hs.items() if not _PKG_TEST_SCRIPT_RE.match(k)}
    hs.update({k: v for k, v in bs.items() if _PKG_TEST_SCRIPT_RE.match(k)})
    if hs or "scripts" in h:
        h["scripts"] = hs
    return (json.dumps(h, indent=2) + "\n").encode()


def _base_test_run(root: Path, base: str) -> tuple[list[tuple[str, bytes, int]], list[str]]:
    """(files to write: path, content, mode) and (paths to remove) that turn the worktree's test run into the base's."""
    base_files, head_files = _tree(root, base), _tree(root, "HEAD")
    writes = []
    for path, (mode, obj) in base_files.items():
        if head_files.get(path) == (mode, obj):
            continue  # the worktree holds HEAD, and HEAD has this file unchanged
        content = _git(root, "cat-file", "blob", obj.decode(), binary=True)
        if path in head_files and path.rsplit("/", 1)[-1].lower() == "package.json":
            head = _git(root, "cat-file", "blob", head_files[path][1].decode(), binary=True)
            content = _package_json(head, content)
            if content == head:
                continue
        writes.append((path, content, 0o755 if mode == b"100755" else 0o644))
    return writes, sorted(set(head_files) - set(base_files))


def _clear(wt: Path, path: str, make_parents: bool) -> Path | None:
    """`wt/path` with nothing at it, every ancestor a real directory inside the worktree. Symlinks, files or
    directories head put in the way are removed (they are in the worktree); never followed or opened."""
    cur = wt
    for part in Path(path).parts[:-1]:
        cur = cur / part
        if cur.is_symlink() or (cur.exists() and not cur.is_dir()):
            if not make_parents:
                return None
            cur.unlink()
        if not cur.exists():
            if not make_parents:
                return None
            cur.mkdir()
    dest = cur / Path(path).name
    if dest.is_dir() and not dest.is_symlink():
        shutil.rmtree(dest)
    elif dest.is_symlink() or dest.exists():
        dest.unlink()  # a hardlink, FIFO or symlink is unlinked, never written through
    return dest


def _overlay(wt: Path, writes: list[tuple[str, bytes, int]], removes: list[str]) -> None:
    for path in removes:
        _clear(wt, path, make_parents=False)
    for path, content, mode in writes:
        dest = _clear(wt, path, make_parents=True) or wt / path
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)


def run(
    repo: Path,
    base: str,
    test_cmd: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    pass_env: list[str] | None = None,
) -> Result:
    root = Path(_git(repo, "rev-parse", "--show-toplevel").strip())
    _git(root, "rev-parse", "--verify", "-q", "--end-of-options", f"{base}^{{commit}}")
    base_commit = _git(root, "merge-base", "--end-of-options", base, "HEAD").strip()
    with head_worktree(root, TMP_PREFIX) as tmp:
        wt = tmp / "head"
        junit = tmp / "junit.xml"
        log = tmp / "output.log"
        cmd = shlex.split(test_cmd) if test_cmd else detect_test_command(wt, junit)
        if not cmd:
            raise DifferentialError(
                "no test command found (no pytest configuration or conftest.py, no package.json test script, "
                "no go.mod): pass --test-cmd"
            )
        result = Result(command=cmd)
        writes, removes = _base_test_run(root, base_commit)
        result.overlaid = [p for p, _, _ in writes]
        result.removed = removes
        if not writes and not removes:
            return result  # the base test run is the head's: nothing to compare
        env = _env(pass_env or [], junit)
        rc, out = _run(cmd, wt, env, timeout, log)
        if rc != 0:
            raise DifferentialError(
                f"the head's own tests fail (exit {rc}), so the comparison is inconclusive:\n{out[-2000:]}"
            )
        # Undo whatever the head's tests wrote: hardlinks, FIFOs, symlinks, edited sources.
        _git(wt, "reset", "--hard", "--quiet", "HEAD")
        _git(wt, "clean", "-fdxq")
        _overlay(wt, writes, removes)
        junit.unlink(missing_ok=True)
        rc, out = _run(cmd, wt, env, timeout, log)
        if rc == 0:
            return result
        changed = result.overlaid + removes
        failed = failing_tests(junit, result.overlaid)
        if failed:
            for test_id, path in failed:
                result.findings.append(_finding(path or changed[0], f"base test `{test_id}` fails on the head code"))
        else:
            # The runs differ only in these files, so the failure is in one of them.
            for path in result.overlaid:
                result.findings.append(
                    _finding(path, f"the base version of this test file fails on the head code (exit {rc})")
                )
            for path in removes:
                result.findings.append(
                    _finding(path, f"without this file, which the base does not have, the base tests fail (exit {rc})")
                )
        return result


def _finding(path: str, detail: str) -> dict[str, Any]:
    return {
        "engine": "differential",
        "rule": RULE,
        "severity": "P0",
        "file": path,
        "line": 1,
        "message": f"{detail}, while the head's own tests pass: a test was deleted or weakened to make the change pass.",
        "snippet": "",
    }
