#!/usr/bin/env python3
"""PrufGate Diff-Scoped Agent Tampering & Guardrail Bypass Detector (Engine 3).

Inspects unified git diffs (`git diff`, staged changes, or PR `base...HEAD`) to detect
when an AI coding agent or contributor silences failing checks instead of fixing the
underlying defect:
  1. test-skip-smuggling (P0): Added lines introducing `.skip(`, `it.skip`, `describe.skip`,
     `test.skip`, `xit(`, `xdescribe(`, `test.only(`, `it.only(`, `@pytest.mark.skip`,
     `@pytest.mark.xfail`, `@unittest.skip`, `t.Skip(`, `#[ignore]`, or `@Disabled`
     without an issue reference comment (e.g., `#123` or `JIRA-456`).
  2. suppression-comment-smuggling (P1): Added lines introducing `@ts-ignore`,
     `@ts-expect-error` (without explanation), `eslint-disable`, `biome-ignore`,
     `# noqa`, `# type: ignore`, `// nolint`, `#[allow(`, `@SuppressWarnings`, or
     `prufgate-ignore` without an inline justification.
  3. unsafe-type-cast-cascade (P1): Added production lines introducing `as unknown as `,
     `: any`, `as any`, `typing.cast(Any, ...)`, or unjustified `unsafe {` blocks.
  4. linter-or-ci-config-weakening (P0): Diffs in `tsconfig.json`, `pyproject.toml`,
     `ruff.toml`, `.eslintrc*`, `biome.json`, `.golangci.yml`, and `.github/workflows/*.yml`
     that disable strictness (`"strict": false`), add global `ignore` rules, or add
     `continue-on-error: true` / `|| true` to CI steps.
  5. coverage-threshold-lowering (P0): a coverage gate (`fail_under`, `--cov-fail-under`,
     Jest/Vitest `lines`/`branches`/`functions`/`statements`) lowered or removed.
  6. prufgate-config-self-exemption (P1): `.prufgate/config.yaml` gaining exemptions, debt,
     exclusions, allowed paths, score owners or a narrower `languages` list, or dropping a pack.
     P0 when an exclusion covers every file or PrufGate's own configuration (`**`, `.prufgate/`).
     PrufGate's configuration files are always analysed, and a deleted one is flagged: the
     configuration under review can neither exclude nor exempt itself.

Untracked files count as added in full. Exit codes: 0 clean, 1 findings, 2 bad
usage, an unreadable --diff-file or a git error (never a silent pass).

CLI Usage:
  python3 prufgate/diff_guard/tamper_detector.py
  python3 prufgate/diff_guard/tamper_detector.py --base=origin/main
  python3 prufgate/diff_guard/tamper_detector.py --diff-file=changes.patch
  python3 prufgate/diff_guard/tamper_detector.py --json-out=reports/raw/diff_guard.json
  python3 prufgate/diff_guard/tamper_detector.py --config=.prufgate/config.yaml
  python3 prufgate/diff_guard/tamper_detector.py --self-check
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

from prufgate.anti_reward_hacking.test_integrity import (  # noqa: E402
    GitDiffError,
    _diff_base,
    _get_git_diff,
    _git,
    is_internal_path,
    is_test_file,
)
from prufgate.config import (  # noqa: E402
    DEFAULT_CONFIG_FILES,
    DEFAULT_PACKS,
    SUPPORTED_LANGUAGES,
    ConfigError,
    PrufGateConfig,
    path_matches_pattern,
)


@dataclass
class Finding:
    """A single agent-tampering or guardrail-bypass finding in a git diff."""

    path: str
    line: int
    rule: str
    text: str
    severity: str = "P0"
    message: str = ""

    def __post_init__(self) -> None:
        self.text = self.text.strip()[:140]
        if not self.message:
            self.message = f"Diff tampering violation ({self.rule}): {self.text}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "snippet": self.text,
        }

    def __str__(self) -> str:
        return f"{self.path}:{self.line}\n    [{self.severity}] [{self.rule}] {self.text}"


@dataclass
class DiffHunk:
    """Parsed unified diff hunk with file metadata and line-numbered changes."""

    file_path: str
    old_path: str
    is_new_file: bool
    is_deleted_file: bool
    old_start: int
    new_start: int
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)
    context_lines: list[tuple[int, str]] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)


# Kept for callers that still filter by substring; prefer is_internal_path().
INTERNAL_SCANNER_PATHS = (
    "prufgate/anti_fabrication/",
    "prufgate/anti_reward_hacking/",
    "prufgate/diff_guard/",
    "prufgate/contract_guard/",
    "prufgate/bola/",
    "prufgate/review/",
    "prufgate/hooks/",
    "prufgate/mcp/",
    "prufgate/synthesizer/",
    "prufgate/cli.py",
    "tests/test_anti_reward_hacking.py",
    "tests/test_diff_guard.py",
    "tests/test_contract_guard.py",
    "tests/test_bola_engine.py",
    "tests/test_cli.py",
    "tests/test_review_engine.py",
    "tests/test_mcp.py",
    "tests/test_synthesizer.py",
    "tests/test_config_yaml.py",
    "tests/test_public_repo_hygiene.py",
    "tests/test_report_hygiene.py",
)

# Issue or ticket reference (e.g., #123, issue #45, GH-123, JIRA-456, https://.../issues/12).
# Project keys are upper case and never a standard's name: `utf-8` or
# `SHA-256` in a test title is not a ticket.
ISSUE_REF_RE = re.compile(
    r"#\d+\b"
    r"|\b(?i:issue|bug|ticket|pr)\s*#?\d+\b"
    r"|\b(?!(?:UTF|SHA|ISO|AES|RSA|TLS|SSL|HTTP|PEP|ES|MD|CRC|IEEE|RFC|ECMA|IPV|X)-)[A-Z][A-Z0-9]{1,9}-\d+\b"
    r"|https?://[^\s)\"']+/issues/\d+"
)

# 1. Test focus leaks (ALWAYS P0 — silently disables the rest of the test suite)
FOCUS_LEAK_RE = re.compile(
    r"\b(?:it|test|describe|context)\.only\s*\("
    r"|\b(?:fit|fdescribe)\s*\("
)

# 1b. Test skip smuggling patterns
SKIP_SMUGGLING_RE = re.compile(
    r"\b(?:it|test|describe|context|suite|specify)\.(?:skip|skipIf|runIf)\s*\("
    r"|\b(?:this|t|ctx|context)\.skip\s*\("  # Mocha this.skip(), node:test t.skip(), Vitest ctx.skip()
    r"|\b(?:xit|xdescribe|xtest|xcontext|xspecify)\b(?:\s*\(|\s+[\"'])"  # also RSpec `xit 'x' do`
    r"|\[(?:Fact|Theory)\s*\([^\]]*\bSkip\s*="  # xUnit [Fact(Skip = "...")]
    r"|\[Ignore\b"  # NUnit / MSTest
    r"|->\s*markTest(?:Skipped|Incomplete)\s*\("  # PHPUnit
    r"|\)\s*->\s*skip\s*\("  # Pest ->skip()
    r"|@pytest\.mark\.(?:skip|xfail)\b"
    r"|\bpytest\.(?:skip|xfail)\s*\("
    r"|@unittest\.skip(?:If|Unless)?\b"
    r"|\bself\.skipTest\s*\("
    r"|\bt\.(?:Skip|Skipf|SkipNow)\s*\("
    r"|#\[ignore(?:\s*\([^)]*\))?\]"
    r"|@(?:Disabled|Ignore)\b"
)

# 2. Suppression comment smuggling patterns
SUPPRESSION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ts-ignore", re.compile(r"//\s*@ts-ignore\b|/\*\s*@ts-ignore\b")),
    ("ts-expect-error", re.compile(r"//\s*@ts-expect-error\b|/\*\s*@ts-expect-error\b")),
    ("eslint-disable", re.compile(r"(?://|/\*)\s*eslint-disable(?:-(?:next-)?line)?\b")),
    ("biome-ignore", re.compile(r"(?://|/\*)\s*biome-ignore\b")),
    ("noqa", re.compile(r"#\s*noqa\b")),
    ("type-ignore", re.compile(r"#\s*type:\s*ignore\b")),
    ("nolint", re.compile(r"//\s*nolint\b")),
    ("rust-allow", re.compile(r"#!?\[allow\s*\(")),
    ("suppress-warnings", re.compile(r"@SuppressWarnings\s*\(")),
    ("prufgate-ignore", re.compile(r"(?:#|//|/\*)\s*prufgate-ignore\b")),
)

# 3. Unsafe type cast cascade in production files
TS_UNSAFE_CAST_RE = re.compile(
    r"\bas\s+unknown\s+as\s+[A-Za-z_$][\w$<>,.\[\]\s]*"
    r"|\bas\s+any\b"
    r"|:\s*any\b"
    r"|<any>(?=[A-Za-z_$(])"
)
PY_UNSAFE_CAST_RE = re.compile(
    r"\b(?:typing\.)?cast\(\s*Any\s*,"
)
RS_UNSAFE_BLOCK_RE = re.compile(
    r"\bunsafe\s*\{"
)
GO_UNSAFE_PTR_RE = re.compile(
    r"\bunsafe\.Pointer\s*\("
)

# 4. Linter or CI config files & weakening patterns
LINTER_CONFIG_PATTERNS = (
    "tsconfig.json",
    "tsconfig.",
    "pyproject.toml",
    "ruff.toml",
    ".ruff.toml",
    ".flake8",
    "setup.cfg",
    "mypy.ini",
    ".eslintrc",
    "eslint.config.",
    "biome.json",
    ".golangci.yml",
    ".golangci.yaml",
)

CI_WORKFLOW_PATTERNS = (
    ".github/workflows/",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
)

LINTER_WEAKENING_RE = re.compile(
    r"""["']?(?:strict|noImplicitAny|strictNullChecks|strictFunctionTypes|noUnusedLocals|noUnusedParameters)["']?\s*:\s*false\b"""
    r"""|\b(?:disallow_untyped_defs|check_untyped_defs|strict|warn_return_any)\s*=\s*(?:false|False)\b"""
    r"""|\bignore_errors\s*=\s*(?:true|True)\b"""
    r"""|["']?ignore["']?\s*[:=]\s*\["""
    r"""|["']?(?:recommended|all)["']?\s*:\s*false\b"""
    r"""|\bdisable-all\s*:\s*true\b"""
    r"""|["'][a-zA-Z0-9_/@-]+["']\s*:\s*(?:["']off["']|\b0\b)"""
)

CI_WEAKENING_RE = re.compile(
    r"\bcontinue-on-error\s*:\s*true\b"
    r"|\ballow_failure\s*:\s*true\b"
    r"|\|\|\s*true\b"
    r"|\|\|\s*exit\s+0\b"
)


# 5. Coverage thresholds lowered or removed.
COVERAGE_FILE_RE = re.compile(
    r"(?:^|/)(?:pyproject\.toml|setup\.cfg|\.coveragerc|tox\.ini|pytest\.ini|package\.json|Makefile"
    r"|\.nycrc(?:\.\w+)?|\.?codecov\.ya?ml|(?:jest|vitest|vite|karma)\.conf(?:ig)?\.[cm]?[jt]s(?:on)?)$"
)
COVERAGE_KEY_RE = re.compile(
    r"""(?P<key>--cov-fail-under|--fail-under|fail[_-]under|min(?:imum)?[_-]?coverage|coverage[_-]?threshold"""
    r"""|["']?\b(?:lines|branches|functions|statements)\b["']?)\s*[:=\s]\s*(?P<val>\d+(?:\.\d+)?)""",
    re.IGNORECASE,
)

# 6. A PrufGate configuration that exempts, narrows or drops checks.
PRUFGATE_CONFIG_RE = re.compile(r"(?:^|/)(?:\.prufgate/(?:config\.ya?ml|fabrication\.json|debt-ceiling\.json)|\.prufgate\.ya?ml)$")
# Sections where an added entry silences or narrows a check (an extra auth guard,
# tenant key or evidence marker makes PrufGate accept more code as safe).
PRUFGATE_WIDENING_SECTIONS = {
    "exempt", "known_debt", "exclude", "allowed_paths", "score_owners", "languages",
    "auth_guards", "tenant_keys", "evidence_markers",
}
YAML_TOP_KEY_RE = re.compile(r"""^["']?([A-Za-z_][\w-]*)["']?\s*:(.*)$""")
# Sections whose entries are paths: an entry here that matches every file, or
# PrufGate's own configuration, switches PrufGate off.
PRUFGATE_PATH_SECTIONS = {"exclude", "allowed_paths"}
# Unrelated sample paths: a pattern matching all of them excludes everything.
CATCH_ALL_PROBES = ("src/main.py", "app/index.ts", "pkg/server/handler.go", "README")
OWN_CONFIG_PROBES = (".prufgate/config.yaml", ".prufgate.yml")


def _is_own_config(rel_path: str) -> bool:
    """A configuration file PrufGate loads: one at the repository root. A copy
    deeper in the tree (a test fixture) is never loaded and is scanned like any file."""
    return bool(PRUFGATE_CONFIG_RE.search(rel_path)) and "/" not in rel_path.replace("\\", "/").removeprefix(".prufgate/")


def _config_finding(path: str, why: str, severity: str = "P1", text: str = "") -> Finding:
    return Finding(
        path=path,
        line=1,
        rule="prufgate-config-self-exemption",
        severity=severity,
        text=text or why,
        message=f"PrufGate configuration in effect {why} compared with the base. A change that silences PrufGate needs a maintainer's review.",
    )


def _git_blob(commit: str, rel: str, root: Path, depth: int = 0) -> str | None:
    """The text of `rel` (repository-relative) at `commit`, following an
    in-repository symbolic link a few levels; None when it is not there."""
    try:
        entry = _git(["ls-tree", "-z", "--full-tree", commit, "--", rel], root).split("\0")[0]
    except GitDiffError:
        return None
    if not entry:
        return None
    mode = entry.split(" ", 1)[0]
    try:
        blob = _git(["show", f"{commit}:{rel}"], root)
    except GitDiffError:
        return None
    if mode != "120000":
        return blob
    target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), blob.strip()))
    if depth >= 5 or target.startswith("../") or target == ".." or posixpath.isabs(target):
        return None
    return _git_blob(commit, target, root, depth + 1)


def _repo_prefix(root: Path) -> str:
    """`root` relative to the repository top level ("" at the top), as git paths use it."""
    try:
        return _git(["rev-parse", "--show-prefix"], root).strip()
    except GitDiffError:
        return ""


def _load_base_config(root: Path, base_commit: str, config_path: str | None) -> PrufGateConfig | None:
    """The configuration that was in effect at `base_commit` (the defaults when
    there was none), or None for a --config outside the repository."""
    prefix = _repo_prefix(root)
    explicit: str | None = None
    rels = list(DEFAULT_CONFIG_FILES)
    if config_path:
        cp = Path(config_path)
        if cp.is_absolute():
            try:
                cp = Path(os.path.relpath(cp, root))
            except ValueError:
                return None
        rel = posixpath.normpath(cp.as_posix())
        if rel.startswith("../") or rel == "..":
            return None
        explicit, rels = rel, [rel]
    with tempfile.TemporaryDirectory() as tmp:
        for rel in rels:
            # Paths are taken as written, never resolved on disk: a link in the
            # branch must not decide which base file is read.
            blob = _git_blob(base_commit, posixpath.normpath(prefix + rel), root)
            if blob is None:
                continue
            dest = Path(tmp) / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(blob, encoding="utf-8")
        try:
            return PrufGateConfig.load(tmp, explicit)
        except ConfigError:
            # No base config (or one this version cannot read): the defaults.
            return PrufGateConfig()


def _applied_packs(cfg: PrufGateConfig) -> set[str]:
    """The packs that run, by the rule `detector.apply_settings` uses: explicit
    packs that name a default pack replace the defaults, others add to them."""
    explicit = set(cfg.packs) if cfg.packs_explicit else set()
    return explicit if explicit & set(DEFAULT_PACKS) else set(DEFAULT_PACKS) | explicit


def config_drift_findings(
    head: PrufGateConfig,
    root: Path,
    base_ref: str | None = None,
    config_path: str | None = None,
) -> list[Finding] | None:
    """Compare the configuration in effect on the branch with the one in effect
    at the base, by value: whatever the YAML spelling, file location, shadowing
    or diff attributes. Returns None when there is no base to compare with."""
    try:
        base_commit = _diff_base(base_ref, root)
    except GitDiffError:
        return None
    base = _load_base_config(root, base_commit, config_path)
    if base is None:
        return None
    path = DEFAULT_CONFIG_FILES[0]
    if head.source_path is not None:
        try:
            path = Path(head.source_path).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            path = Path(head.source_path).name
    elif base.source_path is not None:
        # Deleted or moved away: name the base file (loaded from a temporary copy).
        base_src = Path(base.source_path).as_posix()
        path = next((rel for rel in DEFAULT_CONFIG_FILES if base_src.endswith("/" + rel)), Path(base_src).name)
    out: list[Finding] = []
    for pat in head.exclude:
        if pat not in base.exclude:
            if _disables_prufgate(pat):
                out.append(_config_finding(path, f"excludes every file or its own configuration (`{pat}`)", "P0", pat))
            else:
                out.append(_config_finding(path, f"excludes `{pat}`", text=pat))
    for (ex_path, ex_rule) in head.exempt:
        if (ex_path, ex_rule) not in base.exempt:
            out.append(_config_finding(path, f"exempts `{ex_rule}` in `{ex_path}`"))
    for key in head.known_debt:
        if key not in base.known_debt:
            out.append(_config_finding(path, f"adds known debt `{key[1]}` in `{key[0]}`"))
    for rule, ceiling in head.known_debt_ceilings.items():
        if ceiling > base.known_debt_ceilings.get(rule, 0):
            out.append(_config_finding(path, f"allows {ceiling} `{rule}` finding(s) as debt"))
    dropped = _applied_packs(base) - _applied_packs(head)
    if dropped:
        out.append(_config_finding(path, f"drops pack(s) {', '.join(sorted(dropped))}"))
    if head.languages:
        before = set(base.languages) or set(SUPPORTED_LANGUAGES)
        narrowed = before - set(head.languages)
        if narrowed:
            out.append(_config_finding(path, f"stops scanning {', '.join(sorted(narrowed))}"))
    for name in ("auth_guards", "tenant_keys", "score_owners", "evidence_markers"):
        added = [v for v in getattr(head, name) if v not in getattr(base, name)]
        if added:
            out.append(_config_finding(path, f"widens `{name}` with {', '.join(added)}"))
    return out


def with_config_drift(
    findings: list[Finding],
    head: PrufGateConfig,
    root: Path,
    base_ref: str | None = None,
    config_path: str | None = None,
) -> list[Finding]:
    """Replace the line-based findings on the root configuration with the
    by-value comparison, when a base is available."""
    drift = config_drift_findings(head, root, base_ref, config_path)
    if drift is None:
        return findings
    kept = [f for f in findings if not (f.rule == "prufgate-config-self-exemption" and _is_own_config(f.path))]
    return kept + drift


def _disables_prufgate(pattern: str) -> bool:
    """True for an exclusion that covers every file or PrufGate's own configuration."""
    pattern = pattern.strip().strip("\"'")
    if not pattern:
        return False
    if pattern in (".", "./", "/"):
        return True
    return all(path_matches_pattern(p, pattern) for p in CATCH_ALL_PROBES) or any(
        path_matches_pattern(p, pattern) for p in OWN_CONFIG_PROBES
    )


def _coverage_thresholds(lines: list[tuple[int, str]]) -> dict[str, tuple[float, int, str]]:
    out: dict[str, tuple[float, int, str]] = {}
    for ln, raw in lines:
        if raw.strip().startswith(("#", "//")):
            continue
        for m in COVERAGE_KEY_RE.finditer(raw):
            key = m.group("key").strip("\"'").lstrip("-").lower().replace("-", "_")
            out.setdefault(key, (float(m.group("val")), ln, raw))
    return out


def _coverage_findings(hunk: DiffHunk, rel_path: str) -> list[Finding]:
    if not (COVERAGE_FILE_RE.search(rel_path) or _is_ci_workflow_file(rel_path)):
        return []
    before = _coverage_thresholds(hunk.removed_lines)
    after = _coverage_thresholds(hunk.added_lines)
    out = []
    for key, (old, _old_ln, old_raw) in before.items():
        new = after.get(key)
        if new is None or new[0] < old:
            ln, raw = (new[1], new[2]) if new else (hunk.added_lines[0][0] if hunk.added_lines else hunk.new_start, old_raw)
            what = f"lowered from {old:g} to {new[0]:g}" if new else f"removed (was {old:g})"
            out.append(
                Finding(
                    path=rel_path,
                    line=ln,
                    rule="coverage-threshold-lowering",
                    severity="P0",
                    text=raw,
                    message=f"Coverage threshold `{key}` {what} in '{rel_path}'.",
                )
            )
    return out


def _prufgate_config_findings(hunk: DiffHunk, rel_path: str) -> list[Finding]:
    """Added exemptions, debt, exclusions or narrowed languages, and removed packs."""
    if not PRUFGATE_CONFIG_RE.search(rel_path):
        return []
    out = []

    def flag(ln: int, raw: str, why: str, severity: str = "P1") -> None:
        out.append(
            Finding(
                path=rel_path,
                line=ln,
                rule="prufgate-config-self-exemption",
                severity=severity,
                text=raw,
                message=f"PrufGate configuration {why} in '{rel_path}:{ln}'. A change that silences PrufGate needs a maintainer's review.",
            )
        )

    if hunk.is_deleted_file:
        flag(hunk.new_start or 1, "(file deleted)", "is deleted, so its packs and settings stop applying")
        return out

    if rel_path.endswith(".json"):
        for ln, raw in hunk.added_lines:
            if raw.strip() not in ("", "{", "}", "[", "]", "},", "],"):
                flag(ln, raw, "gains an entry")
        return out

    header = hunk.raw_lines[0] if hunk.raw_lines else ""
    m = YAML_TOP_KEY_RE.match(header.split("@@")[-1].strip()) if header.count("@@") >= 2 else None
    section = m.group(1) if m else ""
    old_ln, new_ln = hunk.old_start, hunk.new_start
    removed_packs: set[str] = set()
    added_packs: set[str] = set()
    for raw_line in hunk.raw_lines[1:]:
        tag, raw = raw_line[:1], raw_line[1:]
        code = raw.split("#", 1)[0].rstrip()
        top = YAML_TOP_KEY_RE.match(code)
        if top:
            section = top.group(1)
        inline = top.group(2).strip() if top else ""
        items = set(re.findall(r"[\w-]+", inline)) if top and section == "packs" else set()
        if not top and section == "packs" and code.strip().startswith("-"):
            items = {code.strip()[1:].strip()}
        if tag == "+":
            added_packs |= items
            if section in PRUFGATE_WIDENING_SECTIONS and code.strip() and (not top or inline not in ("", "{}", "[]")):
                entries = re.findall(r"""[^\s,\[\]"'-][^,\[\]"']*""", inline) if top else [code.strip().lstrip("-").strip()]
                if section in PRUFGATE_PATH_SECTIONS and any(_disables_prufgate(e) for e in entries):
                    flag(new_ln, raw, f"excludes every file or its own configuration through `{section}`", "P0")
                else:
                    flag(new_ln, raw, f"widens `{section}`")
            new_ln += 1
        elif tag == "-":
            removed_packs |= items
            old_ln += 1
        elif tag == " ":
            old_ln += 1
            new_ln += 1
    dropped = removed_packs - added_packs
    if dropped:
        flag(hunk.new_start, "packs: -" + ", -".join(sorted(dropped)), f"drops pack(s) {', '.join(sorted(dropped))}")
    return out


def parse_unified_diff(diff_text: str) -> list[DiffHunk]:
    """Parse a unified git diff into a list of `DiffHunk` objects."""
    hunks: list[DiffHunk] = []
    current_file = ""
    old_file = ""
    is_new = False
    is_del = False
    current_hunk: DiffHunk | None = None
    old_ln = 0
    new_ln = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            current_hunk = None
            is_new = False
            is_del = False
        elif raw_line.startswith("--- "):
            part = raw_line[4:].strip()
            if part == "/dev/null":
                is_new = True
                old_file = "/dev/null"
            else:
                old_file = re.sub(r"^a/", "", part)
        elif raw_line.startswith("+++ "):
            part = raw_line[4:].strip()
            if part == "/dev/null":
                is_del = True
                current_file = old_file
            else:
                current_file = re.sub(r"^b/", "", part)
        elif raw_line.startswith("@@ "):
            m = re.search(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_line)
            if m and current_file:
                old_ln = int(m.group(1))
                new_ln = int(m.group(2))
                current_hunk = DiffHunk(
                    file_path=current_file,
                    old_path=old_file or current_file,
                    is_new_file=is_new,
                    is_deleted_file=is_del,
                    old_start=old_ln,
                    new_start=new_ln,
                    raw_lines=[raw_line],
                )
                hunks.append(current_hunk)
        elif current_hunk is not None:
            current_hunk.raw_lines.append(raw_line)
            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                current_hunk.added_lines.append((new_ln, raw_line[1:]))
                new_ln += 1
            elif raw_line.startswith("-") and not raw_line.startswith("---"):
                current_hunk.removed_lines.append((old_ln, raw_line[1:]))
                old_ln += 1
            elif raw_line.startswith(" "):
                current_hunk.context_lines.append((new_ln, raw_line[1:]))
                old_ln += 1
                new_ln += 1

    return hunks


def _has_suppression_justification(kind: str, line: str, prev_line: str) -> bool:
    """Return True if a linter/type suppression has a meaningful inline or preceding justification."""
    # Check if there is an issue/ticket reference on the line or previous line
    if ISSUE_REF_RE.search(line) or (prev_line.strip().startswith(("#", "//", "/*")) and ISSUE_REF_RE.search(prev_line)):
        return True

    # Explicit separator `-- <reason>` or ` - <reason>` with at least 8 characters
    if re.search(r"(?:--| - )\s*[A-Za-z0-9][^\n]{7,}", line):
        return True

    if kind == "ts-expect-error":
        # Allow `// @ts-expect-error Testing invalid argument runtime error` (>= 10 chars after directive)
        m = re.search(r"@ts-expect-error[:\s-]+([A-Za-z0-9][^\n*/]{9,})", line)
        if m:
            return True

    if kind == "biome-ignore":
        # biome-ignore lint/style/useConst: <reason>
        m = re.search(r"biome-ignore\s+\S+\s*:\s*([A-Za-z0-9][^\n*/]{7,})", line)
        if m:
            return True

    if kind in ("noqa", "type-ignore"):
        # Allow `# noqa: E402 -- reason` or `# type: ignore[assignment]  # optional dependency`
        m = re.search(r"#\s*(?:noqa|type:\s*ignore)(?:\[[^\]]+\]|\s*:\s*[A-Z0-9,\s]+)?\s*(?:#|--)\s*([A-Za-z][^\n]{7,})", line)
        if m:
            return True

    if kind in ("nolint", "eslint-disable", "rust-allow", "suppress-warnings"):
        # Allow trailing `// reason` or `/* reason */` after the directive
        if kind == "nolint":
            m = re.search(r"//\s*nolint(?::[a-zA-Z0-9_,-]+)?\s+(?://|--)?\s*([A-Za-z][^\n]{7,})", line)
            if m:
                return True
        if kind in ("rust-allow", "suppress-warnings"):
            m = re.search(r"(?:\]\s*|@\w+\([^)]*\)\s*)(?://|/\*)\s*([A-Za-z][^\n*/]{7,})", line)
            if m:
                return True

    return False


def _is_linter_config_file(file_path: str) -> bool:
    name = Path(file_path).name
    return any(name == pat or name.startswith(pat) for pat in LINTER_CONFIG_PATTERNS)


def _is_ci_workflow_file(file_path: str) -> bool:
    norm = file_path.replace("\\", "/")
    return any(pat in norm for pat in CI_WORKFLOW_PATTERNS) and norm.endswith((".yml", ".yaml"))


def scan_diff_for_tampering(
    diff_text: str,
    config: PrufGateConfig | None = None,
) -> list[Finding]:
    """Scan a unified git diff for all 4 agent-tampering and guardrail-bypass rules."""
    cfg = config or PrufGateConfig()
    hunks = parse_unified_diff(diff_text)

    findings: list[Finding] = []

    # A pure rename has no hunk: moving the configuration away is a deletion.
    for m in re.finditer(r"^rename from (.+)\nrename to (.+)$", diff_text, re.M):
        if _is_own_config(m.group(1)) and not _is_own_config(m.group(2)):
            findings.append(
                Finding(
                    path=m.group(1),
                    line=1,
                    rule="prufgate-config-self-exemption",
                    severity="P1",
                    text=f"renamed to {m.group(2)}",
                    message=f"PrufGate configuration '{m.group(1)}' is moved away, so its packs and settings stop applying.",
                )
            )

    for hunk in hunks:
        rel_path = hunk.file_path.replace("\\", "/")
        # PrufGate's own configuration is always analysed: the configuration under
        # review must not be able to exclude itself (a head config with `exclude: ["**"]`).
        if _is_own_config(rel_path):
            findings.extend(_prufgate_config_findings(hunk, rel_path))
            continue
        if hunk.is_deleted_file or cfg.is_excluded(rel_path):
            continue

        is_test = is_test_file(rel_path)
        is_linter_cfg = _is_linter_config_file(rel_path)
        is_ci_cfg = _is_ci_workflow_file(rel_path)
        sfx = Path(rel_path).suffix.lower()
        if sfx in (".md", ".mdx", ".rst", ".txt") and not is_linter_cfg and not is_ci_cfg:
            continue

        for idx, (ln, raw) in enumerate(hunk.added_lines):
            s = raw.strip()
            if not s:
                continue
            prev_raw = hunk.added_lines[idx - 1][1] if idx > 0 else ""

            # 1. Test Skip / Focus Smuggling
            if FOCUS_LEAK_RE.search(s):
                if not cfg.is_exempt(rel_path, "test-skip-smuggling"):
                    findings.append(
                        Finding(
                            path=rel_path,
                            line=ln,
                            rule="test-skip-smuggling",
                            severity="P0",
                            text=s,
                            message=f"Focus filter (`only`/`fit`/`fdescribe`) added in '{rel_path}:{ln}' silently skips the rest of the test suite.",
                        )
                    )
            elif SKIP_SMUGGLING_RE.search(s):
                # Allow if accompanied by an issue reference (#123, JIRA-123) or if t.Skip is inside testing.Short()
                has_issue = bool(ISSUE_REF_RE.search(s) or ISSUE_REF_RE.search(prev_raw))
                is_env_guard = bool(
                    re.search(r"\b(?:testing\.Short\(\)|os\.Getenv\b|sys\.platform\b|os\.environ\.get\b)", prev_raw + " " + s)
                )
                if not has_issue and not is_env_guard and not cfg.is_exempt(rel_path, "test-skip-smuggling"):
                    findings.append(
                        Finding(
                            path=rel_path,
                            line=ln,
                            rule="test-skip-smuggling",
                            severity="P0",
                            text=s,
                            message=(
                                f"Unjustified test skip added in '{rel_path}:{ln}' without an issue reference "
                                f"(e.g. `#123` or `PROJ-456`)."
                            ),
                        )
                    )

            # 2. Suppression Comment Smuggling
            for sup_kind, sup_re in SUPPRESSION_PATTERNS:
                if sup_re.search(s):
                    if not _has_suppression_justification(sup_kind, s, prev_raw):
                        if not cfg.is_exempt(rel_path, "suppression-comment-smuggling"):
                            findings.append(
                                Finding(
                                    path=rel_path,
                                    line=ln,
                                    rule="suppression-comment-smuggling",
                                    severity="P1",
                                    text=s,
                                    message=(
                                        f"Suppression directive (`{sup_kind}`) added in '{rel_path}:{ln}' without an inline "
                                        f"justification (`-- reason`) or issue reference (`#123`)."
                                    ),
                                )
                            )
                    break

            # 3. Unsafe Type Cast Cascade (in production non-test files)
            if not is_test and not s.startswith(("#", "//", "/*", "*")):
                # Strip inline comment before checking code syntax
                code_part = re.sub(r"(?://|#).*$", "", s)
                unsafe_hit = False
                if sfx in (".ts", ".tsx", ".mts", ".cts") and TS_UNSAFE_CAST_RE.search(code_part):
                    unsafe_hit = True
                elif sfx == ".py" and PY_UNSAFE_CAST_RE.search(code_part):
                    unsafe_hit = True
                elif sfx == ".rs" and RS_UNSAFE_BLOCK_RE.search(code_part):
                    # Allow Rust `unsafe {` when preceded by `// SAFETY:` comment
                    if "safety:" not in prev_raw.lower() and "safety:" not in s.lower():
                        unsafe_hit = True
                elif sfx == ".go" and GO_UNSAFE_PTR_RE.search(code_part):
                    unsafe_hit = True

                if unsafe_hit and not cfg.is_exempt(rel_path, "unsafe-type-cast-cascade"):
                    findings.append(
                        Finding(
                            path=rel_path,
                            line=ln,
                            rule="unsafe-type-cast-cascade",
                            severity="P1",
                            text=s,
                            message=f"Unsafe type cast or `unsafe` block added in production file '{rel_path}:{ln}'.",
                        )
                    )

            # 4. Linter or CI Config Weakening
            if is_linter_cfg and not s.startswith(("#", "//")):
                if LINTER_WEAKENING_RE.search(s) and not cfg.is_exempt(rel_path, "linter-or-ci-config-weakening"):
                    findings.append(
                        Finding(
                            path=rel_path,
                            line=ln,
                            rule="linter-or-ci-config-weakening",
                            severity="P0",
                            text=s,
                            message=f"Linter or type-checker strictness weakened in '{rel_path}:{ln}': `{s}`.",
                        )
                    )
            elif is_ci_cfg and not s.startswith("#"):
                if CI_WEAKENING_RE.search(s) and not cfg.is_exempt(rel_path, "linter-or-ci-config-weakening"):
                    findings.append(
                        Finding(
                            path=rel_path,
                            line=ln,
                            rule="linter-or-ci-config-weakening",
                            severity="P0",
                            text=s,
                            message=f"CI workflow failure gate weakened in '{rel_path}:{ln}': `{s}`.",
                        )
                    )

        # 5-6. Coverage thresholds and PrufGate's own configuration
        for f in _coverage_findings(hunk, rel_path):
            if not cfg.is_exempt(rel_path, f.rule):
                findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Built-in --self-check fixture suite (30+ positive & negative cases)
# ---------------------------------------------------------------------------

SELF_CHECK_CASES: list[tuple[str, str, set[str]]] = [
    # --- 1. test-skip-smuggling (Positive & Negative across languages) ---
    (
        "ts-it-skip-unjustified-positive",
        """diff --git a/src/auth.test.ts b/src/auth.test.ts
--- a/src/auth.test.ts
+++ b/src/auth.test.ts
@@ -10,3 +10,3 @@
-it('rejects expired JWT', () => {
+it.skip('rejects expired JWT', () => {
   expect(verify(expired)).toBe(false);
 });
""",
        {"test-skip-smuggling"},
    ),
    (
        "ts-describe-only-focus-leak-positive",
        """diff --git a/src/auth.test.ts b/src/auth.test.ts
--- a/src/auth.test.ts
+++ b/src/auth.test.ts
@@ -1,3 +1,3 @@
-describe('Auth Suite', () => {
+describe.only('Auth Suite', () => {
""",
        {"test-skip-smuggling"},
    ),
    (
        "ts-xit-unjustified-positive",
        """diff --git a/src/auth.test.ts b/src/auth.test.ts
--- a/src/auth.test.ts
+++ b/src/auth.test.ts
@@ -5,2 +5,2 @@
-it('checks role', () => {
+xit('checks role', () => {
""",
        {"test-skip-smuggling"},
    ),
    (
        "ts-skip-with-issue-ref-negative",
        """diff --git a/src/auth.test.ts b/src/auth.test.ts
--- a/src/auth.test.ts
+++ b/src/auth.test.ts
@@ -10,3 +10,4 @@
+// Temporarily skipped pending upstream OAuth fix in issue #412
+it.skip('rejects expired JWT', () => {
""",
        set(),
    ),
    (
        "py-pytest-skip-unjustified-positive",
        """diff --git a/tests/test_billing.py b/tests/test_billing.py
--- a/tests/test_billing.py
+++ b/tests/test_billing.py
@@ -4,2 +4,3 @@
+@pytest.mark.skip
 def test_charge_webhook():
""",
        {"test-skip-smuggling"},
    ),
    (
        "py-pytest-xfail-unjustified-positive",
        """diff --git a/tests/test_billing.py b/tests/test_billing.py
--- a/tests/test_billing.py
+++ b/tests/test_billing.py
@@ -4,2 +4,3 @@
+@pytest.mark.xfail(reason="flaky right now")
 def test_charge_webhook():
""",
        {"test-skip-smuggling"},
    ),
    (
        "py-pytest-skip-with-ticket-negative",
        """diff --git a/tests/test_billing.py b/tests/test_billing.py
--- a/tests/test_billing.py
+++ b/tests/test_billing.py
@@ -4,2 +4,3 @@
+@pytest.mark.skip(reason="#209: Stripe sandbox maintenance window")
 def test_charge_webhook():
""",
        set(),
    ),
    (
        "go-t-skip-unjustified-positive",
        """diff --git a/pkg/db/store_test.go b/pkg/db/store_test.go
--- a/pkg/db/store_test.go
+++ b/pkg/db/store_test.go
@@ -8,2 +8,3 @@ func TestMigrationRollback(t *testing.T) {
+    t.Skip("skipping failing test")
""",
        {"test-skip-smuggling"},
    ),
    (
        "go-t-skip-short-guard-negative",
        """diff --git a/pkg/db/store_test.go b/pkg/db/store_test.go
--- a/pkg/db/store_test.go
+++ b/pkg/db/store_test.go
@@ -8,2 +8,4 @@ func TestMigrationRollback(t *testing.T) {
+    if testing.Short() {
+        t.Skip("skipping integration test in short mode")
+    }
""",
        set(),
    ),
    (
        "rust-ignore-unjustified-positive",
        """diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -20,2 +20,3 @@
+    #[ignore]
     #[test]
     fn test_raft_consensus() {
""",
        {"test-skip-smuggling"},
    ),
    (
        "java-disabled-unjustified-positive",
        """diff --git a/src/test/PaymentTest.java b/src/test/PaymentTest.java
--- a/src/test/PaymentTest.java
+++ b/src/test/PaymentTest.java
@@ -12,2 +12,3 @@
+    @Disabled
     @Test
     void refundsOrder() {
""",
        {"test-skip-smuggling"},
    ),
    # --- 2. suppression-comment-smuggling (Positive & Negative) ---
    (
        "ts-ignore-bare-positive",
        """diff --git a/src/router.ts b/src/router.ts
--- a/src/router.ts
+++ b/src/router.ts
@@ -14,2 +14,3 @@
+  // @ts-ignore
   return handler(req.invalidProp);
""",
        {"suppression-comment-smuggling"},
    ),
    (
        "ts-expect-error-bare-positive",
        """diff --git a/src/router.ts b/src/router.ts
--- a/src/router.ts
+++ b/src/router.ts
@@ -14,2 +14,3 @@
+  // @ts-expect-error
   return handler(req.invalidProp);
""",
        {"suppression-comment-smuggling"},
    ),
    (
        "ts-expect-error-explained-negative",
        """diff --git a/src/router.ts b/src/router.ts
--- a/src/router.ts
+++ b/src/router.ts
@@ -14,2 +14,3 @@
+  // @ts-expect-error -- upstream Express request typedef omits custom rawBody property
   return handler(req.rawBody);
""",
        set(),
    ),
    (
        "eslint-disable-bare-positive",
        """diff --git a/src/ui.tsx b/src/ui.tsx
--- a/src/ui.tsx
+++ b/src/ui.tsx
@@ -8,2 +8,3 @@
+  // eslint-disable-next-line react-hooks/exhaustive-deps
   useEffect(() => { load(); }, []);
""",
        {"suppression-comment-smuggling"},
    ),
    (
        "py-noqa-bare-positive",
        """diff --git a/src/service.py b/src/service.py
--- a/src/service.py
+++ b/src/service.py
@@ -10,2 +10,2 @@
-    eval(user_expr)
+    eval(user_expr)  # noqa: S307
""",
        {"suppression-comment-smuggling"},
    ),
    (
        "py-noqa-justified-negative",
        """diff --git a/src/service.py b/src/service.py
--- a/src/service.py
+++ b/src/service.py
@@ -1,2 +1,2 @@
+from prufgate.config import PrufGateConfig  # noqa: E402 -- sys.path bootstrap required before import
""",
        set(),
    ),
    (
        "py-type-ignore-bare-positive",
        """diff --git a/src/service.py b/src/service.py
--- a/src/service.py
+++ b/src/service.py
@@ -15,2 +15,2 @@
+    total: int = "not-an-int"  # type: ignore
""",
        {"suppression-comment-smuggling"},
    ),
    (
        "go-nolint-bare-positive",
        """diff --git a/pkg/api/handler.go b/pkg/api/handler.go
--- a/pkg/api/handler.go
+++ b/pkg/api/handler.go
@@ -22,2 +22,2 @@
+    _ = db.Close() //nolint:errcheck
""",
        {"suppression-comment-smuggling"},
    ),
    (
        "rust-allow-bare-positive",
        """diff --git a/src/main.rs b/src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,2 +1,3 @@
+#[allow(dead_code)]
 fn unused_helper() {}
""",
        {"suppression-comment-smuggling"},
    ),
    (
        "java-suppress-warnings-bare-positive",
        """diff --git a/src/main/App.java b/src/main/App.java
--- a/src/main/App.java
+++ b/src/main/App.java
@@ -5,2 +5,3 @@
+    @SuppressWarnings("unchecked")
     public List<String> getItems() {
""",
        {"suppression-comment-smuggling"},
    ),
    # --- 3. unsafe-type-cast-cascade (Positive & Negative) ---
    (
        "ts-as-unknown-as-positive",
        """diff --git a/src/billing.ts b/src/billing.ts
--- a/src/billing.ts
+++ b/src/billing.ts
@@ -18,2 +18,2 @@
-  return invoice;
+  return (invoice as unknown as ValidatedInvoice);
""",
        {"unsafe-type-cast-cascade"},
    ),
    (
        "ts-colon-any-positive",
        """diff --git a/src/billing.ts b/src/billing.ts
--- a/src/billing.ts
+++ b/src/billing.ts
@@ -18,2 +18,2 @@
+export function parseWebhook(payload: any) {
""",
        {"unsafe-type-cast-cascade"},
    ),
    (
        "ts-any-in-test-file-negative",
        """diff --git a/src/billing.test.ts b/src/billing.test.ts
--- a/src/billing.test.ts
+++ b/src/billing.test.ts
@@ -18,2 +18,2 @@
+  const badInput = { amount: 'invalid' } as any;
""",
        set(),
    ),
    (
        "py-cast-any-positive",
        """diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -12,2 +12,2 @@
+    return typing.cast(Any, raw_session)
""",
        {"unsafe-type-cast-cascade"},
    ),
    (
        "rust-unsafe-block-unjustified-positive",
        """diff --git a/src/buffer.rs b/src/buffer.rs
--- a/src/buffer.rs
+++ b/src/buffer.rs
@@ -9,2 +9,4 @@
+    unsafe {
+        *ptr = 42;
+    }
""",
        {"unsafe-type-cast-cascade"},
    ),
    (
        "rust-unsafe-block-with-safety-comment-negative",
        """diff --git a/src/buffer.rs b/src/buffer.rs
--- a/src/buffer.rs
+++ b/src/buffer.rs
@@ -9,2 +9,5 @@
+    // SAFETY: ptr is guaranteed non-null and aligned by slice bounds check above.
+    unsafe {
+        *ptr = 42;
+    }
""",
        set(),
    ),
    # --- 4. linter-or-ci-config-weakening (Positive & Negative) ---
    (
        "tsconfig-strict-false-positive",
        """diff --git a/tsconfig.json b/tsconfig.json
--- a/tsconfig.json
+++ b/tsconfig.json
@@ -3,3 +3,4 @@
   "compilerOptions": {
-    "strict": true,
+    "strict": false,
+    "noImplicitAny": false
   }
""",
        {"linter-or-ci-config-weakening"},
    ),
    (
        "pyproject-ruff-ignore-positive",
        """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -12,2 +12,3 @@
 [tool.ruff.lint]
+ignore = ["S", "E501", "F401"]
""",
        {"linter-or-ci-config-weakening"},
    ),
    (
        "eslintrc-rule-off-positive",
        """diff --git a/.eslintrc.json b/.eslintrc.json
--- a/.eslintrc.json
+++ b/.eslintrc.json
@@ -5,2 +5,3 @@
   "rules": {
+    "@typescript-eslint/no-explicit-any": "off"
   }
""",
        {"linter-or-ci-config-weakening"},
    ),
    (
        "ci-workflow-continue-on-error-positive",
        """diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -20,2 +20,3 @@
       - name: Run unit tests
+        continue-on-error: true
         run: npm test
""",
        {"linter-or-ci-config-weakening"},
    ),
    (
        "ci-workflow-or-true-positive",
        """diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -20,2 +20,2 @@
-        run: pytest
+        run: pytest || true
""",
        {"linter-or-ci-config-weakening"},
    ),
    (
        "tsconfig-strict-true-negative",
        """diff --git a/tsconfig.json b/tsconfig.json
--- a/tsconfig.json
+++ b/tsconfig.json
@@ -3,2 +3,3 @@
   "compilerOptions": {
+    "strict": true
   }
""",
        set(),
    ),    (
        "coverage-threshold-lowered-positive",
        """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -20,1 +20,1 @@ [tool.coverage.report]
-fail_under = 90
+fail_under = 50
""",
        {"coverage-threshold-lowering"},
    ),
    (
        "coverage-threshold-raised-negative",
        """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -20,1 +20,1 @@ [tool.coverage.report]
-fail_under = 50
+fail_under = 90
""",
        set(),
    ),
    (
        "prufgate-config-new-exemption-positive",
        """diff --git a/.prufgate/config.yaml b/.prufgate/config.yaml
--- a/.prufgate/config.yaml
+++ b/.prufgate/config.yaml
@@ -8,1 +8,2 @@ exempt:
   src/a.ts: { demo-named-data: "#3: seed data" }
+  src/pay.ts: { canned-error-fallback: "#9: later" }
""",
        {"prufgate-config-self-exemption"},
    ),
    (
        "prufgate-config-catch-all-exclude-positive",
        """diff --git a/.prufgate/config.yaml b/.prufgate/config.yaml
--- a/.prufgate/config.yaml
+++ b/.prufgate/config.yaml
@@ -1,1 +1,2 @@
 version: 1
+exclude: ["**"]
""",
        {"prufgate-config-self-exemption"},
    ),
    (
        "prufgate-config-added-pack-negative",
        """diff --git a/.prufgate/config.yaml b/.prufgate/config.yaml
--- a/.prufgate/config.yaml
+++ b/.prufgate/config.yaml
@@ -1,2 +1,3 @@
 packs:
   - core
+  - cti
""",
        set(),
    ),
]


def run_self_check() -> int:
    """Validate every built-in positive and negative diff-tampering fixture."""
    failures: list[str] = []
    cfg = PrufGateConfig()

    for case_id, diff_text, expected_rules in SELF_CHECK_CASES:
        findings = scan_diff_for_tampering(diff_text, config=cfg)
        actual_rules = {f.rule for f in findings}
        if actual_rules != expected_rules:
            failures.append(
                f"[{case_id}] expected rules {sorted(expected_rules)}, got {sorted(actual_rules)}"
            )

    total = len(SELF_CHECK_CASES)
    if failures:
        print(f"tamper_detector self-check FAILED ({len(failures)}/{total}):", file=sys.stderr)
        for fail in failures:
            print(f"  - {fail}", file=sys.stderr)
        return 1

    print(f"tamper_detector self-check: {total} case(s) ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--self-check" in args:
        return run_self_check()

    base_ref: str | None = None
    diff_file: str | None = None
    json_out: str | None = None
    config_path: str | None = None
    include_self = False

    for a in args:
        if a == "--changed":
            pass
        elif a.startswith("--changed=") or a.startswith("--base="):
            base_ref = a.split("=", 1)[1]
            if not base_ref or base_ref.startswith("-"):
                print(f"tamper_detector: refusing base ref {base_ref!r}", file=sys.stderr)
                return 2
        elif a.startswith("--diff-file="):
            diff_file = a.split("=", 1)[1]
        elif a.startswith("--json-out="):
            json_out = a.split("=", 1)[1]
        elif a.startswith("--config="):
            config_path = a.split("=", 1)[1]
        elif a == "--include-self":
            include_self = True
        else:
            print(
                f"usage: {sys.argv[0]} [--changed[=REF]] [--base=REF] [--diff-file=PATH] [--json-out=PATH] [--config=PATH] [--self-check]",
                file=sys.stderr,
            )
            return 2

    try:
        cfg = PrufGateConfig.load(Path.cwd(), config_path)
    except ConfigError as e:
        print(f"tamper_detector: {e}", file=sys.stderr)
        return 2

    if diff_file:
        try:
            diff_text = Path(diff_file).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"tamper_detector: cannot read --diff-file {diff_file}: {e.strerror or e}", file=sys.stderr)
            return 2
    else:
        try:
            diff_text = _get_git_diff(base_ref, cwd=Path.cwd(), strict=True)
        except GitDiffError as e:
            print(f"tamper_detector: git: {e}", file=sys.stderr)
            return 2

    findings = scan_diff_for_tampering(diff_text, config=cfg) if diff_text else []
    if not diff_file:
        findings = with_config_drift(findings, cfg, Path.cwd(), base_ref, config_path)
    if not include_self:
        findings = [f for f in findings if not is_internal_path(f.path)]

    debt_violations, debt_advisories = cfg.check_debt_ratchet(findings)

    if json_out:
        out_path = Path(json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2) + "\n", encoding="utf-8")

    for adv in debt_advisories:
        print(f"notice: {adv}", file=sys.stderr)

    if not findings and not debt_violations:
        print("tamper_detector: diff clean (0 tampering findings).")
        return 0

    for f in findings:
        print(f, file=sys.stderr)
    for v in debt_violations:
        print(f"error: {v}", file=sys.stderr)

    return 1


if __name__ == "__main__":
    sys.exit(main())
