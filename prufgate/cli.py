#!/usr/bin/env python3
"""PrufGate Unified CLI (`prufgate`).

Subcommands:
  - `prufgate check [path] [--changed] [--base REF] [--format text|json|sarif|agent-hook]`
  - `prufgate test-audit [path] [--changed] [--format text|json]`
  - `prufgate bola [path] [--url URL] [--token-a ...] [--token-b ...] [--static-only]`
  - `prufgate review [--base REF] [--diff-file PATH] [--format markdown|json|sarif|github|reviewdog] [--ai]`
  - `prufgate init [path] [--hooks] [--overwrite]`
  - `prufgate mcp`
  - `prufgate api [--host 127.0.0.1] [--port 8000]`
  - `prufgate fast` / `prufgate full` (shortcuts for `check --changed` / `check`)
  - `prufgate --self-check`

Exit codes: 0 clean, 1 blocking findings (P0/P1), 2 usage, configuration or engine error.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent))

import prufgate.contract_guard as cg_engine  # noqa: E402
from prufgate import PROJECT_URL, __version__  # noqa: E402
from prufgate.anti_fabrication import detector as af_detector  # noqa: E402
from prufgate.anti_reward_hacking import test_integrity as ti_engine  # noqa: E402
from prufgate.bola import bola_engine  # noqa: E402
from prufgate.config import ConfigError, PrufGateConfig, expand_rule_aliases, rules_match  # noqa: E402
from prufgate.diff_guard import tamper_detector as dg_engine  # noqa: E402
from prufgate.hooks.agent_hooks import HookConfigError, init_workspace  # noqa: E402
from prufgate.review import reviewer as rev_engine  # noqa: E402


def run_all_self_checks() -> int:
    """Execute built-in fixture verification across all 6 PrufGate core engines."""
    checks = [
        ("anti-fabrication", af_detector.self_check),
        ("test-integrity", ti_engine.run_self_check),
        ("diff-guard", dg_engine.run_self_check),
        ("contract-guard", cg_engine.run_self_check),
        ("bola-engine", bola_engine.run_self_check),
        ("review-engine", rev_engine.run_self_check),
    ]
    failed = 0
    for name, fn in checks:
        rc = fn()
        if rc != 0:
            print(f"[FAIL] {name} self-check exited with {rc}", file=sys.stderr)
            failed += 1
    if failed:
        return 1
    print("prufgate self-check: all 6 core engines passed.")
    return 0


def _collect_unified_findings(
    target_path: Path,
    changed_only: bool = False,
    base_ref: str | None = None,
    config_path: str | None = None,
) -> list[dict[str, Any]]:
    """Run Engines 1-5 on `target_path` and return normalized finding dicts.

    The engines read git and relative paths from the current directory, so the
    scan runs from the workspace root whatever directory `prufgate` was started in.
    """
    target_path = target_path.resolve()
    workspace = target_path if target_path.is_dir() else target_path.parent
    previous_cwd = Path.cwd()
    os.chdir(workspace)
    try:
        return _collect_in_workspace(workspace, target_path, changed_only, base_ref, config_path)
    finally:
        os.chdir(previous_cwd)


def _is_internal(engine: Any, path: str) -> bool:
    """PrufGate's own engine files, matched by whole path segments so a user's
    tests/test_cli.py is never skipped."""
    fn = getattr(engine, "is_internal_path", None)
    if fn is not None:
        return bool(fn(path))
    # Only PrufGate's own repository has these files; elsewhere nothing is internal.
    if not (Path("prufgate/cli.py").is_file() and Path("prufgate/anti_reward_hacking/test_integrity.py").is_file()):
        return False
    norm = "/" + str(path).replace("\\", "/").lstrip("./")
    return any(("/" + p.strip("/") + "/") in norm + "/" for p in getattr(engine, "INTERNAL_SCANNER_PATHS", ()) if "/" in p.strip("/"))


def _git_ok(*args: str) -> str | None:
    try:
        res = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return res.stdout


class BaseRefError(ConfigError):
    """No usable base ref: a changed-files scan would compare against nothing."""


def _commit(ref: str) -> str | None:
    out = _git_ok("rev-parse", "--verify", "-q", "--end-of-options", f"{ref}^{{commit}}")
    return out.strip() if out else None


def resolve_base_ref(explicit: str | None = None) -> str | None:
    """The base ref a changed-files scan diffs against, run from the workspace.

    Order: `explicit`, PRUFGATE_BASE_REF, origin/$GITHUB_BASE_REF; then, only when
    the working tree has no changes, origin/HEAD or HEAD~1, skipping a
    candidate that HEAD is not ahead of (so a clean default branch never
    compares with itself). Returns None when the working tree has changes and
    no base was given: the working-tree diff is scanned. Raises BaseRefError
    when there is nothing to compare: never an empty diff that reads as a pass.
    """
    head = _commit("HEAD")
    if head is None:
        raise BaseRefError("not a git repository with at least one commit: --changed has nothing to compare")
    ref = explicit or os.environ.get("PRUFGATE_BASE_REF") or (
        f"origin/{os.environ['GITHUB_BASE_REF']}" if os.environ.get("GITHUB_BASE_REF") else None
    )
    if ref:
        if ref.startswith("-") or _commit(ref) is None:
            raise BaseRefError(f"base ref {ref!r} is not a commit in this repository (shallow clone? fetch it first)")
        return ref
    dirty = _git_ok("diff", "--quiet", "HEAD") is None or bool(_git_ok("ls-files", "--others", "--exclude-standard"))
    if dirty:
        return None
    for candidate in ("origin/HEAD", "HEAD~1"):
        if _commit(candidate) is None:
            continue
        merge_base = _git_ok("merge-base", candidate, "HEAD")
        if merge_base and merge_base.strip() != head:
            return candidate
    raise BaseRefError(
        "the working tree is clean and no base ref is usable (set --base or PRUFGATE_BASE_REF; "
        "a shallow CI clone needs fetch-depth: 0)"
    )


def _collect_in_workspace(
    workspace: Path,
    target_path: Path,
    changed_only: bool,
    base_ref: str | None,
    config_path: str | None,
) -> list[dict[str, Any]]:
    cfg = PrufGateConfig.load(workspace, config_path)
    if changed_only:
        base_ref = resolve_base_ref(base_ref)

    unified: list[dict[str, Any]] = []

    # 1. Engine 1: Anti-Fabrication Detector
    af_settings = cfg.to_detector_settings()
    af_detector.apply_settings(af_settings)
    if changed_only:
        rel_targets = [f for f in af_detector.changed_files(base_ref) if Path(f).exists()]
        af_files = af_detector.collect(rel_targets) if rel_targets else []
    else:
        af_files = af_detector.collect([os.path.relpath(target_path, workspace)])

    for fpath in af_files:
        rel_f = os.path.normpath(str(fpath)).replace("\\", "/")
        if cfg.is_excluded(rel_f):
            continue
        for f in af_detector.scan_file(Path(rel_f)):
            if cfg.is_exempt(rel_f, f.rule):
                continue
            unified.append(
                {
                    "engine": "anti-fabrication",
                    "rule": f.rule,
                    "severity": "P0",
                    "file": rel_f,
                    "line": f.line,
                    "message": f"Fabrication pattern '{f.rule}': {f.text}",
                    "snippet": f.text,
                }
            )

    # 2. Engine 2: Anti-Reward-Hacking & Test Integrity
    if changed_only:
        diff_text = ti_engine._get_git_diff(base_ref, cwd=workspace)
        if diff_text:
            for df in ti_engine.scan_diff_for_reward_hacking(diff_text, repo_root=workspace, config=cfg):
                if not _is_internal(ti_engine, df.path):
                    unified.append(
                        {
                            "engine": "test-integrity",
                            "rule": df.rule,
                            "severity": df.severity,
                            "file": df.path,
                            "line": df.line,
                            "message": df.message,
                            "snippet": df.text,
                        }
                    )
        test_files = [
            p
            for p in ti_engine._changed_files(base_ref, cwd=workspace)
            if p.is_file() and ti_engine.is_test_file(p)
        ]
    else:
        if target_path.is_file():
            test_files = [target_path] if ti_engine.is_test_file(target_path) else []
        else:
            test_files = ti_engine._iter_test_files([target_path])

    for tf in test_files:
        try:
            rel_tf = str(tf.resolve().relative_to(workspace)).replace("\\", "/")
        except ValueError:
            rel_tf = str(tf).replace("\\", "/")
        if _is_internal(ti_engine, rel_tf):
            continue
        try:
            content = tf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for tf_finding in ti_engine.scan_test_file(tf, content, cfg):
            unified.append(
                {
                    "engine": "test-integrity",
                    "rule": tf_finding.rule,
                    "severity": tf_finding.severity,
                    "file": rel_tf,
                    "line": tf_finding.line,
                    "message": tf_finding.message,
                    "snippet": tf_finding.text,
                }
            )

    # 3. Engine 3: Diff-Scoped Tampering Guard (when git diff is available)
    diff_for_dg = dg_engine._get_git_diff(base_ref, cwd=workspace)
    dg_findings = dg_engine.scan_diff_for_tampering(diff_for_dg, config=cfg) if diff_for_dg else []
    # The configuration in effect, compared by value with the one at the base.
    dg_findings = dg_engine.with_config_drift(dg_findings, cfg, workspace, base_ref, config_path)
    if dg_findings:
        for dgf in dg_findings:
            if not _is_internal(dg_engine, dgf.path):
                unified.append(
                    {
                        "engine": "diff-guard",
                        "rule": dgf.rule,
                        "severity": dgf.severity,
                        "file": dgf.path,
                        "line": dgf.line,
                        "message": dgf.message,
                        "snippet": dgf.text,
                    }
                )

    # 4. Engine 4: Ghost Dependency, API Contract & Env Drift Guard
    if target_path.is_dir():
        for cgf in cg_engine.scan_contract_guard(workspace, changed_only=changed_only, config=cfg, base=base_ref or None):
            unified.append(
                {
                    "engine": "contract-guard",
                    "rule": cgf.rule,
                    "severity": cgf.severity,
                    "file": cgf.path,
                    "line": cgf.line,
                    "message": cgf.message,
                    "snippet": cgf.text,
                }
            )

    # 5. Engine 5: Static Multi-Tenant BOLA Verification
    if target_path.is_dir():
        with redirect_stdout(io.StringIO()):
            bola_findings = bola_engine.run_static_matrix_audit(workspace, config=cfg)
        for bf in bola_findings:
            unified.append(
                {
                    "engine": "bola",
                    "rule": bf.rule_id,
                    "severity": bf.severity,
                    "file": bf.endpoint_or_file,
                    "line": bf.line,
                    "message": bf.message,
                    "snippet": bf.details,
                }
            )

    # Deduplicate by (file, line, rule)
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for item in unified:
        # Aliases of one rule (old and new IDs) are one finding.
        key = (str(item["file"]), int(item["line"]), min(expand_rule_aliases(str(item["rule"]))))
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    # known_debt ceilings: a breach is a blocker; findings within a ceiling are tracked debt.
    violations, advisories = cfg.check_debt_ratchet(deduped)
    for adv in advisories:
        print(f"notice: {adv}", file=sys.stderr)
    if violations:
        for v in violations:
            deduped.append(
                {
                    "engine": "config",
                    "rule": "debt-ceiling-breached",
                    "severity": "P0",
                    "file": str(cfg.source_path.relative_to(workspace)) if cfg.source_path else ".prufgate/config.yaml",
                    "line": 1,
                    "message": v,
                    "snippet": "",
                }
            )
    elif cfg.known_debt_ceilings:
        # A loosened configuration is never debt: the configuration under review sets the ceilings.
        deduped = [
            f
            for f in deduped
            if f["rule"] == "prufgate-config-self-exemption"
            or not any(rules_match(str(f["rule"]), r) for r in cfg.known_debt_ceilings)
        ]
    return deduped


def _format_sarif_findings(findings: list[dict[str, Any]]) -> str:
    results = []
    for f in findings:
        sev = str(f.get("severity", "P1")).upper()
        level = "error" if sev in ("P0", "P1") else "warning"
        results.append(
            {
                "ruleId": str(f.get("rule", "prufgate-finding")),
                "level": level,
                "message": {"text": f"[{sev}] ({f.get('engine', 'prufgate')}) {f.get('message', '')}"},
                "properties": {"severity": sev, "engine": str(f.get("engine", "prufgate"))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f.get("file", "workspace"))},
                            "region": {"startLine": max(1, int(f.get("line", 1)))},
                        }
                    }
                ],
            }
        )
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "prufgate",
                        "version": __version__,
                        "informationUri": os.environ.get("PRUFGATE_INFO_URI", PROJECT_URL),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _stop_hook_active() -> bool:
    """True when a coding agent's Stop hook input says it is already continuing
    because of a stop hook (the documented loop guard)."""
    if sys.stdin is None or sys.stdin.isatty():
        return False
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except (ValueError, OSError):
        return False
    return isinstance(data, dict) and data.get("stop_hook_active") is True


def _cmd_check(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"prufgate check: path does not exist: {args.path}", file=sys.stderr)
        return 2

    try:
        findings = _collect_unified_findings(
            target,
            changed_only=args.changed,
            base_ref=args.base,
            config_path=args.config,
        )
    except (ConfigError, af_detector.SettingsError) as exc:
        print(f"prufgate check: {exc}", file=sys.stderr)
        return 2
    except SystemExit as exc:
        # An engine gave up (for example --changed outside a git repository).
        print(f"prufgate check: an engine stopped the scan (exit {exc.code})", file=sys.stderr)
        return 2
    except Exception as exc:  # an engine crash must never read as a pass
        print(f"prufgate check: engine error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2

    blockers = [f for f in findings if f["severity"] in ("P0", "P1")]

    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif args.format == "sarif":
        print(_format_sarif_findings(findings))
    elif args.format == "agent-hook":
        if blockers:
            print(
                f"PrufGate Agent Guardrail blocked completion ({len(blockers)} blocker finding(s)):",
                file=sys.stderr,
            )
            for b in blockers:
                print(
                    f"  - [{b['severity']}] {b['file']}:{b['line']} ({b['rule']}): {b['message']}",
                    file=sys.stderr,
                )
            print(
                "Fix the fabricated logic, hollow test, or unscoped BOLA query above before finishing.",
                file=sys.stderr,
            )
            return 2
        return 0
    else:
        if not findings:
            print("✔ PrufGate check passed: 0 findings across Engines 1-5.")
            return 0
        print(f"✖ PrufGate check detected {len(findings)} finding(s) ({len(blockers)} blocker(s)):")
        for f in findings:
            print(f"  [{f['severity']}] [{f['engine']}:{f['rule']}] {f['file']}:{f['line']} — {f['message']}")

    return 1 if blockers else 0


def _cmd_test_audit(args: argparse.Namespace) -> int:
    cli_args: list[str] = []
    if args.changed:
        cli_args.append(f"--changed={args.base}" if args.base else "--changed")
    if args.config:
        cli_args.append(f"--config={args.config}")
    if args.json_out:
        cli_args.append(f"--json-out={args.json_out}")
    # The engine reads git and the config from the current directory: run it
    # from the workspace so `prufgate test-audit /path --changed` works anywhere.
    target = Path(args.path or ".").resolve()
    workspace = target if target.is_dir() else target.parent
    if args.path:
        cli_args.append(os.path.relpath(target, workspace))
    previous = Path.cwd()
    os.chdir(workspace)
    try:
        return ti_engine.main(cli_args)
    finally:
        os.chdir(previous)


def _cmd_bola(args: argparse.Namespace) -> int:
    old_env: dict[str, str | None] = {}
    env_overrides = {
        "PRUFGATE_TEST_PROBE_TOKEN_A": args.token_a,
        "PRUFGATE_TEST_PROBE_TOKEN_B": args.token_b,
        "PRUFGATE_TEST_PROBE_TENANT_A_ID": args.tenant_a,
        "PRUFGATE_TEST_PROBE_TENANT_B_ID": args.tenant_b,
    }
    for k, val in env_overrides.items():
        if val is not None:
            old_env[k] = os.environ.get(k)
            os.environ[k] = val

    try:
        ws = Path(args.path).resolve()
        cfg = PrufGateConfig.load(ws, args.config)
        findings: list[bola_engine.BolaFinding] = []
        if not args.static_only and args.url:
            if not bola_engine.check_server_active(args.url):
                print(f"prufgate bola: {args.url} is not reachable; the live probe did not run.", file=sys.stderr)
                return 2
            with redirect_stdout(sys.stderr):
                findings.extend(bola_engine.run_dynamic_matrix(args.url, workspace=ws, config=cfg))
        if ws.exists():
            with redirect_stdout(io.StringIO()):
                findings.extend(bola_engine.run_static_matrix_audit(ws, config=cfg))

        if args.format == "json":
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            if not findings:
                print("✔ PrufGate BOLA verification passed: 0 findings.")
            else:
                print(f"✖ PrufGate BOLA verification found {len(findings)} issue(s):")
                for f in findings:
                    print(f"  [{f.severity}] [{f.rule_id}] {f.endpoint_or_file}:{f.line} — {f.message}")
        return 1 if any(f.severity in ("P0", "P1") for f in findings) else 0
    except ConfigError as exc:
        print(f"prufgate bola: {exc}", file=sys.stderr)
        return 2
    finally:
        for k, prev in old_env.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


def _cmd_review(args: argparse.Namespace) -> int:
    rev_args = [f"--workspace={args.workspace}", f"--format={args.format}"]
    if args.base:
        rev_args.append(f"--base={args.base}")
    if args.diff_file:
        rev_args.append(f"--diff-file={args.diff_file}")
    if args.ai:
        rev_args.append("--ai")
        rev_args.append(f"--ai-provider={args.ai_provider}")
    return rev_engine.main(rev_args)


def _cmd_init(args: argparse.Namespace) -> int:
    ws = Path(args.path).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    try:
        written = init_workspace(ws, install_hooks=args.hooks, overwrite=args.overwrite)
    except HookConfigError as exc:
        print(f"prufgate init: {exc}", file=sys.stderr)
        return 2
    if written:
        print(f"✔ Initialized PrufGate workspace in {ws}:")
        for rel in written:
            print(f"  - {rel}")
    else:
        print(f"✔ PrufGate configuration already exists in {ws} (pass --overwrite to replace).")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)

    if "--self-check" in raw_args or (raw_args and raw_args[0] == "self-check"):
        return run_all_self_checks()
    # Internal: `prufgate base-ref [path]` prints the base ref ./prufgate.sh should use
    # (empty line: scan the working-tree diff) or exits 2 when there is none.
    if raw_args and raw_args[0] == "base-ref":
        prev = Path.cwd()
        try:
            os.chdir(raw_args[1] if len(raw_args) > 1 else ".")
            print(resolve_base_ref() or "")
            return 0
        except (OSError, BaseRefError) as exc:
            print(f"prufgate: {exc}", file=sys.stderr)
            return 2
        finally:
            os.chdir(prev)
    # Shortcuts matching ./prufgate.sh: `prufgate fast` = check --changed, `prufgate full` = check.
    if raw_args and raw_args[0] == "fast":
        raw_args = ["check", "--changed", *raw_args[1:]]
    elif raw_args and raw_args[0] == "full":
        raw_args = ["check", *raw_args[1:]]

    parser = argparse.ArgumentParser(
        prog="prufgate",
        description="PrufGate — checks code for fabricated logic, hollow tests, guardrail tampering and BOLA.",
        epilog="Exit codes: 0 clean, 1 blocking findings (P0/P1), 2 usage, configuration or engine error.",
    )
    parser.add_argument("--self-check", action="store_true", help="Run built-in fixture verification across all engines")
    parser.add_argument("--version", action="version", version=f"prufgate {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand")

    # 1. prufgate check
    p_check = subparsers.add_parser("check", help="Scan workspace or changed files across Engines 1-5")
    p_check.add_argument("path", nargs="?", default=".", help="Workspace or file path to scan")
    p_check.add_argument("--changed", action="store_true", help="Scan only uncommitted or branch-changed files")
    p_check.add_argument("--base", default=None, help="Base git ref when using --changed (e.g. origin/main)")
    p_check.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    p_check.add_argument(
        "--format",
        choices=("text", "json", "sarif", "agent-hook"),
        default="text",
        help="Output format (default: text)",
    )

    # 2. prufgate test-audit
    p_test = subparsers.add_parser("test-audit", help="Audit test suite integrity & anti-reward-hacking (Engine 2)")
    p_test.add_argument("path", nargs="?", default=None, help="Test file or directory to audit")
    p_test.add_argument("--changed", action="store_true", help="Scan only changed test files and diff hunks")
    p_test.add_argument("--base", default=None, help="Base git ref when using --changed")
    p_test.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    p_test.add_argument("--json-out", default=None, help="Write JSON findings to file")

    # 3. prufgate bola
    p_bola = subparsers.add_parser("bola", help="Run static + optional live 2-token BOLA verification (Engine 5)")
    p_bola.add_argument("path", nargs="?", default=".", help="Workspace path to scan")
    p_bola.add_argument("--url", default=None, help="Live target URL for 2-token differential HTTP probing")
    p_bola.add_argument("--token-a", default=None, help="Bearer token for Tenant A")
    p_bola.add_argument("--token-b", default=None, help="Bearer token for Tenant B")
    p_bola.add_argument("--tenant-a", default=None, help="Resource/Tenant ID for Tenant A")
    p_bola.add_argument("--tenant-b", default=None, help="Resource/Tenant ID for Tenant B")
    p_bola.add_argument("--static-only", action="store_true", help="Run only static route & query scoping checks")
    p_bola.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    p_bola.add_argument("--format", choices=("text", "json"), default="text")

    # 4. prufgate review
    p_rev = subparsers.add_parser("review", help="Run deterministic + optional BYO-AI PR diff review (Engine 6)")
    p_rev.add_argument("--workspace", default=".", help="Workspace path")
    p_rev.add_argument("--base", default=None, help="Base git ref for diff analysis (default: origin/main)")
    p_rev.add_argument("--diff-file", default=None, help="Explicit unified diff file to review")
    p_rev.add_argument(
        "--format",
        choices=("markdown", "json", "sarif", "github", "reviewdog"),
        default="markdown",
        help="Review output format",
    )
    p_rev.add_argument("--ai", action="store_true", help="Delegate semantic diff review to local agent CLI or LLM API")
    p_rev.add_argument("--ai-provider", default="auto", help="AI provider (auto, claude, opencode, codex, gemini, openai, anthropic, ollama)")

    # 5. prufgate init
    p_init = subparsers.add_parser("init", help="Initialize .prufgate/config.yaml and coding agent stop hooks")
    p_init.add_argument("path", nargs="?", default=".", help="Workspace directory to initialize")
    p_init.add_argument("--hooks", action="store_true", help="Generate Claude Code, Cursor, and pre-commit hooks")
    p_init.add_argument("--overwrite", action="store_true", help="Overwrite existing config/hook files")

    # 6. prufgate mcp
    subparsers.add_parser("mcp", help="Start PrufGate Model Context Protocol (MCP) stdio server")

    # 7. prufgate api
    p_api = subparsers.add_parser("api", help="Start PrufGate REST API server")
    p_api.add_argument("--host", default=os.environ.get("PRUFGATE_API_HOST", "127.0.0.1"))
    p_api.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(raw_args)

    if args.subcommand == "check":
        if args.format != "agent-hook":
            return _cmd_check(args)
        # Coding-agent Stop hook: any failure blocks (exit 2, the code agents
        # treat as blocking), except when the agent is already continuing
        # because of this hook: then report and let it stop, never loop.
        active = _stop_hook_active()
        try:
            rc = _cmd_check(args)
        except Exception as exc:
            print(f"prufgate: the check could not run: {exc.__class__.__name__}: {exc}", file=sys.stderr)
            rc = 2
        if rc == 0:
            return 0
        if active:
            print("prufgate: stop_hook_active is set; reporting without blocking a second time.", file=sys.stderr)
            return 0
        return 2
    if args.subcommand == "test-audit":
        return _cmd_test_audit(args)
    if args.subcommand == "bola":
        return _cmd_bola(args)
    if args.subcommand == "review":
        return _cmd_review(args)
    if args.subcommand == "init":
        return _cmd_init(args)
    if args.subcommand == "mcp":
        from prufgate.mcp.prufgate_mcp_server import main as mcp_main

        mcp_main()
        return 0
    if args.subcommand == "api":
        from prufgate.api.server import run_server

        run_server(host=args.host, port=args.port)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
