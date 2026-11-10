"""Regression tests for execution, file-access and privacy boundaries.

All adversarial files and credential values below are invented fixtures. No
provider or live target is contacted by these tests.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prufgate.anti_fabrication import detector
from prufgate.api import server
from prufgate.bola import bola_engine
from prufgate.config import PrufGateConfig
from prufgate.hooks import adapters
from prufgate.hooks.agent_hooks import guard_command
from prufgate.mcp import prufgate_mcp_server as mcp
from prufgate.privacy import redact
from prufgate.process import git_command
from prufgate.review import ai_adapter, reviewer
from prufgate.safe_fs import safe_read_text, safe_write_text
from prufgate.synthesizer import parse_results

ROOT = Path(__file__).resolve().parent.parent


def git(root: Path, *args: str) -> None:
    subprocess.run(git_command(*args), cwd=root, check=True, capture_output=True)


def repository(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "-c", "user.name=Review", "-c", "user.email=review@example.com",
        "commit", "--allow-empty", "-qm", "base")


class ExecutionBoundary(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "the shell gate (prufgate.sh, runners/) needs a POSIX shell: on Windows use prufgate check, WSL or the container")
    @unittest.skipUnless(shutil.which("bash"), "shell runner needs bash")
    def test_manifest_helper_ignores_workspace_modules_and_pythonpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            for module in ("json", "datetime", "sitecustomize"):
                (ws / f"{module}.py").write_text(
                    "from pathlib import Path\nPath('executed.marker').write_text('unexpected')\n")
            env = dict(os.environ, WORKSPACE=str(ws), TOOL_ROOT=str(ROOT), PYTHONPATH=str(ws))
            env.pop("PRUFGATE_REPORTS_DIR", None)
            env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
            result = subprocess.run(
                ["bash", "-c", 'source "$TOOL_ROOT/runners/lib.sh"; '
                 'record_tool_status fixture security skipped 0 0 fixture'],
                cwd=ws, env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((ws / "reports/raw/execution_manifest.jsonl").read_text())
            self.assertEqual(manifest["tool"], "fixture")
            self.assertFalse((ws / "executed.marker").exists())

    def test_hook_uses_trusted_cli_despite_a_workspace_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            repository(ws)
            planted = ws / "prufgate"
            planted.mkdir()
            (planted / "__init__.py").write_text(
                "from pathlib import Path\nPath('executed.marker').write_text('unexpected')\n")
            (planted / "cli.py").write_text("raise SystemExit(0)\n")
            (ws / "sample.test.ts").write_text("test('checks output', () => { calculate(); });\n")
            with patch.dict(os.environ, {"PYTHONPATH": str(ws)}):
                code, message = adapters.run_check(str(ws))
            self.assertEqual(code, 2, message)
            self.assertIn("zero-assertion-test", message)
            self.assertFalse((ws / "executed.marker").exists())

    def test_api_fallback_uses_isolated_trusted_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(server, "PRUFGATE_ROOT", Path(tmp)):
                cmd, stdout_report = server.scan_command("fast", Path(tmp))
            self.assertTrue(stdout_report)
            self.assertEqual(cmd[:2], [sys.executable, "-I"])
            self.assertNotIn("-m", cmd)
            self.assertIn("--changed", cmd)

    @unittest.skipUnless(shutil.which("sh"), "generated hooks need a POSIX shell")
    def test_generated_hook_fallback_never_imports_a_workspace_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            planted = ws / "prufgate"
            planted.mkdir()
            (planted / "__init__.py").write_text(
                "from pathlib import Path\nPath('executed.marker').write_text('unexpected')\n")
            (planted / "cli.py").write_text("raise SystemExit(0)\n")
            env = dict(os.environ, PYTHONPATH=str(ws), PATH=os.pathsep.join([
                os.path.dirname(sys.executable), "/usr/bin", "/bin"]))
            result = subprocess.run(
                ["sh", "-c", guard_command("hook cursor shell", "blocked")],
                cwd=ws, env=env, input='{"command":"git status"}',
                text=True, capture_output=True, check=False,
            )
            self.assertFalse((ws / "executed.marker").exists())
            # A real installed module may answer; a missing installation must block.
            self.assertIn(result.returncode, (0, 2))
            if result.returncode == 0:
                self.assertEqual(json.loads(result.stdout)["permission"], "allow")
            else:
                self.assertIn("not installed", result.stderr)

    def test_git_configuration_cannot_start_fsmonitor(self):
        if sys.platform == "win32":
            self.skipTest("the fixture monitor is a POSIX script")
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            repository(ws)
            monitor = ws / "monitor.sh"
            monitor.write_text("#!/bin/sh\nprintf unexpected > executed.marker\nprintf 'token\\0'\n")
            monitor.chmod(0o755)
            git(ws, "config", "core.fsmonitor", str(monitor))
            self.assertIn("monitor.sh", reviewer.get_git_diff("HEAD", ws))
            self.assertEqual(detector.changed_files(cwd=ws), ["monitor.sh"])
            self.assertFalse((ws / "executed.marker").exists())


class FileBoundary(unittest.TestCase):
    def link(self, target: Path, link: Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except (OSError, NotImplementedError) as exc:
            if sys.platform == "win32":
                self.skipTest(f"symlink unavailable: {exc.__class__.__name__}")
            raise

    def test_source_symlink_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            outside = root / "outside.tsx"
            outside.write_text('<button onClick={() => {}}>Save</button>\n')
            link = ws / "widget.tsx"
            self.link(outside, link)
            with self.assertRaises(detector.ScanError):
                detector.scan_file(link, ws)
            self.assertEqual(len(detector.scan_file(outside, root)), 1)

    def test_explicit_read_root_allows_only_contained_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            inside = ws / "inside.txt"
            inside.write_text("inside")
            outside = root / "outside.txt"
            outside.write_text("outside")
            self.link(inside, ws / "inside-link")
            self.link(outside, ws / "outside-link")
            self.assertEqual(safe_read_text(ws / "inside-link", root=ws), "inside")
            with self.assertRaises(OSError):
                safe_read_text(ws / "outside-link", root=ws)

    def test_directory_link_cannot_redirect_a_read_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            (outside / "report.txt").write_text("preserve")
            self.link(outside, root / "reports")
            with self.assertRaises(OSError):
                safe_read_text(root / "reports/report.txt")
            with self.assertRaises(OSError):
                safe_write_text(root / "reports/report.txt", "replacement")
            self.assertEqual((outside / "report.txt").read_text(), "preserve")

    def test_reviewer_replaces_file_link_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            raw = ws / "reports/raw"
            raw.mkdir(parents=True)
            victim = root / "outside.txt"
            victim.write_text("preserve")
            self.link(victim, raw / "pr_review.md")
            diff = root / "empty.diff"
            diff.write_text("")
            with contextlib.redirect_stdout(io.StringIO()):
                code = reviewer.main(["--workspace", str(ws), "--diff-file", str(diff), "--format", "json"])
            self.assertEqual(code, 0)
            self.assertEqual(victim.read_text(), "preserve")
            self.assertFalse((raw / "pr_review.md").is_symlink())
            self.assertIn("No changed lines", (raw / "pr_review.md").read_text())

    def test_atomic_report_write_does_not_modify_a_hard_link_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "outside.txt"
            victim.write_text("preserve")
            try:
                os.link(victim, root / "report.txt")
            except OSError as exc:
                if sys.platform == "win32":
                    self.skipTest(f"hard links unavailable: {exc.__class__.__name__}")
                raise
            safe_write_text(root / "report.txt", "new report")
            self.assertEqual(victim.read_text(), "preserve")
            self.assertEqual((root / "report.txt").read_text(), "new report")

    def test_mcp_summary_never_reads_a_linked_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "workspace/reports"
            reports.mkdir(parents=True)
            victim = root / "outside.txt"
            victim.write_text("private fixture data")
            self.link(victim, reports / "prufgate-review.md")
            result = mcp.prufgate_summary(str(reports.parent))
            self.assertEqual(result["status"], "error")
            self.assertNotIn("private fixture data", json.dumps(result))


class PrivacyBoundary(unittest.TestCase):
    def test_gitleaks_match_is_removed_from_sarif_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = "invented-private-fixture-value"
            (root / "gitleaks.json").write_text(json.dumps([{
                "RuleID": "fixture-token", "Secret": secret, "Match": "token=" + secret,
                "Description": "fixture " + secret, "File": "src/config.py", "StartLine": 3,
            }]))
            findings = parse_results.parse_raw_results(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].line, 3)
            parse_results.generate_sarif(findings, root / "out.sarif", workspace_dir=root)
            parse_results.generate_markdown(findings, None, root / "out.md")
            self.assertNotIn(secret, (root / "out.sarif").read_text())
            self.assertNotIn(secret, (root / "out.md").read_text())

    def test_ai_prompt_and_reply_are_redacted_for_http_and_cli(self):
        secret = "invented-provider-fixture-value"
        reply = json.dumps([{"file": "src/handler.py", "line": 1, "severity": "P1",
                             "title": "Fixture finding", "message": "Value: " + secret}])
        for provider, function in (("openai", "_invoke_http_llm"), ("claude", "_invoke_cli_agent")):
            with self.subTest(provider=provider), patch.object(ai_adapter, "detect_ai_provider", return_value=provider), \
                    patch.object(ai_adapter, function, return_value=(True, reply)) as invoke, \
                    patch.dict(os.environ, {"FIXTURE_API_TOKEN": secret}):
                result = ai_adapter.review_diff_with_ai('+const token = "' + secret + '";')
                self.assertEqual(result.status, "executed")
                self.assertNotIn(secret, invoke.call_args.args[1])
                self.assertIn("[redacted]", invoke.call_args.args[1])
                self.assertEqual(len(result.comments), 1)
                self.assertNotIn(secret, json.dumps(result.comments))

    def test_shared_redaction_preserves_ordinary_code(self):
        ordinary = "const total = subtotal + tax;"
        self.assertEqual(redact(ordinary), ordinary)
        self.assertNotIn("invented-private-value", redact('api_key = "invented-private-value"'))

    def test_deep_file_paths_survive_redaction_and_long_segments_do_not(self):
        # Shaped like a macOS temporary folder: one run of 40+ characters across slashes.
        deep = "/var/folders/zz/q1w2e3r4t5y6u7i8o9p0_a0000gn/T/tmp9x8y7z6w/src/app.py"
        token = "Fx7q" * 12  # invented, 48 characters
        finding = parse_results.Finding("e", "r1", "P1", "m", deep, 2)
        self.assertEqual(finding.file_path, deep)
        with tempfile.TemporaryDirectory() as tmp:
            sarif = parse_results.generate_sarif([finding], Path(tmp) / "out.sarif")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["rawTarget"], deep)
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], deep.lstrip("/"))
        self.assertNotIn(token, parse_results.Finding("e", "r1", "P1", "m", f"/api/reset/{token}", 1).file_path)
        # Free text keeps the stricter rule: a base64 key with slashes is still one key.
        self.assertNotIn("K7MDENG", redact("key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"))

    def test_url_query_and_fragment_keep_the_full_secret_rules(self):
        # Invented: every segment is short, but the run across "/" is 48 characters.
        token = "Fx7q/" * 9 + "Fx7"
        for url in (f"https://api.example.com/v1/items?sig={token}", f"https://app.example.com/cb#{token}",
                    f"/v1/items?sig={token}"):
            with self.subTest(url=url):
                finding = parse_results.Finding("e", "r1", "P1", "m", url, 1)
                self.assertNotIn(token, finding.file_path)
                self.assertTrue(finding.file_path.startswith(url.split("?")[0].split("#")[0]))
                self.assertNotIn(token, bola_engine.BolaFinding("r", "P1", "m", url).endpoint_or_file)
                with tempfile.TemporaryDirectory() as tmp:
                    sarif = parse_results.generate_sarif([finding], Path(tmp) / "out.sarif")
                self.assertNotIn(token, json.dumps(sarif))
        self.assertNotIn("invented-pass", parse_results.Finding(
            "e", "r1", "P1", "m", "https://user:invented-pass@db.example.com/x?a=1", 1).file_path)

    def test_live_bola_does_not_store_response_bodies(self):
        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __init__(self, authenticated, url):
                self.authenticated = authenticated
                self.resource = url.rsplit("/", 1)[-1]

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                if self.authenticated:
                    return json.dumps({"resource": self.resource, "private": "invented-sensitive-response", "token": "invented-probe-token"}).encode()
                return b'{}'

        class Opener:
            def open(self, request, timeout):
                return Response(bool(request.get_header("Authorization")), request.full_url)

        env = {"PRUFGATE_TEST_PROBE_TOKEN_A": "invented-probe-token",
               "PRUFGATE_TEST_PROBE_TOKEN_B": "invented-other-token",
               "PRUFGATE_BOLA_PATHS": "/api/profile", "PRUFGATE_CROSS_TENANT_PATHS": "/api/{tenant_id}"}
        with patch.dict(os.environ, env), patch.object(bola_engine, "target_url_error", return_value=None), \
                patch.object(bola_engine, "discover_workspace_api_routes", return_value=[]), \
                patch.object(bola_engine.urllib.request, "build_opener", return_value=Opener()), \
                contextlib.redirect_stdout(io.StringIO()):
            findings = bola_engine.run_dynamic_matrix("https://example.com", config=PrufGateConfig())
        serialized = json.dumps([f.to_dict() for f in findings])
        self.assertTrue(findings)
        self.assertTrue(any(f.rule_id == "BOLA-CROSS-TENANT-ACCESS" for f in findings))
        self.assertNotIn("invented-sensitive-response", serialized)
        self.assertNotIn("invented-probe-token", serialized)


if __name__ == "__main__":
    unittest.main()
