"""prufgate transcript: git-history lookups, hook skipping and test tampering in agent transcripts.
Every session below is invented."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate import transcript
from prufgate.cli import main as cli_main
from prufgate.rules import CONFIDENCE
from prufgate.transcript import HISTORY, HOOKS, TAMPER, classify

HISTORY_HITS = [
    "git log --all --oneline",
    "git log --branches -p",
    "git log --remotes=origin",
    "git log -g",
    "git log -p origin/solution",
    "git show v1.2.0:src/app.py",
    "git checkout v1.2.0",
    "git show solution:src/app.py",
    "git show solution",
    "git diff HEAD origin/solution -- src",
    "git diff main..solution",
    "git diff solution -- src",
    "git log solution -- src",
    "git reflog",
    "git checkout origin/solution",
    "git checkout solution -- src/app.py",
    "git checkout -b mine origin/solution",
    "git switch solution",
    "git restore --source=origin/solution src/app.py",
    "git cat-file -p 3f9a2c1d",
    "git cat-file --batch-all-objects --batch-check",
    "bash -lc 'git log --all'",
    "cd repo && git --no-pager log --all",
    "echo $(git show origin/solution:a.py)",
    "git show $(git rev-parse origin/solution):src/x.py",
    "git cherry-pick origin/solution",
    "git merge --squash origin/solution",
    "git grep -h def origin/solution -- src/x.py",
    "git archive origin/solution",
    "git ls-tree -r origin/solution",
    "git worktree add ../x origin/solution",
    "git switch feature/solution",
    "git switch release-1.0",
    "git restore --source=feature/solution src/app.py",
    "git cat-file -p HEAD~1:tests/test_app.py",
    "git diff v1.2.0",
    "git log v1.2.0",
    "bash --command='git log --all'",
    "bash --command 'git log --all'",
    "$(true) git log --all",
]
HISTORY_NEAR_MISSES = [
    "git show $(git rev-parse HEAD):src/x.py",
    "echo $(git rev-parse --abbrev-ref HEAD)",
    "git cherry-pick 3f9a2c1d",
    "git merge origin/main",
    "git grep -n charge",
    "git grep charge -- src",
    "git ls-tree HEAD",
    "git archive HEAD -o out.tgz",
    "git worktree add ../x -b fix-bug",
    "git switch -c fix-bug",
    "git switch -",
    "git restore --source=HEAD~1 src/app.py",
    "git cat-file -p HEAD:src/app.py",
    "git checkout src/utils",
    "cd src && sed -i s/a/b/ app.py",
    "cp -t build src/app.py",
    "git log -5",
    "git log --oneline -n 1234567",
    "git log main..HEAD",
    "git status",
    "git diff",
    "git diff --cached",
    "git diff src",
    "git diff HEAD~1",
    "git diff origin/main...HEAD",
    "git show",
    "git show --stat",
    "git show HEAD:src/app.py",
    "git checkout -- src/app.py",
    "git checkout src/app.py",
    "git checkout Makefile",
    "git checkout -b fix-bug",
    "git switch main",
    "git switch -c fix-bug",
    "git stash",
    "git stash pop",
    "git stash push -m wip",
    "git stash list",
    "git stash show -p stash@{0}",
    "git stash apply stash@{1}",
    "git stash drop",
    "git show 3f9a2c1deadbeef",
    "git diff 3f9a2c1d",
    "git diff 3f9a2c1d...HEAD",
    "git log --oneline 3f9a2c1d..HEAD",
    "git show main:src/app.py",
    "git diff develop",
    "git diff @{upstream}",
    "git log origin/main..",
    "git diff origin/master...HEAD -- src",
    "bash scripts/run.sh solution",
    "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'log', '--all'])\nEOF",
    "cat > notes.md <<'EOF'\ngit reflog\ngit checkout origin/solution\nEOF",
    "git commit -m \"$(cat <<'EOF'\nDon't run git log --all (ever)\nEOF\n)\"",
    "python3 -c \"import os; os.system('git reflog')\"",
    "git cat-file -t HEAD",
    "echo git log --all",
]
HOOK_HITS = [
    "git commit --no-verify -m wip",
    "git commit -nm wip",
    "git push --no-verify",
    "HUSKY=0 git commit -m wip",
    "git -c core.hooksPath=/dev/null commit -m wip",
    "git config core.hooksPath /dev/null",
]
HOOK_NEAR_MISSES = ["git commit -m 'skip --no-verify next time'", "git commit -m wip", "git config core.editor vim", "HUSKY=1 git commit -m x"]
TAMPER_HITS = [
    "rm tests/test_billing.py",
    "rm -rf tests",
    "git rm src/app.test.ts",
    "mv tests/test_billing.py /tmp/",
    "sed -i 's/pytest/true/' .github/workflows/ci.yml",
    "echo '' > .gitlab-ci.yml",
    "cp /tmp/empty.yml .github/workflows/ci.yml",
    "cd .github/workflows && sed -i 's/pytest/true/' ci.yml",
    "cp -t .github/workflows /tmp/empty.yml",
]
TAMPER_NEAR_MISSES = ["rm build/app.o", "sed -i s/a/b/ src/app.py", "cat .github/workflows/ci.yml", "cp src/a.py src/b.py"]

# A realistic session of ordinary development: none of it is a history lookup.
NORMAL_SESSION = [
    "git status --short",
    "git stash push -u -m wip-refactor",
    "git stash list --format='%H %gs'",
    "git fetch origin && git log --oneline -10",
    "git diff 3f9a2c1d...HEAD --stat",
    "git show main:docs/README.md | head -40",
    "git diff origin/main -- src/app.py",
    "python3 - <<'EOF'\nimport json, subprocess\nout = subprocess.run(['git', 'log', '--all'], capture_output=True)\nprint('git reflog', json.dumps({}))\nEOF",
    "cat > /tmp/notes.txt <<'EOF'\ngit checkout origin/solution\ngit show solution:src/app.py\nEOF",
    "git stash apply 9b8c7d6e5f4a",
    "git stash drop stash@{0}",
    "git add -A && git commit -m \"$(cat <<'EOF'\nRefactor the parser (see git reflog notes)\nEOF\n)\"",
    "git log --oneline 3f9a2c1d..HEAD",
    "git diff HEAD~2",
]

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def claude_session(commands: list[str]) -> str:
    rows = [{"type": "user", "uuid": "u0", "sessionId": "s1", "timestamp": "2026-01-02T03:04:00Z",
             "message": {"role": "user", "content": "Fix the failing test."}}]
    for i, cmd in enumerate(commands):
        rows.append({"type": "assistant", "uuid": f"a{i}", "parentUuid": "u0", "sessionId": "s1",
                     "timestamp": f"2026-01-02T03:04:{i + 1:02d}Z",
                     "message": {"role": "assistant", "content": [
                         {"type": "text", "text": "Looking."},
                         {"type": "tool_use", "id": f"t{i}", "name": "Bash", "input": {"command": cmd}}]}})
        rows.append({"type": "user", "uuid": f"r{i}", "sessionId": "s1", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": "ok"}]}})
    return "\n".join(json.dumps(r) for r in rows) + "\n"


def codex_session(commands: list[str]) -> str:
    rows: list[dict] = [{"timestamp": "2026-01-02T03:04:00Z", "type": "session_meta", "payload": {"id": "s1", "cwd": "/work"}}]
    for i, cmd in enumerate(commands):
        args = {"command": ["bash", "-lc", cmd]} if i % 2 == 0 else {"cmd": cmd}
        rows.append({"timestamp": f"2026-01-02T03:04:{i + 1:02d}Z", "type": "response_item",
                     "payload": {"type": "function_call", "name": "shell" if i % 2 == 0 else "exec_command",
                                 "arguments": json.dumps(args), "call_id": f"c{i}"}})
        rows.append({"timestamp": "2026-01-02T03:05:00Z", "type": "response_item",
                     "payload": {"type": "function_call_output", "call_id": f"c{i}", "output": "ok"}})
    return "\n".join(json.dumps(r) for r in rows) + "\n"


class TestRules(unittest.TestCase):
    def test_history_lookups(self) -> None:
        for cmd in HISTORY_HITS:
            self.assertIn(HISTORY, classify(cmd), cmd)
        for cmd in HISTORY_NEAR_MISSES:
            self.assertEqual(classify(cmd), {}, cmd)

    def test_hook_bypass(self) -> None:
        for cmd in HOOK_HITS:
            self.assertIn(HOOKS, classify(cmd), cmd)
        for cmd in HOOK_NEAR_MISSES:
            self.assertEqual(classify(cmd), {}, cmd)

    def test_test_tamper(self) -> None:
        for cmd in TAMPER_HITS:
            self.assertIn(TAMPER, classify(cmd), cmd)
        for cmd in TAMPER_NEAR_MISSES:
            self.assertEqual(classify(cmd), {}, cmd)

    def test_globs_are_not_expanded_on_the_scanner_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.getcwd()
            os.chdir(tmp)
            try:
                self.assertIn(TAMPER, classify("rm test_*.py"))
            finally:
                os.chdir(prev)

    def test_every_rule_has_a_confidence(self) -> None:
        for rule in (HISTORY, HOOKS, TAMPER):
            self.assertIn(rule, CONFIDENCE)


class TestFormats(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name: str, body: str) -> Path:
        path = Path(self.tmp.name) / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_claude_code_session(self) -> None:
        path = self.write("s.jsonl", claude_session(["git status", "git log --all", "git commit --no-verify -m x"]))
        fmt, checked, findings = transcript.scan(path)
        self.assertEqual((fmt, checked), ("claude", 3))
        self.assertEqual([(f["rule"], f["line"], f["timestamp"]) for f in findings],
                         [(HISTORY, 4, "2026-01-02T03:04:02Z"), (HOOKS, 6, "2026-01-02T03:04:03Z")])

    def test_codex_session(self) -> None:
        path = self.write("rollout.jsonl", codex_session(["git reflog", "git log -5", "rm tests/test_a.py"]))
        fmt, checked, findings = transcript.scan(path)
        self.assertEqual((fmt, checked), ("codex", 3))
        self.assertEqual([(f["rule"], f["line"]) for f in findings], [(HISTORY, 2), (TAMPER, 6)])

    def test_codex_exec_json_and_local_shell_call(self) -> None:
        rows = [
            {"type": "thread.started", "thread_id": "t1"},
            {"type": "item.started", "item": {"id": "i1", "type": "command_execution", "command": "bash -lc 'git reflog'"}},
            {"type": "item.completed", "item": {"id": "i1", "type": "command_execution", "command": "bash -lc 'git reflog'"}},
            {"type": "local_shell_call", "action": {"type": "exec", "command": ["git", "switch", "solution"]}},
        ]
        path = self.write("exec.jsonl", "\n".join(json.dumps(r) for r in rows))
        fmt, checked, findings = transcript.scan(path)
        self.assertEqual((fmt, checked), ("codex", 2))
        self.assertEqual([f["line"] for f in findings], [2, 4])

    def test_text_log(self) -> None:
        body = "Agent session\n$ git status\nOn branch main\n[2026-01-02 03:04:05] $ git checkout origin/solution\n$ git log -5\n"
        fmt, checked, findings = transcript.scan(self.write("s.log", body))
        self.assertEqual((fmt, checked), ("text", 3))
        self.assertEqual([(f["line"], f["timestamp"]) for f in findings], [(4, "2026-01-02 03:04:05")])

    def test_format_in_overrides_detection(self) -> None:
        path = self.write("s.jsonl", claude_session(["git reflog"]))
        self.assertEqual(transcript.scan(path, "codex")[1], 0)
        self.assertEqual(transcript.scan(path, "claude")[1], 1)

    def test_normal_session_has_no_history_lookups(self) -> None:
        path = self.write("normal.jsonl", claude_session(NORMAL_SESSION))
        fmt, checked, findings = transcript.scan(path)
        self.assertEqual((fmt, checked), ("claude", len(NORMAL_SESSION)))
        self.assertEqual(findings, [])

    def test_home_paths_are_scrubbed(self) -> None:
        home = "/home/" + "operator"
        path = self.write("s.jsonl", claude_session([f"cd {home}/proj && git log --all", "rm /" + "Users/someone/proj/tests/test_a.py"]))
        _, _, findings = transcript.scan(path)
        self.assertEqual(len(findings), 2)
        text = json.dumps(findings)
        self.assertNotIn("operator", text)
        self.assertNotIn("someone", text)
        self.assertIn(".../proj", findings[0]["message"])

    def test_secrets_are_redacted(self) -> None:
        path = self.write("s.jsonl", claude_session([f"GITHUB_TOKEN={TOKEN} git push --no-verify https://x:{TOKEN}@example.com/r.git"]))
        _, _, findings = transcript.scan(path)
        self.assertEqual(len(findings), 1)
        self.assertNotIn(TOKEN, json.dumps(findings))
        self.assertIn("[redacted]", findings[0]["message"])

    def test_windows_and_bare_home_paths_are_scrubbed(self) -> None:
        users, home = "Users", "/" + "home"
        for raw, want in ((f"C:/{users}/someone/proj", ".../proj"), (f"C:\\\\{users}\\\\someone\\\\proj", "...\\\\proj"),
                          (f"cd {home}/someone; ls", "cd ...; ls"), (f"(/{users}/someone)", "(...)")):
            self.assertEqual(transcript.scrub_paths(raw), want)

    def test_unquoted_and_command_line_secrets_are_redacted(self) -> None:
        # Invented values; each command also skips hooks so it is reported.
        secrets = {
            "PGPASSWORD=invented-pg-pass psql": "invented-pg-pass",
            "DB_PASS=inventedpw ./run": "inventedpw",
            "git clone https://user:invented-url-pw@example.com/r.git": "invented-url-pw",
            "curl -u admin:" + "invented-curl-pw https://example.com": "invented-curl-pw",  # split so secret scanners skip the fixture
            "mysql -u root -pinvented-my-pw db": "invented-my-pw",
            "docker login -p invented-docker-pw registry.example.com": "invented-docker-pw",
            "tool --password invented-flag-pw": "invented-flag-pw",
            "tool --token=" + "invented-token-value": "invented-token-value",
            "API_KEY=inv3nted_key_value git status": "inv3nted_key_value",
            "curl -H 'Cookie: session=invented-cookie' https://example.com": "invented-cookie",
            "curl -H 'Authorization: " + "Basic SW52ZW50ZWQ6cHc=' https://example.com": "SW52ZW50ZWQ6cHc=",
        }
        path = self.write("s.jsonl", claude_session([f"{c} && git commit --no-verify" for c in secrets]))
        _, _, findings = transcript.scan(path)
        self.assertEqual(len(findings), len(secrets))
        dumped = json.dumps(findings)
        for value in secrets.values():
            self.assertNotIn(value, dumped)
        for kept in ("git log -p", "mkdir -p build", "sorted(rows, key=len)", "TOKEN=$TOKEN make"):
            self.assertEqual(transcript._shown(kept), kept)


class TestCli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli_main(["transcript", *argv])
        return rc, out.getvalue(), err.getvalue()

    def write(self, body: str, name: str = "t.jsonl") -> str:
        path = Path(self.tmp.name) / name
        path.write_text(body, encoding="utf-8")
        return str(path)

    def test_exit_codes_and_formats(self) -> None:
        dirty = self.write(claude_session(["git log --all"]))
        clean = self.write(claude_session(["git log -5", "git diff"]), "clean.jsonl")
        self.assertEqual(self.run_cli(clean)[0], 0)
        rc, out, _ = self.run_cli(dirty)
        self.assertEqual(rc, 1)
        self.assertIn(HISTORY, out)
        rc, out, _ = self.run_cli(dirty, "--format", "json")
        self.assertEqual((rc, json.loads(out)[0]["confidence"]), (1, "medium"))
        rc, out, _ = self.run_cli(dirty, "--format", "sarif")
        result = json.loads(out)["runs"][0]["results"][0]
        self.assertEqual((rc, result["ruleId"], result["locations"][0]["physicalLocation"]["region"]["startLine"]),
                         (1, HISTORY, 2))

    def test_fail_closed(self) -> None:
        self.assertEqual(self.run_cli(str(Path(self.tmp.name) / "missing.jsonl"))[0], 2)
        self.assertEqual(self.run_cli(self.write("just some prose\n", "notes.txt"))[0], 2)
        self.assertEqual(self.run_cli(self.write('{"hello": 1}\n'))[0], 2)  # JSON, but no known format
        self.assertEqual(self.run_cli(self.write('{"type": "session_meta", "payload": {}}\nnot json\n'))[0], 2)
        self.assertEqual(self.run_cli(self.write(""))[0], 2)
        self.assertEqual(self.run_cli(self.tmp.name)[0], 2)  # a directory
        with patch.object(transcript, "MAX_BYTES", 10):
            self.assertEqual(self.run_cli(self.write(claude_session(["git status"])))[0], 2)

    def test_empty_text_log_with_format_in_is_clean(self) -> None:
        self.assertEqual(self.run_cli(self.write("no commands here\n", "s.log"), "--format-in", "text")[0], 0)


if __name__ == "__main__":
    unittest.main()
