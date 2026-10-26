"""`prufgate transcript`: suspicious commands in a coding agent's session transcript.

Reads a transcript after the fact and reports commands that copy an answer from git
history or get past checks:

- `transcript-history-lookup`: `git log --all/--branches/--remotes/-g`, `git reflog`,
  `git show` or `git diff` against a branch or tag other than the base, `git checkout`,
  `switch` or `restore --source` to another branch or tag, `git cat-file` on anything
  but HEAD, `git cherry-pick`, `merge`, `grep`, `archive`, `ls-tree` or `worktree add`
  with another branch or tag, and `$(git rev-parse <other branch>)` handed to any
  command. A commit hash, `HEAD~n`, the default branch and every `git stash` command
  are ordinary development and not reported.
- `transcript-hook-bypass`: `--no-verify`, `git commit -n`, `core.hooksPath`,
  `HUSKY=0`; the verdicts of the shell guard (`prufgate.hooks.shell_guard`).
- `transcript-test-tamper-command`: removing or moving tests or CI configuration
  (the shell guard), and editing CI configuration in place (`sed -i`, `tee`, `cp`).

Formats, detected from the content (`format_in` overrides):

- `claude`: Claude Code session JSONL; `tool_use` blocks named `Bash` with `input.command`.
- `codex`: Codex CLI rollout JSONL (`response_item` `function_call` / `local_shell_call`
  payloads, and the bare items of older versions) and `codex exec --json` events
  (`command_execution` items).
- `text`: a shell log; lines starting `$ `, optionally after a `[timestamp]`.

Nothing in the transcript is run. Commands are redacted before they are reported.
"""

from __future__ import annotations

import contextvars
import json
import os
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Optional

from prufgate.hooks import shell_guard as sg
from prufgate.review.adjudicate import redact

FORMATS = ("claude", "codex", "text")
MAX_BYTES = 64 * 1024 * 1024
HISTORY, HOOKS, TAMPER = "transcript-history-lookup", "transcript-hook-bypass", "transcript-test-tamper-command"
_SHOWN = 300  # characters of a command shown in a finding

_TEXT_LINE = re.compile(r"^(?:\[(?P<ts>[^\]\n]{1,64})\]\s*)?\$ (?P<cmd>.+)$")
_CODEX_TYPES = {"session_meta", "response_item", "event_msg", "turn_context", "compacted", "function_call", "local_shell_call"}
_BASE_REFS = {"HEAD", "@", "ORIG_HEAD", "main", "master", "develop", "origin/main", "origin/master", "origin/HEAD",
              "origin/develop", "upstream/main", "upstream/master", "-"}
_SHA = re.compile(r"^(?=.*[a-fA-F])[0-9a-fA-F]{7,40}$")
_TAG = re.compile(r"^v?\d+(?:\.\d+)+(?:[-+][\w.]+)?$")
_HOME = re.compile(r"(?:/home|/Users)/[A-Za-z0-9_.@-]+|[A-Za-z]:(?:\\{1,2}|/)Users(?:\\{1,2}|/)[A-Za-z0-9_.@-]+")
_NO_EXT_FILES = {"Makefile", "Dockerfile", "LICENSE", "README", "Jenkinsfile", "Gemfile", "Rakefile", "Procfile"}
_LOG_ALL = {"--all", "--branches", "--remotes", "--tags", "--reflog", "-g", "--walk-reflogs", "--glob"}


class TranscriptError(ValueError):
    """A transcript that cannot be read or whose format is unknown."""


def scrub_paths(text: str) -> str:
    """`/home/<user>/x` and `/Users/<user>/x` become `.../x`: no report names the operator's home."""
    return _HOME.sub("...", text)


def _rev_ok(rev: str, sha_ok: bool = True) -> bool:
    """HEAD, the base branch, a commit hash (a diff against a commit is a diff against the
    base), a stash entry, or something PrufGate cannot read (a variable)."""
    if "$" in rev:
        return True
    r = re.sub(r"@\{(?:u|upstream|push)\}$", "", rev)
    if sha_ok:  # without it only HEAD itself is fine, not `HEAD~5`
        r = re.sub(r"(?:\^\{[^}]*\}|[~^]\d*)+$", "", r)
    return r in _BASE_REFS or r == "" or (sha_ok and bool(_SHA.match(r))) or re.match(r"^stash(?:@\{\d+\})?$", r) is not None


def _foreign(word: str, bare_is_ref: bool, sha_ok: bool = True, only_refs: bool = False) -> bool:
    """`word` names a branch or tag other than HEAD or the base (or, with `sha_ok` off, any
    other commit). A bare name counts only where git reads a ref first (`show`, `checkout`,
    `switch`, words before `--`); with `only_refs` (where git takes nothing but a revision:
    `switch`, `restore --source`) `feature/x` and `release-1.0` count too."""
    if word.startswith("-") or "$" in word or word.startswith(("./", "../", "/")):
        return False
    if ":" in word and not word.startswith(":"):
        return not _rev_ok(word.split(":", 1)[0], sha_ok)  # `rev:path`
    if ".." in word:
        return any(side and not _rev_ok(side, sha_ok) for side in re.split(r"\.\.\.?", word))
    if _rev_ok(word, sha_ok):
        return False
    if _SHA.match(word) or word.startswith(("origin/", "upstream/", "refs/", "remotes/")) or "@{" in word:
        return True
    if _TAG.match(word) or only_refs:
        return True
    # ponytail: a bare word without a dot is read as a branch; `feature/x` is read as a path.
    return bare_is_ref and "/" not in word and "." not in word and word not in _NO_EXT_FILES


def _positionals(args: list[str], with_value: frozenset[str] = frozenset()) -> tuple[list[str], bool]:
    """Positional words before `--`, and whether a `--` was present."""
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return out, True
        if a in with_value:
            i += 1
        elif not a.startswith("-") or a == "-":
            out.append(a)
        i += 1
    return out, False


def _history(args: list[str]) -> Optional[str]:
    """Why `git <args>` reads history the task did not hand out, or None."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in sg._GIT_GLOBAL_WITH_VALUE else 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1:]
    shown = f"git {sub}"
    if sub in ("log", "shortlog", "rev-list", "whatchanged"):
        for a in rest:
            if a == "--":
                break
            if a in _LOG_ALL or a.startswith(("--branches=", "--remotes=", "--tags=", "--glob=")):
                return f"`{shown} {a}` reads the history of every branch, not just the task's"
        pos, dashdash = _positionals(rest)
        if any(_foreign(p, dashdash) for p in pos):
            return f"`{shown}` reads the history of another branch or tag"
    elif sub in ("show", "diff"):
        pos, dashdash = _positionals(rest)
        if any(_foreign(p, sub == "show" or dashdash) for p in pos):
            return f"`{shown}` reads a branch or tag other than HEAD or the base"
    elif sub in ("checkout", "switch"):
        pos, dashdash = _positionals(rest, frozenset({"-b", "-B", "-c", "-C", "--orphan", "--create", "--force-create"}))
        if any(_foreign(p, True, only_refs=sub == "switch") for p in (pos if dashdash else pos[:1])):
            return f"`{shown}` checks out another branch or tag"
    elif sub == "restore":
        for j, a in enumerate(rest):
            src = a.split("=", 1)[1] if a.startswith("--source=") else a[2:] if a.startswith("-s") and len(a) > 2 else (
                rest[j + 1] if a in ("-s", "--source") and j + 1 < len(rest) else None)
            if src is not None and _foreign(src, True, only_refs=True):
                return f"`{shown} --source` restores files from another branch or tag"
    elif sub == "reflog":
        return "`git reflog` lists commits that are no longer on the branch"
    elif sub == "cat-file":
        if any(a.startswith(("--batch", "--batch-all-objects")) for a in rest):
            return "`git cat-file --batch` reads arbitrary objects from the repository"
        pos, _ = _positionals(rest)
        if any(_foreign(p, True, sha_ok=False) for p in pos if p not in ("blob", "tree", "commit", "tag")):
            return "`git cat-file` reads an object other than HEAD's"
    elif sub in ("cherry-pick", "merge", "ls-tree", "archive"):
        pos, _ = _positionals(rest, frozenset({"-m", "-s", "--strategy", "-X", "--strategy-option", "--format", "-o",
                                               "--output", "--prefix", "--remote", "--exec", "--into-name"}))
        if any(_foreign(p, True) for p in (pos[:1] if sub in ("ls-tree", "archive") else pos)):
            return f"`{shown}` reads or copies another branch or tag"
    elif sub == "grep":
        pos, dashdash = _positionals(rest, frozenset({"-e", "-f", "-A", "-B", "-C", "-m", "--max-count", "--max-depth",
                                                      "--threads", "--context", "--before-context", "--after-context"}))
        revs = pos if any(a in ("-e", "-f") for a in rest) else pos[1:]  # the first word is the pattern
        if any(_foreign(p, dashdash) for p in revs):
            return f"`{shown}` searches another branch or tag"
    elif sub == "worktree":
        pos, _ = _positionals(rest, frozenset({"-b", "-B", "--reason"}))
        if pos[:1] == ["add"] and any(_foreign(p, True) for p in pos[2:]):
            return "`git worktree add` checks out another branch or tag"
    return None


def _resolves_foreign(args: list[str]) -> Optional[str]:
    """Inside `$(...)` or backticks, a git command naming another branch or tag (`git rev-parse
    origin/x`) hands that commit to the outer command, which PrufGate otherwise cannot read."""
    pos, _ = _positionals(args, frozenset(sg._GIT_GLOBAL_WITH_VALUE))
    if any(_foreign(p, True) for p in pos[1:]):
        return f"`$(git {pos[0]} ...)` resolves a branch or tag other than HEAD or the base"
    return None


def _writes_ci(tool: str, args: list[str]) -> Optional[str]:
    """Editing CI or PrufGate configuration in place, which the shell guard does not cover.
    Paths are also read under the directory an earlier `cd` moved to."""
    target_dir = next((a.split("=", 1)[1] if "=" in a else args[j + 1] for j, a in enumerate(args)
                       if a.startswith("--target-directory") or (a == "-t" and j + 1 < len(args))), None)
    if tool in ("cp", "install", "ln") and target_dir is not None:
        args = [a for j, a in enumerate(args) if a != "-t" and not a.startswith("--target-directory")
                and not (j and args[j - 1] == "-t")] + [target_dir]
    pos, _ = _positionals(args, frozenset({"-e", "-f", "--expression", "--file"}) if tool in ("sed", "perl") else frozenset())
    if tool in ("sed", "perl") and not any(x in ("-e", "-f") or x.startswith(("--expression", "--file")) for x in args):
        pos = pos[1:]  # the first word is the script
    if tool in ("sed", "perl") and any(a.startswith("-i") or a.startswith("--in-place") or (tool == "perl" and a.startswith("-") and "i" in a) for a in args):
        targets = pos
    elif tool in ("tee", "truncate"):
        targets = pos
    elif tool in ("cp", "install", "ln") and len(pos) >= 2:
        targets = pos[-1:]
    else:
        return None
    for t in targets:
        why = next((w for w in map(sg.protected_config, sg._in_cwd(t)) if w), None)
        if why:
            return f"`{tool}` on {t!r} edits {why}"
    return None


def _walk(command: str, depth: int, out: dict[str, str], in_sub: bool = False) -> None:
    """Fill `out` ({rule: reason}) with the history lookups and CI edits in `command`;
    `in_sub` when `command` is a command substitution."""
    if depth > 8:
        return
    commands, subs = sg._split(command)
    for s in subs:
        _walk(s, depth + 1, out, True)
    for words in commands:
        words, _env = sg._strip_prefix(words)
        while words and sg._substituted(words[0]) and words[0] != sg._REDIRECT:
            words = words[1:]  # `$(true) git log --all`: the command may be the next word
        if not words or words[0] == sg._REDIRECT:
            continue
        tool, args = PurePosixPath(words[0]).name, words[1:]
        if tool in ("cd", "pushd", "popd"):
            operands = [a for a in args if not a.startswith("-") or a == "-"]
            sg._chdir(None if tool == "popd" else (operands[0] if operands else "~"))
        elif tool == "eval":
            _walk(" ".join(args), depth + 1, out)
        elif tool in sg._SHELLS and any(a.startswith("--command=") for a in args):
            for a in args:
                if a.startswith("--command="):
                    _walk(a.split("=", 1)[1], depth + 1, out)
        elif tool in sg._SHELLS and any(a == "--command" or (a.startswith("-") and not a.startswith("--") and "c" in a)
                                        for a in args):
            # `bash -c '...'`: the script is an operand; a script file or heredoc on stdin is not read.
            for a in (a for a in args if not a.startswith("-")):
                _walk(a, depth + 1, out)
        elif tool == "git":
            reason = _history(args) or (_resolves_foreign(args) if in_sub else None)
            if reason:
                out.setdefault(HISTORY, reason)
        else:
            reason = _writes_ci(tool, args)
            if reason:
                out.setdefault(TAMPER, reason)


def classify(command: str) -> dict[str, str]:
    """{rule: reason} for one command; empty when nothing in it is suspicious."""
    out: dict[str, str] = {}
    # os.devnull is not a directory, so the guard never expands globs against the scanner's disk.
    guard = sg.check_command(command, os.devnull)
    if guard:
        reason = guard.replace(sg.RUN_IT_YOURSELF, "").replace(" Fix the code instead of the check.", "").strip()
        if any(k in guard for k in ("removes or moves", "overwrites a test or CI file", "with a redirection changes")):
            out[TAMPER] = reason
        elif any(k in guard for k in ("--no-verify", "skips the", "core.hooksPath")):
            out[HOOKS] = reason
    try:
        contextvars.copy_context().run(_walk, command, 0, out)
    except sg._Unparseable:
        pass  # the guard already said it could not parse it; nothing more can be read
    return out


def _command_text(cmd: Any) -> Optional[str]:
    if isinstance(cmd, str):
        return cmd
    if isinstance(cmd, list) and cmd and all(isinstance(c, str) for c in cmd):
        return shlex.join(cmd)
    return None


def _claude(rows: list[tuple[int, dict[str, Any]]]) -> Iterator[tuple[int, Optional[str], str]]:
    for lineno, obj in rows:
        message = obj.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Bash":
                inp = block.get("input")
                cmd = inp.get("command") if isinstance(inp, dict) else None
                if isinstance(cmd, str):
                    yield lineno, obj.get("timestamp"), cmd


def _codex(rows: list[tuple[int, dict[str, Any]]]) -> Iterator[tuple[int, Optional[str], str]]:
    seen_items: set[str] = set()
    for lineno, obj in rows:
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
        cmd: Any = None
        kind = payload.get("type")
        if kind == "function_call":
            args = payload.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    pass  # not JSON: read the arguments as the command itself
            cmd = args if isinstance(args, str) else (args.get("command") or args.get("cmd")) if isinstance(args, dict) else None
        elif kind == "local_shell_call":
            action = payload.get("action")
            cmd = action.get("command") if isinstance(action, dict) else None
        elif str(obj.get("type", "")).startswith("item.") and isinstance(obj.get("item"), dict):
            item = obj["item"]
            if item.get("type") == "command_execution":
                key = str(item.get("id", lineno))
                if key in seen_items:
                    continue
                seen_items.add(key)
                cmd = item.get("command")
        text = _command_text(cmd)
        if text:
            ts = obj.get("timestamp")
            yield lineno, ts if isinstance(ts, str) else None, text


def _detect(rows: list[tuple[int, dict[str, Any]]]) -> Optional[str]:
    for _, obj in rows:
        kind = str(obj.get("type", ""))
        if "sessionId" in obj or ("uuid" in obj and "message" in obj):
            return "claude"
        if kind in _CODEX_TYPES or kind.startswith(("item.", "thread.", "turn.")):
            return "codex"
    return None


def read_commands(path: Path, format_in: Optional[str] = None) -> tuple[str, list[tuple[int, Optional[str], str]]]:
    """(format, [(line, timestamp, command)]). Raises TranscriptError when the file cannot
    be read, is larger than MAX_BYTES, or is not in a known format."""
    if format_in is not None and format_in not in FORMATS:
        raise TranscriptError(f"unknown format {format_in!r}; use one of {', '.join(FORMATS)}")
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    except OSError as exc:
        raise TranscriptError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > MAX_BYTES:
        raise TranscriptError(f"{path} is larger than {MAX_BYTES // (1024 * 1024)} MiB; split it first")
    lines = data.decode("utf-8", errors="replace").splitlines()
    first = next((ln.strip() for ln in lines if ln.strip()), "")
    if format_in in ("claude", "codex") or (format_in is None and first.startswith("{")):
        rows: list[tuple[int, dict[str, Any]]] = []
        for n, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError as exc:
                raise TranscriptError(f"line {n} is not JSON ({exc.msg})") from exc
            if not isinstance(obj, dict):
                raise TranscriptError(f"line {n} is not a JSON object")
            rows.append((n, obj))
        fmt = format_in or _detect(rows)
        if fmt == "claude":
            return fmt, list(_claude(rows))
        if fmt == "codex":
            return fmt, list(_codex(rows))
        raise TranscriptError("JSON lines that are neither a Claude Code nor a Codex CLI transcript; pass --format-in")
    found = []
    for n, line in enumerate(lines, start=1):
        m = _TEXT_LINE.match(line)
        if m:
            found.append((n, m.group("ts"), m.group("cmd")))
    if not found and format_in != "text":
        raise TranscriptError("unknown transcript format: no JSON lines and no `$ ` command lines; pass --format-in")
    return "text", found


def _shown(command: str) -> str:
    text = " ".join(scrub_paths(redact(command)).split())
    return text if len(text) <= _SHOWN else text[:_SHOWN] + "..."


def scan(path: Path, format_in: Optional[str] = None) -> tuple[str, int, list[dict[str, Any]]]:
    """(format, commands checked, findings). Findings use the CLI's finding shape."""
    fmt, commands = read_commands(path, format_in)
    findings = []
    for lineno, ts, command in commands:
        for rule, reason in classify(command).items():
            when = f" at {ts}" if ts else ""
            why = scrub_paths(redact(reason)).rstrip(".")
            findings.append({
                "rule": rule,
                "severity": "P1",
                "engine": "transcript",
                "file": scrub_paths(str(path)),
                "line": lineno,
                "timestamp": ts,
                "command": _shown(command),
                "message": f"The agent ran `{_shown(command)}`{when}: {why}.",
            })
    return fmt, len(commands), findings
