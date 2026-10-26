"""Inline `prufgate-ignore` comments, shared by every engine.

    return cached  # prufgate-ignore: rule-id, other-rule -- why this is safe

The comment sits on the finding's line or on a comment line just above it.
Without a rule list it covers every rule on that line. The reason after `--`
(or ` - `), at least three characters, is required: an ignore without one suppresses nothing, and the run
reports it as `ignore-without-reason` so the author can add one.

Every honoured ignore is recorded, so the report can count and list it:
in-process through `recording()`, and across engine processes as JSON lines
appended to the file named by `PRUFGATE_SUPPRESSIONS_FILE`.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prufgate.config import rules_match  # noqa: E402

MISSING_REASON_RULE = "ignore-without-reason"
MISSING_REASON_MESSAGE = (
    "A prufgate-ignore comment without a reason suppresses nothing. "
    "Add one after `--`, for example `prufgate-ignore: rule-id -- why this is safe`."
)
SUPPRESSIONS_ENV = "PRUFGATE_SUPPRESSIONS_FILE"

_IGNORE_RE = re.compile(
    r"prufgate-ignore(?![\w-])"
    r"(?:\s*:\s*(?P<rules>\w[\w.-]*(?:[\s,]+\w[\w.-]*)*))?"
    # `-->` is a comment terminator, not the `--` separator; the reason ends at `*/` or `-->`.
    r"(?:\s+(?:--(?!>)\s*|-\s+)(?P<reason>(?:(?!\*/|-->).)*))?",
    re.IGNORECASE,
)
_COMMENT_END_RE = re.compile(r"(?:\s*(?:\*/|-->|}|\"\"\"|'''))+\s*$")
_COMMENT_START = ("//", "#", "/*", "*", "<!--", "--", "{/*")

_sink: list[dict] | None = None
_seen: set[tuple] = set()


def parse(text: str) -> tuple[tuple[str, ...], str] | None:
    """`(rules, reason)` for the first `prufgate-ignore` in `text`, else None.
    An empty rule tuple covers every rule; an empty reason means none was given."""
    m = _IGNORE_RE.search(text)
    if not m:
        return None
    rules = tuple(re.split(r"[\s,]+", m.group("rules") or "")) if m.group("rules") else ()
    reason = _COMMENT_END_RE.sub("", m.group("reason") or "").strip()
    # At least three non-space characters, with a letter or digit: `-- x` is not a reason.
    if not re.search(r"[A-Za-z0-9]", reason) or len(re.sub(r"\s", "", reason)) < 3:
        reason = ""
    return rules, reason


def review_rule_id(title: str) -> str:
    """The rule ID of an Engine 6 review comment: `pr-` and the title in `[a-z0-9-]`,
    the same in every report and the one `prufgate-ignore` names."""
    return "pr-" + (re.sub(r"[^a-z0-9-]+", "-", title.lower()).strip("-") or "review")


def covers(rules: tuple[str, ...], rule: str) -> bool:
    return not rules or any(r.lower() == "all" or rules_match(rule, r) for r in rules)


def context(lines: list[str], line_num: int) -> list[str]:
    """Line `line_num` (1-indexed) and the comment line just above it, if any."""
    if not 1 <= line_num <= len(lines):
        return []
    out = [lines[line_num - 1]]
    if line_num >= 2 and lines[line_num - 2].strip().startswith(_COMMENT_START):
        out.append(lines[line_num - 2])
    return out


def suppressed(
    texts: Iterable[str],
    rule: str,
    *,
    engine: str,
    path: str,
    line: int,
    severity: str = "",
    message: str = "",
) -> bool:
    """True when one of `texts` holds a reasoned ignore covering `rule`.
    Records the honoured ignore, or, when only reasonless ones cover it, a
    missing-reason entry the report turns into an `ignore-without-reason` finding."""
    reasonless = False
    for text in texts:
        parsed = parse(text)
        if parsed is None or not covers(parsed[0], rule):
            continue
        if parsed[1]:
            _record("honoured", engine, path, line, rule, severity, message, parsed[1])
            return True
        reasonless = True
    if reasonless:
        _record("missing-reason", engine, path, line, rule, severity, message, "")
    return False


def suppressed_at(lines: list[str], line_num: int, rule: str, **kw) -> bool:
    return suppressed(context(lines, line_num), rule, line=line_num, **kw)


def _record(kind: str, engine: str, path: str, line: int, rule: str, severity: str, message: str, reason: str) -> None:
    entry = {
        "kind": kind,
        "engine": engine,
        "file": path,
        "line": int(line or 1),
        "rule": rule,
        "severity": severity,
        "message": message,
        "reason": reason,
    }
    if _sink is not None:
        key = (kind, engine, path, entry["line"], rule)
        if key not in _seen:
            _seen.add(key)
            _sink.append(entry)
    out = os.environ.get(SUPPRESSIONS_ENV)
    if out:
        # One short line per write in append mode, so engines running side by side do not interleave.
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


@contextlib.contextmanager
def recording() -> Iterator[list[dict]]:
    """Collect the ignores the engines record inside the block."""
    global _sink, _seen
    prev = _sink, _seen
    _sink, _seen = [], set()
    try:
        yield _sink
    finally:
        _sink, _seen = prev


def load(path: Path) -> list[dict]:
    """Read and deduplicate the JSON lines engines appended to `path`."""
    if not path.is_file():
        return []
    seen: set[tuple] = set()
    out: list[dict] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(e, dict) or e.get("kind") not in ("honoured", "missing-reason"):
            continue
        key = (e.get("kind"), e.get("engine"), e.get("file"), e.get("line"), e.get("rule"))
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out
