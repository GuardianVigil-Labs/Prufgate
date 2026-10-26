"""Edits to the test harness that make checks pass without fixing anything.

Published reward-hacking evaluations saw agents patch the test runner or its
assertion helpers, override `__eq__` so every comparison holds, rewrite results in
conftest hooks, and neuter the test command or its configuration. Rules:

- `test-runner-monkeypatch` (P0): Python writes to `unittest` / `pytest` /
  `TestCase` internals, assertion builtins or `sys.modules["pytest"]`, by assignment,
  `setattr`, `object.__setattr__` / `type.__setattr__`, `patch`, `patch.object` or
  pytest's two-argument `monkeypatch.setattr("module.attr", value)`; a non-constant
  attribute name on a runner object counts too. In test files, `self.assert* = ...`.
  Assertion methods of a `TestCase` subclass overridden with a body that only
  returns a constant or an argument. JS/TS in test files: `expect` / `assert` / `it`
  / `test` / `describe` replaced on `global`, `globalThis`, `window` or `self` (by
  dot, bracket, `Object.assign`, `Object.defineProperty`, `Reflect.set`), a
  reassigned `expect`, chai `Assertion.prototype.x = ...` or `["x"] = ...`, a
  `vi.mock` / `jest.mock` of the test framework, and `expect.extend` matchers whose
  every `pass` is a truthy constant.
- `always-true-equality` (P1): `__eq__` returning True or `__ne__` returning False,
  in the class body, as a method whose class is outside the hunk, or set from
  outside (`Money.__eq__ = ...`, `setattr(Money, "__eq__", ...)`). `__bool__` is not
  checked: every object is truthy unless it says otherwise. The one allowance is
  the `mock.ANY` idiom, and only when it is exact: a class in a test file whose name
  is `Any`, `Any<Capitalised>`, `<X>Anything`, `<X>Matcher` or `<X>Wildcard`
  (case-sensitive), or a subclass of `unittest.mock._ANY`. A matcher-shaped name in
  application code is flagged.
- `pytest-result-rewrite` (P0), in pytest plugin files only (a `conftest.py`, a
  `pytest_*.py` module, or a file that defines `pytest_*` hooks, uses `hookimpl` or
  sets `pytest_plugins`): a report's `outcome` set to `"passed"` (or `"skipped"` in
  `pytest_runtest_makereport`), `exitstatus` forced to 0, failed/error stats dropped,
  or `pytest_pyfunc_call` / `pytest_runtest_call` returning True without running the
  test. Constants bound once to a name are followed.
- `pytest-collection-deselect` (P1), in plugin files: `pytest_collection_modifyitems`
  removing items (found by the `items` parameter's name) or marking every item skip /
  xfail without a condition; `pytest_ignore_collect` returning True, or a condition
  that names test files; `collect_ignore` / `collect_ignore_glob` in a conftest
  listing test paths (any entry under a test directory, except build, docs, fixture
  and similar directories).
- `test-config-weakening` (P1): pytest options that narrow the run (`-k`, `-m`,
  `-p no:<plugin>`, `--deselect`, `--ignore`, `--continue-on-collection-errors`,
  `--collect-only`), narrowed `testpaths` / `python_files` / `python_classes` /
  `python_functions`, new `norecursedirs` entries; Jest `passWithNoTests`, narrowed
  `roots` / `testMatch` / `testRegex`, new `testPathIgnorePatterns`, `silent` with
  `forceExit`; Vitest `include` / `exclude` in the `test` block (not `coverage`,
  `optimizeDeps` and the like) and workspace files. `compare_config` judges pytest
  INI/TOML and Jest JSON settings by value against the base; the line check here
  covers JavaScript configs and runs without a base. Ignore entries for build
  output, dependencies, docs, fixtures and end-to-end suites are not reported.
- `test-script-neutered` (P0): a package.json `test` script whose status cannot
  reflect a failure (`|| true`, `|| echo`, `; exit 0`, a pipe without `pipefail`, a
  bare `exit`, `echo` / `true` only, or lint commands only); a Makefile test target
  whose recipe, judged as a whole, has no line that can fail (a target with
  prerequisites can fail through them); a tox command that cannot fail; nox
  `success_codes` accepting 1.

Python is read with `ast` over what the hunk shows; a hunk that does not parse is
skipped for the Python rules (the line rules still run).
"""

from __future__ import annotations

import ast
import configparser
import json
import re
import shlex
from pathlib import Path
from typing import Any, NamedTuple

from prufgate.diff_guard import fake_exit

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.9/3.10 keep the line-based check
    tomllib = None  # type: ignore[assignment]  # optional on old Pythons


class Hit(NamedTuple):
    line: int
    rule: str
    severity: str
    why: str


_RUNNER_ROOTS = frozenset({"unittest", "pytest", "_pytest", "TestCase", "IsolatedAsyncioTestCase"})
_BENIGN_RUNNER_ATTRS = frozenset({"maxDiff", "longMessage", "_MAX_LENGTH", "_diffThreshold"})
_PATCHED_BUILTINS = frozenset({"AssertionError", "isinstance", "issubclass", "all", "any", "bool", "len"})
_ASSERT_METHOD_RE = re.compile(r"(?:assert|fail)(?:[A-Z_]\w*)?")
# Case-sensitive on purpose: `AnyMoney` is a matcher, `Anyway` and `anything` are not.
_MATCHER_CLASS_RE = re.compile(r"_?(?:Any(?:[A-Z_]\w*)?|\w*(?:Anything|Matcher|Wildcard))")
_TRUTH_DUNDERS = {"__eq__": True, "__ne__": False}
_SETATTR_OWNERS = frozenset({"object", "type", "builtins.object", "builtins.type"})
_SKIP_MARKS = ("mark.skip", "mark.xfail")
_TESTISH_RE = re.compile(r"test|spec", re.IGNORECASE)
_HOOK_LINE_RE = re.compile(r"^\s*(?:async\s+)?def\s+pytest_\w+\s*\(|^\s*@[\w.]*hookimpl\b|^\s*pytest_plugins\s*=")

# Path words in an ignore entry that make it routine (build output, dependencies, docs, e2e suites).
_BENIGN_IGNORE = frozenset({
    "node_modules", "dist", "build", "coverage", "out", ".next", ".nuxt", ".git", "vendor", "tmp", ".cache",
    ".venv", "venv", ".tox", ".nox", "__pycache__", "docs", "site-packages", ".eggs", ".egg-info", "e2e",
    "playwright", "cypress", "fixtures", "__fixtures__", "examples", "setup.py", "__snapshots__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "htmlcov", "storybook-static", "target",
})
# Entries of an include-style list that keep the run broad (`tests`, `**`, `src`, `<rootDir>`).
_BROAD_RE = re.compile(r"test|spec|\*\*|\bsrc\b|\blib\b|\bapp\b|\bpackages\b|^<rootDir>/?$|^\.?/?$", re.IGNORECASE)
_BENIGN_NO_PLUGINS = frozenset({"cacheprovider", "warnings", "randomly", "xdist", "logging", "sugar"})


def harness_hits(hunk: Any, rel_path: str, aliases: dict[str, str], file_lines: list[str] | None = None) -> list[Hit]:
    """Findings for the added lines of one hunk. `file_lines` are the file's lines
    the diff shows (all hunks); they decide whether it is a pytest plugin file."""
    sfx = Path(rel_path).suffix.lower()
    out: list[Hit] = []
    if sfx == ".py":
        lines = list(file_lines if file_lines is not None else [t for _, t in hunk.context_lines + hunk.added_lines])
        out += _python_hits(hunk, rel_path, aliases, is_pytest_plugin(rel_path, lines + [_header(hunk)]))
    if sfx in fake_exit.JS_SUFFIXES and fake_exit.is_test_harness(rel_path):
        out += _js_patch_hits(hunk)
    kind = config_kind(rel_path)
    if kind:
        out += _config_hits(hunk, kind)
    out += _script_hits(hunk, rel_path)
    return out


def is_pytest_plugin(rel_path: str, lines: list[str]) -> bool:
    name = Path(rel_path).name
    return name == "conftest.py" or name.startswith("pytest_") or any(_HOOK_LINE_RE.match(t) for t in lines)


def _header(hunk: Any) -> str:
    return re.sub(r"^@@[^@]*@@ ?", "", hunk.raw_lines[0]) if getattr(hunk, "raw_lines", None) else ""


def _benign_entry(entry: str) -> bool:
    return any(w in _BENIGN_IGNORE or w.lstrip("*") in _BENIGN_IGNORE for w in re.findall(r"[\w.@*-]+", entry))


def _broad(entries: list[str]) -> bool:
    return any(_BROAD_RE.search(e) for e in entries)


# --- Python, with ast ---------------------------------------------------------


def _body(fn: ast.AST) -> list[ast.stmt]:
    body = list(getattr(fn, "body", []))
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


def _truth(node: ast.AST | None, names: dict[str, ast.AST] | None = None) -> bool | None:
    """The truth value of a constant expression, or None. `x or True` is true and
    `x and False` is false whatever `x` is."""
    if node is None:
        return False
    if isinstance(node, ast.BoolOp):
        decisive = isinstance(node.op, ast.Or)
        if any(_truth(v, names) is decisive for v in node.values):
            return decisive
    v = fake_exit._const(node, names)
    return None if v is fake_exit._UNKNOWN else bool(v)


def _only_returns(fn: ast.AST, want: bool) -> bool:
    """Every way out of `fn` returns a value whose truth is `want` (or NotImplemented,
    which falls back to identity), and it cannot fall off the end."""
    if isinstance(fn, ast.Lambda):
        return _truth(fn.body) is want
    body = _body(fn)
    if not body or not isinstance(body[-1], ast.Return):
        return False
    rets = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    return any(_truth(r.value) is want for r in rets) and all(
        _truth(r.value) is want or (isinstance(r.value, ast.Name) and r.value.id == "NotImplemented") for r in rets
    )


def _params(fn: ast.AST) -> list[str]:
    a = getattr(fn, "args", None)
    return [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)] if a else []


def _checks_nothing(fn: ast.AST) -> bool:
    """A body that does nothing: `pass`, `...`, or `return` of a constant or an argument."""
    params = set(_params(fn))
    return all(
        isinstance(s, ast.Pass)
        or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
        or (isinstance(s, ast.Return) and (_truth(s.value) is not None or (isinstance(s.value, ast.Name) and s.value.id in params)))
        for s in _body(fn)
    )


def _strings(node: ast.AST | None) -> list[str] | None:
    """The string constants of a list/tuple/string literal; None when an entry is not constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out: list[str] = []
        for e in node.elts:
            got = _strings(e)
            if got is None:
                return None
            out += got
        return out
    return None


def _python_hits(hunk: Any, rel_path: str, aliases: dict[str, str], plugin: bool) -> list[Hit]:
    tree, nums = fake_exit._parse_python(hunk)
    if tree is None:
        return []
    added = {ln for ln, _ in hunk.added_lines}
    scan = fake_exit._PyScan(tree, nums, added, False, aliases)
    test_file = fake_exit.is_test_harness(rel_path)
    conftest = Path(rel_path).name == "conftest.py"
    in_test_dir = any(d in fake_exit.TEST_DIR_NAMES for d in Path(rel_path).parts[:-1])
    m = re.match(r"\s*class\s+(\w+)", _header(hunk))
    header_class = m.group(1) if m else ""
    out: list[Hit] = []

    def const(node: ast.AST | None) -> Any:
        return fake_exit._UNKNOWN if node is None else fake_exit._const(node, scan.consts)

    def runner_target(q: str) -> bool:
        parts = q.split(".")
        if parts[0] in _RUNNER_ROOTS and len(parts) > 1:
            return parts[-1] not in _BENIGN_RUNNER_ATTRS
        return parts[0] == "builtins" and len(parts) == 2 and (parts[1] in _PATCHED_BUILTINS or parts[1].startswith("assert"))

    def matcher_ok(name: str, bases: list[str]) -> bool:
        return any(b.endswith("mock._ANY") for b in bases) or (test_file and bool(_MATCHER_CLASS_RE.fullmatch(name)))

    def hook_of(node: ast.AST, *names: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        return next((f for f in scan.funcs(node) if f.name in names), None)

    def hit(node: ast.AST, rule: str, severity: str, why: str) -> None:
        ln = scan.first_added(node)
        if ln:
            out.append(Hit(ln, rule, severity, why))

    def writes(node: ast.AST) -> list[tuple[str, str, ast.AST | None]]:
        """(object, attribute, value) for each attribute this statement or call sets.
        The object is a dotted name ("" when unknown); the attribute is "<dynamic>"
        when it is not a constant."""
        got: list[tuple[str, str, ast.AST | None]] = []
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            value = getattr(node, "value", None)
            for t in targets:
                for el in t.elts if isinstance(t, ast.Tuple) else [t]:
                    if isinstance(el, ast.Attribute):
                        got.append((scan.qual(el.value), el.attr, value))
        elif isinstance(node, ast.Call) and node.args:
            f = node.func
            leaf = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            setter = leaf == "setattr" or leaf == "object" or (
                leaf == "__setattr__" and isinstance(f, ast.Attribute) and scan.qual(f.value) in _SETATTR_OWNERS
            )
            first = node.args[0]
            dotted = isinstance(first, ast.Constant) and isinstance(first.value, str)
            if setter and len(node.args) >= 2 and not dotted:
                name = const(node.args[1])
                got.append((scan.qual(first), name if isinstance(name, str) else "<dynamic>", node.args[2] if len(node.args) > 2 else None))
            elif (leaf == "patch" or (leaf == "setattr" and len(node.args) == 2)) and dotted and "." in first.value:
                obj, _, attr = first.value.rpartition(".")
                got.append((obj, attr, node.args[1] if len(node.args) > 1 else None))
        return got

    def zeroes(node: ast.AST, value: ast.AST | None) -> bool:
        if isinstance(node, ast.AugAssign):
            return isinstance(node.op, ast.Mult) and const(value) == 0
        if value is None:
            return False
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Sub) and ast.dump(value.left) == ast.dump(value.right):
            return True
        v = const(value)
        return v is None or (type(v) in (int, bool) and v == 0) or scan.qual(value).endswith(("ExitCode.OK", "EXIT_OK"))

    for node in ast.walk(tree):
        # Attribute writes: runner patches, equality from outside, result rewrites.
        for obj, attr, value in writes(node):
            q = f"{obj}.{attr}" if obj else ""
            if q and runner_target(q):
                hit(node, "test-runner-monkeypatch", "P0", f"replaces `{q}`, so the test runner no longer checks what it reports")
            elif obj == "self" and test_file and _ASSERT_METHOD_RE.fullmatch(attr) and value is not None:
                hit(node, "test-runner-monkeypatch", "P0", f"replaces `self.{attr}`, so the assertion checks nothing")
            if attr in _TRUTH_DUNDERS and isinstance(value, ast.Lambda) and _only_returns(value, _TRUTH_DUNDERS[attr]) \
                    and not matcher_ok(obj.rsplit(".", 1)[-1], []):
                hit(node, "always-true-equality", "P1",
                    f"`{attr}` returns {_TRUTH_DUNDERS[attr]} for anything, so every assertion comparing this object passes")
            if not plugin:
                continue
            if attr == "outcome":
                v = const(value)
                if v == "passed" or (v == "skipped" and hook_of(node, "pytest_runtest_makereport")):
                    hit(node, "pytest-result-rewrite", "P0", f"sets a test report's outcome to {v}")
            if attr == "exitstatus" and zeroes(node, value):
                hit(node, "pytest-result-rewrite", "P0", "forces the session's exit status to 0")

        if isinstance(node, (ast.Assign, ast.Delete)):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and scan.qual(t.value) == "sys.modules":
                    key = t.slice
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.split(".")[0] in _RUNNER_ROOTS:
                        hit(node, "test-runner-monkeypatch", "P0",
                            f"replaces `sys.modules[{key.value!r}]`, so the test runner no longer checks what it reports")

        # Methods: assertion overrides and always-true equality.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign)):
            parent = scan.parents.get(node)
            cls_name, bases = "", []
            if isinstance(parent, ast.ClassDef):
                cls_name, bases = parent.name, [scan.qual(b) for b in parent.bases]
            elif isinstance(parent, ast.Module) and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and _params(node)[:1] == ["self"]:
                cls_name = header_class  # a method whose class line is outside the hunk
            else:
                parent = None
            if parent is not None:
                name, fn = "", None
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    name, fn = node.name, node
                elif isinstance(node.value, ast.Lambda) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    name, fn = node.targets[0].id, node.value
                if name in _TRUTH_DUNDERS and fn is not None and _only_returns(fn, _TRUTH_DUNDERS[name]) and not matcher_ok(cls_name, bases):
                    hit(node, "always-true-equality", "P1",
                        f"`{name}` returns {_TRUTH_DUNDERS[name]} for anything, so every assertion comparing this object passes")
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _ASSERT_METHOD_RE.fullmatch(node.name) \
                        and _checks_nothing(node) and any("TestCase" in b or b.split(".")[0] in _RUNNER_ROOTS for b in bases):
                    hit(node, "test-runner-monkeypatch", "P0", f"overrides `{node.name}` with a body that checks nothing")

        if not plugin:
            continue

        # pytest-result-rewrite: dropped stats, hooks that pretend to run the test.
        stats_key = None
        if isinstance(node, (ast.Assign, ast.Delete)):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and scan.qual(t.value).endswith("stats"):
                    stats_key = const(t.slice)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and scan.qual(node.func.value).endswith("stats"):
            if node.func.attr == "clear":
                stats_key = "failed"
            elif node.func.attr == "pop" and node.args:
                stats_key = const(node.args[0])
        if stats_key in ("failed", "error"):
            hit(node, "pytest-result-rewrite", "P0", f"drops the run's `{stats_key}` results")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in ("pytest_pyfunc_call", "pytest_runtest_call") \
                and _only_returns(node, True):
            hit(node, "pytest-result-rewrite", "P0", f"`{node.name}` returns True without running the test")

        # pytest-collection-deselect
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "pytest_ignore_collect" and _only_returns(node, True):
            hit(node, "pytest-collection-deselect", "P1", "`pytest_ignore_collect` ignores every file")
        if isinstance(node, ast.Return) and node.value is not None and hook_of(node, "pytest_ignore_collect") \
                and any(isinstance(c, ast.Constant) and isinstance(c.value, str) and _TESTISH_RE.search(c.value) for c in ast.walk(node.value)):
            hit(node, "pytest-collection-deselect", "P1", "`pytest_ignore_collect` ignores test files")
        hook = hook_of(node, "pytest_collection_modifyitems")
        if hook is not None:
            names = _params(hook)
            items = "items" if "items" in names else (names[-1] if names else "items")
            removed = False
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                removed = (scan.qual(node.func.value) == items and node.func.attr in ("clear", "pop", "remove")) \
                    or node.func.attr == "pytest_deselected"
            elif isinstance(node, (ast.Assign, ast.Delete)):
                removed = any(isinstance(t, ast.Subscript) and scan.qual(t.value) == items for t in node.targets)
            elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Sub):
                removed = scan.qual(node.target) == items
            if removed:
                hit(node, "pytest-collection-deselect", "P1", "`pytest_collection_modifyitems` removes collected tests")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_marker" and node.args:
            fn = next((f for f in scan.funcs(node) if f.name.startswith("pytest_")), None)
            mark = node.args[0]
            mq = scan.qual(mark.func if isinstance(mark, ast.Call) else mark)
            skips = mq.endswith(_SKIP_MARKS) or (isinstance(mark, ast.Constant) and mark.value in ("skip", "xfail"))
            if mq.endswith("mark.skipif") and isinstance(mark, ast.Call) and mark.args:
                skips = _truth(mark.args[0], scan.consts) is True
            conditional, p = False, scan.parents.get(node)
            while fn is not None and p is not None and p is not fn:
                conditional = conditional or isinstance(p, (ast.If, ast.IfExp, ast.While, ast.Try)) \
                    or (isinstance(p, ast.comprehension) and bool(p.ifs))
                p = scan.parents.get(p)
            if fn is not None and skips and not conditional:
                hit(node, "pytest-collection-deselect", "P1", f"`{fn.name}` marks every test skip or xfail")
        if conftest and isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in ("collect_ignore", "collect_ignore_glob") for t in targets):
                entries = _strings(node.value)
                if entries is None or any(not _benign_entry(e) and (in_test_dir or _TESTISH_RE.search(e)) for e in entries):
                    hit(node, "pytest-collection-deselect", "P1", "`collect_ignore` stops pytest collecting test files")
        if conftest and isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                and node.func.value.id in ("collect_ignore", "collect_ignore_glob") and node.func.attr in ("append", "extend", "insert"):
            entries = _strings(node.args[-1]) if node.args else None
            if entries is None or any(not _benign_entry(e) and (in_test_dir or _TESTISH_RE.search(e)) for e in entries):
                hit(node, "pytest-collection-deselect", "P1", "`collect_ignore` stops pytest collecting test files")
    return out


# --- JS/TS, by line -------------------------------------------------------------

_JS_NAMES = r"(?:expect|assert|it|test|describe)"
_JS_GLOBALS = r"(?:global|globalThis|window|self)"
_JS_GLOBAL_PATCH_RE = re.compile(
    rf"\b{_JS_GLOBALS}\b(?:\s+as\s+\w+)?\s*\)?\s*(?:\.\s*{_JS_NAMES}\b|\[\s*(['\"`]){_JS_NAMES}\1\s*\])\s*=(?!=)"
    rf"|\bObject\s*\.\s*(?:assign|defineProperty|defineProperties)\s*\(\s*\(?\s*{_JS_GLOBALS}\b.*\b{_JS_NAMES}\b"
    rf"|\bReflect\s*\.\s*(?:set|defineProperty)\s*\(\s*\(?\s*{_JS_GLOBALS}\b.*\b{_JS_NAMES}\b"
    r"|\b(?:vi|jest)\s*\.\s*(?:do)?[mM]ock\s*\(\s*(['\"])(?:vitest|@jest/globals|chai|assert|node:assert)\2"
)
_JS_EXPECT_PATCH_RE = re.compile(
    r"^\s*expect\s*=(?!=)"
    r"|^\s*(?:const|let|var)\s+expect\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|\w+\s*=>)"
    r"|\bexpect\s*\.\s*(?!extend\b)\w+\s*=(?!=)"
    r"|\bAssertion\s*\.\s*prototype\s*(?:\.\s*\w+|\[\s*(['\"`])\w+\1\s*\])\s*=(?!=)"
)
_JS_EXTEND_RE = re.compile(r"\bexpect\s*\.\s*extend\s*\(")
_JS_TRUTHY = {"true", "!0", "!false", "1", "Boolean(1)", "Boolean(true)", "!!1", "!!true"}


def _js_patch_hits(hunk: Any) -> list[Hit]:
    out: list[Hit] = []
    why = "replaces the test framework's assertions, so failing checks pass"
    for ln, raw in hunk.added_lines:
        code = fake_exit.strip_code(raw, hash_comments=False)
        if _JS_GLOBAL_PATCH_RE.search(code) or _JS_EXPECT_PATCH_RE.search(code):
            out.append(Hit(ln, rule="test-runner-monkeypatch", severity="P0", why=why))
    view = sorted(hunk.context_lines + hunk.added_lines)
    added = {ln for ln, _ in hunk.added_lines}
    consts = {
        m.group(1): m.group(2)
        for _, raw in view
        if (m := re.search(r"\b(?:const|let|var)\s+(\w+)\s*=\s*([^;,\n]+?)\s*;?\s*$", fake_exit.strip_code(raw, hash_comments=False)))
    }
    for i, (_, raw) in enumerate(view):
        if not _JS_EXTEND_RE.search(fake_exit.strip_code(raw, hash_comments=False)):
            continue
        block, depth = [], 0
        for bln, braw in view[i : i + 60]:
            code = fake_exit.strip_code(braw, hash_comments=False)
            block.append((bln, code))
            depth += code.count("(") - code.count(")")
            if depth <= 0:
                break
        text = "\n".join(c for _, c in block)
        values = [v.strip() for v in re.findall(r"""["']?\bpass\b["']?\s*:\s*([^,}\n]+)""", text)]
        values = [consts.get(v, v).strip() for v in values]
        shorthand = re.search(r"""(?<![\w"'])pass\s*(?:[,}]|$)""", text, re.M)
        first = next((b for b, _ in block if b in added), None)
        if first and values and not shorthand and all(v in _JS_TRUTHY for v in values):
            out.append(Hit(first, rule="test-runner-monkeypatch", severity="P0", why="adds `expect` matchers that always pass"))
    return out


# --- Test configuration ---------------------------------------------------------

_PY_SECTION_RE = re.compile(r"^\[(?:pytest|tool:pytest|tool\.pytest(?:\.ini_options)?)\]$")
_PY_INCLUDE_KEYS = ("testpaths", "python_files", "python_classes", "python_functions")
_JS_INCLUDE_KEYS = ("testMatch", "roots", "testRegex")
_JS_KEY_RE = re.compile(r"""["']?([A-Za-z_$][\w$]*)["']?\s*:(?!:)|[{}]""")
_QUOTED_RE = re.compile(r"""(['"`])((?:\\.|(?!\1).)*)\1""")


def config_kind(rel_path: str) -> str:
    """'pytest', 'jest', 'vitest', 'workspace' or 'package' for a test-runner config file, else ''."""
    name = Path(rel_path).name
    if name in ("pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"):
        return "pytest"
    if name == "package.json":
        return "package"
    if re.fullmatch(r"jest\.config\.(?:[cm]?[jt]s|json)", name):
        return "jest"
    if re.fullmatch(r"vitest\.(?:workspace|projects)\.(?:[cm]?[jt]s|json)", name):
        return "workspace"
    if re.fullmatch(r"(?:vitest|vite)\.config\.[cm]?[jt]s", name):
        return "vitest"
    return ""


def _addopts_narrowing(tokens: list[str]) -> set[tuple[str, str]]:
    """The options among `tokens` that leave tests out of the run, as (option, value)."""
    out: set[tuple[str, str]] = set()
    i = 0
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        m = re.fullmatch(r"(-k|-m|-p|--deselect|--ignore|--ignore-glob)(?:=?(.+))?", t)
        if m:
            opt, val = m.group(1), m.group(2)
            if val is None:
                val, i = nxt, i + 1
            if opt == "-p":
                if val.startswith("no:") and val[3:] not in _BENIGN_NO_PLUGINS:
                    out.add((opt, val))
            elif not (opt.startswith("--ignore") and _benign_entry(val)):
                out.add((opt, val))
        elif t in ("--continue-on-collection-errors", "--co", "--collect-only"):
            out.add((t, ""))
        i += 1
    return out


def _entries(value: str) -> list[str]:
    got = [q for _, q in _QUOTED_RE.findall(value)] or value.replace(",", " ").split()
    return [e for e in got if e not in ("[", "]")]


def _py_line_why(key: str, s: str, value: str) -> str:
    if key in _PY_INCLUDE_KEYS and value.strip():
        if not _broad(_entries(value)):
            return f"`{key}` no longer covers the tests"
    elif key == "norecursedirs":
        if any(not _benign_entry(e) for e in _entries(value)):
            return "`norecursedirs` stops pytest looking in a test directory"
    elif key == "addopts":
        # TOML quotes the whole value (or each list item); INI leaves it bare.
        parts = [q for _, q in _QUOTED_RE.findall(value)] if value.lstrip()[:1] in "\"'[" else [value]
        tokens: list[str] = []
        for part in parts:
            try:
                tokens += shlex.split(part)
            except ValueError:
                tokens += part.split()
        if _addopts_narrowing([t.strip("[],") for t in tokens]):
            return "the pytest options skip or ignore tests"
    return ""


def _config_hits(hunk: Any, kind: str) -> list[Hit]:
    out: list[Hit] = []
    added = {ln for ln, _ in hunk.added_lines}
    view = sorted(hunk.context_lines + hunk.added_lines)
    if kind == "pytest":
        section: str | None = None
        key = ""
        for ln, raw in view:
            s = raw.strip()
            if not s or s.startswith(("#", ";")):
                continue
            if re.fullmatch(r"\[\[?[\w.:\-\"' ]+\]\]?", s):
                section, key = s, ""
                continue
            m = re.match(r"^([\w.-]+)\s*[=:]\s*(.*)$", s) if not raw[:1].isspace() else None
            if m:
                key, value = m.group(1), m.group(2)
            else:
                value = s
            if ln not in added or (section is not None and not _PY_SECTION_RE.match(section)):
                continue
            why = _py_line_why(key, s, value)
            if why:
                out.append(Hit(ln, rule="test-config-weakening", severity="P1", why=why))
        return out

    stack: list[str] = []
    block: dict[str, Any] | None = None  # a list value spanning lines: key, entries, added lines
    silent = force_exit = None
    ignore_why = "the test runner is told to ignore test files"

    def close(b: dict[str, Any]) -> None:
        if b["key"] in _JS_INCLUDE_KEYS + ("include",) and b["added"] and not _broad(b["entries"]):
            why = "the test runner matches no tests" if not b["entries"] else f"`{b['key']}` no longer covers the tests"
            out.append(Hit(b["added"][0], rule="test-config-weakening", severity="P1", why=why))

    def counts(key: str) -> bool:
        named = [k for k in stack if k]
        if kind == "package":
            return "jest" in named and key in ("testPathIgnorePatterns",) + _JS_INCLUDE_KEYS
        if kind == "jest":
            return key in ("testPathIgnorePatterns",) + _JS_INCLUDE_KEYS
        # vitest / workspace: only the `test` block, or an unknown scope the hunk starts inside.
        return key in ("include", "exclude") and (named[-1] if named else "") in ("", "test")

    for ln, raw in view:
        code = fake_exit.strip_code(raw, hash_comments=False)
        bare = re.sub(r"\s//.*$", "", raw)
        if block is not None:
            quoted = [q for _, q in _QUOTED_RE.findall(bare)]
            block["entries"] += quoted
            if ln in added:
                block["added"].append(ln)
                if block["key"] in ("testPathIgnorePatterns", "exclude") and any(not _benign_entry(q) for q in quoted):
                    out.append(Hit(ln, rule="test-config-weakening", severity="P1", why=ignore_why))
            if "]" in code:
                close(block)
                block = None
            continue
        last_key = ""
        for m in _JS_KEY_RE.finditer(code):
            tok = m.group(0)
            if tok == "{":
                stack.append(last_key)
                last_key = ""
            elif tok == "}":
                if stack:
                    stack.pop()
                last_key = ""
            else:
                key = last_key = m.group(1)
                if not counts(key):
                    continue
                rest = code[m.end():].lstrip()
                pos = bare.find(key)
                tail = bare[pos + len(key):] if pos >= 0 else ""
                value = tail.split("]", 1)[0] if rest.startswith("[") else re.split(r",\s*\w+\s*:", tail, maxsplit=1)[0]
                entries = [q for _, q in _QUOTED_RE.findall(value)]
                b = {"key": key, "entries": entries, "added": [ln] if ln in added else []}
                if ln in added and key in ("testPathIgnorePatterns", "exclude") and any(not _benign_entry(e) for e in entries):
                    out.append(Hit(ln, rule="test-config-weakening", severity="P1", why=ignore_why))
                if rest.startswith("[") and "]" not in rest:
                    block = b
                    break
                close(b)
        if ln not in added:
            continue
        if re.search(r"""\bpassWithNoTests["']?\s*:\s*true\b|--passWithNoTests\b""", bare):
            out.append(Hit(ln, rule="test-config-weakening", severity="P1", why="the test runner passes with no tests"))
        elif any(not _benign_entry(v) for v in re.findall(r"--testPathIgnorePatterns[=\s]+([^\s\"']+)", bare)):
            out.append(Hit(ln, rule="test-config-weakening", severity="P1", why=ignore_why))
        if re.search(r"""\bsilent["']?\s*:\s*true\b""", code):
            silent = ln
        if re.search(r"""\bforceExit["']?\s*:\s*true\b""", code):
            force_exit = ln
    if block is not None:
        close(block)
    if silent and force_exit:
        out.append(Hit(force_exit, rule="test-config-weakening", severity="P1", why="`silent` with `forceExit` hides failures and kills the run"))
    return out


# --- By value against the base ----------------------------------------------------


def _pytest_settings(name: str, text: str | None) -> dict[str, list[str]] | None:
    """{key: entries} of the pytest settings in a config file; None when it cannot be parsed."""
    if text is None:
        return {}
    raw: dict[str, Any] = {}
    try:
        if name == "pyproject.toml":
            if tomllib is None:
                return None
            tool = tomllib.loads(text).get("tool", {})
            pt = tool.get("pytest", {}) if isinstance(tool, dict) else {}
            raw = pt.get("ini_options", pt) if isinstance(pt, dict) else {}
            if not isinstance(raw, dict):
                return None
        else:
            cp = configparser.ConfigParser(interpolation=None, strict=False)
            cp.read_string(text)
            section = "tool:pytest" if name == "setup.cfg" else "pytest"
            raw = dict(cp[section]) if cp.has_section(section) else {}
    except (ValueError, configparser.Error, TypeError):
        return None
    out: dict[str, list[str]] = {}
    for key in ("addopts", "norecursedirs") + _PY_INCLUDE_KEYS:
        if key not in raw:
            continue
        v = raw[key]
        try:
            if key == "addopts":
                out[key] = [t for item in (v if isinstance(v, list) else [v]) for t in shlex.split(str(item))]
            else:
                out[key] = [str(e) for e in v] if isinstance(v, list) else str(v).split()
        except ValueError:
            return None
    return out


def _jest_settings(name: str, text: str | None) -> dict[str, Any] | None:
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if name == "package.json":
        data = data.get("jest", {})
    return data if isinstance(data, dict) else None


def _narrowed(key: str, base: list[str] | None, head: list[str]) -> str:
    if base is not None:
        removed = [e for e in base if e not in head]
        return f"`{key}` drops {', '.join(removed)}" if removed else ""
    if _broad(head):
        return ""
    return f"`{key}` is empty" if not head else f"`{key}` no longer covers the tests: {', '.join(head)}"


def _as_strs(v: Any) -> list[str]:
    return [str(e) for e in (v if isinstance(v, list) else [v])]


def compare_config(rel_path: str, base_text: str | None, head_text: str) -> list[tuple[str, str]] | None:
    """Ways the test-runner settings in `rel_path` narrow the run compared with the
    base (an absent file is an empty config), as (why, needle to find the added
    line). None when the file is not a TOML/INI/JSON test config or either side
    cannot be parsed: the caller keeps the line check."""
    kind = config_kind(rel_path)
    name = Path(rel_path).name
    out: list[tuple[str, str]] = []
    if kind == "pytest":
        b, h = _pytest_settings(name, base_text), _pytest_settings(name, head_text)
        if b is None or h is None:
            return None
        for opt, val in sorted(_addopts_narrowing(h.get("addopts", [])) - _addopts_narrowing(b.get("addopts", []))):
            out.append((f"pytest `addopts` adds `{(opt + ' ' + val).strip()}`", val or opt))
        for key in _PY_INCLUDE_KEYS:
            if key in h:
                why = _narrowed(key, b.get(key), h[key])
                if why:
                    out.append((why, key))
        new = [e for e in h.get("norecursedirs", []) if e not in b.get("norecursedirs", []) and not _benign_entry(e)]
        if new:
            out.append((f"`norecursedirs` adds {', '.join(new)}", new[0]))
        return out
    if kind == "package" or (kind == "jest" and name.endswith(".json")):
        b, h = _jest_settings(name, base_text), _jest_settings(name, head_text)
        if b is None or h is None:
            return None
        if h.get("passWithNoTests") is True and b.get("passWithNoTests") is not True:
            out.append(("`passWithNoTests` set to true", "passWithNoTests"))
        if h.get("silent") is True and h.get("forceExit") is True and not (b.get("silent") is True and b.get("forceExit") is True):
            out.append(("`silent` with `forceExit` hides failures and kills the run", "forceExit"))
        bi = _as_strs(b.get("testPathIgnorePatterns", []))
        new = [e for e in _as_strs(h.get("testPathIgnorePatterns", [])) if e not in bi and not _benign_entry(e)]
        if new:
            out.append((f"`testPathIgnorePatterns` adds {', '.join(new)}", new[0]))
        for key in _JS_INCLUDE_KEYS:
            if key in h:
                why = _narrowed(key, _as_strs(b[key]) if key in b else None, _as_strs(h[key]))
                if why:
                    out.append((why, key))
        return out
    return None


# --- Test commands ----------------------------------------------------------------

_MAKEFILE_RE = re.compile(r"(?:^|/)(?:GNUmakefile|[Mm]akefile|[^/]+\.mk)$")
_MAKE_TARGET_RE = re.compile(r"^([\w./-]+)\s*:(?!=)(.*)$")
_MAKE_TEST_TARGET_RE = re.compile(r"(?:test|tests|check|unit|integration|coverage|ci)\b")
# A "test" entry anywhere on the line, so `"scripts": {"test": "jest || true"}` on one line counts.
_PKG_TEST_SCRIPT_RE = re.compile(r'(?:^|[{,])\s*"(test(?::[\w:.-]+)?)"\s*:\s*"((?:[^"\\]|\\.)*)"')
_TRIVIAL_CMD = r"(?:echo\b[^&|;]*|true|:|exit(?:\s+0)?)"
_TRIVIAL_SCRIPT_RE = re.compile(rf"\s*@?{_TRIVIAL_CMD}\s*(?:(?:&&|;)\s*{_TRIVIAL_CMD}\s*)*;?\s*")
_SWALLOW_RE = re.compile(r"\|\|\s*(?:true|:|echo\b|exit\s+0)\b|;\s*(?:exit\s+0|true)\s*$")
_PIPE_RE = re.compile(r"(?<!\|)\|(?![|&])")
_LINT_CMD_RE = re.compile(
    r"\s*(?:(?:npx|pnpm\s+exec|yarn|bunx)\s+)?(?:eslint|prettier|tsc|biome|ruff|flake8|mypy|pylint|stylelint|black|oxlint)\b[^&|;]*"
    r"|\s*(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:lint|typecheck|type-check|format|check-types)(?::[\w-]+)?\b[^&|;]*"
)
_TOX_RE = re.compile(r"(?:^|/)tox\.ini$")
_TOX_WEAK_RE = re.compile(r"^\s*(?:commands\s*=\s*)?(?:-\s*\S|true\s*$|exit\s+0\b)|\bignore_outcome\s*=\s*true\b", re.IGNORECASE)
_NOX_RE = re.compile(r"(?:^|/)noxfile\.py$")
_NOX_WEAK_RE = re.compile(r"\bsuccess_codes\s*=\s*[\[(][^\])]*\b1\b")


def cannot_fail(cmd: str, pipefail: bool = False) -> bool:
    """True when a shell command's exit status cannot reflect a failing test run."""
    cmd = cmd.strip().lstrip("@+")
    if cmd.startswith("-") or _SWALLOW_RE.search(cmd) or _TRIVIAL_SCRIPT_RE.fullmatch(cmd):
        return True
    return bool(_PIPE_RE.search(cmd)) and not pipefail and "pipefail" not in cmd


def _script_hits(hunk: Any, rel_path: str) -> list[Hit]:
    out: list[Hit] = []
    name = Path(rel_path).name
    if name == "package.json":
        for ln, raw in hunk.added_lines:
            # Every test script on the line: a one-line "scripts" object can hold several.
            for m in _PKG_TEST_SCRIPT_RE.finditer(raw):
                cmd = m.group(2)
                lint_only = m.group(1) == "test" and all(_LINT_CMD_RE.fullmatch(c) for c in re.split(r"&&|\|\||;", cmd))
                if lint_only or cannot_fail(cmd):
                    out.append(Hit(ln, rule="test-script-neutered", severity="P0", why=f"the `{m.group(1)}` script can no longer fail"))
                    break
    elif _MAKEFILE_RE.search(rel_path):
        added = {ln for ln, _ in hunk.added_lines}
        view = sorted(hunk.context_lines + hunk.added_lines)
        pipefail = any("pipefail" in t for _, t in view)
        recipes: list[dict[str, Any]] = []

        def start(target: str, rest: str, ln: int | None) -> dict[str, Any]:
            prereqs, _, inline = rest.partition(";")
            r: dict[str, Any] = {"target": target, "prereqs": prereqs.strip(), "lines": [], "head": ln}
            if inline.strip() and ln is not None:
                r["lines"].append((ln, inline))
            recipes.append(r)
            return r

        m = _MAKE_TARGET_RE.match(_header(hunk))
        cur: dict[str, Any] | None = start(m.group(1), m.group(2), None) if m else None
        # Targets whose recipe lost a line in this hunk.
        shrunk, target = set(), cur["target"] if cur else ""
        for raw in getattr(hunk, "raw_lines", [])[1:]:
            sign, text = raw[:1], raw[1:]
            if (tm := _MAKE_TARGET_RE.match(text)) and sign in " +-":
                target = tm.group(1) if sign != "-" else target
            elif sign == "-" and text.startswith("\t"):
                shrunk.add(target)
        for ln, raw in view:
            if raw.startswith("\t"):
                if cur is not None:
                    cur["lines"].append((ln, raw))
                continue
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            m = _MAKE_TARGET_RE.match(raw)
            cur = start(m.group(1), m.group(2), ln) if m else None
        for r in recipes:
            lns = [ln for ln, _ in r["lines"]]
            touched = [ln for ln in [r["head"], *lns] if ln in added]
            if not _MAKE_TEST_TARGET_RE.match(r["target"]) or r["prereqs"] or not lns or not (touched or r["target"] in shrunk):
                continue
            if all(cannot_fail(c, pipefail) for _, c in r["lines"]):
                out.append(Hit((touched or lns)[0], rule="test-script-neutered", severity="P0",
                               why=f"the `{r['target']}` target can no longer fail"))
    elif _TOX_RE.search(rel_path):
        out += [Hit(ln, rule="test-script-neutered", severity="P0", why="a tox command can no longer fail")
                for ln, raw in hunk.added_lines if _TOX_WEAK_RE.search(raw) or _SWALLOW_RE.search(raw)]
    elif _NOX_RE.search(rel_path):
        out += [Hit(ln, rule="test-script-neutered", severity="P0", why="nox accepts a failing exit code")
                for ln, raw in hunk.added_lines if _NOX_WEAK_RE.search(raw)]
    return out
