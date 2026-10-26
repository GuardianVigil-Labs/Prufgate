"""`prufgate verify --mutation`: a mutation smoke test on the lines a branch changed.

A test written hollow from the start passes on the base and on the head, so no diff check sees it.
Mutating the changed production lines does: when a mutant (a flipped comparison, a dropped call, a
replaced return value) survives, no test notices that line doing the wrong thing.

PrufGate does not mutate anything itself. It runs a mutation tool that is already installed, never
installs one, and reads the tool's machine-readable report:

| language | tool | restricted to | report |
|---|---|---|---|
| Python | mutmut (3.x) | mutants of the changed modules (name globs) | `mutants/<file>.meta` and `mutmut show` |
| JavaScript, TypeScript | Stryker | changed line ranges (`--mutate file:a-b`) | `reports/mutation/mutation.json` |
| Java (Maven) | PIT | the changed classes (`-DtargetClasses`), offline | `pit-reports/mutations.xml` |
| Go | gremlins | the diff against the merge base (`--diff`) | `--output` JSON |
| Go | go-mutesting (avito-tech) | the changed files | `report.json` |
| Rust | cargo-mutants | the diff against the merge base (`--in-diff`) | `mutants.out/outcomes.json` |

Running the tool runs the repository's tests, so this is opt-in exactly like `--differential` and
shares its containment (`prufgate/repo_runner.py`): a temporary worktree of the committed HEAD, a
reduced environment, a timeout that kills the process group, cleanup on signals. It is never part of
`check`, the batteries, the MCP server, the API or the hooks.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from prufgate.diff_guard.tamper_detector import parse_unified_diff
from prufgate.differential import part_of_test_run
from prufgate.repo_runner import RunError, env, git, head_worktree, run_command

RULE = "mutation-survivor"
RULE_NO_COVERAGE = "mutation-no-coverage"
TMP_PREFIX = "prufgate-mutation-"
DEFAULT_TIMEOUT = 1800
DEFAULT_MAX_MUTANTS = 200

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mts": "javascript", ".cts": "javascript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
}
# Tried in this order; the first one installed is used. (executable, how to install it)
TOOLS: dict[str, list[tuple[str, str, str]]] = {
    "python": [("mutmut", "mutmut", "pip install mutmut")],
    "javascript": [("stryker", "stryker", "npm install --save-dev @stryker-mutator/core")],
    "java": [("pit", "mvn", "Maven, with org.pitest:pitest-maven in its local repository")],
    "go": [("gremlins", "gremlins", "go install github.com/go-gremlins/gremlins/cmd/gremlins@latest"),
           ("go-mutesting", "go-mutesting",
            "go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest")],
    "rust": [("cargo-mutants", "cargo-mutants", "cargo install --locked cargo-mutants")],
}
TOOL_LANGUAGE = {name: lang for lang, tools in TOOLS.items() for name, _, _ in tools}
TOOL_EXE = {name: exe for tools in TOOLS.values() for name, exe, _ in tools}

KILLED, SURVIVED, TIMEOUT, NO_COVERAGE, OTHER = "killed", "survived", "timeout", "no coverage", "other"


@dataclass
class Mutant:
    file: str
    line: int
    status: str
    description: str


@dataclass
class Result:
    tools: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: Counter = field(default_factory=Counter)  # status -> count, on changed lines
    outside: int = 0  # mutants the tool reported outside the changed lines


@dataclass
class Job:
    """What one tool run needs: where it runs, what changed, and the budget."""
    root: Path  # the worktree
    tmp: Path  # scratch space outside the worktree
    base: str  # merge-base commit
    changed: dict[str, set[int]]  # production file -> changed (added) line numbers, this tool's language
    timeout: int
    max_mutants: int
    environ: dict[str, str]

    def run(self, cmd: list[str], name: str = "tool", ok: tuple[int, ...] = (0,)) -> tuple[int, str]:
        """Run the tool; any exit code outside `ok` is an error, never a pass."""
        rc, out = run_command(cmd, self.root, self.environ, self.timeout, self.tmp / f"{name}.log")
        if rc not in ok:
            raise RunError(f"{name} failed (exit {rc}):\n{out[-2000:]}")
        return rc, out

    def clear(self, *patterns: str) -> None:
        """Delete the report paths the repository may have committed, so only what this run writes is read."""
        root = self.root.resolve()
        for pattern in patterns:
            for p in sorted(self.root.glob(pattern), reverse=True):
                if not p.parent.resolve().is_relative_to(root):
                    raise RunError(f"report path {pattern} leads outside the worktree (a committed symlink)")
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                else:
                    p.unlink()


def changed_lines(root: Path, base_commit: str) -> dict[str, set[int]]:
    """{production file: lines added or changed in HEAD} against `base_commit`; test files are not mutated."""
    diff = git(root, "diff", "-U0", "--no-color", "--no-ext-diff", "--no-renames", base_commit, "HEAD")
    # Regular files only: a committed symlink would let an in-place mutator write outside the worktree.
    regular = {line.split("\t", 1)[1] for line in git(root, "ls-tree", "-r", "-z", "HEAD").split("\0")
               if line.split(" ", 1)[0] in ("100644", "100755") and "\t" in line}
    out: dict[str, set[int]] = {}
    for hunk in parse_unified_diff(diff):
        path = hunk.file_path
        if hunk.is_deleted_file or not hunk.added_lines or part_of_test_run(path) or path not in regular:
            continue
        if Path(path).suffix.lower() in LANGUAGE_BY_SUFFIX:
            out.setdefault(path, set()).update(ln for ln, _ in hunk.added_lines)
    return out


def detect_tool(language: str) -> str | None:
    return next((name for name, _, _ in TOOLS[language] if installed(name)), None)


def installed(tool: str) -> bool:
    return bool(shutil.which(TOOL_EXE[tool])) and (tool != "cargo-mutants" or bool(shutil.which("cargo")))


def install_hint(language: str) -> str:
    return " or ".join(f"{name} ({hint})" for name, _, hint in TOOLS[language])


def _ranges(lines: set[int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for ln in sorted(lines):
        if out and ln == out[-1][1] + 1:
            out[-1] = (out[-1][0], ln)
        else:
            out.append((ln, ln))
    return out


def _rel(root: Path, path: str) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    return p.as_posix()


def _match_file(name: str, files: dict[str, set[int]]) -> str | None:
    """The changed file a tool's report path names: exact, or the one the report path ends with
    (tools report paths relative to a module or package root)."""
    if name in files:
        return name
    hits = [f for f in files if f.endswith("/" + name) or name.endswith("/" + f)]
    if len(hits) > 1:  # dropping them would count their survivors as outside the change
        raise RunError(f"the tool's report path {name} matches several changed files: {', '.join(sorted(hits))}")
    return hits[0] if hits else None


def _load_json(path: Path, tool: str, out: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RunError(f"{tool} wrote no readable report at {path.name}:\n{out[-2000:]}") from None


# --- mutmut ---------------------------------------------------------------------------------------

_MUTMUT_STATUS = {0: SURVIVED, 1: KILLED, 3: KILLED, 5: NO_COVERAGE, 33: NO_COVERAGE, 36: TIMEOUT, 24: TIMEOUT,
                  -24: TIMEOUT, 152: TIMEOUT, 255: TIMEOUT, 37: KILLED}


def _py_module(path: str) -> str:
    mod = path[:-3].replace("/", ".")
    mod = mod[4:] if mod.startswith("src.") else mod
    return mod[: -len(".__init__")] if mod.endswith(".__init__") else mod


def _py_function_span(source: str, mangled: str) -> tuple[int, int] | None:
    """The (first, last) line of the function mutmut names `x_func` or `xǁClassǁmethod`."""
    parts = mangled[1:].split("ǁ") if mangled.startswith("xǁ") else [mangled[2:]]
    parts = [p for p in parts if p]
    try:
        nodes: list[ast.AST] = list(ast.parse(source).body)
    except SyntaxError:
        return None
    found = None
    for part in parts:
        found = next((n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                      and n.name == part), None)
        if found is None:
            return None
        nodes = list(found.body)
    if found is None:
        return None
    # mutmut shows a decorated function from its first decorator line.
    start = min([found.lineno] + [d.lineno for d in getattr(found, "decorator_list", [])])
    return start, getattr(found, "end_lineno", None) or found.lineno


def _diff_change(diff: str) -> tuple[int | None, str]:
    """(1-based line of the first change in the old side, `- old` / `+ new` description) of a unified diff."""
    old_ln, first, removed, added = None, None, [], []
    for line in diff.splitlines():
        m = re.match(r"@@ -(\d+)", line)
        if m:
            old_ln = int(m.group(1))
        elif old_ln is None or line.startswith(("---", "+++")):
            continue
        elif line.startswith("-"):
            first = first or old_ln
            removed.append(line[1:].strip())
            old_ln += 1
        elif line.startswith("+"):
            first = first or old_ln
            added.append(line[1:].strip())
        else:
            old_ln += 1
    return first, f"`{' '.join(removed)}` -> `{' '.join(added)}`"


def _mutmut(job: Job) -> list[Mutant]:
    globs = sorted({f"{_py_module(f)}.*" for f in job.changed})
    job.clear("mutants")
    _, out = job.run(["mutmut", "run", "--", *globs], "mutmut")
    metas = {p: job.root / "mutants" / (p + ".meta") for p in job.changed}
    mutants = []
    for path, meta in metas.items():
        if not meta.is_file():
            continue  # nothing in this file that mutmut mutates
        codes = (_load_json(meta, "mutmut", out).get("exit_code_by_key") or {})
        source = (job.root / path).read_text(encoding="utf-8", errors="replace")
        for key, code in codes.items():
            if code is None:
                continue  # not checked
            status = _MUTMUT_STATUS.get(code, OTHER)
            mangled = re.sub(r"__mutmut_\d+$", "", key.rpartition(".")[2])
            start, end = _py_function_span(source, mangled) or (1, 1)
            # Only a survivor's line is looked up; the others count on the function's first changed line.
            line = min((ln for ln in job.changed[path] if start <= ln <= end), default=start)
            desc = f"mutant {key}"
            if status == SURVIVED:
                _, shown = job.run(["mutmut", "show", "--", key], "mutmut-show")
                rel, change = _diff_change(shown)
                # ponytail: mutmut diffs the function alone, so the line is its first line plus the offset in it.
                line, desc = (start + rel - 1 if rel else start), change
            mutants.append(Mutant(path, line, status, desc))
    return mutants


# --- Stryker --------------------------------------------------------------------------------------

_STRYKER_STATUS = {"Killed": KILLED, "Survived": SURVIVED, "Timeout": TIMEOUT, "NoCoverage": NO_COVERAGE}


def _stryker(job: Job) -> list[Mutant]:
    mutate = ",".join(f"{f}:{a}-{b}" for f, lines in sorted(job.changed.items()) for a, b in _ranges(lines))
    job.clear("reports/mutation")
    _, out = job.run(["stryker", "run", "--reporters", "json", "--mutate", mutate], "stryker")
    report = _load_json(job.root / "reports" / "mutation" / "mutation.json", "stryker", out)
    mutants = []
    for name, entry in (report.get("files") or {}).items():
        path = _rel(job.root, name)
        for m in entry.get("mutants") or []:
            line = int(((m.get("location") or {}).get("start") or {}).get("line") or 0)
            desc = f"{m.get('mutatorName', 'mutation')}: `{m.get('replacement', '')}`"
            mutants.append(Mutant(path, line, _STRYKER_STATUS.get(m.get("status"), OTHER), desc))
    return mutants


# --- PIT ------------------------------------------------------------------------------------------

_PIT_STATUS = {"KILLED": KILLED, "SURVIVED": SURVIVED, "TIMED_OUT": TIMEOUT, "NO_COVERAGE": NO_COVERAGE}


def _java_class(root: Path, path: str) -> str:
    src = re.sub(r"/\*.*?\*/|//[^\n]*", "", (root / path).read_text(encoding="utf-8", errors="replace"), flags=re.S)
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", src, re.MULTILINE)
    return (m.group(1) + "." if m else "") + Path(path).stem


def _pit(job: Job) -> list[Mutant]:
    classes = {_java_class(job.root, f): f for f in job.changed}
    cmd = ["mvn", "-o", "-B", "-q", "org.pitest:pitest-maven:mutationCoverage",
           "-DtargetClasses=" + ",".join(sorted(f"{c}*" for c in classes)),
           "-DoutputFormats=XML", "-DtimestampedReports=false",
           f"-Dfeatures=+CLASSLIMIT(limit[{job.max_mutants}])"]
    job.clear("**/pit-reports")
    _, out = job.run(cmd, "pit")
    reports = sorted(job.root.glob("**/pit-reports/mutations.xml"))
    if not reports:
        raise RunError(f"pit wrote no mutations.xml report:\n{out[-2000:]}")
    mutants = []
    for report in reports:
        try:
            tree = ET.parse(report)
        except ET.ParseError as exc:
            raise RunError(f"pit report {report.name} is not valid XML: {exc}") from None
        for m in tree.iter("mutation"):
            cls = (m.findtext("mutatedClass") or "").split("$")[0]
            path = classes.get(cls)
            if path is None:
                continue
            desc = m.findtext("description") or m.findtext("mutator") or "mutation"
            line = int(m.findtext("lineNumber") or 0)
            mutants.append(Mutant(path, line, _PIT_STATUS.get(m.get("status", ""), OTHER), desc))
    return mutants


# --- Go -------------------------------------------------------------------------------------------

_GREMLINS_STATUS = {"KILLED": KILLED, "LIVED": SURVIVED, "TIMED OUT": TIMEOUT, "NOT COVERED": NO_COVERAGE}


def _gremlins(job: Job) -> list[Mutant]:
    report = job.tmp / "gremlins.json"
    _, out = job.run(["gremlins", "unleash", "--diff", job.base, "--output", str(report), "."], "gremlins")
    data = _load_json(report, "gremlins", out)
    mutants = []
    for entry in data.get("files") or []:
        path = _match_file(str(entry.get("file_name", "")), job.changed) or str(entry.get("file_name", ""))
        for m in entry.get("mutations") or []:
            mutants.append(Mutant(path, int(m.get("line") or 0), _GREMLINS_STATUS.get(m.get("status"), OTHER),
                                  str(m.get("type") or "mutation")))
    return mutants


def _go_mutesting(job: Job) -> list[Mutant]:
    config = job.tmp / "go-mutesting.yml"
    config.write_text("json_output: true\nsilent_mode: true\n", encoding="utf-8")
    report = job.root / "report.json"
    job.clear("report.json")
    _, out = job.run(["go-mutesting", f"--config={config}", "--", *sorted(job.changed)], "go-mutesting")
    if not report.is_file():
        raise RunError("go-mutesting wrote no report.json (the JSON report needs the avito-tech fork):\n"
                       + out[-2000:])
    data = _load_json(report, "go-mutesting", out)
    mutants = []
    for key, status in (("escaped", SURVIVED), ("killed", KILLED), ("timeouted", TIMEOUT), ("errored", OTHER)):
        for m in data.get(key) or []:
            mut = m.get("mutator") or {}
            path = _rel(job.root, str(mut.get("originalFilePath", "")))
            path = _match_file(path, job.changed) or path
            desc = str(mut.get("mutatorName") or "mutation")
            if m.get("diff"):
                desc += ": " + _diff_change(str(m["diff"]))[1]
            mutants.append(Mutant(path, int(mut.get("originalStartLine") or 0), status, desc))
    return mutants


# --- cargo-mutants --------------------------------------------------------------------------------

_CARGO_STATUS = {"CaughtMutant": KILLED, "MissedMutant": SURVIVED, "Timeout": TIMEOUT, "Unviable": OTHER}


def _cargo_mutants(job: Job) -> list[Mutant]:
    diff = job.tmp / "change.diff"
    diff.write_text(git(job.root, "diff", "--no-color", "--no-ext-diff", job.base, "HEAD"), encoding="utf-8")
    _, out = job.run(["cargo", "mutants", "--in-diff", str(diff), "--output", str(job.tmp)], "cargo-mutants",
                     ok=(0, 2, 3))  # 2: missed mutants, 3: timeouts; the report says which
    data = _load_json(job.tmp / "mutants.out" / "outcomes.json", "cargo-mutants", out)
    mutants = []
    for o in data.get("outcomes") or []:
        scenario = o.get("scenario")
        if not isinstance(scenario, dict) or "Mutant" not in scenario:
            continue  # the baseline run
        m = scenario["Mutant"]
        line = int((((m.get("span") or {}).get("start")) or {}).get("line") or 0)
        desc = str(m.get("name") or f"replace with `{m.get('replacement', '')}`")
        mutants.append(Mutant(str(m.get("file", "")), line, _CARGO_STATUS.get(o.get("summary"), OTHER), desc))
    return mutants


RUNNERS: dict[str, Callable[[Job], list[Mutant]]] = {
    "mutmut": _mutmut, "stryker": _stryker, "pit": _pit, "gremlins": _gremlins,
    "go-mutesting": _go_mutesting, "cargo-mutants": _cargo_mutants,
}


def run(
    repo: Path,
    base: str,
    tool: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_mutants: int = DEFAULT_MAX_MUTANTS,
    pass_env: list[str] | None = None,
) -> Result:
    root = Path(git(repo, "rev-parse", "--show-toplevel").strip())
    git(root, "rev-parse", "--verify", "-q", "--end-of-options", f"{base}^{{commit}}")
    base_commit = git(root, "merge-base", "--end-of-options", base, "HEAD").strip()
    changed = changed_lines(root, base_commit)
    if tool is not None:
        if tool not in RUNNERS:
            raise RunError(f"unknown mutation tool {tool!r} (one of: {', '.join(RUNNERS)})")
        if not installed(tool):
            raise RunError(f"--tool {tool}: {TOOL_EXE[tool]} is not on PATH. PrufGate never installs it.")
        lang = TOOL_LANGUAGE[tool]
        changed = {f: ls for f, ls in changed.items() if LANGUAGE_BY_SUFFIX[Path(f).suffix.lower()] == lang}
    result = Result(files=sorted(changed))
    if not changed:
        return result  # nothing to mutate: no tool needed, nothing runs
    plan: dict[str, dict[str, set[int]]] = {}
    for path, lines in changed.items():
        lang = LANGUAGE_BY_SUFFIX[Path(path).suffix.lower()]
        name = tool or detect_tool(lang)
        if name is None:
            raise RunError(f"no mutation tool for the changed {lang} file(s) is installed: install {install_hint(lang)}, "
                           "or pass --tool. PrufGate never installs one.")
        plan.setdefault(name, {})[path] = lines
    result.tools = sorted(plan)
    with head_worktree(root, TMP_PREFIX) as tmp:
        for name, files in sorted(plan.items()):
            job = Job(tmp / "head", tmp, base_commit, files, timeout, max_mutants, env(pass_env or []))
            for m in RUNNERS[name](job):
                if m.file not in files or m.line not in files[m.file]:
                    result.outside += 1
                    continue
                result.summary[m.status] += 1
                if m.status in (SURVIVED, NO_COVERAGE):
                    result.findings.append(_finding(m, name))
    if not result.summary:
        # ponytail: one check for the whole run; a changed file the tool skipped next to one it mutated
        # still passes. Per-file would fail every comment-only edit.
        raise RunError(f"{', '.join(result.tools)} reported no mutants on the changed lines of "
                       f"{', '.join(result.files)}: nothing was tested, so this is not a pass. Check the tool's "
                       "configuration does not exclude these files (for example mutmut's paths_to_mutate).")
    result.findings.sort(key=lambda f: (f["file"], f["line"]))
    return result


def _finding(m: Mutant, tool: str) -> dict[str, Any]:
    if m.status == NO_COVERAGE:
        rule, message = RULE_NO_COVERAGE, (f"no test runs this changed line ({tool}: {m.description}): "
                                           "a mutant of it was never tested.")
    else:
        rule, message = RULE, (f"a mutant of this changed line survives the tests ({tool}: {m.description}): "
                               "no test fails when this line does the wrong thing.")
    return {
        "engine": "mutation",
        "rule": rule,
        "severity": "P1",
        "file": m.file,
        "line": m.line,
        "message": message,
        "snippet": "",
    }
