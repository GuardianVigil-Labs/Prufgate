"""Linter and type-checker configuration compared by value with the base.

The line-based check in `tamper_detector` sees one added line at a time, so it
misses an entry added on its own line inside an existing list, a new code under
an existing per-file-ignores key, or a `select` list that shrinks. This module
parses the file at both sides and reports every way the branch is looser:

- new ignore, exclude or disable entries;
- new per-file-ignores keys, or new codes under an existing key;
- removed select or enable entries;
- a strictness flag set (or left by removal) at its lax value, a rule turned off.

Tightening (an ignore removed, a select entry added) is never reported.

TOML needs `tomllib` (Python 3.11+). On Python 3.9 and 3.10, and for any file
that cannot be parsed at either side (INI files, JavaScript configs, broken
syntax), `compare` returns None and the caller keeps the line-based check.
"""

from __future__ import annotations

import json
import re
from typing import Any

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.9/3.10 keep the line-based check
    tomllib = None  # type: ignore[assignment]  # optional on old Pythons

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]  # PyYAML is a declared dependency

MISSING = object()

# Lists where a new entry silences a check.
IGNORE_KEYS = {
    "ignore", "extend-ignore", "exclude", "extend-exclude", "disable", "ignorePatterns",
    "exclude-dirs", "exclude-files", "exclude-rules", "skip-dirs", "skip-files",
}
# Tables mapping a path to the codes ignored there.
PER_FILE_KEYS = {"per-file-ignores", "extend-per-file-ignores"}
# Lists where a removed entry stops a check.
SELECT_KEYS = {"select", "extend-select", "enable"}
# Strictness flags and their lax value.
LAX = {
    "strict": False, "noImplicitAny": False, "strictNullChecks": False, "strictFunctionTypes": False,
    "strictBindCallApply": False, "noImplicitReturns": False, "noUnusedLocals": False,
    "noUnusedParameters": False, "disallow_untyped_defs": False, "check_untyped_defs": False,
    "warn_return_any": False, "ignore_errors": True, "recommended": False, "all": False,
    "disable-all": True, "skipLibCheck": True,
}
LOW = {"skipLibCheck"}
# Keys that identify the same entry in a list of tables (mypy overrides, eslint overrides).
IDENTITY_KEYS = ("module", "files", "path", "include", "includes", "name")
# A tsconfig `exclude` is routine for build output; only source and tests count.
TS_SOURCE_EXCLUDE_RE = re.compile(r"(?:^|/)(?:src|lib|app|tests?|spec|__tests__)(?:/|\*|$)|^\*\*?(?:/\*)?$|\.(?:test|spec)\.")


def _strip_jsonc(text: str) -> str:
    """JSON with `//` and `/* */` comments and trailing commas, as plain JSON.
    Comment markers and commas inside strings are kept."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    stripped = "".join(out)
    # Trailing commas: comments and strings are gone or intact, so re-scan strings once more.
    out, i, n = [], 0, len(stripped)
    while i < n:
        c = stripped[i]
        if c == '"':
            j = i + 1
            while j < n and stripped[j] != '"':
                j += 2 if stripped[j] == "\\" else 1
            out.append(stripped[i : j + 1])
            i = j + 1
            continue
        if c == "," and re.match(r"\s*[}\]]", stripped[i + 1 :]):
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse(name: str, text: str | None) -> dict[str, Any] | None:
    """The settings in a linter config file, None when it cannot be parsed.
    An absent file (`text` None) is an empty config."""
    if text is None:
        return {}
    try:
        if name.endswith(".toml"):
            if tomllib is None:
                return None
            data: Any = tomllib.loads(text)
            if name == "pyproject.toml":
                tool = data.get("tool", {})
                return {k: tool[k] for k in ("ruff", "mypy") if k in tool}
        elif name.endswith((".json", ".jsonc")) or name == ".eslintrc":
            try:
                data = json.loads(_strip_jsonc(text))
            except ValueError:
                if name != ".eslintrc" or yaml is None:
                    raise
                data = yaml.safe_load(text)
        elif name.endswith((".yml", ".yaml")) and yaml is not None:
            data = yaml.safe_load(text)
        else:
            return None
    except (ValueError, TypeError, RecursionError):
        return None
    except Exception as e:  # yaml.YAMLError without importing it when PyYAML is absent
        if yaml is not None and isinstance(e, yaml.YAMLError):
            return None
        raise
    if data is None:
        return {}
    return data if isinstance(data, dict) else None


def _as_list(v: Any) -> list[Any]:
    if v is MISSING or v is None:
        return []
    return v if isinstance(v, list) else [v]


def _is_off(v: Any) -> bool:
    if isinstance(v, list):
        return bool(v) and _is_off(v[0])
    return v == "off" or (type(v) is int and v == 0)


def _show(v: Any) -> str:
    return json.dumps(v, sort_keys=True) if not isinstance(v, str) else v


def weakenings(base: dict[str, Any], head: dict[str, Any], tsconfig: bool = False) -> list[tuple[str, str, str]]:
    """Every way `head` is looser than `base`, as (description, needle, severity).
    The needle is text to look for on an added line to point at it."""
    out: list[tuple[str, str, str]] = []

    def walk(b: Any, h: Any, path: list[str]) -> None:
        key = re.sub(r"\[\d+\]$", "", path[-1]) if path else ""
        where = ".".join(path)
        parent = path[-2] if len(path) > 1 else ""
        if isinstance(h, dict) or (h is MISSING and isinstance(b, dict)):
            hd = h if isinstance(h, dict) else {}
            bd = b if isinstance(b, dict) else {}
            if key in PER_FILE_KEYS:
                for k, codes in hd.items():
                    if k not in bd:
                        out.append((f"`{where}` adds `{k}` = {_show(codes)}", k, "P0"))
                    else:
                        new = [c for c in _as_list(codes) if c not in _as_list(bd[k])]
                        if new:
                            out.append((f"`{where}` adds {', '.join(map(_show, new))} under `{k}`", _show(new[0]), "P0"))
                return
            for k, v in hd.items():
                walk(bd.get(k, MISSING), v, path + [str(k)])
            for k, v in bd.items():
                if k not in hd:
                    walk(v, MISSING, path + [str(k)])
            return
        if "rules" in path[:-1] and key not in LAX:
            # An eslint or biome rule: "off", 0 or ["off", ...] where it was on.
            if _is_off(h) and not _is_off(b):
                out.append((f"`{where}` turned off", key, "P0"))
            return
        if isinstance(h, list) or isinstance(b, list):
            hl, bl = _as_list(h), _as_list(b)
            if key in IGNORE_KEYS or parent == "exclusions":
                added = [e for e in hl if e not in bl]
                if tsconfig and key == "exclude":
                    added = [e for e in added if isinstance(e, str) and TS_SOURCE_EXCLUDE_RE.search(e)]
                if added:
                    out.append((f"`{where}` adds {', '.join(map(_show, added))}", _show(added[0]), "P0"))
            elif key in SELECT_KEYS:
                removed = [e for e in bl if e not in hl]
                if removed:
                    out.append((f"`{where}` removes {', '.join(map(_show, removed))}", key, "P0"))
            else:
                for i, entry in enumerate(hl):
                    if isinstance(entry, dict) and entry not in bl:
                        match = next(
                            (be for be in bl if isinstance(be, dict)
                             and any(k in entry and be.get(k) == entry[k] for k in IDENTITY_KEYS)),
                            {},
                        )
                        walk(match, entry, path[:-1] + [f"{path[-1]}[{i}]"])
            return
        if key in LAX:
            lax = LAX[key]
            sev = "P2" if key in LOW else "P0"
            if type(h) is bool and h == lax and not (type(b) is bool and b == lax):
                out.append((f"`{where}` set to {_show(h)}", key, sev))
            elif h is MISSING and type(b) is bool and b != lax and lax is False:
                out.append((f"`{where}` = {_show(b)} removed", key, sev))

    walk(base, head, [])
    return out


def compare(name: str, base_text: str | None, head_text: str) -> list[tuple[str, str, str]] | None:
    """Weakenings in linter config `name` (a file name), or None when either side
    cannot be parsed and the caller should fall back to the line-based check."""
    base, head = parse(name, base_text), parse(name, head_text)
    if base is None or head is None:
        return None
    return weakenings(base, head, tsconfig=name.startswith("tsconfig"))


# (case id, file name, base text or None, head text, expected substrings; [] = no finding; None = unparseable)
SELF_CHECK_CASES: list[tuple[str, str, str | None, str, list[str] | None]] = [
    ("ruff-per-file-new-code", "ruff.toml",
     '[lint.per-file-ignores]\n"tests/*" = ["S101"]\n', '[lint.per-file-ignores]\n"tests/*" = ["S101", "S314"]\n', ["S314"]),
    ("ruff-multiline-ignore", "ruff.toml",
     '[lint]\nignore = [\n    "E402",\n]\n', '[lint]\nignore = [\n    "E402",\n    "E501",\n]\n', ["E501"]),
    ("ruff-select-shrinks", "ruff.toml", '[lint]\nselect = ["E", "S"]\n', '[lint]\nselect = ["E"]\n', ["removes S"]),
    ("ruff-tightening", "ruff.toml", '[lint]\nselect = ["E"]\nignore = ["E501"]\n', '[lint]\nselect = ["E", "S"]\nignore = []\n', []),
    ("mypy-override-in-place", "pyproject.toml",
     '[[tool.mypy.overrides]]\nmodule = "app.*"\nwarn_unused_ignores = true\n',
     '[[tool.mypy.overrides]]\nmodule = "app.*"\nwarn_unused_ignores = true\nignore_errors = true\n', ["ignore_errors"]),
    ("tsconfig-strict-off-jsonc", "tsconfig.json",
     '{\n  // base\n  "compilerOptions": {"strict": true,},\n}\n', '{\n  "compilerOptions": {"strict": false},\n}\n', ["strict"]),
    ("tsconfig-exclude-dist-ok", "tsconfig.json", '{"exclude": []}', '{"exclude": ["dist"]}', []),
    ("eslint-override-off", ".eslintrc.json",
     '{"rules": {"no-eval": "error"}}', '{"rules": {"no-eval": "error"}, "overrides": [{"files": ["src/*"], "rules": {"no-eval": "off"}}]}',
     ["no-eval"]),
    ("golangci-exclude-rules", ".golangci.yml",
     "issues:\n  exclude-rules: []\n", "issues:\n  exclude-rules:\n    - linters: [gosec]\n      path: internal/\n", ["gosec"]),
    ("new-file-vs-empty", "biome.json", None, '{"files": {"ignore": ["src/**"]}}', ["src/**"]),
    ("unparseable", "ruff.toml", '[lint]\nignore = ["E501"]\n', "[lint\nignore = [", None),
]


def run_self_check() -> list[str]:
    """Failure descriptions for the built-in cases (TOML cases skipped without tomllib)."""
    failures = []
    for case_id, name, base, head, expected in SELF_CHECK_CASES:
        if name.endswith(".toml") and tomllib is None:
            continue
        got = compare(name, base, head)
        if expected is None or got is None:
            if expected is not got:
                failures.append(f"[linter-drift:{case_id}] expected {expected}, got {got}")
            continue
        text = " ".join(d for d, _, _ in got)
        if (not expected and got) or any(s not in text for s in expected):
            failures.append(f"[linter-drift:{case_id}] expected {expected}, got {text!r}")
    return failures
