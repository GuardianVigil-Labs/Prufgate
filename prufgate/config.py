"""Universal YAML/JSON Configuration Loader for PrufGate.

Supports `.prufgate/config.yaml`, `.prufgate/config.yml`, `.prufgate.yaml`, `.prufgate.yml`,
and legacy `.prufgate/fabrication.json` / `.prufgate/debt-ceiling.json` files.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

DEFAULT_CONFIG_FILES = (
    ".prufgate/config.yaml",
    ".prufgate/config.yml",
    ".prufgate.yaml",
    ".prufgate.yml",
    ".prufgate/fabrication.json",
    ".prufgate/debt-ceiling.json",
)

VALID_PACKS = {"core", "web-ui", "ai-safety", "cti"}
DEFAULT_PACKS = ("core", "web-ui", "ai-safety")

SUPPORTED_LANGUAGES = {
    "typescript",
    "javascript",
    "python",
    "go",
    "rust",
    "java",
    "kotlin",
    "php",
    "ruby",
    "csharp",
}

CONFIG_KEYS = {
    "version",
    "packs",
    "languages",
    "exclude",
    "allowed_paths",
    "auth_guards",
    "tenant_keys",
    "score_owners",
    "exempt",
    "known_debt",
    "model_call_patterns",
    "evidence_markers",
}

DEBT_REF_RE = re.compile(r"^#\d+:\s*\S")

# Bidirectional rule alias groups so legacy and current rule IDs work interchangeably
RULE_ALIAS_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"documentation-address", "documentation-ip-or-domain"}),
    frozenset({"demo-named-data", "fake-named-data", "fake-named-production-data"}),
    frozenset({"always-current-fake", "invented-event-timestamp", "always-current-fake-timestamp"}),
    frozenset({"prompt-invents-finding", "unseeded-llm-judgment-prompt"}),
    frozenset({"stub-click-handler", "stub-event-handler", "disconnected-form-submit", "disconnected-ui-handler"}),
    frozenset({"route-canned-fallback", "unhandled-empty-catch", "canned-error-fallback"}),
    frozenset({"zero-assertion-test", "assertion-free-test"}),
    frozenset({"self-mocked-unit-under-test", "over-mocked-sut"}),
    frozenset({"diff-assertion-weakening", "weakened-or-deleted-assertion-in-diff"}),
    frozenset({"test-skip-smuggling", "test-skip-or-focus-leak"}),
    frozenset({"suppression-comment-smuggling", "linter-or-type-suppression-abuse"}),
    frozenset({"undeclared-or-hallucinated-import", "ghost-dependency", "slopsquatting-import"}),
    frozenset({"undocumented-env-var-drift", "env-var-drift"}),
    frozenset({"frontend-backend-route-mismatch", "api-route-contract-mismatch"}),
    frozenset({"static-bola-unscoped-access", "BOLA-UNSCOPED-OBJECT-ACCESS"}),
    frozenset({"live-bola-differential-probe", "BOLA-CROSS-TENANT-ACCESS", "BOLA-UNAUTHENTICATED-ACCESS"}),
)


def expand_rule_aliases(rule: str) -> set[str]:
    """Return all equivalent aliases for a given rule ID (including itself)."""
    norm = rule.strip()
    out = {norm}
    for group in RULE_ALIAS_GROUPS:
        if norm in group:
            out |= group
    return out


def rules_match(rule_a: str, rule_b: str) -> bool:
    """Return True if rule_a and rule_b are identical or aliases of the same rule."""
    if rule_a == rule_b:
        return True
    return rule_b in expand_rule_aliases(rule_a)


def path_matches_pattern(rel: str, pattern: str) -> bool:
    """Return True if `rel` is the file `pattern` names, lies under the directory
    it names, or matches it as a glob. Never a bare substring: `a.py` must not
    match `data.py`, nor `test` match `src/latest.py`."""
    norm_rel = rel.replace("\\", "/").removeprefix("./")
    norm_pat = pattern.replace("\\", "/").removeprefix("./")
    if not norm_pat:
        return False
    if norm_rel == norm_pat.rstrip("/") or norm_rel.startswith(norm_pat.rstrip("/") + "/"):
        return True
    if any(ch in norm_pat for ch in "*?["):
        if fnmatch.fnmatch(norm_rel, norm_pat):
            return True
        if norm_pat.startswith("**/") and fnmatch.fnmatch(norm_rel, norm_pat[3:]):
            return True
        if norm_pat.endswith("/**") and norm_rel.startswith(norm_pat[:-2]):
            return True
    return False


class ConfigError(ValueError):
    """Raised when a PrufGate configuration file is missing, malformed, or invalid."""


def _parse_str_list(raw: Any, key: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) and x.strip() for x in raw):
        raise ConfigError(f"{key} must be a list of non-empty strings")
    return [x.strip() for x in raw]


def _parse_exempt(raw: Any) -> dict[tuple[str, str], str]:
    """Parse `exempt` in any of its three forms: a list of {path, rule, reason},
    {rule: [path, ...]} or {path: {rule: reason}}."""
    if raw is None or raw == {}:
        return {}
    out: dict[tuple[str, str], str] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(k), str) and item.get(k).strip() for k in ("path", "rule", "reason")
            ):
                raise ConfigError("each exempt entry needs a non-empty path, rule and reason")
            out[(item["path"].strip(), item["rule"].strip())] = item["reason"].strip()
        return out
    if isinstance(raw, dict):
        for rule_key, paths_val in raw.items():
            if isinstance(paths_val, dict):
                # {path: {rule: reason}}: the file-first form, a reason per rule.
                path_key = rule_key
                if not isinstance(path_key, str) or not path_key.strip() or not paths_val:
                    raise ConfigError("exempt file entries need a path and at least one rule")
                for r, reason in paths_val.items():
                    if not isinstance(r, str) or not r.strip() or not isinstance(reason, str) or not reason.strip():
                        raise ConfigError(f"exempt[{path_key!r}] needs a non-empty reason for each rule")
                    out[(path_key.strip(), r.strip())] = reason.strip()
                continue
            if not isinstance(rule_key, str) or not rule_key.strip():
                raise ConfigError("exempt mapping keys must be non-empty rule IDs")
            if not isinstance(paths_val, list) or not paths_val:
                raise ConfigError(f"exempt[{rule_key!r}] must be a non-empty list of file paths")
            for entry in paths_val:
                if isinstance(entry, str) and entry.strip():
                    out[(entry.strip(), rule_key.strip())] = f"Exempted in config under {rule_key.strip()}"
                elif isinstance(entry, dict) and isinstance(entry.get("path"), str) and entry["path"].strip():
                    reason = str(entry.get("reason") or f"Exempted in config under {rule_key.strip()}").strip()
                    out[(entry["path"].strip(), rule_key.strip())] = reason
                else:
                    raise ConfigError(f"exempt[{rule_key!r}] entries must be non-empty path strings or {{path, reason}} mappings")
        return out
    raise ConfigError("exempt must be a list or mapping")


def _parse_known_debt(raw: Any) -> tuple[dict[tuple[str, str], str], dict[str, int]]:
    """Parse `known_debt` into per-file tracked debt entries and per-rule numeric ratchet ceilings."""
    if raw is None or raw == {}:
        return {}, {}
    entries: dict[tuple[str, str], str] = {}
    ceilings: dict[str, int] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(k), str) and item.get(k).strip() for k in ("path", "rule", "reason")
            ):
                raise ConfigError("each known_debt entry needs a non-empty path, rule and reason")
            reason = item["reason"].strip()
            key = (item["path"].strip(), item["rule"].strip())
            if not DEBT_REF_RE.match(reason):
                raise ConfigError(f"known_debt {key} must start with an issue reference ('#123: why')")
            entries[key] = reason
        return entries, ceilings
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or not k.strip():
                raise ConfigError("known_debt keys must be non-empty strings")
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                ceilings[k.strip()] = v
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and isinstance(item.get("path"), str) and isinstance(item.get("reason"), str):
                        reason = item["reason"].strip()
                        key = (item["path"].strip(), k.strip())
                        if not DEBT_REF_RE.match(reason):
                            raise ConfigError(f"known_debt {key} must start with an issue reference ('#123: why')")
                        entries[key] = reason
                    else:
                        raise ConfigError(f"known_debt[{k!r}] list items must be {{path, reason}} mappings")
            else:
                raise ConfigError(f"known_debt[{k!r}] must be a non-negative integer ceiling or list of {{path, reason}} entries")
        return entries, ceilings
    raise ConfigError("known_debt must be a list or mapping")


@dataclass
class PrufGateConfig:
    """Normalized configuration for PrufGate."""

    version: int = 1
    packs: list[str] = field(default_factory=lambda: list(DEFAULT_PACKS))
    packs_explicit: bool = False
    languages: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    auth_guards: list[str] = field(default_factory=list)
    tenant_keys: list[str] = field(default_factory=list)
    score_owners: list[str] = field(default_factory=list)
    exempt: dict[tuple[str, str], str] = field(default_factory=dict)
    known_debt: dict[tuple[str, str], str] = field(default_factory=dict)
    known_debt_ceilings: dict[str, int] = field(default_factory=dict)
    model_call_patterns: list[str] = field(default_factory=list)
    evidence_markers: list[str] = field(default_factory=list)
    source_path: Path | None = None

    def is_excluded(self, rel_path: str) -> bool:
        """Return True if `rel_path` matches any pattern in `exclude`."""
        return any(path_matches_pattern(rel_path, pat) for pat in self.exclude)

    def is_exempt(self, rel_path: str, rule: str) -> bool:
        """Return True if `(rel_path, rule)` is exempted or tracked as per-file known debt."""
        for (ex_path, ex_rule) in list(self.exempt.keys()) + list(self.known_debt.keys()):
            if rules_match(ex_rule, rule) and path_matches_pattern(rel_path, ex_path):
                return True
        return False

    def to_detector_settings(self) -> dict[str, Any]:
        """Convert to the dictionary structure consumed by `detector.apply_settings()`."""
        return {
            "packs": list(self.packs) if self.packs_explicit else [],
            "default_packs": list(self.packs),
            "languages": list(self.languages),
            "exempt": dict(self.exempt),
            "known_debt": dict(self.known_debt),
            "known_debt_ceilings": dict(self.known_debt_ceilings),
            "score_owners": list(self.score_owners),
            "allowed_paths": list(self.exclude),
            "auth_guards": list(self.auth_guards),
            "tenant_keys": list(self.tenant_keys),
            "model_call_patterns": list(self.model_call_patterns),
            "evidence_markers": list(self.evidence_markers),
        }

    def check_debt_ratchet(self, findings: list[Any]) -> tuple[list[str], list[str]]:
        """Compare finding counts against `known_debt_ceilings`.

        Returns `(violations, ratchet_down_advisories)`:
        - `violations`: rules whose current count exceeds the configured ceiling (blocks CI).
        - `ratchet_down_advisories`: rules whose current count is lower than the ceiling
          so the developer can ratchet the ceiling down.
        """
        if not self.known_debt_ceilings:
            return [], []
        counts: dict[str, int] = {rule: 0 for rule in self.known_debt_ceilings}
        for f in findings:
            f_rule = getattr(f, "rule", None) or (f.get("rule") if isinstance(f, dict) else None)
            if not f_rule:
                continue
            for ceiling_rule in self.known_debt_ceilings:
                if rules_match(str(f_rule), ceiling_rule):
                    counts[ceiling_rule] = counts.get(ceiling_rule, 0) + 1

        violations: list[str] = []
        advisories: list[str] = []
        for rule, ceiling in sorted(self.known_debt_ceilings.items()):
            actual = counts.get(rule, 0)
            if actual > ceiling:
                violations.append(
                    f"known_debt ceiling breached for '{rule}': found {actual}, ceiling is {ceiling}"
                )
            elif actual < ceiling:
                advisories.append(
                    f"known_debt for '{rule}' improved ({actual} < {ceiling}): ratchet known_debt.{rule} down to {actual}"
                )
        return violations, advisories

    @classmethod
    def load(
        cls,
        repo_root: Path | str = ".",
        explicit_path: str | Path | None = None,
    ) -> PrufGateConfig:
        """Discover, parse, and validate `.prufgate/config.yaml` (or legacy JSON fallback)."""
        root = Path(repo_root)
        if explicit_path is not None:
            p = Path(explicit_path)
            if not p.is_absolute() and not p.is_file():
                candidate = root / p
                if candidate.is_file():
                    p = candidate
            if not p.is_file():
                raise ConfigError(f"settings file not found: {explicit_path}")
        else:
            found = next((root / rel for rel in DEFAULT_CONFIG_FILES if (root / rel).is_file()), None)
            if found is None:
                return cls()
            p = found

        raw = cls._read_raw_file(p)
        if not isinstance(raw, dict):
            raise ConfigError(f"{p}: expected a top-level mapping/object")

        # Handle legacy debt-ceiling.json files that may contain arbitrary rule-count keys
        if p.name == "debt-ceiling.json" and not (set(raw) & CONFIG_KEYS):
            _, ceilings = _parse_known_debt(raw)
            return cls(known_debt_ceilings=ceilings, source_path=p)

        unknown = set(raw) - CONFIG_KEYS
        if unknown:
            raise ConfigError(f"{p}: unknown key(s): {', '.join(sorted(unknown))}")

        version = raw.get("version", 1)
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ConfigError(f"{p}: version must be a positive integer")

        packs_explicit = "packs" in raw and raw.get("packs") is not None
        if packs_explicit:
            packs = _parse_str_list(raw.get("packs"), "packs")
            unknown_packs = set(packs) - VALID_PACKS
            if unknown_packs:
                raise ConfigError(
                    f"{p}: unknown pack(s): {', '.join(sorted(unknown_packs))} "
                    f"(valid: {', '.join(sorted(VALID_PACKS))})"
                )
        else:
            packs = list(DEFAULT_PACKS)

        languages = [lang.lower() for lang in _parse_str_list(raw.get("languages"), "languages")]
        unknown_langs = set(languages) - SUPPORTED_LANGUAGES
        if unknown_langs:
            raise ConfigError(
                f"{p}: unsupported language(s): {', '.join(sorted(unknown_langs))} "
                f"(supported: {', '.join(sorted(SUPPORTED_LANGUAGES))})"
            )

        exclude = _parse_str_list(raw.get("exclude"), "exclude") + _parse_str_list(
            raw.get("allowed_paths"), "allowed_paths"
        )
        auth_guards = _parse_str_list(raw.get("auth_guards"), "auth_guards")
        tenant_keys = _parse_str_list(raw.get("tenant_keys"), "tenant_keys")
        score_owners = _parse_str_list(raw.get("score_owners"), "score_owners")
        model_call_patterns = _parse_str_list(raw.get("model_call_patterns"), "model_call_patterns")
        evidence_markers = _parse_str_list(raw.get("evidence_markers"), "evidence_markers")

        exempt = _parse_exempt(raw.get("exempt"))
        known_debt, known_debt_ceilings = _parse_known_debt(raw.get("known_debt"))

        for key in known_debt:
            for ex_path, ex_rule in exempt:
                if ex_path == key[0] and rules_match(ex_rule, key[1]):
                    raise ConfigError(f"{key} is both exempt and known debt; it is one or the other")

        for pattern in model_call_patterns + evidence_markers:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ConfigError(f"invalid pattern {pattern!r}: {e}") from e

        return cls(
            version=version,
            packs=packs,
            packs_explicit=packs_explicit,
            languages=languages,
            exclude=exclude,
            auth_guards=auth_guards,
            tenant_keys=tenant_keys,
            score_owners=score_owners,
            exempt=exempt,
            known_debt=known_debt,
            known_debt_ceilings=known_debt_ceilings,
            model_call_patterns=model_call_patterns,
            evidence_markers=evidence_markers,
            source_path=p,
        )

    @staticmethod
    def _read_raw_file(p: Path) -> Any:
        try:
            content = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise ConfigError(f"{p}: cannot be read as UTF-8 text: {e}") from e
        if p.suffix.lower() in {".yaml", ".yml"}:
            if yaml is None:
                raise ConfigError(f"{p}: PyYAML is required to load YAML configuration files")
            try:
                loaded = yaml.safe_load(content)
                return {} if loaded is None else loaded
            except Exception as e:
                raise ConfigError(f"{p}: invalid YAML: {e}") from e
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigError(f"{p}: invalid JSON: {e}") from e
