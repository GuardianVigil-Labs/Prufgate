"""How far each PrufGate rule can be trusted: the one place rule confidence lives.

- `high`: an exact structural match; a hit is almost always what the rule names.
- `medium`: a heuristic with known false positives.
- `low`: a fuzzy or naming-based heuristic. Off by default; `enable_low_confidence: true`
  in `.prufgate/config.yaml` turns these rules on.

Rules from other tools (gitleaks, zizmor, your own ast-grep rules, AI review comments)
are not listed and count as `medium`: never hidden, never claimed exact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable, Optional, TypeVar

from prufgate.config import PrufGateConfig, expand_rule_aliases
from prufgate.inline_ignore import review_rule_id  # re-exported: one definition, in inline_ignore

T = TypeVar("T")

HIGH, MEDIUM, LOW = "high", "medium", "low"
DEFAULT_CONFIDENCE = MEDIUM

CONFIDENCE: dict[str, str] = {
    # Engine 1: anti-fabrication
    "canned-error-fallback": MEDIUM,
    "route-canned-fallback": MEDIUM,
    "unhandled-empty-catch": MEDIUM,
    "verdict-on-error-path": MEDIUM,
    "score-on-error-path": MEDIUM,
    "score-outside-scoring": MEDIUM,
    "simulated-return-value": MEDIUM,
    "fake-named-data": LOW,
    "synthetic-delay-mock": MEDIUM,
    "stub-click-handler": HIGH,
    "disconnected-form-submit": HIGH,
    "always-current-fake-timestamp": MEDIUM,
    "asserted-state": LOW,
    "unimplemented-production-stub": HIGH,
    "prompt-invents-finding": MEDIUM,
    "documentation-ip-or-domain": HIGH,
    "stale-exemption": HIGH,
    "debt-ceiling-breached": HIGH,
    # Engine 1, pack cti
    "hardcoded-cve": MEDIUM,
    "hardcoded-attribution": MEDIUM,
    "keyword-selected-attribution": LOW,
    "ui-verdict-literal": MEDIUM,
    "substring-decides-verdict": MEDIUM,
    "zero-jarm-as-fingerprint": HIGH,
    "empty-input-digest-as-sample": HIGH,
    "llm-generated-intel": MEDIUM,
    # Engine 2: test integrity
    "zero-assertion-test": MEDIUM,
    "tautological-assertion": HIGH,
    "self-mocked-unit-under-test": MEDIUM,
    "caught-and-ignored-test-exception": MEDIUM,
    "snapshot-blind-update-or-empty": HIGH,
    "diff-assertion-weakening": MEDIUM,
    "test-input-special-casing": MEDIUM,
    "diff-test-file-deleted": HIGH,
    "diff-test-count-drop": MEDIUM,
    # Engine 3: diff guard
    "test-skip-smuggling": HIGH,
    "test-fake-exit": HIGH,
    "suppression-comment-smuggling": HIGH,
    "unsafe-type-cast-cascade": HIGH,
    "linter-or-ci-config-weakening": MEDIUM,
    "coverage-threshold-lowering": HIGH,
    "prufgate-config-self-exemption": HIGH,
    "prufgate-config-not-applied": HIGH,
    "prufgate-config-base-invalid": HIGH,
    # Engine 4: contract guard
    "undeclared-or-hallucinated-import": MEDIUM,
    "undocumented-env-var-drift": HIGH,
    "frontend-backend-route-mismatch": MEDIUM,
    "dependency-not-on-registry": HIGH,
    "dependency-recently-published": MEDIUM,
    "dependency-typosquat": MEDIUM,
    # Engine 5: BOLA
    "static-bola-unscoped-access": MEDIUM,
    "BOLA-UNGUARDED-SERVER-ACTION": MEDIUM,
    "BOLA-TABLE-MISSING-TENANT-COLUMN": LOW,
    "BOLA-UNAUTHENTICATED-ACCESS": HIGH,
    "BOLA-CROSS-TENANT-ACCESS": HIGH,
    "BOLA-PROBE-REDIRECT-REFUSED": HIGH,
    # Engine 6: diff reviewer (IDs from `inline_ignore.review_rule_id`)
    "pr-sql-injection-vector": MEDIUM,
    "pr-hardcoded-credential-in-code": MEDIUM,
    "pr-shell-command-injection-risk": MEDIUM,
    "pr-disabled-tls-certificate-verification": HIGH,
    "pr-unsanitized-html-injection-xss": MEDIUM,
    "pr-ignored-error-return-in-go": LOW,
    "pr-unbounded-goroutine-spawn": LOW,
    "pr-credential-logging-in-console": LOW,
    "pr-server-action-missing-authorization-guard": MEDIUM,
    # Gate plumbing and the built-in ast-grep rule
    "ignore-without-reason": HIGH,
    "action-authorization-guard": MEDIUM,
}

# How the synthesizer and the reviewer prefix another engine's rule ID.
_PREFIXES = ("anti-fabrication-", "pr-")
# SARIF `reportingConfiguration.rank` (0-100) for each level.
SARIF_RANK = {HIGH: 90.0, MEDIUM: 60.0, LOW: 30.0}


def confidence(rule_id: str) -> str:
    """The confidence of `rule_id`, through aliases and engine prefixes."""
    rule = str(rule_id).strip()
    if rule.startswith("gate-failed-"):
        return HIGH
    candidates = [rule] + [rule[len(p):] for p in _PREFIXES if rule.startswith(p)]
    for cand in candidates:
        if cand in CONFIDENCE:
            return CONFIDENCE[cand]
        for alias in sorted(expand_rule_aliases(cand)):
            if alias in CONFIDENCE:
                return CONFIDENCE[alias]
    return DEFAULT_CONFIDENCE


def reported(rule_id: str, enable_low_confidence: bool) -> bool:
    """False for a low-confidence rule while low-confidence rules are off."""
    return enable_low_confidence or confidence(rule_id) != LOW


def rule_of(item: Any) -> str:
    """The rule ID of a finding from any engine, as a dict (JSON output) or an object."""
    get = item.get if isinstance(item, dict) else (lambda k: getattr(item, k, None))
    rule = get("rule_id") or get("rule") or get("ruleId")
    if rule:
        return str(rule)
    title = get("title")
    return review_rule_id(str(title)) if title else ""


def visible(items: Iterable[T], enable_low_confidence: bool, rule: Callable[[T], str] = rule_of) -> list[T]:
    """The findings to report and count toward the exit code: low-confidence rules
    are dropped unless `enable_low_confidence` is on. Every surface filters here."""
    return [f for f in items if reported(rule(f), enable_low_confidence)]


def low_confidence_enabled(workspace: Path | str, config_path: Optional[str] = None, ref: Optional[str] = None) -> bool:
    """`enable_low_confidence` from the workspace config (at `ref` when given, like
    every other setting). Raises ConfigError when it does not load."""
    return PrufGateConfig.load(workspace, config_path, ref=ref).enable_low_confidence
