"""`prufgate export-rules --format semgrep`: PrufGate's single-line pattern rules as
Semgrep / Opengrep rules YAML, so a team can run them in the SAST tool it already has.

Only rules that are one regular expression over one line are exported, through
`pattern-regex` (PCRE2 in Semgrep, `re` here). Everything else needs a context
window, diff, configuration or cross-file analysis and is listed, with the reason,
in the header of the output. The output is sorted, so it can be committed and diffed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

import yaml

from prufgate import PROJECT_URL
from prufgate.anti_fabrication import detector as af
from prufgate.anti_fabrication.packs import cti
from prufgate.rules import CONFIDENCE, confidence

LICENSE = "Apache-2.0"
SOURCE_URL = f"{PROJECT_URL}/blob/main/docs/ENGINES.md#engine-1-anti-fabrication"
SEVERITY = {"P0": "ERROR", "P1": "ERROR", "P2": "WARNING", "P3": "INFO"}
ENGINE1_SEVERITY = "P0"  # every Engine 1 finding is P0 (synthesizer)

# The detector skips comment lines (`line.strip().startswith(...)`).
COMMENT_LINE = r"^[ \t]*(?://|#|\*|/\*).*$"
SOURCE_SUFFIXES = sorted(af.SUFFIXES)
WEB_UI_SUFFIXES = sorted(af.WEB_UI_SUFFIXES)
# The detector's default skips: tests, fixtures, build output and tooling.
DEFAULT_EXCLUDE = (
    sorted(af.SKIP_DIR_SEGMENTS)
    + [f"/{d}" for d in sorted(af.ROOT_ONLY_SKIP_SEGMENTS)]
    + sorted(f"*{s}" for s in af.TEST_FILE_SUFFIXES)
    + ["test_*.py"]
)
# The legacy line rules also skip seed data.
SEED_EXCLUDE = sorted(af.SEED_DIR_SEGMENTS)

EMPTY_DIGEST = re.compile("|".join(re.escape(d) for d in sorted(cti.EMPTY_DIGESTS)))

# Each exported rule: (detector rule ID, pack, regex, extra not-regexes, suffixes,
# skips seed dirs, message, positive fixture line, near-miss fixture line).
EXPORTED: list[tuple[str, str, re.Pattern, tuple[str, ...], list[str], bool, str, str, str]] = [
    ("documentation-address", "core", af.DOC_ADDRESS, (r"(?i)^.*placeholder.*$",), SOURCE_SUFFIXES, False,
     "An RFC 5737 / RFC 3849 documentation address or an example.com URL in production code: "
     "invented data presented as real.",
     "const API_BASE = 'https://api.example.com/v1';",
     "<input placeholder='https://api.example.com/v1' />"),
    ("always-current-fake", "core", af.ALWAYS_CURRENT, (), SOURCE_SUFFIXES, False,
     "A timestamp computed as 'now minus a fixed offset' at read time, so static data looks fresh.",
     "  lastSeen: Date.now() - 3600000,",
     "  lastSeen: row.lastSeen,"),
    ("invented-event-timestamp", "core", af.FRESH_EVENT_TIMESTAMP, (), SOURCE_SUFFIXES, True,
     "An operational event timestamp (last fired, last synced, last seen) set to the current time "
     "instead of when the event happened.",
     "  lastSyncedAt: new Date(),",
     "  lastSyncedAt: job.finishedAt,"),
    ("stub-click-handler", "web-ui", af.STUB_CLICK_HANDLER, (), WEB_UI_SUFFIXES, False,
     "A UI handler that does nothing: the control looks wired up but has no effect.",
     "<button onClick={() => {}}>Save</button>",
     "<button onClick={() => save(form)}>Save</button>"),
    # Opt-in pack `cti`: exported only with `--pack cti`.
    ("hardcoded-cve", "cti", cti.CVE_LITERAL, (), SOURCE_SUFFIXES, True,
     "A CVE identifier written as a literal in application code instead of coming from a scan result.",
     "  findings.push({ id: 'CVE-2021-44228' });",
     "  findings.push({ id: result.cveId });"),
    ("hardcoded-attribution", "cti", cti.ATTRIBUTION_LITERALS, (), SOURCE_SUFFIXES, True,
     "A threat actor or malware family written as a literal: attribution must come from a provider at runtime.",
     "  const actor = 'Lazarus Group';",
     "  const actor = intel.actorName;"),
    ("llm-generated-intel", "cti", cti.GENERATED_INTEL, (), SOURCE_SUFFIXES, True,
     "A prompt asking a model to generate threat intelligence (IOCs, actors, attribution) rather than analyse it.",
     "  const prompt = `Generate a list of indicators of compromise for ${domain}`;",
     "  const prompt = `Summarise these indicators of compromise: ${observed}`;"),
    ("substring-decides-verdict", "cti", cti.SUBSTRING_VERDICT, (), SOURCE_SUFFIXES, True,
     "A security verdict decided by a substring test on the input.",
     "  const isMalicious = url.includes('phish');",
     "  const isMalicious = verdict === 'malicious';"),
    ("zero-jarm-as-fingerprint", "cti", cti.ZERO_JARM, (), SOURCE_SUFFIXES, False,
     "The all-zero JARM (no TLS answer) used as a server fingerprint.",
     "  jarm: '" + "0" * 62 + "',",
     "  jarm: '" + "0" * 61 + "1',"),
    ("empty-input-digest-as-sample", "cti", EMPTY_DIGEST, (), SOURCE_SUFFIXES, False,
     "The digest of empty input used as a sample hash: it identifies no file.",
     "  sha256: '" + cti.EMPTY_SHA256 + "',",
     "  sha256: '" + cti.EMPTY_SHA256[:-1] + "0',"),
]

_E1_WINDOW = "needs a multi-line context window around the match"
_DIFF = "needs the diff against the base ref"
SKIPPED: dict[str, str] = {
    # Engine 1
    "canned-error-fallback": "matches the bracket that closes the error handler",
    "route-canned-fallback": "matches the bracket that closes the error handler, route files only",
    "unhandled-empty-catch": "matches the bracket that closes the catch block",
    "verdict-on-error-path": _E1_WINDOW + " (error path)",
    "score-on-error-path": _E1_WINDOW + " (error path)",
    "simulated-return-value": _E1_WINDOW + " (the comment above the return)",
    "synthetic-delay-mock": _E1_WINDOW + " (the canned result after the delay)",
    "disconnected-form-submit": _E1_WINDOW + " (no submit call after preventDefault)",
    "unimplemented-production-stub": _E1_WINDOW + " (no abstract or interface context above)",
    "keyword-selected-attribution": "low confidence, off by default; " + _E1_WINDOW,
    "asserted-state": "low confidence, off by default; " + _E1_WINDOW,
    "fake-named-data": "low confidence, off by default",
    "ui-verdict-literal": "needs the line-level type-union check and UI path prefixes",
    "score-outside-scoring": "needs the project's score_owners configuration",
    "prompt-invents-finding": "needs whole-file conditions (a model call and no evidence)",
    "stale-exemption": "checks the project's configuration, not source",
    "debt-ceiling-breached": "checks the project's configuration, not source",
    # Engine 2: test integrity
    **{r: "needs test-function structure or the diff (Engine 2)" for r in (
        "zero-assertion-test", "tautological-assertion", "self-mocked-unit-under-test",
        "caught-and-ignored-test-exception", "snapshot-blind-update-or-empty", "test-input-special-casing")},
    **{r: _DIFF + " (Engine 2)" for r in (
        "diff-assertion-weakening", "diff-test-file-deleted", "diff-test-count-drop")},
    # Engine 3: diff guard
    **{r: _DIFF + " (Engine 3)" for r in (
        "test-skip-smuggling", "test-fake-exit", "test-runner-monkeypatch", "always-true-equality",
        "pytest-result-rewrite", "pytest-collection-deselect", "test-config-weakening", "test-script-neutered",
        "suppression-comment-smuggling", "unsafe-type-cast-cascade", "linter-or-ci-config-weakening",
        "coverage-threshold-lowering", "prufgate-config-self-exemption", "prufgate-config-not-applied",
        "prufgate-config-base-invalid")},
    # Engine 4: contract guard
    **{r: "needs cross-file analysis or a package registry (Engine 4)" for r in (
        "undeclared-or-hallucinated-import", "undocumented-env-var-drift", "frontend-backend-route-mismatch",
        "dependency-not-on-registry", "dependency-recently-published", "dependency-typosquat",
        "ghost-symbol")},
    # Agent transcripts: shell commands, not source files
    **{r: "reads coding-agent transcripts, not source files" for r in (
        "transcript-history-lookup", "transcript-hook-bypass", "transcript-test-tamper-command")},
    # Engine 5: BOLA
    **{r: "needs cross-file route and schema analysis or a live probe (Engine 5)" for r in (
        "static-bola-unscoped-access", "BOLA-UNGUARDED-SERVER-ACTION", "BOLA-TABLE-MISSING-TENANT-COLUMN",
        "BOLA-UNAUTHENTICATED-ACCESS", "BOLA-CROSS-TENANT-ACCESS", "BOLA-PROBE-REDIRECT-REFUSED",
        "bfla-role-allowed", "bfla-allow-denied")},
    # Engine 6: diff reviewer
    **{r: _DIFF + " (Engine 6)" for r in CONFIDENCE if r.startswith("pr-")},
    "differential-base-tests-fail": "runs the repository's tests",
    "mutation-survivor": "runs the repository's tests under a mutation tool",
    "mutation-no-coverage": "runs the repository's tests under a mutation tool",
    "ignore-without-reason": "judges inline ignores together with the finding they name",
    "action-authorization-guard": "ast-grep: a negated nested-call search with a regex on the callee, "
    "which Semgrep's pattern-not cannot carry",
}


def semgrep_regex(pattern: re.Pattern) -> str:
    """The pattern with its flags inline, for PCRE2 (Semgrep) and `re` alike."""
    flags = "".join(c for f, c in ((re.IGNORECASE, "i"), (re.MULTILINE, "m"), (re.VERBOSE, "x")) if pattern.flags & f)
    unsupported = pattern.flags & ~(re.IGNORECASE | re.MULTILINE | re.VERBOSE | re.UNICODE)
    if unsupported:
        raise ValueError(f"regex flags {unsupported} have no inline form")
    return (f"(?{flags})" if flags else "") + pattern.pattern


def exported(packs: tuple[str, ...] = ()) -> list[tuple]:
    """The rules exported for the default packs plus `packs`."""
    wanted = {"core", "web-ui", *packs}
    return sorted((r for r in EXPORTED if r[1] in wanted), key=lambda r: r[0])


def _rule(entry: tuple) -> dict:
    rule_id, pack, pattern, nots, suffixes, seed, message, _, _ = entry
    exclude = DEFAULT_EXCLUDE + (SEED_EXCLUDE if seed else [])
    return {
        "id": f"prufgate.{rule_id}",
        "message": message,
        "severity": SEVERITY[ENGINE1_SEVERITY],
        "languages": ["regex"],
        "paths": {"include": [f"*{s}" for s in suffixes], "exclude": exclude},
        "patterns": [{"pattern-regex": semgrep_regex(pattern)}]
        + [{"pattern-not-regex": n} for n in (COMMENT_LINE, *nots)],
        "metadata": {
            "prufgate-rule-id": rule_id,
            "confidence": confidence(rule_id),
            "pack": pack,
            "source": SOURCE_URL,
            "license": LICENSE,
        },
    }


def skipped(packs: tuple[str, ...] = ()) -> dict[str, str]:
    """Rules not exported, with the reason."""
    out = dict(SKIPPED)
    out.update({r[0]: f"opt-in pack {r[1]}: add --pack {r[1]}" for r in EXPORTED if r[1] not in {"core", "web-ui", *packs}})
    return dict(sorted(out.items()))


def render(packs: tuple[str, ...] = ()) -> str:
    """The rules YAML, header included."""
    lines = [
        "# PrufGate rules for Semgrep / Opengrep, from `prufgate export-rules --format semgrep`.",
        "# Regenerate rather than edit. License: Apache-2.0. Docs: " + SOURCE_URL,
        "# Not exported (more than a single-line pattern):",
    ] + [f"#   {rule}: {reason}" for rule, reason in skipped(packs).items()]
    body = yaml.safe_dump({"rules": [_rule(e) for e in exported(packs)]}, sort_keys=False, width=10_000)
    return "\n".join(lines) + "\n" + body


def main(fmt: str, out: Optional[str], packs: tuple[str, ...] = ()) -> int:
    if fmt != "semgrep":
        print(f"prufgate export-rules: unknown format {fmt}", file=sys.stderr)
        return 2
    text = render(packs)
    if out:
        try:
            Path(out).write_text(text, encoding="utf-8")
        except OSError as e:
            print(f"prufgate export-rules: cannot write {out}: {e.strerror or e}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
    return 0
