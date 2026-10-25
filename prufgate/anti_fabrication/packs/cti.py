"""Optional Cyber Threat Intelligence (CTI) anti-fabrication rule pack.

Off by default so general software projects are never flagged by domain-specific
threat intelligence heuristics. Enable via `"packs": ["cti"]` in configuration or
`--pack=cti` on the CLI.
"""

from __future__ import annotations

import re

# Threat-intel vocabulary that should never appear as a literal in application
# code. Real findings arrive from a provider at runtime.
ATTRIBUTION_LITERALS = re.compile(
    r"""["'](?:
        (?:APT\s?\d+)                 # APT28, APT 29
      | Lazarus(?:\s+Group)?
      | Fancy\s+Bear | Cozy\s+Bear | Sandworm | Volt\s+Typhoon | Wicked\s+Panda
      | Cobalt\s+Strike | LockBit | AgentTesla | Formbook | Emotet | TrickBot
      | SolarWinds | Dtrack
    )["']""",
    re.VERBOSE | re.IGNORECASE,
)

GENERATED_INTEL = re.compile(
    r"(?:generate|invent|fabricate|make\s+up|come\s+up\s+with|simulate)"
    r"[^\n]{0,80}?"
    r"(?:indicators?\s+of\s+compromise|\bIOCs?\b|threat\s+(?:actor|feed|intel)"
    r"|malware\s+famil|attribution|\bAPT\b|\bC2\b)",
    re.IGNORECASE,
)

SUBSTRING_VERDICT = re.compile(
    r"""\b(?:const|let|var|)\s*
        (?:is|has|looks|seems)\w*
        (?:Exposed|Breached|Malicious|Suspicious|Compromised|Bad|Phish\w*|Threat\w*|Infected|Risky)
        \s*(?::[^=]{0,40})?=\s*
        [^;\n]*?
        (?:\.includes\(|\.indexOf\(|strings\.Contains\(|\.startsWith\(|\.endsWith\()""",
    re.VERBOSE | re.IGNORECASE,
)

SUBSTRING_TEST = re.compile(r"\.includes\(|\.indexOf\(|strings\.Contains\(")
VERDICT_VARIABLE = re.compile(
    r"""\b(?:const|let|var)\s+
        (?:is|has)\w*
        (?:Exposed|Breached|Malicious|Suspicious|Compromised|Phish\w*|Infected|Risky)
        \b""",
    re.VERBOSE | re.IGNORECASE,
)

EMPTY_DIGESTS = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256("")
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5("")
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1("")
}

ZERO_JARM = re.compile(r"(?<![0-9a-fA-F])0{62}(?![0-9a-fA-F])")

UI_VERDICT_LITERAL = re.compile(
    r"""\b(?:threatActor|malwareFamily)\s*:\s*["'][^"']
      | \breputation\s*:\s*["']Malicious["']
      | \bverdict\s*:\s*["'](?:Malicious|Suspicious|Clean)["']""",
    re.VERBOSE,
)
UI_PATHS = ("src/components/", "src/data/", "components/", "ui/", "pages/")

KEYWORD_TEST = re.compile(
    r"""\.includes\(\s*["'][^"']+["']\s*\)|strings\.Contains\(\s*[\w.]+\s*,\s*"[^"]+"\s*\)"""
    r"""|(?<!\w)b?["'][^"']+["']\s+in\s+[\w.]+"""
)
JUDGEMENT_PICK = re.compile(
    r"\b(?:actor|threatActor|c2Family|malwareFamily|toolFamily|linkedActor)\s*(?::?=|:)\s*[^=]"
    r"|THREAT_ACTORS\s*\["
    r"|\b(?:actor|threat_actor|c2_family|malware_family|tool_family)\s*=\s*[^=]"
    r"|\b\w*(?:c2|famil|actor)\w*\.append\("
)

KEYWORD_SOME = re.compile(r"\.some\(\s*\(?\s*\w+\s*\)?\s*=>\s*[\w.]+\.includes\(\s*\w+\s*\)")
TECHNIQUE_PICK = re.compile(r"""\bid\s*:\s*["']T\d{4}(?:\.\d{3})?["']""")
TECHNIQUE_WINDOW = 15

# Vocabulary the core rules gain when the pack is on.
# A hardcoded CVE presented as a scan result.
CVE_LITERAL = re.compile(r"""["']CVE-\d{4}-\d{4,7}["']""")
# A verdict assigned a literal on an error path.
VERDICT_LITERAL = re.compile(
    r"""\b(?:reputation|verdict|status|threatLevel)\s*[:=]\s*["'](?:Malicious|Suspicious|Clean)["']""",
    re.IGNORECASE,
)
# Threat scores set to a constant on an error path.
SCORE_LITERAL = re.compile(r"""\b(?:threatScore|abuseConfidenceScore)\s*[:=]\s*(\d{2,3})\b""")
# Security states asserted as literals.
ASSERTED_STATE_LITERAL = re.compile(
    r"""\b(?:status|state|health|connection|severity|risk)\s*:\s*
        ["'](?:Compromised|Vulnerable|Exposed|Breached|Infected|Blocked|Quarantined|Clustered|Monitor)["']""",
    re.VERBOSE | re.IGNORECASE,
)
# Judgement fields and evidence markers added to the prompt rule.
JUDGEMENT_FIELDS = r"threat_?score|attribution|threat_?actor|malware_?family|tool_?family"
EVIDENCE_MARKERS = r"sightings|providerResults|capabilities|yaraMatches"


def scan_cti_data_json(rel: str, lines: list[str], finding_cls: type) -> list:
    """Scan shipped data/*.json files for empty digests or all-zero JARM fingerprints."""
    out = []
    for i, line in enumerate(lines):
        if any(d in line for d in EMPTY_DIGESTS):
            out.append(finding_cls(rel, i + 1, "empty-input-digest-as-sample", line))
        if ZERO_JARM.search(line):
            out.append(finding_cls(rel, i + 1, "zero-jarm-as-fingerprint", line))
    return out


def scan_cti_v2_lines(rel: str, lines: list[str], finding_cls: type) -> list:
    """Scan source lines for v2 CTI fabrication patterns (seed files included)."""
    out = []
    ui = rel.startswith(UI_PATHS) or "/src/components/" in rel or "/src/data/" in rel
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue
        is_union = "|" in line and re.search(r"""["'];?\s*$|["']\s*\|""", line)
        if ui and UI_VERDICT_LITERAL.search(line) and not is_union:
            out.append(finding_cls(rel, i + 1, "ui-verdict-literal", line))
        if any(d in line for d in EMPTY_DIGESTS):
            out.append(finding_cls(rel, i + 1, "empty-input-digest-as-sample", line))
        if ZERO_JARM.search(line):
            out.append(finding_cls(rel, i + 1, "zero-jarm-as-fingerprint", line))
        if KEYWORD_TEST.search(line) and any(
            JUDGEMENT_PICK.search(candidate)
            for candidate in lines[i : i + 4]
            if not candidate.strip().startswith(("//", "#", "*"))
        ):
            out.append(finding_cls(rel, i + 1, "keyword-selected-attribution", line))
        elif (KEYWORD_TEST.search(line) or KEYWORD_SOME.search(line)) and any(
            TECHNIQUE_PICK.search(candidate)
            for candidate in lines[i : i + TECHNIQUE_WINDOW]
            if not candidate.strip().startswith(("//", "#", "*"))
        ):
            out.append(finding_cls(rel, i + 1, "keyword-selected-attribution", line))
    return out


def scan_cti_legacy_line(rel: str, lines: list[str], i: int, line: str, finding_cls: type) -> list:
    """Scan non-seed source line for legacy CTI fabrication rules."""
    out = []
    if ATTRIBUTION_LITERALS.search(line):
        out.append(finding_cls(rel, i + 1, "hardcoded-attribution", line))
    if GENERATED_INTEL.search(line):
        out.append(finding_cls(rel, i + 1, "llm-generated-intel", line))
    if SUBSTRING_VERDICT.search(line):
        out.append(finding_cls(rel, i + 1, "substring-decides-verdict", line))
    elif VERDICT_VARIABLE.search(line):
        window = "\n".join(lines[i : i + 12])
        statement = window.split(";")[0]
        if len(SUBSTRING_TEST.findall(statement)) >= 2:
            out.append(finding_cls(rel, i + 1, "substring-decides-verdict", line))
    return out


# --- self-check fixtures (run by detector.self_check with the pack on) ------

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# (name, path, source, rule expected or None for "must pass")
SELF_CHECK_CASES: list[tuple[str, str, str, str | None]] = [
    ("a verdict and actor written into seed data", "src/data/indicators.ts",
     "  { value: '192.0.2.10', reputation: 'Malicious', threatActor: 'APT28 (Fancy Bear)' },",
     "ui-verdict-literal"),
    ("a verdict type union", "src/components/x.tsx",
     "  verdict: 'Clean' | 'Malicious' | 'Suspicious';", None),
    ("an actor read from a result", "src/components/x.tsx",
     "  threatActor: result.threatActor,", None),
    ("the empty-string SHA-256 as a sample", "src/data/samples.ts",
     f"  sha256: '{EMPTY_SHA256}',", "empty-input-digest-as-sample"),
    ("an empty-body hash in a shipped signature catalogue", "data/signatures.json",
     f'        "http_body_hash": "{EMPTY_SHA256}",', "empty-input-digest-as-sample"),
    ("an all-zero JARM as a signature", "data/c2.json",
     '  "jarm": "' + "0" * 62 + '",', "zero-jarm-as-fingerprint"),
    ("an all-zero JARM in code", "internal/fp/x.go",
     '\tsig := "' + "0" * 62 + '"', "zero-jarm-as-fingerprint"),
    ("a real JARM in data passes", "internal/fp/data/fp.json",
     '  "jarm": "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",', None),
    ("ATT&CK prose in data passes", "data/attack/enterprise-attack.json",
     '  "description": "APT29 is a threat group attributed to a state",', None),
    ("a hardcoded CVE as a scan result", "src/lib/scan.ts",
     "  findings.push({ id: 'CVE-2024-12345' });", "hardcoded-cve"),
    ("a verdict on the error path", "src/lib/enrich.ts",
     "  } catch (e) {\n    return { verdict: 'Malicious' };", "verdict-on-error-path"),
    ("a threat score on the error path", "src/lib/enrich.ts",
     "  } catch (e) {\n    return { threatScore: 88 };", "score-on-error-path"),
    ("a compromised state asserted as a literal", "src/lib/assets.ts",
     "    { host: 'db-1', status: 'Compromised' },", "asserted-state"),
    ("an actor chosen by a substring of the indicator", "src/lib/attribution.ts", '''
  const looksLikeGroupA = value.includes('cisco') || value.includes('vpn');
  const actor = looksLikeGroupA ? ACTORS['group-a'] : ACTORS['group-b'];
''', "keyword-selected-attribution"),
    ("a C2 family chosen by a substring", "src/lib/evidence.ts", '''
  } else if (clean.includes("brute") || clean.includes("badger")) {
    c2Family = "Brute Ratel C4";
''', "keyword-selected-attribution"),
    ("the same shape in Go", "internal/api/x.go", '''
\tif strings.Contains(ioc, "cobalt") {
\t\tactor = "APT41"
''', "keyword-selected-attribution"),
    ("a C2 label chosen by a byte substring in Python", "worker/x.py", '''
        if b"sliver" in carved_bytes.lower():
            c2_signatures.append("Sliver Implant Metadata")
''', "keyword-selected-attribution"),
    ("another byte-substring C2 label", "worker/x.py", '''
        if b"Demon" in carved_bytes:
            c2_signatures.append("Havoc C2 Demon Stager")
''', "keyword-selected-attribution"),
    ("a byte-substring label with two tests", "worker/x.py", '''
        if b"CobaltStrike" in carved_bytes or b"%s as %s\\\\%s: %d" in carved_bytes:
            c2_signatures.append("Cobalt Strike Beacon Config Block")
''', "keyword-selected-attribution"),
    ("the same shape assigning a family in Python", "worker/y.py", '''
    if "cobalt" in banner:
        malware_family = "Cobalt Strike"
''', "keyword-selected-attribution"),
    ("a Python substring test that picks no family", "worker/x.py", '''
            if "write" in action or "create" in action:
                files_created.append(path)
''', None),
    ("an ATT&CK technique chosen by a domain substring", "src/lib/mapping.ts", '''
    const suspiciousDomains = iocs.domains.filter((d) =>
      d.includes("-security") || d.includes(".ru") || d.includes(".xyz")
    );
    if (suspiciousDomains.length > 0) {
      techniques.push({
        id: "T1583.001",
''', "keyword-selected-attribution"),
    ("an ATT&CK technique chosen by a keyword list", "src/lib/mapping.ts", '''
    const suspiciousUrls = urls.filter((u) => {
      const lower = u.toLowerCase();
      return phishingKeywords.some((kw) => lower.includes(kw));
    });
    if (suspiciousUrls.length > 0) {
      techniques.push({
        id: "T1566.002",
''', "keyword-selected-attribution"),
    ("a technique chosen from an observed flag", "src/lib/mapping.ts", '''
    const dangerous = attachments.filter((a) => a.hasMacroRisk);
    if (dangerous.length > 0) {
      techniques.push({
        id: "T1566.001",
''', None),
    ("a substring test that picks no actor", "src/lib/x.ts", '''
  if (value.includes("://")) {
    kind = "url";
''', None),
]

# (name, source, should_flag) for the prompt rule with the pack's judgement fields.
PROMPT_SELF_CHECK_CASES: list[tuple[str, str, bool]] = [
    ("a prompt asking for a threat score and attribution with nothing supplied", '''
        import { GoogleGenAI } from "@google/genai";
        const r = await genAI.models.generateContent({
          contents: `Analyse "${indicator}". Return JSON:
            { "threatScore": number, "attribution": "string" }`,
        });
        ''', True),
    ("the same prompt with provider sightings supplied", '''
        import { GoogleGenAI } from "@google/genai";
        const r = await genAI.models.generateContent({
          contents: `Sightings: ${JSON.stringify(sightings)}. Return JSON:
            { "threatScore": number, "attribution": "string" }`,
        });
        ''', False),
]
