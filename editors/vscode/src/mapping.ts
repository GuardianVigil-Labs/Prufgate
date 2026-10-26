// Turns `prufgate check --format json` output into plain diagnostic records.
// No `vscode` import here, so the mapping is unit-tested with node:test.
import * as path from "path";

export const RULES_URL = "https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ENGINES.md";

export type Level = "error" | "warning" | "information";

export interface Mapped {
  file: string; // absolute path inside the workspace folder
  line: number; // 0-based
  level: Level;
  message: string;
  rule: string;
}

export function levelFor(severity: string): Level {
  if (severity === "P0" || severity === "P1") return "error";
  if (severity === "P2") return "warning";
  return "information";
}

/** Parses the CLI's JSON. Throws on anything that is not a JSON array; skips malformed
 * findings and any whose file falls outside the workspace folder. */
export function mapFindings(stdout: string, folder: string): Mapped[] {
  const data: unknown = JSON.parse(stdout);
  if (!Array.isArray(data)) throw new Error("prufgate did not return a JSON list of findings");
  const root = path.resolve(folder);
  const out: Mapped[] = [];
  for (const f of data) {
    if (!f || typeof f !== "object") continue;
    const { rule, severity, file, line, message, confidence } = f as Record<string, unknown>;
    if (typeof rule !== "string" || typeof severity !== "string" || typeof file !== "string" || !file) continue;
    const abs = path.resolve(root, file);
    const rel = path.relative(root, abs);
    if (!rel || rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel)) continue;
    const n = typeof line === "number" && Number.isFinite(line) ? Math.max(0, Math.floor(line) - 1) : 0;
    const conf = typeof confidence === "string" && confidence ? confidence : "unknown";
    const text = typeof message === "string" && message ? message : rule;
    out.push({
      file: abs,
      line: n,
      level: levelFor(severity),
      message: `[${severity}] ${text} (${rule}, confidence ${conf})`,
      rule,
    });
  }
  return out;
}
