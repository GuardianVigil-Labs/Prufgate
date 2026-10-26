import * as assert from "node:assert/strict";
import * as path from "node:path";
import { test } from "node:test";
import { levelFor, mapFindings } from "../mapping";

const ROOT = path.resolve("/tmp/ws-example");

function finding(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    engine: "anti_fabrication",
    rule: "canned-error-fallback",
    severity: "P1",
    file: "src/api.ts",
    line: 12,
    message: "A catch returns a hard-coded success value.",
    confidence: "medium",
    ...over,
  };
}

test("severity levels: P0/P1 error, P2 warning, P3 and unknown information", () => {
  assert.equal(levelFor("P0"), "error");
  assert.equal(levelFor("P1"), "error");
  assert.equal(levelFor("P2"), "warning");
  assert.equal(levelFor("P3"), "information");
  assert.equal(levelFor("P9"), "information");
});

test("a finding maps to an absolute file, a 0-based line, the rule and confidence", () => {
  const [d] = mapFindings(JSON.stringify([finding()]), ROOT);
  assert.equal(d.file, path.join(ROOT, "src", "api.ts"));
  assert.equal(d.line, 11);
  assert.equal(d.level, "error");
  assert.equal(d.rule, "canned-error-fallback");
  assert.match(d.message, /\(canned-error-fallback, confidence medium\)$/);
  assert.match(d.message, /^\[P1\] A catch returns/);
});

test("an empty list means no diagnostics", () => {
  assert.deepEqual(mapFindings("[]", ROOT), []);
});

test("output that is not a JSON list is an error, never an empty pass", () => {
  assert.throws(() => mapFindings("", ROOT));
  assert.throws(() => mapFindings("prufgate check passed", ROOT));
  assert.throws(() => mapFindings('{"findings": []}', ROOT));
});

test("malformed findings are skipped, the rest kept", () => {
  const out = mapFindings(
    JSON.stringify([null, 3, finding({ rule: 7 }), finding({ file: "" }), finding({ severity: undefined }), finding({ severity: "P2" })]),
    ROOT,
  );
  assert.equal(out.length, 1);
  assert.equal(out[0].level, "warning");
});

test("files outside the workspace folder are dropped", () => {
  const out = mapFindings(JSON.stringify([finding({ file: "../elsewhere.ts" }), finding({ file: "/etc/passwd" })]), ROOT);
  assert.deepEqual(out, []);
});

test("a missing or bad line goes to the first line; missing confidence says unknown", () => {
  const [a, b] = mapFindings(JSON.stringify([finding({ line: 0 }), finding({ line: "x", confidence: undefined })]), ROOT);
  assert.equal(a.line, 0);
  assert.equal(b.line, 0);
  assert.match(b.message, /confidence unknown\)$/);
});
