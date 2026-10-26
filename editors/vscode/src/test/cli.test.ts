import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { childEnv, qualifiedDir, resolveProgram } from "../cli";

test("a bare name resolves from absolute PATH entries only", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pg-bin-"));
  const exe = path.join(dir, path.sep === "\\" ? "prufgate.EXE" : "prufgate");
  fs.writeFileSync(exe, "");
  assert.equal(resolveProgram("prufgate", { PATH: dir, PATHEXT: ".EXE" }), exe);
  // A relative PATH entry (such as ".") is never searched, so a workspace cannot plant the binary.
  const rel = path.relative(process.cwd(), dir) || ".";
  assert.equal(resolveProgram("prufgate", { PATH: rel, PATHEXT: ".EXE" }), undefined);
  assert.equal(resolveProgram("prufgate", { PATH: "" }), undefined);
});

test("relative paths are refused and absolute paths must exist", () => {
  assert.equal(resolveProgram("./prufgate", { PATH: "" }), undefined);
  assert.equal(resolveProgram("bin/prufgate", { PATH: "" }), undefined);
  assert.equal(resolveProgram(path.join(os.tmpdir(), "no-such-prufgate-binary"), { PATH: "" }), undefined);
});

test("the child environment drops everything outside the allow list", () => {
  const env = childEnv({ PATH: "/usr/bin", HOME: "/home/prufgate", OPENAI_API_KEY: "x", GITHUB_TOKEN: "y" });
  assert.deepEqual(env, { PATH: "/usr/bin", HOME: "/home/prufgate", PRUFGATE_NO_AI_ADJUDICATE: "1", PYTHONIOENCODING: "utf-8" });
});

test("relative and empty PATH entries never reach the child", () => {
  assert.equal(childEnv({ PATH: "/usr/bin::.:bin:/opt/x/" }, false).PATH, "/usr/bin:/opt/x/");
  const win = childEnv({ Path: "C:\\Git\\cmd;;.;\\bin;C:bin;\\\\srv\\tools;d:/x" }, true);
  assert.equal(win.Path, "C:\\Git\\cmd;\\\\srv\\tools;d:/x");
  assert.equal(win.NoDefaultCurrentDirectoryInExePath, "1");
  assert.equal(qualifiedDir("\\bin", true), false); // drive-relative
  assert.equal(qualifiedDir("/usr/bin", false), true);
});

test("a workspace cannot change what a check scans or switch off save checks", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "package.json"), "utf8"));
  for (const key of ["prufgate.path", "prufgate.scope", "prufgate.runOnSave"]) {
    assert.equal(pkg.contributes.configuration.properties[key].scope, "machine", key);
  }
});
