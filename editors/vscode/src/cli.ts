// Finding and starting the prufgate CLI. No `vscode` import, so it is unit-tested with node:test.
import * as fs from "fs";
import * as path from "path";

// Only what the CLI and git need to start. API keys and tokens in the editor's environment stay out.
const ENV_KEYS = ["PATH", "Path", "PATHEXT", "HOME", "USERPROFILE", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"];

/** Resolves the configured program to an absolute path. A bare name is looked up in the absolute
 * PATH entries only, never the workspace folder (Windows would otherwise search the cwd first). */
export function resolveProgram(setting: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const name = setting.trim() || "prufgate";
  if (path.isAbsolute(name)) return isFile(name) ? name : undefined;
  if (name.includes("/") || name.includes("\\")) return undefined; // relative paths are refused
  const exts = process.platform === "win32" ? (env.PATHEXT || ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of (env.PATH ?? env.Path ?? "").split(path.delimiter)) {
    if (!qualifiedDir(dir)) continue;
    for (const ext of exts) {
      const candidate = path.join(dir, name + ext);
      if (isFile(candidate)) return candidate;
    }
  }
  return undefined;
}

/** A directory that names its root: on Windows a drive letter or a UNC share, since `\\bin` and
 * `C:bin` resolve against the current drive or folder (the workspace). */
export function qualifiedDir(dir: string, windows: boolean = process.platform === "win32"): boolean {
  return windows ? /^([A-Za-z]:[\\/]|\\\\[^\\])/.test(dir) : path.posix.isAbsolute(dir);
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR" || code === "EACCES" || code === "EPERM") {
      return false; // missing or unreadable: treated as not found
    }
    throw err;
  }
}

export function childEnv(source: NodeJS.ProcessEnv = process.env, windows: boolean = process.platform === "win32"): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { PRUFGATE_NO_AI_ADJUDICATE: "1", PYTHONIOENCODING: "utf-8" };
  for (const k of ENV_KEYS) if (source[k] !== undefined) env[k] = source[k];
  // The CLI runs in the workspace folder: a relative or empty PATH entry would let it start a planted git.
  const sep = windows ? ";" : ":";
  for (const k of ["PATH", "Path"]) {
    const v = env[k];
    if (v !== undefined) env[k] = v.split(sep).filter((d) => qualifiedDir(d, windows)).join(sep);
  }
  if (windows) env.NoDefaultCurrentDirectoryInExePath = "1"; // no cwd search by CreateProcess
  return env;
}
