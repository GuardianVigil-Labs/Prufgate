import { execFile } from "child_process";
import * as vscode from "vscode";
import { childEnv, resolveProgram } from "./cli";
import { Level, mapFindings, RULES_URL } from "./mapping";

const TIMEOUT_MS = 120_000;
const DEBOUNCE_MS = 1_500;
const MAX_OUTPUT = 32 * 1024 * 1024;

const LEVELS: Record<Level, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
};

let diagnostics: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;
let missingCli = false;
const owned = new Map<string, vscode.Uri[]>(); // folder -> files it set diagnostics on
const counts = new Map<string, [number, number, number]>();
const running = new Set<string>();
const again = new Set<string>();
const timers = new Map<string, NodeJS.Timeout>();

function render(): void {
  let e = 0, w = 0, i = 0;
  for (const [a, b, c] of counts.values()) { e += a; w += b; i += c; }
  status.text = running.size ? "$(sync~spin) PrufGate" : `$(shield) PrufGate $(error) ${e} $(warning) ${w} $(info) ${i}`;
  status.show();
}

function fail(folder: vscode.WorkspaceFolder, why: string): void {
  status.tooltip = `PrufGate could not check ${folder.name}: ${why}`;
  void vscode.window.showWarningMessage(`PrufGate could not check ${folder.name}: ${why}`);
}

function check(folder: vscode.WorkspaceFolder): void {
  if (!vscode.workspace.isTrusted || missingCli || folder.uri.scheme !== "file") return;
  const key = folder.uri.toString();
  if (running.has(key)) { again.add(key); return; }
  const cfg = vscode.workspace.getConfiguration("prufgate", folder.uri);
  const program = resolveProgram(cfg.get<string>("path", "prufgate"));
  if (!program) {
    missingCli = true;
    status.text = "$(shield) PrufGate: not installed";
    status.tooltip = "Install the CLI: pipx install prufgate";
    status.show();
    void vscode.window.showErrorMessage(
      "PrufGate: the prufgate command was not found. Install it with `pipx install prufgate`, or set prufgate.path in your user settings.",
    );
    return;
  }
  const args = ["check", ...(cfg.get<string>("scope", "changed") === "workspace" ? [] : ["--changed"]), "--format", "json"];
  running.add(key);
  render();
  execFile(program, args, { cwd: folder.uri.fsPath, timeout: TIMEOUT_MS, maxBuffer: MAX_OUTPUT, env: childEnv(), windowsHide: true },
    (err, stdout, stderr) => {
      running.delete(key);
      // Exit 1 means blocking findings and still prints JSON; anything else is an error.
      const code = err ? (err as { code?: unknown }).code : 0;
      if (err && code !== 1) {
        fail(folder, err.killed ? "timed out" : (stderr.trim().split("\n").pop() || err.message));
      } else {
        try {
          apply(key, mapFindings(stdout, folder.uri.fsPath));
          status.tooltip = "PrufGate findings. Click to check again.";
        } catch (e) {
          fail(folder, e instanceof Error ? e.message : String(e));
        }
      }
      render();
      if (again.delete(key)) check(folder);
    });
}

function apply(key: string, found: ReturnType<typeof mapFindings>): void {
  for (const uri of owned.get(key) ?? []) diagnostics.delete(uri);
  const byFile = new Map<string, vscode.Diagnostic[]>();
  const c: [number, number, number] = [0, 0, 0];
  for (const f of found) {
    const d = new vscode.Diagnostic(new vscode.Range(f.line, 0, f.line, Number.MAX_SAFE_INTEGER), f.message, LEVELS[f.level]);
    d.source = "PrufGate";
    d.code = { value: f.rule, target: vscode.Uri.parse(RULES_URL) };
    c[f.level === "error" ? 0 : f.level === "warning" ? 1 : 2]++;
    byFile.set(f.file, [...(byFile.get(f.file) ?? []), d]);
  }
  const uris: vscode.Uri[] = [];
  for (const [file, ds] of byFile) {
    const uri = vscode.Uri.file(file);
    diagnostics.set(uri, ds);
    uris.push(uri);
  }
  owned.set(key, uris);
  counts.set(key, c);
}

function checkAll(): void {
  missingCli = false; // an explicit command retries after the user installs the CLI
  for (const f of vscode.workspace.workspaceFolders ?? []) check(f);
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("prufgate");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  status.command = "prufgate.checkWorkspace";
  status.name = "PrufGate";
  context.subscriptions.push(
    diagnostics,
    status,
    vscode.commands.registerCommand("prufgate.checkWorkspace", checkAll),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (!folder || !vscode.workspace.getConfiguration("prufgate", folder.uri).get<boolean>("runOnSave", true)) return;
      const key = folder.uri.toString();
      clearTimeout(timers.get(key));
      timers.set(key, setTimeout(() => { timers.delete(key); check(folder); }, DEBOUNCE_MS));
    }),
    vscode.workspace.onDidChangeConfiguration((e) => { if (e.affectsConfiguration("prufgate")) checkAll(); }),
    { dispose: () => { for (const t of timers.values()) clearTimeout(t); } },
  );
  render();
  if (vscode.workspace.isTrusted) for (const f of vscode.workspace.workspaceFolders ?? []) check(f);
}

export function deactivate(): void {}
