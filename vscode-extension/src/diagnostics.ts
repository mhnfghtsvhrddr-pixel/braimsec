/**
 * Squiggle diagnostics: turn BraimSec findings into VS Code problems so the
 * offending lines are underlined in the editor, grouped per file.
 */

import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from './api';

function toVsSeverity(sev: string): vscode.DiagnosticSeverity {
  switch (sev) {
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

export function findingsToDiagnostics(
  findings: Finding[],
  workspaceRoot: string
): Map<string, vscode.Diagnostic[]> {
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of findings) {
    const abs = path.isAbsolute(f.file) ? f.file : path.join(workspaceRoot, f.file);
    const line = Math.max(1, f.line ?? 1) - 1; // VS Code is 0-based
    const col = Math.max(0, (f.col ?? 1) - 1);
    const range = new vscode.Range(line, col, line, col + 1);
    const diag = new vscode.Diagnostic(
      range,
      `[BraimSec] ${f.message} (${f.tool}/${f.rule_id})`,
      toVsSeverity(f.severity)
    );
    diag.source = 'braimsec';
    const list = byFile.get(abs) ?? [];
    list.push(diag);
    byFile.set(abs, list);
  }
  return byFile;
}

export function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
  workspaceRoot: string
): void {
  collection.clear();
  for (const [file, diags] of findingsToDiagnostics(findings, workspaceRoot)) {
    collection.set(vscode.Uri.file(file), diags);
  }
}
