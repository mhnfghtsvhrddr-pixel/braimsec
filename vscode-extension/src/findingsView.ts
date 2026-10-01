/**
 * Tree view showing the latest BraimSec scan findings, grouped by severity.
 * Clicking a finding opens the file at the reported line.
 */

import * as path from 'path';
import * as vscode from 'vscode';
import { Finding } from './api';

const SEVERITY_ORDER = ['error', 'warning', 'note'] as const;
const SEVERITY_LABEL: Record<string, string> = {
  error: 'Critical',
  warning: 'Warning',
  note: 'Note',
};

export class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    private readonly workspaceRoot: string
  ) {
    const line = finding.line && finding.line > 0 ? `:${finding.line}` : '';
    super(`${finding.file}${line} — ${finding.message}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${finding.tool} · ${finding.rule_id}`;
    this.tooltip = `${finding.message}\n${finding.tool} / ${finding.rule_id} @ ${finding.file}${line}`;
    this.command = {
      command: 'braimsec.openFinding',
      title: 'Open Finding',
      arguments: [this],
    };
    const icon =
      finding.severity === 'error'
        ? new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'))
        : finding.severity === 'warning'
          ? new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'))
          : new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
    this.iconPath = icon;
  }

  /** Absolute file URI the finding points at (best effort). */
  get fileUri(): vscode.Uri {
    const p = this.finding.file;
    const abs = path.isAbsolute(p) ? p : path.join(this.workspaceRoot, p);
    return vscode.Uri.file(abs);
  }

  get lineNumber(): number {
    return Math.max(1, this.finding.line ?? 1);
  }
}

class SeverityGroup extends vscode.TreeItem {
  constructor(
    public readonly severity: string,
    public readonly children: FindingItem[]
  ) {
    super(
      `${SEVERITY_LABEL[severity] ?? severity} (${children.length})`,
      vscode.TreeItemCollapsibleState.Expanded
    );
    this.contextValue = 'severityGroup';
    this.iconPath = new vscode.ThemeIcon(
      severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'info'
    );
  }
}

export class FindingsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly emitter = new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData = this.emitter.event;

  private groups: SeverityGroup[] = [];
  private emptyMessage = 'No scan yet — run "BraimSec: Scan Workspace".';

  setFindings(findings: Finding[], workspaceRoot: string): void {
    const bySev = new Map<string, FindingItem[]>();
    for (const f of findings) {
      const item = new FindingItem(f, workspaceRoot);
      const list = bySev.get(f.severity) ?? [];
      list.push(item);
      bySev.set(f.severity, list);
    }
    this.groups = SEVERITY_ORDER.filter((s) => bySev.has(s)).map(
      (s) => new SeverityGroup(s, bySev.get(s)!)
    );
    // Any non-standard severities go last, unsorted.
    for (const [s, items] of bySev) {
      if (!(SEVERITY_ORDER as readonly string[]).includes(s)) {
        this.groups.push(new SeverityGroup(s, items));
      }
    }
    this.emptyMessage =
      findings.length === 0 ? 'Scan finished — no findings. Nice work!' : this.emptyMessage;
    this.emitter.fire();
  }

  clear(): void {
    this.groups = [];
    this.emptyMessage = 'No scan yet — run "BraimSec: Scan Workspace".';
    this.emitter.fire();
  }

  getTreeItem(el: vscode.TreeItem): vscode.TreeItem {
    return el;
  }

  getChildren(el?: vscode.TreeItem): vscode.TreeItem[] {
    if (!el) {
      if (this.groups.length === 0) {
        const item = new vscode.TreeItem(this.emptyMessage, vscode.TreeItemCollapsibleState.None);
        item.iconPath = new vscode.ThemeIcon('shield');
        return [item];
      }
      return this.groups;
    }
    if (el instanceof SeverityGroup) {
      return el.children;
    }
    return [];
  }
}
