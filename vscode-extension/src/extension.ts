/**
 * BraimSec Scanner — VS Code extension entry point.
 *
 * Talks only to the BraimSec server the user configured (braimsec.serverUrl).
 * The API key is kept in VS Code SecretStorage and never written to
 * settings.json or sent anywhere except the configured server.
 */

import * as path from 'path';
import * as vscode from 'vscode';
import { BraimSecClient, BraimSecError, Finding } from './api';
import { applyDiagnostics } from './diagnostics';
import { FindingItem, FindingsProvider } from './findingsView';
import { fitsServerCap, zipDirectory, zipSingleFile } from './zip';

const SECRET_KEY = 'braimsec.apiKey';

function getServerUrl(): string {
  return (vscode.workspace.getConfiguration('braimsec').get<string>('serverUrl') ?? '').trim();
}

function getProjectId(): string | undefined {
  const v = (vscode.workspace.getConfiguration('braimsec').get<string>('projectId') ?? '').trim();
  return v || undefined;
}

function getPollMs(): number {
  const v = vscode.workspace.getConfiguration('braimsec').get<number>('pollIntervalMs') ?? 3000;
  return Math.max(1000, v);
}

async function getApiKey(
  secrets: vscode.SecretStorage,
  promptIfMissing: boolean
): Promise<string | undefined> {
  let key = await secrets.get(SECRET_KEY);
  if (!key && promptIfMissing) {
    key = await vscode.window.showInputBox({
      title: 'BraimSec: Set API Key',
      prompt: 'Paste your BraimSec API key (stored securely, never in settings)',
      password: true,
      ignoreFocusOut: true,
    });
    if (key) {
      await secrets.store(SECRET_KEY, key.trim());
      key = key.trim();
    }
  }
  return key?.trim() || undefined;
}

async function ensureClient(
  context: vscode.ExtensionContext
): Promise<{ client: BraimSecClient; workspaceRoot: string } | undefined> {
  let serverUrl = getServerUrl();
  if (!serverUrl) {
    const input = await vscode.window.showInputBox({
      title: 'BraimSec: Set Server URL',
      prompt: 'Your BraimSec server URL, e.g. https://api.braimsec.world',
      ignoreFocusOut: true,
    });
    if (!input) {
      return undefined;
    }
    serverUrl = input.trim().replace(/\/+$/, '');
    await vscode.workspace.getConfiguration('braimsec').update('serverUrl', serverUrl, true);
  }

  const apiKey = await getApiKey(context.secrets, true);
  if (!apiKey) {
    return undefined;
  }

  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showErrorMessage('BraimSec: open a workspace folder first.');
    return undefined;
  }
  return { client: new BraimSecClient(serverUrl, apiKey), workspaceRoot: folder.uri.fsPath };
}

function summarize(findings: Finding[]): string {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }
  if (findings.length === 0) {
    return 'BraimSec scan finished: no findings.';
  }
  const parts = Object.entries(counts)
    .map(([sev, n]) => `${n} ${sev}`)
    .join(', ');
  return `BraimSec scan finished: ${findings.length} finding(s) (${parts}).`;
}

async function runScan(
  context: vscode.ExtensionContext,
  provider: FindingsProvider,
  diagnostics: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem,
  target: { kind: 'workspace' } | { kind: 'file'; filePath: string }
): Promise<void> {
  const ready = await ensureClient(context);
  if (!ready) {
    return;
  }
  const { client, workspaceRoot } = ready;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'BraimSec scan',
      cancellable: false,
    },
    async (progress) => {
      try {
        progress.report({ message: 'Zipping files…' });
        const zip =
          target.kind === 'workspace'
            ? await zipDirectory(workspaceRoot)
            : await zipSingleFile(target.filePath, workspaceRoot);
        if (!fitsServerCap(zip)) {
          void vscode.window.showErrorMessage(
            `BraimSec: zip is ${(zip.buffer.length / 1024 / 1024).toFixed(1)} MB — ` +
              'over the 50 MB server limit. Exclude large directories and retry.'
          );
          return;
        }
        const filename =
          target.kind === 'workspace'
            ? `${path.basename(workspaceRoot)}-scan.zip`
            : `${path.basename(target.filePath)}-scan.zip`;

        progress.report({ message: `Uploading ${(zip.buffer.length / 1024).toFixed(0)} KB…` });
        statusBar.text = '$(sync~spin) BraimSec: uploading…';
        statusBar.show();
        const scanId = await client.createScan(zip.buffer, filename, getProjectId());

        progress.report({ message: 'Scanning on server…' });
        statusBar.text = '$(sync~spin) BraimSec: scanning…';
        const info = await client.waitForDone(scanId, {
          pollMs: getPollMs(),
          onStatus: (s) => {
            statusBar.text = `$(sync~spin) BraimSec: ${s.status}…`;
          },
        });

        if (info.status === 'failed') {
          statusBar.text = '$(error) BraimSec: scan failed';
          void vscode.window.showErrorMessage(
            'BraimSec scan failed on the server. Check the server logs for details.'
          );
          return;
        }

        progress.report({ message: 'Fetching findings…' });
        const findings = await client.getResults(scanId);
        provider.setFindings(findings, workspaceRoot);
        applyDiagnostics(diagnostics, findings, workspaceRoot);
        statusBar.text = `$(shield) BraimSec: ${findings.length} finding(s)`;
        void vscode.commands.executeCommand('braimsec.findings.focus');
        void vscode.window.showInformationMessage(summarize(findings));
      } catch (err) {
        const msg = err instanceof BraimSecError ? err.message : String(err);
        statusBar.text = '$(error) BraimSec: error';
        void vscode.window.showErrorMessage(`BraimSec scan failed: ${msg}`);
      }
    }
  );
}

export function activate(context: vscode.ExtensionContext): void {
  const provider = new FindingsProvider();
  const diagnostics = vscode.languages.createDiagnosticCollection('braimsec');
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'braimsec.scanWorkspace';

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('braimsec.findings', provider),
    diagnostics,
    statusBar,

    vscode.commands.registerCommand('braimsec.scanWorkspace', () =>
      runScan(context, provider, diagnostics, statusBar, { kind: 'workspace' })
    ),

    vscode.commands.registerCommand('braimsec.scanFile', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (!doc) {
        void vscode.window.showErrorMessage('BraimSec: open a file first.');
        return;
      }
      if (doc.isUntitled || doc.uri.scheme !== 'file') {
        void vscode.window.showErrorMessage('BraimSec: save the file first.');
        return;
      }
      void runScan(context, provider, diagnostics, statusBar, {
        kind: 'file',
        filePath: doc.uri.fsPath,
      });
    }),

    vscode.commands.registerCommand('braimsec.setApiKey', async () => {
      const key = await vscode.window.showInputBox({
        title: 'BraimSec: Set API Key',
        prompt: 'Paste your BraimSec API key (stored securely, never in settings)',
        password: true,
        ignoreFocusOut: true,
      });
      if (key?.trim()) {
        await context.secrets.store(SECRET_KEY, key.trim());
        void vscode.window.showInformationMessage('BraimSec API key saved securely.');
      }
    }),

    vscode.commands.registerCommand('braimsec.setServerUrl', async () => {
      const current = getServerUrl();
      const input = await vscode.window.showInputBox({
        title: 'BraimSec: Set Server URL',
        prompt: 'Your BraimSec server URL, e.g. https://api.braimsec.world',
        value: current,
        ignoreFocusOut: true,
      });
      if (input?.trim()) {
        const url = input.trim().replace(/\/+$/, '');
        await vscode.workspace.getConfiguration('braimsec').update('serverUrl', url, true);
        void vscode.window.showInformationMessage(`BraimSec server URL set to ${url}`);
      }
    }),

    vscode.commands.registerCommand('braimsec.openFinding', (item: FindingItem) => {
      void vscode.window
        .showTextDocument(item.fileUri, { preview: true })
        .then((editor) => {
          const line = Math.max(1, item.lineNumber) - 1;
          const pos = new vscode.Position(line, 0);
          editor.selection = new vscode.Selection(pos, pos);
          editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        })
        .then(
          () => undefined,
          () => {
            void vscode.window.showWarningMessage(
              `BraimSec: could not open ${item.finding.file} — it may not exist locally.`
            );
          }
        );
    }),

    vscode.commands.registerCommand('braimsec.clearResults', () => {
      provider.clear();
      diagnostics.clear();
      statusBar.hide();
    })
  );
}

export function deactivate(): void {
  // Nothing to clean up.
}
