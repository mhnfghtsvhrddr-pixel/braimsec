/**
 * BraimSec API client — pure TypeScript, no dependency on the `vscode` module
 * so it can be unit-tested with plain Node.
 *
 * Endpoints used (see api/main.py):
 *   POST /api/scans              multipart form: file=<zip>, project_id?
 *                                header X-API-Key  ->  { "scan_id": "..." }
 *   GET  /api/scans/{id}         -> { id, status, severity_summary, ... }
 *                                status: queued | running | done | failed
 *   GET  /api/scans/{id}/results -> [ { id, tool, rule_id, severity,
 *                                       message, file, line, col, ... } ]
 * Severity values: "error" | "warning" | "note".
 */

export interface Finding {
  id: number | string;
  tool: string;
  rule_id: string;
  severity: string;
  message: string;
  file: string;
  line: number | null;
  col: number | null;
}

export interface ScanInfo {
  id: string;
  status: string;
  target_name?: string;
  total_findings?: number;
  severity_summary?: Record<string, number>;
}

export interface WaitOptions {
  pollMs?: number;
  timeoutMs?: number;
  onStatus?: (s: ScanInfo) => void;
}

export class BraimSecError extends Error {
  readonly status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'BraimSecError';
    this.status = status;
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    const t = await res.text();
    return t.slice(0, 300);
  } catch {
    return '';
  }
}

export class BraimSecClient {
  private readonly base: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(serverUrl: string, apiKey: string, fetchImpl?: typeof fetch) {
    if (!serverUrl) {
      throw new BraimSecError('BraimSec server URL is not set');
    }
    if (!apiKey) {
      throw new BraimSecError('BraimSec API key is not set');
    }
    this.base = serverUrl.replace(/\/+$/, '');
    this.apiKey = apiKey;
    // Node >= 18 ships a global fetch; tests inject a mock.
    this.fetchImpl = fetchImpl ?? fetch;
  }

  private headers(): Record<string, string> {
    return { 'X-API-Key': this.apiKey };
  }

  private async checkOk(res: Response, what: string): Promise<void> {
    if (res.ok) {
      return;
    }
    const body = await safeText(res);
    if (res.status === 401) {
      throw new BraimSecError(
        `Authentication failed (401). Check your BraimSec API key. ${body}`.trim(),
        401
      );
    }
    if (res.status === 402) {
      throw new BraimSecError(
        `Quota exceeded (402). Your BraimSec plan has no scans left. ${body}`.trim(),
        402
      );
    }
    if (res.status === 413) {
      throw new BraimSecError(
        `Upload too large (413). The zip exceeds the server limit (50 MB). ${body}`.trim(),
        413
      );
    }
    throw new BraimSecError(`${what} failed: HTTP ${res.status}. ${body}`.trim(), res.status);
  }

  /** Upload a zip of the workspace/file and return the new scan id. */
  async createScan(zip: Uint8Array, filename: string, projectId?: string): Promise<string> {
    const form = new FormData();
    form.append(
      'file',
      new Blob([zip], { type: 'application/zip' }),
      filename
    );
    if (projectId) {
      form.append('project_id', projectId);
    }
    const res = await this.fetchImpl(`${this.base}/api/scans`, {
      method: 'POST',
      headers: this.headers(),
      body: form,
    });
    await this.checkOk(res, 'Scan upload');
    const data = (await res.json()) as { scan_id?: string };
    if (!data || typeof data.scan_id !== 'string' || !data.scan_id) {
      throw new BraimSecError('Server did not return a scan_id');
    }
    return data.scan_id;
  }

  async getScan(scanId: string): Promise<ScanInfo> {
    const res = await this.fetchImpl(
      `${this.base}/api/scans/${encodeURIComponent(scanId)}`,
      { headers: this.headers() }
    );
    await this.checkOk(res, 'Get scan status');
    return (await res.json()) as ScanInfo;
  }

  async getResults(scanId: string): Promise<Finding[]> {
    const res = await this.fetchImpl(
      `${this.base}/api/scans/${encodeURIComponent(scanId)}/results`,
      { headers: this.headers() }
    );
    await this.checkOk(res, 'Get scan results');
    const data = (await res.json()) as Finding[];
    return Array.isArray(data) ? data : [];
  }

  /** Poll until the scan reaches a terminal state (done/failed). */
  async waitForDone(scanId: string, opts: WaitOptions = {}): Promise<ScanInfo> {
    const pollMs = opts.pollMs ?? 3000;
    const timeoutMs = opts.timeoutMs ?? 10 * 60 * 1000;
    const started = Date.now();
    for (;;) {
      const info = await this.getScan(scanId);
      opts.onStatus?.(info);
      if (info.status === 'done' || info.status === 'failed') {
        return info;
      }
      if (Date.now() - started > timeoutMs) {
        throw new BraimSecError(`Timed out waiting for scan ${scanId}`);
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }
}
