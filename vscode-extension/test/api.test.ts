/**
 * Unit tests for the BraimSec API client (src/api.ts).
 * Runs with plain Node — no VS Code needed: `npm test`.
 */

import { strict as assert } from 'node:assert';
import { createServer, IncomingMessage, Server, ServerResponse } from 'node:http';
import { describe, it, before, after } from 'node:test';
import { BraimSecClient, BraimSecError, Finding } from '../src/api';

interface Route {
  method: string;
  path: string;
  handler: (req: IncomingMessage, body: Buffer) => { status: number; json: unknown };
}

function startMock(routes: Route[]): Promise<{ server: Server; url: string; seen: IncomingMessage[] }> {
  const seen: IncomingMessage[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    seen.push(req);
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const route = routes.find((r) => r.method === req.method && req.url === r.path);
      if (!route) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ detail: 'not found' }));
        return;
      }
      const out = route.handler(req, body);
      res.writeHead(out.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out.json));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ server, url: `http://127.0.0.1:${port}`, seen });
    });
  });
}

const FINDINGS: Finding[] = [
  { id: 1, tool: 'semgrep', rule_id: 'braimsec-taint.sql-injection', severity: 'error', message: 'SQLi', file: 'app.py', line: 10, col: 5 },
  { id: 2, tool: 'gitleaks', rule_id: 'aws-key', severity: 'error', message: 'secret', file: 'cfg.py', line: 3, col: 1 },
];

describe('BraimSecClient', () => {
  let mock: { server: Server; url: string; seen: IncomingMessage[] };

  before(async () => {
    let polls = 0;
    mock = await startMock([
      {
        method: 'POST',
        path: '/api/scans',
        handler: (req, body) => {
          assert.equal(req.headers['x-api-key'], 'test-key-123');
          const ct = req.headers['content-type'] ?? '';
          assert.match(ct, /^multipart\/form-data/);
          // The zip bytes must be inside the multipart body.
          assert.ok(body.includes(Buffer.from('PK')), 'multipart body should contain zip data');
          return { status: 200, json: { scan_id: 'scan-1' } };
        },
      },
      {
        method: 'GET',
        path: '/api/scans/scan-1',
        handler: () => {
          polls += 1;
          if (polls < 3) {
            return { status: 200, json: { id: 'scan-1', status: 'running' } };
          }
          return {
            status: 200,
            json: { id: 'scan-1', status: 'done', total_findings: 2, severity_summary: { error: 2 } },
          };
        },
      },
      {
        method: 'GET',
        path: '/api/scans/scan-1/results',
        handler: () => ({ status: 200, json: FINDINGS }),
      },
    ]);
  });

  after(() => {
    mock.server.close();
  });

  it('uploads a zip with the API key header and returns the scan id', async () => {
    const client = new BraimSecClient(mock.url, 'test-key-123');
    // Minimal empty zip (PK\x05\x06 end-of-central-directory record).
    const emptyZip = Buffer.from([
      0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    const scanId = await client.createScan(emptyZip, 'ws-scan.zip');
    assert.equal(scanId, 'scan-1');
  });

  it('polls until the scan is done', async () => {
    const client = new BraimSecClient(mock.url, 'test-key-123');
    const seen: string[] = [];
    const info = await client.waitForDone('scan-1', {
      pollMs: 5,
      timeoutMs: 5000,
      onStatus: (s) => seen.push(s.status),
    });
    assert.equal(info.status, 'done');
    assert.equal(info.total_findings, 2);
    assert.ok(seen.includes('running'), 'should have observed the running state');
  });

  it('parses findings from /results', async () => {
    const client = new BraimSecClient(mock.url, 'test-key-123');
    const findings = await client.getResults('scan-1');
    assert.equal(findings.length, 2);
    assert.equal(findings[0].rule_id, 'braimsec-taint.sql-injection');
    assert.equal(findings[0].line, 10);
  });

  it('throws BraimSecError with status 401 on bad key', async () => {
    const bad = await startMock([
      {
        method: 'GET',
        path: '/api/scans/x',
        handler: () => ({ status: 401, json: { detail: 'Invalid or missing X-API-Key header' } }),
      },
    ]);
    try {
      const client = new BraimSecClient(bad.url, 'wrong-key');
      await assert.rejects(() => client.getScan('x'), (e: unknown) => {
        assert.ok(e instanceof BraimSecError);
        assert.equal((e as BraimSecError).status, 401);
        assert.match((e as Error).message, /API key/);
        return true;
      });
    } finally {
      bad.server.close();
    }
  });

  it('throws when the server returns no scan_id', async () => {
    const weird = await startMock([
      {
        method: 'POST',
        path: '/api/scans',
        handler: () => ({ status: 200, json: { ok: true } }),
      },
    ]);
    try {
      const client = new BraimSecClient(weird.url, 'test-key-123');
      await assert.rejects(() => client.createScan(Buffer.from('PK'), 'a.zip'), /scan_id/);
    } finally {
      weird.server.close();
    }
  });

  it('rejects empty server URL / API key at construction', () => {
    assert.throws(() => new BraimSecClient('', 'k'), /server URL/i);
    assert.throws(() => new BraimSecClient('http://x', ''), /API key/i);
  });

  it('times out when the scan never finishes', async () => {
    const stuck = await startMock([
      {
        method: 'GET',
        path: '/api/scans/stuck',
        handler: () => ({ status: 200, json: { id: 'stuck', status: 'running' } }),
      },
    ]);
    try {
      const client = new BraimSecClient(stuck.url, 'k');
      await assert.rejects(
        () => client.waitForDone('stuck', { pollMs: 5, timeoutMs: 50 }),
        /Timed out/
      );
    } finally {
      stuck.server.close();
    }
  });
});
