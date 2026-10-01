/**
 * Smoke tests for src/zip.ts: the produced buffer must be a zip containing
 * the expected files and skipping junk directories.
 */

import { strict as assert } from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fitsServerCap, zipDirectory, zipSingleFile } from '../src/zip';

describe('zip helpers', () => {
  it('zips a directory and excludes node_modules/.git', async () => {
    const root = mkdtempSync(join(tmpdir(), 'braimsec-zip-'));
    try {
      writeFileSync(join(root, 'app.py'), 'print(1)\n');
      mkdirSync(join(root, 'node_modules', 'dep'), { recursive: true });
      writeFileSync(join(root, 'node_modules', 'dep', 'index.js'), 'x\n');
      mkdirSync(join(root, '.git'), { recursive: true });
      writeFileSync(join(root, '.git', 'HEAD'), 'ref\n');

      const zip = await zipDirectory(root);
      assert.ok(zip.buffer.length > 0);
      assert.ok(zip.buffer.subarray(0, 2).equals(Buffer.from('PK')), 'must start with zip magic');
      const names = zip.buffer.toString('latin1');
      assert.ok(names.includes('app.py'), 'app.py should be packed');
      assert.ok(!names.includes('node_modules'), 'node_modules must be excluded');
      assert.ok(!names.includes('.git/HEAD'), '.git must be excluded');
      assert.ok(fitsServerCap(zip));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('zips a single file with a workspace-relative name', async () => {
    const root = mkdtempSync(join(tmpdir(), 'braimsec-zipf-'));
    try {
      mkdirSync(join(root, 'src'), { recursive: true });
      const fp = join(root, 'src', 'main.py');
      writeFileSync(fp, 'x=1\n');
      const zip = await zipSingleFile(fp, root);
      assert.equal(zip.fileCount, 1);
      const names = zip.buffer.toString('latin1');
      assert.ok(names.includes('src/main.py'), 'entry should keep the relative path');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
