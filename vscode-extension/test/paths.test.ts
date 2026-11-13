/**
 * Regression tests for src/paths.ts: finding file paths must never resolve
 * outside the workspace root, however hostile the scanned repo is.
 * Runs with plain Node — no VS Code needed: `npm test`.
 */

import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { describe, it } from 'node:test';
import { resolveFindingPath } from '../src/paths';

describe('resolveFindingPath', () => {
  const root = mkdtempSync(join(tmpdir(), 'braimsec-paths-'));

  it('resolves a plain relative path inside the workspace', () => {
    assert.equal(resolveFindingPath('src/app.py', root), join(root, 'src', 'app.py'));
  });

  it('keeps an absolute path that already lies inside the workspace', () => {
    const inside = join(root, 'lib', 'util.py');
    assert.equal(resolveFindingPath(inside, root), inside);
  });

  it('rejects a relative path that climbs out with ..', () => {
    assert.equal(resolveFindingPath('../secret.txt', root), null);
    assert.equal(resolveFindingPath('sub/../../secret.txt', root), null);
    assert.equal(resolveFindingPath('..', root), null);
  });

  it('rejects an absolute path outside the workspace', () => {
    const outside = join(tmpdir(), 'outside-workspace.txt');
    assert.equal(resolveFindingPath(outside, root), null);
  });

  it('rejects an empty path', () => {
    assert.equal(resolveFindingPath('', root), null);
  });

  it('treats a path that stays inside after .. as safe', () => {
    // sub/../app.py normalises back inside the root.
    assert.equal(resolveFindingPath(`sub${sep}..${sep}app.py`, root), join(root, 'app.py'));
  });
});
