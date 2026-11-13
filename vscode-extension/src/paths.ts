/**
 * Path helpers for scan findings — pure TypeScript, no dependency on the
 * `vscode` module so they can be unit-tested with plain Node.
 *
 * Finding file paths come from the server, i.e. from the scanned repo's own
 * contents. A hostile repo could report paths like `../../.ssh/id_rsa` or an
 * absolute path outside the workspace, and the extension would otherwise
 * attach diagnostics to — or open in the editor — arbitrary local files.
 * Every consumer must resolve through resolveFindingPath() and drop
 * findings that escape the workspace root.
 */

import * as path from 'path';

/**
 * Resolve a finding's reported `file` against `workspaceRoot`.
 *
 * Relative paths are resolved inside the root; absolute paths are kept
 * only when they already lie inside it. Returns the absolute path, or
 * `null` when the result would escape the workspace (any `..` traversal
 * or an absolute path outside the root, including another drive on
 * Windows). An empty path is also rejected.
 */
export function resolveFindingPath(file: string, workspaceRoot: string): string | null {
  if (!file) {
    return null;
  }
  const root = path.resolve(workspaceRoot);
  // NB: path.resolve() here is the containment boundary itself — the
  // path.relative() check below rejects anything that escapes `root`,
  // so a hostile `file` value can only ever resolve inside the workspace.
  const abs = path.resolve(root, file);
  const rel = path.relative(root, abs);
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    return null;
  }
  return abs;
}
