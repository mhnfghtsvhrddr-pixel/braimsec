/**
 * Zip helpers for the BraimSec VS Code extension.
 *
 * The server accepts a zip upload (50 MB cap, see api/main.py MAX_ZIP_BYTES),
 * so we compress the workspace (or a single file) locally and upload it.
 * Junk directories (node_modules, .git, build outputs, ...) are excluded so
 * scans stay fast and the payload small.
 */

import archiver from 'archiver';
import * as fs from 'fs';
import * as path from 'path';

export const MAX_ZIP_BYTES = 50 * 1024 * 1024; // must stay <= server cap

const DEFAULT_IGNORES = [
  'node_modules/**',
  '.git/**',
  '.hg/**',
  '.svn/**',
  '__pycache__/**',
  '*.pyc',
  '.venv/**',
  'venv/**',
  'dist/**',
  'build/**',
  'out/**',
  'target/**',
  '.next/**',
  'coverage/**',
  '.vscode/**',
  '.idea/**',
  '*.log',
  '.DS_Store',
];

export interface ZipResult {
  buffer: Buffer;
  /** Number of files packed into the archive. */
  fileCount: number;
}

/**
 * Zip a whole directory. Paths inside the zip are relative to `rootDir`,
 * which matches the `file` paths the BraimSec API reports back, so the
 * extension can map findings to workspace files.
 */
export function zipDirectory(rootDir: string, extraIgnores: string[] = []): Promise<ZipResult> {
  return new Promise<ZipResult>((resolve, reject) => {
    const archive = archiver('zip', { zlib: { level: 9 } });
    const chunks: Buffer[] = [];
    let fileCount = 0;

    archive.on('warning', (err: Error) => reject(err));
    archive.on('error', (err: Error) => reject(err));
    archive.on('data', (d: Buffer) => chunks.push(d));
    archive.on('entry', () => {
      fileCount += 1;
    });
    archive.on('end', () => {
      const buffer = Buffer.concat(chunks);
      resolve({ buffer, fileCount });
    });

    archive.glob('**/*', {
      cwd: rootDir,
      dot: true,
      ignore: [...DEFAULT_IGNORES, ...extraIgnores],
      // Skip broken symlinks / unreadable entries instead of failing.
      stat: true,
    });
    void archive.finalize();
  });
}

/**
 * Zip a single file. The zip holds one entry whose name is the file path
 * relative to `baseDir` (falling back to the bare basename), so the
 * reported `file` field still resolves inside the workspace.
 */
export async function zipSingleFile(filePath: string, baseDir?: string): Promise<ZipResult> {
  const rootDir = baseDir ?? path.dirname(filePath);
  const rel = path.relative(rootDir, filePath) || path.basename(filePath);
  const data = await fs.promises.readFile(filePath);
  return new Promise<ZipResult>((resolve, reject) => {
    const archive = archiver('zip', { zlib: { level: 9 } });
    const chunks: Buffer[] = [];
    archive.on('warning', (err: Error) => reject(err));
    archive.on('error', (err: Error) => reject(err));
    archive.on('data', (d: Buffer) => chunks.push(d));
    archive.on('end', () => resolve({ buffer: Buffer.concat(chunks), fileCount: 1 }));
    archive.append(data, { name: rel.split(path.sep).join('/') });
    void archive.finalize();
  });
}

/** True when the produced zip fits the server's upload cap. */
export function fitsServerCap(zip: ZipResult): boolean {
  return zip.buffer.length <= MAX_ZIP_BYTES;
}
