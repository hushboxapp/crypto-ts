import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const consumer = mkdtempSync(join(tmpdir(), 'crypto-ts-package-'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

try {
  const [packed] = JSON.parse(
    execFileSync(npm, ['pack', '--ignore-scripts', '--json', '--pack-destination', consumer], {
      cwd: root,
      encoding: 'utf8',
    }),
  );
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true }));
  execFileSync(
    npm,
    ['install', '--ignore-scripts', '--no-audit', '--no-fund', join(consumer, packed.filename)],
    { cwd: consumer, stdio: 'inherit' },
  );
  copyFileSync(join(root, 'tests/package/runtime.mjs'), join(consumer, 'runtime.mjs'));
  execFileSync(process.execPath, ['runtime.mjs'], { cwd: consumer, stdio: 'inherit' });

  const source = readFileSync(join(root, 'tests/package/consumer.ts'), 'utf8');
  writeFileSync(join(consumer, 'consumer.mts'), source);
  writeFileSync(join(consumer, 'consumer.cts'), source);
  execFileSync(
    process.execPath,
    [
      join(root, 'node_modules/typescript/bin/tsc'),
      '--noEmit',
      '--strict',
      '--module',
      'nodenext',
      '--target',
      'es2020',
      'consumer.mts',
      'consumer.cts',
    ],
    { cwd: consumer, stdio: 'inherit' },
  );
  console.log('Packed declarations passed strict ESM and CommonJS consumer checks.');
} finally {
  rmSync(consumer, { recursive: true, force: true });
}
