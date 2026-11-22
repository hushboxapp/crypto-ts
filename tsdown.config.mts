import { defineConfig, type UserConfig } from 'tsdown';

const shared = {
  format: ['esm', 'cjs'],
  platform: 'neutral',
  dts: { generator: 'oxc' },
  outputOptions: { codeSplitting: false },
  outExtensions: ({ format }) => ({
    js: format === 'es' ? '.mjs' : '.js',
    dts: format === 'es' ? '.d.mts' : '.d.ts',
  }),
  sourcemap: true,
  clean: true,
  target: 'es2020',
  minify: true,
} satisfies UserConfig;

// Build each entry independently so the worker never depends on shared chunks.
export default defineConfig([
  { ...shared, entry: { index: 'src/index.ts' } },
  { ...shared, entry: { 'hashing/argon2.worker': 'src/hashing/argon2.worker.ts' } },
]);
