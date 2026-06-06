import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

const entryPoint = fileURLToPath(new URL('../src/index.ts', import.meta.url));
const outfile = fileURLToPath(new URL('../dist/index.js', import.meta.url));

await build({
  entryPoints: [entryPoint],
  outfile,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: ['node20'],
  sourcemap: true,
  banner: {
    js: '#!/usr/bin/env node',
  },
});
