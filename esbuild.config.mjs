import esbuild from 'esbuild';
import process from 'node:process';

const production = process.argv.includes("production");

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2021',
  outfile: 'main.js',
  sourcemap: production ? false : "inline",
  minify: true,
  logLevel: 'info',
  legalComments: 'none',
  external: ['obsidian', 'electron', '@codemirror/*'],
  metafile: true,
  treeShaking: true
});

if (production) {
  await context.rebuild();
  await context.dispose();
} else {
  await context.watch();
}
