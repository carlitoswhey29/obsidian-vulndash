import esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2021',
  outfile: 'main.js',
  sourcemap: false,
  minify: true,
  logLevel: 'info',
  legalComments: 'none',
  external: ['obsidian'],
  metafile: true,
  treeShaking: true
});
