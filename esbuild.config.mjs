import esbuild from 'esbuild';
import process from 'node:process';
import { mkdir, copyFile } from 'node:fs/promises';
import console from 'node:console';

const production = process.argv.includes('production');

const WORKER_ENTRY_POINTS = {
  normalize: 'src/infrastructure/workers/normalize.worker.ts',
  sbomParse: 'src/infrastructure/workers/sbomParse.worker.ts'
};

async function copyPluginAssets() {
  await mkdir('dist', { recursive: true });
  await copyFile('manifest.json', 'dist/manifest.json');
  await copyFile('styles.css', 'dist/styles.css');
}

function createInlineWorkerPlugin() {
  return {
    name: 'inline-worker-bundles',
    setup(build) {
      build.onResolve({ filter: /^virtual:vulndash-worker\// }, (args) => ({
        namespace: 'vulndash-worker',
        path: args.path
      }));

      build.onLoad({ filter: /.*/, namespace: 'vulndash-worker' }, async (args) => {
        const workerName = args.path.replace('virtual:vulndash-worker/', '');
        const entryPoint = WORKER_ENTRY_POINTS[workerName];
        if (!entryPoint) {
          return {
            errors: [{ text: `Unknown VulnDash worker bundle: ${workerName}` }]
          };
        }

        const result = await esbuild.build({
          entryPoints: [entryPoint],
          bundle: true,
          format: 'iife',
          legalComments: 'none',
          logLevel: 'silent',
          metafile: true,
          minify: production,
          platform: 'browser',
          sourcemap: false,
          target: 'es2021',
          treeShaking: true,
          write: false
        });
        const outputFile = result.outputFiles[0];
        if (!outputFile) {
          return {
            errors: [{ text: `Failed to emit worker bundle for ${workerName}` }]
          };
        }

        return {
          contents: `export default ${JSON.stringify(outputFile.text)};`,
          loader: 'js',
          watchFiles: result.metafile ? Object.keys(result.metafile.inputs) : [entryPoint]
        };
      });
    }
  };
}

const ctx = await esbuild.context({
  entryPoints: ['src/main.ts'],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2021',
  outfile: production ? 'dist/main.js' : 'main.js',
  sourcemap: production ? false : 'inline',
  minify: production,
  logLevel: 'info',
  legalComments: 'none',
  external: ['obsidian', 'electron', '@codemirror/*'],
  metafile: true,
  treeShaking: true,
  plugins: [
    createInlineWorkerPlugin(),
    {
      name: 'copy-plugin-assets',
      setup(build) {
        build.onEnd(async (result) => {
          if (result.errors.length > 0) {
            return;
          }

          if (production) {
            try {
              await copyPluginAssets();
              console.log('Copied manifest.json and styles.css to dist/');
            } catch (error) {
              console.error('Failed to copy plugin assets:', error);
              process.exitCode = 1;
            }
          }
        });
      }
    }
  ]
});

if (production) {
  await ctx.rebuild();
  await ctx.dispose();
} else {
  await ctx.watch();
}

