export const WORKER_BUNDLE_LOADERS = {
  'normalize-vulnerabilities': async (): Promise<string> => {
    const module = await import('virtual:vulndash-worker/normalize');
    return module.default;
  },
  'parse-sbom': async (): Promise<string> => {
    const module = await import('virtual:vulndash-worker/sbomParse');
    return module.default;
  },
  'render-daily-rollup': async (): Promise<string> => {
    const module = await import('virtual:vulndash-worker/rollupRender');
    return module.default;
  }
};
