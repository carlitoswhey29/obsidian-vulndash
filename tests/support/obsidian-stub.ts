export const normalizePath = (path: string): string =>
  path.replace(/\\/g, '/').replace(/\/+/g, '/').replace(/^\.\//, '');
