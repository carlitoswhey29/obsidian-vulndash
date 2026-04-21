import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import console from 'node:console';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const packageJsonPath = path.resolve(__dirname, '../package.json');
const manifestPath = path.resolve(__dirname, '../manifest.json');

const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

if (!pkg.version || typeof pkg.version !== 'string') {
  throw new Error('package.json is missing a valid version field.');
}

manifest.version = pkg.version;

fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

console.log(`Synced manifest.json version -> ${pkg.version}`);
