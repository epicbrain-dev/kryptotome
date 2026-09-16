import { cpSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const sourceDir = resolve(__dirname, '../wasm');
const targetDir = resolve(__dirname, '../dist/wasm');

if (existsSync(sourceDir)) {
  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }
  cpSync(sourceDir, targetDir, { recursive: true });
  console.log(`[copy-wasm] Copied WebAssembly artifacts from ${sourceDir} to ${targetDir}`);
} else {
  console.warn(`[copy-wasm] Source directory ${sourceDir} does not exist. Run 'npm run build:wasm' first.`);
}
