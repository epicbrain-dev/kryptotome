import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const appJsPath = path.resolve(__dirname, '../dist/app.js');
const bundleJsPath = path.resolve(__dirname, '../dist/bundle.js');

if (fs.existsSync(appJsPath)) {
  const content = fs.readFileSync(appJsPath, 'utf8');

  // Strip all ESM export statements for clean browser standalone execution
  let bundleContent = content
    .replace(/^export\s+(class|function|const|let|var|async\s+function)\s+/gm, '$1 ')
    .replace(/^export\s+default\s+/gm, '')
    .replace(/^export\s*\{[^}]*\};?\s*$/gm, '');

  // Add global window attachment fallback
  bundleContent += `
if (typeof window !== "undefined") {
  window.PocketVaultApp = PocketVaultApp;
  if (!window.pocketVault) {
    window.pocketVault = new PocketVaultApp();
  }
}
`;

  // Enterprise safety assertion: ensure zero export keywords remain
  const leftoverExports = bundleContent.match(/\bexport\s+/g);
  if (leftoverExports) {
    throw new Error(`[bundle] Fatal: dist/bundle.js contains unstripped export tokens: ${JSON.stringify(leftoverExports)}`);
  }

  fs.writeFileSync(bundleJsPath, bundleContent, 'utf8');
  console.log('[bundle] Generated enterprise dist/bundle.js with zero export tokens.');
} else {
  console.error('[bundle] Could not find dist/app.js. Run tsc first.');
}
