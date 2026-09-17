import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const studioRoot = path.resolve(__dirname, '..');

test('Publisher Studio: verifies tauri.conf.json configuration', () => {
  const tauriConfPath = path.join(studioRoot, 'src-tauri', 'tauri.conf.json');
  assert.ok(fs.existsSync(tauriConfPath), 'tauri.conf.json must exist');
  
  const raw = fs.readFileSync(tauriConfPath, 'utf8');
  const conf = JSON.parse(raw);
  assert.strictEqual(conf.package.productName, 'Kryptotome Publisher Studio');
  assert.strictEqual(conf.tauri.bundle.identifier, 'org.kryptotome.publisherstudio');
  assert.ok(conf.tauri.windows.length > 0);
  assert.strictEqual(conf.tauri.windows[0].title, 'Kryptotome Publisher Studio');
});

test('Publisher Studio: verifies index.html structure, fantasy aesthetic, and enterprise elements', () => {
  const htmlPath = path.join(studioRoot, 'index.html');
  assert.ok(fs.existsSync(htmlPath), 'index.html must exist');

  const html = fs.readFileSync(htmlPath, 'utf8');
  
  // Verify main views
  assert.ok(html.includes('id="view-package"'), 'Package Studio view must exist');
  assert.ok(html.includes('id="view-signing"'), 'Cryptographic Signer view must exist');
  assert.ok(html.includes('id="view-crowdfunding"'), 'Crowdfund Bridge view must exist');
  assert.ok(html.includes('id="view-vouchers"'), 'POD & NFC Vouchers view must exist');

  // Verify key controls
  assert.ok(html.includes('id="btn-quick-sample"'), 'Quick sample button exists');
  assert.ok(html.includes('id="btn-export-bundle"'), 'Export bundle button exists');
  assert.ok(html.includes('id="schema-validation-banner"'), 'Schema validation banner exists');
  assert.ok(html.includes('id="asset-dropzone"'), 'Asset dropzone exists');
  assert.ok(html.includes('id="root-package-hash"'), 'Root package hash element exists');
  assert.ok(html.includes('id="btn-sign-manifest"'), 'Sign manifest button exists');
  assert.ok(html.includes('id="btn-process-fulfillment"'), 'Fulfillment process button exists');
  assert.ok(html.includes('id="btn-download-fulfillment-csv"'), 'Download fulfillment CSV button exists');
  assert.ok(html.includes('id="btn-generate-pod-batch"'), 'POD batch generation button exists');

  // Verify Enterprise elements & fantasy typography
  assert.ok(html.includes('id="audit-drawer"'), 'Enterprise Audit Chronicle drawer exists');
  assert.ok(html.includes('id="btn-toggle-chronicle"'), 'Audit Chronicle toggle button exists');
  assert.ok(html.includes('id="toast-container"'), 'Toast notification container exists');
  assert.ok(html.includes('Cinzel'), 'Includes Cinzel font');

  // Verify compiled script linkage
  assert.ok(html.includes('src="dist/app.js"'), 'Script src points to dist/app.js');
});

test('Publisher Studio: verifies styles.css theme and Arcane Grimoire fantasy styling', () => {
  const cssPath = path.join(studioRoot, 'src', 'styles.css');
  assert.ok(fs.existsSync(cssPath), 'styles.css must exist');

  const css = fs.readFileSync(cssPath, 'utf8');
  assert.ok(css.includes('--bg-leather:'), 'Contains background leather tokens');
  assert.ok(css.includes('--border-gilded:'), 'Contains gilded gold foil border gradient');
  assert.ok(css.includes('wax-seal-banner'), 'Contains wax seal banner styling');
  assert.ok(css.includes('pod-scratch-code-box'), 'Contains POD scratch-off card styling');
  assert.ok(css.includes('audit-drawer'), 'Contains enterprise audit drawer styles');
  assert.ok(css.includes('toast-container'), 'Contains toast notification styles');
});

test('Publisher Studio: verifies built dist/app.js has zero CommonJS exports and valid web runtime compatibility', () => {
  const jsPath = path.join(studioRoot, 'dist', 'app.js');
  assert.ok(fs.existsSync(jsPath), 'Compiled dist/app.js must exist');

  const js = fs.readFileSync(jsPath, 'utf8');
  assert.ok(!js.includes('exports.'), 'Must not reference undefined exports object');
  assert.ok(!js.includes('Object.defineProperty(exports'), 'Must not define properties on undefined exports');

  assert.ok(js.includes('btn-quick-sample'), 'Contains btn-quick-sample handler');
  assert.ok(js.includes('btn-export-bundle'), 'Contains btn-export-bundle handler');
  assert.ok(js.includes('btn-download-fulfillment-csv'), 'Contains btn-download-fulfillment-csv handler');
  assert.ok(js.includes('asset-dropzone'), 'Contains dropzone handler');
  assert.ok(js.includes('btn-toggle-chronicle'), 'Contains chronicle drawer handler');

  // Execute in isolated browser-like sandbox
  const sandbox = {
    window: {},
    document: {
      readyState: 'complete',
      createElement: (tag) => ({
        innerHTML: '',
        appendChild: () => {},
        setAttribute: () => {},
        getAttribute: () => '',
        addEventListener: () => {},
        classList: { add: () => {}, remove: () => {} },
        querySelectorAll: () => [],
      }),
      getElementById: (id) => ({
        value: 'pkg-test',
        textContent: '',
        innerHTML: '',
        addEventListener: () => {},
        classList: { add: () => {}, remove: () => {} },
        appendChild: () => {},
      }),
      querySelectorAll: () => [],
      addEventListener: () => {},
    },
    Blob: class {},
    URL: { createObjectURL: () => '', revokeObjectURL: () => {} },
  };
  sandbox.window = sandbox;

  assert.doesNotThrow(() => {
    vm.runInNewContext(js, sandbox);
  }, 'Script must evaluate cleanly in browser-like context without throwing ReferenceError');

  assert.ok(sandbox.publisherStudio, 'Exposes publisherStudio on window');
  assert.strictEqual(typeof sandbox.publisherStudio.init, 'function');
  assert.strictEqual(typeof sandbox.publisherStudio.validateSchema, 'function');
  assert.strictEqual(typeof sandbox.publisherStudio.showToast, 'function');
  assert.strictEqual(typeof sandbox.publisherStudio.logChronicle, 'function');
});
