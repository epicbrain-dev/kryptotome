import test from 'node:test';
import assert from 'node:assert';
import { PocketVaultApp } from '../dist/app.js';

test('PocketVaultApp: generateQuickProof creates zkp proof with nonce', () => {
  const app = new PocketVaultApp();
  const proof = app.generateQuickProof('paizo/player-core');
  assert.ok(proof.startsWith('zkp:pocket-vault:paizo/player-core:'));
  const audit = app.getAuditLog();
  assert.ok(audit.some(e => e.action === 'ZK_PROOF_GENERATED'));
});

test('PocketVaultApp: verifies biometric enclave attestation and audit chronicle', () => {
  const app = new PocketVaultApp();
  const attestation = app.verifyBiometrics();
  assert.strictEqual(attestation.enclaveType, 'AppleSecureEnclave');
  assert.strictEqual(attestation.keyTag, 'org.kryptotome.pocketvault.master');
  assert.ok(attestation.attestationDigest.startsWith('attest:'));
  
  const audit = app.getAuditLog();
  assert.ok(audit.some(e => e.action === 'BIOMETRIC_VERIFIED'));
});

test('PocketVaultApp: verifies compiled dist/app.js has zero CommonJS exports', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const fileURLToPath = (await import('node:url')).fileURLToPath;
  const dirname = path.dirname(fileURLToPath(import.meta.url));
  const js = fs.readFileSync(path.resolve(dirname, '../dist/app.js'), 'utf8');

  assert.ok(!js.includes('Object.defineProperty(exports'), 'Must not define properties on undefined exports');
  assert.ok(!js.includes('exports.PocketVaultApp ='), 'Must use native ESM export, not CommonJS exports');
});

test('PocketVaultApp: dist/bundle.js has zero export tokens and executes safely in browser environment', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const vm = await import('node:vm');
  const fileURLToPath = (await import('node:url')).fileURLToPath;
  const dirname = path.dirname(fileURLToPath(import.meta.url));
  const bundleJs = fs.readFileSync(path.resolve(dirname, '../dist/bundle.js'), 'utf8');

  // Strict check: zero unstripped export keywords anywhere in bundle.js
  const exportMatches = bundleJs.match(/\bexport\s+/g);
  assert.strictEqual(exportMatches, null, `dist/bundle.js must not contain any export statements, found: ${exportMatches}`);
  assert.ok(bundleJs.includes('window.PocketVaultApp = PocketVaultApp'), 'bundle.js must expose PocketVaultApp globally');

  // Validate pure JS execution in browser mock sandbox (no SyntaxError, no ReferenceError)
  const listeners = {};
  const mockDocument = {
    readyState: 'complete',
    getElementById: (id) => ({
      id,
      style: {},
      classList: { add: () => {}, remove: () => {} },
      addEventListener: (evt, fn) => { listeners[`${id}:${evt}`] = fn; },
      appendChild: () => {},
      removeChild: () => {},
      contains: () => true,
    }),
    querySelector: () => ({
      style: {},
      addEventListener: (evt, fn) => { listeners[`query:${evt}`] = fn; },
    }),
    querySelectorAll: () => [],
    createElement: () => ({
      style: {},
      classList: { add: () => {}, remove: () => {} },
      innerHTML: '',
    }),
    addEventListener: (evt, fn) => { listeners[`document:${evt}`] = fn; },
  };

  const sandbox = {
    window: {},
    document: mockDocument,
    setTimeout: (fn) => fn(),
    btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
    atob: (b64) => Buffer.from(b64, 'base64').toString('binary'),
    performance: globalThis.performance || { now: () => Date.now() },
    console,
  };
  sandbox.window = sandbox;

  // Execute bundle in isolated VM context - will throw immediately if SyntaxError or ReferenceError
  vm.createContext(sandbox);
  vm.runInContext(bundleJs, sandbox);

  assert.ok(sandbox.PocketVaultApp, 'PocketVaultApp constructor must be attached to window');
  assert.ok(sandbox.pocketVault, 'pocketVault instance must be initialized on window');
  assert.strictEqual(typeof sandbox.generateQuickProof, 'function', 'generateQuickProof global must be defined');
  assert.strictEqual(typeof sandbox.shareBeacon, 'function', 'shareBeacon global must be defined');
  assert.strictEqual(typeof sandbox.verifyBiometrics, 'function', 'verifyBiometrics global must be defined');

  // Verify inline functions execute without error
  const proof = sandbox.generateQuickProof('paizo/player-core');
  assert.ok(proof.startsWith('zkp:pocket-vault:paizo/player-core:'));

  const attestation = sandbox.verifyBiometrics();
  assert.strictEqual(attestation.keyTag, 'org.kryptotome.pocketvault.master');

  // Verify tournament pass functions
  assert.strictEqual(typeof sandbox.generateTournamentTicket, 'function');
  assert.strictEqual(typeof sandbox.verifyTournamentFast, 'function');
  const ticket = sandbox.generateTournamentTicket('Valeros of Andoran');
  assert.ok(ticket.startsWith('KRYP:TOURNEY:'));
  assert.strictEqual(sandbox.verifyTournamentFast(ticket), true);
});

test('PocketVaultApp: verifies fantasy astrolabe, leyline, and tournament pass elements in index.html', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const fileURLToPath = (await import('node:url')).fileURLToPath;
  const dirname = path.dirname(fileURLToPath(import.meta.url));
  const html = fs.readFileSync(path.resolve(dirname, '../index.html'), 'utf8');

  assert.ok(html.includes('astrolabe-viewfinder'), 'Contains Arcane Scrying Lens astrolabe viewfinder');
  assert.ok(html.includes('astrolabe-ring-outer'), 'Contains outer celestial astrolabe ring');
  assert.ok(html.includes('leyline-circle'), 'Contains Planar Leyline circle');
  assert.ok(html.includes('pocket-toast-container'), 'Contains toast container');
  assert.ok(html.includes('Cinzel'), 'Includes Cinzel font');
  assert.ok(html.includes('enclave-status'), 'Includes biometric enclave indicator');
  assert.ok(html.includes('Pathfinder Society: Official Tournament Pass'), 'Contains tournament pass card');
  assert.ok(html.includes('generateTournamentTicket'), 'Contains tournament ticket action button');
});

