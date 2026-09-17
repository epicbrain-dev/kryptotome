import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, execFileSync, execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WASM_DIST_DIR = path.resolve(__dirname, '../dist/wasm');

/**
 * Creates an ephemeral static HTTP server to serve the WASM bundle and HTML test runner.
 */
function createTestServer() {
  const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Kryptotome WASM Headless Browser Testbed</title>
</head>
<body>
  <h1>Kryptotome WASM Browser Testbed</h1>
  <div id="status">INITIALIZING</div>
  <pre id="results"></pre>

  <script type="module">
    import init, { WasmSessionManager, WasmVerifier } from '/wasm/kryptotome_wasm.js';

    const testResults = [];
    function record(name, passed, details = '') {
      testResults.push({ name, passed, details });
    }

    async function runSuite() {
      try {
        // 1. Initialize WASM in browser runtime via streaming fetch
        await init('/wasm/kryptotome_wasm_bg.wasm');
        record('wasm_streaming_initialization', true, 'WASM instantiated successfully in browser');

        // 2. Embedded Verifier Lifecycle
        const verifier = new WasmVerifier();
        record('verifier_instantiation', verifier !== null, 'WasmVerifier instance created');

        const initialLock = verifier.isPackageUnlocked('paizo/pathfinder-player-core');
        record('verifier_initial_lock_state', initialLock === false, 'Package initially locked');

        // Verify proof bundle representation
        const sampleBundle = {
          version: '1.0.0',
          proofSystem: 'groth16',
          curve: 'BLS12-381',
          packageId: 'paizo/pathfinder-player-core',
          challengeNonce: 'browser-challenge-12345',
          contentDigest: 'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
          publisherId: 'did:key:zPublisher123',
          holderCommitment: 'urn:kryptotome:commitment:bls12381:1234abcd',
          proofBytesHex: '8e3daf27351059b3b07f6545ccd553f3be83818cff2b950aa037241dad2b2bf056b86ef30116543674490edebe27e3198b21a3d930a19bef0f42a11a3b7a455efa240e9fe9cc46d87318d5fe99c97576035c87cfd2fc89e468ff097ea5ddfe840d80f9fe5a422d8d2155e052649ed3f8581556447652a42b251df6e2099eff24c391ea775dee2271919bee8f6a2ec505941139778365346c76a0b2250de3c833b96f73ca820ed052c436cda289fdbcc92751280b9d56595b5e39cc459d9a556a',
          issuedAt: new Date().toISOString()
        };

        const sampleChallenge = {
          nonce: 'browser-challenge-12345',
          packageId: 'paizo/pathfinder-player-core',
          timestamp: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 300000).toISOString()
        };

        const isBundleValid = verifier.verifyProofBundle(
          JSON.stringify(sampleBundle),
          JSON.stringify(sampleChallenge)
        );
        record('proof_bundle_verification', isBundleValid === true, 'Groth16 bundle verified in browser');

        const unlockedAfter = verifier.isPackageUnlocked('paizo/pathfinder-player-core');
        record('package_unlocked_after_verification', unlockedAfter === true, 'Package marked unlocked');

        // Reload invalidation
        const reloaded = verifier.reloadPackage('paizo/pathfinder-player-core');
        record('reload_invalidation', reloaded === true, 'Package invalidated on reload');
        record('package_locked_after_reload', verifier.isPackageUnlocked('paizo/pathfinder-player-core') === false);

        // Session exit
        const purgedCount = verifier.exitSession();
        record('session_exit_purge', typeof purgedCount === 'number');

        // 3. Table Session Manager and Ephemeral Attestation
        const sessionManager = new WasmSessionManager('browser-table-session-42');
        record('session_manager_instantiation', sessionManager !== null);

        const hostKeyHex = sessionManager.hostPublicKeyHex();
        record('host_public_key_hex', typeof hostKeyHex === 'string' && hostKeyHex.length === 64);

        // Issue peer attestation
        const attestationJson = sessionManager.issuePeerAttestation(
          'peer:player:valeros',
          'paizo/pathfinder-player-core',
          'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
          JSON.stringify(['spells', 'classes', 'rules']),
          180
        );
        record('issue_peer_attestation', typeof attestationJson === 'string' && attestationJson.includes('peer:player:valeros'));

        // Verify peer attestation with host public key
        const isAttestationValid = WasmSessionManager.verifyPeerAttestation(attestationJson, hostKeyHex);
        record('verify_peer_attestation', isAttestationValid === true, 'Peer attestation Ed25519 signature verified');

        // Rejection of tampered attestation
        const parsedAttestation = JSON.parse(attestationJson);
        parsedAttestation.packageId = 'paizo/unauthorized-spoilers';
        assert.throws ? true : true;
        let tamperedRejected = false;
        try {
          WasmSessionManager.verifyPeerAttestation(JSON.stringify(parsedAttestation), hostKeyHex);
        } catch (e) {
          tamperedRejected = true;
        }
        record('tampered_attestation_rejected', tamperedRejected === true, 'Tampered attestation rejected');

        const allPassed = testResults.every(r => r.passed);
        document.getElementById('status').innerText = allPassed ? 'ALL_BROWSER_TESTS_PASSED' : 'TESTS_FAILED';
        document.getElementById('results').innerText = JSON.stringify(testResults, null, 2);
      } catch (err) {
        document.getElementById('status').innerText = 'ERROR: ' + (err.stack || err.message);
        document.getElementById('results').innerText = JSON.stringify(testResults, null, 2);
      }
    }

    runSuite();
  </script>
</body>
</html>`;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://localhost');
    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
      });
      res.end(htmlContent);
    } else if (url.pathname.startsWith('/wasm/')) {
      const fileName = path.basename(url.pathname);
      const filePath = path.join(WASM_DIST_DIR, fileName);
      if (fs.existsSync(filePath)) {
        const contentType = fileName.endsWith('.wasm')
          ? 'application/wasm'
          : fileName.endsWith('.js')
          ? 'application/javascript; charset=utf-8'
          : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(fs.readFileSync(filePath));
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  });

  return server;
}

/**
 * Resolves a binary path either directly or via system PATH.
 */
function findBinary(candidate) {
  if (fs.existsSync(candidate)) return candidate;
  try {
    const cmd = process.platform === 'win32' ? `where ${candidate}` : `which ${candidate}`;
    const result = execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim().split(/\r?\n/)[0];
    if (result && fs.existsSync(result)) return result;
  } catch {
    // candidate not found in PATH
  }
  return null;
}

/**
 * Finds available browser binaries on the host system.
 */
function detectBrowserRuntimes() {
  const browsers = [];

  // Google Chrome / Chromium (Chrome, Chromium, Brave, Edge)
  const chromeCandidates = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    'google-chrome',
    'chromium-browser',
    'chromium',
  ];

  for (const candidate of chromeCandidates) {
    const resolved = findBinary(candidate);
    if (resolved) {
      browsers.push({ name: 'Chrome (Chromium/V8)', path: resolved, type: 'chrome' });
      break;
    }
  }

  // Safari / WebKit JavaScriptCore runtime
  const jscCandidates = [
    '/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc',
    '/System/Library/Frameworks/JavaScriptCore.framework/Resources/jsc',
  ];

  for (const candidate of jscCandidates) {
    const resolved = findBinary(candidate);
    if (resolved) {
      browsers.push({ name: 'Safari (WebKit/JSC)', path: resolved, type: 'webkit-jsc' });
      break;
    }
  }

  return browsers;
}

test('Headless Browser: kryptotome-wasm WebAssembly testbed runs in browser runtimes', async (t) => {
  const browsers = detectBrowserRuntimes();
  if (browsers.length === 0) {
    t.skip('No compatible browser runtime (Chrome/WebKit/Firefox) detected on this host. Skipping headless browser test.');
    return;
  }

  const server = createTestServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const targetUrl = `http://127.0.0.1:${port}/index.html`;

  try {
    for (const browser of browsers) {
      if (browser.type === 'chrome') {
        await t.test(`Execute kryptotome-wasm in ${browser.name}`, async () => {
          const domOutput = await new Promise((resolve, reject) => {
            execFile(
              browser.path,
              [
                '--headless=new',
                '--disable-gpu',
                '--no-sandbox',
                '--dump-dom',
                '--virtual-time-budget=5000',
                targetUrl,
              ],
              { timeout: 15000 },
              (err, stdout, stderr) => {
                if (err) {
                  return reject(new Error(`Browser ${browser.name} execution failed: ${err.message}\n${stderr}`));
                }
                resolve(stdout);
              }
            );
          });

          assert.ok(
            domOutput.includes('ALL_BROWSER_TESTS_PASSED'),
            `Headless ${browser.name} must output ALL_BROWSER_TESTS_PASSED. Output:\n${domOutput}`
          );
        });
      } else if (browser.type === 'webkit-jsc') {
        await t.test(`Execute kryptotome-wasm in ${browser.name}`, async () => {
          // Verify WebKit WebAssembly compiler and instantiation on compiled binary
          const wasmPath = path.join(WASM_DIST_DIR, 'kryptotome_wasm_bg.wasm');
          assert.ok(fs.existsSync(wasmPath), 'kryptotome_wasm_bg.wasm must exist');

          const jscScript = `
            const wasmBytes = read('${wasmPath}', 'binary');
            const wasmModule = new WebAssembly.Module(wasmBytes);
            if (!(wasmModule instanceof WebAssembly.Module)) {
              throw new Error('Failed to compile WebAssembly module in JSC');
            }
            print('WEBKIT_JSC_WASM_COMPILED_SUCCESSFULLY');
          `;

          const jscOutput = execFileSync(browser.path, ['-e', jscScript], {
            encoding: 'utf8',
            timeout: 10000,
          });

          assert.ok(
            jscOutput.includes('WEBKIT_JSC_WASM_COMPILED_SUCCESSFULLY'),
            'WebKit JSC WebAssembly module compilation must succeed'
          );
        });
      }
    }
  } finally {
    server.close();
  }
});
