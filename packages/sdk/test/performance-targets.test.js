import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { EmbeddedVerifier } from '../dist/verifier.js';
import { KryptotomeVault } from '../dist/vault.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function makeSampleCredential(packageId) {
  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://kryptotome.org/schemas/v1/context.jsonld',
    ],
    id: `urn:kryptotome:cred:${packageId}`,
    type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
    issuer: {
      id: 'did:key:zPublisher123',
      name: 'Paizo Publishing',
      publicKey: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    },
    validFrom: '2026-09-01T00:00:00Z',
    credentialSubject: {
      id: 'did:key:holder',
      holderCommitment: 'pedersen:commitment:123456',
      entitlements: [
        {
          packageId,
          contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
          scope: ['compendium', 'rules'],
        },
      ],
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-09-01T00:00:00Z',
      verificationMethod: 'did:key:zPublisher123#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'z3hWbT6sampleproof',
    },
  };
}

test('Performance Target 1 - Verification Latency: guarantee < 10ms on single CPU core', async () => {
  const verifier = new EmbeddedVerifier();
  const packageId = 'paizo/pathfinder-player-core';
  const iterations = 50;

  let totalMs = 0;
  for (let i = 0; i < iterations; i++) {
    const challenge = verifier.createChallenge(packageId, 60);
    const proof = {
      proofBytes: `zkp:bench:${i}`,
      publicInputs: {
        challengeNonce: challenge.nonce,
        packageId,
        contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
        publisherPubkeyHash: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
      },
    };

    const start = performance.now();
    const verified = await verifier.verifyZkProof(challenge, proof, {
      publisherPublicKeyHex: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    });
    const elapsed = performance.now() - start;
    totalMs += elapsed;
    assert.strictEqual(verified, true);
  }

  const avgLatencyMs = totalMs / iterations;
  console.log(`[Benchmark] Verification Latency: ${avgLatencyMs.toFixed(3)}ms (Target: < 10ms)`);
  assert.ok(
    avgLatencyMs < 10,
    `Verification latency (${avgLatencyMs.toFixed(3)}ms) exceeded target (< 10ms)`
  );
});

test('Performance Target 2 - Proving Latency: guarantee < 200ms on desktop/mobile', async () => {
  const vault = new KryptotomeVault({
    keyId: 'key-bench-1',
    publicKeyHex: 'pubkey123',
    secretKeyHex: 'seckey456',
  });

  const packageId = 'paizo/pathfinder-player-core';
  vault.importCredential(makeSampleCredential(packageId));

  const iterations = 50;
  let totalMs = 0;

  for (let i = 0; i < iterations; i++) {
    const challenge = {
      nonce: `nonce-${i}-${Date.now()}`,
      packageId,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };

    const start = performance.now();
    const proof = await vault.generateProof(challenge);
    const elapsed = performance.now() - start;
    totalMs += elapsed;

    assert.ok(proof.proofBytes);
    assert.strictEqual(proof.publicInputs.packageId, packageId);
  }

  const avgProvingMs = totalMs / iterations;
  console.log(`[Benchmark] Proving Latency: ${avgProvingMs.toFixed(3)}ms (Target: < 200ms)`);
  assert.ok(
    avgProvingMs < 200,
    `Proving latency (${avgProvingMs.toFixed(3)}ms) exceeded target (< 200ms)`
  );
});

test('Performance Target 3 - WASM Binary Size: maintain stripped footprint < 2MB', () => {
  const wasmPaths = [
    path.resolve(__dirname, '../wasm/kryptotome_wasm_bg.wasm'),
    path.resolve(__dirname, '../dist/wasm/kryptotome_wasm_bg.wasm'),
  ];

  let foundWasm = false;
  for (const p of wasmPaths) {
    if (fs.existsSync(p)) {
      foundWasm = true;
      const stats = fs.statSync(p);
      const sizeBytes = stats.size;
      const sizeMb = sizeBytes / (1024 * 1024);
      const sizeKb = sizeBytes / 1024;

      // Gzip compressed size
      const content = fs.readFileSync(p);
      const gzipped = zlib.gzipSync(content);
      const gzipKb = gzipped.length / 1024;

      console.log(
        `[Benchmark] WASM Binary Size (${path.basename(p)}): ${sizeKb.toFixed(1)}KB (${sizeMb.toFixed(2)}MB), Gzipped: ${gzipKb.toFixed(1)}KB (Target: < 2MB)`
      );

      assert.ok(
        sizeMb < 2.0,
        `WASM binary size (${sizeMb.toFixed(2)}MB) exceeded 2MB limit`
      );
    }
  }

  assert.ok(foundWasm, 'WASM binary kryptotome_wasm_bg.wasm must exist');
});

test('Performance Target 4 - Memory Footprint: keep embedded verifier < 16MB in browser/node runtime', () => {
  if (typeof globalThis.gc === 'function') {
    globalThis.gc();
  }

  const initialHeap = process.memoryUsage().heapUsed;

  // Initialize verifiers and simulate active game table with 100 modules/sessions
  const verifiers = [];
  for (let i = 0; i < 50; i++) {
    const v = new EmbeddedVerifier();
    for (let j = 0; j < 10; j++) {
      v.createChallenge(`package-test-${i}-${j}`);
    }
    verifiers.push(v);
  }

  const peakHeap = process.memoryUsage().heapUsed;
  const heapDeltaBytes = Math.max(0, peakHeap - initialHeap);
  const heapDeltaMb = heapDeltaBytes / (1024 * 1024);

  console.log(
    `[Benchmark] Embedded Verifier Memory Delta: ${heapDeltaMb.toFixed(2)}MB (Target: < 16MB)`
  );

  assert.ok(
    heapDeltaMb < 16.0,
    `Memory footprint delta (${heapDeltaMb.toFixed(2)}MB) exceeded 16MB target`
  );
});
