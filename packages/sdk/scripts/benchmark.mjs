#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { EmbeddedVerifier } from '../dist/verifier.js';
import { KryptotomeVault } from '../dist/vault.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('========================================================================');
console.log('         KRYPTOTOME PROTOCOL PERFORMANCE TARGETS BENCHMARK             ');
console.log('========================================================================\n');

const results = [];

// 1. Verification Latency
{
  const verifier = new EmbeddedVerifier();
  const packageId = 'paizo/pathfinder-player-core';
  const iterations = 100;
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
    await verifier.verifyZkProof(challenge, proof, {
      publisherPublicKeyHex: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    });
    totalMs += performance.now() - start;
  }

  const avgMs = totalMs / iterations;
  results.push({
    metric: 'Verification Latency',
    measured: `${avgMs.toFixed(3)} ms`,
    target: '< 10.0 ms',
    passed: avgMs < 10,
  });
}

// 2. Proving Latency
{
  const vault = new KryptotomeVault({
    keyId: 'key-bench-1',
    publicKeyHex: 'pubkey123',
    secretKeyHex: 'seckey456',
  });

  const packageId = 'paizo/pathfinder-player-core';
  vault.importCredential({
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
  });

  const iterations = 100;
  let totalMs = 0;

  for (let i = 0; i < iterations; i++) {
    const challenge = {
      nonce: `nonce-${i}-${Date.now()}`,
      packageId,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };

    const start = performance.now();
    await vault.generateProof(challenge);
    totalMs += performance.now() - start;
  }

  const avgMs = totalMs / iterations;
  results.push({
    metric: 'Proving Latency',
    measured: `${avgMs.toFixed(3)} ms`,
    target: '< 200.0 ms',
    passed: avgMs < 200,
  });
}

// 3. WASM Binary Size
{
  const wasmPath = path.resolve(__dirname, '../wasm/kryptotome_wasm_bg.wasm');
  if (fs.existsSync(wasmPath)) {
    const bytes = fs.statSync(wasmPath).size;
    const mb = bytes / (1024 * 1024);
    const gzBytes = zlib.gzipSync(fs.readFileSync(wasmPath)).length;
    const gzKb = gzBytes / 1024;

    results.push({
      metric: 'WASM Binary Footprint',
      measured: `${(bytes / 1024).toFixed(1)} KB (${mb.toFixed(2)} MB, gzip: ${gzKb.toFixed(1)} KB)`,
      target: '< 2.0 MB',
      passed: mb < 2.0,
    });
  }
}

// 4. Memory Footprint
{
  const initial = process.memoryUsage().heapUsed;
  const pool = [];
  for (let i = 0; i < 50; i++) {
    const v = new EmbeddedVerifier();
    for (let j = 0; j < 10; j++) {
      v.createChallenge(`pkg-${i}-${j}`);
    }
    pool.push(v);
  }
  const deltaMb = Math.max(0, process.memoryUsage().heapUsed - initial) / (1024 * 1024);

  results.push({
    metric: 'Verifier Memory Delta',
    measured: `${deltaMb.toFixed(2)} MB`,
    target: '< 16.0 MB',
    passed: deltaMb < 16.0,
  });
}

// Print Results Table
console.table(
  results.map((r) => ({
    'Target Metric': r.metric,
    'Measured Value': r.measured,
    'Target SLA': r.target,
    'Compliance Status': r.passed ? '✔ PASS' : '✖ FAIL',
  }))
);

const allPassed = results.every((r) => r.passed);
if (!allPassed) {
  console.error('\n❌ One or more performance targets failed.');
  process.exit(1);
} else {
  console.log('\n✅ All Section 10 performance and footprint targets satisfied!\n');
}
