import test from 'node:test';
import assert from 'node:assert';
import { WasmWorkerBridge } from '../dist/wasm/index.js';
import { KryptotomeError } from '../dist/error.js';

const SAMPLE_PROOF = {
  proofBytes: [
    142, 61, 175, 39, 53, 16, 89, 179, 176, 127, 101, 69, 204, 213, 83, 243,
    190, 131, 129, 140, 255, 43, 149, 10, 160, 55, 36, 29, 173, 43, 43, 240,
    86, 184, 110, 243, 1, 22, 84, 54, 116, 73, 14, 222, 189, 39, 227, 25,
    139, 33, 163, 217, 48, 161, 155, 239, 15, 66, 161, 26, 59, 122, 69, 94,
    250, 36, 14, 159, 233, 204, 70, 216, 115, 24, 213, 254, 153, 201, 117, 118,
    3, 92, 135, 207, 210, 252, 137, 228, 104, 255, 9, 126, 165, 221, 254, 132,
    13, 128, 249, 254, 90, 66, 45, 141, 33, 85, 224, 82, 100, 158, 211, 248,
    88, 21, 86, 68, 118, 82, 164, 43, 37, 29, 246, 226, 9, 158, 255, 36,
    195, 145, 234, 119, 93, 238, 34, 113, 145, 155, 238, 143, 106, 46, 197, 5,
    148, 17, 57, 119, 131, 101, 52, 108, 118, 160, 178, 37, 13, 227, 200, 51,
    185, 111, 115, 202, 130, 14, 208, 82, 196, 54, 205, 162, 137, 253, 188, 201,
    39, 81, 40, 11, 157, 86, 89, 91, 94, 57, 204, 69, 157, 154, 85, 106
  ],
  publicInputs: {
    challengeNonce: 'single-use-nonce-12345',
    packageId: 'paizo/pathfinder-player-core',
    contentDigest: 'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
    publisherPubkeyHash: 'ed25519:abcdef0123456789',
    holderCommitment: 'urn:kryptotome:commitment:bls12381:1234abcd'
  }
};

function createValidChallenge(packageId = 'paizo/pathfinder-player-core', nonce = 'single-use-nonce-12345') {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 600 * 1000);
  return {
    nonce,
    packageId,
    timestamp: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
}

function createExpiredChallenge(packageId = 'paizo/pathfinder-player-core', nonce = 'single-use-nonce-12345') {
  const now = new Date();
  const past = new Date(now.getTime() - 600 * 1000);
  return {
    nonce,
    packageId,
    timestamp: past.toISOString(),
    expiresAt: past.toISOString(),
  };
}

test('Worker Bridge: initialization and termination lifecycle', async () => {
  const bridge = new WasmWorkerBridge();
  await bridge.init();

  const isUnlocked = await bridge.isPackageUnlocked('paizo/starfinder-core');
  assert.strictEqual(isUnlocked, false);

  await bridge.terminate();

  await assert.rejects(
    async () => bridge.isPackageUnlocked('paizo/starfinder-core'),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-903'
  );
});

test('Worker Bridge: non-blocking execution keeps main event loop responsive', async () => {
  const bridge = new WasmWorkerBridge();
  await bridge.init();

  const packageId = 'paizo/pathfinder-player-core';
  const challenge = createValidChallenge(packageId, SAMPLE_PROOF.publicInputs.challengeNonce);

  // Measure main event loop responsiveness using high-frequency timer ticks
  const tickIntervalMs = 2;
  const tickDeltas = [];
  let lastTick = performance.now();

  const timer = setInterval(() => {
    const now = performance.now();
    tickDeltas.push(now - lastTick);
    lastTick = now;
  }, tickIntervalMs);

  // Dispatch multiple verification requests in parallel to the worker thread
  const verificationPromises = Array.from({ length: 4 }, () =>
    bridge.verifyZkProof('', challenge, SAMPLE_PROOF)
  );

  const results = await Promise.all(verificationPromises);
  clearInterval(timer);
  await bridge.terminate();

  // All parallel verifications must succeed
  for (const res of results) {
    assert.strictEqual(res, true, 'Verification in worker thread must succeed');
  }

  // Verify that the main thread maintained uninterrupted execution
  assert.ok(tickDeltas.length >= 10, `Expected at least 10 timer ticks, got ${tickDeltas.length}`);

  // Max jitter should be well below what would cause an animation or UI frame stutter (>50ms)
  const maxDelta = Math.max(...tickDeltas);
  assert.ok(
    maxDelta < 40,
    `Main event loop experienced excessive lag during worker proof verification (max lag: ${maxDelta.toFixed(2)}ms)`
  );
});

test('Worker Bridge: cache invalidation lifecycle in worker thread', async () => {
  const bridge = new WasmWorkerBridge();
  await bridge.init();

  const packageId = 'paizo/pathfinder-player-core';
  const challenge = createValidChallenge(packageId, SAMPLE_PROOF.publicInputs.challengeNonce);

  // Verify proof to unlock package
  const verified = await bridge.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(verified, true);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), true);

  // Reload package eviction
  const reloadEvicted = await bridge.reloadPackage(packageId);
  assert.strictEqual(reloadEvicted, true);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), false);

  // Re-verify and invalidatePackage
  await bridge.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), true);
  const packageEvicted = await bridge.invalidatePackage(packageId);
  assert.strictEqual(packageEvicted, true);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), false);

  // Re-verify and invalidateIfDigestMismatch
  await bridge.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), true);
  const mismatchEvicted = await bridge.invalidateIfDigestMismatch(packageId, 'sha256:different-digest');
  assert.strictEqual(mismatchEvicted, true);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), false);

  // Re-verify and exitSession
  await bridge.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), true);
  const purgedCount = await bridge.exitSession();
  assert.ok(purgedCount >= 1);
  assert.strictEqual(await bridge.isPackageUnlocked(packageId), false);

  await bridge.terminate();
});

test('Worker Bridge: table session manager offloading and attestation verification', async () => {
  const bridge = new WasmWorkerBridge();
  await bridge.init();

  const sessionId = 'worker-table-session-vtt';
  const hostPubKey = await bridge.initSession(sessionId);
  assert.strictEqual(typeof hostPubKey, 'string');
  assert.strictEqual(hostPubKey.length, 64);

  // Issue peer attestation in worker
  const attestation = await bridge.issuePeerAttestation(
    sessionId,
    'peer-player-carol',
    'paizo/pathfinder-player-core',
    'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
    ['compendium', 'spells'],
    90
  );

  assert.strictEqual(attestation.sessionId, sessionId);
  assert.strictEqual(attestation.recipientPeerId, 'peer-player-carol');
  assert.strictEqual(attestation.packageId, 'paizo/pathfinder-player-core');

  // Verify attestation in worker
  const isValid = await bridge.verifyPeerAttestation(attestation, hostPubKey);
  assert.strictEqual(isValid, true);

  // Tampered attestation fails with KRYP-702
  const tampered = { ...attestation, packageId: 'paizo/tampered-ruleset' };
  await assert.rejects(
    async () => bridge.verifyPeerAttestation(tampered, hostPubKey),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-702'
  );

  await bridge.terminate();
});

test('Worker Bridge: error code taxonomy propagation across thread boundary', async () => {
  const bridge = new WasmWorkerBridge();
  await bridge.init();

  // Expired challenge -> KRYP-401
  const expiredChallenge = createExpiredChallenge();
  await assert.rejects(
    async () => bridge.verifyZkProof('', expiredChallenge, SAMPLE_PROOF),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-401'
  );

  // Nonce mismatch -> KRYP-302
  const mismatchedChallenge = createValidChallenge('paizo/pathfinder-player-core', 'nonce-mismatch-111');
  await assert.rejects(
    async () => bridge.verifyZkProof('', mismatchedChallenge, SAMPLE_PROOF),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-302'
  );

  // Proof bundle nonce mismatch -> KRYP-302
  const bundle = {
    version: 1,
    curve: 'BLS12-381',
    proofSystem: 'groth16',
    proofBase64: 'dGVzdA==',
    publicInputsBase64: 'dGVzdA==',
    packageId: 'paizo/pathfinder-player-core',
    contentDigest: 'sha256:1234',
    challengeNonce: 'bundle-nonce-mismatch',
    holderCommitmentUrn: 'urn:kryptotome:commitment:bls12381:1234abcd',
  };
  const validChallenge = createValidChallenge('paizo/pathfinder-player-core', 'actual-nonce');
  await assert.rejects(
    async () => bridge.verifyProofBundle(bundle, validChallenge),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-302'
  );

  await bridge.terminate();
});
