import test from 'node:test';
import assert from 'node:assert';
import {
  initWasm,
  isWasmInitialized,
  getWasmModule,
  WasmVerificationEngine,
  WasmSessionEngine,
  WasmVerifier,
  WasmSessionManager,
} from '../dist/wasm/index.js';
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
  const expiresAt = new Date(now.getTime() + 600 * 1000); // 10 minutes future
  return {
    nonce,
    packageId,
    timestamp: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
}

function createExpiredChallenge(packageId = 'paizo/pathfinder-player-core', nonce = 'single-use-nonce-12345') {
  const now = new Date();
  const past = new Date(now.getTime() - 600 * 1000); // 10 minutes ago
  return {
    nonce,
    packageId,
    timestamp: past.toISOString(),
    expiresAt: past.toISOString(),
  };
}

test('WASM Loader: asynchronous initialization and singleton caching', async () => {
  assert.strictEqual(isWasmInitialized(), false, 'WASM should not be initialized initially');

  const initResult1 = await initWasm();
  assert.ok(initResult1, 'initWasm must resolve to module exports');
  assert.strictEqual(isWasmInitialized(), true, 'isWasmInitialized must return true');

  const wasmMod = getWasmModule();
  assert.ok(wasmMod.memory instanceof WebAssembly.Memory, 'Module exports must contain WebAssembly.Memory');

  // Deduplication check
  const initResult2 = await initWasm();
  assert.strictEqual(initResult1, initResult2, 'Subsequent initWasm calls must return cached instance');
});

test('WASM Session Engine: host key generation and peer token verification', async () => {
  const sessionId = 'table-session-vtt-101';
  const sessionEngine = new WasmSessionEngine(sessionId);

  const hostPubKey = sessionEngine.hostPublicKeyHex();
  assert.strictEqual(typeof hostPubKey, 'string');
  assert.strictEqual(hostPubKey.length, 64, 'Ed25519 public key hex must be 64 characters (32 bytes)');

  // Issue ephemeral table peer attestation
  const attestation = sessionEngine.issuePeerAttestation(
    'peer-player-bob',
    'paizo/pathfinder-player-core',
    'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
    ['compendium', 'spells'],
    120
  );

  assert.strictEqual(attestation.sessionId, sessionId);
  assert.strictEqual(attestation.recipientPeerId, 'peer-player-bob');
  assert.strictEqual(attestation.packageId, 'paizo/pathfinder-player-core');
  assert.deepStrictEqual(attestation.permittedScopes, ['compendium', 'spells']);
  assert.strictEqual(typeof attestation.signatureHex, 'string');
  assert.strictEqual(attestation.signatureHex.length, 128, 'Ed25519 signature hex must be 128 characters');

  // Verify peer attestation with valid host public key
  const isValid = WasmSessionEngine.verifyPeerAttestation(attestation, hostPubKey);
  assert.strictEqual(isValid, true, 'Peer attestation must pass verification');

  // Rejects tampered attestation
  const tamperedAttestation = { ...attestation, packageId: 'paizo/gamemastery-guide' };
  assert.throws(
    () => WasmSessionEngine.verifyPeerAttestation(tamperedAttestation, hostPubKey),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-702'
  );

  // Rejects invalid host public key
  const invalidKey = '00'.repeat(32);
  assert.throws(
    () => WasmSessionEngine.verifyPeerAttestation(attestation, invalidKey),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-702'
  );

  // Dispose session engine
  sessionEngine.dispose();
  assert.throws(
    () => sessionEngine.hostPublicKeyHex(),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-903'
  );
});

test('WASM Verification Engine: cache state and invalidation lifecycle', async () => {
  const verifier = new WasmVerificationEngine();
  const packageId = 'paizo/pathfinder-player-core';

  // Initially locked
  assert.strictEqual(verifier.isPackageUnlocked(packageId), false);

  // Configure cache TTL
  verifier.setCacheTtlSeconds(14400);

  // Verify proof to unlock package in cache
  const challenge = createValidChallenge(packageId, SAMPLE_PROOF.publicInputs.challengeNonce);
  const verified = verifier.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(verified, true);
  assert.strictEqual(verifier.isPackageUnlocked(packageId), true, 'Package must be unlocked in cache');

  // Test reload package invalidation
  const reloadEvicted = verifier.reloadPackage(packageId);
  assert.strictEqual(reloadEvicted, true, 'reloadPackage must evict package from cache');
  assert.strictEqual(verifier.isPackageUnlocked(packageId), false, 'Package must be locked after reload');

  // Re-unlock
  verifier.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(verifier.isPackageUnlocked(packageId), true);

  // Test invalidatePackage
  const packageEvicted = verifier.invalidatePackage(packageId);
  assert.strictEqual(packageEvicted, true);
  assert.strictEqual(verifier.isPackageUnlocked(packageId), false);

  // Re-unlock
  verifier.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(verifier.isPackageUnlocked(packageId), true);

  // Test digest mismatch invalidation
  const mismatchEvicted = verifier.invalidateIfDigestMismatch(packageId, 'sha256:differentdigest9999999999999999999999999999999999999999999999999999');
  assert.strictEqual(mismatchEvicted, true, 'invalidateIfDigestMismatch must evict when digests differ');
  assert.strictEqual(verifier.isPackageUnlocked(packageId), false);

  // Re-unlock and test game session exit
  verifier.verifyZkProof('', challenge, SAMPLE_PROOF);
  assert.strictEqual(verifier.isPackageUnlocked(packageId), true);
  const exitPurged = verifier.exitSession();
  assert.strictEqual(exitPurged >= 1, true, 'exitSession must purge active cache entries');
  assert.strictEqual(verifier.isPackageUnlocked(packageId), false);

  // Prune expired
  const pruned = verifier.pruneExpired();
  assert.strictEqual(typeof pruned, 'number');

  // Dispose verifier
  verifier.dispose();
  assert.throws(
    () => verifier.isPackageUnlocked(packageId),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-903'
  );
});

test('WASM Verification Engine: rejects expired challenge with KRYP-401', () => {
  const verifier = new WasmVerificationEngine();
  const expiredChallenge = createExpiredChallenge();

  assert.throws(
    () => verifier.verifyZkProof('', expiredChallenge, SAMPLE_PROOF),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-401'
  );

  verifier.dispose();
});

test('WASM Verification Engine: rejects nonce mismatch with KRYP-302', () => {
  const verifier = new WasmVerificationEngine();
  const mismatchedChallenge = createValidChallenge('paizo/pathfinder-player-core', 'nonce-mismatch-999');

  assert.throws(
    () => verifier.verifyZkProof('', mismatchedChallenge, SAMPLE_PROOF),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-302'
  );

  verifier.dispose();
});

test('WASM Verification Engine: presentation bundle validation', () => {
  const verifier = new WasmVerificationEngine();
  const challenge = createValidChallenge();

  // Test bundle challenge mismatch
  const bundleWithMismatchedNonce = {
    version: 1,
    curve: 'BLS12-381',
    proofSystem: 'groth16',
    proofBase64: 'dGVzdA==',
    publicInputsBase64: 'dGVzdA==',
    packageId: 'paizo/pathfinder-player-core',
    contentDigest: 'sha256:1234',
    challengeNonce: 'different-nonce-999',
    holderCommitmentUrn: 'urn:kryptotome:commitment:bls12381:1234abcd',
  };

  assert.throws(
    () => verifier.verifyProofBundle(bundleWithMismatchedNonce, challenge),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-302'
  );

  // Test bundle with expired challenge
  const expiredChallenge = createExpiredChallenge();
  const bundleMatchingExpired = {
    ...bundleWithMismatchedNonce,
    challengeNonce: expiredChallenge.nonce,
  };

  assert.throws(
    () => verifier.verifyProofBundle(bundleMatchingExpired, expiredChallenge),
    (err) => err instanceof KryptotomeError && err.code === 'KRYP-401'
  );

  verifier.dispose();
});

test('Low-level WASM exports: WasmVerifier and WasmSessionManager direct access', () => {
  const rawVerifier = new WasmVerifier();
  assert.strictEqual(rawVerifier.isPackageUnlocked('non-existent'), false);
  rawVerifier.free();

  const rawSession = new WasmSessionManager('session-raw-1');
  assert.strictEqual(typeof rawSession.hostPublicKeyHex(), 'string');
  rawSession.free();
});
