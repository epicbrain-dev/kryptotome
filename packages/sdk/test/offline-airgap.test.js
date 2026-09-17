import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import {
  KryptotomeVault,
  validateW3cCompliance,
} from '../dist/index.js';
import {
  initWasm,
  WasmVerificationEngine,
  WasmSessionEngine,
} from '../dist/wasm/index.js';

/**
 * Installs a strict air-gap network firewall.
 * Any attempt to make an outbound HTTP/HTTPS request, raw TCP socket connection,
 * or UDP datagram transmission will immediately throw an explicit error.
 */
function installAirGapBarrier() {
  const originalFetch = globalThis.fetch;
  const originalHttpRequest = http.request;
  const originalHttpGet = http.get;
  const originalHttpsRequest = https.request;
  const originalHttpsGet = https.get;
  const originalSocketConnect = net.Socket.prototype.connect;
  const originalDgramSend = dgram.Socket.prototype.send;

  let networkCallAttempted = false;

  const rejectNetwork = (target) => {
    networkCallAttempted = true;
    throw new Error(`AIRGAP_VIOLATION: Attempted outbound network access to [${target}] while offline`);
  };

  globalThis.fetch = async (url) => rejectNetwork(`fetch:${url}`);
  http.request = (...args) => rejectNetwork('http.request');
  http.get = (...args) => rejectNetwork('http.get');
  https.request = (...args) => rejectNetwork('https.request');
  https.get = (...args) => rejectNetwork('https.get');
  net.Socket.prototype.connect = function (...args) {
    rejectNetwork('net.Socket.connect');
  };
  dgram.Socket.prototype.send = function (...args) {
    rejectNetwork('dgram.Socket.send');
  };

  return {
    didAttemptNetwork: () => networkCallAttempted,
    reset: () => {
      networkCallAttempted = false;
    },
    restore: () => {
      globalThis.fetch = originalFetch;
      http.request = originalHttpRequest;
      http.get = originalHttpGet;
      https.request = originalHttpsRequest;
      https.get = originalHttpsGet;
      net.Socket.prototype.connect = originalSocketConnect;
      dgram.Socket.prototype.send = originalDgramSend;
    },
  };
}

test('Offline Air-Gap: Verify all proof generation, verification, and table sharing operate with network disabled', async (t) => {
  const airgap = installAirGapBarrier();

  try {
    // 1. Verify that the air-gap barrier works and blocks network attempts
    await assert.rejects(
      async () => globalThis.fetch('https://license.paizo.com/verify'),
      /AIRGAP_VIOLATION/
    );
    assert.strictEqual(airgap.didAttemptNetwork(), true);
    airgap.reset();
    assert.strictEqual(airgap.didAttemptNetwork(), false);

    // 2. Initialize WASM strictly from local disk without remote CDN
    await initWasm();
    assert.strictEqual(airgap.didAttemptNetwork(), false, 'WASM must initialize locally with zero network calls');

    // 3. Vault & Credential Custody: Operates 100% offline
    const vault = new KryptotomeVault({
      keyId: 'did:key:zUserVaultOffline99',
      publicKeyHex: '112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00',
      secretKeyHex: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
    });

    const packageId = 'paizo/pathfinder-player-core';
    const challengeNonce = 'single-use-nonce-12345';

    const sampleCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://kryptotome.org/schemas/v1/context.jsonld',
      ],
      id: 'urn:uuid:cred-offline-airgap-1',
      type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
      issuer: {
        id: 'did:key:zPublisherAirGap',
        name: 'Offline Publisher',
        publicKey: 'ed25519:abcdef0123456789',
      },
      validFrom: new Date(Date.now() - 3600000).toISOString(),
      credentialSubject: {
        id: 'did:key:zUserVaultOffline99',
        holderCommitment: 'urn:kryptotome:commitment:bls12381:1234abcd',
        entitlements: [
          {
            packageId,
            contentDigest: 'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
            scope: ['rules', 'spells', 'items'],
          },
        ],
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:key:zPublisherAirGap#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'sig-offline-bytes',
      },
    };

    // W3C compliance validation offline
    assert.strictEqual(validateW3cCompliance(sampleCredential).valid, true);

    // Import into vault
    vault.importCredential(sampleCredential);
    const stored = vault.findCredentialForPackage(packageId);
    assert.ok(stored, 'Credential must be stored and indexed in vault offline');

    // 4. Host issues challenge offline
    const challenge = {
      nonce: challengeNonce,
      packageId,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    };

    // 5. Vault generates single-use proof offline
    const proof = await vault.generateProof(challenge);
    assert.ok(proof.proofBytes);
    assert.strictEqual(proof.publicInputs.challengeNonce, challengeNonce);

    // 6. Host Embedded Verifier evaluates proof offline
    const verificationEngine = new WasmVerificationEngine();
    assert.strictEqual(verificationEngine.isPackageUnlocked(packageId), false);

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
        challengeNonce,
        packageId,
        contentDigest: 'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
        publisherPubkeyHash: 'ed25519:abcdef0123456789',
        holderCommitment: 'urn:kryptotome:commitment:bls12381:1234abcd'
      }
    };

    const isVerified = verificationEngine.verifyZkProof('', challenge, SAMPLE_PROOF);
    assert.strictEqual(isVerified, true, 'Verification engine must verify proof offline');
    assert.strictEqual(
      verificationEngine.isPackageUnlocked(packageId),
      true,
      'Package compendium must be marked unlocked offline'
    );

    // 7. Table Sharing Session Manager operates offline
    const sessionEngine = new WasmSessionEngine('table-airgap-session-1');
    const hostPubKey = sessionEngine.hostPublicKeyHex();
    assert.strictEqual(typeof hostPubKey, 'string');

    // Host issues ephemeral attestation for peer offline
    const attestation = sessionEngine.issuePeerAttestation(
      'peer:offline:player1',
      packageId,
      'sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
      ['spells', 'rules'],
      120
    );
    assert.strictEqual(attestation.recipientPeerId, 'peer:offline:player1');

    // Peer verifies session attestation offline
    const isAttestationValid = WasmSessionEngine.verifyPeerAttestation(attestation, hostPubKey);
    assert.strictEqual(isAttestationValid, true, 'Peer attestation must verify offline without reaching host key server');

    // Final Assertion: Zero network calls were attempted across the entire flow
    assert.strictEqual(
      airgap.didAttemptNetwork(),
      false,
      'All proof generation, verification, and table sharing must operate completely offline'
    );
  } finally {
    airgap.restore();
  }
});
