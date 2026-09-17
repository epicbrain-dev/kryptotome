import test from 'node:test';
import assert from 'node:assert';
import {
  CompendiumMerkleTree,
  computeItemLeafHash,
  verifyMerkleInclusionProof,
} from '../dist/merkle.js';
import { TableSessionManager, PeerSessionClient } from '../dist/session.js';
import { KryptotomeVault } from '../dist/vault.js';
import { EmbeddedVerifier } from '../dist/verifier.js';

test('Selective Disclosure: Compendium Merkle tree construction and inclusion verification', () => {
  const items = [
    { id: 'spell-fireball', itemType: 'spell', digest: 'sha256:fireball123' },
    { id: 'spell-heal', itemType: 'spell', digest: 'sha256:heal456' },
    { id: 'feat-power-attack', itemType: 'feat', digest: 'sha256:powerattack789' },
    { id: 'monster-goblin', itemType: 'monster', digest: 'sha256:goblin999' },
  ];

  const tree = new CompendiumMerkleTree(items);
  const root = tree.getRootHex();
  assert.ok(root && root.length === 64, 'Tree root should be a 64-char hex string');

  // Verify inclusion proof for spell-fireball
  const proof = tree.generateInclusionProof('spell-fireball');
  assert.strictEqual(proof.itemId, 'spell-fireball');
  assert.strictEqual(proof.rootHex, root);
  assert.strictEqual(proof.leafHashHex, computeItemLeafHash(items[0]));
  assert.strictEqual(proof.path.length, 2);

  // Verifies against root
  const isValid = verifyMerkleInclusionProof(proof, root);
  assert.strictEqual(isValid, true, 'Valid inclusion proof must verify');

  // Tamper check 1: Corrupted root
  assert.strictEqual(
    verifyMerkleInclusionProof(proof, '0000000000000000000000000000000000000000000000000000000000000000'),
    false,
    'Mismatched root must fail verification'
  );

  // Tamper check 2: Tampered item digest
  const tamperedProof = {
    ...proof,
    leafHashHex: computeItemLeafHash({ id: 'spell-fireball', itemType: 'spell', digest: 'sha256:tampered' }),
  };
  assert.strictEqual(
    verifyMerkleInclusionProof(tamperedProof, root),
    false,
    'Tampered leaf digest must fail inclusion proof'
  );
});

test('Selective Disclosure: Verifier checks proof bundle within performance budget', async () => {
  const verifier = new EmbeddedVerifier();
  const challengeNonce = 'challenge-nonce-selective-123';

  const bundle = {
    version: 1,
    curve: 'BLS12-381',
    proofSystem: 'groth16',
    proofBase64: 'base64:proof-mock-data-xyz',
    publicInputsBase64: 'base64:public-inputs-mock-data-xyz',
    challengeNonce,
    itemDigest: 'sha256:spell-fireball123',
    publisherPubkey: 'ed25519:pubkey-mock',
    holderCommitmentUrn: 'urn:kryptotome:commitment:bls12381:holder-valeros',
  };

  const result = await verifier.verifySelectiveDisclosure(bundle, challengeNonce);
  assert.strictEqual(result, true);

  // Rejection on nonce mismatch
  await assert.rejects(
    async () => {
      await verifier.verifySelectiveDisclosure(bundle, 'wrong-nonce');
    },
    /Nonce mismatch/
  );
});

test('Collective Party Pooling: Multiple players pool distinct rulebooks into aggregated table proof', () => {
  const host = new TableSessionManager({
    sessionId: 'session-table-party-42',
    hostPeerId: 'host-gm-pubkey-hex',
    packageId: 'paizo/gm-core',
    contentDigest: 'sha256:gm-core-digest',
  });

  host.initPartyPool('table-nonce-xyz-789');

  const alice = new PeerSessionClient('peer-alice');
  const bob = new PeerSessionClient('peer-bob');
  const charlie = new PeerSessionClient('peer-charlie');

  // Alice contributes Player Core
  const aliceContrib = alice.createPartyContribution(
    'paizo/pathfinder-player-core',
    'sha256:player-core-digest',
    'table-nonce-xyz-789'
  );
  host.registerPartyContribution(aliceContrib);

  // Bob contributes Monster Core
  const bobContrib = bob.createPartyContribution(
    'paizo/pathfinder-monster-core',
    'sha256:monster-core-digest',
    'table-nonce-xyz-789'
  );
  host.registerPartyContribution(bobContrib);

  // Host validates pooled packages
  assert.strictEqual(host.isPackageInPartyPool('paizo/pathfinder-player-core'), true);
  assert.strictEqual(host.isPackageInPartyPool('paizo/pathfinder-monster-core'), true);
  assert.strictEqual(host.isPackageInPartyPool('paizo/starfinder-core'), false);
  assert.strictEqual(host.getPartyPoolContributions().length, 2);

  // GM finalizes session and issues AggregatedPartySessionProof
  const partyProof = host.finalizePartySession(120);
  assert.strictEqual(partyProof.sessionId, 'session-table-party-42');
  assert.deepStrictEqual(partyProof.pooledPackages, [
    'paizo/pathfinder-monster-core',
    'paizo/pathfinder-player-core',
  ]);
  assert.deepStrictEqual(partyProof.participantPeerIds, ['peer-alice', 'peer-bob']);

  // Charlie (owns neither book) mounts the pooled session
  const mounted = charlie.mountPartySession(partyProof);
  assert.strictEqual(mounted.length, 2);
  assert.strictEqual(charlie.isPackageMounted('paizo/pathfinder-player-core'), true);
  assert.strictEqual(charlie.isPackageMounted('paizo/pathfinder-monster-core'), true);
  assert.strictEqual(charlie.allowsScope('paizo/pathfinder-player-core', 'spells'), true);
});

test('Passkey Hardware Binding: FIDO2/WebAuthn touch presence and user verification', () => {
  const vault = new KryptotomeVault();

  const binding = {
    credentialId: 'cred-yubikey-5-nfc',
    holderCommitmentUrn: 'urn:kryptotome:commitment:bls12381:holder-valeros',
    publicKeyHex: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
    rpId: 'localhost',
    algorithm: 'Ed25519',
    createdAt: new Date().toISOString(),
  };

  vault.bindPasskey(binding);
  assert.deepStrictEqual(vault.getPasskeyBinding(), binding);

  const challenge = 'passkey-unlock-challenge-42';

  // Helper to create mock authenticatorData: 32 bytes rpIdHash + 1 byte flags + 4 bytes counter
  function makeAuthData(userPresent, userVerified) {
    const buf = Buffer.alloc(37);
    let flags = 0;
    if (userPresent) flags |= 0x01; // UP
    if (userVerified) flags |= 0x04; // UV
    buf[32] = flags;
    return buf.toString('hex');
  }

  // 1. Valid assertion: UP=1, UV=1
  const validAssertion = {
    credentialId: 'cred-yubikey-5-nfc',
    authenticatorData: makeAuthData(true, true),
    clientDataJson: JSON.stringify({
      type: 'webauthn.get',
      challenge,
      origin: 'https://localhost',
    }),
    signatureHex: 'sig-mock-hardware-64-bytes',
  };

  const res = vault.verifyPasskeyAssertion(validAssertion, challenge, true);
  assert.strictEqual(res.verified, true);
  assert.strictEqual(res.userPresent, true);
  assert.strictEqual(res.userVerified, true);
  assert.strictEqual(res.holderCommitmentUrn, binding.holderCommitmentUrn);

  // 2. Rejection when User Presence is missing (UP=0)
  const noUpAssertion = {
    ...validAssertion,
    authenticatorData: makeAuthData(false, true),
  };
  assert.throws(
    () => vault.verifyPasskeyAssertion(noUpAssertion, challenge, true),
    /User presence test failed/
  );

  // 3. Rejection when User Verification is missing (UV=0) and required
  const noUvAssertion = {
    ...validAssertion,
    authenticatorData: makeAuthData(true, false),
  };
  assert.throws(
    () => vault.verifyPasskeyAssertion(noUvAssertion, challenge, true),
    /User verification test failed/
  );

  // 4. Rejection on challenge mismatch
  assert.throws(
    () => vault.verifyPasskeyAssertion(validAssertion, 'wrong-challenge', true),
    /Passkey challenge mismatch/
  );
});
