import test from 'node:test';
import assert from 'node:assert';
import {
  Pathbuilder2eAdapter,
  WanderersGuideAdapter,
  UniversalBuilderRegistry,
} from '../dist/index.js';

function createSampleProof(packageId, challengeNonce) {
  return {
    proofBytes: `zkp:sample:${packageId}:${challengeNonce}`,
    publicInputs: {
      challengeNonce,
      packageId,
      contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
      publisherPubkeyHash: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    },
  };
}

test('Pathbuilder2eAdapter: unlocks Remaster feat offline via ZK proof presentation', async () => {
  const adapter = new Pathbuilder2eAdapter();
  const packageId = 'paizo/player-core';
  const pubKey = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5';
  const proof = createSampleProof(packageId, 'nonce-pb-feat-1');

  assert.strictEqual(adapter.isItemUnlocked(packageId, 'reactive-strike'), false);

  const result = await adapter.unlockItem({
    builderId: 'pathbuilder2e',
    packageId,
    itemId: 'reactive-strike',
    itemType: 'feat',
    publisherPublicKeyHex: pubKey,
    proof,
  });

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.itemId, 'reactive-strike');
  assert.strictEqual(result.zkAttestation.verifiedOffline, true);
  assert.strictEqual(result.data.name, 'Reactive Strike');
  assert.strictEqual(result.data.actionType, 'reaction');
  assert.strictEqual(adapter.isItemUnlocked(packageId, 'reactive-strike'), true);
});

test('Pathbuilder2eAdapter: unlocks Remaster class and exports custom pack schema', async () => {
  const adapter = new Pathbuilder2eAdapter();
  const packageId = 'paizo/player-core';
  const pubKey = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5';

  await adapter.unlockItem({
    builderId: 'pathbuilder2e',
    packageId,
    itemId: 'reactive-strike',
    itemType: 'feat',
    publisherPublicKeyHex: pubKey,
    proof: createSampleProof(packageId, 'nonce-pb-1'),
  });

  await adapter.unlockItem({
    builderId: 'pathbuilder2e',
    packageId,
    itemId: 'warpriest',
    itemType: 'class',
    publisherPublicKeyHex: pubKey,
    proof: createSampleProof(packageId, 'nonce-pb-2'),
  });

  const customPack = await adapter.exportUnlockedPack(packageId);
  assert.strictEqual(customPack.packName, `Kryptotome Unlocked: ${packageId}`);
  assert.strictEqual(customPack.feats.length, 1);
  assert.strictEqual(customPack.feats[0].name, 'Reactive Strike');
  assert.strictEqual(customPack.classes.length, 1);
  assert.strictEqual(customPack.classes[0].name, 'Cleric (Warpriest)');
});

test('Pathbuilder2eAdapter: verifyCharacterBuildLegality identifies unentitled feats', async () => {
  const adapter = new Pathbuilder2eAdapter();
  const packageId = 'paizo/player-core';
  const pubKey = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5';

  await adapter.unlockItem({
    builderId: 'pathbuilder2e',
    packageId,
    itemId: 'reactive-strike',
    itemType: 'feat',
    publisherPublicKeyHex: pubKey,
    proof: createSampleProof(packageId, 'nonce-pb-legal'),
  });

  // Check character with 1 unlocked feat and 1 locked feat
  const check = adapter.verifyCharacterBuildLegality({
    feats: [
      { name: 'Reactive Strike', packageId },
      { name: 'Sudden Charge', packageId },
    ],
  });

  assert.strictEqual(check.legal, false);
  assert.deepStrictEqual(check.unverifiedFeats, ['Sudden Charge']);
});

test('WanderersGuideAdapter: offline item unlocking and homebrew export', async () => {
  const adapter = new WanderersGuideAdapter();
  const packageId = 'paizo/player-core';
  const pubKey = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5';

  const result = await adapter.unlockItem({
    builderId: 'wanderersguide',
    packageId,
    itemId: 'battle-medicine',
    itemType: 'feat',
    publisherPublicKeyHex: pubKey,
    proof: createSampleProof(packageId, 'nonce-wg-1'),
  });

  assert.strictEqual(result.success, true);
  assert.strictEqual(result.itemId, 'battle-medicine');
  assert.strictEqual(adapter.isItemUnlocked(packageId, 'battle-medicine'), true);

  const pack = await adapter.exportUnlockedPack(packageId);
  assert.strictEqual(pack.system, 'pf2e');
  assert.strictEqual(pack.zkVerified, true);
  assert.strictEqual(pack.content.feats.length, 1);
});

test('UniversalBuilderRegistry: discovers and manages builder plugins', () => {
  const registry = new UniversalBuilderRegistry();
  const builders = registry.listSupportedBuilders();

  assert.ok(builders.includes('pathbuilder2e'));
  assert.ok(builders.includes('wanderersguide'));

  const pbPlugin = registry.getPlugin('pathbuilder2e');
  assert.ok(pbPlugin);
  assert.strictEqual(pbPlugin.builderId, 'pathbuilder2e');
});
