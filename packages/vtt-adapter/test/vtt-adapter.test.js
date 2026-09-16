import test from 'node:test';
import assert from 'node:assert';
import {
  FoundryVttAdapter,
  renderUnlockModalHtml,
  renderUnlockAnimationCss,
  renderTableSharingStatusBadge,
  renderCompendiumLockOverlay,
} from '../dist/index.js';
import { KryptotomeVault } from '@kryptotome/sdk';

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

class MockCompendiumCollection {
  constructor(id, label) {
    this.metadata = { id, package: id, label };
    this.loadCalls = 0;
    this.getDataCalls = 0;
    this.items = [
      { id: 'spell-1', name: 'Magic Missile', level: 1 },
      { id: 'spell-2', name: 'Fireball', level: 3 },
    ];
  }

  async load() {
    this.loadCalls++;
    return this.items;
  }

  async getData() {
    this.getDataCalls++;
    return { collection: this.metadata.id, entries: this.items };
  }
}

class MockSocketTransport {
  constructor() {
    this.handlers = new Map();
    this.broadcastEvents = [];
  }

  registerHandler(name, handler) {
    this.handlers.set(name, handler);
  }

  async executeAsGM(name, data) {
    const handler = this.handlers.get(name);
    if (!handler) {
      throw new Error(`No GM handler registered for ${name}`);
    }
    return handler(data);
  }

  broadcast(event, data) {
    this.broadcastEvents.push({ event, data });
    const handler = this.handlers.get(event);
    if (handler) {
      handler(data);
    }
  }
}

test('FoundryVttAdapter: compendium hook intercepts load() and unlocks via local vault proof', async () => {
  const adapter = new FoundryVttAdapter({
    gameSystemId: 'dnd5e',
    isGameMaster: true,
    activeSessionId: 'session-table-1',
    localPeerId: 'gm-peer-host',
  });

  const compendium = new MockCompendiumCollection(
    'open-rpg.core-spells',
    'Open RPG Core Spells'
  );
  const packageId = 'open-rpg/core-rules-srd51';

  let promptTriggeredCount = 0;
  let unlockedCallbackCalled = false;

  adapter.hookCompendiumCollection(compendium, packageId, {
    onRequestProof: async (pkgId, nonce) => {
      promptTriggeredCount++;
      return createSampleProof(pkgId, nonce);
    },
    onUnlocked: (pkgId) => {
      unlockedCallbackCalled = true;
      assert.strictEqual(pkgId, packageId);
    },
  });

  assert.strictEqual(adapter.isPackageUnlocked(packageId), false);

  // 1. Initial load call triggers proof prompt and unlocks
  const items = await compendium.load();
  assert.strictEqual(items.length, 2);
  assert.strictEqual(promptTriggeredCount, 1);
  assert.strictEqual(unlockedCallbackCalled, true);
  assert.strictEqual(adapter.isPackageUnlocked(packageId), true);

  // 2. Subsequent load() calls fast-path without prompting again
  const itemsAgain = await compendium.load();
  assert.strictEqual(itemsAgain.length, 2);
  assert.strictEqual(promptTriggeredCount, 1); // Not prompted again
});

test('FoundryVttAdapter: compendium hook intercepts getData() when locked', async () => {
  const adapter = new FoundryVttAdapter({
    gameSystemId: 'dnd5e',
    isGameMaster: true,
    activeSessionId: 'session-table-1',
    localPeerId: 'gm-peer-host',
  });

  const compendium = new MockCompendiumCollection(
    'open-rpg.core-rules',
    'Open RPG Rules'
  );
  const packageId = 'open-rpg/core-rules-srd51';

  adapter.hookCompendiumCollection(compendium, packageId, {
    onRequestProof: async (pkgId, nonce) => createSampleProof(pkgId, nonce),
  });

  const data = await compendium.getData();
  assert.strictEqual(data.collection, 'open-rpg.core-rules');
  assert.strictEqual(data.entries.length, 2);
  assert.strictEqual(adapter.isPackageUnlocked(packageId), true);
});

test('FoundryVttAdapter: compendium hook blocks load() when proof presentation is cancelled', async () => {
  const adapter = new FoundryVttAdapter({
    gameSystemId: 'dnd5e',
    isGameMaster: true,
    activeSessionId: 'session-table-1',
    localPeerId: 'gm-peer-host',
  });

  const compendium = new MockCompendiumCollection('locked-pack', 'Locked Pack');
  const packageId = 'locked/package';

  adapter.hookCompendiumCollection(compendium, packageId, {
    onRequestProof: async () => null, // User clicks cancel
  });

  await assert.rejects(
    async () => {
      await compendium.load();
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-603');
      assert.ok(err.message.includes('credential proof presentation was cancelled'));
      return true;
    }
  );

  assert.strictEqual(compendium.loadCalls, 0); // Original load never executed
  assert.strictEqual(adapter.isPackageUnlocked(packageId), false);
});

test('FoundryVttAdapter: WebRTC / SocketLib table session token dispatch and mounting', async () => {
  const packageId = 'paizo/pathfinder-player-core';
  const sharedSocket = new MockSocketTransport();

  // 1. GM Adapter
  const gmAdapter = new FoundryVttAdapter({
    gameSystemId: 'pf2e',
    isGameMaster: true,
    activeSessionId: 'table-session-1234',
    localPeerId: 'host-gm-peer-id',
  });
  gmAdapter.enableSocketLib(sharedSocket);

  // GM unlocks module first
  const gmProof = createSampleProof(packageId, 'gm-challenge-nonce');
  await gmAdapter.unlockCompendiumModule(
    packageId,
    'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    gmProof
  );
  assert.ok(gmAdapter.getSessionManager());

  // 2. Player Adapter
  const playerAdapter = new FoundryVttAdapter({
    gameSystemId: 'pf2e',
    isGameMaster: false,
    activeSessionId: 'table-session-1234',
    localPeerId: 'player-alice-peer-id',
  });
  const playerDispatcher = playerAdapter.enableSocketLib(sharedSocket);

  assert.strictEqual(playerAdapter.isCompendiumMounted(packageId), false);

  // 3. Player requests access over socket
  const mountedSession = await playerDispatcher.requestAccessOverSocket(packageId);

  assert.ok(mountedSession);
  assert.strictEqual(mountedSession.packageId, packageId);
  assert.strictEqual(mountedSession.recipientPeerId, 'player-alice-peer-id');
  assert.strictEqual(playerAdapter.isCompendiumMounted(packageId), true);
  assert.strictEqual(playerAdapter.isPackageUnlocked(packageId), true);

  // 4. Renewal over socket
  const renewedSession = await playerDispatcher.renewAccessOverSocket(packageId);
  assert.ok(renewedSession);
  assert.strictEqual(renewedSession.packageId, packageId);

  // 5. GM revokes player and broadcasts notice over socket
  const gmNotice = gmAdapter.revokePlayerPeer('player-alice-peer-id', packageId, 'Session ended');
  assert.strictEqual(gmNotice.recipientPeerId, 'player-alice-peer-id');
});

test('FoundryVttAdapter: Reference UI Components render valid HTML/CSS', () => {
  const adapter = new FoundryVttAdapter({
    gameSystemId: 'dnd5e',
    isGameMaster: true,
    activeSessionId: 'session-42',
    localPeerId: 'gm-host',
  });

  // 1. Unlock Modal HTML
  const modalHtml = renderUnlockModalHtml('open-rpg/core-rules-srd51', 'test-fresh-nonce-99', {
    title: 'Unlock Core Rules SRD',
    publisherName: 'Open Gaming Foundation',
    expiresInSeconds: 60,
  });
  assert.ok(modalHtml.includes('open-rpg/core-rules-srd51'));
  assert.ok(modalHtml.includes('test-fresh-nonce-99'));
  assert.ok(modalHtml.includes('Open Gaming Foundation'));
  assert.ok(modalHtml.includes('ktome-btn-primary'));

  // 2. Animations and Stylesheet
  const css = renderUnlockAnimationCss();
  assert.ok(css.includes('@keyframes ktome-pulse-glow'));
  assert.ok(css.includes('@keyframes ktome-unlock-burst'));
  assert.ok(css.includes('.ktome-glass-panel'));

  // 3. Table Sharing Status Badge
  const badgeHtml = renderTableSharingStatusBadge({
    isGameMaster: true,
    sessionId: 'session-42',
    connectedPeerCount: 4,
    packageId: 'open-rpg/core-rules',
    allowedScopes: ['spells', 'classes'],
  });
  assert.ok(badgeHtml.includes('GM Host'));
  assert.ok(badgeHtml.includes('4</strong>'));
  assert.ok(badgeHtml.includes('spells'));

  // 4. Compendium Lock Overlay
  const overlayHtml = renderCompendiumLockOverlay('pack-spells', 'Spells Compendium');
  assert.ok(overlayHtml.includes('ktome-lock-overlay-pack-spells'));
  assert.ok(overlayHtml.includes('Spells Compendium'));

  // 5. Adapter wrapper methods
  assert.ok(adapter.renderStyles().includes('@keyframes'));
  assert.ok(adapter.renderTableSharingStatus('test-pack').includes('GM Host'));
  assert.ok(adapter.renderLockOverlay('test-pack').includes('ktome-lock-overlay-test-pack'));
});
