import test from 'node:test';
import assert from 'node:assert';
import {
  OwlbearVttAdapter,
  OwlbearRoomSync,
  mountTokenItem,
  mountBattlemapItem,
  mountSpellCardItem,
  OBR_LAYERS,
} from '../dist/index.js';

function createMockObr() {
  const addedItems = [];
  const broadcastHandlers = new Map();
  const sentMessages = [];
  const notifications = [];

  return {
    isAvailable: true,
    player: {
      getId: async () => 'mock-player-1',
      getName: async () => 'Tester',
      getRole: async () => 'GM',
    },
    room: {
      getId: async () => 'mock-room-abc',
    },
    scene: {
      isReady: async () => true,
      items: {
        addItems: async (items) => {
          addedItems.push(...items);
        },
        getItems: async (filter) => {
          return filter ? addedItems.filter(filter) : [...addedItems];
        },
        deleteItems: async (ids) => {
          const idSet = new Set(ids);
          const idx = addedItems.findIndex((i) => idSet.has(i.id));
          if (idx >= 0) addedItems.splice(idx, 1);
        },
        updateItems: async () => {},
      },
      grid: {
        getDpi: async () => 150,
        getScale: async () => ({ parsed: { multiplier: 5, unit: 'ft' } }),
      },
    },
    broadcast: {
      sendMessage: async (channel, data, options) => {
        sentMessages.push({ channel, data, options });
        const handler = broadcastHandlers.get(channel);
        if (handler) {
          handler({ data, connectionId: 'mock-conn-1' });
        }
      },
      onMessage: (channel, listener) => {
        broadcastHandlers.set(channel, listener);
        return () => {
          broadcastHandlers.delete(channel);
        };
      },
    },
    notification: {
      show: async (message, variant) => {
        notifications.push({ message, variant });
      },
    },
    _internals: {
      addedItems,
      broadcastHandlers,
      sentMessages,
      notifications,
    },
  };
}

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

test('Owlbear Rodeo: mountTokenItem constructs valid OBR 2.0 image token', () => {
  const token = mountTokenItem({
    name: 'Archmage Evoker',
    imageUrl: 'https://assets.kryptotome.org/tokens/archmage.png',
    gridSize: 1,
    packageId: 'open-rpg/core-bestiary',
    assetDigest: 'sha256:4b227777d4da1fc6e11e80a06451e67d3b43a50370f23ec14ff16a15f84ac524',
    hp: { current: 84, max: 84 },
    ac: 15,
  });

  assert.strictEqual(token.type, 'IMAGE');
  assert.strictEqual(token.layer, OBR_LAYERS.CHARACTER);
  assert.strictEqual(token.name, 'Archmage Evoker');
  assert.strictEqual(token.image.url, 'https://assets.kryptotome.org/tokens/archmage.png');
  assert.strictEqual(token.metadata['kryptotome:type'], 'token');
  assert.strictEqual(token.metadata['kryptotome:packageId'], 'open-rpg/core-bestiary');
  assert.deepStrictEqual(token.metadata['kryptotome:stats'], {
    hp: { current: 84, max: 84 },
    ac: 15,
  });
});

test('Owlbear Rodeo: mountBattlemapItem constructs locked MAP layer item with grid config', () => {
  const map = mountBattlemapItem({
    name: 'Sunken Crypt',
    imageUrl: 'https://assets.kryptotome.org/maps/sunken-crypt.jpg',
    pixelWidth: 3840,
    pixelHeight: 2160,
    dpi: 150,
    packageId: 'open-rpg/dungeon-cartography-vol1',
    assetDigest: 'sha256:1a84f3e6a735e18659d81d2f5a60e0a582fa6cf0c294974f884a6c429d29759d',
  });

  assert.strictEqual(map.type, 'IMAGE');
  assert.strictEqual(map.layer, OBR_LAYERS.MAP);
  assert.strictEqual(map.locked, true);
  assert.strictEqual(map.image.width, 3840);
  assert.strictEqual(map.image.height, 2160);
  assert.strictEqual(map.grid.dpi, 150);
  assert.strictEqual(map.metadata['kryptotome:type'], 'battlemap');
});

test('Owlbear Rodeo: mountSpellCardItem constructs compound card shape & text body', () => {
  const items = mountSpellCardItem({
    name: 'Fireball',
    level: 3,
    school: 'Evocation',
    castingTime: '1 action',
    range: '150 feet',
    duration: 'Instantaneous',
    components: 'V, S, M',
    description: 'A bright explosion of flame.',
    packageId: 'open-rpg/core-spells',
  });

  assert.strictEqual(items.length, 3);
  const [bgCard, header, body] = items;

  assert.strictEqual(bgCard.type, 'SHAPE');
  assert.strictEqual(bgCard.layer, OBR_LAYERS.PROP);
  assert.strictEqual(bgCard.shapeType, 'RECTANGLE');
  assert.strictEqual(bgCard.metadata['kryptotome:type'], 'spell-card');

  assert.strictEqual(header.type, 'TEXT');
  assert.strictEqual(header.layer, OBR_LAYERS.TEXT);
  assert.strictEqual(header.attachedTo, bgCard.id);
  assert.ok(header.text.plainText.includes('Fireball'));
  assert.ok(header.text.plainText.includes('Level 3 • Evocation'));

  assert.strictEqual(body.type, 'TEXT');
  assert.strictEqual(body.attachedTo, bgCard.id);
  assert.ok(body.text.plainText.includes('A bright explosion of flame.'));
});

test('Owlbear Rodeo: OwlbearVttAdapter mounts assets directly to OBR scene', async () => {
  const mockObr = createMockObr();
  const adapter = new OwlbearVttAdapter(
    {
      gameSystemId: 'dnd5e',
      isGameMaster: true,
      activeSessionId: 'session-owlbear-test',
      localPeerId: 'peer-obr-gm',
    },
    mockObr
  );

  // Mount token
  const token = await adapter.mountTokenToCanvas({
    name: 'Goblin Scout',
    imageUrl: 'https://assets.kryptotome.org/tokens/goblin.png',
    gridSize: 1,
    packageId: 'open-rpg/core-bestiary',
    assetDigest: 'sha256:112233',
  });
  assert.ok(token.id);
  assert.strictEqual(mockObr._internals.addedItems.length, 1);

  // Mount map
  const map = await adapter.mountBattlemapToCanvas({
    name: 'Forest Clearing',
    imageUrl: 'https://assets.kryptotome.org/maps/forest.jpg',
    pixelWidth: 1920,
    pixelHeight: 1080,
    packageId: 'open-rpg/forest-maps',
    assetDigest: 'sha256:445566',
  });
  assert.ok(map.id);
  assert.strictEqual(mockObr._internals.addedItems.length, 2);

  // Mount spell card
  const cards = await adapter.mountSpellCardToCanvas({
    name: 'Shield',
    level: 1,
    school: 'Abjuration',
    castingTime: '1 reaction',
    range: 'Self',
    duration: '1 round',
    components: 'V, S',
    description: 'An invisible barrier of magical force appears and protects you.',
    packageId: 'open-rpg/core-spells',
  });
  assert.strictEqual(cards.length, 3);
  assert.strictEqual(mockObr._internals.addedItems.length, 5);
});

test('Owlbear Rodeo: OwlbearRoomSync orchestrates table session broadcast and token mounting', async () => {
  const mockObr = createMockObr();
  const gmAdapter = new OwlbearVttAdapter(
    {
      gameSystemId: 'dnd5e',
      isGameMaster: true,
      activeSessionId: 'session-owlbear-table',
      localPeerId: 'peer-gm-host',
    },
    mockObr
  );

  const publisherPubKeyHex = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5';
  const packageId = 'open-rpg/core-spells';

  // GM unlocks package locally with valid proof
  const challengeNonce = '112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00';
  const proof = createSampleProof(packageId, challengeNonce);
  await gmAdapter.unlockCompendiumLocally(packageId, publisherPubKeyHex, proof);


  // Player adapter
  const playerAdapter = new OwlbearVttAdapter({
    gameSystemId: 'dnd5e',
    isGameMaster: false,
    activeSessionId: 'session-owlbear-table',
    localPeerId: 'peer-player-guest',
  });

  // Player requests access to compendium
  const accessRequest = playerAdapter.getPeerClient().createAccessRequest(packageId);

  // GM processes access request
  const accessResponse = gmAdapter.handlePeerAccessRequest(accessRequest);
  assert.ok(accessResponse.attestation);
  assert.ok(accessResponse.hostPublicKeyHex);
  assert.ok(accessResponse.nonce);

  // Player mounts compendium session
  const mountedSession = playerAdapter.mountCompendiumFromHost(accessResponse);
  assert.strictEqual(mountedSession.packageId, packageId);
  assert.strictEqual(playerAdapter.isCompendiumMounted(packageId), true);
  assert.strictEqual(playerAdapter.isPackageUnlocked(packageId), true);

});
