import test from 'node:test';
import assert from 'node:assert';
import {
  mountTokenItem,
  mountBattlemapItem,
  mountSpellCardItem,
  OwlbearExtensionClient,
  initOwlbearExtensionUI,
  OBR_LAYERS,
} from '../dist/main.js';

function createMockObr() {
  const addedItems = [];
  const notifications = [];

  return {
    isAvailable: true,
    player: {
      getId: async () => 'mock-player-1',
      getName: async () => 'GM Tester',
      getRole: async () => 'GM',
    },
    room: {
      getId: async () => 'room-test-123',
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
    notification: {
      show: async (message, variant) => {
        notifications.push({ message, variant });
      },
    },
    _getAddedItems: () => addedItems,
    _getNotifications: () => notifications,
  };
}

test('Owlbear Extension: mountTokenItem generates valid OBR 2.0 Image Item', () => {
  const token = mountTokenItem({
    name: 'Archmage Evoker',
    imageUrl: 'https://assets.kryptotome.org/tokens/archmage.png',
    gridSize: 1,
    packageId: 'open-rpg/core-bestiary',
    assetDigest: 'sha256:4b227777d4da1fc6e11e80a06451e67d3b43a50370f23ec14ff16a15f84ac524',
    hp: { current: 84, max: 84 },
    ac: 15,
  }, 150);

  assert.strictEqual(token.type, 'IMAGE');
  assert.strictEqual(token.name, 'Archmage Evoker');
  assert.strictEqual(token.layer, OBR_LAYERS.CHARACTER);
  assert.strictEqual(token.image.width, 150);
  assert.strictEqual(token.image.height, 150);
  assert.strictEqual(token.metadata['org.kryptotome.packageId'], 'open-rpg/core-bestiary');
  assert.strictEqual(token.metadata['org.kryptotome.ac'], 15);
  assert.ok(token.id.startsWith('kryptotome-token-'));
});

test('Owlbear Extension: mountBattlemapItem generates valid MAP layer Item', () => {
  const map = mountBattlemapItem({
    name: 'Sunken Crypt of the Lich',
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
});

test('Owlbear Extension: mountSpellCardItem generates composite card items', () => {
  const cardItems = mountSpellCardItem({
    name: 'Fireball',
    level: 3,
    school: 'Evocation',
    castingTime: '1 action',
    range: '150 feet',
    duration: 'Instantaneous',
    components: 'V, S, M',
    description: 'Blossoms into an explosion of flame.',
    packageId: 'open-rpg/core-spells',
  });

  assert.strictEqual(cardItems.length, 3);
  const [shape, title, body] = cardItems;
  assert.strictEqual(shape.type, 'SHAPE');
  assert.strictEqual(shape.layer, OBR_LAYERS.NOTE);
  assert.strictEqual(title.type, 'TEXT');
  assert.strictEqual(title.layer, OBR_LAYERS.TEXT);
  assert.strictEqual(title.attachedTo, shape.id);
  assert.strictEqual(body.attachedTo, shape.id);
  assert.ok(title.text.plainText.includes('Fireball'));
});

test('Owlbear Extension: OwlbearExtensionClient mounts directly to OBR scene', async () => {
  const mockObr = createMockObr();
  const client = new OwlbearExtensionClient(mockObr);

  await client.mountToken({
    name: 'Ancient Red Dragon',
    imageUrl: 'https://assets.kryptotome.org/tokens/red-dragon.png',
    gridSize: 4,
    packageId: 'open-rpg/draconic-codex',
    assetDigest: 'sha256:7f9202573215286950293d0d8fd4598d1a3c75eb20d41e784518349fa81f8016',
  });

  assert.strictEqual(mockObr._getAddedItems().length, 1);
  assert.strictEqual(mockObr._getAddedItems()[0].name, 'Ancient Red Dragon');
  assert.strictEqual(mockObr._getAddedItems()[0].image.width, 600); // 150 * 4
  assert.strictEqual(mockObr._getNotifications().length, 1);
  assert.strictEqual(mockObr._getNotifications()[0].variant, 'SUCCESS');
});

test('Owlbear Extension: initOwlbearExtensionUI operates in non-DOM environment safely', () => {
  const client = initOwlbearExtensionUI();
  assert.ok(client instanceof OwlbearExtensionClient);
});
