import test from 'node:test';
import assert from 'node:assert';
import { ErrataSyncDispatcher } from '../dist/sync.js';

function createMockFetch(handlers) {
  return async (url, options) => {
    const urlString = String(url);
    for (const [pattern, handler] of Object.entries(handlers)) {
      if (urlString.includes(pattern)) {
        return handler(urlString, options);
      }
    }
    throw new Error(`Unhandled mock fetch URL: ${urlString}`);
  };
}

test('ErrataSyncDispatcher: checkForErrata transmits X-Kryptotome-Proof and X-Kryptotome-Digest headers', async () => {
  let capturedHeaders = null;
  let requestedUrl = null;

  const mockFetch = createMockFetch({
    '/packages/open-rpg%2Fcore-rules-srd51/updates': async (url, options) => {
      requestedUrl = url;
      capturedHeaders = options.headers;
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          packageId: 'open-rpg/core-rules-srd51',
          fromDigest: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
          toDigest: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
          patchVersion: '1.0.1',
          publishedAt: '2026-09-15T00:00:00Z',
          publisherId: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
          publisherSignatureHex: 'ed25519:sample',
          operations: [
            { op: 'replace', path: '/items/0/damage', value: '7d6' },
          ],
        }),
      };
    },
  });

  const dispatcher = new ErrataSyncDispatcher(mockFetch);
  const proof = {
    proofBytes: 'zkp:proof:bytes:12345',
    publicInputs: {
      challengeNonce: 'nonce-1',
      packageId: 'open-rpg/core-rules-srd51',
      contentDigest: 'sha256:1111',
      publisherPubkeyHash: 'pubkey',
    },
  };

  const patch = await dispatcher.checkForErrata(
    {
      publisherMirrorUrl: 'https://mirror.opengaming.example/api/v1',
      packageId: 'open-rpg/core-rules-srd51',
      currentDigest: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    },
    proof
  );

  assert.ok(requestedUrl.includes('/packages/open-rpg%2Fcore-rules-srd51/updates'));
  assert.strictEqual(capturedHeaders['X-Kryptotome-Proof'], 'zkp:proof:bytes:12345');
  assert.strictEqual(
    capturedHeaders['X-Kryptotome-Digest'],
    'sha256:1111111111111111111111111111111111111111111111111111111111111111'
  );
  assert.ok(patch);
  assert.strictEqual(patch.patchVersion, '1.0.1');
  assert.strictEqual(patch.operations.length, 1);
});

test('ErrataSyncDispatcher: checkForErrata handles 304 Not Modified and 404 as null', async () => {
  const mockFetch = createMockFetch({
    '/packages/up-to-date/updates': async () => ({
      ok: false,
      status: 304,
      statusText: 'Not Modified',
    }),
    '/packages/no-updates/updates': async () => ({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    }),
  });

  const dispatcher = new ErrataSyncDispatcher(mockFetch);
  const proof = { proofBytes: 'zkp:valid', publicInputs: { challengeNonce: '', packageId: '', contentDigest: '', publisherPubkeyHash: '' } };

  const patch304 = await dispatcher.checkForErrata(
    { publisherMirrorUrl: 'https://cdn.example', packageId: 'up-to-date' },
    proof
  );
  assert.strictEqual(patch304, null);

  const patch404 = await dispatcher.checkForErrata(
    { publisherMirrorUrl: 'https://cdn.example', packageId: 'no-updates' },
    proof
  );
  assert.strictEqual(patch404, null);
});

test('ErrataSyncDispatcher: checkForErrata propagates KRYP-801 on mirror auth rejection', async () => {
  const mockFetch = createMockFetch({
    '/packages/pkg/updates': async () => ({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
    }),
  });

  const dispatcher = new ErrataSyncDispatcher(mockFetch);
  const proof = { proofBytes: 'zkp:invalid' };

  await assert.rejects(
    async () => {
      await dispatcher.checkForErrata(
        { publisherMirrorUrl: 'https://cdn.example', packageId: 'pkg' },
        proof
      );
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-801');
      assert.ok(err.message.includes('Mirror authentication failed'));
      return true;
    }
  );
});

test('ErrataSyncDispatcher: computeJsonPatch and applyJsonPatch RFC 6902 compliance', () => {
  const dispatcher = new ErrataSyncDispatcher();

  const original = {
    title: 'Core Rules SRD',
    version: '1.0.0',
    rules: {
      resting: '8 hours',
      deathSaves: 3,
    },
    spells: [
      { id: 'fireball', damage: '8d6', range: '150 ft' },
      { id: 'magic-missile', damage: '1d4+1' },
    ],
  };

  const updated = {
    title: 'Core Rules SRD (Errata 1.1)',
    version: '1.1.0',
    rules: {
      resting: '8 hours',
      deathSaves: 3,
      exhaustionLevels: 6, // Added field
    },
    spells: [
      { id: 'fireball', damage: '7d6', range: '150 ft' }, // Replaced damage
      // magic-missile removed
      { id: 'cure-wounds', healing: '1d8+mod' }, // Added spell
    ],
  };

  const patchOps = dispatcher.computeJsonPatch(original, updated);
  assert.ok(patchOps.length > 0);

  // Apply computed patch to original
  const result = dispatcher.applyJsonPatch(original, patchOps);
  assert.deepStrictEqual(result, updated);
});

test('ErrataSyncDispatcher: applyErrata updates canonical items while strictly preserving user homebrew', () => {
  const dispatcher = new ErrataSyncDispatcher();

  const compendium = {
    packageId: 'open-rpg/core-rules',
    version: '1.0.0',
    contentDigest: 'sha256:orig-digest-1111',
    items: [
      {
        id: 'spell-fireball',
        name: 'Fireball',
        damage: '8d6',
        range: '150 ft',
        description: 'Bright streak flashes...',
      },
      {
        id: 'spell-shield',
        name: 'Shield',
        acBonus: 5,
        userNotes: 'My GM allows this to deflect magic missiles directly', // User custom field on official item
      },
      {
        id: 'homebrew:spell-mega-meteor',
        name: 'Mega Meteor',
        damage: '20d6',
        homebrew: true,
        author: 'GM Dave',
        notes: 'Campaign climax artifact spell',
      },
      {
        id: 'homebrew:custom-class-gunslinger',
        name: 'Gunslinger Homebrew',
        hitDie: 'd10',
        source: 'homebrew',
      },
    ],
  };

  const patchBundle = {
    packageId: 'open-rpg/core-rules',
    fromDigest: 'sha256:orig-digest-1111',
    toDigest: 'sha256:new-errata-digest-2222',
    patchVersion: '1.0.1',
    publishedAt: '2026-09-16T00:00:00Z',
    publisherId: 'did:key:publisher',
    publisherSignatureHex: ErrataSyncDispatcher.computeSignature(
      'open-rpg/core-rules',
      'sha256:orig-digest-1111',
      'sha256:new-errata-digest-2222',
      '1.0.1',
      'did:key:publisher'
    ),
    operations: [
      // Official errata updates Fireball damage from 8d6 to 7d6
      { op: 'replace', path: '/items/0/damage', value: '7d6' },
      // Official errata updates Shield description
      { op: 'add', path: '/items/1/duration', value: '1 round' },
    ],
  };

  const result = dispatcher.applyErrata(compendium, patchBundle, { verifySignature: true });

  assert.strictEqual(result.newDigest, 'sha256:new-errata-digest-2222');
  assert.strictEqual(result.appliedPatchVersion, '1.0.1');
  assert.strictEqual(result.preservedHomebrewCount, 3); // Mega Meteor, Gunslinger, and Shield userNotes

  // 1. Official items updated
  const updatedFireball = result.compendium.items.find((i) => i.id === 'spell-fireball');
  assert.ok(updatedFireball);
  assert.strictEqual(updatedFireball.damage, '7d6');

  const updatedShield = result.compendium.items.find((i) => i.id === 'spell-shield');
  assert.ok(updatedShield);
  assert.strictEqual(updatedShield.duration, '1 round');
  // 2. User custom field on official item strictly preserved
  assert.strictEqual(
    updatedShield.userNotes,
    'My GM allows this to deflect magic missiles directly'
  );

  // 3. User homebrew items strictly preserved
  const meteor = result.compendium.items.find((i) => i.id === 'homebrew:spell-mega-meteor');
  assert.ok(meteor);
  assert.strictEqual(meteor.damage, '20d6');
  assert.strictEqual(meteor.author, 'GM Dave');

  const gunslinger = result.compendium.items.find((i) => i.id === 'homebrew:custom-class-gunslinger');
  assert.ok(gunslinger);
  assert.strictEqual(gunslinger.hitDie, 'd10');
});

test('ErrataSyncDispatcher: applyErrata rejects package ID and digest mismatches', () => {
  const dispatcher = new ErrataSyncDispatcher();

  const compendium = {
    packageId: 'open-rpg/core-rules',
    version: '1.0.0',
    contentDigest: 'sha256:actual-digest',
    items: [],
  };

  // Package mismatch
  assert.throws(
    () => {
      dispatcher.applyErrata(compendium, {
        packageId: 'wrong/package',
        fromDigest: 'sha256:actual-digest',
        toDigest: 'sha256:new',
        patchVersion: '1.0.1',
        publishedAt: '',
        publisherId: '',
        publisherSignatureHex: '',
        operations: [],
      });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-403');
      return true;
    }
  );

  // Digest mismatch
  assert.throws(
    () => {
      dispatcher.applyErrata(compendium, {
        packageId: 'open-rpg/core-rules',
        fromDigest: 'sha256:different-digest',
        toDigest: 'sha256:new',
        patchVersion: '1.0.1',
        publishedAt: '',
        publisherId: '',
        publisherSignatureHex: '',
        operations: [],
      });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-501');
      return true;
    }
  );
});

test('ErrataSyncDispatcher: rejects prototype-polluting JSON patch paths', () => {
  const dispatcher = new ErrataSyncDispatcher();
  const baseDoc = { a: 1, b: { c: 2 } };

  assert.throws(
    () => {
      dispatcher.applyJsonPatch(baseDoc, [
        { op: 'add', path: '/__proto__/polluted', value: 'yes' },
      ]);
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-501');
      return true;
    }
  );

  assert.throws(
    () => {
      dispatcher.applyJsonPatch(baseDoc, [
        { op: 'replace', path: '/constructor/prototype/polluted', value: 'yes' },
      ]);
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-501');
      return true;
    }
  );

  // Ensure Object prototype was NOT polluted
  assert.strictEqual(({})['polluted'], undefined);
});

