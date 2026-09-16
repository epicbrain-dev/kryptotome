import test from 'node:test';
import assert from 'node:assert';
import { ItchIoBridge } from '../dist/itch.js';
import { InMemoryPublisherRegistry } from '../dist/types.js';
import { validateW3cCompliance, KryptotomeVault } from '@kryptotome/sdk';

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

test('ItchIoBridge: authenticate rejects missing credentials with KRYP-801', async () => {
  const bridge = new ItchIoBridge();
  await assert.rejects(
    async () => {
      await bridge.authenticate({});
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-801');
      assert.ok(err.message.includes('itch.io API token or access token is required'));
      return true;
    }
  );
  assert.strictEqual(bridge.isAuthenticated(), false);
});

test('ItchIoBridge: authenticate successfully contacts /key/me and caches user profile', async () => {
  const mockFetch = createMockFetch({
    '/key/me': async (_url, options) => {
      assert.strictEqual(options.headers.Authorization, 'Bearer test-valid-token');
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          user: {
            id: 98765,
            username: 'game_master_42',
            display_name: 'Game Master GM',
            url: 'https://itch.io/profile/game_master_42',
            gamer: true,
            developer: false,
          },
        }),
      };
    },
  });

  const bridge = new ItchIoBridge({ fetchFn: mockFetch });
  const result = await bridge.authenticate({ accessToken: 'test-valid-token' });

  assert.strictEqual(result, true);
  assert.strictEqual(bridge.isAuthenticated(), true);

  const profile = bridge.getUserProfile();
  assert.ok(profile);
  assert.strictEqual(profile.id, 98765);
  assert.strictEqual(profile.username, 'game_master_42');
  assert.strictEqual(profile.displayName, 'Game Master GM');
});

test('ItchIoBridge: authenticate propagates KRYP-801 on 401 unauthorized or API errors', async () => {
  const mockFetch = createMockFetch({
    '/key/me': async () => ({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ errors: ['invalid key'] }),
    }),
  });

  const bridge = new ItchIoBridge({ fetchFn: mockFetch });
  await assert.rejects(
    async () => {
      await bridge.authenticate({ accessToken: 'expired-token' });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-801');
      assert.ok(err.message.includes('HTTP status 401'));
      return true;
    }
  );
});

test('ItchIoBridge: authenticate propagates KRYP-803 on 429 rate limit exceeded', async () => {
  const mockFetch = createMockFetch({
    '/key/me': async () => ({
      ok: false,
      status: 429,
      statusText: 'Too Many Requests',
      json: async () => ({}),
    }),
  });

  const bridge = new ItchIoBridge({ fetchFn: mockFetch });
  await assert.rejects(
    async () => {
      await bridge.authenticate({ accessToken: 'rate-limited-token' });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-803');
      assert.ok(err.message.includes('rate limit exceeded'));
      return true;
    }
  );
});

test('ItchIoBridge: authenticate propagates KRYP-804 on network failure', async () => {
  const mockFetch = createMockFetch({
    '/key/me': async () => {
      throw new Error('ECONNREFUSED connection failed');
    },
  });

  const bridge = new ItchIoBridge({ fetchFn: mockFetch });
  await assert.rejects(
    async () => {
      await bridge.authenticate({ accessToken: 'test-token' });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-804');
      assert.ok(err.message.includes('Network error'));
      return true;
    }
  );
});

test('ItchIoBridge: fetchPurchasedPackages requires authentication (KRYP-801)', async () => {
  const bridge = new ItchIoBridge();
  await assert.rejects(
    async () => {
      await bridge.fetchPurchasedPackages();
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-801');
      assert.ok(err.message.includes('Not authenticated'));
      return true;
    }
  );
});

test('ItchIoBridge: fetchPurchasedPackages queries user library and matches registered publisher titles', async () => {
  const registry = new InMemoryPublisherRegistry([
    {
      platform: 'itch.io',
      platformItemId: '10101',
      packageId: 'open-rpg/core-rules-srd51',
      publisherId: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      publisherName: 'Open Gaming Foundation',
      publisherPublicKey: '0123456789abcdef',
      contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
      defaultScope: ['compendium', 'character_builder'],
      title: 'Open RPG Core Rules SRD 5.1',
    },
  ]);

  const mockFetch = createMockFetch({
    '/key/me': async () => ({
      ok: true,
      status: 200,
      json: async () => ({ user: { id: 1, username: 'testuser' } }),
    }),
    '/key/my-owned-keys': async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        owned_keys: [
          {
            id: 9001,
            game_id: 10101,
            created_at: '2026-09-01T12:00:00Z',
            game: {
              id: 10101,
              title: 'Open RPG Core Rules SRD 5.1',
              url: 'https://publisher.itch.io/core-rules',
            },
          },
          {
            id: 9002,
            game_id: 20202,
            created_at: '2026-09-10T12:00:00Z',
            game: {
              id: 20202,
              title: 'Unregistered Indie Game',
              url: 'https://indie.itch.io/game',
            },
          },
        ],
      }),
    }),
  });

  const bridge = new ItchIoBridge({ fetchFn: mockFetch, registry });
  await bridge.authenticate({ accessToken: 'valid-token' });

  // 1. Fetch all packages without filtering
  const allRecords = await bridge.fetchPurchasedPackages(false);
  assert.strictEqual(allRecords.length, 2);

  const registeredRecord = allRecords.find((r) => r.itemId === '10101');
  assert.ok(registeredRecord);
  assert.strictEqual(registeredRecord.packageId, 'open-rpg/core-rules-srd51');
  assert.strictEqual(registeredRecord.publisherName, 'Open Gaming Foundation');
  assert.strictEqual(registeredRecord.contentDigest, 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f');
  assert.deepStrictEqual(registeredRecord.scope, ['compendium', 'character_builder']);

  const unregisteredRecord = allRecords.find((r) => r.itemId === '20202');
  assert.ok(unregisteredRecord);
  assert.strictEqual(unregisteredRecord.packageId, 'itch/20202');

  // 2. Fetch filtered to registered Kryptotome publisher packages only
  const filteredRecords = await bridge.fetchPurchasedPackages(true);
  assert.strictEqual(filteredRecords.length, 1);
  assert.strictEqual(filteredRecords[0].itemId, '10101');
});

test('ItchIoBridge: deriveCredential creates valid W3C VC v2.0 bound to holder commitment locally', async () => {
  let fetchCallCount = 0;
  const mockFetch = async () => {
    fetchCallCount++;
    return { ok: true, status: 200, json: async () => ({}) };
  };

  const bridge = new ItchIoBridge({ fetchFn: mockFetch });

  const record = {
    platform: 'itch.io',
    orderId: 'order-998877',
    itemId: '54321',
    title: 'Pathfinder Core Rules',
    purchasedAt: '2026-09-15T00:00:00Z',
    packageId: 'paizo/pathfinder-player-core',
    publisherId: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
    publisherName: 'Paizo Publisher',
    publisherPublicKey: '0123456789abcdef',
    contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
    scope: ['compendium', 'rules'],
  };

  const holderCommitment = 'pedersen:commitment:123456';
  const initialFetchCount = fetchCallCount;

  // Derivation happens 100% locally in client memory
  const cred = await bridge.deriveCredential(record, holderCommitment);

  // Assert NO external network requests were made during credential derivation
  assert.strictEqual(fetchCallCount, initialFetchCount);

  // Validate strict W3C VC v2.0 compliance using the SDK validator
  const compliance = validateW3cCompliance(cred);
  assert.strictEqual(compliance.valid, true, `W3C Errors: ${compliance.errors.join(', ')}`);
  assert.strictEqual(compliance.errors.length, 0);

  // Verify structure & binding
  assert.strictEqual(cred['@context'][0], 'https://www.w3.org/ns/credentials/v2');
  assert.strictEqual(cred.id, 'urn:kryptotome:cred:itch:order-998877');
  assert.ok(cred.type.includes('VerifiableCredential'));
  assert.ok(cred.type.includes('KryptotomeEntitlementCredential'));
  assert.strictEqual(cred.issuer.id, 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH');
  assert.strictEqual(cred.credentialSubject.holderCommitment, holderCommitment);
  assert.strictEqual(cred.credentialSubject.entitlements[0].packageId, 'paizo/pathfinder-player-core');
  assert.strictEqual(cred.proof.proofPurpose, 'assertionMethod');

  // Verify derived credential can be imported and utilized in KryptotomeVault
  const vault = new KryptotomeVault();
  vault.importCredential(cred);

  const found = vault.findCredentialForPackage('paizo/pathfinder-player-core');
  assert.ok(found);
  assert.strictEqual(found.id, cred.id);

  // Generate proof using vault
  const challenge = {
    nonce: 'test-challenge-nonce-123',
    packageId: 'paizo/pathfinder-player-core',
    timestamp: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  };
  const proof = await vault.generateProof(challenge);
  assert.strictEqual(proof.publicInputs.packageId, 'paizo/pathfinder-player-core');
  assert.strictEqual(proof.publicInputs.contentDigest, record.contentDigest);
});

test('ItchIoBridge: deriveCredential rejects missing holder commitment', async () => {
  const bridge = new ItchIoBridge();
  const record = {
    platform: 'itch.io',
    orderId: '123',
    itemId: '456',
    title: 'Game',
    purchasedAt: '2026-09-01T00:00:00Z',
  };

  await assert.rejects(
    async () => {
      await bridge.deriveCredential(record, '');
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-103');
      return true;
    }
  );
});
