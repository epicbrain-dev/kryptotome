import test from 'node:test';
import assert from 'node:assert';
import { DriveThruRpgBridge } from '../dist/drivethru.js';
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

test('DriveThruRpgBridge: authenticate rejects missing application key with KRYP-801', async () => {
  const bridge = new DriveThruRpgBridge();
  await assert.rejects(
    async () => {
      await bridge.authenticate({});
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-801');
      assert.ok(err.message.includes('DriveThruRPG application key required'));
      return true;
    }
  );
  assert.strictEqual(bridge.isAuthenticated(), false);
});

test('DriveThruRpgBridge: authenticate successfully contacts /customer/status and caches profile', async () => {
  const mockFetch = createMockFetch({
    '/customer/status': async (_url, options) => {
      assert.strictEqual(options.headers.Authorization, 'Bearer test-dtrpg-app-key');
      assert.strictEqual(options.headers['X-DTRPG-Application-Key'], 'test-dtrpg-app-key');
      assert.strictEqual(options.headers['X-DTRPG-User-Token'], 'test-user-token');
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          customer: {
            id: 888777,
            name: 'Tabletop Enthusiast',
            email: 'gamer@example.com',
          },
        }),
      };
    },
  });

  const bridge = new DriveThruRpgBridge({ fetchFn: mockFetch });
  const result = await bridge.authenticate({
    applicationKey: 'test-dtrpg-app-key',
    userToken: 'test-user-token',
  });

  assert.strictEqual(result, true);
  assert.strictEqual(bridge.isAuthenticated(), true);

  const profile = bridge.getCustomerProfile();
  assert.ok(profile);
  assert.strictEqual(profile.customerId, 888777);
  assert.strictEqual(profile.name, 'Tabletop Enthusiast');
  assert.strictEqual(profile.email, 'gamer@example.com');
});

test('DriveThruRpgBridge: authenticate propagates KRYP-801 on 401 unauthorized or invalid key', async () => {
  const mockFetch = createMockFetch({
    '/customer/status': async () => ({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ error: 'Invalid application key' }),
    }),
  });

  const bridge = new DriveThruRpgBridge({ fetchFn: mockFetch });
  await assert.rejects(
    async () => {
      await bridge.authenticate({ applicationKey: 'invalid-key' });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-801');
      assert.ok(err.message.includes('HTTP status 401'));
      return true;
    }
  );
});

test('DriveThruRpgBridge: authenticate propagates KRYP-803 on 429 rate limit exceeded', async () => {
  const mockFetch = createMockFetch({
    '/customer/status': async () => ({
      ok: false,
      status: 429,
      statusText: 'Too Many Requests',
      json: async () => ({}),
    }),
  });

  const bridge = new DriveThruRpgBridge({ fetchFn: mockFetch });
  await assert.rejects(
    async () => {
      await bridge.authenticate({ applicationKey: 'rate-limited-key' });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-803');
      assert.ok(err.message.includes('rate limit exceeded'));
      return true;
    }
  );
});

test('DriveThruRpgBridge: authenticate propagates KRYP-804 on network failure', async () => {
  const mockFetch = createMockFetch({
    '/customer/status': async () => {
      throw new Error('ENOTFOUND api.drivethrurpg.com');
    },
  });

  const bridge = new DriveThruRpgBridge({ fetchFn: mockFetch });
  await assert.rejects(
    async () => {
      await bridge.authenticate({ applicationKey: 'test-key' });
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-804');
      assert.ok(err.message.includes('Network error'));
      return true;
    }
  );
});

test('DriveThruRpgBridge: fetchPurchasedPackages requires authentication (KRYP-801)', async () => {
  const bridge = new DriveThruRpgBridge();
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

test('DriveThruRpgBridge: fetchPurchasedPackages queries digital library and matches registered publisher titles', async () => {
  const registry = new InMemoryPublisherRegistry([
    {
      platform: 'drivethrurpg',
      platformItemId: '450231',
      packageId: 'free-league/dragonbane-core-set',
      publisherId: 'did:key:z6MkqB3p87vFf9...',
      publisherName: 'Free League Publishing',
      publisherPublicKey: '0123456789fedcba0123456789fedcba0123456789fedcba0123456789fedcba',
      contentDigest: 'sha256:abc123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      defaultScope: ['compendium', 'rules', 'adventures'],
      title: 'Dragonbane Core Set',
    },
  ]);

  const mockFetch = createMockFetch({
    '/customer/status': async () => ({
      ok: true,
      status: 200,
      json: async () => ({ customer: { id: 1234 } }),
    }),
    '/products/mylibrary/search': async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        products: [
          {
            product_id: 450231,
            name: 'Dragonbane Core Set',
            order_id: 'ord-dtrpg-554433',
            order_date: '2026-08-20T10:00:00Z',
            format: 'PDF',
            publisher: 'Free League Publishing',
          },
          {
            product_id: 999999,
            name: 'Random Unregistered Indie Zine',
            order_id: 'ord-dtrpg-112233',
            order_date: '2026-08-25T11:00:00Z',
            format: 'PDF',
            publisher: 'Indie Creator',
          },
        ],
      }),
    }),
  });

  const bridge = new DriveThruRpgBridge({ fetchFn: mockFetch, registry });
  await bridge.authenticate({ applicationKey: 'valid-app-key' });

  // 1. Fetch all packages without filtering
  const allRecords = await bridge.fetchPurchasedPackages(false);
  assert.strictEqual(allRecords.length, 2);

  const registered = allRecords.find((r) => r.itemId === '450231');
  assert.ok(registered);
  assert.strictEqual(registered.platform, 'drivethrurpg');
  assert.strictEqual(registered.packageId, 'free-league/dragonbane-core-set');
  assert.strictEqual(registered.publisherName, 'Free League Publishing');
  assert.strictEqual(registered.orderId, 'ord-dtrpg-554433');
  assert.deepStrictEqual(registered.scope, ['compendium', 'rules', 'adventures']);

  const unregistered = allRecords.find((r) => r.itemId === '999999');
  assert.ok(unregistered);
  assert.strictEqual(unregistered.packageId, 'dtrpg/999999');

  // 2. Fetch filtered to registered Kryptotome publisher packages only
  const filtered = await bridge.fetchPurchasedPackages(true);
  assert.strictEqual(filtered.length, 1);
  assert.strictEqual(filtered[0].itemId, '450231');
});

test('DriveThruRpgBridge: deriveCredential creates valid W3C VC v2.0 bound to holder commitment locally', async () => {
  let fetchCallCount = 0;
  const mockFetch = async () => {
    fetchCallCount++;
    return { ok: true, status: 200, json: async () => ({}) };
  };

  const bridge = new DriveThruRpgBridge({ fetchFn: mockFetch });

  const record = {
    platform: 'drivethrurpg',
    orderId: 'ord-dtrpg-554433',
    itemId: '450231',
    title: 'Dragonbane Core Set',
    purchasedAt: '2026-08-20T10:00:00Z',
    packageId: 'free-league/dragonbane-core-set',
    publisherId: 'did:key:z6MkqB3p87vFf9778899aabbccddeeff00112233445566778899',
    publisherName: 'Free League Publishing',
    publisherPublicKey: '0123456789fedcba0123456789fedcba0123456789fedcba0123456789fedcba',
    contentDigest: 'sha256:abc123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    scope: ['compendium', 'rules', 'adventures'],
  };

  const holderCommitment = 'poseidon:commitment:userKeySecret99';
  const initialFetchCount = fetchCallCount;

  // Derivation happens 100% locally in client memory
  const cred = await bridge.deriveCredential(record, holderCommitment);

  // Assert NO external network requests were made during credential derivation
  assert.strictEqual(fetchCallCount, initialFetchCount);

  // Validate strict W3C VC v2.0 compliance using SDK validator
  const compliance = validateW3cCompliance(cred);
  assert.strictEqual(compliance.valid, true, `W3C Errors: ${compliance.errors.join(', ')}`);
  assert.strictEqual(compliance.errors.length, 0);

  // Verify structure & commitment binding
  assert.strictEqual(cred['@context'][0], 'https://www.w3.org/ns/credentials/v2');
  assert.strictEqual(cred.id, 'urn:kryptotome:cred:dtrpg:ord-dtrpg-554433');
  assert.ok(cred.type.includes('VerifiableCredential'));
  assert.ok(cred.type.includes('KryptotomeEntitlementCredential'));
  assert.strictEqual(cred.issuer.id, 'did:key:z6MkqB3p87vFf9778899aabbccddeeff00112233445566778899');
  assert.strictEqual(cred.credentialSubject.holderCommitment, holderCommitment);
  assert.strictEqual(cred.credentialSubject.entitlements[0].packageId, 'free-league/dragonbane-core-set');
  assert.strictEqual(cred.proof.proofPurpose, 'assertionMethod');

  // Verify derived credential integrates into KryptotomeVault and generates proof
  const vault = new KryptotomeVault();
  vault.importCredential(cred);

  const found = vault.findCredentialForPackage('free-league/dragonbane-core-set');
  assert.ok(found);
  assert.strictEqual(found.id, cred.id);

  const challenge = {
    nonce: 'dtrpg-challenge-nonce-456',
    packageId: 'free-league/dragonbane-core-set',
    timestamp: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  };
  const proof = await vault.generateProof(challenge);
  assert.strictEqual(proof.publicInputs.packageId, 'free-league/dragonbane-core-set');
  assert.strictEqual(proof.publicInputs.contentDigest, record.contentDigest);
});

test('DriveThruRpgBridge: deriveCredential rejects missing holder commitment', async () => {
  const bridge = new DriveThruRpgBridge();
  const record = {
    platform: 'drivethrurpg',
    orderId: '123',
    itemId: '456',
    title: 'Game Book',
    purchasedAt: '2026-08-01T00:00:00Z',
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
