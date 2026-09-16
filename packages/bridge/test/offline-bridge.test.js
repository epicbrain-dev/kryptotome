import test from 'node:test';
import assert from 'node:assert';
import { OfflineBridge } from '../dist/offline.js';
import { validateW3cCompliance, KryptotomeVault } from '@kryptotome/sdk';

test('OfflineBridge: importReceipt imports valid signed invoice and parses entitlements', async () => {
  const bridge = new OfflineBridge();

  const invoice = OfflineBridge.createSignedInvoice({
    invoiceId: 'inv-2026-9901',
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKeyHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
    issuedAt: '2026-09-01T00:00:00Z',
    orderReference: {
      merchant: 'GenCon Direct Booth',
      orderNumber: 'GC-2026-888',
    },
    entitlements: [
      {
        packageId: 'paizo/pathfinder-gm-core',
        contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
        scope: ['compendium', 'rules'],
        title: 'Pathfinder GM Core',
      },
    ],
  });

  const records = await bridge.importReceipt(invoice);
  assert.strictEqual(records.length, 1);
  assert.strictEqual(records[0].platform, 'offline');
  assert.strictEqual(records[0].orderId, 'inv-2026-9901');
  assert.strictEqual(records[0].packageId, 'paizo/pathfinder-gm-core');
  assert.strictEqual(records[0].title, 'Pathfinder GM Core');
  assert.strictEqual(records[0].publisherId, 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH');

  const fetched = await bridge.fetchPurchasedPackages();
  assert.strictEqual(fetched.length, 1);
  assert.strictEqual(fetched[0].packageId, 'paizo/pathfinder-gm-core');
});

test('OfflineBridge: importReceipt accepts JSON string or Buffer', async () => {
  const bridge = new OfflineBridge();

  const invoice = OfflineBridge.createSignedInvoice({
    invoiceId: 'inv-buffer-1',
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKeyHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
    entitlements: [
      {
        packageId: 'paizo/pathfinder-player-core',
        contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
        scope: ['compendium'],
      },
    ],
  });

  const buffer = Buffer.from(JSON.stringify(invoice), 'utf-8');
  const records = await bridge.importReceipt(buffer);
  assert.strictEqual(records.length, 1);
  assert.strictEqual(records[0].orderId, 'inv-buffer-1');
});

test('OfflineBridge: rejects tampered or forged invoice signatures with KRYP-201', async () => {
  const bridge = new OfflineBridge();

  const invoice = OfflineBridge.createSignedInvoice({
    invoiceId: 'inv-legit',
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKeyHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
    entitlements: [
      {
        packageId: 'paizo/pathfinder-gm-core',
        contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
        scope: ['compendium'],
      },
    ],
  });

  // Tamper with entitlement data
  invoice.entitlements[0].packageId = 'paizo/hacked-unauthorized-package';

  await assert.rejects(
    async () => {
      await bridge.importReceipt(invoice);
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-201');
      assert.ok(err.message.includes('signature verification failed'));
      return true;
    }
  );
});

test('OfflineBridge: rejects expired invoices with KRYP-104', async () => {
  const bridge = new OfflineBridge();

  const invoice = OfflineBridge.createSignedInvoice({
    invoiceId: 'inv-expired',
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKeyHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
    issuedAt: '2025-01-01T00:00:00Z',
    expiresAt: '2025-06-01T00:00:00Z', // In the past
    entitlements: [
      {
        packageId: 'paizo/demo-pack',
        contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
        scope: ['compendium'],
      },
    ],
  });

  await assert.rejects(
    async () => {
      await bridge.importReceipt(invoice);
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-104');
      assert.ok(err.message.includes('expired'));
      return true;
    }
  );
});

test('OfflineBridge: deriveCredential creates valid W3C VC v2.0 bound to holder commitment locally', async () => {
  const bridge = new OfflineBridge();

  const invoice = OfflineBridge.createSignedInvoice({
    invoiceId: 'inv-offline-vc-1',
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKeyHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
    entitlements: [
      {
        packageId: 'paizo/pathfinder-player-core',
        contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
        scope: ['compendium', 'rules'],
      },
    ],
  });

  const records = await bridge.importReceipt(invoice);
  const record = records[0];
  const holderCommitment = 'pedersen:commitment:airgapUserSecret77';

  const cred = await bridge.deriveCredential(record, holderCommitment);

  // W3C VC v2.0 Compliance verification
  const compliance = validateW3cCompliance(cred);
  assert.strictEqual(compliance.valid, true, `W3C Errors: ${compliance.errors.join(', ')}`);
  assert.strictEqual(cred.credentialSubject.holderCommitment, holderCommitment);
  assert.strictEqual(cred.credentialSubject.entitlements[0].packageId, 'paizo/pathfinder-player-core');
  assert.strictEqual(cred.issuer.id, 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH');

  // Verify vault import and proof generation
  const vault = new KryptotomeVault();
  vault.importCredential(cred);
  const challenge = {
    nonce: 'airgap-challenge-nonce-1',
    packageId: 'paizo/pathfinder-player-core',
    timestamp: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  };
  const proof = await vault.generateProof(challenge);
  assert.strictEqual(proof.publicInputs.packageId, 'paizo/pathfinder-player-core');
});

test('OfflineBridge: Air-gapped QR code export and import single-frame round-trip', async () => {
  const bridge = new OfflineBridge();

  const cred = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://kryptotome.org/schemas/v1/context.jsonld',
    ],
    id: 'urn:kryptotome:cred:offline:qr-test-1',
    type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKey: '0123456789abcdef',
    },
    validFrom: '2026-09-01T00:00:00Z',
    credentialSubject: {
      id: 'did:key:holder',
      holderCommitment: 'pedersen:commitment:qr123',
      entitlements: [
        {
          packageId: 'paizo/pathfinder-core',
          contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
          scope: ['compendium'],
        },
      ],
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-09-01T00:00:00Z',
      verificationMethod: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'z3hWbT6sampleproof',
    },
  };

  const frames = bridge.exportCredentialToQr(cred, { maxChunkSize: 2000 });
  assert.strictEqual(frames.length, 1);
  assert.ok(frames[0].startsWith('ktome:vc:v1/1/1/'));

  const imported = bridge.importCredentialFromQr(frames[0]);
  assert.strictEqual(imported.id, cred.id);
  assert.strictEqual(imported.credentialSubject.holderCommitment, cred.credentialSubject.holderCommitment);
});

test('OfflineBridge: Air-gapped QR code multi-frame chunked export and out-of-order reassembly', async () => {
  const bridge = new OfflineBridge();

  const cred = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://kryptotome.org/schemas/v1/context.jsonld',
    ],
    id: 'urn:kryptotome:cred:offline:chunked-test',
    type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKey: '0123456789abcdef',
    },
    validFrom: '2026-09-01T00:00:00Z',
    credentialSubject: {
      id: 'did:key:holder',
      holderCommitment: 'pedersen:commitment:longsecretchunktest'.repeat(5),
      entitlements: [
        {
          packageId: 'paizo/pathfinder-remaster-player-core',
          contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
          scope: ['compendium', 'rules', 'spells', 'classes'],
        },
      ],
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-09-01T00:00:00Z',
      verificationMethod: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'z3hWbT6sampleproof'.repeat(3),
    },
  };

  // Chunk with small chunk size to force multiple animated QR frames
  const frames = bridge.exportCredentialToQr(cred, { maxChunkSize: 150 });
  assert.ok(frames.length > 3);

  // Reassemble frames out of order (simulating asynchronous camera scanning)
  const shuffled = [...frames].reverse();
  const imported = bridge.importCredentialFromQr(shuffled);

  assert.strictEqual(imported.id, cred.id);
  assert.strictEqual(imported.credentialSubject.holderCommitment, cred.credentialSubject.holderCommitment);
});

test('OfflineBridge: Air-gapped QR code detects frame corruption and checksum mismatch', async () => {
  const bridge = new OfflineBridge();

  const cred = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://kryptotome.org/schemas/v1/context.jsonld',
    ],
    id: 'urn:kryptotome:cred:offline:corruption-test',
    type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKey: '0123456789abcdef',
    },
    validFrom: '2026-09-01T00:00:00Z',
    credentialSubject: {
      id: 'did:key:holder',
      holderCommitment: 'pedersen:commitment:corrupttest',
      entitlements: [
        {
          packageId: 'paizo/pathfinder-core',
          contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
          scope: ['compendium'],
        },
      ],
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-09-01T00:00:00Z',
      verificationMethod: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'z3hWbT6sampleproof',
    },
  };

  const frames = bridge.exportCredentialToQr(cred, { maxChunkSize: 150 });
  // Corrupt one frame's data
  frames[0] = frames[0] + 'CORRUPTED';

  assert.throws(
    () => {
      bridge.importCredentialFromQr(frames);
    },
    (err) => {
      assert.strictEqual(err.code, 'KRYP-106');
      assert.ok(err.message.includes('checksum verification failed'));
      return true;
    }
  );
});

test('OfflineBridge: Air-gapped QR code export and import for invoices', async () => {
  const bridge = new OfflineBridge();

  const invoice = OfflineBridge.createSignedInvoice({
    invoiceId: 'inv-qr-inv-1',
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKeyHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
    entitlements: [
      {
        packageId: 'paizo/pathfinder-player-core',
        contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
        scope: ['compendium'],
      },
    ],
  });

  const frames = bridge.exportInvoiceToQr(invoice, { maxChunkSize: 200 });
  assert.ok(frames.length > 1);

  const imported = bridge.importInvoiceFromQr(frames);
  assert.strictEqual(imported.invoiceId, invoice.invoiceId);
  assert.strictEqual(imported.signature.signatureHex, invoice.signature.signatureHex);
});
