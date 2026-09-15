import test from 'node:test';
import assert from 'node:assert';
import { validateW3cCompliance } from '../dist/validator.js';

function createSampleCredential() {
  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://kryptotome.org/schemas/v1/context.jsonld',
    ],
    id: 'urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6',
    type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
    issuer: {
      id: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      name: 'Paizo Publisher',
      publicKey: '0123456789abcdef',
    },
    validFrom: '2026-09-15T00:00:00Z',
    validUntil: '2027-09-15T00:00:00Z',
    credentialSubject: {
      id: 'did:key:z6MkhvjV2VwKvZ3pZ9N8qV6',
      holderCommitment: 'pedersen:commitment:123456',
      entitlements: [
        {
          packageId: 'paizo/pathfinder-remaster-player-core',
          contentDigest: 'sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f',
          scope: ['compendium', 'character_builder'],
        },
      ],
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-09-15T00:00:00Z',
      verificationMethod: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'z3hWbT6...sample_signature_value',
    },
  };
}

test('W3C VC v2.0: valid credential passes compliance check', () => {
  const cred = createSampleCredential();
  const res = validateW3cCompliance(cred);
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.errors.length, 0);
});

test('W3C VC v2.0: rejects invalid @context order or missing v2 URI', () => {
  const cred = createSampleCredential();
  cred['@context'][0] = 'https://www.w3.org/2018/credentials/v1'; // v1 invalid for v2
  const res = validateW3cCompliance(cred);
  assert.strictEqual(res.valid, false);
  assert.ok(res.errors.some(e => e.includes("First element in @context must be 'https://www.w3.org/ns/credentials/v2'")));
});

test('W3C VC v2.0: rejects missing VerifiableCredential in type', () => {
  const cred = createSampleCredential();
  cred.type = ['KryptotomeEntitlementCredential'];
  const res = validateW3cCompliance(cred);
  assert.strictEqual(res.valid, false);
  assert.ok(res.errors.some(e => e.includes("Credential type must include 'VerifiableCredential'")));
});

test('W3C VC v2.0: rejects invalid date order (validUntil <= validFrom)', () => {
  const cred = createSampleCredential();
  cred.validUntil = '2025-01-01T00:00:00Z'; // before 2026 validFrom
  const res = validateW3cCompliance(cred);
  assert.strictEqual(res.valid, false);
  assert.ok(res.errors.some(e => e.includes('validUntil must be strictly after validFrom')));
});

test('W3C VC v2.0: rejects non-URI issuer or subject ID', () => {
  const cred = createSampleCredential();
  cred.issuer.id = 'not-a-valid-uri';
  cred.credentialSubject.id = 'also-not-a-uri';
  const res = validateW3cCompliance(cred);
  assert.strictEqual(res.valid, false);
  assert.strictEqual(res.errors.length, 2);
});

test('W3C VC v2.0: rejects non-assertionMethod proof purpose', () => {
  const cred = createSampleCredential();
  cred.proof.proofPurpose = 'authentication'; // Invalid purpose for credential assertion
  const res = validateW3cCompliance(cred);
  assert.strictEqual(res.valid, false);
  assert.ok(res.errors.some(e => e.includes("proofPurpose must be 'assertionMethod'")));
});
