import test from 'node:test';
import assert from 'node:assert';
import { KryptotomeError, KRYPTOTOME_ERROR_METADATA } from '../dist/error.js';

test('Error Taxonomy: KRYP-100 through KRYP-900 are fully defined', () => {
  const codes = Object.keys(KRYPTOTOME_ERROR_METADATA);
  assert.ok(codes.length >= 30, `Expected at least 30 codes, found ${codes.length}`);

  // Check key series
  assert.ok(codes.includes('KRYP-101'));
  assert.ok(codes.includes('KRYP-201'));
  assert.ok(codes.includes('KRYP-301'));
  assert.ok(codes.includes('KRYP-401'));
  assert.ok(codes.includes('KRYP-501'));
  assert.ok(codes.includes('KRYP-601'));
  assert.ok(codes.includes('KRYP-701'));
  assert.ok(codes.includes('KRYP-801'));
  assert.ok(codes.includes('KRYP-901'));

  // Ensure each entry has category and description
  for (const code of codes) {
    const meta = KRYPTOTOME_ERROR_METADATA[code];
    assert.ok(meta.category && meta.category.length > 0, `Missing category for ${code}`);
    assert.ok(meta.description && meta.description.length > 0, `Missing description for ${code}`);
  }
});

test('Error Taxonomy: KryptotomeError formats correctly', () => {
  const err = new KryptotomeError('KRYP-301', 'Proof pairing check failed', { nonce: 'abc-123' });
  assert.strictEqual(err.code, 'KRYP-301');
  assert.strictEqual(err.category, 'Zero-Knowledge Proofs & Circuits');
  assert.strictEqual(err.message, '[KRYP-301] Proof pairing check failed');
  assert.deepStrictEqual(err.details, { nonce: 'abc-123' });
});
