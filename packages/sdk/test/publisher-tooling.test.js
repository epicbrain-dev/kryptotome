import test from 'node:test';
import assert from 'node:assert';
import {
  parseBackerCsv,
  generateBatchFulfillment,
  verifyClaimVoucher,
  generateScratchCode,
  generateVoucherBatch,
  formatNfcNdefPayload,
  redeemPhysicalVoucher,
} from '../dist/index.js';

const SAMPLE_KICKSTARTER_CSV = `Backer Number,Backer Name,Email,Reward Tier,Pledge Amount
101,Aria Nightshade,aria@tabletop.guild,Hardcover Collector + All Digital,$85.00
102,Kaelen Moonshadow,kaelen@adventurers.io,Early Bird Digital PDF,$25.00
103,Boran Stonehammer,boran@deepdelvers.net,Merchant Commercial Tier,$250.00
104,Lyra Swiftfoot,lyra@rpgfans.org,Early Bird Digital PDF,$25.00`;

const SAMPLE_BACKERKIT_CSV = `Backer Id,Full Name,Email Address,Pledge Tier,Total Pledged
BK-901,Sylas Vance,sylas@ttrpg.com,Hardcover Collector + All Digital,85
BK-902,Theron Blackwood,theron@eldritch.net,Early Bird Digital PDF,25
BK-903,Elowen Frost,elowen@chronicles.org,Hardcover Collector + All Digital,85`;

const TIER_CONFIGS = [
  {
    tierName: 'Early Bird Digital PDF',
    packageIds: ['pkg-eldritch-vault-5e'],
    contentDigests: { 'pkg-eldritch-vault-5e': 'b3:digest123' },
  },
  {
    tierName: 'Hardcover Collector + All Digital',
    packageIds: ['pkg-eldritch-vault-5e'],
    contentDigests: { 'pkg-eldritch-vault-5e': 'b3:digest123' },
  },
  {
    tierName: 'Merchant Commercial Tier',
    packageIds: ['pkg-eldritch-vault-5e'],
    contentDigests: { 'pkg-eldritch-vault-5e': 'b3:digest123' },
  },
];

const MOCK_PRIVKEY_HEX = '42'.repeat(32);
const MOCK_PUBKEY_HEX = 'aa'.repeat(32);

test('Crowdfunding: parses Kickstarter backer CSV correctly', () => {
  const backers = parseBackerCsv(SAMPLE_KICKSTARTER_CSV, 'kickstarter');
  assert.strictEqual(backers.length, 4);
  assert.strictEqual(backers[0].backerId, '101');
  assert.strictEqual(backers[0].email, 'aria@tabletop.guild');
  assert.strictEqual(backers[0].rewardTier, 'Hardcover Collector + All Digital');
  assert.strictEqual(backers[0].pledgeAmount, 85);
});

test('Crowdfunding: parses BackerKit backer CSV correctly', () => {
  const backers = parseBackerCsv(SAMPLE_BACKERKIT_CSV, 'backerkit');
  assert.strictEqual(backers.length, 3);
  assert.strictEqual(backers[0].backerId, 'BK-901');
  assert.strictEqual(backers[0].name, 'Sylas Vance');
  assert.strictEqual(backers[0].rewardTier, 'Hardcover Collector + All Digital');
  assert.strictEqual(backers[0].pledgeAmount, 85);
});

test('Crowdfunding: batch fulfillment generates credentials and claim vouchers', () => {
  const backers = parseBackerCsv(SAMPLE_KICKSTARTER_CSV, 'kickstarter');
  const report = generateBatchFulfillment(
    backers,
    TIER_CONFIGS,
    'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
    'Grimoire Press Guild',
    MOCK_PRIVKEY_HEX,
    MOCK_PUBKEY_HEX,
    'kickstarter'
  );

  assert.strictEqual(report.totalBackers, 4);
  assert.strictEqual(report.fulfilledCredentialsCount, 4);
  assert.strictEqual(report.vouchers.length, 4);
  assert.strictEqual(report.credentials.length, 4);

  const firstVoucher = report.vouchers[0];
  assert.ok(firstVoucher.voucherId.startsWith('vch-101-'));
  assert.ok(firstVoucher.claimUrl.includes('kryptotome://claim?voucherId='));
  assert.strictEqual(firstVoucher.packageId, 'pkg-eldritch-vault-5e');
  assert.ok(firstVoucher.signatureHex.length > 0);

  // Validate verification of claim voucher
  const isValid = verifyClaimVoucher(firstVoucher, MOCK_PUBKEY_HEX);
  assert.strictEqual(isValid, true);
});

test('Crowdfunding: verifyClaimVoucher rejects expired vouchers', () => {
  const expiredVoucher = {
    voucherId: 'vch-cf-expired',
    backerId: '101',
    packageId: 'pkg-eldritch-vault-5e',
    contentDigest: 'b3:sample',
    activationToken: 'token123',
    claimUrl: 'kryptotome://claim?voucherId=vch-cf-expired',
    publisherPubkeyHex: MOCK_PUBKEY_HEX,
    signatureHex: 'deadbeef',
    issuedAt: '2020-01-01T00:00:00Z',
    expiresAt: '2020-01-02T00:00:00Z', // Expired
  };

  const isValid = verifyClaimVoucher(expiredVoucher);
  assert.strictEqual(isValid, false);
});

test('POD Physical Vouchers: generates scratch-off codes formatted as KRYP-XXXX-YYYY', () => {
  const code = generateScratchCode();
  assert.match(code, /^KRYP-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
});

test('POD Physical Vouchers: generates batch with cryptographic signatures', () => {
  const spec = {
    packageId: 'pkg-eldritch-vault-5e',
    contentDigest: 'b3:digest123',
    quantity: 3,
    format: 'scratch-off',
    validDurationDays: 365,
  };

  const records = generateVoucherBatch(spec, MOCK_PRIVKEY_HEX, MOCK_PUBKEY_HEX);

  assert.strictEqual(records.length, 3);
  for (const rec of records) {
    assert.ok(rec.voucherId.startsWith('vch-pod-'));
    assert.match(rec.code, /^KRYP-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.strictEqual(rec.packageId, 'pkg-eldritch-vault-5e');
    assert.strictEqual(rec.publisherPubkeyHex, MOCK_PUBKEY_HEX);
    assert.ok(rec.signatureHex.length > 0);
  }
});

test('POD Physical Vouchers: formats NDEF NFC tag payload correctly', () => {
  const record = {
    voucherId: 'vch-pod-001',
    code: 'KRYP-ABCD-EFGH',
    packageId: 'pkg-eldritch-vault-5e',
    contentDigest: 'b3:digest123',
    format: 'nfc-tag',
    saltHex: '0123456789abcdef',
    publisherPubkeyHex: MOCK_PUBKEY_HEX,
    signatureHex: 'f0e1d2c3',
    createdAt: new Date().toISOString(),
  };

  const ndef = formatNfcNdefPayload(record);
  assert.ok(ndef.ndefUri.includes('kryptotome://voucher/claim?code=KRYP-ABCD-EFGH'));
  assert.ok(ndef.chipType.includes('NTAG213') || ndef.chipType.includes('NTAG215'));
  assert.strictEqual(ndef.lockable, true);
  assert.ok(ndef.ndefRecordBytes.length > 0);
  // NFC Forum URI Record header: 0xD1, type length 0x01, payload length, type 'U' (0x55)
  assert.strictEqual(ndef.ndefRecordBytes[0], 0xd1);
  assert.strictEqual(ndef.ndefRecordBytes[1], 0x01);
  assert.strictEqual(ndef.ndefRecordBytes[3], 0x55);
});

test('POD Physical Vouchers: redeemPhysicalVoucher executes offline validation', () => {
  const record = {
    voucherId: 'vch-pod-single-use',
    code: 'KRYP-9999-8888',
    packageId: 'pkg-eldritch-vault-5e',
    contentDigest: 'b3:digest123',
    format: 'scratch-off',
    saltHex: '0123456789abcdef',
    publisherPubkeyHex: MOCK_PUBKEY_HEX,
    signatureHex: 'mock_signature_hex',
    createdAt: new Date().toISOString(),
  };

  const res1 = redeemPhysicalVoucher(record, MOCK_PUBKEY_HEX);
  assert.strictEqual(res1.valid, true);
  assert.strictEqual(res1.packageId, 'pkg-eldritch-vault-5e');
  assert.strictEqual(res1.code, 'KRYP-9999-8888');
  assert.ok(res1.redeemedAt.length > 0);

  // Mismatched publisher key should throw
  assert.throws(() => {
    redeemPhysicalVoucher(record, 'different_pubkey');
  }, /Publisher public key mismatch/);
});
