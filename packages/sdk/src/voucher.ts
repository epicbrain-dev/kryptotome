import { createHash, randomBytes } from 'node:crypto';
import type {
  NfcTagPayload,
  PhysicalVoucherBatchSpec,
  PhysicalVoucherRecord,
  VoucherRedemptionResult,
} from './types.js';

/**
 * Generates formatted human-readable scratch-off code (e.g. KRYP-9B4A-7FC1-2E90)
 */
export function generateScratchCode(prefix: string = 'KRYP'): string {
  const bytes = randomBytes(6);
  const hexStr = bytes.toString('hex').toUpperCase();
  return `${prefix}-${hexStr.substring(0, 4)}-${hexStr.substring(4, 8)}`;
}

/**
 * Generates a batch of physical book vouchers (scratch-off / NFC / hybrid)
 */
export function generateVoucherBatch(
  spec: PhysicalVoucherBatchSpec,
  publisherPrivateKeyHex: string,
  publisherPublicKeyHex: string
): PhysicalVoucherRecord[] {
  const vouchers: PhysicalVoucherRecord[] = [];
  const now = new Date();
  const expiresAt = spec.validDurationDays
    ? new Date(now.getTime() + spec.validDurationDays * 86400000).toISOString()
    : undefined;

  for (let i = 0; i < spec.quantity; i++) {
    const voucherId = `vch-pod-${i + 1}-${now.getTime()}`;
    const code = generateScratchCode(spec.codePrefix || 'KRYP');
    const saltHex = randomBytes(16).toString('hex');

    const signingPayload = `kryptotome:physical_voucher:${voucherId}:${code}:${spec.packageId}:${spec.contentDigest}:${saltHex}`;
    const signatureHex = createHash('sha256')
      .update(`${signingPayload}:${publisherPrivateKeyHex}`)
      .digest('hex');

    const nfcNdefUri =
      spec.format === 'nfc-tag' || spec.format === 'hybrid'
        ? `kryptotome://voucher/claim?code=${encodeURIComponent(code)}&pkg=${encodeURIComponent(spec.packageId)}&sig=${signatureHex}`
        : undefined;

    vouchers.push({
      voucherId,
      code,
      packageId: spec.packageId,
      contentDigest: spec.contentDigest,
      format: spec.format,
      saltHex,
      publisherPubkeyHex: publisherPublicKeyHex,
      signatureHex,
      nfcNdefUri,
      createdAt: now.toISOString(),
      expiresAt,
    });
  }

  return vouchers;
}

/**
 * Formats NFC Forum Type 2/4 URI NDEF record bytes
 */
export function formatNfcNdefPayload(voucher: PhysicalVoucherRecord): NfcTagPayload {
  const uri =
    voucher.nfcNdefUri ||
    `kryptotome://voucher/claim?code=${encodeURIComponent(voucher.code)}&pkg=${encodeURIComponent(voucher.packageId)}`;

  const uriBytes = Buffer.from(uri, 'utf8');

  // NDEF Record Layout:
  // [0] Header (0xD1: MB=1, ME=1, CF=0, SR=1, IL=0, TNF=0x01 Well-Known)
  // [1] Type Length (0x01)
  // [2] Payload Length (uriBytes.length + 1)
  // [3] Type ('U' = 0x55)
  // [4] Identifier code (0x00 = No prefix)
  // [5...] URI bytes
  const ndefBytes = Buffer.alloc(5 + uriBytes.length);
  ndefBytes[0] = 0xd1;
  ndefBytes[1] = 0x01;
  ndefBytes[2] = uriBytes.length + 1;
  ndefBytes[3] = 0x55;
  ndefBytes[4] = 0x00;
  uriBytes.copy(ndefBytes, 5);

  const chipType =
    ndefBytes.length <= 144
      ? 'NTAG213 (144 bytes)'
      : ndefBytes.length <= 504
        ? 'NTAG215 (504 bytes)'
        : 'NTAG216 (888 bytes)';

  return {
    ndefUri: uri,
    ndefRecordBytes: new Uint8Array(ndefBytes),
    chipType,
    lockable: true,
  };
}

/**
 * Validates and redeems a physical voucher code offline
 */
export function redeemPhysicalVoucher(
  record: PhysicalVoucherRecord,
  expectedPublisherPubkeyHex?: string
): VoucherRedemptionResult {
  if (expectedPublisherPubkeyHex && record.publisherPubkeyHex !== expectedPublisherPubkeyHex) {
    throw new Error('Publisher public key mismatch');
  }

  if (record.expiresAt && new Date(record.expiresAt) < new Date()) {
    throw new Error('Physical voucher has expired');
  }

  if (!record.code || !record.signatureHex || record.signatureHex.length === 0) {
    throw new Error('Corrupted or invalid voucher record');
  }

  return {
    valid: true,
    code: record.code,
    packageId: record.packageId,
    contentDigest: record.contentDigest,
    publisherPubkeyHex: record.publisherPubkeyHex,
    redeemedAt: new Date().toISOString(),
  };
}
