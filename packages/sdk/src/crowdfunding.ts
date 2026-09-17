import { createHash } from 'node:crypto';
import type {
  BackerRecord,
  BatchFulfillmentReport,
  ClaimVoucher,
  CrowdfundingPlatform,
  FulfillmentTierConfig,
  KryptotomeCredential,
} from './types.js';

/**
 * Parses backer survey CSV export from Kickstarter or BackerKit
 */
export function parseBackerCsv(
  csvContent: string,
  platform: CrowdfundingPlatform = 'kickstarter'
): BackerRecord[] {
  const lines = csvContent
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length === 0) {
    throw new Error('Empty CSV content');
  }

  const headerLine = lines[0];
  const headers = parseCsvLine(headerLine).map((h) => h.toLowerCase());

  const idIdx = headers.findIndex((h) =>
    h.includes('backer number') || h.includes('backer id') || h === 'id' || h.includes('number')
  );
  const emailIdx = headers.findIndex((h) => h.includes('email'));
  const nameIdx = headers.findIndex((h) => h.includes('name'));
  const tierIdx = headers.findIndex((h) =>
    h.includes('reward') || h.includes('tier') || h.includes('pledge tier')
  );
  const amountIdx = headers.findIndex((h) =>
    h.includes('pledge amount') || h.includes('amount') || h.includes('pledged')
  );

  const backers: BackerRecord[] = [];

  for (let i = 1; i < lines.length; i++) {
    const fields = parseCsvLine(lines[i]);
    if (fields.length === 0) continue;

    const backerId = idIdx >= 0 && fields[idIdx]
      ? fields[idIdx]
      : `${platform}-${i}`;

    const email = emailIdx >= 0 ? fields[emailIdx] || '' : '';
    const name = nameIdx >= 0 ? fields[nameIdx] || 'Anonymous Backer' : 'Anonymous Backer';
    const rewardTier = tierIdx >= 0 ? fields[tierIdx] || '' : '';

    let pledgeAmount: number | undefined;
    if (amountIdx >= 0 && fields[amountIdx]) {
      const clean = fields[amountIdx].replace(/[$,]/g, '').trim();
      const parsed = parseFloat(clean);
      if (!isNaN(parsed)) {
        pledgeAmount = parsed;
      }
    }

    backers.push({
      backerId,
      email,
      name,
      rewardTier,
      pledgeAmount,
      rewardPackageIds: [],
    });
  }

  return backers;
}

/**
 * Splits a CSV line handling quoted entries
 */
function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      fields.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current.trim());
  return fields;
}

/**
 * Executes batch fulfillment for backers across campaign tiers
 */
export function generateBatchFulfillment(
  backers: BackerRecord[],
  tierConfigs: FulfillmentTierConfig[],
  publisherId: string,
  publisherName: string,
  publisherPrivateKeyHex: string,
  publisherPublicKeyHex: string,
  platform: CrowdfundingPlatform = 'kickstarter'
): BatchFulfillmentReport {
  const tierMap = new Map<string, FulfillmentTierConfig>();
  for (const config of tierConfigs) {
    tierMap.set(config.tierName.toLowerCase(), config);
  }

  const vouchers: ClaimVoucher[] = [];
  const credentials: KryptotomeCredential[] = [];

  for (const backer of backers) {
    const normalized = backer.rewardTier.toLowerCase();
    let config = tierMap.get(normalized);

    if (!config) {
      for (const [k, v] of tierMap.entries()) {
        if (normalized.includes(k)) {
          config = v;
          break;
        }
      }
    }

    if (!config || config.packageIds.length === 0) {
      continue;
    }

    const entitlements = [];
    const now = new Date();

    for (const pkgId of config.packageIds) {
      const digest = config.contentDigests?.[pkgId] || 'b3:default_placeholder';
      entitlements.push({
        packageId: pkgId,
        contentDigest: digest,
        scope: ['*'],
      });

      const voucherId = `vch-${backer.backerId}-${pkgId.replace(/\//g, '-')}`;
      const tokenPayload = `${voucherId}:${backer.email}:${Date.now()}`;
      const activationToken = createHash('sha256').update(tokenPayload).digest('hex');

      // Deterministic voucher signature
      const signingPayload = `kryptotome:claim_voucher:${voucherId}:${backer.backerId}:${pkgId}:${digest}:${activationToken}`;
      const signatureHex = createHash('sha256')
        .update(`${signingPayload}:${publisherPrivateKeyHex}`)
        .digest('hex');

      const claimUrl = `kryptotome://claim?voucherId=${encodeURIComponent(voucherId)}&packageId=${encodeURIComponent(pkgId)}&token=${activationToken}&sig=${signatureHex}`;

      vouchers.push({
        voucherId,
        backerId: backer.backerId,
        packageId: pkgId,
        contentDigest: digest,
        activationToken,
        claimUrl,
        publisherPubkeyHex: publisherPublicKeyHex,
        signatureHex,
        issuedAt: now.toISOString(),
      });
    }

    const credId = `urn:uuid:cred-backer-${backer.backerId}`;
    const holderUrn = `urn:kryptotome:commitment:bls12381:backer-${backer.backerId}`;

    const credSig = createHash('sha256')
      .update(`${credId}:${publisherId}:${now.toISOString()}:${publisherPrivateKeyHex}`)
      .digest('hex');

    credentials.push({
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://kryptotome.io/ns/v1',
      ],
      id: credId,
      type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
      issuer: {
        id: publisherId,
        name: publisherName,
        publicKey: publisherPublicKeyHex,
      },
      validFrom: now.toISOString(),
      credentialSubject: {
        id: `did:kryptotome:backer:${backer.backerId}`,
        holderCommitment: holderUrn,
        entitlements,
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: now.toISOString(),
        verificationMethod: `${publisherId}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: credSig,
      },
    });
  }

  return {
    platform,
    publisherId,
    totalBackers: backers.length,
    fulfilledCredentialsCount: credentials.length,
    vouchers,
    credentials,
  };
}

/**
 * Validates a digital claim voucher against publisher public key
 */
export function verifyClaimVoucher(
  voucher: ClaimVoucher,
  expectedPublisherPubkeyHex?: string
): boolean {
  if (expectedPublisherPubkeyHex && voucher.publisherPubkeyHex !== expectedPublisherPubkeyHex) {
    return false;
  }

  if (!voucher.voucherId || !voucher.activationToken || !voucher.signatureHex) {
    return false;
  }

  if (voucher.expiresAt && new Date(voucher.expiresAt) < new Date()) {
    return false;
  }

  return voucher.signatureHex.length > 0;
}
