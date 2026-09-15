import type { KryptotomeCredential } from '@kryptotome/sdk';
import type { MerchantBridge, MerchantPurchaseRecord } from './types.js';

export interface ItchAuthConfig {
  accessToken: string;
}

export class ItchIoBridge implements MerchantBridge {
  public platformName = 'itch.io';
  private accessToken: string | null = null;

  public async authenticate(credentials: Record<string, string>): Promise<boolean> {
    if (!credentials.accessToken) {
      throw new Error('itch.io API token required');
    }
    this.accessToken = credentials.accessToken;
    // Client-side call to https://itch.io/api/1/key/me
    return true;
  }

  public async fetchPurchasedPackages(): Promise<MerchantPurchaseRecord[]> {
    if (!this.accessToken) {
      throw new Error('Not authenticated with itch.io');
    }
    // Placeholder returning empty records for scaffold
    return [];
  }

  public async deriveCredential(
    record: MerchantPurchaseRecord,
    holderCommitment: string
  ): Promise<KryptotomeCredential> {
    const now = new Date().toISOString();
    return {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://kryptotome.org/schemas/v1/context.jsonld',
      ],
      id: `urn:kryptotome:cred:itch:${record.orderId}`,
      type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
      issuer: {
        id: 'did:kryptotome:bridge:itch',
        name: 'itch.io Local Bridge',
        publicKey: 'bridge_pubkey_placeholder',
      },
      validFrom: now,
      credentialSubject: {
        id: 'did:key:holder',
        holderCommitment,
        entitlements: [
          {
            packageId: `itch/${record.itemId}`,
            contentDigest: 'sha256:placeholder',
            scope: ['compendium', 'rules'],
          },
        ],
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: now,
        verificationMethod: 'did:kryptotome:bridge:itch#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'bridge_signature_placeholder',
      },
    };
  }
}
