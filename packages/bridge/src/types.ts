import type { KryptotomeCredential } from '@kryptotome/sdk';

export interface MerchantPurchaseRecord {
  platform: 'itch.io' | 'drivethrurpg' | 'offline' | 'airgap';
  orderId: string;
  itemId: string;
  title: string;
  purchasedAt: string;
  packageId?: string;
  publisherId?: string;
  publisherName?: string;
  publisherPublicKey?: string;
  contentDigest?: string;
  scope?: string[];
  rawMetadata?: Record<string, unknown>;
}

export interface InvoiceEntitlement {
  packageId: string;
  contentDigest: string;
  scope: string[];
  title?: string;
}

export interface SignedDigitalInvoice {
  version: '1.0.0';
  invoiceId: string;
  issuer: {
    id: string;
    name: string;
    publicKeyHex: string;
  };
  issuedAt: string;
  expiresAt?: string;
  orderReference?: {
    merchant?: string;
    orderNumber?: string;
    customerReference?: string;
  };
  entitlements: InvoiceEntitlement[];
  signature: {
    algorithm: 'Ed25519';
    signatureHex: string;
  };
}

export interface QrFrame {
  index: number;
  total: number;
  payload: string;
  checksum: string;
}

export interface QrExportOptions {
  maxChunkSize?: number;
  prefix?: string;
}

export interface PublisherTitleMapping {
  platform: 'itch.io' | 'drivethrurpg' | 'offline' | 'airgap';
  platformItemId: string;
  packageId: string;
  publisherId: string;
  publisherName?: string;
  publisherPublicKey?: string;
  contentDigest: string;
  defaultScope?: string[];
  title?: string;
}

export interface PublisherRegistry {
  register(mapping: PublisherTitleMapping): void;
  findMapping(
    platform: 'itch.io' | 'drivethrurpg' | 'offline' | 'airgap',
    itemId: string,
    title?: string
  ): PublisherTitleMapping | undefined;
  listMappings(): PublisherTitleMapping[];
}

export class InMemoryPublisherRegistry implements PublisherRegistry {
  private mappings: Map<string, PublisherTitleMapping> = new Map();

  constructor(initialMappings?: PublisherTitleMapping[]) {
    if (initialMappings) {
      for (const m of initialMappings) {
        this.register(m);
      }
    }
  }

  public register(mapping: PublisherTitleMapping): void {
    const key = `${mapping.platform}:${mapping.platformItemId}`;
    this.mappings.set(key, mapping);
  }

  public findMapping(
    platform: 'itch.io' | 'drivethrurpg' | 'offline' | 'airgap',
    itemId: string,
    title?: string
  ): PublisherTitleMapping | undefined {
    const directKey = `${platform}:${itemId}`;
    const direct = this.mappings.get(directKey);
    if (direct) {
      return direct;
    }

    if (title) {
      for (const mapping of this.mappings.values()) {
        if (
          mapping.platform === platform &&
          mapping.title &&
          mapping.title.toLowerCase() === title.toLowerCase()
        ) {
          return mapping;
        }
      }
    }

    return undefined;
  }

  public listMappings(): PublisherTitleMapping[] {
    return Array.from(this.mappings.values());
  }
}

export interface CredentialDerivationOptions {
  subjectId?: string;
  validUntil?: string;
  scope?: string[];
  issuerId?: string;
  issuerName?: string;
  issuerPublicKey?: string;
  signingKeyHex?: string;
}

export interface MerchantBridge {
  platformName: string;
  authenticate(credentials: Record<string, string>): Promise<boolean>;
  fetchPurchasedPackages(filterToRegistered?: boolean): Promise<MerchantPurchaseRecord[]>;
  deriveCredential(
    record: MerchantPurchaseRecord,
    holderCommitment: string,
    options?: CredentialDerivationOptions
  ): Promise<KryptotomeCredential>;
}
