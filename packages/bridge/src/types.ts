import type { KryptotomeCredential } from '@kryptotome/sdk';

export interface MerchantPurchaseRecord {
  platform: 'itch.io' | 'drivethrurpg';
  orderId: string;
  itemId: string;
  title: string;
  purchasedAt: string;
}

export interface MerchantBridge {
  platformName: string;
  authenticate(credentials: Record<string, string>): Promise<boolean>;
  fetchPurchasedPackages(): Promise<MerchantPurchaseRecord[]>;
  deriveCredential(
    record: MerchantPurchaseRecord,
    holderCommitment: string
  ): Promise<KryptotomeCredential>;
}
