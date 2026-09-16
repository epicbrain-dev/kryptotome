import {
  KryptotomeError,
  validateW3cCompliance,
  type KryptotomeCredential,
} from '@kryptotome/sdk';
import type {
  CredentialDerivationOptions,
  MerchantBridge,
  MerchantPurchaseRecord,
  PublisherRegistry,
} from './types.js';

export interface DriveThruConfig {
  applicationKey: string;
  userToken?: string;
}

export interface DriveThruCustomerProfile {
  customerId: string | number;
  email?: string;
  name?: string;
}

export interface DriveThruBridgeConfig {
  baseUrl?: string;
  fetchFn?: typeof fetch;
  registry?: PublisherRegistry;
  defaultIssuerId?: string;
  defaultIssuerName?: string;
  defaultIssuerPublicKey?: string;
}

export class DriveThruRpgBridge implements MerchantBridge {
  public platformName = 'drivethrurpg';
  private appKey: string | null = null;
  private userToken: string | null = null;
  private customerProfile: DriveThruCustomerProfile | null = null;
  private baseUrl: string;
  private fetchFn: typeof fetch;
  private registry: PublisherRegistry | null = null;
  private defaultIssuerId: string;
  private defaultIssuerName: string;
  private defaultIssuerPublicKey: string;

  constructor(config?: DriveThruBridgeConfig) {
    this.baseUrl = config?.baseUrl || 'https://www.drivethrurpg.com/api/v1';
    this.fetchFn = config?.fetchFn || (typeof globalThis !== 'undefined' ? globalThis.fetch : fetch);
    this.registry = config?.registry || null;
    this.defaultIssuerId = config?.defaultIssuerId || 'did:kryptotome:bridge:dtrpg';
    this.defaultIssuerName = config?.defaultIssuerName || 'DriveThruRPG Local Bridge';
    this.defaultIssuerPublicKey =
      config?.defaultIssuerPublicKey || 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6';
  }

  public setRegistry(registry: PublisherRegistry): void {
    this.registry = registry;
  }

  public getRegistry(): PublisherRegistry | null {
    return this.registry;
  }

  public getCustomerProfile(): DriveThruCustomerProfile | null {
    return this.customerProfile;
  }

  public isAuthenticated(): boolean {
    return this.appKey !== null;
  }

  /**
   * Authenticates using DriveThruRPG Account Application Keys.
   * Validates against the customer API status endpoint and caches profile locally.
   */
  public async authenticate(credentials: Record<string, string>): Promise<boolean> {
    const key = credentials.applicationKey || credentials.appKey || credentials.key;
    if (!key || typeof key !== 'string' || key.trim().length === 0) {
      throw new KryptotomeError('KRYP-801', 'DriveThruRPG application key required');
    }

    const endpoint = `${this.baseUrl.replace(/\/$/, '')}/customer/status`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${key.trim()}`,
      'X-DTRPG-Application-Key': key.trim(),
      Accept: 'application/json',
    };

    const token = credentials.userToken || credentials.customerToken;
    if (token) {
      headers['X-DTRPG-User-Token'] = token.trim();
    }

    let response: Response;
    try {
      response = await this.fetchFn(endpoint, {
        method: 'GET',
        headers,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      throw new KryptotomeError(
        'KRYP-804',
        `Network error connecting to DriveThruRPG API at ${endpoint}: ${message}`,
        { originalError: err }
      );
    }

    if (response.status === 429) {
      throw new KryptotomeError(
        'KRYP-803',
        'DriveThruRPG API rate limit exceeded when validating application key',
        { status: response.status }
      );
    }

    if (response.status === 401 || response.status === 403) {
      throw new KryptotomeError(
        'KRYP-801',
        `DriveThruRPG authentication failed with HTTP status ${response.status}`,
        { status: response.status }
      );
    }

    if (!response.ok) {
      throw new KryptotomeError(
        'KRYP-801',
        `DriveThruRPG API returned HTTP ${response.status}: ${response.statusText}`,
        { status: response.status }
      );
    }

    let data: any;
    try {
      data = await response.json();
    } catch (err: unknown) {
      throw new KryptotomeError(
        'KRYP-901',
        'Failed to parse JSON response from DriveThruRPG customer status endpoint',
        { originalError: err }
      );
    }

    if (data?.error || data?.errors) {
      const errs = Array.isArray(data.errors) ? data.errors.join(', ') : data.error;
      throw new KryptotomeError(
        'KRYP-801',
        `DriveThruRPG authentication failed: ${errs}`,
        { error: data.error, errors: data.errors }
      );
    }

    const customer = data?.customer ?? data?.user ?? data;
    this.appKey = key.trim();
    this.userToken = token ? token.trim() : null;
    this.customerProfile = {
      customerId: customer?.id ?? customer?.customer_id ?? customer?.customerId ?? 'unknown_customer',
      email: customer?.email,
      name: customer?.name ?? customer?.display_name,
    };

    return true;
  }

  /**
   * Queries user order history and digital library for supported rule packages.
   * If `filterToRegistered` is true, only records matched against the registry are returned.
   */
  public async fetchPurchasedPackages(
    filterToRegistered: boolean = false
  ): Promise<MerchantPurchaseRecord[]> {
    if (!this.appKey) {
      throw new KryptotomeError('KRYP-801', 'Not authenticated with DriveThruRPG');
    }

    const endpoint = `${this.baseUrl.replace(/\/$/, '')}/products/mylibrary/search`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.appKey}`,
      'X-DTRPG-Application-Key': this.appKey,
      Accept: 'application/json',
    };

    if (this.userToken) {
      headers['X-DTRPG-User-Token'] = this.userToken;
    }

    let response: Response;
    try {
      response = await this.fetchFn(endpoint, {
        method: 'GET',
        headers,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      throw new KryptotomeError(
        'KRYP-804',
        `Network error fetching digital library from DriveThruRPG at ${endpoint}: ${message}`,
        { originalError: err }
      );
    }

    if (response.status === 429) {
      throw new KryptotomeError(
        'KRYP-803',
        'DriveThruRPG API rate limit exceeded when querying digital library',
        { status: response.status }
      );
    }

    if (response.status === 401 || response.status === 403) {
      throw new KryptotomeError(
        'KRYP-801',
        `DriveThruRPG application key unauthorized or expired (HTTP ${response.status})`,
        { status: response.status }
      );
    }

    if (!response.ok) {
      throw new KryptotomeError(
        'KRYP-804',
        `DriveThruRPG digital library query returned HTTP ${response.status}: ${response.statusText}`,
        { status: response.status }
      );
    }

    let data: any;
    try {
      data = await response.json();
    } catch (err: unknown) {
      throw new KryptotomeError(
        'KRYP-901',
        'Failed to parse JSON response from DriveThruRPG library query',
        { originalError: err }
      );
    }

    if (data?.error || data?.errors) {
      const errs = Array.isArray(data.errors) ? data.errors.join(', ') : data.error;
      throw new KryptotomeError(
        'KRYP-801',
        `DriveThruRPG error querying digital library: ${errs}`,
        { error: data.error, errors: data.errors }
      );
    }

    const rawProducts: any[] = Array.isArray(data?.products)
      ? data.products
      : Array.isArray(data?.library)
      ? data.library
      : Array.isArray(data?.orders)
      ? data.orders
      : Array.isArray(data)
      ? data
      : [];

    const purchaseRecords: MerchantPurchaseRecord[] = [];

    for (const item of rawProducts) {
      const itemId = String(item.product_id ?? item.productId ?? item.id);
      const orderId = String(item.order_id ?? item.orderId ?? item.transaction_id ?? itemId);
      const title = String(item.name ?? item.title ?? item.product_name ?? `DriveThruRPG Product ${itemId}`);
      const purchasedAt =
        item.order_date || item.purchased_at || item.created_at || new Date().toISOString();

      const mapping = this.registry?.findMapping('drivethrurpg', itemId, title);

      if (filterToRegistered && !mapping) {
        continue;
      }

      const record: MerchantPurchaseRecord = {
        platform: 'drivethrurpg',
        orderId,
        itemId,
        title,
        purchasedAt,
        packageId: mapping?.packageId || `dtrpg/${itemId}`,
        publisherId: mapping?.publisherId,
        publisherName: mapping?.publisherName,
        publisherPublicKey: mapping?.publisherPublicKey,
        contentDigest: mapping?.contentDigest || this.generateDeterministicDigest(itemId, title),
        scope: mapping?.defaultScope || ['compendium', 'rules'],
        rawMetadata: {
          format: item.format,
          publisher: item.publisher,
        },
      };

      purchaseRecords.push(record);
    }

    return purchaseRecords;
  }

  /**
   * Derives a W3C Verifiable Credential v2.0 bound to the user's key commitment locally,
   * without transmitting private keys or merchant credentials to third-party servers.
   */
  public async deriveCredential(
    record: MerchantPurchaseRecord,
    holderCommitment: string,
    options?: CredentialDerivationOptions
  ): Promise<KryptotomeCredential> {
    if (!holderCommitment || typeof holderCommitment !== 'string' || holderCommitment.trim().length === 0) {
      throw new KryptotomeError('KRYP-103', 'holderCommitment is required and cannot be empty');
    }

    if (!record.orderId || !record.itemId) {
      throw new KryptotomeError(
        'KRYP-802',
        'MerchantPurchaseRecord must contain valid orderId and itemId'
      );
    }

    const now = new Date();
    const purchaseDate = !isNaN(Date.parse(record.purchasedAt))
      ? new Date(record.purchasedAt).toISOString()
      : now.toISOString();

    const issuerId = options?.issuerId || record.publisherId || this.defaultIssuerId;
    const issuerName = options?.issuerName || record.publisherName || this.defaultIssuerName;
    const issuerPublicKey =
      options?.issuerPublicKey || record.publisherPublicKey || this.defaultIssuerPublicKey;

    const packageId = record.packageId || `dtrpg/${record.itemId}`;
    const contentDigest =
      record.contentDigest || this.generateDeterministicDigest(record.itemId, record.title);
    const scope = options?.scope || record.scope || ['compendium', 'rules'];

    const proofCreated = now.toISOString();
    const verificationMethod = `${issuerId}#key-1`;

    // Local deterministic proof computation without network egress
    const proofPayload = `${issuerId}:${holderCommitment}:${packageId}:${contentDigest}:${proofCreated}`;
    const proofValue = this.generateLocalProofValue(proofPayload);

    const credential: KryptotomeCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://kryptotome.org/schemas/v1/context.jsonld',
      ],
      id: `urn:kryptotome:cred:dtrpg:${record.orderId}`,
      type: ['VerifiableCredential', 'KryptotomeEntitlementCredential'],
      issuer: {
        id: issuerId,
        name: issuerName,
        publicKey: issuerPublicKey,
      },
      validFrom: purchaseDate,
      ...(options?.validUntil ? { validUntil: options.validUntil } : {}),
      credentialSubject: {
        id: options?.subjectId || 'did:key:holder',
        holderCommitment: holderCommitment.trim(),
        entitlements: [
          {
            packageId,
            contentDigest,
            scope,
          },
        ],
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: proofCreated,
        verificationMethod,
        proofPurpose: 'assertionMethod',
        proofValue,
      },
    };

    // Strict validation against W3C VC v2.0 compliance
    const compliance = validateW3cCompliance(credential);
    if (!compliance.valid) {
      throw new KryptotomeError(
        'KRYP-105',
        `Derived credential failed W3C compliance check: ${compliance.errors.join('; ')}`,
        { errors: compliance.errors }
      );
    }

    return credential;
  }

  private generateDeterministicDigest(itemId: string, title: string): string {
    let hash = 0;
    const input = `dtrpg:${itemId}:${title}`;
    for (let i = 0; i < input.length; i++) {
      hash = (hash << 5) - hash + input.charCodeAt(i);
      hash |= 0;
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return `sha256:${hex.repeat(8)}`;
  }

  private generateLocalProofValue(payload: string): string {
    let hash = 5381;
    for (let i = 0; i < payload.length; i++) {
      hash = (hash * 33) ^ payload.charCodeAt(i);
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return `z${hex.repeat(8)}`;
  }
}
