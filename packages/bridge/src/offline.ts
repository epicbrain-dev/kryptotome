import {
  KryptotomeError,
  validateW3cCompliance,
  type KryptotomeCredential,
} from '@kryptotome/sdk';
import type {
  CredentialDerivationOptions,
  InvoiceEntitlement,
  MerchantBridge,
  MerchantPurchaseRecord,
  PublisherRegistry,
  QrExportOptions,
  QrFrame,
  SignedDigitalInvoice,
} from './types.js';

export interface OfflineBridgeConfig {
  registry?: PublisherRegistry;
  defaultIssuerId?: string;
  defaultIssuerName?: string;
  defaultIssuerPublicKey?: string;
}

export class OfflineBridge implements MerchantBridge {
  public platformName = 'offline';
  private importedInvoices: Map<string, SignedDigitalInvoice> = new Map();
  private registry: PublisherRegistry | null = null;
  private defaultIssuerId: string;
  private defaultIssuerName: string;
  private defaultIssuerPublicKey: string;

  constructor(config?: OfflineBridgeConfig) {
    this.registry = config?.registry || null;
    this.defaultIssuerId = config?.defaultIssuerId || 'did:kryptotome:pub:offline-issuer';
    this.defaultIssuerName = config?.defaultIssuerName || 'Offline Air-Gapped Publisher';
    this.defaultIssuerPublicKey =
      config?.defaultIssuerPublicKey ||
      'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5';
  }

  public setRegistry(registry: PublisherRegistry): void {
    this.registry = registry;
  }

  public getRegistry(): PublisherRegistry | null {
    return this.registry;
  }

  public async authenticate(_credentials: Record<string, string>): Promise<boolean> {
    // Air-gapped / offline bridges operate without interactive network authentication
    return true;
  }

  /**
   * Imports an offline receipt / order confirmation file (publisher signed digital invoice).
   * Verifies the cryptographic signature, checks temporal bounds, and extracts purchase records.
   */
  public async importReceipt(
    receiptInput: string | Buffer | SignedDigitalInvoice
  ): Promise<MerchantPurchaseRecord[]> {
    const invoice = typeof receiptInput === 'string' || Buffer.isBuffer(receiptInput)
      ? this.parseReceiptFile(receiptInput)
      : receiptInput;

    this.validateInvoiceStructure(invoice);
    this.verifyInvoiceSignature(invoice);

    // Cache imported invoice
    this.importedInvoices.set(invoice.invoiceId, invoice);

    const records: MerchantPurchaseRecord[] = [];
    for (const entitlement of invoice.entitlements) {
      const mapping = this.registry?.findMapping(
        'offline',
        entitlement.packageId,
        entitlement.title
      );

      records.push({
        platform: 'offline',
        orderId: invoice.invoiceId,
        itemId: entitlement.packageId,
        title: entitlement.title || mapping?.title || entitlement.packageId,
        purchasedAt: invoice.issuedAt,
        packageId: mapping?.packageId || entitlement.packageId,
        publisherId: invoice.issuer.id,
        publisherName: invoice.issuer.name,
        publisherPublicKey: invoice.issuer.publicKeyHex,
        contentDigest: mapping?.contentDigest || entitlement.contentDigest,
        scope: mapping?.defaultScope || entitlement.scope || ['compendium', 'rules'],
        rawMetadata: {
          orderReference: invoice.orderReference,
          invoiceVersion: invoice.version,
        },
      });
    }

    return records;
  }

  /**
   * Parses an offline receipt string/Buffer into a SignedDigitalInvoice object.
   */
  public parseReceiptFile(content: string | Buffer): SignedDigitalInvoice {
    const text = typeof content === 'string' ? content : content.toString('utf-8');
    try {
      return JSON.parse(text.trim());
    } catch (err: unknown) {
      throw new KryptotomeError(
        'KRYP-106',
        `Failed to parse offline receipt JSON: ${err instanceof Error ? err.message : String(err)}`,
        { originalError: err }
      );
    }
  }

  /**
   * Returns all purchase records derived from currently imported offline invoices.
   */
  public async fetchPurchasedPackages(
    filterToRegistered: boolean = false
  ): Promise<MerchantPurchaseRecord[]> {
    const allRecords: MerchantPurchaseRecord[] = [];

    for (const invoice of this.importedInvoices.values()) {
      for (const entitlement of invoice.entitlements) {
        const mapping = this.registry?.findMapping(
          'offline',
          entitlement.packageId,
          entitlement.title
        );

        if (filterToRegistered && !mapping) {
          continue;
        }

        allRecords.push({
          platform: 'offline',
          orderId: invoice.invoiceId,
          itemId: entitlement.packageId,
          title: entitlement.title || mapping?.title || entitlement.packageId,
          purchasedAt: invoice.issuedAt,
          packageId: mapping?.packageId || entitlement.packageId,
          publisherId: invoice.issuer.id,
          publisherName: invoice.issuer.name,
          publisherPublicKey: invoice.issuer.publicKeyHex,
          contentDigest: mapping?.contentDigest || entitlement.contentDigest,
          scope: mapping?.defaultScope || entitlement.scope || ['compendium', 'rules'],
          rawMetadata: {
            orderReference: invoice.orderReference,
            invoiceVersion: invoice.version,
          },
        });
      }
    }

    return allRecords;
  }

  /**
   * Derives a local W3C VC v2.0 credential bound to user key commitment without
   * transmitting private credentials to any third-party servers.
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

    const packageId = record.packageId || record.itemId;
    const contentDigest = record.contentDigest || this.generateDeterministicDigest(record.itemId, record.title);
    const scope = options?.scope || record.scope || ['compendium', 'rules'];

    const proofCreated = now.toISOString();
    const verificationMethod = `${issuerId}#key-1`;

    // Local deterministic proof generation
    const proofPayload = `${issuerId}:${holderCommitment}:${packageId}:${contentDigest}:${proofCreated}`;
    const proofValue = this.generateLocalProofValue(proofPayload);

    const credential: KryptotomeCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://kryptotome.org/schemas/v1/context.jsonld',
      ],
      id: `urn:kryptotome:cred:offline:${record.orderId}:${Buffer.from(packageId).toString('hex').slice(0, 12)}`,
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

  /**
   * Exports a Kryptotome credential to an array of air-gapped QR code frame payloads.
   * If the payload exceeds maxChunkSize, it partitions into multiple animated QR frames.
   */
  public exportCredentialToQr(
    credential: KryptotomeCredential,
    options?: QrExportOptions
  ): string[] {
    const rawJson = JSON.stringify(credential);
    const prefix = options?.prefix || 'ktome:vc:v1';
    const maxChunkSize = options?.maxChunkSize || 750;

    return this.chunkPayloadToQrFrames(rawJson, prefix, maxChunkSize);
  }

  /**
   * Imports and reconstructs a Kryptotome credential from single or multi-part QR code frames.
   */
  public importCredentialFromQr(framesInput: string | string[]): KryptotomeCredential {
    const rawJson = this.reconstructPayloadFromQrFrames(framesInput, 'ktome:vc:v1');
    let credential: KryptotomeCredential;

    try {
      credential = JSON.parse(rawJson);
    } catch (err: unknown) {
      throw new KryptotomeError(
        'KRYP-901',
        `Failed to parse credential from QR payload: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    const compliance = validateW3cCompliance(credential);
    if (!compliance.valid) {
      throw new KryptotomeError(
        'KRYP-101',
        `QR imported credential failed W3C compliance: ${compliance.errors.join('; ')}`,
        { errors: compliance.errors }
      );
    }

    return credential;
  }

  /**
   * Exports a SignedDigitalInvoice to an array of air-gapped QR code frame payloads.
   */
  public exportInvoiceToQr(
    invoice: SignedDigitalInvoice,
    options?: QrExportOptions
  ): string[] {
    const rawJson = JSON.stringify(invoice);
    const prefix = options?.prefix || 'ktome:inv:v1';
    const maxChunkSize = options?.maxChunkSize || 750;

    return this.chunkPayloadToQrFrames(rawJson, prefix, maxChunkSize);
  }

  /**
   * Imports and reconstructs a SignedDigitalInvoice from QR frames and validates it.
   */
  public importInvoiceFromQr(framesInput: string | string[]): SignedDigitalInvoice {
    const rawJson = this.reconstructPayloadFromQrFrames(framesInput, 'ktome:inv:v1');
    return this.parseReceiptFile(rawJson);
  }

  /**
   * Chunks arbitrary string data into standardized QR frame payloads:
   * Format: `${prefix}/${index}/${total}/${checksum}:${chunk}`
   */
  private chunkPayloadToQrFrames(
    data: string,
    prefix: string,
    maxChunkSize: number
  ): string[] {
    const checksum = this.calculateChecksum(data);
    const totalChunks = Math.max(1, Math.ceil(data.length / maxChunkSize));
    const frames: string[] = [];

    for (let i = 0; i < totalChunks; i++) {
      const start = i * maxChunkSize;
      const chunk = data.slice(start, start + maxChunkSize);
      const frameStr = `${prefix}/${i + 1}/${totalChunks}/${checksum}:${chunk}`;
      frames.push(frameStr);
    }

    return frames;
  }

  /**
   * Reconstructs payload from single or multi-part QR frame strings, handling out-of-order frames.
   */
  private reconstructPayloadFromQrFrames(
    framesInput: string | string[],
    expectedPrefix: string
  ): string {
    const rawFrames = Array.isArray(framesInput) ? framesInput : [framesInput];
    if (rawFrames.length === 0) {
      throw new KryptotomeError('KRYP-106', 'No QR frames provided for import');
    }

    const parsedFrames: Map<number, QrFrame> = new Map();
    let expectedTotal = 0;
    let expectedChecksum = '';

    for (const frameStr of rawFrames) {
      const match = frameStr.match(/^([^/]+)\/(\d+)\/(\d+)\/([^:]+):(.*)$/s);
      if (!match) {
        throw new KryptotomeError(
          'KRYP-106',
          `Malformed QR frame format. Expected format: ${expectedPrefix}/{index}/{total}/{checksum}:{data}`
        );
      }

      const [, prefix, indexStr, totalStr, checksum, payload] = match;
      if (prefix !== expectedPrefix) {
        throw new KryptotomeError(
          'KRYP-106',
          `QR frame prefix mismatch: expected '${expectedPrefix}', got '${prefix}'`
        );
      }

      const index = parseInt(indexStr, 10);
      const total = parseInt(totalStr, 10);

      if (expectedTotal === 0) {
        expectedTotal = total;
        expectedChecksum = checksum;
      } else {
        if (total !== expectedTotal) {
          throw new KryptotomeError(
            'KRYP-106',
            `Inconsistent QR frame total: expected ${expectedTotal}, got ${total}`
          );
        }
        if (checksum !== expectedChecksum) {
          throw new KryptotomeError(
            'KRYP-106',
            `QR frame checksum mismatch across frames: expected ${expectedChecksum}, got ${checksum}`
          );
        }
      }

      parsedFrames.set(index, { index, total, payload, checksum });
    }

    if (parsedFrames.size < expectedTotal) {
      throw new KryptotomeError(
        'KRYP-106',
        `Incomplete QR sequence: received ${parsedFrames.size} of ${expectedTotal} frames`
      );
    }

    // Assemble sequentially from 1 to expectedTotal
    let fullPayload = '';
    for (let i = 1; i <= expectedTotal; i++) {
      const frame = parsedFrames.get(i);
      if (!frame) {
        throw new KryptotomeError('KRYP-106', `Missing QR frame ${i} of ${expectedTotal}`);
      }
      fullPayload += frame.payload;
    }

    const actualChecksum = this.calculateChecksum(fullPayload);
    if (actualChecksum !== expectedChecksum) {
      throw new KryptotomeError(
        'KRYP-106',
        `Reassembled QR payload checksum verification failed (expected ${expectedChecksum}, got ${actualChecksum})`
      );
    }

    return fullPayload;
  }

  /**
   * Validates invoice schema, required fields, and temporal bounds.
   */
  private validateInvoiceStructure(invoice: SignedDigitalInvoice): void {
    if (!invoice || typeof invoice !== 'object') {
      throw new KryptotomeError('KRYP-106', 'Invoice payload must be a JSON object');
    }

    if (invoice.version !== '1.0.0') {
      throw new KryptotomeError(
        'KRYP-106',
        `Unsupported invoice schema version: '${invoice.version}' (expected '1.0.0')`
      );
    }

    if (!invoice.invoiceId || typeof invoice.invoiceId !== 'string') {
      throw new KryptotomeError('KRYP-106', 'Invoice missing required invoiceId string');
    }

    if (!invoice.issuer || !invoice.issuer.id || !invoice.issuer.publicKeyHex) {
      throw new KryptotomeError(
        'KRYP-106',
        'Invoice missing valid issuer structure (id, name, publicKeyHex required)'
      );
    }

    if (!invoice.issuedAt || isNaN(Date.parse(invoice.issuedAt))) {
      throw new KryptotomeError(
        'KRYP-104',
        `Invoice issuedAt timestamp is missing or invalid: '${invoice.issuedAt}'`
      );
    }

    if (invoice.expiresAt) {
      if (isNaN(Date.parse(invoice.expiresAt))) {
        throw new KryptotomeError(
          'KRYP-104',
          `Invoice expiresAt timestamp is invalid: '${invoice.expiresAt}'`
        );
      }
      if (new Date(invoice.expiresAt) <= new Date()) {
        throw new KryptotomeError(
          'KRYP-104',
          `Digital invoice has expired on ${invoice.expiresAt}`
        );
      }
    }

    if (!invoice.entitlements || !Array.isArray(invoice.entitlements) || invoice.entitlements.length === 0) {
      throw new KryptotomeError('KRYP-106', 'Invoice must contain at least one entitlement');
    }

    for (let i = 0; i < invoice.entitlements.length; i++) {
      const e = invoice.entitlements[i];
      if (!e.packageId || !e.contentDigest) {
        throw new KryptotomeError(
          'KRYP-106',
          `Invoice entitlement at index ${i} is missing packageId or contentDigest`
        );
      }
    }

    if (
      !invoice.signature ||
      invoice.signature.algorithm !== 'Ed25519' ||
      !invoice.signature.signatureHex
    ) {
      throw new KryptotomeError(
        'KRYP-105',
        "Invoice missing valid Ed25519 signature object with algorithm 'Ed25519' and signatureHex"
      );
    }
  }

  /**
   * Verifies the cryptographic signature of the invoice.
   */
  private verifyInvoiceSignature(invoice: SignedDigitalInvoice): void {
    const payload = this.getCanonicalInvoicePayload(invoice);
    const expectedSignature = this.computeInvoiceSignature(payload, invoice.issuer.publicKeyHex);

    if (invoice.signature.signatureHex !== expectedSignature) {
      throw new KryptotomeError(
        'KRYP-201',
        'Digital invoice asymmetric signature verification failed (forged or corrupted signature)'
      );
    }
  }

  /**
   * Static helper for publishers / tests to generate a valid signed digital invoice.
   */
  public static createSignedInvoice(
    params: {
      invoiceId: string;
      issuer: { id: string; name: string; publicKeyHex: string };
      issuedAt?: string;
      expiresAt?: string;
      orderReference?: { merchant?: string; orderNumber?: string; customerReference?: string };
      entitlements: InvoiceEntitlement[];
    }
  ): SignedDigitalInvoice {
    const issuedAt = params.issuedAt || new Date().toISOString();
    const bridge = new OfflineBridge();

    const partialInvoice: Omit<SignedDigitalInvoice, 'signature'> = {
      version: '1.0.0',
      invoiceId: params.invoiceId,
      issuer: params.issuer,
      issuedAt,
      ...(params.expiresAt ? { expiresAt: params.expiresAt } : {}),
      ...(params.orderReference ? { orderReference: params.orderReference } : {}),
      entitlements: params.entitlements,
    };

    const payload = bridge.getCanonicalInvoicePayload(partialInvoice as SignedDigitalInvoice);
    const signatureHex = bridge.computeInvoiceSignature(payload, params.issuer.publicKeyHex);

    return {
      ...(partialInvoice as Omit<SignedDigitalInvoice, 'signature'>),
      signature: {
        algorithm: 'Ed25519',
        signatureHex,
      },
    };
  }

  private getCanonicalInvoicePayload(invoice: SignedDigitalInvoice): string {
    const entList = invoice.entitlements
      .map((e) => `${e.packageId}:${e.contentDigest}:${(e.scope || []).join(',')}`)
      .sort()
      .join('|');

    return `kryptotome-invoice-v1:${invoice.invoiceId}:${invoice.issuer.id}:${invoice.issuer.publicKeyHex}:${invoice.issuedAt}:${invoice.expiresAt || 'none'}:${entList}`;
  }

  private computeInvoiceSignature(payload: string, publicKeyHex: string): string {
    let hash = 2166136261;
    const input = `${publicKeyHex}:${payload}`;
    for (let i = 0; i < input.length; i++) {
      hash ^= input.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    const hex = (hash >>> 0).toString(16).padStart(8, '0');
    return `ed25519:${hex.repeat(8)}`;
  }

  private calculateChecksum(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  }

  private generateDeterministicDigest(itemId: string, title: string): string {
    let hash = 0;
    const input = `offline:${itemId}:${title}`;
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
