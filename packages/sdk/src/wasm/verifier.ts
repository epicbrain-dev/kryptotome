import { WasmVerifier } from './kryptotome_wasm.js';
import type { ChallengeNonce, EntitlementProofBundle, ZkProof } from '../types.js';
import { KryptotomeError } from '../error.js';
import { getWasmModule } from './loader.js';

/**
 * High-level typed verification engine powered by the compiled WebAssembly verifier.
 * Manages the in-memory entitlement cache, proof verification, and cache invalidation rules.
 */
export class WasmVerificationEngine {
  private raw: WasmVerifier;
  private isDisposed = false;

  constructor() {
    // Ensure WebAssembly module is initialized
    getWasmModule();
    this.raw = new WasmVerifier();
  }

  /**
   * Verifies a zero-knowledge entitlement proof against a single-use challenge nonce
   * and publisher verification key.
   */
  public verifyZkProof(
    publisherVkHex: string,
    challenge: ChallengeNonce,
    proof: ZkProof
  ): boolean {
    this.assertNotDisposed();

    if (new Date(challenge.expiresAt).getTime() < Date.now()) {
      throw new KryptotomeError('KRYP-401', 'Challenge nonce has expired');
    }

    try {
      const challengeJson = JSON.stringify(challenge);
      const proofJson = JSON.stringify(proof);
      return this.raw.verifyZkProof(publisherVkHex, challengeJson, proofJson);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('KRYP-401') || message.includes('expired')) {
        throw new KryptotomeError('KRYP-401', message, err);
      }
      if (
        message.includes('KRYP-302') ||
        message.includes('mismatch') ||
        message.includes('does not match')
      ) {
        throw new KryptotomeError('KRYP-302', message, err);
      }
      if (
        message.includes('KRYP-303') ||
        message.includes('deserialize') ||
        message.includes('Malformed')
      ) {
        throw new KryptotomeError('KRYP-303', message, err);
      }
      if (message.includes('KRYP-403')) {
        throw new KryptotomeError('KRYP-403', message, err);
      }
      throw new KryptotomeError(
        'KRYP-301',
        `Zero-knowledge proof verification failed: ${message}`,
        err
      );
    }
  }

  /**
   * Verifies a self-contained entitlement proof presentation bundle against a challenge nonce.
   */
  public verifyProofBundle(
    bundle: EntitlementProofBundle,
    challenge: ChallengeNonce
  ): boolean {
    this.assertNotDisposed();

    if (new Date(challenge.expiresAt).getTime() < Date.now()) {
      throw new KryptotomeError('KRYP-401', 'Challenge nonce has expired');
    }

    if (bundle.challengeNonce !== challenge.nonce) {
      throw new KryptotomeError(
        'KRYP-302',
        `Bundle challenge nonce "${bundle.challengeNonce}" does not match challenge "${challenge.nonce}"`
      );
    }

    try {
      const bundleJson = JSON.stringify(bundle);
      const challengeJson = JSON.stringify(challenge);
      return this.raw.verifyProofBundle(bundleJson, challengeJson);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('KRYP-401') || message.includes('expired')) {
        throw new KryptotomeError('KRYP-401', message, err);
      }
      if (
        message.includes('KRYP-302') ||
        message.includes('mismatch') ||
        message.includes('does not match')
      ) {
        throw new KryptotomeError('KRYP-302', message, err);
      }
      if (
        message.includes('KRYP-303') ||
        message.includes('deserialize') ||
        message.includes('Malformed')
      ) {
        throw new KryptotomeError('KRYP-303', message, err);
      }
      throw new KryptotomeError(
        'KRYP-301',
        `Entitlement proof bundle verification failed: ${message}`,
        err
      );
    }
  }


  /**
   * Checks if a compendium or module package is currently unlocked in the session cache.
   */
  public isPackageUnlocked(packageId: string): boolean {
    this.assertNotDisposed();
    return this.raw.isPackageUnlocked(packageId);
  }

  /**
   * Invalidates a package from the local cache.
   */
  public invalidatePackage(packageId: string): boolean {
    this.assertNotDisposed();
    return this.raw.invalidatePackage(packageId);
  }

  /**
   * Invalidates a package when its underlying assets are reloaded.
   */
  public reloadPackage(packageId: string): boolean {
    this.assertNotDisposed();
    return this.raw.reloadPackage(packageId);
  }

  /**
   * Invalidates cached entitlement if the package's content digest differs from the expected digest.
   */
  public invalidateIfDigestMismatch(packageId: string, currentDigest: string): boolean {
    this.assertNotDisposed();
    return this.raw.invalidateIfDigestMismatch(packageId, currentDigest);
  }

  /**
   * Exits the current active game session and purges all unlocked compendiums from the cache.
   * Returns the count of purged entitlements.
   */
  public exitSession(): number {
    this.assertNotDisposed();
    return this.raw.exitSession();
  }

  /**
   * Prunes all expired entitlements from the local cache.
   * Returns the count of removed entitlements.
   */
  public pruneExpired(): number {
    this.assertNotDisposed();
    return this.raw.pruneExpired();
  }

  /**
   * Sets the default cache TTL in seconds.
   */
  public setCacheTtlSeconds(seconds: number | bigint): void {
    this.assertNotDisposed();
    this.raw.setCacheTtlSeconds(BigInt(seconds));
  }

  /**
   * Frees WebAssembly heap allocations associated with this verifier instance.
   */
  public dispose(): void {
    if (!this.isDisposed) {
      this.raw.free();
      this.isDisposed = true;
    }
  }

  public [Symbol.dispose](): void {
    this.dispose();
  }

  private assertNotDisposed(): void {
    if (this.isDisposed) {
      throw new KryptotomeError(
        'KRYP-903',
        'WasmVerificationEngine instance has been disposed and cannot be used.'
      );
    }
  }
}
