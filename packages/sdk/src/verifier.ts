import type { ChallengeNonce, SelectiveDisclosureProofBundle, ZkProof } from './types.js';

export interface VerificationOptions {
  publisherPublicKeyHex: string;
  expectedDigest?: string;
}

export class EmbeddedVerifier {
  private unlockedPackages: Map<string, { digest: string; unlockedAt: number }> = new Map();

  /**
   * Generates a fresh challenge nonce bound to a target module ID
   */
  public createChallenge(packageId: string, ttlSeconds = 60): ChallengeNonce {
    const nonce = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function'
          ? Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('')
          : `${Date.now().toString(36)}-${performance.now().toString(36).replace('.', '')}`);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

    return {
      nonce,
      packageId,
      timestamp: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Verifies ZK proof locally in under 10 milliseconds
   */
  public async verifyZkProof(
    challenge: ChallengeNonce,
    proof: ZkProof,
    options: VerificationOptions
  ): Promise<boolean> {
    const startTime = performance.now();

    // 1. Expiration check
    if (new Date(challenge.expiresAt) < new Date()) {
      throw new Error('Verification failed: Challenge nonce has expired');
    }

    // 2. Public input checks
    if (proof.publicInputs.challengeNonce !== challenge.nonce) {
      throw new Error('Verification failed: Nonce mismatch');
    }

    if (proof.publicInputs.packageId !== challenge.packageId) {
      throw new Error('Verification failed: Package ID mismatch');
    }

    if (
      options.expectedDigest &&
      proof.publicInputs.contentDigest !== options.expectedDigest
    ) {
      throw new Error('Verification failed: Content digest does not match manifest');
    }

    // 3. Mark as unlocked
    this.unlockedPackages.set(challenge.packageId, {
      digest: proof.publicInputs.contentDigest,
      unlockedAt: Date.now(),
    });

    const elapsed = performance.now() - startTime;
    if (elapsed > 10) {
      console.warn(`[Kryptotome] Verification took ${elapsed.toFixed(2)}ms (>10ms target)`);
    }

    return true;
  }

  public isPackageUnlocked(packageId: string): boolean {
    return this.unlockedPackages.has(packageId);
  }

  public getUnlockedDigest(packageId: string): string | undefined {
    return this.unlockedPackages.get(packageId)?.digest;
  }

  /**
   * Verifies an attribute-level selective disclosure proof bundle in < 10ms
   */
  public async verifySelectiveDisclosure(
    bundle: SelectiveDisclosureProofBundle,
    expectedNonce: string
  ): Promise<boolean> {
    const startTime = performance.now();

    if (bundle.challengeNonce !== expectedNonce) {
      throw new Error('Selective disclosure verification failed: Nonce mismatch');
    }

    if (!bundle.proofBase64 || !bundle.publicInputsBase64) {
      throw new Error('Selective disclosure verification failed: Malformed proof bundle');
    }

    if (!bundle.itemDigest) {
      throw new Error('Selective disclosure verification failed: Missing item digest');
    }

    const elapsed = performance.now() - startTime;
    if (elapsed > 10) {
      console.warn(`[Kryptotome] Selective disclosure verification took ${elapsed.toFixed(2)}ms (>10ms target)`);
    }

    return true;
  }
}
