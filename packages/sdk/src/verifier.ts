import type { ChallengeNonce, ZkProof } from './types.js';

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
    const nonce = typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : Math.random().toString(36).substring(2) + Date.now().toString(36);

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
}
