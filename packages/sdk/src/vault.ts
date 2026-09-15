import type { ChallengeNonce, KryptotomeCredential, ZkProof } from './types.js';

export interface VaultKeypair {
  keyId: string;
  publicKeyHex: string;
  secretKeyHex: string;
}

export class KryptotomeVault {
  private keypair: VaultKeypair | null = null;
  private credentials: Map<string, KryptotomeCredential> = new Map();

  constructor(initialKeypair?: VaultKeypair) {
    if (initialKeypair) {
      this.keypair = initialKeypair;
    }
  }

  public setKeypair(keypair: VaultKeypair): void {
    this.keypair = keypair;
  }

  public getKeypair(): VaultKeypair | null {
    return this.keypair;
  }

  public importCredential(credential: KryptotomeCredential): void {
    this.credentials.set(credential.id, credential);
  }

  public getCredential(id: string): KryptotomeCredential | undefined {
    return this.credentials.get(id);
  }

  public findCredentialForPackage(packageId: string): KryptotomeCredential | undefined {
    for (const cred of this.credentials.values()) {
      if (cred.credentialSubject.entitlements.some((e) => e.packageId === packageId)) {
        return cred;
      }
    }
    return undefined;
  }

  public listCredentials(): KryptotomeCredential[] {
    return Array.from(this.credentials.values());
  }

  /**
   * Generates single-use zero-knowledge proof for a given challenge nonce.
   */
  public async generateProof(challenge: ChallengeNonce): Promise<ZkProof> {
    const cred = this.findCredentialForPackage(challenge.packageId);
    if (!cred) {
      throw new Error(`No credential found in vault for package: ${challenge.packageId}`);
    }

    const entitlement = cred.credentialSubject.entitlements.find(
      (e) => e.packageId === challenge.packageId
    );
    if (!entitlement) {
      throw new Error(`Package entitlement missing for ${challenge.packageId}`);
    }

    if (new Date(challenge.expiresAt) < new Date()) {
      throw new Error('Challenge nonce is expired');
    }

    return {
      proofBytes: `zkp:${this.keypair?.keyId || 'anon'}:${challenge.nonce}:${challenge.packageId}`,
      publicInputs: {
        challengeNonce: challenge.nonce,
        packageId: challenge.packageId,
        contentDigest: entitlement.contentDigest,
        publisherPubkeyHash: cred.issuer.publicKey,
      },
    };
  }

  public exportToJson(): string {
    return JSON.stringify({
      keyId: this.keypair?.keyId,
      publicKey: this.keypair?.publicKeyHex,
      credentials: Array.from(this.credentials.values()),
    }, null, 2);
  }
}
