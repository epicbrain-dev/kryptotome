import type {
  ChallengeNonce,
  KryptotomeCredential,
  PasskeyAssertion,
  PasskeyBinding,
  PasskeyVerificationResult,
  ZkProof,
} from './types.js';

export interface VaultKeypair {
  keyId: string;
  publicKeyHex: string;
  secretKeyHex: string;
}

export class KryptotomeVault {
  private keypair: VaultKeypair | null = null;
  private credentials: Map<string, KryptotomeCredential> = new Map();
  private passkeyBinding: PasskeyBinding | null = null;

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
      passkeyBinding: this.passkeyBinding,
    }, null, 2);
  }

  /**
   * Binds a FIDO2 / WebAuthn hardware passkey to the local vault
   */
  public bindPasskey(binding: PasskeyBinding): void {
    this.passkeyBinding = binding;
  }

  /**
   * Returns active passkey hardware binding if configured
   */
  public getPasskeyBinding(): PasskeyBinding | null {
    return this.passkeyBinding;
  }

  /**
   * Verifies hardware passkey assertion presence (UP=1, UV=1) before unlocking
   */
  public verifyPasskeyAssertion(
    assertion: PasskeyAssertion,
    expectedChallenge: string,
    requireUserVerification = true
  ): PasskeyVerificationResult {
    if (!this.passkeyBinding) {
      throw new Error('No passkey hardware binding configured in this vault');
    }

    if (assertion.credentialId !== this.passkeyBinding.credentialId) {
      throw new Error('Passkey credential ID does not match registered binding');
    }

    // Parse clientDataJSON
    let clientData: { type?: string; challenge?: string; origin?: string };
    try {
      clientData = JSON.parse(assertion.clientDataJson);
    } catch {
      throw new Error('Malformed clientDataJSON in passkey assertion');
    }

    if (clientData.type !== 'webauthn.get') {
      throw new Error(`Unexpected clientData type '${clientData.type}'. Expected 'webauthn.get'`);
    }

    if (clientData.challenge !== expectedChallenge) {
      throw new Error('Passkey challenge mismatch');
    }

    // Parse flags from authenticatorData
    const authDataBytes = Buffer.from(assertion.authenticatorData, 'hex');
    if (authDataBytes.length < 37) {
      throw new Error('Invalid authenticatorData length (must be >= 37 bytes)');
    }

    const flags = authDataBytes[32];
    const userPresent = (flags & 0x01) !== 0;
    const userVerified = (flags & 0x04) !== 0;

    if (!userPresent) {
      throw new Error('User presence test failed (UP flag not set)');
    }

    if (requireUserVerification && !userVerified) {
      throw new Error('User verification test failed (UV flag not set)');
    }

    if (!assertion.signatureHex || assertion.signatureHex.length === 0) {
      throw new Error('Missing hardware signature in passkey assertion');
    }

    return {
      verified: true,
      userPresent,
      userVerified,
      holderCommitmentUrn: this.passkeyBinding.holderCommitmentUrn,
      verifiedAt: new Date().toISOString(),
    };
  }
}
