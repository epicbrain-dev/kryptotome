import { EmbeddedVerifier, TableSessionManager } from '@kryptotome/sdk';
import type { SessionAttestation, ZkProof } from '@kryptotome/sdk';

export interface VttAdapterConfig {
  gameSystemId: string;
  isGameMaster: boolean;
  activeSessionId: string;
  localPeerId: string;
}

export class FoundryVttAdapter {
  private verifier: EmbeddedVerifier;
  private sessionManager: TableSessionManager | null = null;
  private config: VttAdapterConfig;

  constructor(config: VttAdapterConfig) {
    this.config = config;
    this.verifier = new EmbeddedVerifier();
  }

  /**
   * GM unlocks compendium module locally by validating ZK proof
   */
  public async unlockCompendiumModule(
    packageId: string,
    publisherPublicKeyHex: string,
    proof: ZkProof,
    expectedDigest?: string
  ): Promise<boolean> {
    const challenge = this.verifier.createChallenge(packageId);
    const verified = await this.verifier.verifyZkProof(challenge, proof, {
      publisherPublicKeyHex,
      expectedDigest,
    });

    if (verified && this.config.isGameMaster) {
      // Initialize table session sharing for connected peers
      this.sessionManager = new TableSessionManager({
        sessionId: this.config.activeSessionId,
        hostPeerId: this.config.localPeerId,
        packageId,
        contentDigest: proof.publicInputs.contentDigest,
      });
    }

    return verified;
  }

  /**
   * For GM: Authorize a player connected to the game table
   */
  public authorizePlayerPeer(peerId: string): SessionAttestation {
    if (!this.sessionManager) {
      throw new Error('No active table session initialized');
    }
    return this.sessionManager.issuePeerToken(peerId);
  }

  /**
   * For Player: Mount compendium mechanics using GM's ephemeral session token
   */
  public mountSessionToken(token: SessionAttestation): boolean {
    if (new Date(token.expiresAt) < new Date()) {
      throw new Error('Received table session token has expired');
    }
    // Mount plaintext compendium rules into client runtime
    return true;
  }
}
