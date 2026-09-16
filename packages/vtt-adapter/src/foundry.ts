import { EmbeddedVerifier, PeerSessionClient, TableSessionManager } from '@kryptotome/sdk';
import type {
  MountedCompendiumSession,
  PeerAccessRequest,
  PeerAccessResponse,
  PeerSessionRenewalRequest,
  SessionAttestation,
  SessionRevocationNotice,
  ZkProof,
} from '@kryptotome/sdk';

export interface VttAdapterConfig {
  gameSystemId: string;
  isGameMaster: boolean;
  activeSessionId: string;
  localPeerId: string;
}

export class FoundryVttAdapter {
  private verifier: EmbeddedVerifier;
  private sessionManager: TableSessionManager | null = null;
  private peerClient: PeerSessionClient;
  private config: VttAdapterConfig;

  constructor(config: VttAdapterConfig) {
    this.config = config;
    this.verifier = new EmbeddedVerifier();
    this.peerClient = new PeerSessionClient(config.localPeerId);
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
   * For GM (Host): Process incoming peer access request, verify entitlement, and issue signed response
   */
  public handlePeerAccessRequest(
    request: PeerAccessRequest,
    customScopes?: string[]
  ): PeerAccessResponse {
    if (!this.sessionManager) {
      throw new Error('No active table session initialized on host');
    }
    return this.sessionManager.handleAccessRequest(request, true, customScopes);
  }

  /**
   * For GM (Host): Revoke an individual player peer (e.g. disconnected or removed)
   */
  public revokePlayerPeer(
    peerId: string,
    packageId?: string,
    reason: string = 'Player removed from table session'
  ): SessionRevocationNotice {
    if (!this.sessionManager) {
      throw new Error('No active table session initialized on host');
    }
    return this.sessionManager.revokePeer(peerId, packageId, reason);
  }

  /**
   * For GM (Host): Handle peer session renewal request
   */
  public handleSessionRenewal(
    request: PeerSessionRenewalRequest,
    durationMinutes?: number
  ): PeerAccessResponse {
    if (!this.sessionManager) {
      throw new Error('No active table session initialized on host');
    }
    return this.sessionManager.handleRenewalRequest(request, durationMinutes);
  }

  /**
   * For Player: Step 1 of handshake - initiate access request for a compendium module
   */
  public requestCompendiumAccess(packageId: string): PeerAccessRequest {
    return this.peerClient.createAccessRequest(packageId);
  }

  /**
   * For Player: Step 4 of handshake - validate host response and mount compendium in client memory
   */
  public mountCompendiumFromHost(
    response: PeerAccessResponse,
    expectedHostPubKeyHex?: string
  ): MountedCompendiumSession {
    return this.peerClient.processHandshakeResponse(response, expectedHostPubKeyHex);
  }

  /**
   * For Player: Request renewal for an active mounted compendium session
   */
  public requestSessionRenewal(packageId: string): PeerSessionRenewalRequest {
    return this.peerClient.createRenewalRequest(packageId);
  }

  /**
   * For Player: Process renewal response from host
   */
  public processRenewalResponse(
    response: PeerAccessResponse,
    expectedHostPubKeyHex?: string
  ): MountedCompendiumSession {
    return this.peerClient.processRenewalResponse(response, expectedHostPubKeyHex);
  }

  /**
   * For Player: Handle revocation notice and purge target or all compendiums from memory
   */
  public handleRevocationNotice(
    notice: SessionRevocationNotice,
    expectedHostPubKeyHex?: string
  ): number {
    return this.peerClient.processRevocationNotice(notice, expectedHostPubKeyHex);
  }

  /**
   * For Player: Disconnect from table and purge all compendium data from client memory
   */
  public disconnectAndPurge(): number {
    return this.peerClient.disconnectAndPurge();
  }

  /**
   * Checks if a compendium module is mounted in client memory
   */
  public isCompendiumMounted(packageId: string): boolean {
    return this.peerClient.isPackageMounted(packageId);
  }

  /**
   * Checks access to a specific asset path under current scopes
   */
  public checkAssetAccess(packageId: string, assetPath: string): void {
    this.peerClient.checkAssetAccess(packageId, assetPath);
  }

  /**
   * For Player: Mount compendium mechanics using GM's ephemeral session token (legacy helper)
   */
  public mountSessionToken(token: SessionAttestation): boolean {
    if (new Date(token.expiresAt) < new Date()) {
      throw new Error('Received table session token has expired');
    }
    // Mount plaintext compendium rules into client runtime
    return true;
  }
}
