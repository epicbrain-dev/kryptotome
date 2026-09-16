import {
  EmbeddedVerifier,
  KryptotomeError,
  PeerSessionClient,
  TableSessionManager,
} from '@kryptotome/sdk';
import type {
  ChallengeNonce,
  MountedCompendiumSession,
  PeerAccessRequest,
  PeerAccessResponse,
  PeerSessionRenewalRequest,
  SessionAttestation,
  SessionRevocationNotice,
  ZkProof,
} from '@kryptotome/sdk';
import { VttSocketDispatcher, type VttSocketTransport } from './socket.js';
import {
  renderCompendiumLockOverlay,
  renderTableSharingStatusBadge,
  renderUnlockAnimationCss,
  renderUnlockModalHtml,
  type TableSharingBadgeState,
  type UnlockModalOptions,
} from './ui.js';

export interface VttAdapterConfig {
  gameSystemId: string;
  isGameMaster: boolean;
  activeSessionId: string;
  localPeerId: string;
}

export interface CompendiumCollectionLike {
  metadata: { id: string; package: string; label: string; [key: string]: unknown };
  load(): Promise<any>;
  getData(options?: any): Promise<any>;
  [key: string]: any;
}

export interface CompendiumHookOptions {
  onRequestProof?: (
    packageId: string,
    challengeNonce: string
  ) => Promise<ZkProof | null>;
  onUnlocked?: (packageId: string) => void;
  publisherPublicKeyHex?: string;
  expectedDigest?: string;
}

export class FoundryVttAdapter {
  private verifier: EmbeddedVerifier;
  private sessionManager: TableSessionManager | null = null;
  private peerClient: PeerSessionClient;
  private config: VttAdapterConfig;
  private socketDispatcher: VttSocketDispatcher | null = null;
  private hookedCompendiums: Map<string, CompendiumCollectionLike> = new Map();

  constructor(config: VttAdapterConfig) {
    this.config = config;
    this.verifier = new EmbeddedVerifier();
    this.peerClient = new PeerSessionClient(config.localPeerId);
  }

  public getVerifier(): EmbeddedVerifier {
    return this.verifier;
  }

  public getSessionManager(): TableSessionManager | null {
    return this.sessionManager;
  }

  public getPeerClient(): PeerSessionClient {
    return this.peerClient;
  }

  public getConfig(): VttAdapterConfig {
    return { ...this.config };
  }

  /**
   * Initializes seamless WebRTC / SocketLib dispatch for table sessions.
   */
  public enableSocketLib(socket: VttSocketTransport): VttSocketDispatcher {
    this.socketDispatcher = new VttSocketDispatcher(this, socket, this.config.isGameMaster);
    return this.socketDispatcher;
  }

  public getSocketDispatcher(): VttSocketDispatcher | null {
    return this.socketDispatcher;
  }

  /**
   * GM unlocks compendium module locally by validating ZK proof.
   */
  public async unlockCompendiumModule(
    packageId: string,
    publisherPublicKeyHex: string,
    proof: ZkProof,
    expectedDigest?: string,
    challenge?: ChallengeNonce
  ): Promise<boolean> {
    const targetChallenge =
      challenge ||
      (proof.publicInputs?.challengeNonce
        ? {
            nonce: proof.publicInputs.challengeNonce,
            packageId,
            timestamp: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 60000).toISOString(),
          }
        : this.verifier.createChallenge(packageId));

    const verified = await this.verifier.verifyZkProof(targetChallenge, proof, {
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
   * Intercepts Foundry VTT `CompendiumCollection.load()` and `getData()` calls.
   * Checks if module is unlocked; if locked, triggers challenge prompt before loading plaintext rule assets.
   */
  public hookCompendiumCollection(
    compendium: CompendiumCollectionLike,
    packageId: string,
    options?: CompendiumHookOptions
  ): CompendiumCollectionLike {
    const originalLoad = compendium.load;
    const originalGetData = compendium.getData;
    const self = this;

    compendium.load = async function () {
      if (!self.isPackageUnlocked(packageId)) {
        await self.promptAndUnlock(packageId, options);
      }
      return originalLoad.call(this);
    };

    compendium.getData = async function (opts?: any) {
      if (!self.isPackageUnlocked(packageId)) {
        await self.promptAndUnlock(packageId, options);
      }
      return originalGetData.call(this, opts);
    };

    this.hookedCompendiums.set(packageId, compendium);
    return compendium;
  }

  /**
   * Prompts user for local credential proof and unlocks the compendium pack.
   */
  public async promptAndUnlock(
    packageId: string,
    options?: CompendiumHookOptions
  ): Promise<boolean> {
    const challenge = this.verifier.createChallenge(packageId);

    if (options?.onRequestProof) {
      const proof = await options.onRequestProof(packageId, challenge.nonce);
      if (!proof) {
        throw new KryptotomeError(
          'KRYP-603',
          `Package '${packageId}' is locked: credential proof presentation was cancelled or not provided`
        );
      }

      const verified = await this.unlockCompendiumModule(
        packageId,
        options.publisherPublicKeyHex || 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
        proof,
        options.expectedDigest,
        challenge
      );

      if (!verified) {
        throw new KryptotomeError(
          'KRYP-301',
          `ZK proof verification failed for package '${packageId}'`
        );
      }

      if (options.onUnlocked) {
        options.onUnlocked(packageId);
      }
      return true;
    }

    throw new KryptotomeError(
      'KRYP-603',
      `Compendium package '${packageId}' is locked: no proof resolver registered`
    );
  }

  /**
   * Checks if a package is unlocked locally by verifier (GM) or mounted via peer session (Player).
   */
  public isPackageUnlocked(packageId: string): boolean {
    return (
      this.verifier.isPackageUnlocked(packageId) ||
      this.peerClient.isPackageMounted(packageId)
    );
  }

  /**
   * For GM: Authorize a player connected to the game table
   */
  public authorizePlayerPeer(peerId: string): SessionAttestation {
    if (!this.sessionManager) {
      throw new KryptotomeError('KRYP-704', 'No active table session initialized');
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
      throw new KryptotomeError('KRYP-704', 'No active table session initialized on host');
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
      throw new KryptotomeError('KRYP-704', 'No active table session initialized on host');
    }
    const notice = this.sessionManager.revokePeer(peerId, packageId, reason);

    // If socket dispatcher is active, broadcast revocation notice to peers
    if (this.socketDispatcher) {
      try {
        this.socketDispatcher.broadcastRevocationNotice(notice);
      } catch {
        // Broadcast best-effort
      }
    }

    return notice;
  }

  /**
   * For GM (Host): Handle peer session renewal request
   */
  public handleSessionRenewal(
    request: PeerSessionRenewalRequest,
    durationMinutes?: number
  ): PeerAccessResponse {
    if (!this.sessionManager) {
      throw new KryptotomeError('KRYP-704', 'No active table session initialized on host');
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
   * UI Reference Renderers
   */
  public renderUnlockModal(
    packageId: string,
    challengeNonce: string,
    options?: UnlockModalOptions
  ): string {
    return renderUnlockModalHtml(packageId, challengeNonce, options);
  }

  public renderTableSharingStatus(packageId?: string): string {
    const peerCount = this.sessionManager ? 1 : 0;
    const state: TableSharingBadgeState = {
      isGameMaster: this.config.isGameMaster,
      sessionId: this.config.activeSessionId,
      connectedPeerCount: peerCount,
      packageId,
      allowedScopes: ['spells', 'classes', 'rules', 'compendium'],
    };
    return renderTableSharingStatusBadge(state);
  }

  public renderLockOverlay(packageId: string, title?: string): string {
    return renderCompendiumLockOverlay(packageId, title);
  }

  public renderStyles(): string {
    return renderUnlockAnimationCss();
  }
}
