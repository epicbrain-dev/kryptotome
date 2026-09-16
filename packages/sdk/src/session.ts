import type {
  MountedCompendiumSession,
  PeerAccessRequest,
  PeerAccessResponse,
  PeerSessionRenewalRequest,
  ScopePolicyConfig,
  SessionAttestation,
  SessionRevocationNotice,
} from './types.js';

export class ScopePolicy {
  public allowedScopes: string[];
  public restrictedScopes: string[];
  public peerOverrides: Map<string, string[]> = new Map();

  constructor(config?: Partial<ScopePolicyConfig>) {
    this.allowedScopes = config?.allowedScopes || [
      'spells',
      'classes',
      'feats',
      'items',
      'character_builder',
      'rules',
      'compendium',
      'actor',
      'read',
    ];
    this.restrictedScopes = config?.restrictedScopes || [
      'gm_notes',
      'monsters',
      'adventures',
      'traps',
      'secrets',
      'admin',
    ];
    if (config?.peerOverrides) {
      for (const [peer, scopes] of Object.entries(config.peerOverrides)) {
        this.peerOverrides.set(peer, scopes);
      }
    }
  }

  public setPeerOverride(peerId: string, scopes: string[]): void {
    this.peerOverrides.set(peerId, scopes);
  }

  public evaluateScopes(peerId: string, requestedScopes?: string[]): string[] {
    const override = this.peerOverrides.get(peerId);
    if (override) {
      return [...override];
    }

    const candidates = requestedScopes && requestedScopes.length > 0
      ? requestedScopes
      : this.allowedScopes;

    const wildcardAllowed = this.allowedScopes.includes('*');

    return candidates.filter((scope) => {
      const isAllowed =
        wildcardAllowed ||
        this.allowedScopes.some((s) => s === scope || scope.startsWith(`${s}:`));
      const isRestricted = this.restrictedScopes.some(
        (s) => s === scope || scope.startsWith(`${s}:`)
      );
      return isAllowed && !isRestricted;
    });
  }
}

export interface TableShareConfig {
  sessionId: string;
  hostPeerId: string;
  packageId: string;
  contentDigest: string;
  defaultScopes?: string[];
  sessionDurationMinutes?: number;
  scopePolicy?: ScopePolicy;
}

export class TableSessionManager {
  private config: TableShareConfig;
  private peerTokens: Map<string, SessionAttestation> = new Map();
  private revokedPeers: Map<string, SessionRevocationNotice> = new Map();
  private scopePolicy: ScopePolicy;

  constructor(config: TableShareConfig) {
    this.config = config;
    this.scopePolicy = config.scopePolicy || new ScopePolicy();
  }

  public getScopePolicy(): ScopePolicy {
    return this.scopePolicy;
  }

  public setScopePolicy(policy: ScopePolicy): void {
    this.scopePolicy = policy;
  }

  public isPeerRevoked(recipientPeerId: string, packageId: string): boolean {
    if (this.revokedPeers.has('*')) return true;
    if (this.revokedPeers.has(recipientPeerId)) return true;
    return this.revokedPeers.has(`${recipientPeerId}:${packageId}`);
  }

  public revokePeer(
    recipientPeerId: string,
    packageId?: string,
    reason: string = 'Revoked by host'
  ): SessionRevocationNotice {
    const key = packageId ? `${recipientPeerId}:${packageId}` : recipientPeerId;
    const now = new Date().toISOString();

    const notice: SessionRevocationNotice = {
      sessionId: this.config.sessionId,
      hostPeerId: this.config.hostPeerId,
      recipientPeerId,
      packageId,
      revokedAt: now,
      reason,
      signatureHex: 'mock_revocation_signature_hex',
    };

    this.revokedPeers.set(key, notice);
    return notice;
  }

  /**
   * Generates ephemeral table-sharing session token for a connected table player
   */
  public issuePeerToken(recipientPeerId: string, customScopes?: string[]): SessionAttestation {
    const now = new Date();
    const durationMin = this.config.sessionDurationMinutes || 240; // 4 hour default game session
    const expiresAt = new Date(now.getTime() + durationMin * 60 * 1000);

    const evaluatedScopes = this.scopePolicy.evaluateScopes(
      recipientPeerId,
      customScopes || this.config.defaultScopes
    );

    const attestation: SessionAttestation = {
      sessionId: this.config.sessionId,
      hostPeerId: this.config.hostPeerId,
      recipientPeerId,
      packageId: this.config.packageId,
      contentDigest: this.config.contentDigest,
      permittedScopes: evaluatedScopes,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      signatureHex: 'mock_signature_hex_for_scaffolding',
    };

    this.peerTokens.set(recipientPeerId, attestation);
    return attestation;
  }

  /**
   * Handshake Step 2 & 3: Host verifies entitlement and issues signed response with short expiry
   */
  public handleAccessRequest(
    request: PeerAccessRequest,
    isEntitled: boolean = true,
    customScopes?: string[]
  ): PeerAccessResponse {
    if (this.isPeerRevoked(request.recipientPeerId, request.packageId)) {
      throw new Error(
        `[KRYP-703] Peer '${request.recipientPeerId}' has been revoked from accessing table session`
      );
    }

    if (!isEntitled || request.packageId !== this.config.packageId) {
      throw new Error(
        `[KRYP-603] Host has no local entitlement for requested package '${request.packageId}'`
      );
    }

    const attestation = this.issuePeerToken(request.recipientPeerId, customScopes);

    return {
      attestation,
      hostPublicKeyHex: this.config.hostPeerId,
      nonce: request.nonce,
    };
  }

  /**
   * Handles peer renewal request, extending validity if peer remains authorized
   */
  public handleRenewalRequest(
    request: PeerSessionRenewalRequest,
    durationMinutes?: number
  ): PeerAccessResponse {
    if (request.sessionId !== this.config.sessionId) {
      throw new Error(
        `[KRYP-704] Renewal session ID '${request.sessionId}' does not match host session '${this.config.sessionId}'`
      );
    }

    if (this.isPeerRevoked(request.recipientPeerId, request.packageId)) {
      throw new Error(
        `[KRYP-703] Cannot renew session: peer '${request.recipientPeerId}' has been revoked`
      );
    }

    const now = new Date();
    const duration = durationMinutes || this.config.sessionDurationMinutes || 240;
    const expiresAt = new Date(now.getTime() + duration * 60 * 1000);

    const prior = this.peerTokens.get(request.recipientPeerId);
    const updatedScopes = this.scopePolicy.evaluateScopes(
      request.recipientPeerId,
      prior ? prior.permittedScopes : undefined
    );

    const attestation: SessionAttestation = {
      sessionId: this.config.sessionId,
      hostPeerId: this.config.hostPeerId,
      recipientPeerId: request.recipientPeerId,
      packageId: request.packageId,
      contentDigest: this.config.contentDigest,
      permittedScopes: updatedScopes,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      signatureHex: 'mock_signature_hex_for_renewal',
    };

    this.peerTokens.set(request.recipientPeerId, attestation);

    return {
      attestation,
      hostPublicKeyHex: this.config.hostPeerId,
      nonce: request.renewalNonce,
    };
  }

  public validatePeerToken(token: SessionAttestation): boolean {
    if (new Date(token.expiresAt) < new Date()) {
      return false;
    }
    if (token.sessionId !== this.config.sessionId) {
      return false;
    }
    return true;
  }
}

/**
 * Client-side session manager running on player devices.
 * Initiates handshake requests, manages in-memory mounted compendiums, renewal, and dynamic scope filtering.
 */
export class PeerSessionClient {
  private peerId: string;
  private mountedSessions: Map<string, MountedCompendiumSession> = new Map();
  private pendingRequests: Map<string, PeerAccessRequest> = new Map();
  private pendingRenewals: Map<string, PeerSessionRenewalRequest> = new Map();
  private lastSignatures: Map<string, string> = new Map();

  constructor(peerId: string) {
    this.peerId = peerId;
  }

  public getPeerId(): string {
    return this.peerId;
  }

  /**
   * Step 1: Peer requests module access by generating a challenge nonce and request payload
   */
  public createAccessRequest(packageId: string): PeerAccessRequest {
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    const request: PeerAccessRequest = {
      recipientPeerId: this.peerId,
      packageId,
      nonce,
      timestamp: new Date().toISOString(),
    };

    this.pendingRequests.set(packageId, request);
    return request;
  }

  /**
   * Step 4: Peer receives host response, validates host signature and bounds,
   * then mounts compendium into client memory.
   */
  public processHandshakeResponse(
    response: PeerAccessResponse,
    expectedHostPubKeyHex?: string
  ): MountedCompendiumSession {
    const { attestation, hostPublicKeyHex, nonce } = response;

    // 1. Recipient check
    if (attestation.recipientPeerId !== this.peerId) {
      throw new Error(
        `[KRYP-703] Recipient peer ID mismatch: expected ${this.peerId}, got ${attestation.recipientPeerId}`
      );
    }

    // 2. Nonce replay / mismatch check
    const pending = this.pendingRequests.get(attestation.packageId);
    if (pending && pending.nonce !== nonce) {
      throw new Error(
        `[KRYP-402] Response nonce '${nonce}' does not match pending request nonce '${pending.nonce}'`
      );
    }

    // 3. Expected host check
    if (expectedHostPubKeyHex && hostPublicKeyHex !== expectedHostPubKeyHex) {
      throw new Error(
        `[KRYP-204] Host public key '${hostPublicKeyHex}' does not match expected key '${expectedHostPubKeyHex}'`
      );
    }

    // 4. Expiration check
    if (new Date(attestation.expiresAt) <= new Date()) {
      throw new Error(`[KRYP-701] Received table session token has expired`);
    }

    // 5. Mount compendium into client memory
    const mounted: MountedCompendiumSession = {
      packageId: attestation.packageId,
      contentDigest: attestation.contentDigest,
      hostPeerId: hostPublicKeyHex,
      recipientPeerId: attestation.recipientPeerId,
      sessionId: attestation.sessionId,
      permittedScopes: attestation.permittedScopes,
      issuedAt: attestation.issuedAt,
      expiresAt: attestation.expiresAt,
      mountedAt: new Date().toISOString(),
    };

    this.mountedSessions.set(attestation.packageId, mounted);
    this.lastSignatures.set(attestation.packageId, attestation.signatureHex);
    this.pendingRequests.delete(attestation.packageId);

    return mounted;
  }

  /**
   * Creates session renewal request before token expires
   */
  public createRenewalRequest(packageId: string): PeerSessionRenewalRequest {
    const session = this.mountedSessions.get(packageId);
    if (!session) {
      throw new Error(`[KRYP-603] Package '${packageId}' is not mounted in client memory`);
    }

    const renewalNonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    const request: PeerSessionRenewalRequest = {
      sessionId: session.sessionId,
      recipientPeerId: this.peerId,
      packageId,
      renewalNonce,
      currentSignatureHex: this.lastSignatures.get(packageId) || '',
      timestamp: new Date().toISOString(),
    };

    this.pendingRenewals.set(packageId, request);
    return request;
  }

  /**
   * Processes renewal response, extending expiration time in client memory
   */
  public processRenewalResponse(
    response: PeerAccessResponse,
    expectedHostPubKeyHex?: string
  ): MountedCompendiumSession {
    const { attestation, hostPublicKeyHex, nonce } = response;

    if (attestation.recipientPeerId !== this.peerId) {
      throw new Error(`[KRYP-703] Renewal recipient does not match local peer`);
    }

    const pending = this.pendingRenewals.get(attestation.packageId);
    if (pending && pending.renewalNonce !== nonce) {
      throw new Error(`[KRYP-402] Renewal response nonce mismatch`);
    }

    if (expectedHostPubKeyHex && hostPublicKeyHex !== expectedHostPubKeyHex) {
      throw new Error(`[KRYP-204] Host public key mismatch`);
    }

    const mounted: MountedCompendiumSession = {
      packageId: attestation.packageId,
      contentDigest: attestation.contentDigest,
      hostPeerId: hostPublicKeyHex,
      recipientPeerId: attestation.recipientPeerId,
      sessionId: attestation.sessionId,
      permittedScopes: attestation.permittedScopes,
      issuedAt: attestation.issuedAt,
      expiresAt: attestation.expiresAt,
      mountedAt: new Date().toISOString(),
    };

    this.mountedSessions.set(attestation.packageId, mounted);
    this.lastSignatures.set(attestation.packageId, attestation.signatureHex);
    this.pendingRenewals.delete(attestation.packageId);

    return mounted;
  }

  /**
   * Processes signed revocation notice and unmounts/purges compendium from client memory
   */
  public processRevocationNotice(
    notice: SessionRevocationNotice,
    expectedHostPubKeyHex?: string
  ): number {
    if (expectedHostPubKeyHex && notice.hostPeerId !== expectedHostPubKeyHex) {
      throw new Error(`[KRYP-204] Revocation notice host public key mismatch`);
    }

    if (notice.recipientPeerId !== this.peerId && notice.recipientPeerId !== '*') {
      return 0;
    }

    if (notice.packageId && notice.packageId !== '*') {
      const removed = this.unmountPackage(notice.packageId);
      this.lastSignatures.delete(notice.packageId);
      this.pendingRequests.delete(notice.packageId);
      this.pendingRenewals.delete(notice.packageId);
      return removed ? 1 : 0;
    }

    const count = this.mountedSessions.size;
    this.mountedSessions.clear();
    this.lastSignatures.clear();
    this.pendingRequests.clear();
    this.pendingRenewals.clear();
    return count;
  }

  /**
   * Disconnects from table session and cleanly purges all mounted memory
   */
  public disconnectAndPurge(): number {
    const count = this.mountedSessions.size;
    this.mountedSessions.clear();
    this.lastSignatures.clear();
    this.pendingRequests.clear();
    this.pendingRenewals.clear();
    return count;
  }

  /**
   * Dynamic scope check: determines whether a scope is allowed
   */
  public allowsScope(packageId: string, scope: string): boolean {
    const session = this.getMountedSession(packageId);
    if (!session) return false;
    if (session.permittedScopes.includes('*')) return true;
    return session.permittedScopes.some((s) => s === scope || scope.startsWith(`${s}:`));
  }

  /**
   * Resolves scope category from asset path and checks access
   */
  public allowsAssetPath(packageId: string, assetPath: string): boolean {
    const category = this.categoryFromAssetPath(assetPath);
    return this.allowsScope(packageId, category);
  }

  /**
   * Checks access to asset path, throwing KRYP-703 if restricted
   */
  public checkAssetAccess(packageId: string, assetPath: string): void {
    if (!this.isPackageMounted(packageId)) {
      throw new Error(`[KRYP-701] Package '${packageId}' is not mounted in active session`);
    }
    if (!this.allowsAssetPath(packageId, assetPath)) {
      const category = this.categoryFromAssetPath(assetPath);
      throw new Error(
        `[KRYP-703] Access denied to asset '${assetPath}': scope '${category}' is restricted for peer '${this.peerId}'`
      );
    }
  }

  /**
   * Filters asset paths list to only permitted items
   */
  public filterAccessibleAssets(packageId: string, assetPaths: string[]): string[] {
    return assetPaths.filter((path) => this.allowsAssetPath(packageId, path));
  }

  private categoryFromAssetPath(assetPath: string): string {
    const normalized = assetPath.replace(/\\/g, '/').replace(/^\//, '');
    const slashIdx = normalized.indexOf('/');
    if (slashIdx !== -1) {
      return normalized.substring(0, slashIdx);
    }
    const dotIdx = normalized.indexOf('.');
    if (dotIdx !== -1) {
      return normalized.substring(0, dotIdx);
    }
    return normalized;
  }

  /**
   * Checks if a package is currently mounted and active in memory
   */
  public isPackageMounted(packageId: string): boolean {
    const session = this.mountedSessions.get(packageId);
    if (!session) return false;
    return new Date(session.expiresAt) > new Date();
  }

  /**
   * Retrieves active mounted session from memory
   */
  public getMountedSession(packageId: string): MountedCompendiumSession | undefined {
    const session = this.mountedSessions.get(packageId);
    if (!session) return undefined;
    if (new Date(session.expiresAt) <= new Date()) {
      this.mountedSessions.delete(packageId);
      return undefined;
    }
    return session;
  }

  /**
   * Returns list of currently mounted package IDs
   */
  public mountedPackageIds(): string[] {
    return Array.from(this.mountedSessions.keys()).filter((pkg) => this.isPackageMounted(pkg));
  }

  /**
   * Unmounts a compendium package from client memory
   */
  public unmountPackage(packageId: string): boolean {
    return this.mountedSessions.delete(packageId);
  }

  /**
   * Unmounts all packages from client memory
   */
  public unmountAll(): number {
    const count = this.mountedSessions.size;
    this.mountedSessions.clear();
    return count;
  }
}
