import type { SessionAttestation } from './types.js';

export interface TableShareConfig {
  sessionId: string;
  hostPeerId: string;
  packageId: string;
  contentDigest: string;
  defaultScopes?: string[];
  sessionDurationMinutes?: number;
}

export class TableSessionManager {
  private config: TableShareConfig;
  private peerTokens: Map<string, SessionAttestation> = new Map();

  constructor(config: TableShareConfig) {
    this.config = config;
  }

  /**
   * Generates ephemeral table-sharing session token for a connected table player
   */
  public issuePeerToken(recipientPeerId: string, customScopes?: string[]): SessionAttestation {
    const now = new Date();
    const durationMin = this.config.sessionDurationMinutes || 240; // 4 hour default game session
    const expiresAt = new Date(now.getTime() + durationMin * 60 * 1000);

    const attestation: SessionAttestation = {
      sessionId: this.config.sessionId,
      hostPeerId: this.config.hostPeerId,
      recipientPeerId,
      packageId: this.config.packageId,
      contentDigest: this.config.contentDigest,
      permittedScopes: customScopes || this.config.defaultScopes || ['read', 'character_builder'],
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      signatureHex: 'mock_signature_hex_for_scaffolding',
    };

    this.peerTokens.set(recipientPeerId, attestation);
    return attestation;
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
