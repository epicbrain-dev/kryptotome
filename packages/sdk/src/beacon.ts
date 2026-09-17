/**
 * Kryptotome Protocol: Air-Gapped Table Beacon Client & Manager
 * Enables offline, battery-powered local Wi-Fi / BLE tabletop sessions without Internet.
 */

export interface TableBeaconConfig {
  sessionId: string;
  tableName: string;
  advertisedService: string;
  campaignPackageIds: string[];
}

export interface TableBeaconState {
  isActive: boolean;
  sessionId: string;
  tableName: string;
  advertisedService: string;
  connectedPeers: string[];
  startedAt: string;
}

export interface PeerHandshakeRequest {
  peerId: string;
  packageId: string;
  presentationProof: string;
  timestamp: string;
}

export interface PeerHandshakeResponse {
  peerId: string;
  packageId: string;
  accessGranted: boolean;
  ephemeralToken: string;
  latencyMs: number;
}

export class AirGappedTableBeacon {
  private config: TableBeaconConfig;
  private connectedPeers: Set<string> = new Set();
  private isActive: boolean = false;
  private startedAt: string = '';

  constructor(config?: Partial<TableBeaconConfig>) {
    this.config = {
      sessionId: config?.sessionId || `session-table-${Date.now()}`,
      tableName: config?.tableName || 'Friday Night Table',
      advertisedService: config?.advertisedService || '_kryptotome-table._tcp',
      campaignPackageIds: config?.campaignPackageIds || ['paizo/player-core', 'paizo/gm-core'],
    };
  }

  public start(): TableBeaconState {
    this.isActive = true;
    this.startedAt = new Date().toISOString();
    return this.getState();
  }

  public stop(): boolean {
    if (!this.isActive) return false;
    this.isActive = false;
    this.connectedPeers.clear();
    return true;
  }

  public handlePeerHandshake(request: PeerHandshakeRequest): PeerHandshakeResponse {
    const startTime = performance.now();

    if (!this.isActive) {
      throw new Error('Table beacon is currently inactive');
    }

    if (!request.presentationProof.startsWith('zkp:')) {
      throw new Error('Invalid zero-knowledge presentation proof format');
    }

    const isEntitled = this.config.campaignPackageIds.includes(request.packageId);
    if (!isEntitled) {
      throw new Error(`Package "${request.packageId}" not entitled in this campaign`);
    }

    this.connectedPeers.add(request.peerId);
    const latencyMs = performance.now() - startTime;

    return {
      peerId: request.peerId,
      packageId: request.packageId,
      accessGranted: true,
      ephemeralToken: `token:${this.config.sessionId}:${request.peerId}:${Date.now()}`,
      latencyMs,
    };
  }

  public getState(): TableBeaconState {
    return {
      isActive: this.isActive,
      sessionId: this.config.sessionId,
      tableName: this.config.tableName,
      advertisedService: this.config.advertisedService,
      connectedPeers: Array.from(this.connectedPeers),
      startedAt: this.startedAt,
    };
  }

  public getConnectedPeerCount(): number {
    return this.connectedPeers.size;
  }
}
