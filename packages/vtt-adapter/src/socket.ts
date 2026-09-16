import type {
  MountedCompendiumSession,
  PeerAccessRequest,
  PeerAccessResponse,
  PeerSessionRenewalRequest,
  SessionRevocationNotice,
} from '@kryptotome/sdk';
import type { FoundryVttAdapter } from './foundry.js';

export interface VttSocketTransport {
  registerHandler(
    name: string,
    handler: (data: any, senderPeerId?: string) => Promise<any> | any
  ): void;
  executeAsGM(name: string, data: any): Promise<any>;
  executeAsUser?(name: string, userId: string, data: any): Promise<any>;
  broadcast?(event: string, data: any): void;
}

export class VttSocketDispatcher {
  private adapter: FoundryVttAdapter;
  private socket: VttSocketTransport;
  private isGm: boolean;

  constructor(adapter: FoundryVttAdapter, socket: VttSocketTransport, isGm: boolean) {
    this.adapter = adapter;
    this.socket = socket;
    this.isGm = isGm;

    this.registerHandlers();
  }

  private registerHandlers(): void {
    if (this.isGm) {
      // 1. GM receives peer access request from player
      this.socket.registerHandler(
        'kryptotome:requestAccess',
        async (request: PeerAccessRequest, _senderPeerId?: string): Promise<PeerAccessResponse> => {
          return this.adapter.handlePeerAccessRequest(request);
        }
      );

      // 2. GM receives session renewal request from player
      this.socket.registerHandler(
        'kryptotome:renewAccess',
        async (
          request: PeerSessionRenewalRequest,
          _senderPeerId?: string
        ): Promise<PeerAccessResponse> => {
          return this.adapter.handleSessionRenewal(request);
        }
      );
    } else {
      // 3. Player receives revocation notice broadcast from GM
      this.socket.registerHandler(
        'kryptotome:revokeNotice',
        async (notice: SessionRevocationNotice): Promise<number> => {
          return this.adapter.handleRevocationNotice(notice);
        }
      );
    }
  }

  /**
   * For Player: Dispatches peer access request to GM host over socket and mounts
   * returned compendium session in client memory seamlessly.
   */
  public async requestAccessOverSocket(
    packageId: string,
    expectedHostPubKeyHex?: string
  ): Promise<MountedCompendiumSession> {
    if (this.isGm) {
      throw new Error('GM host does not need to request compendium access from itself');
    }

    const request = this.adapter.requestCompendiumAccess(packageId);
    const response: PeerAccessResponse = await this.socket.executeAsGM(
      'kryptotome:requestAccess',
      request
    );

    return this.adapter.mountCompendiumFromHost(response, expectedHostPubKeyHex);
  }

  /**
   * For Player: Dispatches session renewal request to GM host over socket.
   */
  public async renewAccessOverSocket(
    packageId: string,
    expectedHostPubKeyHex?: string
  ): Promise<MountedCompendiumSession> {
    if (this.isGm) {
      throw new Error('GM host does not need to renew compendium access over socket');
    }

    const request = this.adapter.requestSessionRenewal(packageId);
    const response: PeerAccessResponse = await this.socket.executeAsGM(
      'kryptotome:renewAccess',
      request
    );

    return this.adapter.processRenewalResponse(response, expectedHostPubKeyHex);
  }

  /**
   * For GM: Broadcasts revocation notice to all players or targeted peer.
   */
  public broadcastRevocationNotice(notice: SessionRevocationNotice): void {
    if (!this.isGm) {
      throw new Error('Only GM host can broadcast revocation notices');
    }

    if (this.socket.broadcast) {
      this.socket.broadcast('kryptotome:revokeNotice', notice);
    } else {
      this.socket.executeAsGM('kryptotome:revokeNotice', notice);
    }
  }
}
