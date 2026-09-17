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
  SessionRevocationNotice,
  ZkProof,
} from '@kryptotome/sdk';

/**
 * Owlbear Rodeo 2.0 Layer Constants
 */
export const OBR_LAYERS = {
  MAP: 'MAP',
  GRID: 'GRID',
  DRAWING: 'DRAWING',
  PROP: 'PROP',
  MOUNT: 'MOUNT',
  CHARACTER: 'CHARACTER',
  ATTACHMENT: 'ATTACHMENT',
  NOTE: 'NOTE',
  TEXT: 'TEXT',
  FOG: 'FOG',
} as const;

export type ObrLayer = (typeof OBR_LAYERS)[keyof typeof OBR_LAYERS];

export interface ObrVector2 {
  x: number;
  y: number;
}

export interface ObrItemMetadata {
  [key: string]: unknown;
}

export interface ObrBaseItem {
  id: string;
  type: string;
  name: string;
  layer: ObrLayer;
  position: ObrVector2;
  rotation: number;
  scale: ObrVector2;
  visible: boolean;
  locked: boolean;
  zIndex: number;
  metadata: ObrItemMetadata;
  attachedTo?: string;
}

export interface ObrImageItem extends ObrBaseItem {
  type: 'IMAGE';
  image: {
    url: string;
    mime: string;
    width: number;
    height: number;
  };
  grid: {
    dpi: number;
    offset: ObrVector2;
  };
}

export interface ObrTextItem extends ObrBaseItem {
  type: 'TEXT';
  text: {
    plainText: string;
    style: {
      color: string;
      fontSize: number;
      fontFamily: string;
      textAlign: 'LEFT' | 'CENTER' | 'RIGHT';
      fontWeight: number;
    };
  };
}

export interface ObrShapeItem extends ObrBaseItem {
  type: 'SHAPE';
  shapeType: 'RECTANGLE' | 'CIRCLE' | 'HEXAGON';
  width: number;
  height: number;
  style: {
    fillColor: string;
    fillOpacity: number;
    strokeColor: string;
    strokeOpacity: number;
    strokeWidth: number;
  };
}

export type ObrItem = ObrImageItem | ObrTextItem | ObrShapeItem | ObrBaseItem;

/**
 * Owlbear Rodeo 2.0 SDK Interface Abstraction
 */
export interface ObrSdkContext {
  isAvailable: boolean;
  player: {
    getId(): Promise<string>;
    getName(): Promise<string>;
    getRole(): Promise<'GM' | 'PLAYER'>;
  };
  room: {
    getId(): Promise<string>;
  };
  scene: {
    isReady(): Promise<boolean>;
    items: {
      addItems(items: ObrItem[]): Promise<void>;
      getItems(filter?: (item: ObrItem) => boolean): Promise<ObrItem[]>;
      deleteItems(ids: string[]): Promise<void>;
      updateItems(items: ObrItem[]): Promise<void>;
    };
    grid: {
      getDpi(): Promise<number>;
      getScale(): Promise<{ parsed: { multiplier: number; unit: string } }>;
    };
  };
  broadcast: {
    sendMessage(channel: string, data: unknown, options?: { destination?: 'ALL' | 'LOCAL' | 'REMOTE' }): Promise<void>;
    onMessage(channel: string, listener: (event: { data: unknown; connectionId: string }) => void): () => void;
  };
  notification: {
    show(message: string, variant?: 'DEFAULT' | 'SUCCESS' | 'WARNING' | 'ERROR'): Promise<void>;
  };
}

export interface MountTokenOptions {
  id?: string;
  name: string;
  imageUrl: string;
  width?: number;
  height?: number;
  position?: ObrVector2;
  gridSize?: number; // In grid units (e.g. 1 for Medium, 2 for Large)
  packageId: string;
  assetDigest: string;
  hp?: { current: number; max: number };
  ac?: number;
  proofAttestation?: string;
}

export interface MountBattlemapOptions {
  id?: string;
  name: string;
  imageUrl: string;
  pixelWidth: number;
  pixelHeight: number;
  dpi?: number;
  gridOffset?: ObrVector2;
  position?: ObrVector2;
  packageId: string;
  assetDigest: string;
  proofAttestation?: string;
}

export interface MountSpellCardOptions {
  id?: string;
  name: string;
  level: number;
  school: string;
  castingTime: string;
  range: string;
  duration: string;
  components: string;
  description: string;
  packageId: string;
  position?: ObrVector2;
  proofAttestation?: string;
}

/**
 * Creates an Owlbear Rodeo 2.0 Image Item configured for a character/creature token.
 */
export function mountTokenItem(options: MountTokenOptions, dpi = 150): ObrImageItem {
  const sizeMultiplier = options.gridSize ?? 1;
  const tokenWidth = options.width ?? dpi * sizeMultiplier;
  const tokenHeight = options.height ?? dpi * sizeMultiplier;

  return {
    id: options.id || `kryptotome-token-${crypto.randomUUID()}`,
    type: 'IMAGE',
    name: options.name,
    layer: OBR_LAYERS.CHARACTER,
    position: options.position || { x: 0, y: 0 },
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: false,
    zIndex: 1,
    image: {
      url: options.imageUrl,
      mime: 'image/png',
      width: tokenWidth,
      height: tokenHeight,
    },
    grid: {
      dpi,
      offset: { x: 0, y: 0 },
    },
    metadata: {
      'kryptotome:type': 'token',
      'kryptotome:packageId': options.packageId,
      'kryptotome:assetDigest': options.assetDigest,
      'kryptotome:verified': true,
      'kryptotome:attestation': options.proofAttestation || null,
      'kryptotome:stats': {
        hp: options.hp || null,
        ac: options.ac || null,
      },
    },
  };
}

/**
 * Creates an Owlbear Rodeo 2.0 Image Item configured as a room battlemap on the MAP layer.
 */
export function mountBattlemapItem(options: MountBattlemapOptions): ObrImageItem {
  const dpi = options.dpi || 150;

  return {
    id: options.id || `kryptotome-map-${crypto.randomUUID()}`,
    type: 'IMAGE',
    name: options.name,
    layer: OBR_LAYERS.MAP,
    position: options.position || { x: 0, y: 0 },
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: true,
    zIndex: 0,
    image: {
      url: options.imageUrl,
      mime: 'image/jpeg',
      width: options.pixelWidth,
      height: options.pixelHeight,
    },
    grid: {
      dpi,
      offset: options.gridOffset || { x: 0, y: 0 },
    },
    metadata: {
      'kryptotome:type': 'battlemap',
      'kryptotome:packageId': options.packageId,
      'kryptotome:assetDigest': options.assetDigest,
      'kryptotome:verified': true,
      'kryptotome:attestation': options.proofAttestation || null,
    },
  };
}

/**
 * Creates an Owlbear Rodeo 2.0 interactive Spell Card cluster (background card, header, and text body).
 */
export function mountSpellCardItem(options: MountSpellCardOptions): ObrItem[] {
  const cardId = options.id || `kryptotome-spell-${crypto.randomUUID()}`;
  const pos = options.position || { x: 100, y: 100 };
  const cardWidth = 320;
  const cardHeight = 220;

  // 1. Background Card Shape
  const backgroundCard: ObrShapeItem = {
    id: `${cardId}-bg`,
    type: 'SHAPE',
    name: `${options.name} (Card)`,
    layer: OBR_LAYERS.PROP,
    position: pos,
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: false,
    zIndex: 2,
    shapeType: 'RECTANGLE',
    width: cardWidth,
    height: cardHeight,
    style: {
      fillColor: '#0f172a',
      fillOpacity: 0.92,
      strokeColor: '#6366f1',
      strokeOpacity: 0.9,
      strokeWidth: 3,
    },
    metadata: {
      'kryptotome:type': 'spell-card',
      'kryptotome:packageId': options.packageId,
      'kryptotome:verified': true,
      'kryptotome:attestation': options.proofAttestation || null,
      'kryptotome:spell': {
        name: options.name,
        level: options.level,
        school: options.school,
        castingTime: options.castingTime,
        range: options.range,
        duration: options.duration,
        components: options.components,
      },
    },
  };

  // 2. Title & School Header
  const levelText = options.level === 0 ? 'Cantrip' : `Level ${options.level}`;
  const headerText: ObrTextItem = {
    id: `${cardId}-header`,
    type: 'TEXT',
    name: `${options.name} Header`,
    layer: OBR_LAYERS.TEXT,
    position: { x: pos.x + 16, y: pos.y + 16 },
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: false,
    zIndex: 3,
    attachedTo: backgroundCard.id,
    text: {
      plainText: `${options.name}\n${levelText} • ${options.school}`,
      style: {
        color: '#38bdf8',
        fontSize: 16,
        fontFamily: 'Inter, sans-serif',
        textAlign: 'LEFT',
        fontWeight: 700,
      },
    },
    metadata: {
      'kryptotome:parentCard': cardId,
    },
  };

  // 3. Body Details & Stats
  const bodyText: ObrTextItem = {
    id: `${cardId}-body`,
    type: 'TEXT',
    name: `${options.name} Details`,
    layer: OBR_LAYERS.TEXT,
    position: { x: pos.x + 16, y: pos.y + 64 },
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: false,
    zIndex: 3,
    attachedTo: backgroundCard.id,
    text: {
      plainText: `Cast: ${options.castingTime} | Range: ${options.range}\nDuration: ${options.duration}\nComponents: ${options.components}\n\n${options.description}`,
      style: {
        color: '#e2e8f0',
        fontSize: 12,
        fontFamily: 'Inter, sans-serif',
        textAlign: 'LEFT',
        fontWeight: 400,
      },
    },
    metadata: {
      'kryptotome:parentCard': cardId,
    },
  };

  return [backgroundCard, headerText, bodyText];
}

export interface OwlbearVttConfig {
  gameSystemId: string;
  isGameMaster: boolean;
  activeSessionId: string;
  localPeerId: string;
}

/**
 * Owlbear Rodeo 2.0 VTT Adapter for Kryptotome Protocol.
 * Facilitates cryptographic compendium unlocking and canvas mounting over OBR SDK & WebRTC.
 */
export class OwlbearVttAdapter {
  private verifier: EmbeddedVerifier;
  private sessionManager: TableSessionManager | null = null;
  private peerClient: PeerSessionClient;
  private config: OwlbearVttConfig;
  private obr: ObrSdkContext | null = null;
  private roomSync: OwlbearRoomSync | null = null;
  private mountedSessions: Map<string, MountedCompendiumSession> = new Map();

  constructor(config: OwlbearVttConfig, obr?: ObrSdkContext) {
    this.config = config;
    this.verifier = new EmbeddedVerifier();
    this.peerClient = new PeerSessionClient(config.localPeerId);
    if (obr) {
      this.attachObrSdk(obr);
    }
  }

  public attachObrSdk(obr: ObrSdkContext): void {
    this.obr = obr;
    this.roomSync = new OwlbearRoomSync(this, obr);
  }

  public getObrSdk(): ObrSdkContext | null {
    return this.obr;
  }

  public getRoomSync(): OwlbearRoomSync | null {
    return this.roomSync;
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

  public getConfig(): OwlbearVttConfig {
    return { ...this.config };
  }

  /**
   * Initializes host table session manager (GM only).
   */
  public initHostSession(packageId: string, contentDigest: string): void {
    if (!this.config.isGameMaster) {
      throw new KryptotomeError(
        'KRYP-401',
        'Only GM host can initialize an Owlbear table session manager'
      );
    }
    this.sessionManager = new TableSessionManager({
      sessionId: this.config.activeSessionId,
      hostPeerId: this.config.localPeerId,
      packageId,
      contentDigest,
    });
  }

  /**
   * Mounts an unlocked token directly onto the active Owlbear Rodeo 2.0 room canvas.
   */
  public async mountTokenToCanvas(options: MountTokenOptions): Promise<ObrImageItem> {
    const item = mountTokenItem(options);
    if (this.obr?.scene) {
      await this.obr.scene.items.addItems([item]);
      await this.obr.notification.show(`Mounted token "${options.name}" to canvas`, 'SUCCESS');
    }
    return item;
  }

  /**
   * Mounts an unlocked battlemap directly onto the active Owlbear Rodeo 2.0 room canvas MAP layer.
   */
  public async mountBattlemapToCanvas(options: MountBattlemapOptions): Promise<ObrImageItem> {
    const item = mountBattlemapItem(options);
    if (this.obr?.scene) {
      await this.obr.scene.items.addItems([item]);
      await this.obr.notification.show(`Mounted battlemap "${options.name}" to canvas`, 'SUCCESS');
    }
    return item;
  }

  /**
   * Mounts an unlocked interactive spell card directly onto the active Owlbear Rodeo 2.0 room canvas.
   */
  public async mountSpellCardToCanvas(options: MountSpellCardOptions): Promise<ObrItem[]> {
    const items = mountSpellCardItem(options);
    if (this.obr?.scene) {
      await this.obr.scene.items.addItems(items);
      await this.obr.notification.show(`Mounted spell card "${options.name}" to canvas`, 'SUCCESS');
    }
    return items;
  }

  /**
   * Unlocks a compendium package locally on the GM machine.
   */
  public async unlockCompendiumLocally(
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

    const isValid = await this.verifier.verifyZkProof(targetChallenge, proof, {
      publisherPublicKeyHex,
      expectedDigest,
    });

    if (!isValid) {
      throw new KryptotomeError(
        'KRYP-301',
        `Cryptographic proof verification failed for package ${packageId}`
      );
    }

    if (this.config.isGameMaster) {
      this.initHostSession(packageId, proof.publicInputs.contentDigest);
    }

    return true;
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
   * Checks if a compendium module is mounted in client memory
   */
  public isCompendiumMounted(packageId: string): boolean {
    return this.peerClient.isPackageMounted(packageId);
  }


  /**
   * Player mounts compendium session granted by GM host.
   */
  public mountCompendiumFromHost(
    response: PeerAccessResponse,
    expectedHostPubKeyHex?: string
  ): MountedCompendiumSession {
    const session = this.peerClient.processHandshakeResponse(
      response,
      expectedHostPubKeyHex
    );
    this.mountedSessions.set(session.packageId, session);
    return session;
  }

  /**
   * GM handles incoming peer access request.
   */
  public handlePeerAccessRequest(request: PeerAccessRequest, customScopes?: string[]): PeerAccessResponse {
    if (!this.sessionManager) {
      throw new KryptotomeError(
        'KRYP-401',
        'Session manager is not initialized on host'
      );
    }
    return this.sessionManager.handleAccessRequest(request, true, customScopes);
  }

  /**
   * GM handles session renewal.
   */
  public handleSessionRenewal(request: PeerSessionRenewalRequest, durationMinutes?: number): PeerAccessResponse {
    if (!this.sessionManager) {
      throw new KryptotomeError(
        'KRYP-401',
        'Session manager is not initialized on host'
      );
    }
    return this.sessionManager.handleRenewalRequest(request, durationMinutes);
  }

  /**
   * Player handles revocation notice.
   */
  public handleRevocationNotice(notice: SessionRevocationNotice, expectedHostPubKeyHex?: string): number {
    return this.peerClient.processRevocationNotice(notice, expectedHostPubKeyHex);
  }
}

/**
 * Coordinates room WebRTC / OBR Broadcast channels for table session synchronization.
 */
export class OwlbearRoomSync {
  private adapter: OwlbearVttAdapter;
  private obr: ObrSdkContext;
  private unsubscribeMessages: (() => void) | null = null;
  public static readonly BROADCAST_CHANNEL = 'kryptotome:table-sync';

  constructor(adapter: OwlbearVttAdapter, obr: ObrSdkContext) {
    this.adapter = adapter;
    this.obr = obr;
    this.setupBroadcastChannel();
  }

  private setupBroadcastChannel(): void {
    if (!this.obr.broadcast) {
      return;
    }

    this.unsubscribeMessages = this.obr.broadcast.onMessage(
      OwlbearRoomSync.BROADCAST_CHANNEL,
      async (event) => {
        await this.handleBroadcastMessage(event.data);
      }
    );
  }

  public destroy(): void {
    if (this.unsubscribeMessages) {
      this.unsubscribeMessages();
      this.unsubscribeMessages = null;
    }
  }

  /**
   * Dispatches a broadcast event to table participants.
   */
  public async sendTableMessage(type: string, payload: unknown): Promise<void> {
    await this.obr.broadcast.sendMessage(OwlbearRoomSync.BROADCAST_CHANNEL, {
      type,
      payload,
      senderPeerId: this.adapter.getConfig().localPeerId,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Internal message handler for WebRTC / OBR broadcast channels.
   */
  public async handleBroadcastMessage(data: unknown): Promise<void> {
    if (!data || typeof data !== 'object') return;
    const msg = data as { type: string; payload: any; senderPeerId: string };
    const isGm = this.adapter.getConfig().isGameMaster;

    switch (msg.type) {
      case 'kryptotome:requestAccess': {
        if (isGm) {
          try {
            const response = this.adapter.handlePeerAccessRequest(msg.payload);
            await this.sendTableMessage('kryptotome:accessGranted', {
              targetPeerId: msg.senderPeerId,
              response,
            });
          } catch (err) {
            await this.sendTableMessage('kryptotome:accessDenied', {
              targetPeerId: msg.senderPeerId,
              error: (err as Error).message,
            });
          }
        }
        break;
      }

      case 'kryptotome:accessGranted': {
        if (!isGm && msg.payload.targetPeerId === this.adapter.getConfig().localPeerId) {
          this.adapter.mountCompendiumFromHost(msg.payload.response);
          await this.obr.notification.show(
            `Unlocked compendium session for "${msg.payload.response.attestation.packageId}"!`,
            'SUCCESS'
          );
        }
        break;
      }

      case 'kryptotome:revokeNotice': {
        if (!isGm) {
          const purged = this.adapter.handleRevocationNotice(msg.payload);
          if (purged > 0) {
            await this.obr.notification.show(
              'A compendium session token has been revoked by the GM.',
              'WARNING'
            );
          }
        }
        break;
      }

      default:
        break;
    }
  }

  /**
   * Player initiates an access request to GM host over OBR broadcast.
   */
  public async requestAccessFromHost(packageId: string): Promise<PeerAccessRequest> {
    const request = this.adapter.getPeerClient().createAccessRequest(packageId);
    await this.sendTableMessage('kryptotome:requestAccess', request);
    return request;
  }
}

