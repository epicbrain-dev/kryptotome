/**
 * Kryptotome Vault - Owlbear Rodeo 2.0 Extension Frontend
 * Seamlessly mounts zero-knowledge verified tokens, battlemaps, and spell cards
 * directly to the Owlbear Rodeo room canvas via the OBR 2.0 SDK.
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
  metadata: Record<string, unknown>;
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

export interface ObrSdkContext {
  isAvailable: boolean;
  player?: {
    getId(): Promise<string>;
    getName(): Promise<string>;
    getRole(): Promise<'GM' | 'PLAYER'>;
  };
  room?: {
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
  broadcast?: {
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
  gridSize?: number;
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

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function secureUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  }
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function mountTokenItem(options: MountTokenOptions, dpi: number = 150): ObrImageItem {
  const sizeMultiplier = options.gridSize ?? 1;
  const tokenWidth = options.width ?? dpi * sizeMultiplier;
  const tokenHeight = options.height ?? dpi * sizeMultiplier;

  return {
    id: options.id || `kryptotome-token-${secureUUID()}`,
    type: 'IMAGE',
    name: options.name,
    layer: OBR_LAYERS.CHARACTER,
    position: options.position ?? { x: 0, y: 0 },
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
      offset: { x: tokenWidth / 2, y: tokenHeight / 2 },
    },
    metadata: {
      'org.kryptotome.packageId': options.packageId,
      'org.kryptotome.assetDigest': options.assetDigest,
      'org.kryptotome.hp': options.hp ?? { current: 10, max: 10 },
      'org.kryptotome.ac': options.ac ?? 10,
      'org.kryptotome.proofAttestation': options.proofAttestation || 'offline_verified',
      'org.kryptotome.mountedAt': new Date().toISOString(),
    },
  };
}

export function mountBattlemapItem(options: MountBattlemapOptions): ObrImageItem {
  const dpi = options.dpi ?? 150;
  return {
    id: options.id || `kryptotome-map-${secureUUID()}`,
    type: 'IMAGE',
    name: options.name,
    layer: OBR_LAYERS.MAP,
    position: options.position ?? { x: 0, y: 0 },
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
      offset: options.gridOffset ?? { x: 0, y: 0 },
    },
    metadata: {
      'org.kryptotome.packageId': options.packageId,
      'org.kryptotome.assetDigest': options.assetDigest,
      'org.kryptotome.proofAttestation': options.proofAttestation || 'offline_verified',
      'org.kryptotome.mountedAt': new Date().toISOString(),
    },
  };
}

export function mountSpellCardItem(
  options: MountSpellCardOptions,
  cardWidth: number = 320,
  cardHeight: number = 220
): ObrItem[] {
  const cardId = options.id || `kryptotome-spellcard-${secureUUID()}`;
  const pos = options.position ?? { x: 100, y: 100 };

  const backgroundShape: ObrShapeItem = {
    id: cardId,
    type: 'SHAPE',
    shapeType: 'RECTANGLE',
    name: `${options.name} (Card)`,
    layer: OBR_LAYERS.NOTE,
    position: pos,
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: false,
    zIndex: 10,
    width: cardWidth,
    height: cardHeight,
    style: {
      fillColor: '#121826',
      fillOpacity: 0.95,
      strokeColor: '#6366f1',
      strokeOpacity: 0.8,
      strokeWidth: 2,
    },
    metadata: {
      'org.kryptotome.packageId': options.packageId,
      'org.kryptotome.spellLevel': options.level,
      'org.kryptotome.school': options.school,
      'org.kryptotome.proofAttestation': options.proofAttestation || 'offline_verified',
    },
  };

  const titleText: ObrTextItem = {
    id: `${cardId}-title`,
    type: 'TEXT',
    name: `${options.name} Title`,
    layer: OBR_LAYERS.TEXT,
    position: { x: pos.x + 12, y: pos.y + 12 },
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: false,
    zIndex: 11,
    attachedTo: cardId,
    text: {
      plainText: `${options.name} (Level ${options.level} ${options.school})`,
      style: {
        color: '#f8fafc',
        fontSize: 14,
        fontFamily: 'sans-serif',
        textAlign: 'LEFT',
        fontWeight: 700,
      },
    },
    metadata: { 'org.kryptotome.parentCardId': cardId },
  };

  const bodyText: ObrTextItem = {
    id: `${cardId}-body`,
    type: 'TEXT',
    name: `${options.name} Body`,
    layer: OBR_LAYERS.TEXT,
    position: { x: pos.x + 12, y: pos.y + 40 },
    rotation: 0,
    scale: { x: 1, y: 1 },
    visible: true,
    locked: false,
    zIndex: 11,
    attachedTo: cardId,
    text: {
      plainText: `Cast: ${options.castingTime} | Range: ${options.range} | Dur: ${options.duration}\nComp: ${options.components}\n\n${options.description}`,
      style: {
        color: '#94a3b8',
        fontSize: 11,
        fontFamily: 'sans-serif',
        textAlign: 'LEFT',
        fontWeight: 400,
      },
    },
    metadata: { 'org.kryptotome.parentCardId': cardId },
  };

  return [backgroundShape, titleText, bodyText];
}

export class OwlbearExtensionClient {
  private obr?: ObrSdkContext;

  constructor(obr?: ObrSdkContext) {
    this.obr = obr;
  }

  public getObr(): ObrSdkContext | undefined {
    return this.obr;
  }

  public async mountToken(options: MountTokenOptions): Promise<ObrImageItem> {
    const dpi = this.obr ? await this.obr.scene.grid.getDpi() : 150;
    const item = mountTokenItem(options, dpi);

    if (this.obr && this.obr.isAvailable) {
      await this.obr.scene.items.addItems([item]);
      await this.obr.notification.show(`Mounted token "${options.name}" to canvas`, 'SUCCESS');
    }
    return item;
  }

  public async mountBattlemap(options: MountBattlemapOptions): Promise<ObrImageItem> {
    const item = mountBattlemapItem(options);

    if (this.obr && this.obr.isAvailable) {
      await this.obr.scene.items.addItems([item]);
      await this.obr.notification.show(`Mounted battlemap "${options.name}" to canvas`, 'SUCCESS');
    }
    return item;
  }

  public async mountSpellCard(options: MountSpellCardOptions): Promise<ObrItem[]> {
    const items = mountSpellCardItem(options);

    if (this.obr && this.obr.isAvailable) {
      await this.obr.scene.items.addItems(items);
      await this.obr.notification.show(`Mounted spell card "${options.name}" to canvas`, 'SUCCESS');
    }
    return items;
  }
}

declare const window: any;

export function initOwlbearExtensionUI(obrContext?: ObrSdkContext): OwlbearExtensionClient {
  const obr = obrContext || (typeof window !== 'undefined' ? window.OBR : undefined);
  const client = new OwlbearExtensionClient(obr);

  if (typeof document === 'undefined') {
    return client;
  }

  // Update status badge
  const statusEl = document.getElementById('vaultStatusText');
  if (statusEl) {
    statusEl.textContent = obr && obr.isAvailable ? 'Owlbear 2.0 Connected' : 'Local Vault Standalone';
  }

  // Tab navigation
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-tab');
      tabBtns.forEach((b) => b.classList.remove('active'));
      tabContents.forEach((c) => c.classList.remove('active'));

      btn.classList.add('active');
      const contentEl = document.getElementById(`${target}-tab`);
      if (contentEl) contentEl.classList.add('active');
    });
  });

  // Action Button Listeners
  document.getElementById('mountArchmageBtn')?.addEventListener('click', async () => {
    await client.mountToken({
      name: 'Archmage Evoker',
      imageUrl: 'https://assets.kryptotome.org/tokens/archmage.png',
      gridSize: 1,
      packageId: 'open-rpg/core-bestiary',
      assetDigest: 'sha256:4b227777d4da1fc6e11e80a06451e67d3b43a50370f23ec14ff16a15f84ac524',
      hp: { current: 84, max: 84 },
      ac: 15,
    });
  });

  document.getElementById('mountDragonBtn')?.addEventListener('click', async () => {
    await client.mountToken({
      name: 'Ancient Red Dragon',
      imageUrl: 'https://assets.kryptotome.org/tokens/red-dragon.png',
      gridSize: 4,
      packageId: 'open-rpg/draconic-codex',
      assetDigest: 'sha256:7f9202573215286950293d0d8fd4598d1a3c75eb20d41e784518349fa81f8016',
      hp: { current: 546, max: 546 },
      ac: 22,
    });
  });

  document.getElementById('mountCryptBtn')?.addEventListener('click', async () => {
    await client.mountBattlemap({
      name: 'Sunken Crypt of the Lich',
      imageUrl: 'https://assets.kryptotome.org/maps/sunken-crypt.jpg',
      pixelWidth: 3840,
      pixelHeight: 2160,
      dpi: 150,
      packageId: 'open-rpg/dungeon-cartography-vol1',
      assetDigest: 'sha256:1a84f3e6a735e18659d81d2f5a60e0a582fa6cf0c294974f884a6c429d29759d',
    });
  });

  document.getElementById('mountFireballBtn')?.addEventListener('click', async () => {
    await client.mountSpellCard({
      name: 'Fireball',
      level: 3,
      school: 'Evocation',
      castingTime: '1 action',
      range: '150 feet',
      duration: 'Instantaneous',
      components: 'V, S, M',
      description: 'A bright streak flashes from your pointing finger to a point you choose within range and blossoms into an explosion of flame.',
      packageId: 'open-rpg/core-spells',
    });
  });

  document.getElementById('mountMissileBtn')?.addEventListener('click', async () => {
    await client.mountSpellCard({
      name: 'Magic Missile',
      level: 1,
      school: 'Evocation',
      castingTime: '1 action',
      range: '120 feet',
      duration: 'Instantaneous',
      components: 'V, S',
      description: 'You create three glowing darts of magical force that strike targets infallibly for 1d4 + 1 force damage each.',
      packageId: 'open-rpg/core-spells',
    });
  });

  return client;
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    initOwlbearExtensionUI();
  });
}
