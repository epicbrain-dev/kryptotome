import {
  EmbeddedVerifier,
  KryptotomeError,
  type ChallengeNonce,
  type ZkProof,
} from '@kryptotome/sdk';

/**
 * Universal Open Character Builder Data Interfaces
 */
export interface BuilderUnlockRequest {
  builderId: 'pathbuilder2e' | 'wanderersguide' | string;
  packageId: string;
  itemId: string;
  itemType: 'feat' | 'class' | 'spell' | 'ancestry' | 'heritage' | 'equipment';
  publisherPublicKeyHex: string;
  proof: ZkProof;
  expectedDigest?: string;
}

export interface BuilderUnlockResult<T = unknown> {
  success: boolean;
  packageId: string;
  itemId: string;
  itemType: string;
  unlockedAt: string;
  data: T;
  zkAttestation: {
    contentDigest: string;
    verifiedOffline: boolean;
  };
}

export interface CharacterBuilderPlugin {
  readonly builderId: string;
  readonly supportedSystems: string[];

  unlockItem(request: BuilderUnlockRequest): Promise<BuilderUnlockResult>;
  isItemUnlocked(packageId: string, itemId: string): boolean;
  exportUnlockedPack(packageId: string): Promise<any>;
}


/**
 * Pathbuilder 2e Custom Pack Schemas
 */
export interface PathbuilderFeatRecord {
  name: string;
  level: number;
  traits: string[];
  actionType: 'none' | 'reaction' | 'free' | '1-action' | '2-actions' | '3-actions';
  prerequisites?: string;
  description: string;
  source: string;
  kryptotomePackageId?: string;
}

export interface PathbuilderClassRecord {
  name: string;
  keyAttribute: string;
  hpPerLevel: number;
  perceptionProficiency: 'trained' | 'expert' | 'master' | 'legendary';
  savingThrows: {
    fortitude: 'trained' | 'expert' | 'master' | 'legendary';
    reflex: 'trained' | 'expert' | 'master' | 'legendary';
    will: 'trained' | 'expert' | 'master' | 'legendary';
  };
  features: Array<{ level: number; name: string; description: string }>;
  source: string;
}

export interface PathbuilderCustomPack {
  packName: string;
  version: string;
  author: string;
  rulesVersion: string;
  feats: PathbuilderFeatRecord[];
  classes: PathbuilderClassRecord[];
  spells: Array<{ name: string; level: number; school: string; description: string }>;
}

/**
 * Pathbuilder 2e Local Entitlement Adapter
 * Facilitates offline unlocking of Pathfinder 2e Remaster feats, classes, and archetypes
 * directly into Pathbuilder custom pack format using local ZK proofs.
 */
export class Pathbuilder2eAdapter implements CharacterBuilderPlugin {
  public readonly builderId = 'pathbuilder2e';
  public readonly supportedSystems = ['pf2e', 'pf2e-remaster'];
  private verifier: EmbeddedVerifier;
  private unlockedItems: Map<string, BuilderUnlockResult> = new Map();

  // Reference database of rulebook assets keyed by package:item
  private rulebookCatalog: Map<string, { type: string; data: any }> = new Map();

  constructor(verifier?: EmbeddedVerifier) {
    this.verifier = verifier || new EmbeddedVerifier();
    this.seedDefaultCatalog();
  }

  private seedDefaultCatalog(): void {
    // Paizo ORC Remaster - Sample Feats
    this.rulebookCatalog.set('paizo/player-core:feat:reactive-strike', {
      type: 'feat',
      data: {
        name: 'Reactive Strike',
        level: 1,
        traits: ['Fighter'],
        actionType: 'reaction',
        prerequisites: 'Trained in simple or martial weapons',
        description: 'You snap out a weapon strike at a creature that leaves itself open.',
        source: 'Pathfinder Player Core',
      } as PathbuilderFeatRecord,
    });

    this.rulebookCatalog.set('paizo/player-core:feat:sudden-charge', {
      type: 'feat',
      data: {
        name: 'Sudden Charge',
        level: 1,
        traits: ['Barbarian', 'Fighter', 'Flourish', 'Open'],
        actionType: '2-actions',
        description: 'With a quick sprint, you dash up to your foe and swing.',
        source: 'Pathfinder Player Core',
      } as PathbuilderFeatRecord,
    });

    // Paizo ORC Remaster - Sample Class
    this.rulebookCatalog.set('paizo/player-core:class:warpriest', {
      type: 'class',
      data: {
        name: 'Cleric (Warpriest)',
        keyAttribute: 'Wisdom',
        hpPerLevel: 8,
        perceptionProficiency: 'trained',
        savingThrows: { fortitude: 'expert', reflex: 'trained', will: 'expert' },
        features: [
          { level: 1, name: 'Deity and Cause', description: 'Dedicate yourself to your faith.' },
          { level: 1, name: 'Divine Font', description: 'Channel heal or harm spells freely.' },
        ],
        source: 'Pathfinder Player Core',
      } as PathbuilderClassRecord,
    });
  }

  public async unlockItem(request: BuilderUnlockRequest): Promise<BuilderUnlockResult> {
    const catalogKey = `${request.packageId}:${request.itemType}:${request.itemId}`;
    const catalogEntry = this.rulebookCatalog.get(catalogKey);

    if (!catalogEntry) {
      throw new KryptotomeError(
        'KRYP-603',
        `Item '${request.itemId}' (${request.itemType}) not found in catalog for package '${request.packageId}'`
      );
    }

    const challenge: ChallengeNonce = {
      nonce: request.proof.publicInputs.challengeNonce,
      packageId: request.packageId,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };

    const verified = await this.verifier.verifyZkProof(challenge, request.proof, {
      publisherPublicKeyHex: request.publisherPublicKeyHex,
      expectedDigest: request.expectedDigest,
    });

    if (!verified) {
      throw new KryptotomeError(
        'KRYP-301',
        `ZK proof verification failed for Pathbuilder item '${request.itemId}'`
      );
    }

    const result: BuilderUnlockResult = {
      success: true,
      packageId: request.packageId,
      itemId: request.itemId,
      itemType: request.itemType,
      unlockedAt: new Date().toISOString(),
      data: catalogEntry.data,
      zkAttestation: {
        contentDigest: request.proof.publicInputs.contentDigest,
        verifiedOffline: true,
      },
    };

    this.unlockedItems.set(catalogKey, result);
    return result;
  }

  public isItemUnlocked(packageId: string, itemId: string): boolean {
    for (const [key] of this.unlockedItems) {
      if (key.startsWith(`${packageId}:`) && key.endsWith(`:${itemId}`)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Generates a Pathbuilder 2e custom pack JSON containing all unlocked feats and classes.
   */
  public async exportUnlockedPack(packageId: string): Promise<PathbuilderCustomPack> {
    const feats: PathbuilderFeatRecord[] = [];
    const classes: PathbuilderClassRecord[] = [];
    const spells: any[] = [];

    for (const [key, item] of this.unlockedItems) {
      if (key.startsWith(`${packageId}:`)) {
        if (item.itemType === 'feat') {
          feats.push({ ...(item.data as PathbuilderFeatRecord), kryptotomePackageId: packageId });
        } else if (item.itemType === 'class') {
          classes.push(item.data as PathbuilderClassRecord);
        } else if (item.itemType === 'spell') {
          spells.push(item.data);
        }
      }
    }

    return {
      packName: `Kryptotome Unlocked: ${packageId}`,
      version: '1.0.0',
      author: 'Kryptotome Vault (Local)',
      rulesVersion: '2.0.0',
      feats,
      classes,
      spells,
    };
  }

  /**
   * Filters a Pathbuilder character JSON build, verifying legality of feats against unlocked credentials.
   */
  public verifyCharacterBuildLegality(characterJson: {
    feats?: Array<{ name: string; source?: string; packageId?: string }>;
  }): { legal: boolean; unverifiedFeats: string[] } {
    const unverified: string[] = [];

    for (const feat of characterJson.feats || []) {
      if (feat.packageId) {
        const isUnlocked = this.isItemUnlocked(
          feat.packageId,
          feat.name.toLowerCase().replace(/\s+/g, '-')
        );
        if (!isUnlocked) {
          unverified.push(feat.name);
        }
      }
    }

    return {
      legal: unverified.length === 0,
      unverifiedFeats: unverified,
    };
  }
}

/**
 * Wanderer's Guide Local Entitlement Adapter
 * Implements offline entitlement verification for Wanderer's Guide character structures.
 */
export interface WanderersGuideHomebrewPack {
  id: string;
  name: string;
  system: 'pf2e';
  content: {
    classes: any[];
    feats: any[];
    spells: any[];
  };
  zkVerified: boolean;
}

export class WanderersGuideAdapter implements CharacterBuilderPlugin {
  public readonly builderId = 'wanderersguide';
  public readonly supportedSystems = ['pf2e'];
  private verifier: EmbeddedVerifier;
  private unlockedItems: Map<string, BuilderUnlockResult> = new Map();

  constructor(verifier?: EmbeddedVerifier) {
    this.verifier = verifier || new EmbeddedVerifier();
  }

  public async unlockItem(request: BuilderUnlockRequest): Promise<BuilderUnlockResult> {
    const challenge: ChallengeNonce = {
      nonce: request.proof.publicInputs.challengeNonce,
      packageId: request.packageId,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };

    const verified = await this.verifier.verifyZkProof(challenge, request.proof, {
      publisherPublicKeyHex: request.publisherPublicKeyHex,
      expectedDigest: request.expectedDigest,
    });

    if (!verified) {
      throw new KryptotomeError(
        'KRYP-301',
        `ZK proof verification failed for Wanderer's Guide item '${request.itemId}'`
      );
    }

    const result: BuilderUnlockResult = {
      success: true,
      packageId: request.packageId,
      itemId: request.itemId,
      itemType: request.itemType,
      unlockedAt: new Date().toISOString(),
      data: {
        id: request.itemId,
        name: request.itemId.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
        packageId: request.packageId,
        type: request.itemType,
      },
      zkAttestation: {
        contentDigest: request.proof.publicInputs.contentDigest,
        verifiedOffline: true,
      },
    };

    const key = `${request.packageId}:${request.itemType}:${request.itemId}`;
    this.unlockedItems.set(key, result);
    return result;
  }

  public isItemUnlocked(packageId: string, itemId: string): boolean {
    for (const [key] of this.unlockedItems) {
      if (key.startsWith(`${packageId}:`) && key.endsWith(`:${itemId}`)) {
        return true;
      }
    }
    return false;
  }

  public async exportUnlockedPack(packageId: string): Promise<WanderersGuideHomebrewPack> {
    const feats: any[] = [];
    const classes: any[] = [];
    const spells: any[] = [];

    for (const [key, item] of this.unlockedItems) {
      if (key.startsWith(`${packageId}:`)) {
        if (item.itemType === 'feat') feats.push(item.data);
        else if (item.itemType === 'class') classes.push(item.data);
        else if (item.itemType === 'spell') spells.push(item.data);
      }
    }

    return {
      id: `wg-${packageId.replace('/', '-')}`,
      name: `Kryptotome Vault: ${packageId}`,
      system: 'pf2e',
      content: { classes, feats, spells },
      zkVerified: true,
    };
  }
}

/**
 * Universal Builder Adapter Registry
 * Dispatches entitlement lookups across registered open character builders.
 */
export class UniversalBuilderRegistry {
  private plugins: Map<string, CharacterBuilderPlugin> = new Map();

  constructor() {
    this.registerPlugin(new Pathbuilder2eAdapter());
    this.registerPlugin(new WanderersGuideAdapter());
  }

  public registerPlugin(plugin: CharacterBuilderPlugin): void {
    this.plugins.set(plugin.builderId, plugin);
  }

  public getPlugin(builderId: string): CharacterBuilderPlugin | undefined {
    return this.plugins.get(builderId);
  }

  public listSupportedBuilders(): string[] {
    return Array.from(this.plugins.keys());
  }
}
