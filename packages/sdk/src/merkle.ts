import { createHash } from 'node:crypto';
import type { CompendiumItem, MerkleInclusionProof, MerklePathNode } from './types.js';

/**
 * Computes deterministic leaf hash: Sha256("kryptotome:leaf:" || id || ":" || itemType || ":" || digest)
 */
export function computeItemLeafHash(item: CompendiumItem): string {
  const prefix = 'kryptotome:leaf:';
  const payload = `${prefix}${item.id}:${item.itemType}:${item.digest}`;
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Computes deterministic internal node hash: Sha256("kryptotome:node:" || left || right)
 */
export function computeNodeHash(leftBytes: Uint8Array, rightBytes: Uint8Array): Uint8Array {
  const hasher = createHash('sha256');
  hasher.update(Buffer.from('kryptotome:node:', 'utf8'));
  hasher.update(Buffer.from(leftBytes));
  hasher.update(Buffer.from(rightBytes));
  return new Uint8Array(hasher.digest());
}

/**
 * Verifies a cryptographic Merkle inclusion proof certifying an item belongs to a compendium root
 */
export function verifyMerkleInclusionProof(
  proof: MerkleInclusionProof,
  expectedRootHex?: string
): boolean {
  const targetRoot = (expectedRootHex || proof.rootHex).toLowerCase();
  let currentBytes = Buffer.from(proof.leafHashHex, 'hex');

  for (const step of proof.path) {
    const siblingBytes = Buffer.from(step.hashHex, 'hex');
    if (siblingBytes.length !== 32) {
      return false;
    }

    const hasher = createHash('sha256');
    hasher.update(Buffer.from('kryptotome:node:', 'utf8'));
    if (step.isLeft) {
      hasher.update(siblingBytes);
      hasher.update(currentBytes);
    } else {
      hasher.update(currentBytes);
      hasher.update(siblingBytes);
    }
    currentBytes = hasher.digest();
  }

  return currentBytes.toString('hex') === targetRoot;
}

/**
 * Deterministic binary Merkle tree over compendium items for attribute-level selective disclosure
 */
export class CompendiumMerkleTree {
  private items: CompendiumItem[];
  private layers: Uint8Array[][] = [];

  constructor(items: CompendiumItem[]) {
    if (items.length === 0) {
      throw new Error('Cannot construct a compendium Merkle tree with 0 items');
    }
    this.items = [...items];
    this.buildTree();
  }

  private buildTree(): void {
    let currentLayer: Uint8Array[] = this.items.map((item) => {
      const hex = computeItemLeafHash(item);
      return new Uint8Array(Buffer.from(hex, 'hex'));
    });
    this.layers = [currentLayer];

    while (currentLayer.length > 1) {
      const nextLayer: Uint8Array[] = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        if (i + 1 < currentLayer.length) {
          nextLayer.push(computeNodeHash(currentLayer[i], currentLayer[i + 1]));
        } else {
          // Odd number of leaves: duplicate last element
          nextLayer.push(computeNodeHash(currentLayer[i], currentLayer[i]));
        }
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  /**
   * Root hash of the Merkle tree in hex format
   */
  public getRootHex(): string {
    const rootBytes = this.layers[this.layers.length - 1][0];
    return Buffer.from(rootBytes).toString('hex');
  }

  /**
   * Generates a cryptographic Merkle inclusion proof for an individual compendium item
   */
  public generateInclusionProof(itemId: string): MerkleInclusionProof {
    const index = this.items.findIndex((item) => item.id === itemId);
    if (index === -1) {
      throw new Error(`Item '${itemId}' not found in compendium Merkle tree`);
    }

    const item = this.items[index];
    const leafHashHex = computeItemLeafHash(item);
    const path: MerklePathNode[] = [];

    let currentIndex = index;
    for (let layerIdx = 0; layerIdx < this.layers.length - 1; layerIdx++) {
      const layer = this.layers[layerIdx];
      const isRightChild = currentIndex % 2 === 1;
      const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;

      const siblingBytes = siblingIndex < layer.length ? layer[siblingIndex] : layer[currentIndex];
      path.push({
        hashHex: Buffer.from(siblingBytes).toString('hex'),
        isLeft: isRightChild,
      });

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      itemId: item.id,
      itemType: item.itemType,
      itemDigest: item.digest,
      leafHashHex,
      path,
      rootHex: this.getRootHex(),
    };
  }
}
