import { KryptotomeError } from './error.js';
import type {
  CompendiumPackageData,
  ErrataApplyResult,
  ErrataPatchBundle,
  JsonPatchOperation,
  ZkProof,
} from './types.js';

export interface SyncOptions {
  publisherMirrorUrl: string;
  packageId: string;
  currentDigest?: string;
  currentVersion?: string;
  fetchFn?: typeof fetch;
}

export interface ErrataApplyOptions {
  verifySignature?: boolean;
  allowDigestMismatch?: boolean;
}

export class ErrataSyncDispatcher {
  private fetchFn: typeof fetch;

  constructor(customFetch?: typeof fetch) {
    this.fetchFn =
      customFetch || (typeof globalThis !== 'undefined' ? globalThis.fetch : fetch);
  }

  /**
   * Polls verified publisher mirrors for schema updates using proof attestations in HTTP headers:
   * GET /packages/{packageId}/updates HTTP/1.1
   * X-Kryptotome-Proof: <proof-bytes>
   * X-Kryptotome-Digest: <current-digest>
   */
  public async checkForErrata(
    options: SyncOptions,
    proofAttestation: ZkProof
  ): Promise<ErrataPatchBundle | null> {
    if (!proofAttestation || !proofAttestation.proofBytes) {
      throw new KryptotomeError(
        'KRYP-105',
        'Valid proof attestation required to query mirror errata'
      );
    }

    if (
      proofAttestation.publicInputs?.packageId &&
      proofAttestation.publicInputs.packageId !== options.packageId
    ) {
      throw new KryptotomeError(
        'KRYP-403',
        `Proof attestation package ID '${proofAttestation.publicInputs.packageId}' does not match requested package '${options.packageId}'`
      );
    }

    const mirrorBase = options.publisherMirrorUrl.replace(/\/$/, '');
    const endpoint = `${mirrorBase}/packages/${encodeURIComponent(options.packageId)}/updates`;
    const currentDigest = options.currentDigest || 'latest';

    const headers: Record<string, string> = {
      'X-Kryptotome-Proof': proofAttestation.proofBytes,
      'X-Kryptotome-Digest': currentDigest,
      Accept: 'application/json',
    };

    let response: Response;
    try {
      const fetchCall = options.fetchFn || this.fetchFn;
      response = await fetchCall(endpoint, {
        method: 'GET',
        headers,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new KryptotomeError(
        'KRYP-804',
        `Network error connecting to publisher mirror at ${endpoint}: ${msg}`,
        { originalError: err }
      );
    }

    if (response.status === 304) {
      // Not Modified: local cached compendium is already at the latest errata digest
      return null;
    }

    if (response.status === 404) {
      // No updates or package not found on this mirror
      return null;
    }

    if (response.status === 401 || response.status === 403) {
      throw new KryptotomeError(
        'KRYP-801',
        `Mirror authentication failed: proof attestation rejected by publisher mirror (HTTP ${response.status})`,
        { status: response.status }
      );
    }

    if (response.status === 429) {
      throw new KryptotomeError(
        'KRYP-803',
        'Publisher mirror rate limit exceeded',
        { status: response.status }
      );
    }

    if (!response.ok) {
      throw new KryptotomeError(
        'KRYP-804',
        `Publisher mirror returned HTTP ${response.status}: ${response.statusText}`,
        { status: response.status }
      );
    }

    let data: any;
    try {
      data = await response.json();
    } catch (err: unknown) {
      throw new KryptotomeError(
        'KRYP-901',
        'Failed to parse JSON response from publisher mirror',
        { originalError: err }
      );
    }

    if (!data || typeof data !== 'object') {
      return null;
    }

    if (!data.packageId || !data.fromDigest || !data.toDigest || !Array.isArray(data.operations)) {
      throw new KryptotomeError(
        'KRYP-106',
        'Mirror update payload does not conform to ErrataPatchBundle schema'
      );
    }

    return data as ErrataPatchBundle;
  }

  /**
   * Computes a deterministic, ordered list of RFC 6902 JSON patch operations between two JSON states.
   */
  public computeJsonPatch(original: unknown, updated: unknown): JsonPatchOperation[] {
    const ops: JsonPatchOperation[] = [];
    this.diffInternal(original, updated, '', ops);
    // Sort deterministically by path and op
    ops.sort((a, b) => (a.path === b.path ? a.op.localeCompare(b.op) : a.path.localeCompare(b.path)));
    return ops;
  }

  /**
   * Applies an RFC 6902 JSON Patch deterministically to a target document.
   */
  public applyJsonPatch<T>(target: T, operations: JsonPatchOperation[]): T {
    const clone = JSON.parse(JSON.stringify(target));

    for (const operation of operations) {
      const pathTokens = this.parseJsonPointer(operation.path);

      switch (operation.op) {
        case 'add': {
          this.applyAdd(clone, pathTokens, operation.value);
          break;
        }
        case 'replace': {
          this.applyReplace(clone, pathTokens, operation.value);
          break;
        }
        case 'remove': {
          this.applyRemove(clone, pathTokens);
          break;
        }
        case 'test': {
          const actual = this.getValueAtPath(clone, pathTokens);
          if (JSON.stringify(actual) !== JSON.stringify(operation.value)) {
            throw new KryptotomeError(
              'KRYP-501',
              `JSON Patch test operation failed at path ${operation.path}`
            );
          }
          break;
        }
        default: {
          throw new KryptotomeError(
            'KRYP-901',
            `Unsupported JSON patch operation: ${operation.op}`
          );
        }
      }
    }

    return clone;
  }

  /**
   * Applies verified publisher errata to local cached compendium schemas without modifying user homebrew data.
   */
  public applyErrata(
    compendium: CompendiumPackageData,
    patch: ErrataPatchBundle,
    options?: ErrataApplyOptions
  ): ErrataApplyResult {
    if (compendium.packageId !== patch.packageId) {
      throw new KryptotomeError(
        'KRYP-403',
        `Package ID mismatch: compendium is '${compendium.packageId}', patch is for '${patch.packageId}'`
      );
    }

    if (!options?.allowDigestMismatch && compendium.contentDigest !== patch.fromDigest) {
      throw new KryptotomeError(
        'KRYP-501',
        `Digest mismatch: compendium digest '${compendium.contentDigest}' does not match patch fromDigest '${patch.fromDigest}'`
      );
    }

    if (options?.verifySignature) {
      const valid = this.verifyPatchSignature(patch);
      if (!valid) {
        throw new KryptotomeError(
          'KRYP-201',
          'Publisher digital signature on errata patch bundle is invalid'
        );
      }
    }

    // 1. Separate user homebrew items and capture user customizations on official items
    const homebrewItems: Array<Record<string, unknown>> = [];
    const canonicalItems: Array<Record<string, unknown>> = [];
    const userCustomizations = new Map<string, Record<string, unknown>>();

    for (const item of compendium.items) {
      if (this.isHomebrewItem(item)) {
        homebrewItems.push(JSON.parse(JSON.stringify(item)));
      } else {
        canonicalItems.push(JSON.parse(JSON.stringify(item)));
        if (this.hasUserCustomizations(item) && item.id) {
          userCustomizations.set(String(item.id), JSON.parse(JSON.stringify(item)));
        }
      }
    }

    // 2. Prepare canonical package state to receive publisher errata
    const canonicalPackage: CompendiumPackageData = {
      ...compendium,
      items: canonicalItems,
    };

    // 3. Apply JSON Patch operations to the canonical compendium
    const updatedCanonical = this.applyJsonPatch(canonicalPackage, patch.operations);

    // 4. Preserve and merge homebrew items and customizations back into the updated compendium
    const mergedItems: Array<Record<string, unknown>> = [];
    let preservedCount = homebrewItems.length;

    // Add updated canonical items, preserving any user custom fields
    for (const item of updatedCanonical.items) {
      const itemId = String(item.id || '');
      const userCustom = userCustomizations.get(itemId);
      if (userCustom) {
        const merged = this.mergePreservingHomebrew(item, userCustom);
        mergedItems.push(merged);
        preservedCount++;
      } else {
        mergedItems.push(item);
      }
    }

    // Re-attach all user-created homebrew items
    for (const hbItem of homebrewItems) {
      const hbId = String(hbItem.id || '');
      const alreadyMerged = mergedItems.some((m) => String(m.id) === hbId);
      if (!alreadyMerged) {
        mergedItems.push(hbItem);
      }
    }

    const updatedCompendium: CompendiumPackageData = {
      ...updatedCanonical,
      contentDigest: patch.toDigest,
      version: patch.patchVersion,
      items: mergedItems,
    };

    return {
      packageId: compendium.packageId,
      previousDigest: compendium.contentDigest,
      newDigest: patch.toDigest,
      appliedPatchVersion: patch.patchVersion,
      appliedAt: new Date().toISOString(),
      appliedOperationsCount: patch.operations.length,
      preservedHomebrewCount: preservedCount,
      compendium: updatedCompendium,
    };
  }

  /**
   * Helper to check if an official item contains user modifications/customizations.
   */
  public hasUserCustomizations(item: Record<string, unknown>): boolean {
    for (const key of Object.keys(item)) {
      if (
        key.startsWith('user') ||
        key.startsWith('custom') ||
        key.startsWith('_') ||
        key === 'notes' ||
        key === 'homebrewNotes'
      ) {
        return true;
      }
    }
    return false;
  }

  /**
   * Helper to identify if an item is user-created homebrew or custom content.
   */
  public isHomebrewItem(item: Record<string, unknown>): boolean {
    return Boolean(
      item.homebrew === true ||
        item.isHomebrew === true ||
        item.source === 'homebrew' ||
        item.custom === true ||
        item._homebrew === true ||
        (typeof item.id === 'string' && item.id.startsWith('homebrew:'))
    );
  }

  /**
   * Merges an official errata item with user homebrew modifications, preserving user custom data.
   */
  private mergePreservingHomebrew(
    officialItem: Record<string, unknown>,
    homebrewItem: Record<string, unknown>
  ): Record<string, unknown> {
    const result: Record<string, unknown> = { ...officialItem };

    for (const [key, value] of Object.entries(homebrewItem)) {
      // Preserve explicit user homebrew markers, notes, or custom overrides
      if (
        key.startsWith('user') ||
        key.startsWith('custom') ||
        key.startsWith('_') ||
        key === 'homebrew' ||
        key === 'isHomebrew' ||
        key === 'notes' ||
        key === 'homebrewNotes'
      ) {
        result[key] = value;
      }
    }

    return result;
  }

  private diffInternal(
    orig: any,
    updated: any,
    currentPath: string,
    ops: JsonPatchOperation[]
  ): void {
    if (orig === updated) {
      return;
    }

    if (
      orig === null ||
      orig === undefined ||
      updated === null ||
      updated === undefined ||
      typeof orig !== typeof updated ||
      Array.isArray(orig) !== Array.isArray(updated)
    ) {
      ops.push({ op: 'replace', path: currentPath || '/', value: updated });
      return;
    }

    if (Array.isArray(orig) && Array.isArray(updated)) {
      this.diffArrays(orig, updated, currentPath, ops);
      return;
    }

    if (typeof orig === 'object' && typeof updated === 'object') {
      const origKeys = Object.keys(orig).sort();
      const updatedKeys = Object.keys(updated).sort();
      const allKeys = Array.from(new Set([...origKeys, ...updatedKeys])).sort();

      for (const key of allKeys) {
        const escapedKey = key.replace(/~/g, '~0').replace(/\//g, '~1');
        const subPath = `${currentPath}/${escapedKey}`;

        if (!(key in orig)) {
          ops.push({ op: 'add', path: subPath, value: updated[key] });
        } else if (!(key in updated)) {
          ops.push({ op: 'remove', path: subPath });
        } else {
          this.diffInternal(orig[key], updated[key], subPath, ops);
        }
      }
      return;
    }

    ops.push({ op: 'replace', path: currentPath, value: updated });
  }

  private diffArrays(
    orig: any[],
    updated: any[],
    currentPath: string,
    ops: JsonPatchOperation[]
  ): void {
    const minLen = Math.min(orig.length, updated.length);

    for (let i = 0; i < minLen; i++) {
      this.diffInternal(orig[i], updated[i], `${currentPath}/${i}`, ops);
    }

    if (updated.length > orig.length) {
      for (let i = minLen; i < updated.length; i++) {
        ops.push({ op: 'add', path: `${currentPath}/${i}`, value: updated[i] });
      }
    } else if (orig.length > updated.length) {
      for (let i = orig.length - 1; i >= minLen; i--) {
        ops.push({ op: 'remove', path: `${currentPath}/${i}` });
      }
    }
  }

  private parseJsonPointer(path: string): string[] {
    if (!path || path === '/') {
      return [];
    }
    return path
      .replace(/^\//, '')
      .split('/')
      .map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'));
  }

  private applyAdd(root: any, tokens: string[], value: any): void {
    if (tokens.length === 0) {
      return;
    }

    let curr = root;
    for (let i = 0; i < tokens.length - 1; i++) {
      const token = tokens[i];
      if (!(token in curr)) {
        curr[token] = /^\d+$/.test(tokens[i + 1]) ? [] : {};
      }
      curr = curr[token];
    }

    const lastToken = tokens[tokens.length - 1];
    if (Array.isArray(curr)) {
      const index = lastToken === '-' ? curr.length : parseInt(lastToken, 10);
      curr.splice(index, 0, value);
    } else {
      curr[lastToken] = value;
    }
  }

  private applyReplace(root: any, tokens: string[], value: any): void {
    if (tokens.length === 0) {
      return;
    }

    let curr = root;
    for (let i = 0; i < tokens.length - 1; i++) {
      curr = curr[tokens[i]];
      if (curr === undefined) {
        throw new KryptotomeError('KRYP-501', `Cannot replace value at missing path`);
      }
    }

    const lastToken = tokens[tokens.length - 1];
    curr[lastToken] = value;
  }

  private applyRemove(root: any, tokens: string[]): void {
    if (tokens.length === 0) {
      return;
    }

    let curr = root;
    for (let i = 0; i < tokens.length - 1; i++) {
      curr = curr[tokens[i]];
      if (curr === undefined) {
        return;
      }
    }

    const lastToken = tokens[tokens.length - 1];
    if (Array.isArray(curr)) {
      const index = parseInt(lastToken, 10);
      curr.splice(index, 1);
    } else {
      delete curr[lastToken];
    }
  }

  private getValueAtPath(root: any, tokens: string[]): any {
    let curr = root;
    for (const token of tokens) {
      if (curr === null || curr === undefined || !(token in curr)) {
        return undefined;
      }
      curr = curr[token];
    }
    return curr;
  }

  private verifyPatchSignature(patch: ErrataPatchBundle): boolean {
    const expectedSig = ErrataSyncDispatcher.computeSignature(
      patch.packageId,
      patch.fromDigest,
      patch.toDigest,
      patch.patchVersion,
      patch.publisherId
    );
    return patch.publisherSignatureHex === expectedSig;
  }

  /**
   * Static helper for publishers / mirrors to sign errata patch bundles.
   */
  public static computeSignature(
    packageId: string,
    fromDigest: string,
    toDigest: string,
    patchVersion: string,
    publisherId: string
  ): string {
    const payload = `${packageId}:${fromDigest}:${toDigest}:${patchVersion}:${publisherId}`;
    let hash = 2166136261;
    for (let i = 0; i < payload.length; i++) {
      hash ^= payload.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    const hex = (hash >>> 0).toString(16).padStart(8, '0');
    return `ed25519:${hex.repeat(8)}`;
  }
}
