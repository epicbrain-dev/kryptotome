import type { ZkProof } from './types.js';

export interface SyncOptions {
  publisherMirrorUrl: string;
  packageId: string;
  currentVersion: string;
}

export interface ErrataPatch {
  packageId: string;
  patchVersion: string;
  appliedAt: string;
  schemaDiffCount: number;
}

export class ErrataSyncDispatcher {
  /**
   * Polls verified publisher mirrors for schema updates using proof attestations
   */
  public async checkForErrata(
    _options: SyncOptions,
    proofAttestation: ZkProof
  ): Promise<ErrataPatch | null> {
    if (!proofAttestation.proofBytes) {
      throw new Error('Valid proof attestation required to query mirror errata');
    }

    // In functionality phase, perform authenticated GET to mirror
    // with ZK proof header: Authorization: KryptotomeProof <b64>
    return null;
  }
}
