import { initWasm, type WasmInitOptions } from './loader.js';
import { WasmVerificationEngine } from './verifier.js';
import { WasmSessionEngine } from './session.js';
import { KryptotomeError, type KryptotomeErrorCode } from '../error.js';
import type { ChallengeNonce, EntitlementProofBundle, SessionAttestation, ZkProof } from '../types.js';

export interface WorkerRequestMessage {
  id: string;
  action:
    | 'INIT'
    | 'VERIFY_ZK_PROOF'
    | 'VERIFY_PROOF_BUNDLE'
    | 'IS_PACKAGE_UNLOCKED'
    | 'INVALIDATE_PACKAGE'
    | 'RELOAD_PACKAGE'
    | 'INVALIDATE_IF_DIGEST_MISMATCH'
    | 'EXIT_SESSION'
    | 'PRUNE_EXPIRED'
    | 'SET_CACHE_TTL'
    | 'SESSION_INIT'
    | 'HOST_PUBLIC_KEY'
    | 'ISSUE_PEER_ATTESTATION'
    | 'VERIFY_PEER_ATTESTATION';
  payload?: any;
}

export interface WorkerResponseMessage {
  id: string;
  success: boolean;
  result?: any;
  error?: {
    code: KryptotomeErrorCode;
    message: string;
    details?: unknown;
  };
}

let verifier: WasmVerificationEngine | null = null;
let sessionEngines: Map<string, WasmSessionEngine> = new Map();

/**
 * Handles incoming RPC commands inside the Web Worker context.
 */
export async function handleWorkerRequest(req: WorkerRequestMessage): Promise<WorkerResponseMessage> {
  const { id, action, payload } = req;

  try {
    switch (action) {
      case 'INIT': {
        await initWasm(payload as WasmInitOptions);
        if (!verifier) {
          verifier = new WasmVerificationEngine();
        }
        return { id, success: true, result: true };
      }

      case 'VERIFY_ZK_PROOF': {
        if (!verifier) {
          await initWasm();
          verifier = new WasmVerificationEngine();
        }
        const { publisherVkHex, challenge, proof } = payload as {
          publisherVkHex: string;
          challenge: ChallengeNonce;
          proof: ZkProof;
        };
        const result = verifier.verifyZkProof(publisherVkHex, challenge, proof);
        return { id, success: true, result };
      }

      case 'VERIFY_PROOF_BUNDLE': {
        if (!verifier) {
          await initWasm();
          verifier = new WasmVerificationEngine();
        }
        const { bundle, challenge } = payload as {
          bundle: EntitlementProofBundle;
          challenge: ChallengeNonce;
        };
        const result = verifier.verifyProofBundle(bundle, challenge);
        return { id, success: true, result };
      }

      case 'IS_PACKAGE_UNLOCKED': {
        if (!verifier) {
          return { id, success: true, result: false };
        }
        const { packageId } = payload as { packageId: string };
        const result = verifier.isPackageUnlocked(packageId);
        return { id, success: true, result };
      }

      case 'INVALIDATE_PACKAGE': {
        if (!verifier) return { id, success: true, result: false };
        const { packageId } = payload as { packageId: string };
        return { id, success: true, result: verifier.invalidatePackage(packageId) };
      }

      case 'RELOAD_PACKAGE': {
        if (!verifier) return { id, success: true, result: false };
        const { packageId } = payload as { packageId: string };
        return { id, success: true, result: verifier.reloadPackage(packageId) };
      }

      case 'INVALIDATE_IF_DIGEST_MISMATCH': {
        if (!verifier) return { id, success: true, result: false };
        const { packageId, currentDigest } = payload as { packageId: string; currentDigest: string };
        return { id, success: true, result: verifier.invalidateIfDigestMismatch(packageId, currentDigest) };
      }

      case 'EXIT_SESSION': {
        if (!verifier) return { id, success: true, result: 0 };
        return { id, success: true, result: verifier.exitSession() };
      }

      case 'PRUNE_EXPIRED': {
        if (!verifier) return { id, success: true, result: 0 };
        return { id, success: true, result: verifier.pruneExpired() };
      }

      case 'SET_CACHE_TTL': {
        if (!verifier) {
          await initWasm();
          verifier = new WasmVerificationEngine();
        }
        const { seconds } = payload as { seconds: number };
        verifier.setCacheTtlSeconds(seconds);
        return { id, success: true, result: true };
      }

      case 'SESSION_INIT': {
        await initWasm();
        const { sessionId } = payload as { sessionId: string };
        const engine = new WasmSessionEngine(sessionId);
        sessionEngines.set(sessionId, engine);
        return { id, success: true, result: engine.hostPublicKeyHex() };
      }

      case 'HOST_PUBLIC_KEY': {
        const { sessionId } = payload as { sessionId: string };
        const engine = sessionEngines.get(sessionId);
        if (!engine) {
          throw new KryptotomeError('KRYP-704', `Session "${sessionId}" not found in worker`);
        }
        return { id, success: true, result: engine.hostPublicKeyHex() };
      }

      case 'ISSUE_PEER_ATTESTATION': {
        const { sessionId, recipientPeerId, packageId, contentDigest, scopes, durationMinutes } =
          payload as {
            sessionId: string;
            recipientPeerId: string;
            packageId: string;
            contentDigest: string;
            scopes: string[];
            durationMinutes: number;
          };
        const engine = sessionEngines.get(sessionId);
        if (!engine) {
          throw new KryptotomeError('KRYP-704', `Session "${sessionId}" not found in worker`);
        }
        const attestation = engine.issuePeerAttestation(
          recipientPeerId,
          packageId,
          contentDigest,
          scopes,
          durationMinutes
        );
        return { id, success: true, result: attestation };
      }

      case 'VERIFY_PEER_ATTESTATION': {
        await initWasm();
        const { attestation, hostPubkeyHex } = payload as {
          attestation: SessionAttestation | string;
          hostPubkeyHex: string;
        };
        const result = WasmSessionEngine.verifyPeerAttestation(attestation, hostPubkeyHex);
        return { id, success: true, result };
      }

      default:
        throw new KryptotomeError('KRYP-903', `Unknown worker action: ${action}`);
    }
  } catch (err: unknown) {
    if (err instanceof KryptotomeError) {
      return {
        id,
        success: false,
        error: {
          code: err.code,
          message: err.message,
          details: err.details,
        },
      };
    }
    const message = err instanceof Error ? err.message : String(err);
    return {
      id,
      success: false,
      error: {
        code: 'KRYP-903',
        message,
      },
    };
  }
}

// Auto-register listeners in worker contexts
if (typeof process !== 'undefined' && process.versions?.node) {
  import('node:worker_threads')
    .then(({ parentPort }) => {
      if (parentPort) {
        parentPort.on('message', async (msg: WorkerRequestMessage) => {
          const res = await handleWorkerRequest(msg);
          parentPort.postMessage(res);
        });
      }
    })
    .catch(() => {});
}

if (typeof self !== 'undefined' && typeof (self as any).postMessage === 'function') {
  (self as any).addEventListener('message', async (event: any) => {
    const msg = event.data as WorkerRequestMessage;
    if (msg && msg.id && msg.action) {
      const res = await handleWorkerRequest(msg);
      (self as any).postMessage(res);
    }
  });
}
