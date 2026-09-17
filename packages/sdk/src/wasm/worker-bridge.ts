import type { ChallengeNonce, EntitlementProofBundle, SessionAttestation, ZkProof } from '../types.js';
import { KryptotomeError } from '../error.js';
import type { WasmInitOptions } from './loader.js';
import type { WorkerRequestMessage, WorkerResponseMessage } from './worker-runtime.js';

export interface WasmWorkerOptions {
  /**
   * Custom worker script URL or file path. Defaults to `./worker-runtime.js`.
   */
  workerUrl?: string | URL;
  /**
   * Optional factory function to instantiate a custom Web Worker or Node Worker.
   * Recommended for bundlers like Vite, Webpack, or Rollup:
   * e.g. `workerFactory: () => new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })`
   */
  workerFactory?: () => any | Promise<any>;
  /**
   * Optional pre-existing Web Worker or Node Worker instance.
   */
  worker?: any;
  /**
   * Custom WASM initialization options for the worker.
   */
  wasmInitOptions?: WasmInitOptions;
}

interface PendingCall {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
  action: string;
}

/**
 * High-level client bridge that offloads zero-knowledge proof verification,
 * entitlement cache operations, and ephemeral table session token signing to a background
 * Web Worker or Node worker thread.
 *
 * Prevents main UI thread hitching or frame drops in virtual tabletop applications.
 */
export class WasmWorkerBridge {
  private worker: any;
  private pendingCalls = new Map<string, PendingCall>();
  private requestCounter = 0;
  private isTerminated = false;
  private isInitialized = false;

  constructor(private options: WasmWorkerOptions = {}) {}

  /**
   * Initializes the background worker and mounts the Kryptotome WebAssembly module.
   */
  public async init(): Promise<void> {
    if (this.isInitialized) return;
    this.assertNotTerminated();

    if (!this.worker) {
      this.worker = await this.spawnWorker();
      this.attachWorkerListeners();
    }

    await this.sendRequest('INIT', this.options.wasmInitOptions);
    this.isInitialized = true;
  }

  /**
   * Verifies a zero-knowledge entitlement proof in the background worker thread.
   */
  public async verifyZkProof(
    publisherVkHex: string,
    challenge: ChallengeNonce,
    proof: ZkProof
  ): Promise<boolean> {
    await this.ensureReady();
    return this.sendRequest('VERIFY_ZK_PROOF', { publisherVkHex, challenge, proof });
  }

  /**
   * Verifies a self-contained entitlement proof bundle in the background worker thread.
   */
  public async verifyProofBundle(
    bundle: EntitlementProofBundle,
    challenge: ChallengeNonce
  ): Promise<boolean> {
    await this.ensureReady();
    return this.sendRequest('VERIFY_PROOF_BUNDLE', { bundle, challenge });
  }

  /**
   * Checks if a package is currently unlocked in the worker's session cache.
   */
  public async isPackageUnlocked(packageId: string): Promise<boolean> {
    await this.ensureReady();
    return this.sendRequest('IS_PACKAGE_UNLOCKED', { packageId });
  }

  /**
   * Invalidates a package from the worker's cache.
   */
  public async invalidatePackage(packageId: string): Promise<boolean> {
    await this.ensureReady();
    return this.sendRequest('INVALIDATE_PACKAGE', { packageId });
  }

  /**
   * Reloads a package in the worker cache.
   */
  public async reloadPackage(packageId: string): Promise<boolean> {
    await this.ensureReady();
    return this.sendRequest('RELOAD_PACKAGE', { packageId });
  }

  /**
   * Invalidates package cache if content digest does not match.
   */
  public async invalidateIfDigestMismatch(packageId: string, currentDigest: string): Promise<boolean> {
    await this.ensureReady();
    return this.sendRequest('INVALIDATE_IF_DIGEST_MISMATCH', { packageId, currentDigest });
  }

  /**
   * Exits the current active session in the worker, purging all cached packages.
   */
  public async exitSession(): Promise<number> {
    await this.ensureReady();
    return this.sendRequest('EXIT_SESSION');
  }

  /**
   * Prunes expired entitlements in the worker cache.
   */
  public async pruneExpired(): Promise<number> {
    await this.ensureReady();
    return this.sendRequest('PRUNE_EXPIRED');
  }

  /**
   * Configures cache TTL in the worker verifier.
   */
  public async setCacheTtlSeconds(seconds: number): Promise<void> {
    await this.ensureReady();
    await this.sendRequest('SET_CACHE_TTL', { seconds });
  }

  /**
   * Initializes an ephemeral table session manager inside the worker thread.
   * Returns the host Ed25519 public key hex.
   */
  public async initSession(sessionId: string): Promise<string> {
    await this.ensureReady();
    return this.sendRequest('SESSION_INIT', { sessionId });
  }

  /**
   * Retrieves the host public key for an initialized session from the worker.
   */
  public async getHostPublicKey(sessionId: string): Promise<string> {
    await this.ensureReady();
    return this.sendRequest('HOST_PUBLIC_KEY', { sessionId });
  }

  /**
   * Issues an ephemeral peer session attestation token inside the worker thread.
   */
  public async issuePeerAttestation(
    sessionId: string,
    recipientPeerId: string,
    packageId: string,
    contentDigest: string,
    scopes: string[],
    durationMinutes: number
  ): Promise<SessionAttestation> {
    await this.ensureReady();
    return this.sendRequest('ISSUE_PEER_ATTESTATION', {
      sessionId,
      recipientPeerId,
      packageId,
      contentDigest,
      scopes,
      durationMinutes,
    });
  }

  /**
   * Validates a peer attestation token in the worker thread.
   */
  public async verifyPeerAttestation(
    attestation: SessionAttestation | string,
    hostPubkeyHex: string
  ): Promise<boolean> {
    await this.ensureReady();
    return this.sendRequest('VERIFY_PEER_ATTESTATION', { attestation, hostPubkeyHex });
  }

  /**
   * Terminates the background worker thread and rejects any pending operations.
   */
  public async terminate(): Promise<void> {
    if (this.isTerminated) return;
    this.isTerminated = true;

    // Reject all pending calls
    const err = new KryptotomeError('KRYP-903', 'Worker terminated before response was received');
    for (const pending of this.pendingCalls.values()) {
      pending.reject(err);
    }
    this.pendingCalls.clear();

    if (this.worker) {
      if (typeof this.worker.terminate === 'function') {
        await this.worker.terminate();
      } else if (typeof this.worker.close === 'function') {
        this.worker.close();
      }
      this.worker = null;
    }
  }

  public async [Symbol.asyncDispose](): Promise<void> {
    await this.terminate();
  }

  private async ensureReady(): Promise<void> {
    if (!this.isInitialized) {
      await this.init();
    }
  }

  private assertNotTerminated(): void {
    if (this.isTerminated) {
      throw new KryptotomeError(
        'KRYP-903',
        'WasmWorkerBridge has been terminated and cannot process further requests'
      );
    }
  }

  private async spawnWorker(): Promise<any> {
    if (this.options.worker) {
      return this.options.worker;
    }

    if (this.options.workerFactory) {
      return await this.options.workerFactory();
    }

    const defaultUrl = this.options.workerUrl ?? new URL('./worker-runtime.js', import.meta.url);

    // 1. Node.js environment
    if (typeof process !== 'undefined' && process.versions?.node) {
      const { Worker } = await import('node:worker_threads');
      const { fileURLToPath } = await import('node:url');
      const filePath = defaultUrl instanceof URL ? fileURLToPath(defaultUrl) : defaultUrl;
      return new Worker(filePath);
    }

    // 2. Browser / Web Worker / Electron renderer
    if (typeof Worker !== 'undefined') {
      return new Worker(defaultUrl, { type: 'module' });
    }

    throw new KryptotomeError(
      'KRYP-903',
      'Neither Web Worker nor Node.js worker_threads are supported in this environment'
    );
  }

  private attachWorkerListeners(): void {
    const onMessage = (msg: WorkerResponseMessage) => {
      if (!msg || !msg.id) return;
      const pending = this.pendingCalls.get(msg.id);
      if (!pending) return;

      this.pendingCalls.delete(msg.id);

      if (msg.success) {
        pending.resolve(msg.result);
      } else {
        const errorPayload = msg.error;
        const code = errorPayload?.code ?? 'KRYP-903';
        const message = errorPayload?.message ?? 'Worker execution failed';
        pending.reject(new KryptotomeError(code, message, errorPayload?.details));
      }
    };

    const onError = (err: any) => {
      const errorObj = err instanceof Error ? err : new Error(String(err));
      for (const pending of this.pendingCalls.values()) {
        pending.reject(
          new KryptotomeError('KRYP-903', `Worker runtime exception: ${errorObj.message}`, errorObj)
        );
      }
      this.pendingCalls.clear();
    };

    if (typeof this.worker.on === 'function') {
      // Node worker_threads.Worker
      this.worker.on('message', onMessage);
      this.worker.on('error', onError);
    } else if (typeof this.worker.addEventListener === 'function') {
      // Browser / Web Worker
      this.worker.addEventListener('message', (ev: any) => onMessage(ev.data));
      this.worker.addEventListener('error', onError);
    }
  }

  private sendRequest<T = any>(action: string, payload?: any): Promise<T> {
    this.assertNotTerminated();

    const id = `req-${++this.requestCounter}-${Date.now()}`;
    const req: WorkerRequestMessage = { id, action: action as any, payload };

    return new Promise<T>((resolve, reject) => {
      this.pendingCalls.set(id, { resolve, reject, action });
      this.worker.postMessage(req);
    });
  }
}
