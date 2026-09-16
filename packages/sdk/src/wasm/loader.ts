import defaultInit, {
  initSync as initSyncWasm,
  type InitInput,
  type InitOutput,
  type SyncInitInput,
} from './kryptotome_wasm.js';
import { KryptotomeError } from '../error.js';

export interface WasmInitOptions {
  /**
   * Custom WebAssembly source: URL, file path, Response, BufferSource, or precompiled WebAssembly.Module
   */
  moduleOrPath?: InitInput;
  /**
   * Force re-instantiation even if already initialized
   */
  force?: boolean;
}

let wasmInstance: InitOutput | null = null;
let initPromise: Promise<InitOutput> | null = null;

/**
 * Checks whether the Kryptotome WebAssembly module is initialized
 */
export function isWasmInitialized(): boolean {
  return wasmInstance !== null;
}

/**
 * Returns the initialized WebAssembly module instance, or throws if not initialized
 */
export function getWasmModule(): InitOutput {
  if (!wasmInstance) {
    throw new KryptotomeError(
      'KRYP-903',
      'Kryptotome WebAssembly module has not been initialized. Call await initWasm() before invoking verification routines.'
    );
  }
  return wasmInstance;
}

/**
 * Resolves candidate filesystem URLs for locating kryptotome_wasm_bg.wasm in Node.js
 */
function getNodeCandidateUrls(): URL[] {
  return [
    new URL('./kryptotome_wasm_bg.wasm', import.meta.url),
    new URL('../../wasm/kryptotome_wasm_bg.wasm', import.meta.url),
    new URL('../../../wasm/kryptotome_wasm_bg.wasm', import.meta.url),
    new URL('../wasm/kryptotome_wasm_bg.wasm', import.meta.url),
  ];
}

/**
 * Attempts to load the WebAssembly binary from the local filesystem in Node.js environments
 */
async function loadWasmFromNodeFs(candidates: URL[]): Promise<Uint8Array | null> {
  if (typeof process === 'undefined' || !process.versions?.node) {
    return null;
  }
  try {
    const { readFile } = await import('node:fs/promises');
    const { fileURLToPath } = await import('node:url');
    for (const url of candidates) {
      try {
        const filePath = fileURLToPath(url);
        const buffer = await readFile(filePath);
        return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      } catch {
        // Continue to next candidate
      }
    }
  } catch {
    // Dynamic import of node:fs failed (non-Node environment or bundler shim)
  }
  return null;
}

/**
 * Synchronously attempts to load the WebAssembly binary in Node.js environments
 */
function loadWasmFromNodeFsSync(candidates: URL[]): Uint8Array | null {
  if (typeof process === 'undefined' || !process.versions?.node) {
    return null;
  }
  try {
    // Check if node:fs is available synchronously via require or process.getBuiltinModule
    const nodeFs = (typeof process !== 'undefined' && 'getBuiltinModule' in process)
      ? (process as { getBuiltinModule: (id: string) => typeof import('node:fs') }).getBuiltinModule('node:fs')
      : undefined;
    const nodeUrl = (typeof process !== 'undefined' && 'getBuiltinModule' in process)
      ? (process as { getBuiltinModule: (id: string) => typeof import('node:url') }).getBuiltinModule('node:url')
      : undefined;

    if (nodeFs?.readFileSync && nodeUrl?.fileURLToPath) {
      for (const url of candidates) {
        try {
          const filePath = nodeUrl.fileURLToPath(url);
          const buffer = nodeFs.readFileSync(filePath);
          return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        } catch {
          // Continue
        }
      }
    }
  } catch {
    // Non-Node environment
  }
  return null;
}

/**
 * Asynchronously initializes the Kryptotome WebAssembly module for use across Node.js,
 * browser, Web Worker, and Electron renderer environments.
 *
 * Calls are safely deduplicated to avoid duplicate instantiation overhead.
 */
export async function initWasm(options?: WasmInitOptions): Promise<InitOutput> {
  if (wasmInstance && !options?.force) {
    return wasmInstance;
  }

  if (initPromise && !options?.force) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      let input: InitInput | undefined = options?.moduleOrPath;

      if (!input) {
        // 1. Attempt Node.js local file resolution first
        const nodeBytes = await loadWasmFromNodeFs(getNodeCandidateUrls());
        if (nodeBytes) {
          input = nodeBytes;
        } else {
          // 2. Default browser / bundler URL resolution
          input = new URL('kryptotome_wasm_bg.wasm', import.meta.url);
        }
      }

      const instance = await defaultInit({ module_or_path: input });
      wasmInstance = instance;
      return instance;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      throw new KryptotomeError(
        'KRYP-903',
        `Failed to initialize Kryptotome WebAssembly module: ${message}`,
        err
      );
    } finally {
      if (!wasmInstance) {
        initPromise = null;
      }
    }
  })();

  return initPromise;
}

/**
 * Synchronously initializes the Kryptotome WebAssembly module using pre-compiled bytes or module.
 */
export function initWasmSync(bytesOrModule?: SyncInitInput): InitOutput {
  if (wasmInstance) {
    return wasmInstance;
  }

  let input = bytesOrModule;
  if (!input) {
    const nodeBytes = loadWasmFromNodeFsSync(getNodeCandidateUrls());
    if (nodeBytes) {
      input = nodeBytes;
    } else {
      throw new KryptotomeError(
        'KRYP-903',
        'Cannot synchronously initialize WebAssembly without preloaded bytes outside Node.js. Use await initWasm() instead.'
      );
    }
  }

  try {
    const instance = initSyncWasm({ module: input });
    wasmInstance = instance;
    return instance;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    throw new KryptotomeError(
      'KRYP-903',
      `Failed to synchronously initialize Kryptotome WebAssembly module: ${message}`,
      err
    );
  }
}
