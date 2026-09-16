export {
  initWasm,
  initWasmSync,
  isWasmInitialized,
  getWasmModule,
  type WasmInitOptions,
} from './loader.js';

export { WasmVerificationEngine } from './verifier.js';
export { WasmSessionEngine } from './session.js';
export { WasmWorkerBridge, type WasmWorkerOptions } from './worker-bridge.js';
export {
  handleWorkerRequest,
  type WorkerRequestMessage,
  type WorkerResponseMessage,
} from './worker-runtime.js';

// Low-level WebAssembly classes and types
export {
  WasmVerifier,
  WasmSessionManager,
  type InitInput,
  type InitOutput,
  type SyncInitInput,
} from './kryptotome_wasm.js';

