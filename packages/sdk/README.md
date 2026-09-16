# @kryptotome/sdk

**TypeScript SDK, WebAssembly verifier bridge, and client runtime for the Kryptotome Protocol.**

`@kryptotome/sdk` provides client-side zero-knowledge proof verification, local vault interactions, table session authorization, and dynamic compendium synchronization for browser and Node.js environments.

---

## Features

- **Embedded WebAssembly Verifier**: High-performance verifier bindings (`WasmVerifier`, `WasmSessionManager`) compiled from Rust.
- **Web Worker Offloading**: `WorkerVerifierBridge` for offloading cryptographic pairing and ZK proof verification off the main UI event loop.
- **Dynamic Errata & Sync Dispatcher**: `ErrataSyncDispatcher` supporting RFC 6902 JSON patches with strict preservation of user homebrew items and custom annotations.
- **Table Session Sharing**: Ephemeral Ed25519 table session token verification and dynamic scoping for Virtual Tabletop sessions.
- **Strict Standards Compliance**: Enforces [W3C VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) and Kryptotome Error Taxonomy (`KRYP-100` through `KRYP-900`).

---

## Installation

```bash
npm install @kryptotome/sdk
```

---

## Usage

### 1. Dynamic Errata Synchronization with Homebrew Preservation

The `ErrataSyncDispatcher` polls official mirrors with authenticated ZK proof headers and applies RFC 6902 delta patches without overwriting or stripping custom homebrew rules:

```typescript
import { ErrataSyncDispatcher } from '@kryptotome/sdk';

const dispatcher = new ErrataSyncDispatcher('https://mirror.example.com/errata');

// 1. Check mirror for updates with proof of ownership
const patchBundle = await dispatcher.checkForErrata(
  'open-rpg/core-rules',
  'sha256-original-digest',
  zkProofToken
);

// 2. Apply patch while safeguarding homebrew items and custom fields
if (patchBundle) {
  const result = dispatcher.applyErrata(compendiumData, patchBundle);
  console.log(`Applied patch v${result.updatedPackage.version}`);
  console.log(`Preserved ${result.preservedHomebrewCount} homebrew items.`);
}
```

### 2. Embedded WASM Verifier & Web Worker

```typescript
import { WasmLoader, WorkerVerifierBridge } from '@kryptotome/sdk';

// Main-thread WASM execution
await WasmLoader.init();
const verifier = WasmLoader.createVerifier();
const isValid = verifier.verifyPresentation(proofBundleJson);

// Or offload to Web Worker to prevent UI frame drops
const workerBridge = new WorkerVerifierBridge();
await workerBridge.init();
const result = await workerBridge.verifyProof(proofBundleJson);
```

### 3. Running Performance Benchmarks

`@kryptotome/sdk` includes automated CI performance benchmarks verifying protocol SLAs:

```bash
# Run benchmark suite via root or package script
npm run bench
```

Target benchmarks enforced:
- **Verification Latency**: $< 10\text{ ms}$ on single CPU core.
- **Proving Latency**: $< 200\text{ ms}$ on desktop/mobile.
- **WASM Footprint**: $< 2\text{ MB}$ raw stripped binary.
- **Memory Footprint**: $< 16\text{ MB}$ verifier memory delta.

---

## License

Apache-2.0
