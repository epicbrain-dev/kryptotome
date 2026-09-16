# Kryptotome Protocol: Engineering Implementation & Testing Checklist

This document tracks all modules, features, cryptographic circuits, integrations, performance targets, and testbeds required to achieve full production readiness for the **Kryptotome Protocol**.

---

## 1. Protocol Architecture & Standards Compliance

- [x] Project repository scaffolding (Cargo workspace + TypeScript monorepo).
- [x] Machine-readable JSON Schemas for W3C VC v2.0, Package Manifest, and Session Tokens.
- [x] Positioning & Terminology Guide strictly prohibiting Web3/crypto jargon.
- [x] Implement full JSON-LD context resolution for `https://kryptotome.org/schemas/v1/context.jsonld`.
- [x] Validate strict compliance with [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
- [x] Define standardized error codes taxonomy (`KRYP-100` through `KRYP-900`) across Rust and TypeScript runtimes.

---

## 2. Core Cryptography & Zero-Knowledge Circuits (`kryptotome-core`)

### 2.1 Cryptographic Primitives
- [x] SHA-256 deterministic file and directory content digests.
- [x] Implement BLAKE3 content digesting option for large compendium asset libraries.
- [x] Ed25519 digital signature signing and verification models.
- [x] Select pairing-friendly elliptic curve suite (**BLS12-381** via `arkworks-rs` with ~128-bit security and ~1.3ms pairing latency).
- [x] Implement cryptographic commitment scheme (Pedersen on BLS12-381 G1) for binding holder secret key to credentials.

### 2.2 Zero-Knowledge Proof Circuit
- [x] Define R1CS / Plonk constraint circuit in `arkworks-rs`:
  - [x] **Private Witness**: Holder secret key $sk_H$, credential signature $\sigma_{pub}$, holder commitment randomness $r$.
  - [x] **Public Inputs**: Challenge nonce $N$, Package ID $P$, Content Digest $D$, Publisher Verification Key $PK_{pub}$, Holder Commitment $C_s$.
  - [x] **Circuit Constraint 1**: Prove knowledge of $sk_H$ such that $\text{Commit}(sk_H, r) == \text{HolderCommitment}$.
  - [x] **Circuit Constraint 2**: Prove valid signature $\sigma_{pub}$ over $(\text{PackageID}, \text{Digest}, \text{HolderCommitment})$ under $PK_{pub}$.
  - [x] **Circuit Constraint 3**: Bind challenge nonce $N$ into the public Fiat-Shamir / proof transcript.
- [x] Generate trusted setup parameters / universal SRS ceremony assets for the entitlement circuit (`generate_entitlement_setup`).
- [x] Implement proof serialization and deserialization targeting compact binary / base64 representations (`serialize_proof_compressed`, `serialize_proof_base64`, `EntitlementProofBundle`, canonical URN format).

---

## 3. Local Keychain & Vault Runtime (`kryptotome-vault`)

### 3.1 Key Custody
- [x] Base `Keyring` structure and asymmetric key generation (Ed25519).
- [x] Implement secure secret key zeroization on drop (`zeroize::Zeroize`, `zeroize::ZeroizeOnDrop`, `ZeroizingSecretKey`).
- [x] Platform OS Keychain / Keyring bindings (macOS Keychain, Windows Credential Manager, Linux Secret Service via `keyring-rs` / `PlatformKeyring`).
- [x] Support encrypted keystore with Argon2id passphrase derivation and AES-256-GCM / ChaCha20-Poly1305 (`EncryptedKeystore`).

### 3.2 Credential Lifecycle
- [x] In-memory credential store with package indexing (`VaultStore`).
- [x] Import and export of credentials via JSON.
- [x] Implement credential backup and restore encryption format (`.kryptotome-vault.enc`).
- [x] Support credential revocation checks via static publisher revocation lists / Merkle trees.

### 3.3 Proof Generation
- [x] Challenge nonce parsing and expiration validation.
- [x] Integrate full `arkworks` prover inside `create_proof_for_challenge`.
- [x] Ensure proof generation executes in $< 200\text{ms}$ on commodity hardware (measured $\approx 6.6\text{ms}$).
- [x] Ensure zero leakage of secret keys, holder identity, or correlatable session identifiers during proof generation (Groth16 zero-knowledge randomization and cryptographic zeroization).

---

## 4. Embedded Verification Engine & WASM (`kryptotome-verifier`, `kryptotome-wasm`)

### 4.1 Verifier Logic
- [x] Challenge nonce expiration check and public inputs verification.
- [x] Local entitlement cache (`EntitlementCache`) to avoid re-proving during an active game session.
- [x] Fast zero-knowledge proof verification pipeline:
  - [x] Arkworks Groth16 / Plonk pairing evaluation (`verify_entitlement_proof_prepared`, `verify_kzg_opening`, `verify_plonk_batch_opening`).
  - [x] Target verification latency: $< 10\text{ms}$ (measured $\approx 2.5\text{ms}$ on BLS12-381).
- [x] Cache invalidation rules (timeout, package reload, game session exit).

### 4.2 WebAssembly Target (`wasm32-unknown-unknown`)
- [x] `wasm-bindgen` bindings for `WasmVerifier` and `WasmSessionManager`.
- [x] Compile release WASM with `wasm-opt -Oz`.
- [x] Verify compiled `.wasm` file payload size $< 2\text{MB}$ (measured $\approx 558\text{KB}$).
- [x] Implement JavaScript / TypeScript WASM loader module (`@kryptotome/sdk/wasm`).
- [x] Test WASM execution inside Web Workers and Electron renderer processes without blocking the main UI thread.

---

## 5. Publisher Signing Toolchain CLI (`kryptotome-cli`)

- [x] CLI command parsing with `clap` (Commands: `sign-package`, `digest`, `keygen`, `vault-status`).
- [x] Deterministic directory traversal and content digest computation.
- [x] Manifest generation with package ID, publisher metadata, license attribution, and Ed25519 signature.
- [x] Support recursive directory scanning for multi-gigabyte compendiums with progress bars (`indicatif`).
- [x] Add manifest verification command: `kryptotome verify-manifest --manifest <path> --pubkey <key>`.
- [x] Support Paizo ORC, Creative Commons CC-BY-4.0, and CC0 license metadata validation.
- [x] Add batch signing and publisher release packaging command (`.ktome` archive bundling).

---

## 6. Table-Sharing Ephemeral Session Protocol

- [x] Ephemeral `SessionAttestation` data model and Ed25519 signature verification.
- [x] `SessionManager` for host/GM to issue time-scoped tokens for connected peers.
- [x] Peer authorization handshake protocol:
  - [x] Peer requests module access: sends `recipientPeerId` + requested `packageId`.
  - [x] Host checks local entitlement: verifies host owns module.
  - [x] Host issues signed `SessionAttestation` with short expiry (e.g. 4 hours).
  - [x] Peer validates host signature locally and mounts compendium in client memory.
- [x] Support dynamic scope limiting (e.g. GM allows players access to `spells` and `classes`, but hides `gm_notes` or `monsters`).
- [x] Session renewal and revocation mechanisms for disconnected peers.

---

## 7. Local Merchant Bridge Integrations (`@kryptotome/bridge`)

### 7.1 itch.io Bridge
- [x] Interface definition (`ItchIoBridge`).
- [x] Integrate itch.io OAuth / API token endpoint (`https://itch.io/api/1/key/me`).
- [x] Query user purchase library for registered Kryptotome publisher titles.
- [x] Derive local W3C VC v2.0 credential locally without transmitting private credentials to third-party servers.

### 7.2 DriveThruRPG Bridge
- [x] Interface definition (`DriveThruRpgBridge`).
- [x] Implement authentication using DriveThruRPG Account Application Keys.
- [x] Query user order history and digital library for supported rule packages.
- [x] Derive local W3C VC v2.0 credential bound to user key commitment.

### 7.3 Offline Air-Gapped Bridges
- [x] Support offline receipt / order confirmation file import (e.g. publisher signed digital invoice).
- [x] Air-gapped QR code import/export for mobile key vaults.

---

## 8. Dynamic Errata & Sync Dispatcher (`@kryptotome/sdk`)

- [x] Scaffold `ErrataSyncDispatcher`.
- [x] Implement authenticated mirror polling using proof attestations in HTTP headers:
  ```http
  GET /packages/{packageId}/updates HTTP/1.1
  X-Kryptotome-Proof: <proof-bytes>
  X-Kryptotome-Digest: <current-digest>
  ```
- [x] Compute deterministic JSON patch / delta updates for rule compendiums.
- [x] Automatically apply verified publisher errata to local cached compendium schemas without modifying user homebrew data.

---

## 9. Virtual Tabletop (VTT) & Client Integrations (`@kryptotome/vtt-adapter`)

- [x] Foundry VTT adapter scaffold (`FoundryVttAdapter`).
- [x] Implement Foundry VTT Compendium Pack hook:
  - [x] Intercept `CompendiumCollection.load()` or `getData()`.
  - [x] Check `EmbeddedVerifier.isPackageUnlocked(packageId)`.
  - [x] If locked, trigger challenge modal asking user to present credential proof from local vault.
  - [x] If unlocked, decrypt/load plaintext rule assets into canvas.
- [x] Integrate Foundry VTT WebRTC / SocketLib for seamless GM-to-player table session token dispatch.
- [x] Build reference UI components for prompt, unlock animation, and table sharing status.

---

## 10. Performance, Footprint, and Optimization Targets

- [x] **Verification Latency**: Benchmark proof verification to guarantee $< 10\text{ms}$ on single CPU core.
- [x] **Proving Latency**: Benchmark ZK proof generation to guarantee $< 200\text{ms}$ on desktop/mobile.
- [x] **WASM Binary Size**: Maintain stripped and compressed `.wasm` footprint $< 2\text{MB}$.
- [x] **Memory Footprint**: Keep embedded verifier memory footprint $< 16\text{MB}$ in browser runtime.
- [x] Add automated CI performance regression benchmarks using `criterion` (Rust) and `benchmark.js` (Node/Browser).

---

## 11. Security, Privacy, and Unlinkability Audits

- [ ] Mathematical unlinkability verification: Ensure that proofs generated across multiple challenge nonces cannot be clustered or linked to a single identity.
- [ ] Verify that zero Personally Identifiable Information (PII) is stored in credentials, manifests, or proofs.
- [ ] Verify immunity against replay attacks via nonce expiration and uniqueness checks.
- [ ] Conduct automated dependency audit (`cargo audit`, `npm audit`).
- [ ] Add fuzz testing for untrusted manifest and proof inputs using `cargo fuzz` (libFuzzer).

---

## 12. Test Suites & Debugging Testbeds

### 12.1 Rust Unit & Integration Tests
- [x] Rust workspace test harness initialized (`cargo test`).
- [ ] Unit tests for `compute_file_digest` and `compute_directory_digest` with deterministic fixture comparisons.
- [ ] Unit tests for `Keyring` generation, serialization, and signing.
- [ ] Unit tests for `VaultStore` credential import, lookup, and export.
- [ ] Unit tests for `SessionManager` attestation issuance, expiry, and signature validation.
- [ ] End-to-end integration test: Publisher signs package $\rightarrow$ User imports credential $\rightarrow$ Host issues challenge $\rightarrow$ Vault generates proof $\rightarrow$ Verifier confirms valid.

### 12.2 TypeScript & Node Testbeds
- [x] TypeScript package compilation test harness (`npm run build`).
- [ ] Node native test suite (`node --test`) for `@kryptotome/sdk`.
- [ ] Node native test suite for `@kryptotome/bridge` mock authentication.
- [ ] Integration test for Foundry VTT adapter compendium unlock flow.

### 12.3 Cross-Platform & E2E Browser Testing
- [ ] Headless browser test running `kryptotome-wasm` in Chrome/Firefox/Safari WebAssembly runtimes.
- [ ] Test offline behavior: Verify that all proof generation, verification, and table sharing operate with network interfaces disabled.

---

## 13. Future Horizons & Expansion Roadmap (Post-v1.0)

*See detailed architectural specifications in [docs/EXPANSION_ROADMAP.md](docs/EXPANSION_ROADMAP.md).*

### 13.1 Ecosystem & Cross-VTT Expansion
- [ ] **Owlbear Rodeo 2.0 Extension**: Build an official Owlbear extension utilizing native SDK and WebRTC channels to mount unlocked tokens, battlemaps, and spell cards directly into the room canvas.
- [ ] **Web VTT Browser Extension (Roll20 & Alchemy)**: Develop a lightweight WebExtensions (Manifest V3) plugin that injects unlocked compendium records into web VTT character sheets via local vault proofs.
- [ ] **Open Character Builder Adapters**: Implement local entitlement plugins for open character builders (e.g. Pathbuilder 2e, Wanderer's Guide) to unlock character feats and classes offline.
- [ ] **Standalone "Pocket Vault" Mobile App (Tauri / iOS / Android)**: Build a biometric-secured (Secure Enclave / Android Keystore) mobile vault with camera QR scanning and local BLE/mDNS beacons for table sessions.

### 13.2 Advanced Cryptography & Table Privacy
- [ ] **Attribute-Level Selective Disclosure**: Extend ZK-SNARK circuits with Merkle inclusion proofs to prove ownership of individual spells or monster stat blocks without disclosing the specific book bundle or edition.
- [ ] **Collective Party Pooling (Multi-Holder Aggregation)**: Allow multiple players at a table to pool distinct owned rulebooks into an aggregated session proof, sharing the combined compendium across the campaign.
- [ ] **Hardware Key & Passkey Binding (FIDO2 / WebAuthn)**: Enable binding user Pedersen commitments directly to hardware keys (YubiKeys) or OS Passkeys for tamper-proof key custody.

### 13.3 Indie Publisher & Creator Tooling
- [ ] **Kryptotome Publisher Studio (GUI Desktop App)**: Develop a desktop tool (Tauri + Rust) for indie creators to drag-and-drop rulebook PDFs/markdown, auto-compute BLAKE3 digests, validate schemas, and sign distribution packages.
- [ ] **Crowdfunding Fulfillment Bridge (Kickstarter & BackerKit)**: Automated connector that issues batch-signed W3C VC credentials or digital activation links directly to campaign backers.
- [ ] **Print-on-Demand (POD) NFC & Physical Voucher Claims**: Standardize scratch-off cryptographic codes and NFC tags embedded in physical hardcover books to claim digital compendium rights.

### 13.4 Decentralized Distribution & Dependency Graphs
- [ ] **Peer-to-Peer Compendium Swarms (BitTorrent / Libp2p)**: Distribute multi-gigabyte compendium asset packs (4K maps, audio) over content-addressed P2P swarms, mounted only upon local proof verification.
- [ ] **Homebrew Dependency & Lineage Graph**: Establish cryptographic dependency declarations for third-party creators (e.g., *"Requires entitlement to Core Rules v1.2+"*), maintaining an open, verifiable attribution tree.
- [ ] **Universal Cross-VTT Schema Transpiler**: Build an automated conversion pipeline translating standard open gaming schemas (ORC, SRD 5.1 JSON) into Foundry VTT LevelDB packs, Roll20 JSON, or Markdown on-demand.

### 13.5 In-Person & Convention Play
- [ ] **Air-Gapped Table Beacons (BLE / Offline Wi-Fi)**: Run a lightweight verifier daemon on a Raspberry Pi or GM laptop broadcasting an offline hotspot for instant, zero-Internet table session mounting.
- [ ] **Organized Play & Tournament Fast Check-In**: Enable convention check-ins (e.g., Pathfinder Society, Adventurers League) to verify character sheet build legality and rulebook ownership in $< 10\text{ms}$ via QR code scan with zero PII shared.

