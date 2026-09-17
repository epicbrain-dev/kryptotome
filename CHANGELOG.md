# Changelog

All notable changes to the **Kryptotome Protocol** specification, Rust crates, WebAssembly modules, and client libraries are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-16

### Initial Production Protocol Release (v1.0.0)

Kryptotome is a vendor-agnostic, privacy-preserving digital entitlement and content synchronization protocol for tabletop gaming. It enables local-first, air-gapped content ownership using zero-knowledge proofs (BLS12-381 + Groth16) without Web3/blockchain dependencies or centralized DRM servers.

### Added

#### Core Cryptography & Circuits (`kryptotome-core`)
- **Elliptic Curve Suite**: BLS12-381 curve operations via `arkworks-rs` with pairing latency under 1.3ms.
- **Commitment Scheme**: Information-theoretic hiding Pedersen commitments on $\mathbb{G}_1$ for binding holder secret keys to digital credentials.
- **Zero-Knowledge Circuit**: Groth16 R1CS circuit proving knowledge of secret key and valid publisher signature over package ID, content digest, and challenge nonce without revealing identity or correlatable identifiers.
- **Serialization Formats**: Compact binary format with magic header `\x89KTOME\x01\x00`, base64 encoding, and canonical URN representations (`urn:kryptotome:zkproof:v1:...`).
- **Content Digests**: Deterministic SHA-256 and high-throughput BLAKE3 file and directory tree digesting with canonical path sorting.

#### Local Custody & Vault Runtime (`kryptotome-vault`)
- **Key Custody**: Ed25519 `Keyring` with zeroization on drop (`zeroize::Zeroize`, `zeroize::ZeroizeOnDrop`) and platform OS keychain bindings (macOS Keychain, Windows Credential Manager, Linux Secret Service).
- **Credential Storage**: In-memory `VaultStore` with package-indexed fast lookup, export/import to JSON, and encrypted backups (`.kryptotome-vault.enc`) via Argon2id and AES-256-GCM / ChaCha20-Poly1305.
- **Revocation Checking**: Publisher revocation lists with cryptographic Merkle tree inclusion proofs.
- **Offline Proof Generation**: Single-use Groth16 proof generation executing in $\approx 6.6\text{ms}$ on commodity hardware.

#### Embedded Verifier & Table Sharing (`kryptotome-verifier`)
- **Embedded Verifier**: Fast proof verification in $< 2.5\text{ms}$ on BLS12-381 using prepared pairing precomputation.
- **Session Caching**: `EntitlementCache` with timeout rules, package reload detection, digest mismatch eviction, and game session exit purges.
- **Table Sharing**: `SessionManager` issuing ephemeral, Ed25519-signed `SessionAttestation` tokens for table peers with dynamic scope limiting (permitting player compendiums while shielding GM notes and spoilers).
- **Client Runtime**: `PeerSessionClient` verifying host attestations and mounting compendiums in volatile client memory with immediate purge on revocation.

#### WebAssembly Engine (`kryptotome-wasm`)
- **WASM Interface**: High-level JS-friendly `WasmVerifier` and `WasmSessionManager` bindings via `wasm-bindgen`.
- **Binary Footprint**: Stripped, size-optimized WebAssembly payload (`wasm-opt -Oz`) at **563 KB** (well below the 2 MB budget).
- **Thread Safety**: Non-blocking execution within Web Workers and Electron background processes without freezing UI threads.

#### Client SDK (`@kryptotome/sdk`)
- **W3C VC 2.0 Compliance**: Full compliance with the W3C Verifiable Credentials Data Model v2.0 and JSON-LD context resolution.
- **Error Taxonomy**: Comprehensive error code hierarchy (`KRYP-100` through `KRYP-900`) across Rust and TypeScript.
- **Errata Sync**: `ErrataSyncDispatcher` supporting RFC 6902 JSON Patch updates with strict preservation of user homebrew.
- **Web Worker Bridge**: `WorkerBridge` offloading cryptographic proofs and verification to dedicated background threads.

#### Virtual Tabletop Adapter (`@kryptotome/vtt-adapter`)
- **Foundry VTT Integration**: `FoundryVttAdapter` intercepting compendium `load()` and `getData()` requests to unlock content via local vault proofs.
- **Table Token Sharing**: WebRTC and SocketLib session token distribution for connected players.
- **UI Components**: Reference UI overlays for lock status, unlock prompts, and proof generation progress.

#### Publisher Toolchain & CLI (`kryptotome-cli`)
- **CLI Commands**: `sign-package`, `digest`, `keygen`, `vault-status`, `verify-manifest`, and `bundle`.
- **License Validation**: Automated compliance checks for Paizo ORC, Creative Commons CC-BY-4.0, and CC0 licenses.
- **Batch Release Packaging**: Archive bundling into `.ktome` container format with tar/gzip compression and manifest inspection.

#### Merchant Bridges (`@kryptotome/bridge`)
- **itch.io & DriveThruRPG Bridges**: Client-side API integration fetching user purchases and deriving local W3C Verifiable Credentials.
- **Air-Gapped Offline Bridge**: Paper receipt scanning and multi-frame chunked QR code transmission for conventions and air-gapped tables.

#### Comprehensive Testbeds & Audits
- **Rust Unit & Integration Tests**: 97 automated tests covering all primitives, fixtures, circuits, memory sanitization, and end-to-end pipelines.
- **Node & Browser Testbeds**: 72 automated tests in `@kryptotome/sdk`, `@kryptotome/bridge`, and `@kryptotome/vtt-adapter`.
- **Headless Browser Testing**: Chrome (Chromium/V8) and Safari (WebKit/JSC) WebAssembly execution test harness.
- **Offline Air-Gap Testing**: Verification that all proof generation, verification, and table sharing operate with network interfaces disabled (0 network requests).
- **Security Audits**: Fuzz regression panic-freedom, zero PII leakage audit, and statistical unlinkability tests.
