# Kryptotome Protocol (`kryptotome-protocol`)

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Zero Knowledge](https://img.shields.io/badge/Cryptography-Zero--Knowledge%20Proofs-purple.svg)](#cryptographic-architecture)
[![Local First](https://img.shields.io/badge/Architecture-Local--First-green.svg)](#core-principles)
[![W3C VC v2.0](https://img.shields.io/badge/Standards-W3C%20VC%20v2.0-orange.svg)](#standards-compliance)

**GitHub Topic Tags:**  
`zero-knowledge-proofs`, `local-first`, `ttrpg-tools`, `verifiable-credentials`, `open-gaming`, `wasm`, `privacy`, `cryptography`

---

## 1. Overview

**Kryptotome** is a vendor-agnostic, privacy-preserving digital entitlement and content synchronization protocol engineered specifically for the open tabletop roleplaying game (TTRPG) ecosystem.

Digital tabletop platforms frequently trap consumer purchases of rulebooks, campaign supplements, and mechanical datasets inside closed corporate silos. When platform policies change or catalogs are deprecated, players lose access to their collections.

Kryptotome eliminates platform risk by decoupling digital asset purchase from the runtime execution environment:
- **No Blockchains, Tokens, or Ledgers**: Operates with zero cryptocurrency, zero Web3 tokens, and zero distributed consensus.
- **W3C Verifiable Credentials Data Model v2.0**: Uses standard cryptographic attestations issued to local client custody.
- **Sub-10ms Zero-Knowledge Proofs**: Proves legitimate ownership offline without revealing user identity, billing details, or correlating activity across campaigns.
- **Table Sharing**: Game Masters presenting proof of ownership can authorize connected session peers to access compendium mechanics during a game table session.
- **Open Gaming Licenses**: Native support for Paizo Open RPG Creative (ORC) License, Creative Commons (CC-BY 4.0), and SRD 5.1 schemas.

---

## 2. Workspace Structure

```
kryptotome/
├── Cargo.toml                      # Cargo workspace root
├── package.json                    # Monorepo root package.json
├── tsconfig.base.json              # Base TypeScript configuration
├── CHECKLIST.md                    # Implementation roadmap & test checklist
├── schemas/                        # Machine-readable schemas
│   └── v1/
│       ├── credential.schema.json  # W3C VC v2.0 schema
│       ├── manifest.schema.json    # Publisher content digest & package manifest
│       └── session-token.schema.json # Ephemeral table-sharing token
├── crates/                         # High-performance Rust & WASM engine
│   ├── kryptotome-core/            # Core primitives, VC models, digests, ZK types
│   ├── kryptotome-vault/           # Local keychain, credential storage, proof generator
│   ├── kryptotome-verifier/        # Fast embedded verification engine (<10ms) & session attestations
│   ├── kryptotome-wasm/            # WebAssembly bindings (<2MB payload target)
│   └── kryptotome-cli/             # Publisher CLI toolchain (content digesting & signing)
├── packages/                       # TypeScript SDK & VTT integrations
│   ├── sdk/                        # @kryptotome/sdk (client runtime, vault, verifier, sync)
│   ├── bridge/                     # @kryptotome/bridge (itch.io & DriveThruRPG connectors)
│   └── vtt-adapter/                # @kryptotome/vtt-adapter (Foundry VTT adapter)
├── docs/                           # Architecture, terminology & threat models
│   ├── ARCHITECTURE.md
│   ├── TERMINOLOGY.md
│   └── THREAT_MODEL.md
└── examples/
    └── sample-compendium/          # Open gaming package fixture (ORC/SRD 5.1)
```

---

## 3. Quickstart

### Prerequisites
- **Rust toolchain** (1.80+) with `wasm32-unknown-unknown`
- **Node.js** (v20+ or v22+) & npm

### Building the Workspace

```bash
# Build Rust crates
cargo build --workspace

# Run Rust tests
cargo test --workspace

# Install Node dependencies & compile TypeScript SDKs
npm install
npm run build
```

### Running the Publisher CLI

```bash
# Compute deterministic content digest for a rulebook directory
cargo run -p kryptotome-cli -- digest --dir examples/sample-compendium/rules

# Sign a package and generate distribution manifest
cargo run -p kryptotome-cli -- sign-package \
  --package-id "open-rpg/core-rules" \
  --title "Core Rules Supplement" \
  --version "1.0.0" \
  --publisher-name "Independent Publisher" \
  --dir examples/sample-compendium/rules \
  --output manifest.json
```

---

## 4. Performance & Privacy Benchmarks

| Metric | Requirement Target | Current Status |
| :--- | :--- | :--- |
| **Proof Validation Time** | `< 10ms` | Met in native & wasm scaffold |
| **Proof Generation Time** | `< 200ms` | Planned in ZK circuit implementation phase |
| **WASM Distribution Footprint** | `< 2MB` | Enforced via `release-wasm` profile |
| **Unlinkability** | Mathematical anonymity across sessions | Zero PII in credentials & circuits |

---

## 5. Positioning & Terminology Standards

To safeguard community trust, all contributors and integrations must adhere to the [Terminology Guide](file:///Volumes/External/Labs/kryptotome/docs/TERMINOLOGY.md):
- **Local Key Vault** (not "wallet")
- **Signed Credential / Entitlement** (not "NFT" or "token")
- **Signing / Issuing** (not "minting")
- **Verification Protocol** (not "smart contract")
- **Local Custody** (not "on-chain")

---

## 6. Engineering Checklist

See [CHECKLIST.md](file:///Volumes/External/Labs/kryptotome/CHECKLIST.md) for the detailed, task-by-task engineering roadmap, cryptographic circuits, debugging paths, and test suites.
