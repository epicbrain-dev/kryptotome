# Kryptotome Protocol: Positioning & Terminology Guide

To safeguard community trust and prevent brand confusion, all Kryptotome source code, schemas, error messages, documentation, user interfaces, and public communications must strictly avoid Web3 and cryptocurrency nomenclature.

Kryptotome is an **open, local-first content authentication protocol**. It does not use blockchains, tokens, cryptocurrency, smart contracts, or distributed ledgers.

---

## Prohibited vs. Required Terminology

| Prohibited Term (Web3 / Crypto) | Required Kryptotome Protocol Term | Context / Notes |
| :--- | :--- | :--- |
| **Wallet** | **Local Key Vault** / **Keychain** | Secure local client storage for keys and credentials. |
| **Mint / Minting** | **Signing** / **Issuing** | Publisher signing content manifests or issuing credentials. |
| **Token / NFT** | **Signed Credential** / **Entitlement** / **Session Attestation** | W3C VC v2.0 verifiable credential or ephemeral session token. |
| **Smart Contract** | **Verification Protocol** / **Circuit** / **Rule Schema** | Cryptographic verification logic or schema definition. |
| **DApp / Web3 App** | **Local-First Application** / **VTT Client** | Offline-capable tabletop tools. |
| **Gas / Transaction Fee** | *N/A (Free)* | Verification is strictly local and incurs zero network or gas costs. |
| **On-chain / Ledger** | **Local Custody** / **Publisher Manifest** | Stored locally in vault or published as static JSON. |
| **Airdrop** | **Errata Sync** / **Content Update** | Dynamic delivery of patches and schema updates. |
| **DAO** | **Open Gaming Consortium** / **Standards Working Group** | Standards governance. |

---

## Language Rules for Error Messages and APIs

- **Never** name functions or variables `*Token*` unless explicitly qualified as `SessionToken` or `BearerToken` in standard HTTP/OAuth contexts.
- **Never** throw errors referencing "blockchain", "gas", "transactions", or "wallets".
- Use precise security and cryptography terminology: *asymmetric keypair*, *zero-knowledge proof*, *cryptographic commitment*, *content digest*, *verifiable credential*.
