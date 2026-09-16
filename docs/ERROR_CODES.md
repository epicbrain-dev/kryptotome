# Kryptotome Protocol: Standardized Error Codes Taxonomy (`KRYP-100` – `KRYP-900`)

This document defines the authoritative error codes taxonomy shared across all Kryptotome Protocol implementations, including the Rust core crates (`crates/kryptotome-core`), WebAssembly bindings (`crates/kryptotome-wasm`), and TypeScript client SDKs (`@kryptotome/sdk`).

---

## Error Range Allocation

| Range | Category | Primary Focus |
| :--- | :--- | :--- |
| **`KRYP-100` – `KRYP-199`** | **Schema & Standards Compliance** | W3C VC v2.0, JSON-LD context, manifest schemas, temporal bounds. |
| **`KRYP-200` – `KRYP-299`** | **Cryptographic Signatures** | Ed25519 asymmetric signatures, publisher public key validation. |
| **`KRYP-300` – `KRYP-399`** | **Zero-Knowledge Proofs & Circuits** | Arkworks R1CS/Plonk circuits, pairing checks, public input verification. |
| **`KRYP-400` – `KRYP-499`** | **Challenge Nonces & Replay Defense** | Challenge freshness, expiration, replay mitigation, package binding. |
| **`KRYP-500` – `KRYP-599`** | **Content Integrity & Digests** | Deterministic SHA-256 / BLAKE3 file trees, compendium asset validation. |
| **`KRYP-600` – `KRYP-699`** | **Local Keychain & Vault Custody** | OS keychain access, encrypted keystore decryption, key zeroization. |
| **`KRYP-700` – `KRYP-799`** | **Table-Sharing Ephemeral Sessions** | GM table tokens, peer authorization, time-scoped attestations, scopes. |
| **`KRYP-800` – `KRYP-899`** | **Merchant Bridge Integrations** | itch.io OAuth API, DriveThruRPG Application Keys, order derivations. |
| **`KRYP-900` – `KRYP-999`** | **System, IO & Runtime** | JSON serialization, filesystem IO, WASM memory and sandbox limits. |

---

## Detailed Code Reference

### 100 Series: Schema & Standards Compliance
- **`KRYP-101` (`InvalidContext`)**: `@context` must be an ordered array where index `0` is `https://www.w3.org/ns/credentials/v2`.
- **`KRYP-102` (`MissingCredentialType`)**: Credential `type` must include both `VerifiableCredential` and `KryptotomeEntitlementCredential`.
- **`KRYP-103` (`InvalidUriIdentifier`)**: Identifier (`id`, `issuer.id`, `credentialSubject.id`) is not a valid URI.
- **`KRYP-104` (`InvalidTemporalBounds`)**: Temporal ordering violation (`validUntil <= validFrom`) or invalid timestamp format.
- **`KRYP-105` (`MalformedProofStructure`)**: Proof is malformed, missing `verificationMethod`, or purpose is not `assertionMethod`.
- **`KRYP-106` (`InvalidManifestSchema`)**: Publisher package manifest does not conform to `manifest.schema.json`.
- **`KRYP-107` (`CredentialRevoked`)**: Credential has been revoked by publisher revocation list or Merkle tree.

### 200 Series: Cryptographic Signatures
- **`KRYP-201` (`SignatureVerificationFailed`)**: Asymmetric digital signature (Ed25519) verification failed against data payload.
- **`KRYP-202` (`InvalidPublicKeyFormat`)**: Public key format is corrupted or unexpected byte length.
- **`KRYP-203` (`CorruptedSignature`)**: Signature bytes are malformed or invalid length.
- **`KRYP-204` (`UntrustedPublisherKey`)**: Publisher public key is not registered or untrusted.

### 300 Series: Zero-Knowledge Proofs & Circuits
- **`KRYP-301` (`ZkProofVerificationFailed`)**: Elliptic curve pairing evaluation or ZK argument verification returned false.
- **`KRYP-302` (`PublicInputMismatch`)**: Proof public inputs do not match target module ID, content digest, or challenge nonce.
- **`KRYP-303` (`MalformedProofEncoding`)**: ZK proof bytes cannot be deserialized into proving curve coordinates.
- **`KRYP-304` (`ProverSetupFailed`)**: Circuit setup or universal SRS parameters failed to load.
- **`KRYP-305` (`ConstraintUnsatisfied`)**: Witness values failed to satisfy zero-knowledge circuit constraints.

### 400 Series: Challenge Nonces & Replay Defense
- **`KRYP-401` (`ChallengeExpired`)**: Challenge nonce timestamp exceeds maximum time-to-live (TTL).
- **`KRYP-402` (`NonceReplayDetected`)**: Nonce has already been presented and retired; replay rejected.
- **`KRYP-403` (`ChallengePackageMismatch`)**: Challenge nonce was issued for a different package ID than requested.

### 500 Series: Content Integrity & Digests
- **`KRYP-501` (`DigestMismatch`)**: Computed content digest of local files does not match publisher signed manifest root.
- **`KRYP-502` (`MissingOrCorruptAsset`)**: Required compendium dataset or schema file is missing from the directory.
- **`KRYP-503` (`UnsupportedDigestAlgorithm`)**: Digest algorithm is unsupported (only SHA-256 and BLAKE3 are permitted).

### 600 Series: Local Keychain & Vault Custody
- **`KRYP-601` (`KeyringAccessFailed`)**: Failed to access OS secure enclave or local keystore.
- **`KRYP-602` (`VaultDecryptionFailed`)**: Vault passkey is incorrect or keystore payload is corrupted.
- **`KRYP-603` (`EntitlementNotFound`)**: Local vault does not contain an entitlement for the specified package ID.
- **`KRYP-604` (`KeyCustodyError`)**: Cryptographic key custody or zeroization failure.

### 700 Series: Table-Sharing Ephemeral Sessions
- **`KRYP-701` (`SessionTokenExpired`)**: Game table session attestation has expired.
- **`KRYP-702` (`InvalidSessionSignature`)**: Session token signature is invalid under the host GM's temporary public key.
- **`KRYP-703` (`PeerUnauthorized`)**: Connected table peer lacks authorization for requested scope.
- **`KRYP-704` (`SessionIdMismatch`)**: Token was issued for a different game table session.

### 800 Series: Merchant Bridge Integrations
- **`KRYP-801` (`MerchantAuthFailed`)**: Merchant authorization failed (invalid itch.io OAuth token or DriveThruRPG key).
- **`KRYP-802` (`MerchantPurchaseNotFound`)**: Authenticated user account does not possess a purchase record for the package.
- **`KRYP-803` (`MerchantRateLimitExceeded`)**: Merchant API rate limit encountered.
- **`KRYP-804` (`MerchantNetworkError`)**: Network error connecting to merchant API endpoints.

### 900 Series: System, IO & Runtime
- **`KRYP-901` (`SerializationError`)**: JSON or binary data format serialization/deserialization failed.
- **`KRYP-902` (`IoError`)**: Local filesystem input/output operation failed.
- **`KRYP-903` (`WasmRuntimeError`)**: WebAssembly sandbox execution error or memory fault.
