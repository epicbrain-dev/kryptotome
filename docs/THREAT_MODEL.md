# Kryptotome Protocol: Threat Model & Privacy Guarantees

## 1. Security Goals

1. **Unlinkability**: A user proving ownership of the same credential across different applications, sessions, or campaigns cannot be correlated by verifiers or passive observers.
2. **Key Secrecy**: Verification proofs must reveal zero knowledge about the user's primary secret key or other owned credentials.
3. **Replay Defense**: Challenge nonces with strict time-to-live (TTL) prevent eavesdroppers from reusing intercepted proofs.
4. **Integrity & Authenticity**: Content schemas are protected by publisher digital signatures (Ed25519) and deterministic digests (SHA-256 / BLAKE3), guaranteeing that rules and errata are authentic.
5. **Offline Resiliency**: Verification operates completely disconnected from the Internet; absence of network connectivity cannot cause denial of service.

---

## 2. Adversary Models

### Adversary A: Malicious or Compromised VTT Host
- **Capabilities**: Can issue arbitrary challenge nonces and inspect all submitted proofs.
- **Defense**: Zero-knowledge proofs yield no private information or linkable identifiers across multiple challenges. The host only learns that the holder possesses a valid signature on the module digest from the legitimate publisher.

### Adversary B: Network Eavesdropper
- **Capabilities**: Observes network traffic during table sharing or sync.
- **Defense**: Table-sharing sessions use ephemeral session attestations signed for specific peer identifiers with short lifespans. No persistent identifiers or real names are transmitted.

### Adversary C: Counterfeit Content Publisher
- **Capabilities**: Attempts to spoof publisher identity or distribute corrupted rule data.
- **Defense**: Root manifests require Ed25519 signatures from published publisher verification keys; file schemas are validated against deterministic merkle/digest trees.

### Adversary D: Rogue Errata Mirror or Man-in-the-Middle
- **Capabilities**: Intercepts errata synchronization queries and returns malicious RFC 6902 delta patches or attempts to strip user homebrew content.
- **Defense**: Errata bundles require cryptographic binding to the target package ID, version increment validation, and pre/post-patch package digest matching. The sync dispatcher isolates user homebrew items and custom schema attributes, preventing official patches from deleting user data.

### Adversary E: Tampered Physical Invoice / Air-Gapped QR Attacker
- **Capabilities**: Crafts fake physical convention receipts or injects corrupted frames into multi-frame animated QR streams.
- **Defense**: Invoices must be signed by the publisher's registered Ed25519 public key. QR frames carry sequential frame index headers, total frame counts, payload lengths, and checksums. Any tampered, expired, or corrupted frames are rejected (`KRYP-201`, `KRYP-104`).

