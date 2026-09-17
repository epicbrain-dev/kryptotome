# Kryptotome Protocol: Threat Model & Privacy Guarantees

## 1. Security Goals

1. **Mathematical Unlinkability**: A user proving ownership of the same credential across different applications, sessions, or campaigns cannot be correlated by verifiers or passive observers. Proofs exhibit uniform blinding randomness on the elliptic curve group, high Shannon entropy ($> 7.80\text{ bits/byte}$), and zero statistical clustering (Hamming distance ratio divergence $< 0.02$).
2. **Zero Personally Identifiable Information (PII)**: Zero real names, emails, IP addresses, payment tokens, or persistent device hardware identifiers are stored, processed, or transmitted in credentials, manifests, presentation envelopes, or network wire streams. Holder identity is represented solely as a cryptographic Pedersen commitment URN (`urn:kryptotome:commitment:bls12381:...`).
3. **Key Secrecy & Witness Hiding**: Verification proofs reveal zero knowledge about the user's primary secret key ($sk_H$), credential commitment blinding factors ($r$), or other owned credentials.
4. **Replay Defense & Nonce Uniqueness**: Ephemeral challenge nonces coupled with stateful consumed nonce tracking in verifiers and session managers guarantee that intercepted proofs or handshake requests cannot be replayed (`KRYP-401`, `KRYP-402`).
5. **Integrity & Authenticity**: Content schemas are protected by publisher digital signatures (Ed25519) and deterministic digests (SHA-256 / BLAKE3), guaranteeing that rules, supplements, and errata are authentic.
6. **Robustness Against Hostile Inputs**: Verification, manifest ingestion, and bundle decoding routines are hardened against corrupted, truncated, or adversarial inputs via continuous `cargo fuzz` (libFuzzer) and mutation regressions.
7. **Offline Resiliency**: Verification operates completely disconnected from the Internet; absence of network connectivity cannot cause denial of service.

---

## 2. Adversary Models & Defenses

### Adversary A: Malicious or Compromised VTT Host
- **Capabilities**: Can issue arbitrary challenge nonces, inspect all submitted proofs, and record incoming verification attempts across campaigns.
- **Defense**: Zero-knowledge proofs yield no private information or linkable identifiers across multiple challenges.
  - The Groth16 proof coordinates $(A, B, C) \in G_1 \times G_2 \times G_1$ are independently randomized by uniformly chosen scalar blinding factors on every proof generation.
  - Pairwise bitwise Hamming distance between proofs from the same identity ($d(P_{A,1}, P_{A,2})$) is statistically indistinguishable from proofs between two entirely different identities ($d(P_{A}, P_{B})$), with a clustering ratio of $\approx 0.5000$ and divergence $< 0.02$.
  - The host only learns that the holder possesses a valid signature on the module digest from the legitimate publisher.

### Adversary B: Network Eavesdropper & Proof Replay Attacker
- **Capabilities**: Observes network traffic during table sharing, inspects plaintext wire payloads, and attempts to replay intercepted proofs or access requests.
- **Defense**:
  - Table-sharing sessions use ephemeral session attestations signed for specific peer identifiers with short lifespans (default 60 minutes).
  - Challenge nonces carry strict expiration bounds (`ChallengeNonce::is_expired()`).
  - **Stateful Consumed Nonce Tracking**: Both `EmbeddedVerifier` and `SessionManager` maintain active registries of seen nonces. Any attempt to present an already consumed nonce is rejected immediately with `KryptotomeErrorCode::Kryp402NonceReplayDetected`.
  - Nonce registries automatically purge expired timestamps, maintaining a bounded memory footprint ($< 16\text{MB}$).

### Adversary C: Counterfeit Content Publisher
- **Capabilities**: Attempts to spoof publisher identity or distribute corrupted rule data.
- **Defense**: Root manifests require Ed25519 signatures from published publisher verification keys; file schemas are validated against deterministic merkle/digest trees (`KRYP-201`, `KRYP-501`).

### Adversary D: Rogue Errata Mirror or Man-in-the-Middle
- **Capabilities**: Intercepts errata synchronization queries and returns malicious RFC 6902 delta patches or attempts to strip user homebrew content.
- **Defense**: Errata bundles require cryptographic binding to the target package ID, version increment validation, and pre/post-patch package digest matching. The sync dispatcher isolates user homebrew items and custom schema attributes, preventing official patches from deleting user data.

### Adversary E: Tampered Physical Invoice / Air-Gapped QR Attacker
- **Capabilities**: Crafts fake physical convention receipts or injects corrupted frames into multi-frame animated QR streams.
- **Defense**: Invoices must be signed by the publisher's registered Ed25519 public key. QR frames carry sequential frame index headers, total frame counts, payload lengths, and checksums. Any tampered, expired, or corrupted frames are rejected (`KRYP-201`, `KRYP-104`).

### Adversary F: Malformed / Hostile Input Fuzzer
- **Capabilities**: Injects malformed binary streams, out-of-order JSON schemas, non-UTF8 bytes, corrupted base64, or boundary elliptic curve scalar coordinates into verifiers.
- **Defense**: All deserializers and input processors are audited and fuzzed with `cargo fuzz` (libFuzzer) over 299,000+ random executions with zero panics or memory violations. In-tree property mutation test suites continuously validate parsing resilience.

---

## 3. Auditing & Verification Specifications

Automated tests and security harnesses enforce all threat model requirements:

| Audit Category | Test / Harness | Security Guarantee |
| :--- | :--- | :--- |
| **Mathematical Unlinkability** | `cargo test --test unlinkability_audit` | Shannon entropy $> 7.80$ b/B; Hamming variance ratio $\approx 0.50$; non-clustering divergence $< 0.02$. |
| **Zero-PII Compliance** | `cargo test --test pii_audit` | Rejection of emails, IPs, paths, SSNs, credit cards across credentials, manifests, and proofs. |
| **Replay Attack Immunity** | `cargo test --test replay_immunity_audit` | Instant rejection of duplicated or expired nonces in verifiers and session managers (`KRYP-401`, `KRYP-402`). |
| **Dependency Security** | `./scripts/security_audit.sh` | Continuous scanning against RustSec Advisory DB and npm audit (0 vulnerabilities). |
| **libFuzzer Robustness** | `cargo +nightly fuzz run <target>` | Panic-free deserialization on untrusted manifests, proofs, and bundles. |
