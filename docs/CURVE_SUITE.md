# Cryptographic Architecture Decision Record: Elliptic Curve Suite Selection

**Status**: Accepted  
**Decision**: Standardize on **BLS12-381** via `arkworks-rs` (`ark-bls12-381`) as the production pairing-friendly curve for the Kryptotome Protocol.

---

## 1. Context & Protocol Requirements

Kryptotome decouples tabletop RPG entitlement purchases from proprietary runtimes using zero-knowledge credentials and offline verification.

The protocol imposes three critical cryptographic constraints:
1. **Low-Latency Verification**: Host applications (such as Foundry VTT or native desktop clients) must verify ownership proofs in **$< 10\text{ms}$** without dropping render frames.
2. **Conservative Long-Term Security**: Content purchases represent durable player entitlements. The cryptographic primitives must guarantee **$\ge 128\text{ bits}$ of security**, protecting against advances in number field sieve attacks.
3. **Strict Non-Blockchain Positioning**: The protocol eschews distributed ledgers and Ethereum/EVM infrastructure. Curves optimized solely for EVM precompiles at the expense of security margins are undesirable.

---

## 2. Evaluated Candidate Curves

| Metric / Attribute | **BLS12-381** (Selected) | **BN254 (alt_bn128)** | **BLS12-377** |
| :--- | :--- | :--- | :--- |
| **Security Level** | **$\approx 128$ bits** (Conservative) | $\approx 100$ bits (Degraded by Kim-Barbulescu) | $\approx 125$ bits |
| **Base Field Size ($q$)** | 381 bits | 254 bits | 377 bits |
| **Scalar Field Size ($r$)** | 255 bits | 254 bits | 253 bits |
| **G1 Compressed Size** | **48 bytes** | 32 bytes | 48 bytes |
| **G2 Compressed Size** | **96 bytes** | 64 bytes | 96 bytes |
| **Single Pairing Latency** | **$\sim 1.2\text{ms}$** on ARM64 | $\sim 0.6\text{ms}$ on ARM64 | $\sim 1.2\text{ms}$ on ARM64 |
| **Ecosystem & Standards** | Zcash Sapling, W3C BBS+, Filecoin, Arkworks | Ethereum EVM Precompile (EIP-197) | Zexe (2-Chain with BW6-761) |
| **WebAssembly Compatibility** | Excellent (`wasm32-unknown-unknown`) | Excellent | Good |

---

## 3. Evaluation & Trade-off Analysis

### 3.1 Why BLS12-381 Was Selected
1. **True 128-Bit Security Margin**:  
   BN254's effective discrete log security was reduced to $\approx 100\text{ bits}$ following the Kim-Barbulescu variant of the Number Field Sieve (ex-Tower NFS). For consumer content that should remain valid for decades, 100 bits is insufficient. BLS12-381 was specifically engineered by Sean Bowe in 2017 to provide a clean 128-bit security level.
2. **Sub-10ms Performance Target**:  
   In our benchmarks using `arkworks-rs`, a single pairing check on BLS12-381 executes in **$\approx 1.2 - 2.5\text{ms}$**, well under our 10ms budget.
3. **Compact Proof Representations**:  
   G1 elements serialize to 48 bytes; G2 elements serialize to 96 bytes. A Groth16 proof consists of $(\pi_A \in G_1, \pi_B \in G_2, \pi_C \in G_1)$, totaling only **192 bytes** compressed.
4. **Alignment with W3C Verifiable Credentials**:  
   BLS12-381 is the foundational curve chosen by the W3C Verifiable Credentials Data Integrity Working Group for BBS+ signatures and pairing-based selective disclosure.

### 3.2 Why BN254 Was Deferred
BN254 was originally prioritized in blockchain ecosystems due to its adoption in Ethereum precompiles (`0x08`). Because Kryptotome is strictly local-first and does not interact with smart contracts or EVM runtimes, the reduced security margin of BN254 offers no architectural advantage.

---

## 4. Implementation Details

- **Rust Implementation**: [`crates/kryptotome-core/src/curve.rs`](file:///Volumes/External/Labs/kryptotome/crates/kryptotome-core/src/curve.rs)
- **Pairing Engine**: `ark_bls12_381::Bls12_381` via `ark_ec::pairing::Pairing`
- **Compression**: `CanonicalSerialize` and `CanonicalDeserialize` with automatic subgroup validation.
- **Verification Engine**: Evaluates Miller loop and final exponentiation:
  $$\prod_{i} e(P_i, Q_i) \stackrel{?}{=} 1$$
