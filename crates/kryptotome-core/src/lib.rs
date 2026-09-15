//! Kryptotome Core: Primitives, data models, and ZK interfaces
//!
//! Decouples digital tabletop asset purchases from closed runtimes via W3C VC v2.0
//! and zero-knowledge proof primitives.

pub mod credential;
pub mod digest;
pub mod error;
pub mod zkp;

pub use credential::{
    CredentialSubject, Entitlement, Issuer, KryptotomeCredential, ProofData,
};
pub use digest::{compute_directory_digest, compute_file_digest, ContentDigest};
pub use error::{KryptotomeError, Result};
pub use zkp::{ChallengeNonce, ProofInputs, VerificationKey, ZkProof};
