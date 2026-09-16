//! Kryptotome Core: Primitives, data models, and ZK interfaces
//!
//! Decouples digital tabletop asset purchases from closed runtimes via W3C VC v2.0
//! and zero-knowledge proof primitives.

pub mod commitment;
pub mod credential;
pub mod curve;
pub mod digest;
pub mod error;
pub mod zkp;

pub use commitment::{
    scalar_from_bytes, PedersenCommitment, PedersenCommitmentScheme,
};

pub use curve::{
    deserialize_g1_compressed, deserialize_g2_compressed, pairing, random_scalar,
    serialize_g1_compressed, serialize_g2_compressed, verify_pairing_equality, BaseField,
    CurveSuite, G1Point, G2Point, ProductionPairingEngine, ScalarField, TargetField,
};

pub use credential::{
    CredentialSubject, Entitlement, Issuer, KryptotomeCredential, ProofData,
};
pub use digest::{
    compute_directory_digest, compute_directory_digest_blake3,
    compute_directory_digest_with_algorithm, compute_file_digest,
    compute_file_digest_blake3, compute_file_digest_with_algorithm, ContentDigest,
    DigestAlgorithm,
};
pub use error::{KryptotomeError, Result};
pub use zkp::{ChallengeNonce, ProofInputs, VerificationKey, ZkProof};
