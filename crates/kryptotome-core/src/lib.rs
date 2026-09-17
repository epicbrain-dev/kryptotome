//! Kryptotome Core: Primitives, data models, and ZK interfaces
//!
//! Decouples digital tabletop asset purchases from closed runtimes via W3C VC v2.0
//! and zero-knowledge proof primitives.

pub mod circuit;
pub mod commitment;
pub mod credential;
pub mod curve;
pub mod digest;
pub mod error;
pub mod zkp;

pub use circuit::{
    compute_circuit_commitment, compute_circuit_signature_witness, create_entitlement_proof,
    derive_circuit_blinding_for_commitment, deserialize_pk_compressed, deserialize_proof_base64,
    deserialize_proof_base64_url, deserialize_proof_compressed, deserialize_public_inputs_base64,
    deserialize_public_inputs_compressed, deserialize_vk_base64, deserialize_vk_compressed,
    generate_entitlement_setup, get_or_init_entitlement_prepared_vk, get_or_init_entitlement_setup,
    prepare_verifying_key, proof_from_urn, proof_to_urn, prove_entitlement_for_credential,
    serialize_pk_compressed, serialize_proof_base64, serialize_proof_base64_url,
    serialize_proof_compressed, serialize_public_inputs_base64, serialize_public_inputs_compressed,
    serialize_vk_base64, serialize_vk_compressed, string_to_scalar, verify_entitlement_proof,
    verify_entitlement_proof_prepared, EntitlementCircuit, EntitlementProofBundle,
    Groth16PreparedVerifyingKey, Groth16Proof, Groth16ProvingKey, Groth16VerifyingKey,
    BUNDLE_MAGIC,
};

pub use commitment::{scalar_from_bytes, PedersenCommitment, PedersenCommitmentScheme};

pub use curve::{
    deserialize_g1_compressed, deserialize_g2_compressed, evaluate_multi_pairing, g1_generator,
    g2_generator, pairing, random_scalar, serialize_g1_compressed, serialize_g2_compressed,
    verify_kzg_opening, verify_multi_pairing_identity, verify_pairing_equality,
    verify_plonk_batch_opening, AffineRepr, BaseField, CurveGroup, CurveSuite, G1Point, G2Point,
    ProductionPairingEngine, ScalarField, TargetField,
};

pub use credential::{CredentialSubject, Entitlement, Issuer, KryptotomeCredential, ProofData};
pub use digest::{
    compute_directory_digest, compute_directory_digest_blake3,
    compute_directory_digest_with_algorithm, compute_file_digest, compute_file_digest_blake3,
    compute_file_digest_blake3_with_progress, compute_file_digest_with_algorithm,
    compute_file_digest_with_progress, ContentDigest, DigestAlgorithm,
};
pub use error::{KryptotomeError, Result};
pub use zkp::{ChallengeNonce, ProofInputs, VerificationKey, ZkProof};
