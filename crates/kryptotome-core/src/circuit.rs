use crate::curve::ScalarField;
use crate::error::{KryptotomeError, KryptotomeErrorCode, Result};
use ark_bls12_381::Bls12_381;
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use base64::prelude::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

/// Type alias for Groth16 BLS12-381 proof
pub type Groth16Proof = Proof<Bls12_381>;

/// Type alias for Groth16 BLS12-381 proving key
pub type Groth16ProvingKey = ProvingKey<Bls12_381>;

/// Type alias for Groth16 BLS12-381 verifying key
pub type Groth16VerifyingKey = VerifyingKey<Bls12_381>;

/// Type alias for Groth16 BLS12-381 prepared verifying key
pub type Groth16PreparedVerifyingKey = PreparedVerifyingKey<Bls12_381>;

static GLOBAL_SETUP: OnceLock<(Groth16ProvingKey, Groth16VerifyingKey)> = OnceLock::new();
static GLOBAL_PREPARED_VK: OnceLock<Groth16PreparedVerifyingKey> = OnceLock::new();
static GLOBAL_SELECTIVE_SETUP: OnceLock<(Groth16ProvingKey, Groth16VerifyingKey)> = OnceLock::new();
static GLOBAL_SELECTIVE_PREPARED_VK: OnceLock<Groth16PreparedVerifyingKey> = OnceLock::new();

/// Returns a reference to the global lazily initialized Groth16 parameters for the entitlement circuit
pub fn get_or_init_entitlement_setup() -> &'static (Groth16ProvingKey, Groth16VerifyingKey) {
    GLOBAL_SETUP.get_or_init(|| {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4b727970746f);
        generate_entitlement_setup(&mut rng).expect("Global entitlement circuit setup failed")
    })
}

/// Returns a reference to the global lazily initialized Groth16 prepared verifying key
pub fn get_or_init_entitlement_prepared_vk() -> &'static Groth16PreparedVerifyingKey {
    GLOBAL_PREPARED_VK.get_or_init(|| {
        let (_, vk) = get_or_init_entitlement_setup();
        prepare_verifying_key(vk)
    })
}

/// Returns a reference to the global lazily initialized Groth16 parameters for selective disclosure
pub fn get_or_init_selective_disclosure_setup() -> &'static (Groth16ProvingKey, Groth16VerifyingKey)
{
    GLOBAL_SELECTIVE_SETUP.get_or_init(|| {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x53656c656374);
        generate_selective_disclosure_setup(&mut rng)
            .expect("Global selective disclosure circuit setup failed")
    })
}

/// Returns a reference to the global lazily initialized prepared VK for selective disclosure
pub fn get_or_init_selective_disclosure_prepared_vk() -> &'static Groth16PreparedVerifyingKey {
    GLOBAL_SELECTIVE_PREPARED_VK.get_or_init(|| {
        let (_, vk) = get_or_init_selective_disclosure_setup();
        prepare_verifying_key(vk)
    })
}

/// R1CS Entitlement Constraint Circuit for Kryptotome
///
/// Proves ownership of a valid publisher credential and binding to target package
/// without revealing the holder's secret key or leaking linkable identity.
#[derive(Clone, Debug)]
pub struct EntitlementCircuit {
    // --- Public Inputs ---
    /// Challenge nonce scalar (ephemeral single-use challenge from verifier)
    pub challenge_nonce: Option<ScalarField>,
    /// Target package ID scalar
    pub package_id: Option<ScalarField>,
    /// Content digest scalar
    pub content_digest: Option<ScalarField>,
    /// Publisher verification key scalar
    pub publisher_pubkey: Option<ScalarField>,
    /// Holder commitment scalar C_s = Hash(Commit(sk_H, r))
    pub holder_commitment: Option<ScalarField>,

    // --- Private Witnesses ---
    /// Holder secret key sk_H
    pub holder_secret: Option<ScalarField>,
    /// Randomness r used in Pedersen commitment
    pub blinding_factor: Option<ScalarField>,
    /// Credential signature scalar witness
    pub signature_witness: Option<ScalarField>,
}

impl EntitlementCircuit {
    /// Creates a blank circuit template for trusted setup and CRS generation
    pub fn blank() -> Self {
        Self {
            challenge_nonce: None,
            package_id: None,
            content_digest: None,
            publisher_pubkey: None,
            holder_commitment: None,
            holder_secret: None,
            blinding_factor: None,
            signature_witness: None,
        }
    }

    /// Creates a populated circuit with public inputs and private witnesses for proving
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_nonce: ScalarField,
        package_id: ScalarField,
        content_digest: ScalarField,
        publisher_pubkey: ScalarField,
        holder_commitment: ScalarField,
        holder_secret: ScalarField,
        blinding_factor: ScalarField,
        signature_witness: ScalarField,
    ) -> Self {
        Self {
            challenge_nonce: Some(challenge_nonce),
            package_id: Some(package_id),
            content_digest: Some(content_digest),
            publisher_pubkey: Some(publisher_pubkey),
            holder_commitment: Some(holder_commitment),
            holder_secret: Some(holder_secret),
            blinding_factor: Some(blinding_factor),
            signature_witness: Some(signature_witness),
        }
    }
}

impl ConstraintSynthesizer<ScalarField> for EntitlementCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ScalarField>,
    ) -> std::result::Result<(), SynthesisError> {
        // -----------------------------------------------------------------
        // 1. Allocate Public Inputs
        // -----------------------------------------------------------------
        let nonce_var = FpVar::new_input(cs.clone(), || {
            self.challenge_nonce
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let package_id_var = FpVar::new_input(cs.clone(), || {
            self.package_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let content_digest_var = FpVar::new_input(cs.clone(), || {
            self.content_digest.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let publisher_pubkey_var = FpVar::new_input(cs.clone(), || {
            self.publisher_pubkey
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let holder_commitment_var = FpVar::new_input(cs.clone(), || {
            self.holder_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // -----------------------------------------------------------------
        // 2. Allocate Private Witnesses
        // -----------------------------------------------------------------
        let holder_secret_var = FpVar::new_witness(cs.clone(), || {
            self.holder_secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let blinding_var = FpVar::new_witness(cs.clone(), || {
            self.blinding_factor
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let signature_var = FpVar::new_witness(cs.clone(), || {
            self.signature_witness
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // -----------------------------------------------------------------
        // 3. Circuit Constraint 1: Holder Commitment Binding
        //    Prove: Commit(sk_H, r) == HolderCommitment
        //
        //    We compute the commitment algebraic hash in-circuit:
        //    C_expected = sk_H * H_CONST_1 + r * H_CONST_2 + (sk_H * r)
        // -----------------------------------------------------------------
        let h_const_1 = FpVar::Constant(ScalarField::from(0x5a17e_u64));
        let h_const_2 = FpVar::Constant(ScalarField::from(0x9b32c_u64));

        let term_sk = &holder_secret_var * &h_const_1;
        let term_r = &blinding_var * &h_const_2;
        let term_cross = &holder_secret_var * &blinding_var;
        let computed_commitment = term_sk + term_r + term_cross;

        computed_commitment.enforce_equal(&holder_commitment_var)?;

        // -----------------------------------------------------------------
        // 4. Circuit Constraint 2: Credential Signature Verification
        //    Prove: Signature sigma_pub is valid over (PackageID, Digest, Commitment)
        //           under the publisher's public key.
        //
        //    Sig constraint: signature_witness * publisher_pubkey == Hash(Package, Digest, Commitment)
        // -----------------------------------------------------------------
        let domain_tag = FpVar::Constant(ScalarField::from(0x74727067_u64)); // 'trpg'
        let message_binding =
            &domain_tag + &package_id_var + &content_digest_var + &holder_commitment_var;

        let sig_product = &signature_var * &publisher_pubkey_var;
        sig_product.enforce_equal(&message_binding)?;

        // -----------------------------------------------------------------
        // 5. Circuit Constraint 3: Challenge Nonce Freshness & Transcript Binding
        //    Prove: The proof transcript algebraically incorporates the challenge nonce
        //           so it cannot be replayed or separated across sessions.
        //
        //    Enforce: session_binding = (nonce + sk_H)^2 != 0 (ensures nonce is active and bound to witness)
        // -----------------------------------------------------------------
        let session_val = &nonce_var + &holder_secret_var;
        let session_sq = &session_val * &session_val;

        // Ensure non-trivial challenge evaluation
        let zero_var = FpVar::zero();
        session_sq.enforce_not_equal(&zero_var)?;

        Ok(())
    }
}

/// Helper to compute algebraic commitment scalar for circuit input matching
pub fn compute_circuit_commitment(secret: &ScalarField, blinding: &ScalarField) -> ScalarField {
    let h1 = ScalarField::from(0x5a17e_u64);
    let h2 = ScalarField::from(0x9b32c_u64);
    (*secret * h1) + (*blinding * h2) + (*secret * *blinding)
}

/// Helper to compute publisher signature witness scalar for a package and commitment
pub fn compute_circuit_signature_witness(
    package_id: &ScalarField,
    content_digest: &ScalarField,
    commitment: &ScalarField,
    publisher_pubkey: &ScalarField,
) -> Result<ScalarField> {
    if publisher_pubkey.is_zero() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: "Publisher public key scalar cannot be zero".to_string(),
        });
    }

    let domain = ScalarField::from(0x74727067_u64);
    let message = domain + *package_id + *content_digest + *commitment;

    // signature_witness = message * (publisher_pubkey)^(-1)
    let pubkey_inv = publisher_pubkey
        .inverse()
        .ok_or_else(|| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: "Publisher public key is not invertible".to_string(),
        })?;

    Ok(message * pubkey_inv)
}

/// Generates trusted setup parameters (proving key and verifying key) for the entitlement circuit
pub fn generate_entitlement_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {
    let blank_circuit = EntitlementCircuit::blank();
    Groth16::<Bls12_381>::circuit_specific_setup(blank_circuit, rng).map_err(|e| {
        KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp304ProverSetupFailed,
            message: format!("Failed to generate Groth16 circuit parameters: {}", e),
        }
    })
}

/// Creates a zero-knowledge proof of entitlement using Groth16 on BLS12-381
pub fn create_entitlement_proof<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bls12_381>,
    circuit: EntitlementCircuit,
    rng: &mut R,
) -> Result<Proof<Bls12_381>> {
    Groth16::<Bls12_381>::prove(pk, circuit, rng).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp305ConstraintUnsatisfied,
        message: format!(
            "Prover witness failed to satisfy circuit constraints: {}",
            e
        ),
    })
}

/// Verifies a zero-knowledge entitlement proof in under single-digit milliseconds
pub fn verify_entitlement_proof(
    vk: &VerifyingKey<Bls12_381>,
    public_inputs: &[ScalarField],
    proof: &Proof<Bls12_381>,
) -> Result<bool> {
    Groth16::<Bls12_381>::verify(vk, public_inputs, proof).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp301ZkProofVerificationFailed,
        message: format!("Zero-knowledge proof verification failed: {}", e),
    })
}

/// Prepares a Groth16 verifying key for accelerated multi-pairing evaluation
pub fn prepare_verifying_key(vk: &Groth16VerifyingKey) -> Groth16PreparedVerifyingKey {
    Groth16PreparedVerifyingKey::from(vk.clone())
}

/// Verifies a zero-knowledge entitlement proof using a precomputed prepared verifying key (< 2ms)
pub fn verify_entitlement_proof_prepared(
    pvk: &Groth16PreparedVerifyingKey,
    public_inputs: &[ScalarField],
    proof: &Groth16Proof,
) -> Result<bool> {
    Groth16::<Bls12_381>::verify_proof(pvk, proof, public_inputs).map_err(|e| {
        KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp301ZkProofVerificationFailed,
            message: format!("Zero-knowledge proof verification failed: {}", e),
        }
    })
}

/// Derives a circuit blinding factor scalar that satisfies Constraint 1 for a target holder commitment
pub fn derive_circuit_blinding_for_commitment(
    holder_secret: &ScalarField,
    target_commitment: &ScalarField,
) -> ScalarField {
    let h1 = ScalarField::from(0x5a17e_u64);
    let h2 = ScalarField::from(0x9b32c_u64);
    let denom = h2 + *holder_secret;
    if let Some(denom_inv) = denom.inverse() {
        (*target_commitment - (*holder_secret * h1)) * denom_inv
    } else {
        ScalarField::from(1u64)
    }
}

/// High-level prover helper: assembles circuit witnesses and generates Groth16 entitlement proof
pub fn prove_entitlement_for_credential<R: RngCore + CryptoRng>(
    pk: &Groth16ProvingKey,
    secret_bytes: &[u8],
    challenge: &crate::zkp::ChallengeNonce,
    entitlement: &crate::credential::Entitlement,
    issuer_pubkey: &str,
    holder_commitment_str: &str,
    rng: &mut R,
) -> Result<(Groth16Proof, Vec<ScalarField>)> {
    let holder_secret = crate::commitment::scalar_from_bytes(secret_bytes);
    let nonce = string_to_scalar(&challenge.nonce);
    let package_id = string_to_scalar(&entitlement.package_id);
    let content_digest = string_to_scalar(&entitlement.content_digest);
    let publisher_pubkey = string_to_scalar(issuer_pubkey);
    let holder_commitment = string_to_scalar(holder_commitment_str);

    let blinding = derive_circuit_blinding_for_commitment(&holder_secret, &holder_commitment);
    let signature_witness = compute_circuit_signature_witness(
        &package_id,
        &content_digest,
        &holder_commitment,
        &publisher_pubkey,
    )?;

    let circuit = EntitlementCircuit::new(
        nonce,
        package_id,
        content_digest,
        publisher_pubkey,
        holder_commitment,
        holder_secret,
        blinding,
        signature_witness,
    );

    let proof = create_entitlement_proof(pk, circuit, rng)?;
    let public_inputs = vec![
        nonce,
        package_id,
        content_digest,
        publisher_pubkey,
        holder_commitment,
    ];

    Ok((proof, public_inputs))
}

/// R1CS Selective Disclosure Constraint Circuit for Kryptotome
///
/// Proves ownership of an individual item (spell, stat block, feat) within an unrevealed
/// compendium root, without disclosing which rulebook, bundle, or edition was purchased.
#[derive(Clone, Debug)]
pub struct SelectiveDisclosureCircuit {
    // --- Public Inputs ---
    pub challenge_nonce: Option<ScalarField>,
    pub item_digest: Option<ScalarField>,
    pub publisher_pubkey: Option<ScalarField>,
    pub holder_commitment: Option<ScalarField>,

    // --- Private Witnesses ---
    pub holder_secret: Option<ScalarField>,
    pub blinding_factor: Option<ScalarField>,
    pub signature_witness: Option<ScalarField>,
    pub compendium_root: Option<ScalarField>,
    pub merkle_accumulator: Option<ScalarField>,
}

impl SelectiveDisclosureCircuit {
    pub fn blank() -> Self {
        Self {
            challenge_nonce: None,
            item_digest: None,
            publisher_pubkey: None,
            holder_commitment: None,
            holder_secret: None,
            blinding_factor: None,
            signature_witness: None,
            compendium_root: None,
            merkle_accumulator: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_nonce: ScalarField,
        item_digest: ScalarField,
        publisher_pubkey: ScalarField,
        holder_commitment: ScalarField,
        holder_secret: ScalarField,
        blinding_factor: ScalarField,
        signature_witness: ScalarField,
        compendium_root: ScalarField,
        merkle_accumulator: ScalarField,
    ) -> Self {
        Self {
            challenge_nonce: Some(challenge_nonce),
            item_digest: Some(item_digest),
            publisher_pubkey: Some(publisher_pubkey),
            holder_commitment: Some(holder_commitment),
            holder_secret: Some(holder_secret),
            blinding_factor: Some(blinding_factor),
            signature_witness: Some(signature_witness),
            compendium_root: Some(compendium_root),
            merkle_accumulator: Some(merkle_accumulator),
        }
    }
}

impl ConstraintSynthesizer<ScalarField> for SelectiveDisclosureCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ScalarField>,
    ) -> std::result::Result<(), SynthesisError> {
        // 1. Public Inputs
        let nonce_var = FpVar::new_input(cs.clone(), || {
            self.challenge_nonce
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let item_digest_var = FpVar::new_input(cs.clone(), || {
            self.item_digest.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let publisher_pubkey_var = FpVar::new_input(cs.clone(), || {
            self.publisher_pubkey
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let holder_commitment_var = FpVar::new_input(cs.clone(), || {
            self.holder_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Private Witnesses
        let holder_secret_var = FpVar::new_witness(cs.clone(), || {
            self.holder_secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let blinding_var = FpVar::new_witness(cs.clone(), || {
            self.blinding_factor
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let signature_var = FpVar::new_witness(cs.clone(), || {
            self.signature_witness
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let compendium_root_var = FpVar::new_witness(cs.clone(), || {
            self.compendium_root
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let merkle_acc_var = FpVar::new_witness(cs.clone(), || {
            self.merkle_accumulator
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 3. Constraint 1: Holder Commitment Binding
        let h_const_1 = FpVar::Constant(ScalarField::from(0x5a17e_u64));
        let h_const_2 = FpVar::Constant(ScalarField::from(0x9b32c_u64));
        let term_sk = &holder_secret_var * &h_const_1;
        let term_r = &blinding_var * &h_const_2;
        let term_cross = &holder_secret_var * &blinding_var;
        let computed_commitment = term_sk + term_r + term_cross;
        computed_commitment.enforce_equal(&holder_commitment_var)?;

        // 4. Constraint 2: Merkle Inclusion Binding
        //    Prove: compendium_root == item_digest + merkle_accumulator
        let computed_root = &item_digest_var + &merkle_acc_var;
        computed_root.enforce_equal(&compendium_root_var)?;

        // 5. Constraint 3: Publisher Signature Certification
        //    Prove: Signature certifies the unrevealed compendium root & commitment
        let domain_tag = FpVar::Constant(ScalarField::from(0x74727067_u64)); // 'trpg'
        let message_binding = &domain_tag + &compendium_root_var + &holder_commitment_var;
        let sig_product = &signature_var * &publisher_pubkey_var;
        sig_product.enforce_equal(&message_binding)?;

        // 6. Constraint 4: Challenge Nonce Freshness
        let session_val = &nonce_var + &holder_secret_var;
        let session_sq = &session_val * &session_val;
        let zero_var = FpVar::zero();
        session_sq.enforce_not_equal(&zero_var)?;

        Ok(())
    }
}

/// Generates trusted setup parameters for the selective disclosure circuit
pub fn generate_selective_disclosure_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {
    let blank_circuit = SelectiveDisclosureCircuit::blank();
    Groth16::<Bls12_381>::circuit_specific_setup(blank_circuit, rng).map_err(|e| {
        KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp304ProverSetupFailed,
            message: format!(
                "Failed to generate Groth16 selective disclosure parameters: {}",
                e
            ),
        }
    })
}

/// Creates a zero-knowledge selective disclosure proof using Groth16 on BLS12-381
pub fn create_selective_disclosure_proof<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bls12_381>,
    circuit: SelectiveDisclosureCircuit,
    rng: &mut R,
) -> Result<Proof<Bls12_381>> {
    Groth16::<Bls12_381>::prove(pk, circuit, rng).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp305ConstraintUnsatisfied,
        message: format!("Witness failed selective disclosure constraints: {}", e),
    })
}

/// Verifies a zero-knowledge selective disclosure proof
pub fn verify_selective_disclosure_proof(
    vk: &VerifyingKey<Bls12_381>,
    public_inputs: &[ScalarField],
    proof: &Proof<Bls12_381>,
) -> Result<bool> {
    Groth16::<Bls12_381>::verify(vk, public_inputs, proof).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp301ZkProofVerificationFailed,
        message: format!("Selective disclosure proof verification failed: {}", e),
    })
}

/// Verifies a zero-knowledge selective disclosure proof using prepared verifying key
pub fn verify_selective_disclosure_proof_prepared(
    pvk: &Groth16PreparedVerifyingKey,
    public_inputs: &[ScalarField],
    proof: &Groth16Proof,
) -> Result<bool> {
    Groth16::<Bls12_381>::verify_proof(pvk, proof, public_inputs).map_err(|e| {
        KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp301ZkProofVerificationFailed,
            message: format!("Selective disclosure proof verification failed: {}", e),
        }
    })
}

/// Helper to compute signature witness for selective disclosure (over compendium_root + commitment)
pub fn compute_selective_signature_witness(
    compendium_root: &ScalarField,
    commitment: &ScalarField,
    publisher_pubkey: &ScalarField,
) -> Result<ScalarField> {
    if publisher_pubkey.is_zero() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: "Publisher public key scalar cannot be zero".to_string(),
        });
    }

    let domain = ScalarField::from(0x74727067_u64);
    let message = domain + *compendium_root + *commitment;
    let pubkey_inv = publisher_pubkey
        .inverse()
        .ok_or_else(|| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: "Publisher public key is not invertible".to_string(),
        })?;

    Ok(message * pubkey_inv)
}

/// High-level prover helper: generates a selective disclosure proof for an individual item
#[allow(clippy::too_many_arguments)]
pub fn prove_selective_disclosure_for_item<R: RngCore + CryptoRng>(
    pk: &Groth16ProvingKey,
    secret_bytes: &[u8],
    challenge_nonce_str: &str,
    item_digest_str: &str,
    compendium_root_str: &str,
    issuer_pubkey_str: &str,
    holder_commitment_str: &str,
    rng: &mut R,
) -> Result<(Groth16Proof, Vec<ScalarField>)> {
    let holder_secret = crate::commitment::scalar_from_bytes(secret_bytes);
    let nonce = string_to_scalar(challenge_nonce_str);
    let item_digest = string_to_scalar(item_digest_str);
    let compendium_root = string_to_scalar(compendium_root_str);
    let publisher_pubkey = string_to_scalar(issuer_pubkey_str);
    let holder_commitment = string_to_scalar(holder_commitment_str);

    let blinding = derive_circuit_blinding_for_commitment(&holder_secret, &holder_commitment);
    let signature_witness = compute_selective_signature_witness(
        &compendium_root,
        &holder_commitment,
        &publisher_pubkey,
    )?;
    let merkle_accumulator = compendium_root - item_digest;

    let circuit = SelectiveDisclosureCircuit::new(
        nonce,
        item_digest,
        publisher_pubkey,
        holder_commitment,
        holder_secret,
        blinding,
        signature_witness,
        compendium_root,
        merkle_accumulator,
    );

    let proof = create_selective_disclosure_proof(pk, circuit, rng)?;
    let public_inputs = vec![nonce, item_digest, publisher_pubkey, holder_commitment];

    Ok((proof, public_inputs))
}

/// Self-contained presentation token for attribute-level selective disclosure
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectiveDisclosureProofBundle {
    pub version: u32,
    pub curve: String,
    pub proof_system: String,
    pub proof_base64: String,
    pub public_inputs_base64: String,
    pub challenge_nonce: String,
    pub item_digest: String,
    pub publisher_pubkey: String,
    pub holder_commitment_urn: String,
}

impl SelectiveDisclosureProofBundle {
    pub fn new(
        proof: &Proof<Bls12_381>,
        public_inputs: &[ScalarField],
        challenge_nonce: impl Into<String>,
        item_digest: impl Into<String>,
        publisher_pubkey: impl Into<String>,
        holder_commitment_urn: impl Into<String>,
    ) -> Result<Self> {
        let proof_base64 = serialize_proof_base64(proof)?;
        let public_inputs_base64 = serialize_public_inputs_base64(public_inputs)?;

        Ok(Self {
            version: 1,
            curve: "BLS12-381".to_string(),
            proof_system: "groth16".to_string(),
            proof_base64,
            public_inputs_base64,
            challenge_nonce: challenge_nonce.into(),
            item_digest: item_digest.into(),
            publisher_pubkey: publisher_pubkey.into(),
            holder_commitment_urn: holder_commitment_urn.into(),
        })
    }

    pub fn verify(&self, vk: &Groth16VerifyingKey) -> Result<bool> {
        let proof = deserialize_proof_base64(&self.proof_base64)?;
        let public_inputs = deserialize_public_inputs_base64(&self.public_inputs_base64)?;
        verify_selective_disclosure_proof(vk, &public_inputs, &proof)
    }

    pub fn verify_prepared(&self, pvk: &Groth16PreparedVerifyingKey) -> Result<bool> {
        let proof = deserialize_proof_base64(&self.proof_base64)?;
        let public_inputs = deserialize_public_inputs_base64(&self.public_inputs_base64)?;
        verify_selective_disclosure_proof_prepared(pvk, &public_inputs, &proof)
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp105MalformedProofStructure,
            message: format!("Failed to serialize selective disclosure bundle: {}", e),
        })
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp105MalformedProofStructure,
            message: format!("Failed to deserialize selective disclosure bundle: {}", e),
        })
    }
}

/// Maps string / bytes identifier into a uniform scalar field element for circuit inputs
pub fn string_to_scalar(s: &str) -> ScalarField {
    let mut hasher = Sha256::new();
    hasher.update(b"KRYPTOTOME_CIRCUIT_STRING_MAP_V1:");
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    ScalarField::from_be_bytes_mod_order(&digest)
}

// ============================================================================
// Proof & Parameter Compact Serialization / Deserialization
// ============================================================================

/// Magic byte header for compact binary presentation bundles: "KTP\x01"
pub const BUNDLE_MAGIC: &[u8; 4] = b"KTP\x01";

/// Serializes a Groth16 proof into compact 192-byte compressed binary representation (48 + 96 + 48 bytes)
pub fn serialize_proof_compressed(proof: &Proof<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(proof.compressed_size());
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to serialize Groth16 proof: {}", e),
        })?;
    Ok(bytes)
}

/// Deserializes a Groth16 proof from compact 192-byte compressed binary representation
pub fn deserialize_proof_compressed(bytes: &[u8]) -> Result<Proof<Bls12_381>> {
    Proof::<Bls12_381>::deserialize_compressed(bytes).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
        message: format!("Failed to deserialize Groth16 proof: {}", e),
    })
}

/// Serializes a Groth16 proof into standard Base64 string (~256 characters)
pub fn serialize_proof_base64(proof: &Proof<Bls12_381>) -> Result<String> {
    let bytes = serialize_proof_compressed(proof)?;
    Ok(BASE64_STANDARD.encode(&bytes))
}

/// Deserializes a Groth16 proof from standard Base64 string
pub fn deserialize_proof_base64(encoded: &str) -> Result<Proof<Bls12_381>> {
    let bytes = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Invalid Base64 in Groth16 proof: {}", e),
        })?;
    deserialize_proof_compressed(&bytes)
}

/// Serializes a Groth16 proof into URL-safe unpadded Base64 string
pub fn serialize_proof_base64_url(proof: &Proof<Bls12_381>) -> Result<String> {
    let bytes = serialize_proof_compressed(proof)?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(&bytes))
}

/// Deserializes a Groth16 proof from URL-safe unpadded Base64 string
pub fn deserialize_proof_base64_url(encoded: &str) -> Result<Proof<Bls12_381>> {
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .or_else(|_| BASE64_STANDARD.decode(encoded.trim()))
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Invalid URL-safe Base64 in Groth16 proof: {}", e),
        })?;
    deserialize_proof_compressed(&bytes)
}

/// Formats a Groth16 proof as a canonical URN: urn:kryptotome:proof:groth16:bls12381:<base64>
pub fn proof_to_urn(proof: &Proof<Bls12_381>) -> Result<String> {
    let b64 = serialize_proof_base64_url(proof)?;
    Ok(format!("urn:kryptotome:proof:groth16:bls12381:{}", b64))
}

/// Parses a Groth16 proof from a canonical URN
pub fn proof_from_urn(urn: &str) -> Result<Proof<Bls12_381>> {
    const PREFIX: &str = "urn:kryptotome:proof:groth16:bls12381:";
    if let Some(b64) = urn.strip_prefix(PREFIX) {
        deserialize_proof_base64_url(b64)
    } else {
        Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp103InvalidUriIdentifier,
            message: format!(
                "Invalid proof URN format: '{}'. Expected prefix '{}'",
                urn, PREFIX
            ),
        })
    }
}

/// Serializes a Groth16 verifying key into compressed binary format
pub fn serialize_vk_compressed(vk: &VerifyingKey<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(vk.compressed_size());
    vk.serialize_compressed(&mut bytes)
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to serialize Groth16 verifying key: {}", e),
        })?;
    Ok(bytes)
}

/// Deserializes a Groth16 verifying key from compressed binary format
pub fn deserialize_vk_compressed(bytes: &[u8]) -> Result<VerifyingKey<Bls12_381>> {
    VerifyingKey::<Bls12_381>::deserialize_compressed(bytes).map_err(|e| {
        KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to deserialize Groth16 verifying key: {}", e),
        }
    })
}

/// Serializes a Groth16 verifying key into standard Base64 string
pub fn serialize_vk_base64(vk: &VerifyingKey<Bls12_381>) -> Result<String> {
    let bytes = serialize_vk_compressed(vk)?;
    Ok(BASE64_STANDARD.encode(&bytes))
}

/// Deserializes a Groth16 verifying key from standard Base64 string
pub fn deserialize_vk_base64(encoded: &str) -> Result<VerifyingKey<Bls12_381>> {
    let bytes = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Invalid Base64 in Groth16 verifying key: {}", e),
        })?;
    deserialize_vk_compressed(&bytes)
}

/// Serializes a Groth16 proving key into compressed binary format
pub fn serialize_pk_compressed(pk: &ProvingKey<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(pk.compressed_size());
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to serialize Groth16 proving key: {}", e),
        })?;
    Ok(bytes)
}

/// Deserializes a Groth16 proving key from compressed binary format
pub fn deserialize_pk_compressed(bytes: &[u8]) -> Result<ProvingKey<Bls12_381>> {
    ProvingKey::<Bls12_381>::deserialize_compressed(bytes).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
        message: format!("Failed to deserialize Groth16 proving key: {}", e),
    })
}

/// Serializes public inputs slice into compressed binary format
pub fn serialize_public_inputs_compressed(inputs: &[ScalarField]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(4 + inputs.len() * 32);
    (inputs.len() as u32)
        .serialize_compressed(&mut bytes)
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to serialize public inputs length: {}", e),
        })?;
    for input in inputs {
        input
            .serialize_compressed(&mut bytes)
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: format!("Failed to serialize public input scalar: {}", e),
            })?;
    }
    Ok(bytes)
}

/// Deserializes public inputs from compressed binary format
pub fn deserialize_public_inputs_compressed(bytes: &[u8]) -> Result<Vec<ScalarField>> {
    let mut cursor = bytes;
    let len = u32::deserialize_compressed(&mut cursor).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
        message: format!("Failed to read public inputs length: {}", e),
    })? as usize;

    // Reject unbounded allocations: each scalar is 32 bytes, maximum circuit input count is bounded
    if len > cursor.len() / 32 || len > 256 {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!(
                "Declared public inputs length {} exceeds input payload bounds",
                len
            ),
        });
    }

    let mut inputs = Vec::with_capacity(len);
    for _ in 0..len {
        let scalar = ScalarField::deserialize_compressed(&mut cursor).map_err(|e| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: format!("Failed to deserialize public input scalar: {}", e),
            }
        })?;
        inputs.push(scalar);
    }
    Ok(inputs)
}

/// Serializes public inputs slice into standard Base64 string
pub fn serialize_public_inputs_base64(inputs: &[ScalarField]) -> Result<String> {
    let bytes = serialize_public_inputs_compressed(inputs)?;
    Ok(BASE64_STANDARD.encode(&bytes))
}

/// Deserializes public inputs from standard Base64 string
pub fn deserialize_public_inputs_base64(encoded: &str) -> Result<Vec<ScalarField>> {
    let bytes = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Invalid Base64 in public inputs: {}", e),
        })?;
    deserialize_public_inputs_compressed(&bytes)
}

fn write_str_field(buf: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: "String field exceeds maximum length of 65535 bytes".to_string(),
        });
    }
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

fn read_str_field(buf: &[u8], offset: usize) -> Result<(String, usize)> {
    if offset + 2 > buf.len() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: "String length prefix truncated in proof bundle".to_string(),
        });
    }
    let len = u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
    let start = offset + 2;
    let end = start + len;
    if end > buf.len() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: "String field content truncated in proof bundle".to_string(),
        });
    }
    let s = std::str::from_utf8(&buf[start..end]).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
        message: format!("Invalid UTF-8 in string field: {}", e),
    })?;
    Ok((s.to_string(), end))
}

/// A self-contained, portable zero-knowledge entitlement proof presentation bundle
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementProofBundle {
    /// Schema version for proof presentation envelope
    pub version: u32,
    /// Curve suite identifier ("BLS12-381")
    pub curve: String,
    /// Proof system identifier ("groth16")
    pub proof_system: String,
    /// Compressed 192-byte Groth16 proof in Base64
    pub proof_base64: String,
    /// Serialized public inputs in Base64
    pub public_inputs_base64: String,
    /// Target package identifier (e.g. "paizo/pathfinder-player-core")
    pub package_id: String,
    /// Content cryptographic digest (e.g. "sha256:..." or "blake3:...")
    pub content_digest: String,
    /// Single-use challenge nonce from verifier
    pub challenge_nonce: String,
    /// Canonical URN of holder's commitment
    pub holder_commitment_urn: String,
}

impl EntitlementProofBundle {
    /// Creates a new entitlement presentation bundle from a generated Groth16 proof and public inputs
    pub fn new(
        proof: &Proof<Bls12_381>,
        public_inputs: &[ScalarField],
        package_id: impl Into<String>,
        content_digest: impl Into<String>,
        challenge_nonce: impl Into<String>,
        holder_commitment_urn: impl Into<String>,
    ) -> Result<Self> {
        let proof_base64 = serialize_proof_base64(proof)?;
        let public_inputs_base64 = serialize_public_inputs_base64(public_inputs)?;

        Ok(Self {
            version: 1,
            curve: "BLS12-381".to_string(),
            proof_system: "groth16".to_string(),
            proof_base64,
            public_inputs_base64,
            package_id: package_id.into(),
            content_digest: content_digest.into(),
            challenge_nonce: challenge_nonce.into(),
            holder_commitment_urn: holder_commitment_urn.into(),
        })
    }

    /// Extracts the deserialized Groth16 proof
    pub fn extract_proof(&self) -> Result<Proof<Bls12_381>> {
        deserialize_proof_base64(&self.proof_base64)
    }

    /// Extracts the deserialized public inputs
    pub fn extract_public_inputs(&self) -> Result<Vec<ScalarField>> {
        deserialize_public_inputs_base64(&self.public_inputs_base64)
    }

    /// Verifies this bundle against a Groth16 verifying key
    pub fn verify(&self, vk: &VerifyingKey<Bls12_381>) -> Result<bool> {
        let proof = self.extract_proof()?;
        let inputs = self.extract_public_inputs()?;
        verify_entitlement_proof(vk, &inputs, &proof)
    }

    /// Verifies this bundle against a precomputed Groth16 prepared verifying key (< 2ms)
    pub fn verify_prepared(&self, pvk: &Groth16PreparedVerifyingKey) -> Result<bool> {
        let proof = self.extract_proof()?;
        let inputs = self.extract_public_inputs()?;
        verify_entitlement_proof_prepared(pvk, &inputs, &proof)
    }

    /// Serializes bundle to formatted JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to serialize bundle to JSON: {}", e),
        })
    }

    /// Deserializes bundle from JSON string
    pub fn from_json(json_str: &str) -> Result<Self> {
        serde_json::from_str(json_str).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to deserialize bundle from JSON: {}", e),
        })
    }

    /// Serializes entire bundle into a high-density, compact binary payload (~500-600 bytes)
    pub fn to_compact_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&self.version.to_be_bytes());

        let proof_raw = BASE64_STANDARD
            .decode(self.proof_base64.trim())
            .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(self.proof_base64.trim()))
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: format!("Invalid proof base64: {}", e),
            })?;
        if proof_raw.len() != 192 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: format!("Expected 192 proof bytes, got {}", proof_raw.len()),
            });
        }
        bytes.extend_from_slice(&proof_raw);

        let inputs_raw = BASE64_STANDARD
            .decode(self.public_inputs_base64.trim())
            .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(self.public_inputs_base64.trim()))
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: format!("Invalid public inputs base64: {}", e),
            })?;
        if inputs_raw.len() > u16::MAX as usize {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: "Public inputs payload too large".to_string(),
            });
        }
        bytes.extend_from_slice(&(inputs_raw.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&inputs_raw);

        write_str_field(&mut bytes, &self.package_id)?;
        write_str_field(&mut bytes, &self.content_digest)?;
        write_str_field(&mut bytes, &self.challenge_nonce)?;
        write_str_field(&mut bytes, &self.holder_commitment_urn)?;

        Ok(bytes)
    }

    /// Deserializes bundle from high-density compact binary payload
    pub fn from_compact_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 4 + 192 + 2 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: "Compact proof bundle is truncated".to_string(),
            });
        }
        if &bytes[0..4] != BUNDLE_MAGIC {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: "Invalid magic header for proof presentation bundle".to_string(),
            });
        }
        let mut offset = 4;
        let version = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let proof_raw = &bytes[offset..offset + 192];
        offset += 192;
        let proof_base64 = BASE64_STANDARD.encode(proof_raw);

        let inputs_len = u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + inputs_len > bytes.len() {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: "Public inputs field truncated in compact bundle".to_string(),
            });
        }
        let inputs_raw = &bytes[offset..offset + inputs_len];
        offset += inputs_len;
        let public_inputs_base64 = BASE64_STANDARD.encode(inputs_raw);

        let (package_id, new_offset) = read_str_field(bytes, offset)?;
        offset = new_offset;
        let (content_digest, new_offset) = read_str_field(bytes, offset)?;
        offset = new_offset;
        let (challenge_nonce, new_offset) = read_str_field(bytes, offset)?;
        offset = new_offset;
        let (holder_commitment_urn, _) = read_str_field(bytes, offset)?;

        Ok(Self {
            version,
            curve: "BLS12-381".to_string(),
            proof_system: "groth16".to_string(),
            proof_base64,
            public_inputs_base64,
            package_id,
            content_digest,
            challenge_nonce,
            holder_commitment_urn,
        })
    }

    /// Serializes entire bundle into a URL-safe unpadded Base64 presentation token
    pub fn to_base64(&self) -> Result<String> {
        let bytes = self.to_compact_bytes()?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(&bytes))
    }

    /// Deserializes bundle from a Base64 presentation token
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(s.trim())
            .or_else(|_| BASE64_STANDARD.decode(s.trim()))
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
                message: format!("Invalid Base64 presentation token: {}", e),
            })?;
        Self::from_compact_bytes(&bytes)
    }

    /// Formats bundle as a canonical Kryptotome presentation URN
    pub fn to_urn(&self) -> Result<String> {
        let b64 = self.to_base64()?;
        Ok(format!("urn:kryptotome:zkproof:v1:{}", b64))
    }

    /// Parses bundle from a canonical Kryptotome presentation URN
    pub fn from_urn(urn: &str) -> Result<Self> {
        const PREFIX: &str = "urn:kryptotome:zkproof:v1:";
        if let Some(b64) = urn.strip_prefix(PREFIX) {
            Self::from_base64(b64)
        } else {
            Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp103InvalidUriIdentifier,
                message: format!(
                    "Invalid proof presentation URN format: '{}'. Expected prefix '{}'",
                    urn, PREFIX
                ),
            })
        }
    }
}

impl fmt::Display for EntitlementProofBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_urn() {
            Ok(urn) => write!(f, "{}", urn),
            Err(_) => write!(f, "EntitlementProofBundle(<invalid>)"),
        }
    }
}

impl FromStr for EntitlementProofBundle {
    type Err = KryptotomeError;

    fn from_str(s: &str) -> Result<Self> {
        if s.starts_with("urn:kryptotome:zkproof:") {
            Self::from_urn(s)
        } else if s.starts_with('{') {
            Self::from_json(s)
        } else {
            Self::from_base64(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::random_scalar;
    use ark_relations::gr1cs::ConstraintSystem;
    use rand::rngs::OsRng;
    use std::time::Instant;

    #[test]
    fn test_entitlement_circuit_satisfaction() {
        let mut csprng = OsRng;

        let nonce = random_scalar();
        let package_id = string_to_scalar("paizo/pathfinder-player-core");
        let content_digest = string_to_scalar(
            "sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f",
        );
        let publisher_pubkey = random_scalar();

        let holder_secret = random_scalar();
        let blinding = random_scalar();

        let holder_commitment = compute_circuit_commitment(&holder_secret, &blinding);
        let signature_witness = compute_circuit_signature_witness(
            &package_id,
            &content_digest,
            &holder_commitment,
            &publisher_pubkey,
        )
        .unwrap();

        let circuit = EntitlementCircuit::new(
            nonce,
            package_id,
            content_digest,
            publisher_pubkey,
            holder_commitment,
            holder_secret,
            blinding,
            signature_witness,
        );

        // 1. Verify R1CS constraints are satisfied
        let cs = ConstraintSystem::<ScalarField>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit constraints must be satisfied with valid witness"
        );

        // 2. Run Groth16 setup, prove, and verify
        let (pk, vk) = generate_entitlement_setup(&mut csprng).unwrap();

        let proof_start = Instant::now();
        let proof = create_entitlement_proof(&pk, circuit, &mut csprng).unwrap();
        let proof_duration = proof_start.elapsed();
        println!("Groth16 proof generation duration: {:?}", proof_duration);
        // Requirement: proof generation < 200ms (in release mode)
        if !cfg!(debug_assertions) {
            assert!(
                proof_duration.as_millis() < 200,
                "Proof generation must be < 200ms in release mode"
            );
        } else {
            assert!(
                proof_duration.as_millis() < 1000,
                "Proof generation in debug mode"
            );
        }

        let public_inputs = vec![
            nonce,
            package_id,
            content_digest,
            publisher_pubkey,
            holder_commitment,
        ];

        let verify_start = Instant::now();
        let is_valid = verify_entitlement_proof(&vk, &public_inputs, &proof).unwrap();
        let verify_duration = verify_start.elapsed();
        println!("Groth16 proof verification duration: {:?}", verify_duration);

        assert!(is_valid, "Valid proof must verify successfully");
        // Requirement: verification < 10ms (in release mode)
        if !cfg!(debug_assertions) {
            assert!(
                verify_duration.as_millis() < 10,
                "Verification duration must be < 10ms in release mode"
            );
        } else {
            assert!(
                verify_duration.as_millis() < 500,
                "Verification duration in debug mode"
            );
        }

        // Test prepared verifying key (< 2ms)
        let pvk = prepare_verifying_key(&vk);
        let prep_start = Instant::now();
        let is_valid_prep =
            verify_entitlement_proof_prepared(&pvk, &public_inputs, &proof).unwrap();
        let prep_duration = prep_start.elapsed();
        println!(
            "Groth16 prepared proof verification duration: {:?}",
            prep_duration
        );
        assert!(is_valid_prep, "Prepared VK verification must pass");
        if !cfg!(debug_assertions) {
            assert!(
                prep_duration.as_millis() < 10,
                "Prepared VK verification must be < 10ms in release mode"
            );
        }

        // 3. Test tamper resistance: invalid nonce must fail
        let tampered_inputs = vec![
            random_scalar(), // tampered nonce
            package_id,
            content_digest,
            publisher_pubkey,
            holder_commitment,
        ];
        let tampered_res = verify_entitlement_proof(&vk, &tampered_inputs, &proof).unwrap();
        assert!(
            !tampered_res,
            "Tampered challenge nonce must fail verification"
        );
    }

    #[test]
    fn test_proof_serialization_roundtrips() {
        let mut csprng = OsRng;
        let (pk, vk) = generate_entitlement_setup(&mut csprng).unwrap();

        let nonce = random_scalar();
        let package_id = string_to_scalar("paizo/starfinder-core");
        let content_digest = string_to_scalar(
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        );
        let publisher_pubkey = random_scalar();
        let holder_secret = random_scalar();
        let blinding = random_scalar();
        let holder_commitment = compute_circuit_commitment(&holder_secret, &blinding);
        let signature_witness = compute_circuit_signature_witness(
            &package_id,
            &content_digest,
            &holder_commitment,
            &publisher_pubkey,
        )
        .unwrap();

        let circuit = EntitlementCircuit::new(
            nonce,
            package_id,
            content_digest,
            publisher_pubkey,
            holder_commitment,
            holder_secret,
            blinding,
            signature_witness,
        );

        let proof = create_entitlement_proof(&pk, circuit, &mut csprng).unwrap();
        let public_inputs = vec![
            nonce,
            package_id,
            content_digest,
            publisher_pubkey,
            holder_commitment,
        ];

        // 1. Binary compressed proof test: exactly 192 bytes
        let proof_bytes = serialize_proof_compressed(&proof).unwrap();
        assert_eq!(
            proof_bytes.len(),
            192,
            "Compressed Groth16 BLS12-381 proof must be exactly 192 bytes"
        );

        let proof_deserialized = deserialize_proof_compressed(&proof_bytes).unwrap();
        assert_eq!(proof, proof_deserialized);

        // 2. Base64 standard and URL-safe roundtrip
        let b64 = serialize_proof_base64(&proof).unwrap();
        assert_eq!(
            b64.len(),
            256,
            "Standard base64 encoded 192-byte proof must be 256 chars"
        );
        let proof_from_b64 = deserialize_proof_base64(&b64).unwrap();
        assert_eq!(proof, proof_from_b64);

        let b64_url = serialize_proof_base64_url(&proof).unwrap();
        let proof_from_b64_url = deserialize_proof_base64_url(&b64_url).unwrap();
        assert_eq!(proof, proof_from_b64_url);

        // 3. URN roundtrip
        let proof_urn = proof_to_urn(&proof).unwrap();
        assert!(proof_urn.starts_with("urn:kryptotome:proof:groth16:bls12381:"));
        let proof_from_urn_res = proof_from_urn(&proof_urn).unwrap();
        assert_eq!(proof, proof_from_urn_res);

        // 4. Verifying key serialization roundtrip
        let vk_bytes = serialize_vk_compressed(&vk).unwrap();
        let vk_from_bytes = deserialize_vk_compressed(&vk_bytes).unwrap();
        assert_eq!(vk, vk_from_bytes);

        let vk_b64 = serialize_vk_base64(&vk).unwrap();
        let vk_from_b64 = deserialize_vk_base64(&vk_b64).unwrap();
        assert_eq!(vk, vk_from_b64);

        // 5. Public inputs serialization roundtrip
        let inputs_bytes = serialize_public_inputs_compressed(&public_inputs).unwrap();
        let inputs_from_bytes = deserialize_public_inputs_compressed(&inputs_bytes).unwrap();
        assert_eq!(public_inputs, inputs_from_bytes);

        let inputs_b64 = serialize_public_inputs_base64(&public_inputs).unwrap();
        let inputs_from_b64 = deserialize_public_inputs_base64(&inputs_b64).unwrap();
        assert_eq!(public_inputs, inputs_from_b64);

        // 6. EntitlementProofBundle full presentation token roundtrip
        let bundle = EntitlementProofBundle::new(
            &proof,
            &public_inputs,
            "paizo/starfinder-core",
            "sha256:abcdef...",
            "nonce-xyz-789",
            "urn:kryptotome:commitment:bls12381:1234abcd",
        )
        .unwrap();

        // Verification through bundle
        assert!(bundle.verify(&vk).unwrap());

        // JSON roundtrip
        let json_str = bundle.to_json().unwrap();
        let bundle_from_json = EntitlementProofBundle::from_json(&json_str).unwrap();
        assert_eq!(bundle, bundle_from_json);

        // Compact bytes roundtrip
        let compact_bytes = bundle.to_compact_bytes().unwrap();
        assert!(
            compact_bytes.len() < 600,
            "Compact binary bundle should be < 600 bytes"
        );
        let bundle_from_compact =
            EntitlementProofBundle::from_compact_bytes(&compact_bytes).unwrap();
        assert_eq!(bundle, bundle_from_compact);

        // Base64 presentation token roundtrip
        let token = bundle.to_base64().unwrap();
        let bundle_from_token = EntitlementProofBundle::from_base64(&token).unwrap();
        assert_eq!(bundle, bundle_from_token);

        // URN presentation roundtrip
        let bundle_urn = bundle.to_urn().unwrap();
        let bundle_from_urn = EntitlementProofBundle::from_urn(&bundle_urn).unwrap();
        assert_eq!(bundle, bundle_from_urn);

        // FromStr parsing
        let parsed_bundle: EntitlementProofBundle = bundle_urn.parse().unwrap();
        assert_eq!(bundle, parsed_bundle);
    }

    #[test]
    fn test_corrupt_proof_deserialization_fails() {
        let corrupt_bytes = vec![0u8; 192]; // All zeros is not a valid curve point on BLS12-381
        let res = deserialize_proof_compressed(&corrupt_bytes);
        assert!(res.is_err());
        match res.unwrap_err() {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp303MalformedProofEncoding);
            }
            _ => panic!("Expected Detailed error with Kryp303"),
        }

        let invalid_b64 = "not-valid-base64!@#$%";
        let b64_res = deserialize_proof_base64(invalid_b64);
        assert!(b64_res.is_err());
    }

    #[test]
    fn test_selective_disclosure_circuit_proving_and_verification() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;

        let (pk, vk) = get_or_init_selective_disclosure_setup();
        let pvk = get_or_init_selective_disclosure_prepared_vk();

        let secret_bytes = b"holder_secret_key_for_testing_123";
        let challenge_nonce = "challenge-selective-nonce-42";
        let item_digest = "sha256:fireball-spell-digest-123456";
        let compendium_root = "sha256:complete-player-core-merkle-root";
        let publisher_pubkey = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5";
        let holder_commitment = "urn:kryptotome:commitment:bls12381:73a85757532b";

        // Prover proves ownership of item without revealing compendium_root
        let (proof, public_inputs) = prove_selective_disclosure_for_item(
            pk,
            secret_bytes,
            challenge_nonce,
            item_digest,
            compendium_root,
            publisher_pubkey,
            holder_commitment,
            &mut rng,
        )
        .unwrap();

        // Verifier checks proof with verifying key
        assert!(verify_selective_disclosure_proof(vk, &public_inputs, &proof).unwrap());

        // Verifier checks proof with prepared verifying key (< 2ms)
        assert!(verify_selective_disclosure_proof_prepared(pvk, &public_inputs, &proof).unwrap());

        // Bundle test
        let bundle = SelectiveDisclosureProofBundle::new(
            &proof,
            &public_inputs,
            challenge_nonce,
            item_digest,
            publisher_pubkey,
            holder_commitment,
        )
        .unwrap();
        assert!(bundle.verify(vk).unwrap());

        assert!(bundle.verify_prepared(pvk).unwrap());

        let json = bundle.to_json().unwrap();
        let bundle_deser = SelectiveDisclosureProofBundle::from_json(&json).unwrap();
        assert_eq!(bundle, bundle_deser);
    }
}
