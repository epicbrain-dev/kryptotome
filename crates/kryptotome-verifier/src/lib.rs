//! Kryptotome Verifier: Fast Embedded Verification Engine (<10ms)
//!
//! Evaluates single-use zero-knowledge proofs offline and issues/validates
//! ephemeral session tokens for GM-to-player table-sharing.

pub mod cache;
pub mod session;

pub use cache::{
    CachedEntitlement, EntitlementCache, InvalidationEvent, InvalidationReason,
    DEFAULT_CACHE_TTL_SECONDS,
};
pub use kryptotome_core::{
    AggregatedPartySessionProof, CompendiumItem, CompendiumMerkleTree, MerkleInclusionProof,
    MerklePathNode, PartyMemberContribution, PartySessionPool, PasskeyAssertion, PasskeyBinding,
    PasskeyHardwareManager, PasskeyVerificationResult, SelectiveDisclosureCircuit,
    SelectiveDisclosureProofBundle,
};
pub use session::{
    EntitlementProvider, MountedCompendiumSession, PeerAccessRequest, PeerAccessResponse,
    PeerSessionClient, PeerSessionRenewalRequest, RevocationEntry, ScopePolicy, SessionAttestation,
    SessionManager, SessionRevocationNotice, DEFAULT_SESSION_DURATION_MINUTES,
};

use chrono::{DateTime, Utc};
use kryptotome_core::{
    deserialize_proof_compressed, deserialize_vk_compressed,
    error::{KryptotomeError, KryptotomeErrorCode, Result},
    get_or_init_entitlement_prepared_vk, get_or_init_selective_disclosure_prepared_vk,
    prepare_verifying_key, string_to_scalar, verify_entitlement_proof_prepared, verify_kzg_opening,
    verify_multi_pairing_identity, verify_pairing_equality, verify_plonk_batch_opening,
    zkp::{ChallengeNonce, VerificationKey, ZkProof},
    EntitlementProofBundle, G1Point, G2Point, Groth16PreparedVerifyingKey, Groth16VerifyingKey,
    ScalarField, TargetField,
};
use std::collections::HashMap;

/// High-performance embedded zero-knowledge verification engine
pub struct EmbeddedVerifier {
    cache: EntitlementCache,
    default_pvk: Option<Groth16PreparedVerifyingKey>,
    publisher_keys: HashMap<String, Groth16PreparedVerifyingKey>,
    consumed_nonces: HashMap<String, DateTime<Utc>>,
}

impl Default for EmbeddedVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbeddedVerifier {
    /// Creates a new EmbeddedVerifier with lazy global setup
    pub fn new() -> Self {
        Self {
            cache: EntitlementCache::new(),
            default_pvk: None,
            publisher_keys: HashMap::new(),
            consumed_nonces: HashMap::new(),
        }
    }

    /// Creates a verifier configured with an explicit Groth16 verifying key
    pub fn with_verifying_key(vk: &Groth16VerifyingKey) -> Self {
        let pvk = prepare_verifying_key(vk);
        Self {
            cache: EntitlementCache::new(),
            default_pvk: Some(pvk),
            publisher_keys: HashMap::new(),
            consumed_nonces: HashMap::new(),
        }
    }

    /// Creates a verifier configured with a precomputed prepared verifying key
    pub fn with_prepared_vk(pvk: Groth16PreparedVerifyingKey) -> Self {
        Self {
            cache: EntitlementCache::new(),
            default_pvk: Some(pvk),
            publisher_keys: HashMap::new(),
            consumed_nonces: HashMap::new(),
        }
    }

    /// Registers a publisher verifying key into the engine
    pub fn register_publisher_vk(&mut self, publisher_id: &str, vk: &Groth16VerifyingKey) {
        let pvk = prepare_verifying_key(vk);
        self.publisher_keys.insert(publisher_id.to_string(), pvk);
    }

    /// Registers a publisher verifying key from compressed binary bytes
    pub fn register_publisher_vk_compressed(
        &mut self,
        publisher_id: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let vk = deserialize_vk_compressed(bytes)?;
        self.register_publisher_vk(publisher_id, &vk);
        Ok(())
    }

    /// Resolves the prepared verifying key for a given publisher or defaults
    pub fn resolve_pvk(&self, publisher_id: Option<&str>) -> &Groth16PreparedVerifyingKey {
        if let Some(id) = publisher_id {
            if let Some(pvk) = self.publisher_keys.get(id) {
                return pvk;
            }
        }
        if let Some(ref pvk) = self.default_pvk {
            pvk
        } else {
            get_or_init_entitlement_prepared_vk()
        }
    }

    /// Checks if a nonce was already consumed, cleaning up expired nonces
    pub fn is_nonce_consumed(&mut self, nonce: &str) -> bool {
        let now = Utc::now();
        self.consumed_nonces
            .retain(|_, expires_at| *expires_at > now);
        self.consumed_nonces.contains_key(nonce)
    }

    /// Marks a challenge nonce as consumed with an expiration timestamp
    pub fn mark_nonce_consumed(&mut self, nonce: &str, expires_at: DateTime<Utc>) {
        let now = Utc::now();
        self.consumed_nonces.retain(|_, exp| *exp > now);
        self.consumed_nonces.insert(nonce.to_string(), expires_at);
    }

    /// Verifies zero-knowledge proof against publisher verification key and challenge nonce in < 10ms
    pub fn verify_zk_proof(
        &mut self,
        vk: &VerificationKey,
        challenge: &ChallengeNonce,
        proof: &ZkProof,
    ) -> Result<bool> {
        // 1. Check challenge validity and expiration
        if challenge.is_expired() {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp401ChallengeExpired,
                message: "Challenge nonce has expired".to_string(),
            });
        }

        // 2. Prevent replay attacks: check if nonce was already consumed
        if self.is_nonce_consumed(&challenge.nonce) {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                message: format!(
                    "Challenge nonce '{}' has already been consumed (replay detected)",
                    challenge.nonce
                ),
            });
        }

        // 3. Validate binding of public inputs to challenge
        if proof.public_inputs.challenge_nonce != challenge.nonce {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp302PublicInputMismatch,
                message: "Challenge nonce does not match proof public inputs".to_string(),
            });
        }

        if proof.public_inputs.package_id != challenge.package_id {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp403ChallengePackageMismatch,
                message: "Package ID does not match challenge".to_string(),
            });
        }

        // 4. Deserialize Groth16 proof
        let groth16_proof = deserialize_proof_compressed(&proof.proof_bytes)?;

        // 5. Map public inputs to scalar fields
        let nonce_scalar = string_to_scalar(&proof.public_inputs.challenge_nonce);
        let package_scalar = string_to_scalar(&proof.public_inputs.package_id);
        let digest_scalar = string_to_scalar(&proof.public_inputs.content_digest);
        let pubkey_scalar = string_to_scalar(&proof.public_inputs.publisher_pubkey_hash);
        let commitment_str = proof
            .public_inputs
            .holder_commitment
            .as_deref()
            .unwrap_or("");
        let commitment_scalar = string_to_scalar(commitment_str);

        let public_inputs = vec![
            nonce_scalar,
            package_scalar,
            digest_scalar,
            pubkey_scalar,
            commitment_scalar,
        ];

        // 6. Select prepared verifying key (explicit in vk bytes, by publisher_id, or default)
        let resolved_pvk_holder: Option<Groth16PreparedVerifyingKey>;
        let pvk_ref: &Groth16PreparedVerifyingKey = if !vk.key_bytes.is_empty() {
            if let Ok(parsed_vk) = deserialize_vk_compressed(&vk.key_bytes) {
                resolved_pvk_holder = Some(prepare_verifying_key(&parsed_vk));
                resolved_pvk_holder.as_ref().unwrap()
            } else {
                self.resolve_pvk(Some(&vk.publisher_id))
            }
        } else {
            self.resolve_pvk(Some(&vk.publisher_id))
        };

        // 7. Fast Arkworks Groth16 pairing evaluation
        let is_valid = verify_entitlement_proof_prepared(pvk_ref, &public_inputs, &groth16_proof)?;

        if is_valid {
            self.mark_nonce_consumed(&challenge.nonce, challenge.expires_at);
            self.cache.mark_verified(
                &proof.public_inputs.package_id,
                &proof.public_inputs.content_digest,
            );
        }

        Ok(is_valid)
    }

    /// Verifies a self-contained EntitlementProofBundle against challenge and prepared VK
    pub fn verify_proof_bundle(
        &mut self,
        bundle: &EntitlementProofBundle,
        challenge: &ChallengeNonce,
    ) -> Result<bool> {
        if challenge.is_expired() {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp401ChallengeExpired,
                message: "Challenge nonce has expired".to_string(),
            });
        }

        // Prevent replay attacks: check if nonce was already consumed
        if self.is_nonce_consumed(&challenge.nonce) {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                message: format!(
                    "Challenge nonce '{}' has already been consumed (replay detected)",
                    challenge.nonce
                ),
            });
        }

        if bundle.challenge_nonce != challenge.nonce {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp302PublicInputMismatch,
                message: "Challenge nonce does not match proof presentation bundle".to_string(),
            });
        }

        if bundle.package_id != challenge.package_id {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp403ChallengePackageMismatch,
                message: "Package ID does not match challenge".to_string(),
            });
        }

        let pvk = self.resolve_pvk(None);
        let is_valid = bundle.verify_prepared(pvk)?;

        if is_valid {
            self.mark_nonce_consumed(&challenge.nonce, challenge.expires_at);
            self.cache
                .mark_verified(&bundle.package_id, &bundle.content_digest);
        }

        Ok(is_valid)
    }

    /// Verifies an attribute-level selective disclosure proof bundle (< 10ms)
    pub fn verify_selective_disclosure(
        &mut self,
        bundle: &SelectiveDisclosureProofBundle,
        expected_nonce: &str,
    ) -> Result<bool> {
        if self.is_nonce_consumed(expected_nonce) {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                message: format!(
                    "Challenge nonce '{}' has already been consumed (replay detected)",
                    expected_nonce
                ),
            });
        }

        if bundle.challenge_nonce != expected_nonce {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp302PublicInputMismatch,
                message: "Challenge nonce does not match selective disclosure proof".to_string(),
            });
        }

        let pvk = get_or_init_selective_disclosure_prepared_vk();
        let is_valid = bundle.verify_prepared(pvk)?;

        if is_valid {
            let expires_at = Utc::now() + chrono::Duration::minutes(5);
            self.mark_nonce_consumed(expected_nonce, expires_at);
        }

        Ok(is_valid)
    }

    /// Fast Plonk / KZG polynomial commitment opening verification (< 2ms)
    pub fn verify_plonk_kzg(
        &self,
        commitment: &G1Point,
        point_z: &ScalarField,
        value_y: &ScalarField,
        proof_w: &G1Point,
        srs_g2_x: &G2Point,
    ) -> bool {
        verify_kzg_opening(commitment, point_z, value_y, proof_w, srs_g2_x)
    }

    /// Fast batched Plonk opening verification (< 2ms)
    #[allow(clippy::too_many_arguments)]
    pub fn verify_plonk_batch(
        &self,
        w_z: &G1Point,
        w_zw: &G1Point,
        folded_commitments: &G1Point,
        point_z: &ScalarField,
        omega: &ScalarField,
        challenge_u: &ScalarField,
        srs_g2_x: &G2Point,
    ) -> bool {
        verify_plonk_batch_opening(
            w_z,
            w_zw,
            folded_commitments,
            point_z,
            omega,
            challenge_u,
            srs_g2_x,
        )
    }

    /// Evaluates a multi-pairing: prod_{i} e(P_i, Q_i) into target field GT
    pub fn evaluate_multi_pairing(&self, pairs: &[(&G1Point, &G2Point)]) -> TargetField {
        kryptotome_core::evaluate_multi_pairing(pairs)
    }

    /// Verifies whether the multi-pairing product equals the identity in GT: prod_{i} e(P_i, Q_i) == 1
    pub fn verify_multi_pairing_identity(&self, pairs: &[(&G1Point, &G2Point)]) -> bool {
        verify_multi_pairing_identity(pairs)
    }

    /// Verifies equality of two pairings: e(P1, Q1) == e(P2, Q2)
    pub fn verify_pairing_equality(
        &self,
        p1: &G1Point,
        q1: &G2Point,
        p2: &G1Point,
        q2: &G2Point,
    ) -> bool {
        verify_pairing_equality(p1, q1, p2, q2)
    }

    /// Checks if a package is currently unlocked in the local session cache
    pub fn is_package_unlocked(&self, package_id: &str) -> bool {
        self.cache.is_unlocked(package_id)
    }

    /// Invalidates entitlement for a specific package
    pub fn invalidate_package(&mut self, package_id: &str) -> bool {
        self.cache
            .invalidate_package(package_id, InvalidationReason::ManualEviction)
    }

    /// Invalidates entitlement when package assets are reloaded
    pub fn reload_package(&mut self, package_id: &str) -> bool {
        self.cache.reload_package(package_id)
    }

    /// Invalidates entitlement if local file content digest changed
    pub fn invalidate_if_digest_mismatch(
        &mut self,
        package_id: &str,
        current_digest: &str,
    ) -> bool {
        self.cache
            .invalidate_if_digest_mismatch(package_id, current_digest)
    }

    /// Exits the current active game session and purges unlocked compendiums
    pub fn exit_session(&mut self) -> usize {
        self.cache.exit_session(None)
    }

    /// Exits a specific game session by ID and purges its unlocked compendiums
    pub fn exit_session_id(&mut self, session_id: &str) -> usize {
        self.cache.exit_session(Some(session_id))
    }

    /// Prunes expired entitlements from the cache
    pub fn prune_expired(&mut self) -> usize {
        self.cache.prune_expired().len()
    }

    /// Configures the default TTL duration for verified packages
    pub fn set_cache_ttl(&mut self, ttl: chrono::Duration) {
        self.cache.set_default_ttl(ttl);
    }

    /// Configures the default TTL duration in seconds
    pub fn set_cache_ttl_seconds(&mut self, seconds: i64) {
        self.cache
            .set_default_ttl(chrono::Duration::seconds(seconds));
    }

    /// Returns a reference to the internal entitlement cache
    pub fn cache(&self) -> &EntitlementCache {
        &self.cache
    }

    /// Returns a mutable reference to the internal entitlement cache
    pub fn cache_mut(&mut self) -> &mut EntitlementCache {
        &mut self.cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_construction_and_key_registration() {
        let mut verifier = EmbeddedVerifier::new();
        assert!(!verifier.is_package_unlocked("paizo/starfinder-core"));

        let (_, vk) = kryptotome_core::get_or_init_entitlement_setup();
        verifier.register_publisher_vk("publisher-1", vk);
        let pvk = verifier.resolve_pvk(Some("publisher-1"));
        assert!(!pvk.vk.gamma_abc_g1.is_empty());
    }

    #[test]
    fn test_verifier_selective_disclosure() {
        use rand::rngs::OsRng;
        let mut verifier = EmbeddedVerifier::new();

        let (pk, _) = kryptotome_core::get_or_init_selective_disclosure_setup();
        let secret = [77u8; 32];
        let challenge_nonce = "challenge-selective-test-99";
        let item_digest = "sha256:spell-fireball-test";
        let compendium_root = "sha256:root-test";
        let publisher_pubkey = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let holder_commitment = "urn:kryptotome:commitment:bls12381:test99";

        let (proof, public_inputs) = kryptotome_core::circuit::prove_selective_disclosure_for_item(
            pk,
            &secret,
            challenge_nonce,
            item_digest,
            compendium_root,
            publisher_pubkey,
            holder_commitment,
            &mut OsRng,
        )
        .unwrap();

        let bundle = SelectiveDisclosureProofBundle::new(
            &proof,
            &public_inputs,
            challenge_nonce,
            item_digest,
            publisher_pubkey,
            holder_commitment,
        )
        .unwrap();

        // Verification passes with expected challenge nonce
        let is_valid = verifier
            .verify_selective_disclosure(&bundle, challenge_nonce)
            .unwrap();
        assert!(is_valid);

        // Replay rejected: second attempt with same nonce fails
        let replay_err = verifier
            .verify_selective_disclosure(&bundle, challenge_nonce)
            .unwrap_err();
        assert!(matches!(
            replay_err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                ..
            }
        ));
    }
}
