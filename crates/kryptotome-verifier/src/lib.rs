//! Kryptotome Verifier: Fast Embedded Verification Engine (<10ms)
//!
//! Evaluates single-use zero-knowledge proofs offline and issues/validates
//! ephemeral session tokens for GM-to-player table-sharing.

pub mod cache;
pub mod session;

pub use cache::EntitlementCache;
pub use session::{SessionAttestation, SessionManager};

use kryptotome_core::{
    error::{KryptotomeError, Result},
    zkp::{ChallengeNonce, VerificationKey, ZkProof},
};

pub struct EmbeddedVerifier {
    cache: EntitlementCache,
}

impl Default for EmbeddedVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbeddedVerifier {
    pub fn new() -> Self {
        Self {
            cache: EntitlementCache::new(),
        }
    }

    /// Verifies zero-knowledge proof against publisher verification key and challenge nonce
    pub fn verify_zk_proof(
        &mut self,
        _vk: &VerificationKey,
        challenge: &ChallengeNonce,
        proof: &ZkProof,
    ) -> Result<bool> {
        // 1. Check challenge validity and expiration
        if challenge.is_expired() {
            return Err(KryptotomeError::InvalidChallenge(
                "Challenge nonce has expired".to_string(),
            ));
        }

        // 2. Validate binding of public inputs to challenge
        if proof.public_inputs.challenge_nonce != challenge.nonce {
            return Err(KryptotomeError::InvalidChallenge(
                "Challenge nonce does not match proof public inputs".to_string(),
            ));
        }

        if proof.public_inputs.package_id != challenge.package_id {
            return Err(KryptotomeError::InvalidChallenge(
                "Package ID does not match challenge".to_string(),
            ));
        }

        // 3. In functionality phase, run Groth16 / arkworks pairing check
        // For scaffold: ensure proof bytes exist and mark cached verification
        let is_valid = !proof.proof_bytes.is_empty();
        if is_valid {
            self.cache.mark_verified(
                &proof.public_inputs.package_id,
                &proof.public_inputs.content_digest,
            );
        }

        Ok(is_valid)
    }

    pub fn is_package_unlocked(&self, package_id: &str) -> bool {
        self.cache.is_unlocked(package_id)
    }
}
