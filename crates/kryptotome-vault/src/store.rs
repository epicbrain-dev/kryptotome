use crate::keyring::Keyring;
use kryptotome_core::{
    credential::KryptotomeCredential,
    error::{KryptotomeError, Result},
    zkp::{ChallengeNonce, ProofInputs, ZkProof},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VaultStore {
    pub credentials: HashMap<String, KryptotomeCredential>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVaultFile {
    pub version: String,
    pub key_id: String,
    pub credentials_count: usize,
    pub payload_json: String,
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    pub fn insert_credential(&mut self, credential: KryptotomeCredential) {
        self.credentials.insert(credential.id.clone(), credential);
    }

    pub fn get_credential(&self, credential_id: &str) -> Option<&KryptotomeCredential> {
        self.credentials.get(credential_id)
    }

    pub fn find_for_package(&self, package_id: &str) -> Option<&KryptotomeCredential> {
        self.credentials
            .values()
            .find(|c| c.has_entitlement(package_id))
    }

    pub fn export_to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(KryptotomeError::SerializationError)
    }

    pub fn import_from_json(json_str: &str) -> Result<Self> {
        serde_json::from_str(json_str).map_err(KryptotomeError::SerializationError)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = self.export_to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::import_from_json(&content)
    }

    /// Generate a single-use ZK proof for a challenge nonce
    pub fn create_proof_for_challenge(
        &self,
        keyring: &Keyring,
        challenge: &ChallengeNonce,
    ) -> Result<ZkProof> {
        let cred = self
            .find_for_package(&challenge.package_id)
            .ok_or_else(|| KryptotomeError::EntitlementNotFound(challenge.package_id.clone()))?;

        if challenge.is_expired() {
            return Err(KryptotomeError::InvalidChallenge(
                "Challenge nonce has expired".to_string(),
            ));
        }

        let entitlement = cred
            .credential_subject
            .entitlements
            .iter()
            .find(|e| e.package_id == challenge.package_id)
            .ok_or_else(|| KryptotomeError::EntitlementNotFound(challenge.package_id.clone()))?;

        // Construct proof with public inputs
        let public_inputs = ProofInputs {
            challenge_nonce: challenge.nonce.clone(),
            package_id: challenge.package_id.clone(),
            content_digest: entitlement.content_digest.clone(),
            publisher_pubkey_hash: cred.issuer.public_key.clone(),
        };

        // Note: Real ZK circuit execution (Groth16/arkworks) will be wired in functionality phase
        let mock_proof_payload = format!(
            "zkp:{}:{}:{}",
            keyring.key_id, challenge.nonce, entitlement.package_id
        );

        Ok(ZkProof {
            proof_bytes: mock_proof_payload.into_bytes(),
            public_inputs,
        })
    }
}
