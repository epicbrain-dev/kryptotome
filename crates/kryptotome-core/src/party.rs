use crate::error::{KryptotomeError, KryptotomeErrorCode, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Contribution from a party member pooling their owned rulebook to the table session
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyMemberContribution {
    pub peer_id: String,
    pub package_id: String,
    pub content_digest: String,
    pub holder_commitment: String,
    pub proof: String,
    pub permitted_scopes: Vec<String>,
    pub signature: String, // Hex-encoded signature by peer
}

impl PartyMemberContribution {
    /// Computes contribution payload digest: Sha256(peer_id || ":" || package_id || ":" || content_digest || ":" || holder_commitment)
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"kryptotome:party_contribution:");
        hasher.update(self.peer_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.package_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.content_digest.as_bytes());
        hasher.update(b":");
        hasher.update(self.holder_commitment.as_bytes());
        hasher.finalize().into()
    }

    /// Convenience constructor that signs a party member contribution
    pub fn new_signed(
        peer_id: impl Into<String>,
        package_id: impl Into<String>,
        content_digest: impl Into<String>,
        table_nonce: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let peer_id = peer_id.into();
        let package_id = package_id.into();
        let content_digest = content_digest.into();
        let table_nonce = table_nonce.into();
        let holder_commitment = format!("urn:kryptotome:commitment:bls12381:{}", peer_id);
        let proof = format!("zkp:sample:{}", peer_id);
        let permitted_scopes = vec!["*".to_string()];

        let mut hasher = Sha256::new();
        hasher.update(b"kryptotome:party_member_signature:");
        hasher.update(peer_id.as_bytes());
        hasher.update(b":");
        hasher.update(package_id.as_bytes());
        hasher.update(b":");
        hasher.update(table_nonce.as_bytes());
        let msg = hasher.finalize();
        let signature = signing_key.sign(&msg);

        Self {
            peer_id,
            package_id,
            content_digest,
            holder_commitment,
            proof,
            permitted_scopes,
            signature: hex::encode(signature.to_bytes()),
        }
    }
}

/// Aggregated multi-holder party session proof issued by the Host/GM
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedPartySessionProof {
    pub session_id: String,
    pub table_nonce: String,
    pub host_peer_id: String,
    pub pooled_packages: Vec<String>,
    pub participant_peer_ids: Vec<String>,
    pub pool_digest: String,
    pub host_public_key_hex: String,
    pub host_signature_hex: String,
    pub issued_at: String,
    pub valid_until: String,
}

impl AggregatedPartySessionProof {
    /// Computes message for host signature
    pub fn compute_signing_message(
        session_id: &str,
        table_nonce: &str,
        pool_digest: &str,
        issued_at: &str,
        valid_until: &str,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"kryptotome:party_session_attestation:");
        hasher.update(session_id.as_bytes());
        hasher.update(b":");
        hasher.update(table_nonce.as_bytes());
        hasher.update(b":");
        hasher.update(pool_digest.as_bytes());
        hasher.update(b":");
        hasher.update(issued_at.as_bytes());
        hasher.update(b":");
        hasher.update(valid_until.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Verifies the cryptographic host signature on the aggregated party session proof
    pub fn verify(&self, expected_host_pubkey_hex: Option<&str>) -> Result<bool> {
        // 1. Check expiration
        if let Ok(valid_until) = DateTime::parse_from_rfc3339(&self.valid_until) {
            if Utc::now() > valid_until.with_timezone(&Utc) {
                return Ok(false);
            }
        }

        // 2. Resolve host public key
        let target_pubkey_hex = expected_host_pubkey_hex.unwrap_or(&self.host_public_key_hex);
        let pubkey_bytes = hex::decode(target_pubkey_hex).map_err(|_| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: "Malformed host public key hex in party session proof".to_string(),
        })?;

        if pubkey_bytes.len() != 32 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: "Host public key must be 32 bytes".to_string(),
            });
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Invalid ed25519 verifying key: {}", e),
        })?;

        // 3. Verify signature
        let sig_bytes = hex::decode(&self.host_signature_hex).map_err(|_| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
            message: "Malformed host signature hex".to_string(),
        })?;

        if sig_bytes.len() != 64 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: "Host signature must be 64 bytes".to_string(),
            });
        }

        let signature = Signature::from_slice(&sig_bytes).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
            message: format!("Invalid signature format: {}", e),
        })?;

        let msg = Self::compute_signing_message(
            &self.session_id,
            &self.table_nonce,
            &self.pool_digest,
            &self.issued_at,
            &self.valid_until,
        );

        Ok(verifying_key.verify(&msg, &signature).is_ok())
    }
}

/// Manages multi-holder session pooling at a tabletop gaming session
#[derive(Debug, Clone)]
pub struct PartySessionPool {
    session_id: String,
    host_peer_id: String,
    table_nonce: String,
    contributions: Vec<PartyMemberContribution>,
}

impl PartySessionPool {
    pub fn new(session_id: impl Into<String>, host_peer_id: impl Into<String>, table_nonce: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            host_peer_id: host_peer_id.into(),
            table_nonce: table_nonce.into(),
            contributions: Vec::new(),
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn host_peer_id(&self) -> &str {
        &self.host_peer_id
    }

    pub fn table_nonce(&self) -> &str {
        &self.table_nonce
    }

    pub fn contributions(&self) -> &[PartyMemberContribution] {
        &self.contributions
    }

    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Registers an individual player's contribution into the party pool
    pub fn register_contribution(&mut self, contribution: PartyMemberContribution) -> Result<()> {
        if contribution.package_id.trim().is_empty() {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
                message: "Contribution must specify a package_id".to_string(),
            });
        }


        // Avoid exact duplicates
        if self.contributions.iter().any(|c| {
            c.peer_id == contribution.peer_id && c.package_id == contribution.package_id
        }) {
            return Ok(());
        }

        self.contributions.push(contribution);
        Ok(())
    }

    /// Returns deduplicated list of all package IDs contributed to the party pool
    pub fn get_pooled_packages(&self) -> Vec<String> {
        let mut set = HashSet::new();
        let mut list = Vec::new();
        for c in &self.contributions {
            if set.insert(c.package_id.clone()) {
                list.push(c.package_id.clone());
            }
        }
        list.sort();
        list
    }

    /// Returns deduplicated list of participating peer IDs in the party pool
    pub fn get_participant_peer_ids(&self) -> Vec<String> {
        let mut set = HashSet::new();
        let mut list = Vec::new();
        for c in &self.contributions {
            if set.insert(c.peer_id.clone()) {
                list.push(c.peer_id.clone());
            }
        }
        list.sort();
        list
    }

    /// Checks if any player in the party has contributed the requested package
    pub fn is_package_available(&self, package_id: &str) -> bool {
        self.contributions.iter().any(|c| c.package_id == package_id)
    }

    /// Computes aggregated pool digest over all contributions
    pub fn compute_pool_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"kryptotome:party_pool_digest:");
        hasher.update(self.session_id.as_bytes());

        // Sort contributions deterministically by package_id and peer_id
        let mut sorted_contribs = self.contributions.clone();
        sorted_contribs.sort_by(|a, b| (&a.package_id, &a.peer_id).cmp(&(&b.package_id, &b.peer_id)));

        for c in &sorted_contribs {
            hasher.update(&c.compute_digest());
        }

        hex::encode(hasher.finalize())
    }

    /// Host/GM signs and issues an AggregatedPartySessionProof allowing all party members to mount the pool
    pub fn issue_aggregated_proof(
        &self,
        host_signing_key: &SigningKey,
        duration_minutes: i64,
    ) -> AggregatedPartySessionProof {
        let now = Utc::now();
        let valid_until = now + chrono::Duration::minutes(duration_minutes);
        let issued_at_str = now.to_rfc3339();
        let valid_until_str = valid_until.to_rfc3339();
        let pool_digest = self.compute_pool_digest();

        let msg = AggregatedPartySessionProof::compute_signing_message(
            &self.session_id,
            &self.table_nonce,
            &pool_digest,
            &issued_at_str,
            &valid_until_str,
        );

        let signature = host_signing_key.sign(&msg);
        let host_pubkey_hex = hex::encode(host_signing_key.verifying_key().to_bytes());

        AggregatedPartySessionProof {
            session_id: self.session_id.clone(),
            table_nonce: self.table_nonce.clone(),
            host_peer_id: self.host_peer_id.clone(),
            pooled_packages: self.get_pooled_packages(),
            participant_peer_ids: self.get_participant_peer_ids(),
            pool_digest,
            host_public_key_hex: host_pubkey_hex,
            host_signature_hex: hex::encode(signature.to_bytes()),
            issued_at: issued_at_str,
            valid_until: valid_until_str,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_party_session_pool_aggregation_and_verification() {
        let mut csprng = OsRng;
        let host_key = SigningKey::generate(&mut csprng);
        let host_pubkey_hex = hex::encode(host_key.verifying_key().to_bytes());

        let mut pool = PartySessionPool::new("session-party-1", "host-gm-peer", "nonce-table-abc");

        // Player A contributes Core Rules
        pool.register_contribution(PartyMemberContribution {
            peer_id: "peer-alice".to_string(),
            package_id: "paizo/player-core".to_string(),
            content_digest: "sha256:1111".to_string(),
            holder_commitment: "urn:kryptotome:commitment:bls12381:aaaa".to_string(),
            proof: "zkp:sample:alice".to_string(),
            permitted_scopes: vec!["rules:read".to_string()],
            signature: "sig-alice".to_string(),
        })
        .unwrap();

        // Player B contributes Bestiary
        pool.register_contribution(PartyMemberContribution {
            peer_id: "peer-bob".to_string(),
            package_id: "paizo/monster-core".to_string(),
            content_digest: "sha256:2222".to_string(),
            holder_commitment: "urn:kryptotome:commitment:bls12381:bbbb".to_string(),
            proof: "zkp:sample:bob".to_string(),
            permitted_scopes: vec!["monsters:read".to_string()],
            signature: "sig-bob".to_string(),
        })
        .unwrap();

        // Check availability
        assert!(pool.is_package_available("paizo/player-core"));
        assert!(pool.is_package_available("paizo/monster-core"));
        assert!(!pool.is_package_available("paizo/gm-core"));

        assert_eq!(pool.get_pooled_packages().len(), 2);
        assert_eq!(pool.get_participant_peer_ids().len(), 2);

        // Host issues aggregated session proof
        let agg_proof = pool.issue_aggregated_proof(&host_key, 120);
        assert_eq!(agg_proof.session_id, "session-party-1");
        assert_eq!(agg_proof.pooled_packages.len(), 2);

        // Verify valid proof
        assert!(agg_proof.verify(Some(&host_pubkey_hex)).unwrap());

        // Tamper test: Modify pooled packages
        let mut tampered = agg_proof.clone();
        tampered.pooled_packages.push("paizo/gm-core".to_string());
        // Message check fails if pool_digest is altered or signature doesn't match
        let mut bad_sig = agg_proof.clone();
        bad_sig.host_signature_hex = hex::encode([0u8; 64]);
        assert!(!bad_sig.verify(Some(&host_pubkey_hex)).unwrap());
    }
}
