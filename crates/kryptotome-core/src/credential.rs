use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// W3C Verifiable Credentials Data Model v2.0 compliant Kryptotome credential
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KryptotomeCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: Issuer,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub credential_subject: CredentialSubject,
    pub proof: ProofData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Issuer {
    pub id: String,
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub id: String,
    /// Cryptographic commitment (e.g. Pedersen/Poseidon) binding credential to user secret key
    pub holder_commitment: String,
    pub entitlements: Vec<Entitlement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entitlement {
    pub package_id: String,
    pub content_digest: String,
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProofData {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: DateTime<Utc>,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String,
}

impl KryptotomeCredential {
    pub fn new(
        id: String,
        issuer: Issuer,
        subject_id: String,
        holder_commitment: String,
        entitlements: Vec<Entitlement>,
        proof_value: String,
    ) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://kryptotome.org/schemas/v1/context.jsonld".to_string(),
            ],
            id,
            credential_type: vec![
                "VerifiableCredential".to_string(),
                "KryptotomeEntitlementCredential".to_string(),
            ],
            issuer,
            valid_from: Utc::now(),
            valid_until: None,
            credential_subject: CredentialSubject {
                id: subject_id,
                holder_commitment,
                entitlements,
            },
            proof: ProofData {
                proof_type: "Ed25519Signature2020".to_string(),
                created: Utc::now(),
                verification_method: "did:key:publisher#key-1".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value,
            },
        }
    }

    pub fn has_entitlement(&self, package_id: &str) -> bool {
        self.credential_subject
            .entitlements
            .iter()
            .any(|e| e.package_id == package_id)
    }

    /// Validates strict compliance with the W3C Verifiable Credentials Data Model v2.0 specification
    pub fn validate_w3c_compliance(&self) -> crate::error::Result<()> {
        use crate::error::KryptotomeError;

        // 1. Validate @context: Must be an ordered set where index 0 is https://www.w3.org/ns/credentials/v2
        if self.context.is_empty() {
            return Err(KryptotomeError::W3cComplianceError(
                "@context cannot be empty".to_string(),
            ));
        }
        if self.context[0] != "https://www.w3.org/ns/credentials/v2" {
            return Err(KryptotomeError::W3cComplianceError(format!(
                "First element in @context must be 'https://www.w3.org/ns/credentials/v2', found '{}'",
                self.context[0]
            )));
        }
        if !self
            .context
            .contains(&"https://kryptotome.org/schemas/v1/context.jsonld".to_string())
        {
            return Err(KryptotomeError::W3cComplianceError(
                "@context must include 'https://kryptotome.org/schemas/v1/context.jsonld'"
                    .to_string(),
            ));
        }

        // 2. Validate id: Must be a URI
        if !is_valid_uri(&self.id) {
            return Err(KryptotomeError::W3cComplianceError(format!(
                "Credential id must be a valid URI, found '{}'",
                self.id
            )));
        }

        // 3. Validate type: Must include "VerifiableCredential" and "KryptotomeEntitlementCredential"
        if !self
            .credential_type
            .contains(&"VerifiableCredential".to_string())
        {
            return Err(KryptotomeError::W3cComplianceError(
                "Credential type must include 'VerifiableCredential'".to_string(),
            ));
        }
        if !self
            .credential_type
            .contains(&"KryptotomeEntitlementCredential".to_string())
        {
            return Err(KryptotomeError::W3cComplianceError(
                "Credential type must include 'KryptotomeEntitlementCredential'".to_string(),
            ));
        }

        // 4. Validate issuer
        if !is_valid_uri(&self.issuer.id) {
            return Err(KryptotomeError::W3cComplianceError(format!(
                "Issuer id must be a valid URI, found '{}'",
                self.issuer.id
            )));
        }
        if self.issuer.public_key.trim().is_empty() {
            return Err(KryptotomeError::W3cComplianceError(
                "Issuer public key cannot be empty".to_string(),
            ));
        }

        // 5. Validate validFrom and validUntil temporal bounds
        if let Some(until) = self.valid_until {
            if until <= self.valid_from {
                return Err(KryptotomeError::W3cComplianceError(
                    "validUntil must be strictly after validFrom".to_string(),
                ));
            }
        }

        // 6. Validate credentialSubject
        if !is_valid_uri(&self.credential_subject.id) {
            return Err(KryptotomeError::W3cComplianceError(format!(
                "CredentialSubject id must be a valid URI, found '{}'",
                self.credential_subject.id
            )));
        }
        if self.credential_subject.holder_commitment.trim().is_empty() {
            return Err(KryptotomeError::W3cComplianceError(
                "Holder commitment cannot be empty".to_string(),
            ));
        }
        if self.credential_subject.entitlements.is_empty() {
            return Err(KryptotomeError::W3cComplianceError(
                "CredentialSubject must contain at least one entitlement".to_string(),
            ));
        }
        for ent in &self.credential_subject.entitlements {
            if ent.package_id.trim().is_empty() {
                return Err(KryptotomeError::W3cComplianceError(
                    "Entitlement packageId cannot be empty".to_string(),
                ));
            }
            if ent.content_digest.trim().is_empty() {
                return Err(KryptotomeError::W3cComplianceError(
                    "Entitlement contentDigest cannot be empty".to_string(),
                ));
            }
            if ent.scope.is_empty() {
                return Err(KryptotomeError::W3cComplianceError(
                    "Entitlement scope cannot be empty".to_string(),
                ));
            }
        }

        // 7. Validate proof: assertionMethod required for W3C VC v2.0
        if self.proof.proof_purpose != "assertionMethod" {
            return Err(KryptotomeError::W3cComplianceError(format!(
                "Proof purpose must be 'assertionMethod', found '{}'",
                self.proof.proof_purpose
            )));
        }
        if !is_valid_uri(&self.proof.verification_method) {
            return Err(KryptotomeError::W3cComplianceError(format!(
                "Proof verificationMethod must be a valid URI, found '{}'",
                self.proof.verification_method
            )));
        }
        if self.proof.proof_value.trim().is_empty() {
            return Err(KryptotomeError::W3cComplianceError(
                "Proof proofValue cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

fn is_valid_uri(s: &str) -> bool {
    s.starts_with("urn:")
        || s.starts_with("did:")
        || s.starts_with("http://")
        || s.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_sample_credential() -> KryptotomeCredential {
        let issuer = Issuer {
            id: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string(),
            name: "Paizo Publisher".to_string(),
            public_key: "pubkey_hex_sample".to_string(),
        };

        let entitlements = vec![Entitlement {
            package_id: "paizo/pathfinder-remaster-player-core".to_string(),
            content_digest: "sha256:abcd1234ef01".to_string(),
            scope: vec!["compendium".to_string(), "rules".to_string()],
        }];

        KryptotomeCredential::new(
            "urn:uuid:123e4567-e89b-12d3-a456-426614174000".to_string(),
            issuer,
            "did:key:z6MkhvjV2VwKvZ3pZ9N8qV6".to_string(),
            "commitment:pedersen:999aabbcc".to_string(),
            entitlements,
            "proofvalue_signature_sample".to_string(),
        )
    }

    #[test]
    fn test_valid_w3c_compliance() {
        let cred = create_sample_credential();
        assert!(cred.validate_w3c_compliance().is_ok());
    }

    #[test]
    fn test_invalid_context_first_element() {
        let mut cred = create_sample_credential();
        cred.context[0] = "https://www.w3.org/2018/credentials/v1".to_string(); // v1 instead of v2
        let err = cred.validate_w3c_compliance().unwrap_err();
        assert!(err
            .to_string()
            .contains("First element in @context must be 'https://www.w3.org/ns/credentials/v2'"));
    }

    #[test]
    fn test_missing_verifiable_credential_type() {
        let mut cred = create_sample_credential();
        cred.credential_type = vec!["KryptotomeEntitlementCredential".to_string()];
        let err = cred.validate_w3c_compliance().unwrap_err();
        assert!(err
            .to_string()
            .contains("must include 'VerifiableCredential'"));
    }

    #[test]
    fn test_invalid_temporal_bounds() {
        let mut cred = create_sample_credential();
        cred.valid_until = Some(cred.valid_from - chrono::Duration::hours(1));
        let err = cred.validate_w3c_compliance().unwrap_err();
        assert!(err
            .to_string()
            .contains("validUntil must be strictly after validFrom"));
    }

    #[test]
    fn test_invalid_issuer_id() {
        let mut cred = create_sample_credential();
        cred.issuer.id = "invalid-not-a-uri".to_string();
        let err = cred.validate_w3c_compliance().unwrap_err();
        assert!(err.to_string().contains("Issuer id must be a valid URI"));
    }

    #[test]
    fn test_empty_entitlements() {
        let mut cred = create_sample_credential();
        cred.credential_subject.entitlements.clear();
        let err = cred.validate_w3c_compliance().unwrap_err();
        assert!(err
            .to_string()
            .contains("must contain at least one entitlement"));
    }
}
