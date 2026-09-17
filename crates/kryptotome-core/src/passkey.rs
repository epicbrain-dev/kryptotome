use crate::error::{KryptotomeError, KryptotomeErrorCode, Result};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// WebAuthn / FIDO2 authenticator flags (RFC 9153 / W3C WebAuthn Level 3)
pub const WEBAUTHN_FLAG_USER_PRESENT: u8 = 0x01; // Bit 0: User Present (UP)
pub const WEBAUTHN_FLAG_USER_VERIFIED: u8 = 0x04; // Bit 2: User Verified (UV)

/// Cryptographic binding between a user's Pedersen commitment and a hardware security key / Passkey
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyBinding {
    pub credential_id: String,
    pub holder_commitment_urn: String,
    pub public_key_hex: String,
    pub rp_id: String,
    pub algorithm: String, // "Ed25519"
    pub created_at: String,
}

/// Client data representation in WebAuthn JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedClientData {
    pub r#type: String, // e.g. "webauthn.get"
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin", default)]
    pub cross_origin: Option<bool>,
}

/// Passkey assertion returned by hardware authenticator (YubiKey / Touch ID / Face ID)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    pub credential_id: String,
    pub authenticator_data_hex: String,
    pub client_data_json: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyVerificationResult {
    pub verified: bool,
    pub user_present: bool,
    pub user_verified: bool,
    pub holder_commitment_urn: String,
    pub verified_at: String,
}

pub struct PasskeyHardwareManager;

impl PasskeyHardwareManager {
    /// Creates a hardware binding between a Pedersen commitment and an Ed25519 hardware key
    pub fn create_binding(
        credential_id: impl Into<String>,
        holder_commitment_urn: impl Into<String>,
        public_key_hex: impl Into<String>,
        rp_id: impl Into<String>,
    ) -> Result<PasskeyBinding> {
        let pubkey_str = public_key_hex.into();
        let pubkey_bytes = hex::decode(&pubkey_str).map_err(|_| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: "Malformed hardware public key hex".to_string(),
        })?;

        if pubkey_bytes.len() != 32 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: "Hardware Ed25519 public key must be exactly 32 bytes".to_string(),
            });
        }

        Ok(PasskeyBinding {
            credential_id: credential_id.into(),
            holder_commitment_urn: holder_commitment_urn.into(),
            public_key_hex: pubkey_str,
            rp_id: rp_id.into(),
            algorithm: "Ed25519".to_string(),
            created_at: Utc::now().to_rfc3339(),
        })
    }

    /// Verifies hardware passkey assertion against registered binding and challenge nonce
    pub fn verify_assertion(
        binding: &PasskeyBinding,
        expected_challenge: &str,
        assertion: &PasskeyAssertion,
        require_user_verification: bool,
    ) -> Result<PasskeyVerificationResult> {
        // 1. Verify credential ID matches
        if assertion.credential_id != binding.credential_id {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: format!(
                    "Assertion credential ID '{}' does not match binding '{}'",
                    assertion.credential_id, binding.credential_id
                ),
            });
        }

        // 2. Parse and verify clientDataJSON
        let client_data: CollectedClientData = serde_json::from_str(&assertion.client_data_json)
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp105MalformedProofStructure,
                message: format!("Malformed clientDataJSON: {}", e),
            })?;

        if client_data.r#type != "webauthn.get" {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: format!(
                    "Unexpected clientData type '{}'. Expected 'webauthn.get'",
                    client_data.r#type
                ),
            });
        }

        if client_data.challenge != expected_challenge {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp302PublicInputMismatch,
                message: "Assertion challenge does not match expected challenge nonce".to_string(),
            });
        }

        // 3. Parse authenticator data flags
        let auth_data_bytes = hex::decode(&assertion.authenticator_data_hex).map_err(|_| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: "Malformed authenticatorData hex".to_string(),
            }
        })?;

        if auth_data_bytes.len() < 37 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: "authenticatorData is too short (< 37 bytes)".to_string(),
            });
        }

        let flags = auth_data_bytes[32];
        let user_present = (flags & WEBAUTHN_FLAG_USER_PRESENT) != 0;
        let user_verified = (flags & WEBAUTHN_FLAG_USER_VERIFIED) != 0;

        if !user_present {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: "Hardware user presence flag (UP) was not asserted".to_string(),
            });
        }

        if require_user_verification && !user_verified {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: "Biometric user verification flag (UV) was not asserted".to_string(),
            });
        }


        // 4. Cryptographic signature check: verify signature over (authData || sha256(clientDataJSON))
        let client_data_hash = Sha256::digest(assertion.client_data_json.as_bytes());
        let mut signed_data = Vec::with_capacity(auth_data_bytes.len() + 32);
        signed_data.extend_from_slice(&auth_data_bytes);
        signed_data.extend_from_slice(&client_data_hash);

        let pubkey_bytes = hex::decode(&binding.public_key_hex).map_err(|_| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: "Invalid binding public key hex".to_string(),
            }
        })?;

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr).map_err(|e| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: format!("Invalid ed25519 verifying key: {}", e),
            }
        })?;

        let sig_bytes = hex::decode(&assertion.signature_hex).map_err(|_| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: "Malformed assertion signature hex".to_string(),
            }
        })?;

        if sig_bytes.len() != 64 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: "Hardware assertion signature must be 64 bytes".to_string(),
            });
        }

        let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: format!("Invalid signature format: {}", e),
            }
        })?;

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: format!("Hardware passkey signature validation failed: {}", e),
            })?;

        Ok(PasskeyVerificationResult {
            verified: true,
            user_present,
            user_verified,
            holder_commitment_urn: binding.holder_commitment_urn.clone(),
            verified_at: Utc::now().to_rfc3339(),
        })
    }

    /// Helper to craft a mock hardware assertion for testing
    pub fn create_mock_assertion(
        signing_key: &ed25519_dalek::SigningKey,
        credential_id: &str,
        challenge: &str,
        origin: &str,
        user_verified: bool,
    ) -> PasskeyAssertion {
        use ed25519_dalek::Signer;

        // 37 bytes authenticator data: 32 bytes rpIdHash + 1 byte flags + 4 bytes counter
        let mut auth_data = vec![0u8; 37];
        let mut flags = WEBAUTHN_FLAG_USER_PRESENT;
        if user_verified {
            flags |= WEBAUTHN_FLAG_USER_VERIFIED;
        }
        auth_data[32] = flags;

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false
        });
        let client_data_str = client_data.to_string();
        let client_data_hash = Sha256::digest(client_data_str.as_bytes());

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        let sig = signing_key.sign(&signed_data);

        PasskeyAssertion {
            credential_id: credential_id.to_string(),
            authenticator_data_hex: hex::encode(auth_data),
            client_data_json: client_data_str,
            signature_hex: hex::encode(sig.to_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_passkey_binding_and_assertion_verification() {
        let mut csprng = OsRng;
        let hardware_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let hardware_pubkey_hex = hex::encode(hardware_key.verifying_key().to_bytes());

        let commitment_urn = "urn:kryptotome:commitment:bls12381:73a85757532b";
        let binding = PasskeyHardwareManager::create_binding(
            "cred-yubikey-1",
            commitment_urn,
            hardware_pubkey_hex,
            "kryptotome.org",
        )
        .unwrap();

        let challenge = "nonce-challenge-fido2-test";
        let assertion = PasskeyHardwareManager::create_mock_assertion(
            &hardware_key,
            "cred-yubikey-1",
            challenge,
            "https://kryptotome.org",
            true,
        );

        // Verify valid assertion
        let result = PasskeyHardwareManager::verify_assertion(
            &binding,
            challenge,
            &assertion,
            true, // require UV
        )
        .unwrap();

        assert!(result.verified);
        assert!(result.user_present);
        assert!(result.user_verified);
        assert_eq!(result.holder_commitment_urn, commitment_urn);

        // Challenge mismatch test
        assert!(PasskeyHardwareManager::verify_assertion(
            &binding,
            "wrong-challenge",
            &assertion,
            true,
        )
        .is_err());
    }
}
