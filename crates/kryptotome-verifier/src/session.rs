use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionAttestation {
    pub session_id: String,
    pub host_peer_id: String,
    pub recipient_peer_id: String,
    pub package_id: String,
    pub content_digest: String,
    pub permitted_scopes: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature_hex: String,
}

pub struct SessionManager {
    host_signing_key: SigningKey,
    host_verifying_key: VerifyingKey,
    session_id: String,
}

impl SessionManager {
    pub fn new(session_id: String) -> Self {
        let mut csprng = OsRng;
        let host_signing_key = SigningKey::generate(&mut csprng);
        let host_verifying_key = host_signing_key.verifying_key();

        Self {
            host_signing_key,
            host_verifying_key,
            session_id,
        }
    }

    pub fn host_public_key_hex(&self) -> String {
        hex_encode(self.host_verifying_key.as_bytes())
    }

    /// Signs an ephemeral session token for a connected table peer
    pub fn issue_peer_attestation(
        &self,
        recipient_peer_id: &str,
        package_id: &str,
        content_digest: &str,
        scopes: Vec<String>,
        valid_duration_minutes: i64,
    ) -> SessionAttestation {
        let now = Utc::now();
        let expires_at = now + Duration::minutes(valid_duration_minutes);

        let payload_to_sign = format!(
            "{}:{}:{}:{}:{}",
            self.session_id, recipient_peer_id, package_id, content_digest, expires_at.timestamp()
        );

        let signature = self.host_signing_key.sign(payload_to_sign.as_bytes());

        SessionAttestation {
            session_id: self.session_id.clone(),
            host_peer_id: self.host_public_key_hex(),
            recipient_peer_id: recipient_peer_id.to_string(),
            package_id: package_id.to_string(),
            content_digest: content_digest.to_string(),
            permitted_scopes: scopes,
            issued_at: now,
            expires_at,
            signature_hex: hex_encode(&signature.to_bytes()),
        }
    }

    /// Peer validates received session attestation
    pub fn verify_peer_attestation(
        attestation: &SessionAttestation,
        host_pubkey_hex: &str,
    ) -> Result<bool, String> {
        if Utc::now() > attestation.expires_at {
            return Err("Session attestation has expired".to_string());
        }

        let pubkey_bytes = hex_decode(host_pubkey_hex)
            .map_err(|e| format!("Invalid host public key hex: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| format!("Invalid public key: {}", e))?;

        let sig_bytes = hex_decode(&attestation.signature_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        let payload = format!(
            "{}:{}:{}:{}:{}",
            attestation.session_id,
            attestation.recipient_peer_id,
            attestation.package_id,
            attestation.content_digest,
            attestation.expires_at.timestamp()
        );

        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map(|_| true)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Odd hex length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Hex parse error: {}", e))
        })
        .collect()
}
