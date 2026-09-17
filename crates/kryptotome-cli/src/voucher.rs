use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Physical print-on-demand voucher formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PhysicalVoucherFormat {
    /// Scratch-off foil covered alphanumeric code (e.g. inside back cover)
    ScratchOffCode,
    /// NFC NTAG inlay sticker/chip embedded in book binding or cover
    NfcTag,
    /// Dual format: Physical scratch-off code + NFC tag inlay
    Hybrid,
}

/// Specification for a batch release of physical book vouchers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalVoucherBatchSpec {
    pub publisher_id: String,
    pub package_id: String,
    pub content_digest: String,
    pub quantity: usize,
    pub format: PhysicalVoucherFormat,
    pub code_prefix: Option<String>,
    pub valid_duration_days: Option<i64>,
}

/// An individual physical claim voucher record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalVoucherRecord {
    pub voucher_id: String,
    pub code: String,
    pub package_id: String,
    pub content_digest: String,
    pub format: PhysicalVoucherFormat,
    pub salt_hex: String,
    pub publisher_pubkey_hex: String,
    pub signature_hex: String,
    pub nfc_ndef_uri: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

impl PhysicalVoucherRecord {
    /// Computes deterministic payload for voucher signature
    pub fn compute_signing_payload(
        voucher_id: &str,
        code: &str,
        package_id: &str,
        content_digest: &str,
        salt_hex: &str,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"kryptotome:physical_voucher:");
        hasher.update(voucher_id.as_bytes());
        hasher.update(b":");
        hasher.update(code.as_bytes());
        hasher.update(b":");
        hasher.update(package_id.as_bytes());
        hasher.update(b":");
        hasher.update(content_digest.as_bytes());
        hasher.update(b":");
        hasher.update(salt_hex.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Verifies cryptographic signature and expiration status of the physical voucher
    pub fn verify(&self, expected_pubkey_hex: Option<&str>) -> Result<bool> {
        // Expiration check
        if let Some(ref exp_str) = self.expires_at {
            if let Ok(exp_date) = DateTime::parse_from_rfc3339(exp_str) {
                if Utc::now() > exp_date.with_timezone(&Utc) {
                    return Err(KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp104InvalidTemporalBounds,
                        message: "Physical voucher code has expired".to_string(),
                    });
                }
            }
        }

        let target_pubkey = expected_pubkey_hex.unwrap_or(&self.publisher_pubkey_hex);
        let pubkey_bytes = hex::decode(target_pubkey).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Malformed publisher public key hex: {}", e),
        })?;

        if pubkey_bytes.len() != 32 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: "Publisher public key must be 32 bytes".to_string(),
            });
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&key_arr).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: format!("Invalid verifying key format: {}", e),
            })?;

        let sig_bytes =
            hex::decode(&self.signature_hex).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                message: format!("Malformed signature hex: {}", e),
            })?;

        if sig_bytes.len() != 64 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                message: "Signature must be 64 bytes".to_string(),
            });
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let msg = Self::compute_signing_payload(
            &self.voucher_id,
            &self.code,
            &self.package_id,
            &self.content_digest,
            &self.salt_hex,
        );

        Ok(verifying_key.verify(&msg, &signature).is_ok())
    }
}

/// Formatted NFC NDEF payload for hardware tag inlays
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfcTagPayload {
    pub ndef_uri: String,
    pub ndef_record_bytes: Vec<u8>,
    pub chip_type: String,
    pub lockable: bool,
}

/// Generates formatted human-readable scratch-off code (e.g. KRYP-9B4A-7FC1-2E90)
fn generate_scratch_code(prefix: Option<&str>) -> String {
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    let hex_str = hex::encode(bytes).to_uppercase();

    let p = prefix.unwrap_or("KRYP");
    format!("{}-{}-{}", p, &hex_str[0..4], &hex_str[4..8])
}

/// Generates a batch of physical vouchers with cryptographic signatures
pub fn generate_voucher_batch(
    spec: &PhysicalVoucherBatchSpec,
    signing_key: &SigningKey,
) -> Result<Vec<PhysicalVoucherRecord>> {
    if spec.quantity == 0 {
        return Ok(Vec::new());
    }

    let publisher_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let now = Utc::now();
    let expires_at = spec
        .valid_duration_days
        .map(|days| (now + Duration::days(days)).to_rfc3339());

    let mut vouchers = Vec::with_capacity(spec.quantity);

    for idx in 0..spec.quantity {
        let voucher_id = format!("vch-pod-{}-{}", idx + 1, now.timestamp());
        let code = generate_scratch_code(spec.code_prefix.as_deref());

        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);
        let salt_hex = hex::encode(salt_bytes);

        let msg = PhysicalVoucherRecord::compute_signing_payload(
            &voucher_id,
            &code,
            &spec.package_id,
            &spec.content_digest,
            &salt_hex,
        );

        let signature = signing_key.sign(&msg);
        let signature_hex = hex::encode(signature.to_bytes());

        let nfc_ndef_uri = match spec.format {
            PhysicalVoucherFormat::NfcTag | PhysicalVoucherFormat::Hybrid => Some(format!(
                "kryptotome://voucher/claim?code={}&pkg={}&sig={}",
                code,
                spec.package_id.replace('/', "%2F"),
                signature_hex
            )),
            PhysicalVoucherFormat::ScratchOffCode => None,
        };

        vouchers.push(PhysicalVoucherRecord {
            voucher_id,
            code,
            package_id: spec.package_id.clone(),
            content_digest: spec.content_digest.clone(),
            format: spec.format,
            salt_hex,
            publisher_pubkey_hex: publisher_pubkey_hex.clone(),
            signature_hex,
            nfc_ndef_uri,
            created_at: now.to_rfc3339(),
            expires_at: expires_at.clone(),
        });
    }

    Ok(vouchers)
}

/// Encodes an NFC Forum URI NDEF record (RFC / NFC Forum Type 2/4 standard)
pub fn format_ndef_payload(voucher: &PhysicalVoucherRecord) -> Result<NfcTagPayload> {
    let uri = voucher.nfc_ndef_uri.clone().unwrap_or_else(|| {
        format!(
            "kryptotome://voucher/claim?code={}&pkg={}",
            voucher.code,
            voucher.package_id.replace('/', "%2F")
        )
    });

    // NDEF URI Record formatting:
    // Header byte: 0xD1 (MB=1, ME=1, CF=0, SR=1, IL=0, TNF=0x01 Well-Known)
    // Type Length: 0x01
    // Payload Length: URI bytes len + 1 (for URI identifier code 0x00: No prefix)
    // Type: 'U' (0x55)
    // Identifier code: 0x00 (custom scheme)
    // URI payload bytes
    let uri_bytes = uri.as_bytes();
    let mut ndef = vec![
        0xD1,                        // NDEF header
        0x01,                        // Type length = 1
        (uri_bytes.len() + 1) as u8, // Payload length
        0x55,                        // Record type 'U' (URI)
        0x00,                        // URI prefix code (none, full URI following)
    ];
    ndef.extend_from_slice(uri_bytes);

    let chip_type = if ndef.len() <= 144 {
        "NTAG213 (144 bytes)".to_string()
    } else if ndef.len() <= 504 {
        "NTAG215 (504 bytes)".to_string()
    } else {
        "NTAG216 (888 bytes)".to_string()
    };

    Ok(NfcTagPayload {
        ndef_uri: uri,
        ndef_record_bytes: ndef,
        chip_type,
        lockable: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_physical_voucher_generation_and_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let spec = PhysicalVoucherBatchSpec {
            publisher_id: "did:kryptotome:pub:green-ronin".to_string(),
            package_id: "green-ronin/mutants-and-masterminds-core".to_string(),
            content_digest: "b3:mm_core_digest_123".to_string(),
            quantity: 5,
            format: PhysicalVoucherFormat::Hybrid,
            code_prefix: Some("MANDM".to_string()),
            valid_duration_days: Some(365),
        };

        let vouchers = generate_voucher_batch(&spec, &signing_key).unwrap();
        assert_eq!(vouchers.len(), 5);

        for v in &vouchers {
            assert!(v.code.starts_with("MANDM-"));
            assert_eq!(v.package_id, "green-ronin/mutants-and-masterminds-core");
            assert!(v.nfc_ndef_uri.is_some());
            assert!(v.verify(None).unwrap());

            // NDEF payload generation
            let ndef = format_ndef_payload(v).unwrap();
            assert!(ndef
                .ndef_uri
                .starts_with("kryptotome://voucher/claim?code="));
            assert_eq!(ndef.ndef_record_bytes[3], 0x55); // 'U'
            assert!(ndef.lockable);
        }

        // Tamper test: Alter code
        let mut tampered = vouchers[0].clone();
        tampered.code = "MANDM-FAKE-CODE".to_string();
        assert!(!tampered.verify(None).unwrap());
    }
}
