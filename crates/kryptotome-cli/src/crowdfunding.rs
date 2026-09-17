use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kryptotome_core::credential::{CredentialSubject, Entitlement, Issuer, KryptotomeCredential, ProofData};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Supported crowdfunding platforms for backer export ingestion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrowdfundingPlatform {
    Kickstarter,
    BackerKit,
    Custom,
}

impl CrowdfundingPlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Kickstarter => "kickstarter",
            Self::BackerKit => "backerkit",
            Self::Custom => "custom",
        }
    }
}

/// An ingested backer record from a crowdfunding campaign export
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackerRecord {
    pub backer_id: String,
    pub email: String,
    pub name: String,
    pub reward_tier: String,
    pub pledge_amount: Option<f64>,
    pub reward_package_ids: Vec<String>,
}

/// Mapping configuration from campaign reward tier name to entitled compendium package IDs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FulfillmentTierConfig {
    pub tier_name: String,
    pub package_ids: Vec<String>,
    pub content_digests: HashMap<String, String>,
}

/// Single-use 1-click digital claim voucher for vault import
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimVoucher {
    pub voucher_id: String,
    pub backer_id: String,
    pub package_id: String,
    pub content_digest: String,
    pub activation_token: String,
    pub claim_url: String,
    pub publisher_pubkey_hex: String,
    pub signature_hex: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
}

impl ClaimVoucher {
    /// Computes deterministic message for publisher signature
    pub fn compute_signing_payload(
        voucher_id: &str,
        backer_id: &str,
        package_id: &str,
        content_digest: &str,
        activation_token: &str,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"kryptotome:claim_voucher:");
        hasher.update(voucher_id.as_bytes());
        hasher.update(b":");
        hasher.update(backer_id.as_bytes());
        hasher.update(b":");
        hasher.update(package_id.as_bytes());
        hasher.update(b":");
        hasher.update(content_digest.as_bytes());
        hasher.update(b":");
        hasher.update(activation_token.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Verifies the publisher cryptographic signature on the claim voucher
    pub fn verify(&self, expected_pubkey_hex: Option<&str>) -> Result<bool> {
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
        let verifying_key = VerifyingKey::from_bytes(&key_arr).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Invalid verifying key format: {}", e),
        })?;

        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| KryptotomeError::Detailed {
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
            &self.backer_id,
            &self.package_id,
            &self.content_digest,
            &self.activation_token,
        );

        Ok(verifying_key.verify(&msg, &signature).is_ok())
    }
}

/// Comprehensive report of crowdfunding fulfillment execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchFulfillmentReport {
    pub platform: CrowdfundingPlatform,
    pub publisher_id: String,
    pub total_backers: usize,
    pub fulfilled_credentials_count: usize,
    pub vouchers: Vec<ClaimVoucher>,
    pub credentials: Vec<KryptotomeCredential>,
}

/// Parses backer survey CSV export from Kickstarter or BackerKit
pub fn parse_backer_csv(csv_content: &str, platform: CrowdfundingPlatform) -> Result<Vec<BackerRecord>> {
    let lines: Vec<&str> = csv_content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
            message: "Empty CSV content".to_string(),
        });
    }

    let header_line = lines[0];
    let headers: Vec<String> = header_line
        .split(',')
        .map(|h| h.trim().trim_matches('"').to_lowercase())
        .collect();

    // Map column indices
    let id_idx = headers.iter().position(|h| {
        h.contains("backer number") || h.contains("backer id") || h.contains("id")
    });
    let email_idx = headers.iter().position(|h| h.contains("email"));
    let name_idx = headers.iter().position(|h| h.contains("name"));
    let tier_idx = headers.iter().position(|h| {
        h.contains("reward") || h.contains("tier") || h.contains("pledge tier")
    });
    let amount_idx = headers.iter().position(|h| {
        h.contains("pledge amount") || h.contains("amount") || h.contains("pledged")
    });

    let mut backers = Vec::new();

    for (row_num, line) in lines[1..].iter().enumerate() {
        // Simple comma split handling quoted strings
        let fields = parse_csv_line(line);
        if fields.is_empty() {
            continue;
        }

        let backer_id = id_idx
            .and_then(|idx| fields.get(idx).cloned())
            .unwrap_or_else(|| format!("{}-{}", platform.as_str(), row_num + 1));

        let email = email_idx
            .and_then(|idx| fields.get(idx).cloned())
            .unwrap_or_default();

        let name = name_idx
            .and_then(|idx| fields.get(idx).cloned())
            .unwrap_or_else(|| "Anonymous Backer".to_string());

        let reward_tier = tier_idx
            .and_then(|idx| fields.get(idx).cloned())
            .unwrap_or_default();

        let pledge_amount = amount_idx
            .and_then(|idx| fields.get(idx))
            .and_then(|val| {
                let cleaned = val.replace('$', "").replace(',', "").trim().to_string();
                cleaned.parse::<f64>().ok()
            });

        backers.push(BackerRecord {
            backer_id,
            email,
            name,
            reward_tier,
            pledge_amount,
            reward_package_ids: Vec::new(),
        });
    }

    Ok(backers)
}

/// Helper to parse a CSV line respecting quotes
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current = String::new();
            }
            _ => {
                current.push(ch);
            }
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Executes batch fulfillment: generates signed W3C credentials and 1-click claim vouchers
pub fn generate_batch_fulfillment(
    backers: &[BackerRecord],
    tier_configs: &[FulfillmentTierConfig],
    publisher_id: &str,
    publisher_name: &str,
    platform: CrowdfundingPlatform,
    signing_key: &SigningKey,
) -> Result<BatchFulfillmentReport> {
    let mut tier_map: HashMap<String, &FulfillmentTierConfig> = HashMap::new();
    for config in tier_configs {
        tier_map.insert(config.tier_name.to_lowercase(), config);
    }

    let publisher_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let mut vouchers = Vec::new();
    let mut credentials = Vec::new();

    for backer in backers {
        let normalized_tier = backer.reward_tier.to_lowercase();
        let config_opt = tier_map.get(&normalized_tier).copied().or_else(|| {
            tier_map
                .iter()
                .find(|(k, _)| normalized_tier.contains(k.as_str()))
                .map(|(_, c)| *c)
        });

        let config = match config_opt {
            Some(c) => c,
            None => continue,
        };

        if config.package_ids.is_empty() {
            continue;
        }

        let mut entitlements = Vec::new();

        for pkg_id in &config.package_ids {
            let digest = config
                .content_digests
                .get(pkg_id)
                .cloned()
                .unwrap_or_else(|| "b3:default_placeholder".to_string());

            entitlements.push(Entitlement {
                package_id: pkg_id.clone(),
                content_digest: digest.clone(),
                scope: vec!["*".to_string()],
            });

            // Generate 1-click claim voucher
            let voucher_id = format!("vch-{}-{}", backer.backer_id, pkg_id.replace('/', "-"));
            let token_data = format!("{}:{}:{}", voucher_id, backer.email, Utc::now().timestamp());
            let activation_token = hex::encode(Sha256::digest(token_data.as_bytes()));

            let signing_payload = ClaimVoucher::compute_signing_payload(
                &voucher_id,
                &backer.backer_id,
                pkg_id,
                &digest,
                &activation_token,
            );
            let signature = signing_key.sign(&signing_payload);

            let claim_url = format!(
                "kryptotome://claim?voucherId={}&packageId={}&token={}&sig={}",
                voucher_id,
                urlencoding_simple(pkg_id),
                activation_token,
                hex::encode(signature.to_bytes())
            );

            vouchers.push(ClaimVoucher {
                voucher_id,
                backer_id: backer.backer_id.clone(),
                package_id: pkg_id.clone(),
                content_digest: digest,
                activation_token,
                claim_url,
                publisher_pubkey_hex: publisher_pubkey_hex.clone(),
                signature_hex: hex::encode(signature.to_bytes()),
                issued_at: Utc::now().to_rfc3339(),
                expires_at: None,
            });
        }

        // Issue batch W3C Verifiable Credential v2.0
        let cred_id = format!("urn:uuid:cred-backer-{}", backer.backer_id);
        let holder_urn = format!("urn:kryptotome:commitment:bls12381:backer-{}", backer.backer_id);

        let subject = CredentialSubject {
            id: format!("did:kryptotome:backer:{}", backer.backer_id),
            holder_commitment: holder_urn,
            entitlements,
        };

        let now = Utc::now();
        let payload_to_sign = format!("{}:{}:{}", cred_id, publisher_id, now.to_rfc3339());
        let cred_sig = signing_key.sign(payload_to_sign.as_bytes());

        let credential = KryptotomeCredential {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://kryptotome.io/ns/v1".to_string(),
            ],
            id: cred_id,
            credential_type: vec![
                "VerifiableCredential".to_string(),
                "KryptotomeEntitlementCredential".to_string(),
            ],
            issuer: Issuer {
                id: publisher_id.to_string(),
                name: publisher_name.to_string(),
                public_key: publisher_pubkey_hex.clone(),
            },
            valid_from: now,
            valid_until: None,
            credential_subject: subject,
            proof: ProofData {
                proof_type: "Ed25519Signature2020".to_string(),
                created: now,
                verification_method: format!("{}#key-1", publisher_id),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: hex::encode(cred_sig.to_bytes()),
            },
        };

        credentials.push(credential);
    }

    Ok(BatchFulfillmentReport {
        platform,
        publisher_id: publisher_id.to_string(),
        total_backers: backers.len(),
        fulfilled_credentials_count: credentials.len(),
        vouchers,
        credentials,
    })
}

fn urlencoding_simple(s: &str) -> String {
    s.replace('/', "%2F").replace(':', "%3A")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_parse_kickstarter_csv() {
        let csv = r#"Backer Number,Backer Name,Email,Reward Title,Pledge Amount
101,"Alice Adventure",alice@example.com,"Digital PDF Tier",$25.00
102,"Bob Barbarian",bob@example.com,"All-In Digital & Hardcover",$60.00
103,"Charlie Cleric",charlie@example.com,"Custom Tier",$15.00
"#;

        let backers = parse_backer_csv(csv, CrowdfundingPlatform::Kickstarter).unwrap();
        assert_eq!(backers.len(), 3);
        assert_eq!(backers[0].backer_id, "101");
        assert_eq!(backers[0].name, "Alice Adventure");
        assert_eq!(backers[0].email, "alice@example.com");
        assert_eq!(backers[0].reward_tier, "Digital PDF Tier");
        assert_eq!(backers[0].pledge_amount, Some(25.0));

        assert_eq!(backers[1].backer_id, "102");
        assert_eq!(backers[1].pledge_amount, Some(60.0));
    }

    #[test]
    fn test_batch_fulfillment_and_voucher_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let backers = vec![
            BackerRecord {
                backer_id: "ks-101".to_string(),
                email: "alice@example.com".to_string(),
                name: "Alice".to_string(),
                reward_tier: "Digital Core Tier".to_string(),
                pledge_amount: Some(30.0),
                reward_package_ids: Vec::new(),
            },
            BackerRecord {
                backer_id: "ks-102".to_string(),
                email: "bob@example.com".to_string(),
                name: "Bob".to_string(),
                reward_tier: "All-In Compendium".to_string(),
                pledge_amount: Some(80.0),
                reward_package_ids: Vec::new(),
            },
        ];

        let mut digests_core = HashMap::new();
        digests_core.insert("paizo/player-core".to_string(), "b3:pcore_hash".to_string());

        let mut digests_all = HashMap::new();
        digests_all.insert("paizo/player-core".to_string(), "b3:pcore_hash".to_string());
        digests_all.insert("paizo/monster-core".to_string(), "b3:mcore_hash".to_string());

        let tiers = vec![
            FulfillmentTierConfig {
                tier_name: "Digital Core Tier".to_string(),
                package_ids: vec!["paizo/player-core".to_string()],
                content_digests: digests_core,
            },
            FulfillmentTierConfig {
                tier_name: "All-In Compendium".to_string(),
                package_ids: vec![
                    "paizo/player-core".to_string(),
                    "paizo/monster-core".to_string(),
                ],
                content_digests: digests_all,
            },
        ];

        let report = generate_batch_fulfillment(
            &backers,
            &tiers,
            "did:kryptotome:pub:paizo",
            "Paizo Inc",
            CrowdfundingPlatform::Kickstarter,
            &signing_key,
        )
        .unwrap();

        assert_eq!(report.total_backers, 2);
        assert_eq!(report.fulfilled_credentials_count, 2);
        // Alice gets 1 voucher, Bob gets 2 vouchers = 3 total vouchers
        assert_eq!(report.vouchers.len(), 3);

        // Verify voucher signatures
        for voucher in &report.vouchers {
            assert!(voucher.verify(None).unwrap());
            assert!(voucher.claim_url.starts_with("kryptotome://claim?"));
        }

        // Verify tamper detection on voucher
        let mut tampered = report.vouchers[0].clone();
        tampered.activation_token = "tampered_token_xyz".to_string();
        assert!(!tampered.verify(None).unwrap());
    }
}
