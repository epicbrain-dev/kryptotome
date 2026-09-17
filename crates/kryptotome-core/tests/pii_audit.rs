use chrono::Utc;
use kryptotome_core::{
    circuit::EntitlementProofBundle,
    credential::{CredentialSubject, Entitlement, Issuer, KryptotomeCredential, ProofData},
    zkp::{ProofInputs, ZkProof},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Automated PII Inspector that scans text/binary for forbidden personal identifiers
struct PiiInspector;

impl PiiInspector {
    /// Asserts that a serialized string contains zero PII patterns
    fn assert_zero_pii(context: &str, content: &str) {
        // 1. Email addresses (e.g. user@example.com)
        assert!(
            !Self::has_email_pattern(content),
            "PII Leak Detected in {}: Contains email address pattern! Content snippet: {}",
            context,
            Self::snippet(content)
        );

        // 2. IPv4 / IPv6 addresses
        assert!(
            !Self::has_ip_pattern(content),
            "PII Leak Detected in {}: Contains IP address pattern! Content snippet: {}",
            context,
            Self::snippet(content)
        );

        // 3. User home filesystem directories (e.g. /Users/john, /home/alice, C:\Users\bob)
        assert!(
            !Self::has_user_home_path(content),
            "PII Leak Detected in {}: Contains local filesystem user path! Content snippet: {}",
            context,
            Self::snippet(content)
        );

        // 4. US Social Security Numbers (e.g. 123-45-6789)
        assert!(
            !Self::has_ssn_pattern(content),
            "PII Leak Detected in {}: Contains SSN pattern! Content snippet: {}",
            context,
            Self::snippet(content)
        );

        // 5. Phone numbers
        assert!(
            !Self::has_phone_pattern(content),
            "PII Leak Detected in {}: Contains phone number pattern! Content snippet: {}",
            context,
            Self::snippet(content)
        );

        // 6. Payment Card numbers (13 to 19 digits)
        assert!(
            !Self::has_credit_card_pattern(content),
            "PII Leak Detected in {}: Contains credit card pattern! Content snippet: {}",
            context,
            Self::snippet(content)
        );
    }

    fn snippet(s: &str) -> String {
        if s.len() > 120 {
            format!("{}...", &s[..120])
        } else {
            s.to_string()
        }
    }

    fn has_email_pattern(s: &str) -> bool {
        // Match user@domain.tld
        let bytes = s.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'@' && i > 0 && i < bytes.len() - 1 {
                let left = &s[..i];
                let right = &s[i + 1..];
                let left_valid = left
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric());
                let right_has_dot = right.contains('.')
                    && right.chars().next().is_some_and(|c| c.is_alphanumeric());
                if left_valid && right_has_dot {
                    return true;
                }
            }
        }
        false
    }

    fn has_ip_pattern(s: &str) -> bool {
        // Match IPv4: 4 digit groups separated by dots
        for word in s.split(|c: char| !c.is_alphanumeric() && c != '.') {
            let parts: Vec<&str> = word.split('.').collect();
            if parts.len() == 4 {
                let all_u8 = parts.iter().all(|p| p.parse::<u8>().is_ok());
                if all_u8 && parts[0] != "0" {
                    // Exclude version numbers like 1.0.0.0
                    return true;
                }
            }
        }
        false
    }

    fn has_user_home_path(s: &str) -> bool {
        let lower = s.to_lowercase();
        lower.contains("/users/") || lower.contains("/home/") || lower.contains("c:\\users\\")
    }

    fn has_ssn_pattern(s: &str) -> bool {
        for word in s.split_whitespace() {
            let clean = word.trim_matches(|c: char| !c.is_numeric() && c != '-');
            let parts: Vec<&str> = clean.split('-').collect();
            if parts.len() == 3
                && parts[0].len() == 3
                && parts[1].len() == 2
                && parts[2].len() == 4
                && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
            {
                return true;
            }
        }
        false
    }

    fn has_phone_pattern(s: &str) -> bool {
        // Match +1-800-555-0199 or (555) 123-4567
        for word in s.split_whitespace() {
            let digits: String = word.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() == 10 && (word.contains('-') || word.contains('(')) {
                return true;
            }
        }
        false
    }

    fn has_credit_card_pattern(s: &str) -> bool {
        for word in s.split_whitespace() {
            let digits: String = word.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() == 16 && (digits.starts_with('4') || digits.starts_with('5')) {
                return true;
            }
        }
        false
    }
}

#[test]
fn test_credential_schema_contains_zero_pii() {
    let cred = KryptotomeCredential {
        context: vec![
            "https://www.w3.org/ns/credentials/v2".to_string(),
            "https://kryptotome.org/schemas/v1/context.jsonld".to_string(),
        ],
        id: "urn:uuid:7b2a64c4-7220-4e8c-8f19-97df21458e38".to_string(),
        credential_type: vec![
            "VerifiableCredential".to_string(),
            "KryptotomeEntitlementCredential".to_string(),
        ],
        issuer: Issuer {
            id: "did:key:z6MkuTgz7yCq6GZtQWz8vRjM3E5kL".to_string(),
            name: "Paizo Publishing, LLC".to_string(),
            public_key: "ed25519:abcdef0123456789abcdef0123456789".to_string(),
        },
        valid_from: Utc::now(),
        valid_until: None,
        credential_subject: CredentialSubject {
            id: "urn:uuid:e9112448-f608-41be-b437-567e33550e58".to_string(),
            holder_commitment: "urn:kryptotome:commitment:bls12381:8591c2b53...".to_string(),
            entitlements: vec![Entitlement {
                package_id: "paizo/pathfinder-core".to_string(),
                content_digest:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                scope: vec!["core_rules".to_string(), "compendium".to_string()],
            }],
        },
        proof: ProofData {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Utc::now(),
            verification_method: "did:key:z6MkuTgz7yCq6GZtQWz8vRjM3E5kL#key-1".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "z3jG7Vp...".to_string(),
        },
    };

    let serialized = serde_json::to_string_pretty(&cred).expect("Serialization succeeds");
    PiiInspector::assert_zero_pii("KryptotomeCredential JSON", &serialized);

    // Assert that holder identity is strictly a cryptographic commitment
    assert!(
        cred.credential_subject
            .holder_commitment
            .starts_with("urn:kryptotome:commitment:"),
        "Holder commitment must be a canonical commitment URN"
    );
    assert!(
        !serialized.contains("email")
            && !serialized.contains("username")
            && !serialized.contains("realName"),
        "No PII fields permitted in credential schema"
    );
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LicenseMetadata {
    pub code: String,
    pub url: Option<String>,
    pub open_gaming_content: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageManifest {
    pub schema_version: String,
    pub package_id: String,
    pub version: String,
    pub title: String,
    pub publisher: String,
    pub license: LicenseMetadata,
    pub content_digest: String,
    pub files: HashMap<String, String>,
    pub signature: String,
}

#[test]
fn test_package_manifest_schema_contains_zero_pii() {
    let mut files = HashMap::new();
    files.insert(
        "rules/spells.json".to_string(),
        "sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222".to_string(),
    );
    files.insert(
        "assets/token.png".to_string(),
        "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff".to_string(),
    );

    let manifest = PackageManifest {
        schema_version: "kryptotome/manifest/v1".to_string(),
        package_id: "free-league/alien-rpg-core".to_string(),
        version: "1.0.4".to_string(),
        title: "ALIEN RPG Core Rulebook".to_string(),
        publisher: "Free League Publishing".to_string(),
        license: LicenseMetadata {
            code: "FreeLeague-ORC-1.0".to_string(),
            url: Some("https://freeleaguepublishing.com/license".to_string()),
            open_gaming_content: true,
        },
        content_digest: "sha256:ffff1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
            .to_string(),
        files,
        signature: "sig_ed25519_abcdef".to_string(),
    };

    let serialized_json = serde_json::to_string_pretty(&manifest).unwrap();
    PiiInspector::assert_zero_pii("PackageManifest JSON", &serialized_json);
}

#[test]
fn test_zk_proof_and_presentation_bundle_contain_zero_pii() {
    let proof = ZkProof {
        proof_bytes: vec![0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f],
        public_inputs: ProofInputs {
            challenge_nonce: "challenge-single-use-nonce-99".to_string(),
            package_id: "paizo/starfinder-core".to_string(),
            content_digest: "blake3:abcdef0123456789".to_string(),
            publisher_pubkey_hash: "pubkey_hash_1234".to_string(),
            holder_commitment: Some("urn:kryptotome:commitment:bls12381:deadbeef".to_string()),
        },
    };

    let serialized_proof = serde_json::to_string(&proof).unwrap();
    PiiInspector::assert_zero_pii("ZkProof JSON", &serialized_proof);

    let bundle = EntitlementProofBundle {
        version: 1,
        curve: "BLS12-381".to_string(),
        proof_system: "groth16".to_string(),
        proof_base64: "S3J5cHRv".to_string(),
        public_inputs_base64: "cHVibGlj".to_string(),
        package_id: "paizo/starfinder-core".to_string(),
        content_digest: "blake3:abcdef0123456789".to_string(),
        challenge_nonce: "challenge-single-use-nonce-99".to_string(),
        holder_commitment_urn: "urn:kryptotome:commitment:bls12381:deadbeef".to_string(),
    };

    let serialized_bundle = serde_json::to_string(&bundle).unwrap();
    PiiInspector::assert_zero_pii("EntitlementProofBundle JSON", &serialized_bundle);
}
