use blake3::Hasher;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub use kryptotome_cli::crowdfunding::{
    generate_batch_fulfillment, parse_backer_csv, BackerRecord, BatchFulfillmentReport,
    ClaimVoucher, CrowdfundingPlatform, FulfillmentTierConfig,
};
pub use kryptotome_cli::voucher::{
    format_ndef_payload, generate_voucher_batch, NfcTagPayload, PhysicalVoucherBatchSpec,
    PhysicalVoucherFormat, PhysicalVoucherRecord,
};

/// Maximum bounds to prevent memory exhaustion / DoS in enterprise environments
pub const MAX_BACKER_ROWS: usize = 50_000;
pub const MAX_ASSET_SIZE_BYTES: u64 = 256 * 1024 * 1024; // 256MB

/// Digital rulebook asset entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulebookAsset {
    pub path: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub blake3_hash: String,
}

/// Supported open gaming licensing schemas
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseSchema {
    PaizoOrc,
    CreativeCommonsBy4,
    CreativeCommonsZero,
    Ogl10a,
    CustomProprietary,
}

/// Package manifest schema for Kryptotome Publisher Studio
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StudioPackageManifest {
    pub package_id: String,
    pub title: String,
    pub system: String,
    pub version: String,
    pub publisher: String,
    pub license: LicenseSchema,
    pub license_attribution: String,
    pub assets: Vec<RulebookAsset>,
    pub package_hash: String,
}

/// Package build output with signature
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuiltPackageBundle {
    pub manifest: StudioPackageManifest,
    pub publisher_public_key: String,
    pub signature_hex: String,
    pub created_at: String,
    pub bundle_checksum: String,
}

/// Validation error for schema compliance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaValidationError {
    pub field: String,
    pub message: String,
    pub error_code: String,
}

/// Enterprise Audit Log Entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub operation: String,
    pub package_id: Option<String>,
    pub digest: String,
    pub status: String,
    pub details: String,
}

/// Thread-safe enterprise audit chronicle
pub struct PublisherAuditChronicle {
    entries: Mutex<Vec<AuditLogEntry>>,
}

impl Default for PublisherAuditChronicle {
    fn default() -> Self {
        Self::new()
    }
}

impl PublisherAuditChronicle {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn record(
        &self,
        operation: &str,
        package_id: Option<&str>,
        digest: &str,
        status: &str,
        details: &str,
    ) {
        let entry = AuditLogEntry {
            timestamp: Utc::now().to_rfc3339(),
            operation: operation.to_string(),
            package_id: package_id.map(|s| s.to_string()),
            digest: digest.to_string(),
            status: status.to_string(),
            details: details.to_string(),
        };
        if let Ok(mut lock) = self.entries.lock() {
            lock.push(entry);
        }
    }

    pub fn get_entries(&self) -> Vec<AuditLogEntry> {
        self.entries.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

/// Global chronicle instance
pub static AUDIT_CHRONICLE: std::sync::LazyLock<PublisherAuditChronicle> =
    std::sync::LazyLock::new(PublisherAuditChronicle::new);

/// Sanitize asset path against directory traversal
pub fn sanitize_asset_path(path: &str) -> Result<String, KryptotomeError> {
    let clean = path.trim().replace('\\', "/");
    if clean.contains("..") || clean.starts_with('/') {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
            message: format!(
                "Security violation: Invalid asset path containing traversal sequences: {}",
                path
            ),
        });
    }
    Ok(clean)
}

/// Scan asset contents and compute BLAKE3 hash with boundary checks
pub fn hash_asset_content(
    path: &str,
    mime_type: &str,
    content: &[u8],
) -> Result<RulebookAsset, KryptotomeError> {
    let safe_path = sanitize_asset_path(path)?;

    if content.len() as u64 > MAX_ASSET_SIZE_BYTES {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
            message: format!(
                "Asset {} exceeds enterprise size limit of {} bytes",
                path, MAX_ASSET_SIZE_BYTES
            ),
        });
    }

    let mut hasher = Hasher::new();
    hasher.update(content);
    let hash_hex = hasher.finalize().to_hex().to_string();

    AUDIT_CHRONICLE.record(
        "HASH_ASSET",
        None,
        &hash_hex,
        "SUCCESS",
        &format!("Hashed asset: {}", safe_path),
    );

    Ok(RulebookAsset {
        path: safe_path,
        mime_type: mime_type.to_string(),
        size_bytes: content.len() as u64,
        blake3_hash: hash_hex,
    })
}

/// Validate publisher manifest schema compliance (Paizo ORC, CC-BY, etc.)
pub fn validate_package_schema(
    manifest: &StudioPackageManifest,
) -> Result<(), Vec<SchemaValidationError>> {
    let mut errors = Vec::new();

    if manifest.package_id.trim().is_empty() {
        errors.push(SchemaValidationError {
            field: "package_id".into(),
            message: "Package ID cannot be empty.".into(),
            error_code: "KRYP-106".into(),
        });
    }

    if manifest.title.trim().is_empty() {
        errors.push(SchemaValidationError {
            field: "title".into(),
            message: "Title cannot be empty.".into(),
            error_code: "KRYP-106".into(),
        });
    }

    if manifest.publisher.trim().is_empty() {
        errors.push(SchemaValidationError {
            field: "publisher".into(),
            message: "Publisher organization is required.".into(),
            error_code: "KRYP-106".into(),
        });
    }

    if manifest.license == LicenseSchema::PaizoOrc && manifest.license_attribution.trim().is_empty()
    {
        errors.push(SchemaValidationError {
            field: "license_attribution".into(),
            message: "Paizo ORC license requires explicit copyright attribution statement.".into(),
            error_code: "KRYP-106".into(),
        });
    }

    if manifest.license == LicenseSchema::CreativeCommonsBy4
        && manifest.license_attribution.trim().is_empty()
    {
        errors.push(SchemaValidationError {
            field: "license_attribution".into(),
            message: "CC-BY-4.0 license requires author attribution notices.".into(),
            error_code: "KRYP-106".into(),
        });
    }

    if manifest.assets.is_empty() {
        errors.push(SchemaValidationError {
            field: "assets".into(),
            message: "Package must contain at least one asset (PDF, Markdown, or JSON).".into(),
            error_code: "KRYP-106".into(),
        });
    }

    if errors.is_empty() {
        AUDIT_CHRONICLE.record(
            "SCHEMA_VALIDATE",
            Some(&manifest.package_id),
            &manifest.package_hash,
            "SUCCESS",
            "Manifest schema compliance verified",
        );
        Ok(())
    } else {
        AUDIT_CHRONICLE.record(
            "SCHEMA_VALIDATE",
            Some(&manifest.package_id),
            &manifest.package_hash,
            "FAILED",
            &format!("Schema validation failed with {} errors", errors.len()),
        );
        Err(errors)
    }
}

/// Compute package-level BLAKE3 hash deterministically from sorted assets
pub fn compute_package_hash(package_id: &str, version: &str, assets: &[RulebookAsset]) -> String {
    let mut sorted_assets = assets.to_vec();
    sorted_assets.sort_by(|a, b| a.path.cmp(&b.path));

    let mut hasher = Hasher::new();
    hasher.update(package_id.as_bytes());
    hasher.update(version.as_bytes());
    for asset in &sorted_assets {
        hasher.update(asset.path.as_bytes());
        hasher.update(asset.blake3_hash.as_bytes());
        hasher.update(&asset.size_bytes.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Sign package manifest and produce BuiltPackageBundle
pub fn sign_and_build_package(
    manifest: StudioPackageManifest,
    signing_key_bytes: &[u8; 32],
) -> Result<BuiltPackageBundle, KryptotomeError> {
    validate_package_schema(&manifest).map_err(|errs| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
        message: format!("Schema validation failed: {:?}", errs),
    })?;

    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let pub_key_hex = hex::encode(verifying_key.to_bytes());

    // Sign the package hash + package_id
    let payload = format!("{}:{}", manifest.package_id, manifest.package_hash);
    let signature = signing_key.sign(payload.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    let created_at = Utc::now().to_rfc3339();

    // Compute bundle checksum
    let mut bundle_hasher = Hasher::new();
    bundle_hasher.update(manifest.package_hash.as_bytes());
    bundle_hasher.update(pub_key_hex.as_bytes());
    bundle_hasher.update(sig_hex.as_bytes());
    let bundle_checksum = bundle_hasher.finalize().to_hex().to_string();

    AUDIT_CHRONICLE.record(
        "SIGN_PACKAGE",
        Some(&manifest.package_id),
        &bundle_checksum,
        "SUCCESS",
        &format!("Package signed with publisher key {}", &pub_key_hex[..16]),
    );

    Ok(BuiltPackageBundle {
        manifest,
        publisher_public_key: pub_key_hex,
        signature_hex: sig_hex,
        created_at,
        bundle_checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_hashing_and_manifest_validation() {
        let pdf_data = b"%PDF-1.7 Test Rulebook Content";
        let asset1 = hash_asset_content("rules/core.pdf", "application/pdf", pdf_data).unwrap();
        assert!(!asset1.blake3_hash.is_empty());
        assert_eq!(asset1.size_bytes, pdf_data.len() as u64);

        let pkg_hash = compute_package_hash(
            "pkg-cosmic-horror-5e",
            "1.0.0",
            std::slice::from_ref(&asset1),
        );
        assert!(!pkg_hash.is_empty());

        let manifest = StudioPackageManifest {
            package_id: "pkg-cosmic-horror-5e".into(),
            title: "Cosmic Horror 5e Guide".into(),
            system: "5e".into(),
            version: "1.0.0".into(),
            publisher: "Eldritch Press".into(),
            license: LicenseSchema::PaizoOrc,
            license_attribution: "".into(), // missing attribution should fail
            assets: vec![asset1],
            package_hash: pkg_hash,
        };

        let err = validate_package_schema(&manifest).unwrap_err();
        assert_eq!(err[0].field, "license_attribution");
    }

    #[test]
    fn test_sign_and_build_package_flow() {
        let md_data = b"# Spells\nArcane Blast...";
        let asset = hash_asset_content("spells.md", "text/markdown", md_data).unwrap();
        let pkg_hash = compute_package_hash("pkg-spells", "1.0.0", std::slice::from_ref(&asset));

        let manifest = StudioPackageManifest {
            package_id: "pkg-spells".into(),
            title: "Tome of Spells".into(),
            system: "pathfinder-2e".into(),
            version: "1.0.0".into(),
            publisher: "Mage Guild Labs".into(),
            license: LicenseSchema::CreativeCommonsBy4,
            license_attribution: "Copyright 2026 Mage Guild Labs under CC-BY-4.0".into(),
            assets: vec![asset],
            package_hash: pkg_hash,
        };

        let seed = [42u8; 32];
        let bundle = sign_and_build_package(manifest, &seed).expect("build bundle");
        assert!(!bundle.signature_hex.is_empty());
        assert!(!bundle.bundle_checksum.is_empty());
        assert_eq!(bundle.manifest.publisher, "Mage Guild Labs");

        let entries = AUDIT_CHRONICLE.get_entries();
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_path_traversal_sanitization() {
        assert!(sanitize_asset_path("../secrets.txt").is_err());
        assert!(sanitize_asset_path("/etc/passwd").is_err());
        assert_eq!(
            sanitize_asset_path("rules\\chapter1.pdf").unwrap(),
            "rules/chapter1.pdf"
        );
    }
}
