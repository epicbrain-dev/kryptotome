use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kryptotome_core::error::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestVerificationReport {
    pub is_valid: bool,
    pub package_id: String,
    pub version: String,
    pub root_digest: String,
    pub publisher_id: String,
    pub publisher_name: String,
    pub verifying_key_hex: String,
    pub algorithm: String,
    pub license: PackageLicense,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryIntegrityReport {
    pub is_valid: bool,
    pub matched_files: usize,
    pub total_manifest_files: usize,
    pub root_digest_match: bool,
    pub computed_root_digest: String,
    pub expected_root_digest: String,
    pub missing_files: Vec<String>,
    pub altered_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFileEntry {
    pub path: String,
    pub size: u64,
    pub digest: String,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePublisher {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub mirror_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageLicense {
    pub r#type: String,
    pub url: String,
    pub attribution: String,
}

impl PackageLicense {
    pub fn new_orc(publisher_name: &str) -> Self {
        Self {
            r#type: "ORC-1.0".to_string(),
            url: "https://paizo.com/orclicense".to_string(),
            attribution: format!("Published by {}", publisher_name),
        }
    }

    pub fn new_cc_by(attribution: &str) -> Self {
        Self {
            r#type: "CC-BY-4.0".to_string(),
            url: "https://creativecommons.org/licenses/by/4.0/".to_string(),
            attribution: attribution.to_string(),
        }
    }

    pub fn new_cc0(attribution: Option<&str>) -> Self {
        Self {
            r#type: "CC0-1.0".to_string(),
            url: "https://creativecommons.org/publicdomain/zero/1.0/".to_string(),
            attribution: attribution.unwrap_or_default().to_string(),
        }
    }

    pub fn validate(&self) -> Result<crate::license::OpenGameLicenseType> {
        crate::license::validate_license_metadata(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSignature {
    pub algorithm: String,
    pub signature_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageManifest {
    pub schema_version: String,
    pub package_id: String,
    pub title: String,
    pub version: String,
    pub description: String,
    pub publisher: PackagePublisher,
    pub license: PackageLicense,
    pub digest_algorithm: String,
    pub root_digest: String,
    pub files: Vec<ManifestFileEntry>,
    pub signature: Option<ManifestSignature>,
}

pub struct PublisherToolchain {
    signing_key: SigningKey,
}

impl PublisherToolchain {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Ingests directory, computes deterministic content digests, and signs manifest with default ORC license
    pub fn build_and_sign_package<P: AsRef<Path>>(
        &self,
        package_id: &str,
        title: &str,
        version: &str,
        publisher_name: &str,
        source_dir: P,
        algorithm: kryptotome_core::DigestAlgorithm,
    ) -> Result<PackageManifest> {
        self.build_and_sign_package_with_options(
            package_id,
            title,
            version,
            publisher_name,
            source_dir,
            crate::scanner::ScanOptions {
                algorithm,
                show_progress: true,
            },
        )
    }

    /// Ingests directory using specified scan options (with default ORC license)
    pub fn build_and_sign_package_with_options<P: AsRef<Path>>(
        &self,
        package_id: &str,
        title: &str,
        version: &str,
        publisher_name: &str,
        source_dir: P,
        options: crate::scanner::ScanOptions,
    ) -> Result<PackageManifest> {
        let default_license = PackageLicense::new_orc(publisher_name);
        self.build_and_sign_package_with_license(
            package_id,
            title,
            version,
            publisher_name,
            source_dir,
            options,
            default_license,
        )
    }

    /// Ingests directory using specified scan options and explicit license metadata
    pub fn build_and_sign_package_with_license<P: AsRef<Path>>(
        &self,
        package_id: &str,
        title: &str,
        version: &str,
        publisher_name: &str,
        source_dir: P,
        options: crate::scanner::ScanOptions,
        license: PackageLicense,
    ) -> Result<PackageManifest> {
        // Validate license metadata against open gaming license standards (ORC, CC-BY-4.0, CC0)
        license.validate()?;

        let scanner = crate::scanner::CompendiumScanner::new(options.clone());
        let scan_result = scanner.scan_directory(&source_dir)?;

        let pubkey_hex = hex_encode(self.signing_key.verifying_key().as_bytes());

        let mut manifest = PackageManifest {
            schema_version: "1.0.0".to_string(),
            package_id: package_id.to_string(),
            title: title.to_string(),
            version: version.to_string(),
            description: format!("Deterministic signed package for {}", title),
            publisher: PackagePublisher {
                id: format!("did:kryptotome:pub:{}", &pubkey_hex[..16]),
                name: publisher_name.to_string(),
                public_key: pubkey_hex,
                mirror_urls: vec![],
            },
            license,
            digest_algorithm: options.algorithm.as_str().to_string(),
            root_digest: scan_result.root_digest.clone(),
            files: scan_result.files,
            signature: None,
        };

        // Sign the package root digest
        let payload_to_sign = format!("{}:{}:{}", manifest.package_id, manifest.version, scan_result.root_digest);
        let signature = self.signing_key.sign(payload_to_sign.as_bytes());

        manifest.signature = Some(ManifestSignature {
            algorithm: "Ed25519".to_string(),
            signature_value: hex_encode(&signature.to_bytes()),
        });

        Ok(manifest)
    }
}

/// Cryptographically verify the Ed25519 signature and publisher attribution of a package manifest
pub fn verify_package_manifest(
    manifest: &PackageManifest,
    expected_pubkey_hex: Option<&str>,
) -> Result<ManifestVerificationReport> {
    let signature_entry = manifest.signature.as_ref().ok_or_else(|| {
        kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp203CorruptedSignature,
            message: "Manifest does not contain a cryptographic signature".to_string(),
        }
    })?;

    if signature_entry.algorithm != "Ed25519" {
        return Err(kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp203CorruptedSignature,
            message: format!("Unsupported signature algorithm '{}', expected 'Ed25519'", signature_entry.algorithm),
        });
    }

    // Determine the public key to verify with
    let pubkey_hex = match expected_pubkey_hex {
        Some(expected) => {
            if !manifest.publisher.public_key.is_empty()
                && !manifest.publisher.public_key.eq_ignore_ascii_case(expected)
            {
                return Err(kryptotome_core::KryptotomeError::Detailed {
                    code: kryptotome_core::error::KryptotomeErrorCode::Kryp204UntrustedPublisherKey,
                    message: format!(
                        "Public key mismatch: manifest states '{}' but verification requested '{}'",
                        manifest.publisher.public_key, expected
                    ),
                });
            }
            expected
        }
        None => &manifest.publisher.public_key,
    };

    let pubkey_bytes = hex_decode(pubkey_hex).map_err(|_| {
        kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Invalid hex encoding in public key: '{}'", pubkey_hex),
        }
    })?;

    if pubkey_bytes.len() != 32 {
        return Err(kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Expected 32-byte Ed25519 public key, got {} bytes", pubkey_bytes.len()),
        });
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&key_arr).map_err(|e| {
        kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Malformed Ed25519 public key: {}", e),
        }
    })?;

    let sig_bytes = hex_decode(&signature_entry.signature_value).map_err(|_| {
        kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp203CorruptedSignature,
            message: "Invalid hex encoding in signature value".to_string(),
        }
    })?;

    let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
        kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp203CorruptedSignature,
            message: format!("Malformed Ed25519 signature bytes: {}", e),
        }
    })?;

    let payload_to_verify = format!("{}:{}:{}", manifest.package_id, manifest.version, manifest.root_digest);

    verifying_key
        .verify(payload_to_verify.as_bytes(), &signature)
        .map_err(|e| {
            kryptotome_core::KryptotomeError::Detailed {
                code: kryptotome_core::error::KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: format!("Ed25519 signature verification failed: {}", e),
            }
        })?;

    // Validate license metadata conforming to open gaming standards (ORC, CC-BY-4.0, CC0)
    manifest.license.validate()?;

    Ok(ManifestVerificationReport {
        is_valid: true,
        package_id: manifest.package_id.clone(),
        version: manifest.version.clone(),
        root_digest: manifest.root_digest.clone(),
        publisher_id: manifest.publisher.id.clone(),
        publisher_name: manifest.publisher.name.clone(),
        verifying_key_hex: pubkey_hex.to_string(),
        algorithm: "Ed25519".to_string(),
        license: manifest.license.clone(),
    })
}

/// Verify that the files in a local directory match the package manifest
pub fn verify_package_directory<P: AsRef<Path>>(
    manifest: &PackageManifest,
    dir_path: P,
    show_progress: bool,
) -> Result<DirectoryIntegrityReport> {
    let dir = dir_path.as_ref();
    if !dir.is_dir() {
        return Err(kryptotome_core::KryptotomeError::Detailed {
            code: kryptotome_core::error::KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
            message: format!("Directory path not found: {:?}", dir),
        });
    }

    let algorithm: kryptotome_core::DigestAlgorithm = manifest.digest_algorithm.parse()?;
    let scanner = crate::scanner::CompendiumScanner::new(crate::scanner::ScanOptions {
        algorithm,
        show_progress,
    });
    let scan_result = scanner.scan_directory(dir)?;

    let root_digest_match = scan_result.root_digest == manifest.root_digest;
    let mut missing_files = Vec::new();
    let mut altered_files = Vec::new();
    let mut matched_files = 0;

    for expected_file in &manifest.files {
        match scan_result.files.iter().find(|f| f.path == expected_file.path) {
            Some(found) => {
                if found.digest == expected_file.digest && found.size == expected_file.size {
                    matched_files += 1;
                } else {
                    altered_files.push(expected_file.path.clone());
                }
            }
            None => {
                missing_files.push(expected_file.path.clone());
            }
        }
    }

    let is_valid = root_digest_match && missing_files.is_empty() && altered_files.is_empty();

    Ok(DirectoryIntegrityReport {
        is_valid,
        matched_files,
        total_manifest_files: manifest.files.len(),
        root_digest_match,
        computed_root_digest: scan_result.root_digest,
        expected_root_digest: manifest.root_digest.clone(),
        missing_files,
        altered_files,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    let clean = s.trim();
    if clean.len() % 2 != 0 {
        return Err(());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
