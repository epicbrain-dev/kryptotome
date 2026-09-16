use ed25519_dalek::{Signer, SigningKey};
use kryptotome_core::error::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFileEntry {
    pub path: String,
    pub size: u64,
    pub digest: String,
    pub content_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePublisher {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub mirror_urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageLicense {
    pub r#type: String,
    pub url: String,
    pub attribution: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSignature {
    pub algorithm: String,
    pub signature_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

    /// Ingests directory, computes deterministic content digests, and signs manifest
    pub fn build_and_sign_package<P: AsRef<Path>>(
        &self,
        package_id: &str,
        title: &str,
        version: &str,
        publisher_name: &str,
        source_dir: P,
        algorithm: kryptotome_core::DigestAlgorithm,
    ) -> Result<PackageManifest> {
        let root_digest = kryptotome_core::compute_directory_digest_with_algorithm(&source_dir, algorithm)?;
        let pubkey_hex = hex_encode(self.signing_key.verifying_key().as_bytes());

        // Collect individual files for manifest
        let mut files = Vec::new();
        if source_dir.as_ref().is_dir() {
            Self::collect_files_recursive(source_dir.as_ref(), source_dir.as_ref(), algorithm, &mut files)?;
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));

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
            license: PackageLicense {
                r#type: "ORC-1.0".to_string(),
                url: "https://paizo.com/orclicense".to_string(),
                attribution: format!("Published by {}", publisher_name),
            },
            digest_algorithm: algorithm.as_str().to_string(),
            root_digest: root_digest.clone(),
            files,
            signature: None,
        };

        // Sign the package root digest
        let payload_to_sign = format!("{}:{}:{}", manifest.package_id, manifest.version, root_digest);
        let signature = self.signing_key.sign(payload_to_sign.as_bytes());

        manifest.signature = Some(ManifestSignature {
            algorithm: "Ed25519".to_string(),
            signature_value: hex_encode(&signature.to_bytes()),
        });

        Ok(manifest)
    }

    fn collect_files_recursive(
        current_dir: &Path,
        base_dir: &Path,
        algorithm: kryptotome_core::DigestAlgorithm,
        entries: &mut Vec<ManifestFileEntry>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(current_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let rel_path = path
                    .strip_prefix(base_dir)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
                    .to_string_lossy()
                    .to_string();
                let digest = kryptotome_core::compute_file_digest_with_algorithm(&path, algorithm)?;
                let metadata = std::fs::metadata(&path)?;
                let content_type = if rel_path.ends_with(".json") {
                    "application/json".to_string()
                } else if rel_path.ends_with(".png") || rel_path.ends_with(".webp") {
                    "image/webp".to_string()
                } else {
                    "application/octet-stream".to_string()
                };

                entries.push(ManifestFileEntry {
                    path: rel_path,
                    size: metadata.len(),
                    digest,
                    content_type,
                });
            } else if path.is_dir() {
                Self::collect_files_recursive(&path, base_dir, algorithm, entries)?;
            }
        }
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
