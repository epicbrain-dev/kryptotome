use crate::bundle::{build_ktome_archive, BundleReport};
use crate::license::OpenGameLicenseType;
use crate::publisher::{PackageLicense, PublisherToolchain};
use crate::scanner::ScanOptions;
use ed25519_dalek::SigningKey;
use indicatif::{ProgressBar, ProgressStyle};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Specification for a single package entry in a batch release
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPackageSpec {
    pub package_id: String,
    pub title: String,
    pub version: String,
    pub dir: PathBuf,
    #[serde(default)]
    pub license_type: Option<String>,
    #[serde(default)]
    pub license_url: Option<String>,
    #[serde(default)]
    pub license_attribution: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
}

/// Batch release specification containing multiple compendiums
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSignSpec {
    pub publisher_name: String,
    pub packages: Vec<BatchPackageSpec>,
}

/// Result of signing and packaging a single module within a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPackageResult {
    pub package_id: String,
    pub title: String,
    pub version: String,
    pub root_digest: String,
    pub manifest_path: PathBuf,
    pub bundle_path: PathBuf,
    pub bundle_size_bytes: u64,
}

/// Comprehensive summary report for a batch release execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSignReport {
    pub publisher_name: String,
    pub publisher_public_key: String,
    pub total_packages: usize,
    pub packages: Vec<BatchPackageResult>,
}

/// Execute batch signing and `.ktome` archive bundling
pub fn execute_batch_sign<P: AsRef<Path>>(
    spec: BatchSignSpec,
    output_dir: P,
    signing_key: Option<SigningKey>,
    show_progress: bool,
) -> Result<BatchSignReport> {
    let output_dir = output_dir.as_ref();
    std::fs::create_dir_all(output_dir)?;

    let mut csprng = OsRng;
    let signing_key = signing_key.unwrap_or_else(|| SigningKey::generate(&mut csprng));
    let pubkey_hex = hex_encode(signing_key.verifying_key().as_bytes());
    let toolchain = PublisherToolchain::new(signing_key);

    let total_pkgs = spec.packages.len();
    let pb = if show_progress {
        let p = ProgressBar::new(total_pkgs as u64);
        p.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} Batch Release [{pos}/{len}] {wide_msg:.cyan}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        p
    } else {
        ProgressBar::hidden()
    };

    let mut results = Vec::with_capacity(total_pkgs);

    for pkg in &spec.packages {
        pb.set_message(format!("Signing and bundling '{}'", pkg.title));

        let algo_str = pkg.algorithm.as_deref().unwrap_or("sha-256");
        let digest_algo: kryptotome_core::DigestAlgorithm = algo_str.parse()?;

        // Build license metadata
        let license_type_str = pkg.license_type.as_deref().unwrap_or("ORC-1.0");
        let license_enum: OpenGameLicenseType = license_type_str.parse()?;
        let license_url = pkg
            .license_url
            .clone()
            .unwrap_or_else(|| license_enum.canonical_url().to_string());
        let attribution = pkg
            .license_attribution
            .clone()
            .unwrap_or_else(|| match license_enum {
                OpenGameLicenseType::Cc0_1_0 => "".to_string(),
                _ => format!("Published by {}", spec.publisher_name),
            });

        let license = PackageLicense {
            r#type: license_enum.as_str().to_string(),
            url: license_url,
            attribution,
        };

        let scan_options = ScanOptions {
            algorithm: digest_algo,
            show_progress: false, // inner progress suppressed so batch bar remains clean
        };

        // 1. Build and sign package manifest
        let manifest = toolchain.build_and_sign_package_with_license(
            &pkg.package_id,
            &pkg.title,
            &pkg.version,
            &spec.publisher_name,
            &pkg.dir,
            scan_options,
            license,
        )?;

        // 2. Determine file names
        let safe_id = pkg.package_id.replace(['/', ':', '\\'], "_");
        let manifest_filename = format!("{}-{}.manifest.json", safe_id, pkg.version);
        let bundle_filename = format!("{}-{}.ktome", safe_id, pkg.version);

        let manifest_dest = output_dir.join(manifest_filename);
        let bundle_dest = output_dir.join(bundle_filename);

        // Save manifest JSON
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        std::fs::write(&manifest_dest, manifest_json)?;

        // 3. Bundle into .ktome archive
        let bundle_report: BundleReport =
            build_ktome_archive(&manifest, &pkg.dir, &bundle_dest, false)?;

        results.push(BatchPackageResult {
            package_id: pkg.package_id.clone(),
            title: pkg.title.clone(),
            version: pkg.version.clone(),
            root_digest: manifest.root_digest,
            manifest_path: manifest_dest,
            bundle_path: bundle_dest,
            bundle_size_bytes: bundle_report.archive_size_bytes,
        });

        pb.inc(1);
    }

    pb.finish_with_message("Batch release bundling complete");

    let report = BatchSignReport {
        publisher_name: spec.publisher_name,
        publisher_public_key: pubkey_hex,
        total_packages: results.len(),
        packages: results,
    };

    // Save batch summary manifest
    let summary_json = serde_json::to_string_pretty(&report)?;
    std::fs::write(output_dir.join("batch-summary.json"), summary_json)?;

    Ok(report)
}

/// Automatically scan a parent directory where each subdirectory is an open compendium module
pub fn auto_discover_batch_spec<P: AsRef<Path>>(
    parent_dir: P,
    publisher_name: &str,
    default_version: &str,
    default_license: &str,
) -> Result<BatchSignSpec> {
    let parent_dir = parent_dir.as_ref();
    if !parent_dir.is_dir() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
            message: format!("Directory not found: {:?}", parent_dir),
        });
    }

    let mut packages = Vec::new();
    for entry in std::fs::read_dir(parent_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Skip hidden or system folders
            if dir_name.starts_with('.') || dir_name == "target" || dir_name == "node_modules" {
                continue;
            }

            let title = dir_name
                .replace(['-', '_'], " ")
                .split_whitespace()
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");

            let package_id = format!(
                "{}/{}",
                publisher_name.to_lowercase().replace(' ', "-"),
                dir_name.to_lowercase()
            );

            packages.push(BatchPackageSpec {
                package_id,
                title,
                version: default_version.to_string(),
                dir: path,
                license_type: Some(default_license.to_string()),
                license_url: None,
                license_attribution: None,
                algorithm: Some("sha-256".to_string()),
            });
        }
    }

    packages.sort_by(|a, b| a.package_id.cmp(&b.package_id));

    if packages.is_empty() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
            message: format!("No package subdirectories found in {:?}", parent_dir),
        });
    }

    Ok(BatchSignSpec {
        publisher_name: publisher_name.to_string(),
        packages,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
