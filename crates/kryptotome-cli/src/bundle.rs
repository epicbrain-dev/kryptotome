use crate::publisher::{
    verify_package_directory, verify_package_manifest, DirectoryIntegrityReport,
    ManifestVerificationReport, PackageManifest,
};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use indicatif::{ProgressBar, ProgressStyle};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// Report generated after bundling a .ktome archive
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleReport {
    pub package_id: String,
    pub version: String,
    pub archive_path: PathBuf,
    pub archive_size_bytes: u64,
    pub total_files_bundled: usize,
    pub root_digest: String,
}

/// Report generated after unpacking a .ktome archive
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnpackReport {
    pub package_id: String,
    pub version: String,
    pub extracted_dir: PathBuf,
    pub extracted_files: usize,
    pub manifest_verified: Option<ManifestVerificationReport>,
    pub directory_integrity: Option<DirectoryIntegrityReport>,
}

/// Bundle a signed PackageManifest and its compendium directory into a single .ktome archive
pub fn build_ktome_archive<P: AsRef<Path>, Q: AsRef<Path>>(
    manifest: &PackageManifest,
    source_dir: P,
    output_ktome_path: Q,
    show_progress: bool,
) -> Result<BundleReport> {
    let source_dir = source_dir.as_ref();
    let output_path = output_ktome_path.as_ref();

    if !source_dir.is_dir() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
            message: format!("Source directory not found: {:?}", source_dir),
        });
    }

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let file = File::create(output_path)?;
    let buf_writer = BufWriter::with_capacity(131072, file);
    let gz = GzEncoder::new(buf_writer, Compression::default());
    let mut tar = tar::Builder::new(gz);

    // 1. Add manifest.json at the archive root
    let manifest_json = serde_json::to_string_pretty(manifest)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_json.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "manifest.json", manifest_json.as_bytes())?;

    // 2. Add all declared files in order
    let pb = if show_progress {
        let p = ProgressBar::new(manifest.files.len() as u64);
        p.set_style(
            ProgressStyle::default_bar()
                .template("  ↳ Bundling .ktome [{pos}/{len}] {wide_msg:.yellow}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        p
    } else {
        ProgressBar::hidden()
    };

    let mut bundled_count = 0;
    for entry in &manifest.files {
        let file_path = source_dir.join(&entry.path);
        if !file_path.is_file() {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
                message: format!("Declared file missing on disk: {:?}", file_path),
            });
        }

        pb.set_message(entry.path.clone());
        let mut f = File::open(&file_path)?;
        tar.append_file(&entry.path, &mut f)?;
        bundled_count += 1;
        pb.inc(1);
    }

    tar.finish()?;
    let gz_encoder = tar.into_inner()?;
    let mut writer = gz_encoder.finish()?;
    writer.flush()?;

    pb.finish_and_clear();

    let archive_size = std::fs::metadata(output_path)?.len();

    Ok(BundleReport {
        package_id: manifest.package_id.clone(),
        version: manifest.version.clone(),
        archive_path: output_path.to_path_buf(),
        archive_size_bytes: archive_size,
        total_files_bundled: bundled_count + 1, // manifest + assets
        root_digest: manifest.root_digest.clone(),
    })
}

/// Inspect and extract PackageManifest directly from a .ktome archive without full extraction
pub fn inspect_ktome_archive<P: AsRef<Path>>(ktome_path: P) -> Result<PackageManifest> {
    let file = File::open(ktome_path.as_ref())?;
    let buf_reader = BufReader::with_capacity(131072, file);
    let gz = GzDecoder::new(buf_reader);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path == Path::new("manifest.json") {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            let manifest: PackageManifest = serde_json::from_str(&content)?;
            return Ok(manifest);
        }
    }

    Err(KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
        message: "No manifest.json found in .ktome archive root".to_string(),
    })
}

/// Unpack a .ktome archive to a destination directory with optional integrity and signature verification
pub fn unpack_ktome_archive<P: AsRef<Path>, Q: AsRef<Path>>(
    ktome_path: P,
    dest_dir: Q,
    verify_after_unpack: bool,
    show_progress: bool,
) -> Result<UnpackReport> {
    let ktome_path = ktome_path.as_ref();
    let dest_dir = dest_dir.as_ref();

    if !ktome_path.is_file() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
            message: format!("Archive file not found: {:?}", ktome_path),
        });
    }

    std::fs::create_dir_all(dest_dir)?;

    let file = File::open(ktome_path)?;
    let buf_reader = BufReader::with_capacity(131072, file);
    let gz = GzDecoder::new(buf_reader);
    let mut archive = tar::Archive::new(gz);

    let mut extracted_files = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let rel_path = entry.path()?.to_path_buf();
        let target_path = dest_dir.join(&rel_path);

        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        entry.unpack(&target_path)?;
        extracted_files += 1;
    }

    let manifest_path = dest_dir.join("manifest.json");
    if !manifest_path.is_file() {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
            message: "Unpacked archive is missing manifest.json".to_string(),
        });
    }

    let manifest_json = std::fs::read_to_string(&manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&manifest_json)?;

    let (manifest_verified, directory_integrity) = if verify_after_unpack {
        let man_rep = verify_package_manifest(&manifest, None)?;
        let dir_rep = verify_package_directory(&manifest, dest_dir, show_progress)?;
        if !dir_rep.is_valid {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp501DigestMismatch,
                message: format!(
                    "Extracted archive integrity check failed! Missing files: {:?}, altered files: {:?}",
                    dir_rep.missing_files, dir_rep.altered_files
                ),
            });
        }
        (Some(man_rep), Some(dir_rep))
    } else {
        (None, None)
    };

    Ok(UnpackReport {
        package_id: manifest.package_id,
        version: manifest.version,
        extracted_dir: dest_dir.to_path_buf(),
        extracted_files,
        manifest_verified,
        directory_integrity,
    })
}
