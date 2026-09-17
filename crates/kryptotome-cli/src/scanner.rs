use crate::publisher::ManifestFileEntry;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use kryptotome_core::digest::{compute_file_digest_with_progress, DigestAlgorithm};
use kryptotome_core::error::Result;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Configuration options for compendium directory scanning
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub algorithm: DigestAlgorithm,
    pub show_progress: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            algorithm: DigestAlgorithm::Sha256,
            show_progress: true,
        }
    }
}

/// Discovered file metadata prior to hashing
#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub absolute_path: PathBuf,
    pub relative_path: String,
    pub size: u64,
    pub content_type: String,
}

/// Result of scanning and digesting a compendium directory
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub root_digest: String,
    pub files: Vec<ManifestFileEntry>,
    pub total_bytes: u64,
    pub total_files: usize,
}

/// High-throughput recursive compendium scanner with indicatif progress bars
pub struct CompendiumScanner {
    options: ScanOptions,
}

impl CompendiumScanner {
    pub fn new(options: ScanOptions) -> Self {
        Self { options }
    }

    /// Recursively scan directory, report progress, and compute deterministic root and file digests
    pub fn scan_directory<P: AsRef<Path>>(&self, root_dir: P) -> Result<ScanResult> {
        let root_dir = root_dir.as_ref();
        if !root_dir.is_dir() {
            return Err(kryptotome_core::KryptotomeError::Detailed {
                code: kryptotome_core::error::KryptotomeErrorCode::Kryp502MissingOrCorruptAsset,
                message: format!("Path is not a directory: {:?}", root_dir),
            });
        }

        // 1. Discovery Phase: Traverse directory tree and collect all files
        let mp = MultiProgress::new();
        if !self.options.show_progress {
            mp.set_draw_target(ProgressDrawTarget::hidden());
        }

        let discovery_pb = mp.add(ProgressBar::new_spinner());
        discovery_pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        discovery_pb.enable_steady_tick(Duration::from_millis(80));
        discovery_pb.set_message("Discovering compendium files...");

        let mut discovered = Vec::new();
        let mut visited_paths = HashSet::new();
        Self::discover_files_recursive(
            root_dir,
            root_dir,
            &mut discovered,
            &mut visited_paths,
            &discovery_pb,
        )?;

        // Deterministically sort discovered files by relative path
        discovered.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

        let total_files = discovered.len();
        let total_bytes: u64 = discovered.iter().map(|f| f.size).sum();

        discovery_pb.finish_with_message(format!(
            "Discovered {} files ({}) across compendium directory hierarchy",
            total_files,
            indicatif::HumanBytes(total_bytes)
        ));

        // 2. Digesting Phase: Multi-progress bars for bytes throughput and file tracking
        let bytes_pb = mp.add(ProgressBar::new(total_bytes));
        bytes_pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({binary_bytes_per_sec}, ETA {eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-"),
        );

        let files_pb = mp.add(ProgressBar::new(total_files as u64));
        files_pb.set_style(
            ProgressStyle::default_bar()
                .template("  ↳ [{pos}/{len} files] {wide_msg:.yellow}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );

        let mut manifest_entries = Vec::with_capacity(total_files);

        for file in &discovered {
            files_pb.set_message(file.relative_path.clone());

            let digest = compute_file_digest_with_progress(
                &file.absolute_path,
                self.options.algorithm,
                |chunk_len| {
                    bytes_pb.inc(chunk_len);
                },
            )?;

            manifest_entries.push(ManifestFileEntry {
                path: file.relative_path.clone(),
                size: file.size,
                digest,
                content_type: file.content_type.clone(),
            });

            files_pb.inc(1);
        }

        bytes_pb.finish_with_message("Hashing completed");
        files_pb.finish_with_message("All compendium files indexed");

        // 3. Compute Deterministic Root Digest across sorted files
        // Matches kryptotome-core directory digest specification: "rel_path:digest\n"
        let root_digest = match self.options.algorithm {
            DigestAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                for entry in &manifest_entries {
                    hasher.update(entry.path.as_bytes());
                    hasher.update(b":");
                    hasher.update(entry.digest.as_bytes());
                    hasher.update(b"\n");
                }
                hex_encode(&hasher.finalize())
            }
            DigestAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                for entry in &manifest_entries {
                    hasher.update(entry.path.as_bytes());
                    hasher.update(b":");
                    hasher.update(entry.digest.as_bytes());
                    hasher.update(b"\n");
                }
                hasher.finalize().to_hex().to_string()
            }
        };

        Ok(ScanResult {
            root_digest,
            files: manifest_entries,
            total_bytes,
            total_files,
        })
    }

    fn discover_files_recursive(
        current_dir: &Path,
        base_dir: &Path,
        discovered: &mut Vec<DiscoveredFile>,
        visited: &mut HashSet<PathBuf>,
        pb: &ProgressBar,
    ) -> Result<()> {
        let canonical = match current_dir.canonicalize() {
            Ok(c) => c,
            Err(_) => current_dir.to_path_buf(),
        };

        if !visited.insert(canonical) {
            // Guard against symlink cycles
            return Ok(());
        }

        let read_dir = std::fs::read_dir(current_dir)?;
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;

            if file_type.is_dir() {
                Self::discover_files_recursive(&path, base_dir, discovered, visited, pb)?;
            } else if file_type.is_file() {
                let rel_path = path
                    .strip_prefix(base_dir)
                    .map_err(std::io::Error::other)?
                    .to_string_lossy()
                    .replace('\\', "/");

                if rel_path == "manifest.json" {
                    continue;
                }

                let metadata = entry.metadata()?;
                let content_type = detect_content_type(&rel_path);

                discovered.push(DiscoveredFile {
                    absolute_path: path,
                    relative_path: rel_path,
                    size: metadata.len(),
                    content_type,
                });

                pb.set_message(format!(
                    "Found {} files ({})",
                    discovered.len(),
                    indicatif::HumanBytes(discovered.iter().map(|f| f.size).sum::<u64>())
                ));
            }
        }

        Ok(())
    }
}

/// Content type detection for tabletop gaming assets and compendium schemas
pub fn detect_content_type(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.ends_with(".json") {
        "application/json".to_string()
    } else if lower.ends_with(".webp") {
        "image/webp".to_string()
    } else if lower.ends_with(".png") {
        "image/png".to_string()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".to_string()
    } else if lower.ends_with(".svg") {
        "image/svg+xml".to_string()
    } else if lower.ends_with(".webm") {
        "video/webm".to_string()
    } else if lower.ends_with(".mp4") {
        "video/mp4".to_string()
    } else if lower.ends_with(".mp3") {
        "audio/mpeg".to_string()
    } else if lower.ends_with(".ogg") {
        "audio/ogg".to_string()
    } else if lower.ends_with(".wav") {
        "audio/wav".to_string()
    } else if lower.ends_with(".pdf") {
        "application/pdf".to_string()
    } else if lower.ends_with(".txt") {
        "text/plain".to_string()
    } else if lower.ends_with(".md") {
        "text/markdown".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
