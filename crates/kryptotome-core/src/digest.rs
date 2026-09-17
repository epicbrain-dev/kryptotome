use crate::error::{KryptotomeError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

/// Supported cryptographic digest algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum DigestAlgorithm {
    #[default]
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "BLAKE3")]
    Blake3,
}

impl DigestAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Blake3 => "BLAKE3",
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for DigestAlgorithm {
    type Err = KryptotomeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "SHA-256" | "SHA256" => Ok(Self::Sha256),
            "BLAKE3" | "B3" => Ok(Self::Blake3),
            _ => Err(KryptotomeError::Detailed {
                code: crate::error::KryptotomeErrorCode::Kryp503UnsupportedDigestAlgorithm,
                message: format!(
                    "Unsupported digest algorithm: '{}'. Expected 'SHA-256' or 'BLAKE3'",
                    s
                ),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContentDigest {
    pub algorithm: DigestAlgorithm,
    pub hex_digest: String,
}

impl ContentDigest {
    pub fn new(algorithm: DigestAlgorithm, hex_digest: String) -> Self {
        Self {
            algorithm,
            hex_digest,
        }
    }

    pub fn new_sha256(hex_digest: String) -> Self {
        Self::new(DigestAlgorithm::Sha256, hex_digest)
    }

    pub fn new_blake3(hex_digest: String) -> Self {
        Self::new(DigestAlgorithm::Blake3, hex_digest)
    }
}

/// Computes file digest with chosen algorithm (SHA-256 or BLAKE3) with a byte progress callback.
/// The callback is invoked with the number of bytes read in each chunk.
pub fn compute_file_digest_with_progress<P: AsRef<Path>, F: FnMut(u64)>(
    path: P,
    algorithm: DigestAlgorithm,
    mut on_bytes: F,
) -> Result<String> {
    const BUFFER_SIZE: usize = 131072; // 128 KB buffer for high I/O throughput on multi-gigabyte files
    let mut file = File::open(path)?;
    let mut buffer = [0u8; BUFFER_SIZE];

    match algorithm {
        DigestAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                on_bytes(count as u64);
            }
            let result = hasher.finalize();
            Ok(hex_encode(&result))
        }
        DigestAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                on_bytes(count as u64);
            }
            let result = hasher.finalize();
            Ok(result.to_hex().to_string())
        }
    }
}

/// Computes file digest with chosen algorithm (SHA-256 or BLAKE3)
pub fn compute_file_digest_with_algorithm<P: AsRef<Path>>(
    path: P,
    algorithm: DigestAlgorithm,
) -> Result<String> {
    compute_file_digest_with_progress(path, algorithm, |_| {})
}

/// Computes SHA-256 digest of a single file (default)
pub fn compute_file_digest<P: AsRef<Path>>(path: P) -> Result<String> {
    compute_file_digest_with_algorithm(path, DigestAlgorithm::Sha256)
}

/// Computes BLAKE3 digest of a single file for high-throughput compendium processing
pub fn compute_file_digest_blake3<P: AsRef<Path>>(path: P) -> Result<String> {
    compute_file_digest_with_algorithm(path, DigestAlgorithm::Blake3)
}

/// Computes BLAKE3 digest of a single file with a streaming chunk progress callback
pub fn compute_file_digest_blake3_with_progress<P: AsRef<Path>, F: FnMut(u64)>(
    path: P,
    on_bytes: F,
) -> Result<String> {
    compute_file_digest_with_progress(path, DigestAlgorithm::Blake3, on_bytes)
}

/// Computes deterministic root digest of a directory schema with specified algorithm
pub fn compute_directory_digest_with_algorithm<P: AsRef<Path>>(
    dir_path: P,
    algorithm: DigestAlgorithm,
) -> Result<String> {
    let mut entries = Vec::new();

    if dir_path.as_ref().is_dir() {
        collect_dir_entries_recursive(
            dir_path.as_ref(),
            dir_path.as_ref(),
            algorithm,
            &mut entries,
        )?;
    }

    // Sort entries deterministically by relative path
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    match algorithm {
        DigestAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            for (rel_path, digest) in entries {
                hasher.update(rel_path.as_bytes());
                hasher.update(b":");
                hasher.update(digest.as_bytes());
                hasher.update(b"\n");
            }
            let root_result = hasher.finalize();
            Ok(hex_encode(&root_result))
        }
        DigestAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            for (rel_path, digest) in entries {
                hasher.update(rel_path.as_bytes());
                hasher.update(b":");
                hasher.update(digest.as_bytes());
                hasher.update(b"\n");
            }
            let root_result = hasher.finalize();
            Ok(root_result.to_hex().to_string())
        }
    }
}

/// Recursively collect file paths and digests relative to base directory
fn collect_dir_entries_recursive(
    current_dir: &Path,
    base_dir: &Path,
    algorithm: DigestAlgorithm,
    entries: &mut Vec<(String, String)>,
) -> Result<()> {
    for entry in std::fs::read_dir(current_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let rel_path = path
                .strip_prefix(base_dir)
                .map_err(std::io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            let digest = compute_file_digest_with_algorithm(&path, algorithm)?;
            entries.push((rel_path, digest));
        } else if path.is_dir() {
            collect_dir_entries_recursive(&path, base_dir, algorithm, entries)?;
        }
    }
    Ok(())
}

/// Computes deterministic root digest of an open-gaming directory schema using SHA-256
pub fn compute_directory_digest<P: AsRef<Path>>(dir_path: P) -> Result<String> {
    compute_directory_digest_with_algorithm(dir_path, DigestAlgorithm::Sha256)
}

/// Computes deterministic root digest of an open-gaming directory schema using BLAKE3
pub fn compute_directory_digest_blake3<P: AsRef<Path>>(dir_path: P) -> Result<String> {
    compute_directory_digest_with_algorithm(dir_path, DigestAlgorithm::Blake3)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_digest_algorithm_parsing() {
        assert_eq!(
            DigestAlgorithm::from_str("SHA-256").unwrap(),
            DigestAlgorithm::Sha256
        );
        assert_eq!(
            DigestAlgorithm::from_str("sha256").unwrap(),
            DigestAlgorithm::Sha256
        );
        assert_eq!(
            DigestAlgorithm::from_str("BLAKE3").unwrap(),
            DigestAlgorithm::Blake3
        );
        assert_eq!(
            DigestAlgorithm::from_str("b3").unwrap(),
            DigestAlgorithm::Blake3
        );
        assert!(DigestAlgorithm::from_str("MD5").is_err());
    }

    #[test]
    fn test_blake3_file_and_directory_digest() {
        let temp_dir =
            std::env::temp_dir().join(format!("ktome_test_b3_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let file_a = temp_dir.join("rules_a.json");
        let mut fa = File::create(&file_a).unwrap();
        fa.write_all(b"{\"rule\": \"stealth\"}").unwrap();

        let file_b = temp_dir.join("rules_b.json");
        let mut fb = File::create(&file_b).unwrap();
        fb.write_all(b"{\"rule\": \"perception\"}").unwrap();

        // 1. Check BLAKE3 file digests
        let b3_a = compute_file_digest_blake3(&file_a).unwrap();
        let b3_b = compute_file_digest_blake3(&file_b).unwrap();
        assert_eq!(b3_a.len(), 64);
        assert_eq!(b3_b.len(), 64);
        assert_ne!(b3_a, b3_b);

        // 2. Check BLAKE3 directory digest is deterministic
        let root_1 = compute_directory_digest_blake3(&temp_dir).unwrap();
        let root_2 = compute_directory_digest_blake3(&temp_dir).unwrap();
        assert_eq!(root_1, root_2);
        assert_eq!(root_1.len(), 64);

        // 3. Compare with SHA-256 directory digest (should be different hash)
        let root_sha = compute_directory_digest(&temp_dir).unwrap();
        assert_ne!(root_1, root_sha);

        // Cleanup
        std::fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_compute_file_digest_with_progress() {
        let temp_dir =
            std::env::temp_dir().join(format!("ktome_test_prog_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let test_file = temp_dir.join("large_sample.bin");

        // Write 300KB of test data (exceeding 128KB chunk boundary)
        let sample_data = vec![0x42u8; 300 * 1024];
        std::fs::write(&test_file, &sample_data).unwrap();

        let mut sha256_bytes_seen = 0u64;
        let sha256_digest =
            compute_file_digest_with_progress(&test_file, DigestAlgorithm::Sha256, |chunk_len| {
                sha256_bytes_seen += chunk_len
            })
            .unwrap();
        assert_eq!(sha256_bytes_seen, 300 * 1024);
        assert_eq!(sha256_digest, compute_file_digest(&test_file).unwrap());

        let mut b3_bytes_seen = 0u64;
        let b3_digest = compute_file_digest_blake3_with_progress(&test_file, |chunk_len| {
            b3_bytes_seen += chunk_len
        })
        .unwrap();
        assert_eq!(b3_bytes_seen, 300 * 1024);
        assert_eq!(b3_digest, compute_file_digest_blake3(&test_file).unwrap());

        std::fs::remove_dir_all(temp_dir).unwrap();
    }
}
