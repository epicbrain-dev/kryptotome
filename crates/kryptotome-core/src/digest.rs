use crate::error::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentDigest {
    pub algorithm: String,
    pub hex_digest: String,
}

impl ContentDigest {
    pub fn new_sha256(hex_digest: String) -> Self {
        Self {
            algorithm: "SHA-256".to_string(),
            hex_digest,
        }
    }
}

/// Computes SHA-256 digest of a single file
pub fn compute_file_digest<P: AsRef<Path>>(path: P) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let result = hasher.finalize();
    Ok(hex_encode(&result))
}

/// Computes deterministic root digest of an open-gaming directory schema
pub fn compute_directory_digest<P: AsRef<Path>>(dir_path: P) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut entries = Vec::new();

    if dir_path.as_ref().is_dir() {
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let filename = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
                let digest = compute_file_digest(&path)?;
                entries.push((filename, digest));
            }
        }
    }

    // Sort entries deterministically by filename
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, digest) in entries {
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }

    let root_result = hasher.finalize();
    Ok(hex_encode(&root_result))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
