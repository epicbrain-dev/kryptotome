use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Standard file extension for publisher revocation lists
pub const REVOCATION_LIST_FILE_EXTENSION: &str = ".kryptotome-revocations.json";

/// Format identifier for the publisher revocation list schema
pub const REVOCATION_LIST_FORMAT: &str = "kryptotome-revocation-list-v1";

/// Status of a credential revocation check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum RevocationStatus {
    Active,
    Revoked {
        revoked_at: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl RevocationStatus {
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// An individual entry indicating a revoked credential
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationEntry {
    pub credential_id: String,
    pub revoked_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RevocationEntry {
    pub fn new(credential_id: impl Into<String>, reason: Option<&str>) -> Self {
        Self {
            credential_id: credential_id.into(),
            revoked_at: Utc::now(),
            reason: reason.map(|s| s.to_string()),
        }
    }

    pub fn with_timestamp(
        credential_id: impl Into<String>,
        revoked_at: DateTime<Utc>,
        reason: Option<&str>,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            revoked_at,
            reason: reason.map(|s| s.to_string()),
        }
    }

    /// Computes canonical leaf hash for the credential ID using BLAKE3
    pub fn leaf_hash(&self) -> [u8; 32] {
        compute_leaf_hash(&self.credential_id)
    }
}

/// Canonical leaf hash function for credential IDs in Merkle trees
pub fn compute_leaf_hash(credential_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kryptotome:revocation:leaf:");
    hasher.update(credential_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Step direction in a Merkle inclusion proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MerkleDirection {
    Left,
    Right,
}

/// Single step along the Merkle authentication path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProofStep {
    pub direction: MerkleDirection,
    pub hash_hex: String,
}

/// Cryptographic Merkle inclusion proof proving a credential ID is present in a Merkle tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProof {
    pub credential_id: String,
    pub leaf_hash_hex: String,
    pub lemma: Vec<MerkleProofStep>,
    pub root_hex: String,
}

impl MerkleProof {
    /// Verifies this inclusion proof against a specified 32-byte Merkle root
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let leaf_bytes = match hex_decode(&self.leaf_hash_hex) {
            Ok(h) if h.len() == 32 => h,
            _ => return false,
        };

        let mut current_hash = [0u8; 32];
        current_hash.copy_from_slice(&leaf_bytes);

        // Verify leaf hash matches the claimed credential ID
        if current_hash != compute_leaf_hash(&self.credential_id) {
            return false;
        }

        for step in &self.lemma {
            let sibling_bytes = match hex_decode(&step.hash_hex) {
                Ok(h) if h.len() == 32 => h,
                _ => return false,
            };

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"kryptotome:revocation:node:");
            match step.direction {
                MerkleDirection::Left => {
                    hasher.update(&sibling_bytes);
                    hasher.update(&current_hash);
                }
                MerkleDirection::Right => {
                    hasher.update(&current_hash);
                    hasher.update(&sibling_bytes);
                }
            }
            current_hash = *hasher.finalize().as_bytes();
        }

        &current_hash == expected_root
    }

    /// Verifies this inclusion proof against a hex-encoded Merkle root string
    pub fn verify_hex(&self, expected_root_hex: &str) -> bool {
        match hex_decode(expected_root_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                self.verify(&arr)
            }
            _ => false,
        }
    }
}

/// Binary Merkle tree over revoked credential entries
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleRevocationTree {
    /// Leaves of the tree in deterministic order (leaf_hash, credential_id)
    leaves: Vec<([u8; 32], String)>,
    /// Levels of the tree from leaves up to root
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleRevocationTree {
    /// Builds a Merkle tree from a slice of revoked entries
    pub fn from_entries(entries: &[RevocationEntry]) -> Self {
        let mut sorted_entries = entries.to_vec();
        sorted_entries.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
        sorted_entries.dedup_by(|a, b| a.credential_id == b.credential_id);

        let leaves: Vec<([u8; 32], String)> = sorted_entries
            .into_iter()
            .map(|e| (compute_leaf_hash(&e.credential_id), e.credential_id))
            .collect();

        if leaves.is_empty() {
            return Self {
                leaves: Vec::new(),
                levels: vec![vec![[0u8; 32]]],
            };
        }

        let mut levels = Vec::new();
        let mut current_level: Vec<[u8; 32]> = leaves.iter().map(|(h, _)| *h).collect();
        levels.push(current_level.clone());

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"kryptotome:revocation:node:");
                hasher.update(&left);
                hasher.update(&right);
                next_level.push(*hasher.finalize().as_bytes());
            }
            current_level = next_level;
            levels.push(current_level.clone());
        }

        Self { leaves, levels }
    }

    /// Returns the 32-byte root hash of the Merkle tree
    pub fn root_hash(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|lvl| lvl.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Returns the root hash as a hex string
    pub fn root_hex(&self) -> String {
        hex_encode(&self.root_hash())
    }

    /// Generates a Merkle inclusion proof for a given credential ID if present
    pub fn generate_proof(&self, credential_id: &str) -> Option<MerkleProof> {
        let leaf_idx = self.leaves.iter().position(|(_, id)| id == credential_id)?;
        let leaf_hash = self.leaves[leaf_idx].0;

        let mut lemma = Vec::new();
        let mut idx = leaf_idx;

        for level_idx in 0..self.levels.len() - 1 {
            let current_level = &self.levels[level_idx];
            let is_right_child = idx % 2 == 1;
            let sibling_idx = if is_right_child {
                idx - 1
            } else if idx + 1 < current_level.len() {
                idx + 1
            } else {
                idx
            };

            let sibling_hash = current_level[sibling_idx];
            lemma.push(MerkleProofStep {
                direction: if is_right_child {
                    MerkleDirection::Left
                } else {
                    MerkleDirection::Right
                },
                hash_hex: hex_encode(&sibling_hash),
            });

            idx /= 2;
        }

        Some(MerkleProof {
            credential_id: credential_id.to_string(),
            leaf_hash_hex: hex_encode(&leaf_hash),
            lemma,
            root_hex: self.root_hex(),
        })
    }

    /// Checks if a credential ID is present in the tree
    pub fn contains(&self, credential_id: &str) -> bool {
        self.leaves.iter().any(|(_, id)| id == credential_id)
    }

    /// Total count of leaves in tree
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

/// Static publisher revocation list containing revoked credential entries,
/// a cryptographically verifiable Merkle tree accumulator root, and digital signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublisherRevocationList {
    /// Format identifier (e.g. "kryptotome-revocation-list-v1")
    pub format: String,
    /// Schema format version
    pub version: u32,
    /// Public DID / URI of the issuing publisher
    pub issuer_id: String,
    /// Timestamp when this revocation list was generated
    pub issued_at: DateTime<Utc>,
    /// Cryptographic 32-byte Merkle root accumulator of all revoked credentials in hex
    pub merkle_root_hex: String,
    /// Ordered list of revoked credential entries
    pub revoked_credentials: Vec<RevocationEntry>,
    /// Optional Ed25519 digital signature in hex verifying authenticity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
}

impl PublisherRevocationList {
    /// Creates an empty publisher revocation list
    pub fn new(issuer_id: impl Into<String>) -> Self {
        let issuer = issuer_id.into();
        let tree = MerkleRevocationTree::from_entries(&[]);
        Self {
            format: REVOCATION_LIST_FORMAT.to_string(),
            version: 1,
            issuer_id: issuer,
            issued_at: Utc::now(),
            merkle_root_hex: tree.root_hex(),
            revoked_credentials: Vec::new(),
            signature_hex: None,
        }
    }

    /// Creates a revocation list from an existing set of entries
    pub fn from_entries(issuer_id: impl Into<String>, entries: Vec<RevocationEntry>) -> Self {
        let tree = MerkleRevocationTree::from_entries(&entries);
        Self {
            format: REVOCATION_LIST_FORMAT.to_string(),
            version: 1,
            issuer_id: issuer_id.into(),
            issued_at: Utc::now(),
            merkle_root_hex: tree.root_hex(),
            revoked_credentials: entries,
            signature_hex: None,
        }
    }

    /// Adds a revoked credential to the list and recomputes the Merkle root
    pub fn add_revocation(&mut self, credential_id: &str, reason: Option<&str>) {
        if let Some(existing) = self
            .revoked_credentials
            .iter_mut()
            .find(|e| e.credential_id == credential_id)
        {
            existing.reason = reason.map(|s| s.to_string());
            existing.revoked_at = Utc::now();
        } else {
            self.revoked_credentials
                .push(RevocationEntry::new(credential_id, reason));
        }
        self.recompute_merkle_root();
        self.signature_hex = None; // Invalidate signature on change
    }

    /// Recomputes the Merkle accumulator root from current entries
    pub fn recompute_merkle_root(&mut self) {
        let tree = MerkleRevocationTree::from_entries(&self.revoked_credentials);
        self.merkle_root_hex = tree.root_hex();
    }

    /// Builds the internal Merkle tree for proofs and audits
    pub fn to_merkle_tree(&self) -> MerkleRevocationTree {
        MerkleRevocationTree::from_entries(&self.revoked_credentials)
    }

    /// Checks if the list's declared Merkle root matches its contents
    pub fn verify_merkle_root(&self) -> bool {
        let tree = self.to_merkle_tree();
        tree.root_hex() == self.merkle_root_hex
    }

    /// Canonical payload used for digital signature generation and verification
    pub fn canonical_signing_payload(&self) -> String {
        format!(
            "kryptotome:revocation-list:{}:{}:{}:{}",
            self.issuer_id,
            self.issued_at.to_rfc3339(),
            self.merkle_root_hex,
            self.revoked_credentials.len()
        )
    }

    /// Signs the revocation list using a publisher Ed25519 signing key
    pub fn sign(&mut self, signing_key: &SigningKey) {
        self.recompute_merkle_root();
        let payload = self.canonical_signing_payload();
        let signature = signing_key.sign(payload.as_bytes());
        self.signature_hex = Some(hex_encode(&signature.to_bytes()));
    }

    /// Verifies the publisher signature against an Ed25519 public key hex string
    pub fn verify_signature(&self, public_key_hex: &str) -> Result<bool> {
        let sig_hex = self
            .signature_hex
            .as_ref()
            .ok_or_else(|| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: "Revocation list contains no digital signature".to_string(),
            })?;

        let clean_pub_hex = public_key_hex
            .strip_prefix("ed25519:")
            .unwrap_or(public_key_hex)
            .trim();

        let pub_bytes = hex_decode(clean_pub_hex).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Invalid publisher public key hex: {}", e),
        })?;

        if pub_bytes.len() != 32 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: format!("Expected 32-byte public key, got {}", pub_bytes.len()),
            });
        }

        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&pub_arr).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: format!("Malformed Ed25519 public key: {}", e),
            })?;

        let sig_bytes = hex_decode(sig_hex).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp203CorruptedSignature,
            message: format!("Invalid signature hex: {}", e),
        })?;

        if sig_bytes.len() != 64 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                message: format!(
                    "Expected 64-byte Ed25519 signature, got {}",
                    sig_bytes.len()
                ),
            });
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let payload = self.canonical_signing_payload();
        match verifying_key.verify(payload.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: "Revocation list signature verification failed".to_string(),
            }),
        }
    }

    /// Checks whether a credential ID is revoked
    pub fn is_credential_revoked(&self, credential_id: &str) -> bool {
        self.revoked_credentials
            .iter()
            .any(|e| e.credential_id == credential_id)
    }

    /// Returns detailed revocation status for a credential
    pub fn check_status(&self, credential_id: &str) -> RevocationStatus {
        match self
            .revoked_credentials
            .iter()
            .find(|e| e.credential_id == credential_id)
        {
            Some(entry) => RevocationStatus::Revoked {
                revoked_at: entry.revoked_at,
                reason: entry.reason.clone(),
            },
            None => RevocationStatus::Active,
        }
    }

    /// Returns revocation entry if credential is in the list
    pub fn get_entry(&self, credential_id: &str) -> Option<&RevocationEntry> {
        self.revoked_credentials
            .iter()
            .find(|e| e.credential_id == credential_id)
    }

    /// Generates a cryptographic Merkle inclusion proof for a revoked credential
    pub fn generate_merkle_proof(&self, credential_id: &str) -> Option<MerkleProof> {
        self.to_merkle_tree().generate_proof(credential_id)
    }

    /// Verifies a Merkle inclusion proof against this list's root
    pub fn verify_merkle_proof(&self, proof: &MerkleProof) -> bool {
        if proof.root_hex != self.merkle_root_hex {
            return false;
        }
        proof.verify_hex(&self.merkle_root_hex)
    }

    /// Serializes list to formatted JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(KryptotomeError::SerializationError)
    }

    /// Deserializes list from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        let list: Self = serde_json::from_str(json).map_err(KryptotomeError::SerializationError)?;
        if list.format != REVOCATION_LIST_FORMAT {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp106InvalidManifestSchema,
                message: format!("Unsupported revocation list format: {}", list.format),
            });
        }
        Ok(list)
    }

    /// Saves revocation list to a file on disk
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self.to_json()?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Loads revocation list from a file on disk
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json(&content)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp901SerializationError,
            message: "Invalid hex string length".to_string(),
        });
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp901SerializationError,
                message: format!("Invalid hex byte: {}", e),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_merkle_revocation_tree_empty() {
        let tree = MerkleRevocationTree::from_entries(&[]);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root_hash(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_revocation_tree_single_leaf() {
        let entries = vec![RevocationEntry::new("cred-123", Some("Refunded"))];
        let tree = MerkleRevocationTree::from_entries(&entries);
        assert_eq!(tree.leaf_count(), 1);
        let expected_leaf = compute_leaf_hash("cred-123");
        assert_eq!(tree.root_hash(), expected_leaf);

        let proof = tree.generate_proof("cred-123").expect("Proof should exist");
        assert!(proof.verify(&tree.root_hash()));
        assert!(tree.generate_proof("cred-nonexistent").is_none());
    }

    #[test]
    fn test_merkle_revocation_tree_multi_leaf_proof_verification() {
        let entries = vec![
            RevocationEntry::new("cred-a", Some("Compromised")),
            RevocationEntry::new("cred-b", Some("Refunded")),
            RevocationEntry::new("cred-c", Some("Superseded")),
            RevocationEntry::new("cred-d", None),
            RevocationEntry::new("cred-e", Some("Admin revocation")),
        ];

        let tree = MerkleRevocationTree::from_entries(&entries);
        assert_eq!(tree.leaf_count(), 5);

        // Every entry in the tree must produce a valid proof
        for entry in &entries {
            let proof = tree
                .generate_proof(&entry.credential_id)
                .expect("Proof must be generated");
            assert!(proof.verify(&tree.root_hash()));
            assert!(proof.verify_hex(&tree.root_hex()));
        }

        // Non-existent entry should return None
        assert!(tree.generate_proof("cred-unknown").is_none());
    }

    #[test]
    fn test_merkle_proof_tamper_detection() {
        let entries = vec![
            RevocationEntry::new("cred-1", None),
            RevocationEntry::new("cred-2", None),
        ];
        let tree = MerkleRevocationTree::from_entries(&entries);
        let mut proof = tree.generate_proof("cred-1").unwrap();

        // 1. Genuine proof passes
        assert!(proof.verify(&tree.root_hash()));

        // 2. Tampering with credential ID fails verification
        proof.credential_id = "cred-tampered".to_string();
        assert!(!proof.verify(&tree.root_hash()));

        // 3. Tampering with root fails verification
        proof.credential_id = "cred-1".to_string();
        let mut bogus_root = tree.root_hash();
        bogus_root[0] ^= 0xff;
        assert!(!proof.verify(&bogus_root));
    }

    #[test]
    fn test_publisher_revocation_list_signing_and_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_hex = hex_encode(signing_key.verifying_key().as_bytes());

        let mut list = PublisherRevocationList::new("did:key:zPublisher999");
        list.add_revocation("cred-revoked-1", Some("Key compromise"));
        list.add_revocation("cred-revoked-2", Some("Chargeback"));

        assert_eq!(list.revoked_credentials.len(), 2);
        assert!(list.is_credential_revoked("cred-revoked-1"));
        assert!(list.is_credential_revoked("cred-revoked-2"));
        assert!(!list.is_credential_revoked("cred-active-3"));

        assert_eq!(list.check_status("cred-active-3"), RevocationStatus::Active);
        match list.check_status("cred-revoked-1") {
            RevocationStatus::Revoked { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("Key compromise"));
            }
            _ => panic!("Expected Revoked status"),
        }

        // Sign the list
        list.sign(&signing_key);
        assert!(list.signature_hex.is_some());

        // Verify signature passes
        assert!(list.verify_signature(&pub_hex).unwrap());
        assert!(list.verify_merkle_root());

        // Proof generation from list
        let proof = list
            .generate_merkle_proof("cred-revoked-1")
            .expect("Proof must exist");
        assert!(list.verify_merkle_proof(&proof));

        // Tamper with list entries invalidates signature
        list.revoked_credentials
            .push(RevocationEntry::new("cred-tampered", None));
        assert!(list.verify_signature(&pub_hex).is_err());
    }

    #[test]
    fn test_revocation_list_json_and_file_roundtrip() {
        let mut list = PublisherRevocationList::new("did:key:zPublisherFile");
        list.add_revocation("cred-file-1", Some("Superseded"));

        let json = list.to_json().expect("JSON serialization failed");
        let restored =
            PublisherRevocationList::from_json(&json).expect("JSON deserialization failed");
        assert_eq!(list, restored);

        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!(
            "test_revocations_{}{}",
            Utc::now().timestamp_nanos_opt().unwrap_or(0),
            REVOCATION_LIST_FILE_EXTENSION
        ));
        list.save_to_file(&path).expect("File save failed");

        let file_restored =
            PublisherRevocationList::load_from_file(&path).expect("File load failed");
        assert_eq!(list, file_restored);

        let _ = fs::remove_file(&path);
    }
}
