use crate::keyring::{Keyring, KeyringBackupData};
use crate::keystore::{EncryptionCipher, KdfParams};
use crate::revocation::{PublisherRevocationList, RevocationStatus};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use chrono::Utc;
use kryptotome_core::{
    credential::KryptotomeCredential,
    error::{KryptotomeError, KryptotomeErrorCode, Result},
    zkp::{ChallengeNonce, ProofInputs, ZkProof},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// Standard file extension for encrypted Kryptotome credential vault backups
pub const BACKUP_FILE_EXTENSION: &str = ".kryptotome-vault.enc";

/// Format identifier for backup envelope schema
pub const BACKUP_FORMAT_IDENTIFIER: &str = "kryptotome-vault-backup-v1";

/// In-memory credential store indexing credentials by ID
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct VaultStore {
    pub credentials: HashMap<String, KryptotomeCredential>,
}

/// Legacy / simple encrypted vault file metadata container
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVaultFile {
    pub version: String,
    pub key_id: String,
    pub credentials_count: usize,
    pub payload_json: String,
}

/// Secure authenticated credential vault backup envelope (.kryptotome-vault.enc)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedVaultBackup {
    /// Format identifier (e.g. "kryptotome-vault-backup-v1")
    pub format: String,
    /// Schema format version
    pub version: u32,
    /// Timestamp when backup was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Public DID / Key ID of the custody keyring included in backup, if any
    pub vault_key_id: Option<String>,
    /// Number of credentials stored in the encrypted payload
    pub credential_count: usize,
    /// Symmetric cipher used for authenticated encryption
    pub cipher: EncryptionCipher,
    /// Argon2id key derivation parameters
    pub kdf: KdfParams,
    /// 12-byte (96-bit) AEAD initialization vector / nonce in hex
    pub nonce_hex: String,
    /// Encrypted ciphertext with appended 16-byte authentication tag in hex
    pub ciphertext_hex: String,
}

/// Plaintext decrypted payload contents of a vault backup
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultBackupPayload {
    /// Schema format version
    pub version: u32,
    /// Timestamp when backup was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Optional custody keyring secret material
    pub keyring: Option<KeyringBackupData>,
    /// All credentials stored in the vault
    pub credentials: Vec<KryptotomeCredential>,
}

impl VaultBackupPayload {
    /// Unpacks the backup payload into a `VaultStore` and optional `Keyring`
    pub fn to_store_and_keyring(&self) -> Result<(VaultStore, Option<Keyring>)> {
        let mut store = VaultStore::new();
        for cred in &self.credentials {
            store.insert_credential(cred.clone());
        }

        let keyring = match &self.keyring {
            Some(data) => Some(Keyring::from_backup_data(data).map_err(|e| {
                KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                    message: format!("Failed to restore keyring from backup data: {}", e),
                }
            })?),
            None => None,
        };

        Ok((store, keyring))
    }
}

impl EncryptedVaultBackup {
    /// Serializes backup envelope to formatted JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp901SerializationError,
            message: format!("Failed to serialize encrypted backup to JSON: {}", e),
        })
    }

    /// Deserializes backup envelope from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp901SerializationError,
            message: format!("Failed to deserialize encrypted backup from JSON: {}", e),
        })
    }

    /// Saves encrypted backup envelope directly to a file on disk
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self.to_json()?;
        fs::write(path, json).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp902IoError,
            message: format!("Failed to write encrypted vault backup file: {}", e),
        })
    }

    /// Loads encrypted backup envelope from a file on disk
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp902IoError,
            message: format!("Failed to read encrypted vault backup file: {}", e),
        })?;
        Self::from_json(&content)
    }

    /// Decrypts the backup envelope with a passphrase, recovering the plaintext payload
    pub fn decrypt(&self, passphrase: &str) -> Result<VaultBackupPayload> {
        if self.format != BACKUP_FORMAT_IDENTIFIER {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
                message: format!("Unsupported backup format identifier: {}", self.format),
            });
        }

        let nonce_bytes = hex_decode(&self.nonce_hex)?;
        let ciphertext = hex_decode(&self.ciphertext_hex)?;

        if nonce_bytes.len() != 12 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
                message: "Invalid AEAD nonce length, expected 12 bytes".to_string(),
            });
        }

        let mut derived_key = self.kdf.derive_key(passphrase)?;

        let mut decrypted_bytes = match self.cipher {
            EncryptionCipher::Aes256Gcm => {
                let cipher_engine = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| {
                    KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                        message: format!("Invalid AES key: {}", e),
                    }
                })?;
                let nonce = AesNonce::from_slice(&nonce_bytes);
                cipher_engine.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
                    KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
                        message: "Invalid passphrase or corrupted AES-256-GCM vault backup".to_string(),
                    }
                })?
            }
            EncryptionCipher::ChaCha20Poly1305 => {
                let cipher_engine = ChaCha20Poly1305::new_from_slice(&derived_key).map_err(|e| {
                    KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                        message: format!("Invalid ChaCha20 key: {}", e),
                    }
                })?;
                let nonce = ChaChaNonce::from_slice(&nonce_bytes);
                cipher_engine.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
                    KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
                        message: "Invalid passphrase or corrupted ChaCha20-Poly1305 vault backup".to_string(),
                    }
                })?
            }
        };

        derived_key.zeroize();

        let payload_res = serde_json::from_slice::<VaultBackupPayload>(&decrypted_bytes).map_err(|e| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
                message: format!("Failed to deserialize decrypted backup payload: {}", e),
            }
        });

        decrypted_bytes.zeroize();
        payload_res
    }
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    pub fn insert_credential(&mut self, credential: KryptotomeCredential) {
        self.credentials.insert(credential.id.clone(), credential);
    }

    pub fn get_credential(&self, credential_id: &str) -> Option<&KryptotomeCredential> {
        self.credentials.get(credential_id)
    }

    pub fn find_for_package(&self, package_id: &str) -> Option<&KryptotomeCredential> {
        self.credentials
            .values()
            .find(|c| c.has_entitlement(package_id))
    }

    pub fn export_to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(KryptotomeError::SerializationError)
    }

    pub fn import_from_json(json_str: &str) -> Result<Self> {
        serde_json::from_str(json_str).map_err(KryptotomeError::SerializationError)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = self.export_to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::import_from_json(&content)
    }

    /// Exports vault credentials and optional custody keyring to an encrypted backup
    /// using standard recommended Argon2id parameters.
    pub fn export_backup(
        &self,
        keyring: Option<&Keyring>,
        passphrase: &str,
        cipher: EncryptionCipher,
    ) -> Result<EncryptedVaultBackup> {
        self.export_backup_with_params(keyring, passphrase, cipher, KdfParams::recommended())
    }

    /// Exports vault credentials and optional custody keyring using explicit KDF parameters
    pub fn export_backup_with_params(
        &self,
        keyring: Option<&Keyring>,
        passphrase: &str,
        cipher: EncryptionCipher,
        kdf: KdfParams,
    ) -> Result<EncryptedVaultBackup> {
        let credentials: Vec<KryptotomeCredential> = self.credentials.values().cloned().collect();
        let keyring_data = keyring.map(|k| k.to_backup_data());
        let payload = VaultBackupPayload {
            version: 1,
            created_at: Utc::now(),
            keyring: keyring_data,
            credentials,
        };

        let mut payload_bytes = serde_json::to_vec(&payload)
            .map_err(KryptotomeError::SerializationError)?;
        let mut derived_key = kdf.derive_key(passphrase)?;

        let (nonce_bytes, ciphertext_bytes) = match cipher {
            EncryptionCipher::Aes256Gcm => {
                let cipher_engine = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| {
                    KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                        message: format!("Invalid AES key: {}", e),
                    }
                })?;
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let ct = cipher_engine
                    .encrypt(&nonce, payload_bytes.as_slice())
                    .map_err(|e| KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                        message: format!("AES-256-GCM encryption failed: {}", e),
                    })?;
                (nonce.to_vec(), ct)
            }
            EncryptionCipher::ChaCha20Poly1305 => {
                let cipher_engine = ChaCha20Poly1305::new_from_slice(&derived_key).map_err(|e| {
                    KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                        message: format!("Invalid ChaCha20 key: {}", e),
                    }
                })?;
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                let ct = cipher_engine
                    .encrypt(&nonce, payload_bytes.as_slice())
                    .map_err(|e| KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                        message: format!("ChaCha20-Poly1305 encryption failed: {}", e),
                    })?;
                (nonce.to_vec(), ct)
            }
        };

        derived_key.zeroize();
        payload_bytes.zeroize();

        Ok(EncryptedVaultBackup {
            format: BACKUP_FORMAT_IDENTIFIER.to_string(),
            version: 1,
            created_at: payload.created_at,
            vault_key_id: keyring.map(|k| k.key_id.clone()),
            credential_count: payload.credentials.len(),
            cipher,
            kdf,
            nonce_hex: hex_encode(&nonce_bytes),
            ciphertext_hex: hex_encode(&ciphertext_bytes),
        })
    }

    /// Saves encrypted backup directly to a file (.kryptotome-vault.enc)
    pub fn save_backup_file(
        &self,
        keyring: Option<&Keyring>,
        passphrase: &str,
        cipher: EncryptionCipher,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let backup = self.export_backup(keyring, passphrase, cipher)?;
        backup.save_to_file(path)
    }

    /// Saves encrypted backup directly to a file with custom KDF parameters
    pub fn save_backup_file_with_params(
        &self,
        keyring: Option<&Keyring>,
        passphrase: &str,
        cipher: EncryptionCipher,
        kdf: KdfParams,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let backup = self.export_backup_with_params(keyring, passphrase, cipher, kdf)?;
        backup.save_to_file(path)
    }

    /// Restores a new `VaultStore` and optional `Keyring` from an `EncryptedVaultBackup`
    pub fn restore_from_backup(
        backup: &EncryptedVaultBackup,
        passphrase: &str,
    ) -> Result<(VaultStore, Option<Keyring>)> {
        let payload = backup.decrypt(passphrase)?;
        payload.to_store_and_keyring()
    }

    /// Restores a new `VaultStore` and optional `Keyring` from an encrypted backup file on disk
    pub fn restore_from_backup_file(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<(VaultStore, Option<Keyring>)> {
        let backup = EncryptedVaultBackup::load_from_file(path)?;
        Self::restore_from_backup(&backup, passphrase)
    }

    /// Restores and merges credentials from a backup into this `VaultStore`, returning restored `Keyring` if present
    pub fn restore_into(
        &mut self,
        backup: &EncryptedVaultBackup,
        passphrase: &str,
    ) -> Result<Option<Keyring>> {
        let payload = backup.decrypt(passphrase)?;
        for cred in payload.credentials {
            self.insert_credential(cred);
        }
        match payload.keyring {
            Some(data) => {
                let kr = Keyring::from_backup_data(&data).map_err(|e| KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                    message: format!("Failed to restore keyring from backup data: {}", e),
                })?;
                Ok(Some(kr))
            }
            None => Ok(None),
        }
    }

    /// Generate a single-use ZK proof for a challenge nonce using the full Arkworks Groth16 prover
    pub fn create_proof_for_challenge(
        &self,
        keyring: &Keyring,
        challenge: &ChallengeNonce,
    ) -> Result<ZkProof> {
        let (pk, _) = kryptotome_core::get_or_init_entitlement_setup();
        self.create_proof_for_challenge_with_pk(keyring, challenge, pk)
    }

    /// Generate a single-use ZK proof for a challenge nonce with an explicit Groth16 proving key
    pub fn create_proof_for_challenge_with_pk(
        &self,
        keyring: &Keyring,
        challenge: &ChallengeNonce,
        pk: &kryptotome_core::Groth16ProvingKey,
    ) -> Result<ZkProof> {
        let cred = self
            .find_for_package(&challenge.package_id)
            .ok_or_else(|| KryptotomeError::EntitlementNotFound(challenge.package_id.clone()))?;

        if challenge.is_expired() {
            return Err(KryptotomeError::InvalidChallenge(
                "Challenge nonce has expired".to_string(),
            ));
        }

        let entitlement = cred
            .credential_subject
            .entitlements
            .iter()
            .find(|e| e.package_id == challenge.package_id)
            .ok_or_else(|| KryptotomeError::EntitlementNotFound(challenge.package_id.clone()))?;

        let mut rng = aes_gcm::aead::OsRng;
        let (proof, _public_inputs_scalars) = kryptotome_core::prove_entitlement_for_credential(
            pk,
            keyring.secret_bytes(),
            challenge,
            entitlement,
            &cred.issuer.public_key,
            &cred.credential_subject.holder_commitment,
            &mut rng,
        )?;

        let proof_bytes = kryptotome_core::serialize_proof_compressed(&proof)?;

        let public_inputs = ProofInputs {
            challenge_nonce: challenge.nonce.clone(),
            package_id: challenge.package_id.clone(),
            content_digest: entitlement.content_digest.clone(),
            publisher_pubkey_hash: cred.issuer.public_key.clone(),
            holder_commitment: Some(cred.credential_subject.holder_commitment.clone()),
        };

        Ok(ZkProof {
            proof_bytes,
            public_inputs,
        })
    }

    /// Generates a self-contained EntitlementProofBundle containing the Groth16 proof and public inputs
    pub fn create_proof_bundle_for_challenge(
        &self,
        keyring: &Keyring,
        challenge: &ChallengeNonce,
    ) -> Result<kryptotome_core::EntitlementProofBundle> {
        let (pk, _) = kryptotome_core::get_or_init_entitlement_setup();
        let cred = self
            .find_for_package(&challenge.package_id)
            .ok_or_else(|| KryptotomeError::EntitlementNotFound(challenge.package_id.clone()))?;

        if challenge.is_expired() {
            return Err(KryptotomeError::InvalidChallenge(
                "Challenge nonce has expired".to_string(),
            ));
        }

        let entitlement = cred
            .credential_subject
            .entitlements
            .iter()
            .find(|e| e.package_id == challenge.package_id)
            .ok_or_else(|| KryptotomeError::EntitlementNotFound(challenge.package_id.clone()))?;

        let mut rng = aes_gcm::aead::OsRng;
        let (proof, public_inputs_scalars) = kryptotome_core::prove_entitlement_for_credential(
            pk,
            keyring.secret_bytes(),
            challenge,
            entitlement,
            &cred.issuer.public_key,
            &cred.credential_subject.holder_commitment,
            &mut rng,
        )?;

        kryptotome_core::EntitlementProofBundle::new(
            &proof,
            &public_inputs_scalars,
            &entitlement.package_id,
            &entitlement.content_digest,
            &challenge.nonce,
            &cred.credential_subject.holder_commitment,
        )
    }

    /// Checks the revocation status of a credential against a publisher revocation list
    pub fn check_credential_revocation(
        &self,
        credential_id: &str,
        revocation_list: &PublisherRevocationList,
    ) -> RevocationStatus {
        revocation_list.check_status(credential_id)
    }

    /// Checks if a credential stored in the vault has been revoked
    pub fn is_credential_revoked(
        &self,
        credential_id: &str,
        revocation_list: &PublisherRevocationList,
    ) -> bool {
        revocation_list.is_credential_revoked(credential_id)
    }

    /// Lists all credential IDs currently in the vault that are marked revoked in the revocation list
    pub fn list_revoked_credentials(
        &self,
        revocation_list: &PublisherRevocationList,
    ) -> Vec<String> {
        self.credentials
            .keys()
            .filter(|id| revocation_list.is_credential_revoked(id))
            .cloned()
            .collect()
    }

    /// Purges all credentials from the vault that are marked revoked in the revocation list,
    /// returning the list of revoked credential IDs that were removed.
    pub fn purge_revoked_credentials(
        &mut self,
        revocation_list: &PublisherRevocationList,
    ) -> Vec<String> {
        let revoked_ids = self.list_revoked_credentials(revocation_list);
        for id in &revoked_ids {
            self.credentials.remove(id);
        }
        revoked_ids
    }

    /// Validates that a credential exists in the vault and is not revoked,
    /// returning a reference to the credential or an error.
    pub fn validate_credential_with_revocation<'a>(
        &'a self,
        credential_id: &str,
        revocation_list: &PublisherRevocationList,
    ) -> Result<&'a KryptotomeCredential> {
        let cred = self.get_credential(credential_id).ok_or_else(|| {
            KryptotomeError::EntitlementNotFound(credential_id.to_string())
        })?;

        match revocation_list.check_status(credential_id) {
            RevocationStatus::Active => Ok(cred),
            RevocationStatus::Revoked { revoked_at, reason } => {
                Err(KryptotomeError::CredentialRevoked(format!(
                    "Credential {} was revoked at {} (reason: {:?})",
                    credential_id, revoked_at, reason
                )))
            }
        }
    }

    /// Creates a single-use ZK proof for a challenge nonce, verifying the credential is not revoked
    pub fn create_proof_for_challenge_with_revocation(
        &self,
        keyring: &Keyring,
        challenge: &ChallengeNonce,
        revocation_list: &PublisherRevocationList,
    ) -> Result<ZkProof> {
        let cred = self
            .find_for_package(&challenge.package_id)
            .ok_or_else(|| KryptotomeError::EntitlementNotFound(challenge.package_id.clone()))?;

        if let RevocationStatus::Revoked { revoked_at, reason } =
            revocation_list.check_status(&cred.id)
        {
            return Err(KryptotomeError::CredentialRevoked(format!(
                "Credential {} for package {} was revoked at {} (reason: {:?})",
                cred.id, challenge.package_id, revoked_at, reason
            )));
        }

        self.create_proof_for_challenge(keyring, challenge)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
            message: "Invalid hex string length in encrypted backup".to_string(),
        });
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
                message: format!("Invalid hex byte in encrypted backup: {}", e),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryptotome_core::credential::{Entitlement, Issuer, KryptotomeCredential};
    use rand::RngCore;

    fn make_sample_credential(id: &str, package_id: &str) -> KryptotomeCredential {
        let issuer = Issuer {
            id: "did:key:zPublisher123".to_string(),
            name: "Test Publisher".to_string(),
            public_key: "ed25519:abcdef0123456789".to_string(),
        };
        let entitlements = vec![Entitlement {
            package_id: package_id.to_string(),
            content_digest: "sha256:fedcba9876543210".to_string(),
            scope: vec!["full-access".to_string()],
        }];
        KryptotomeCredential::new(
            id.to_string(),
            issuer,
            "did:key:zHolderKey456".to_string(),
            "urn:kryptotome:commitment:bls12381:1234abcd".to_string(),
            entitlements,
            "proofvalue_signature_sample".to_string(),
        )
    }

    #[test]
    fn test_vault_backup_restore_aes_256_gcm() {
        let mut store = VaultStore::new();
        store.insert_credential(make_sample_credential("cred-1", "pkg.elder-scrolls"));
        store.insert_credential(make_sample_credential("cred-2", "pkg.cyberpunk-dlc"));

        let keyring = Keyring::generate();
        let passphrase = "correct-horse-battery-staple-vault";

        let backup = store
            .export_backup_with_params(
                Some(&keyring),
                passphrase,
                EncryptionCipher::Aes256Gcm,
                KdfParams::fast(),
            )
            .expect("Backup creation should succeed");

        assert_eq!(backup.format, BACKUP_FORMAT_IDENTIFIER);
        assert_eq!(backup.version, 1);
        assert_eq!(backup.cipher, EncryptionCipher::Aes256Gcm);
        assert_eq!(backup.credential_count, 2);
        assert_eq!(backup.vault_key_id.as_deref(), Some(keyring.key_id.as_str()));

        // Restore
        let (restored_store, restored_keyring) =
            VaultStore::restore_from_backup(&backup, passphrase)
                .expect("Restore should succeed");

        assert_eq!(restored_store.credentials.len(), 2);
        assert!(restored_store.get_credential("cred-1").is_some());
        assert!(restored_store.get_credential("cred-2").is_some());

        let restored_kr = restored_keyring.expect("Keyring must be restored");
        assert_eq!(restored_kr.key_id, keyring.key_id);
        assert_eq!(restored_kr.public_key_hex, keyring.public_key_hex);
        assert_eq!(restored_kr.secret_bytes(), keyring.secret_bytes());
    }

    #[test]
    fn test_vault_backup_restore_chacha20_poly1305() {
        let mut store = VaultStore::new();
        store.insert_credential(make_sample_credential("cred-alpha", "pkg.baldurs-gate-expansion"));

        let keyring = Keyring::generate();
        let passphrase = "chacha20-poly1305-super-secret-key";

        let backup = store
            .export_backup_with_params(
                Some(&keyring),
                passphrase,
                EncryptionCipher::ChaCha20Poly1305,
                KdfParams::fast(),
            )
            .expect("ChaCha20 backup should succeed");

        assert_eq!(backup.cipher, EncryptionCipher::ChaCha20Poly1305);
        assert_eq!(backup.credential_count, 1);

        let (restored_store, restored_keyring) =
            VaultStore::restore_from_backup(&backup, passphrase)
                .expect("Restore should succeed");

        assert_eq!(restored_store.credentials.len(), 1);
        assert!(restored_store.find_for_package("pkg.baldurs-gate-expansion").is_some());
        let restored_kr = restored_keyring.expect("Keyring must be present");
        assert_eq!(restored_kr.secret_bytes(), keyring.secret_bytes());
    }

    #[test]
    fn test_vault_backup_without_keyring() {
        let mut store = VaultStore::new();
        store.insert_credential(make_sample_credential("cred-anon", "pkg.indie-game"));

        let passphrase = "only-credentials-passphrase";
        let backup = store
            .export_backup_with_params(
                None,
                passphrase,
                EncryptionCipher::Aes256Gcm,
                KdfParams::fast(),
            )
            .expect("Backup without keyring should succeed");

        assert!(backup.vault_key_id.is_none());
        assert_eq!(backup.credential_count, 1);

        let (restored_store, restored_keyring) =
            VaultStore::restore_from_backup(&backup, passphrase)
                .expect("Restore should succeed");

        assert_eq!(restored_store.credentials.len(), 1);
        assert!(restored_keyring.is_none());
    }

    #[test]
    fn test_vault_backup_bad_passphrase_rejection() {
        let mut store = VaultStore::new();
        store.insert_credential(make_sample_credential("cred-1", "pkg.zelda"));

        let backup = store
            .export_backup_with_params(
                None,
                "correct-passphrase",
                EncryptionCipher::Aes256Gcm,
                KdfParams::fast(),
            )
            .unwrap();

        let err = VaultStore::restore_from_backup(&backup, "wrong-passphrase").unwrap_err();
        match err {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp602VaultDecryptionFailed);
            }
            _ => panic!("Expected Detailed KryptotomeError with Kryp602, got {:?}", err),
        }
    }

    #[test]
    fn test_vault_backup_file_roundtrip() {
        let mut store = VaultStore::new();
        store.insert_credential(make_sample_credential("cred-file", "pkg.starfield-dlc"));
        let keyring = Keyring::generate();

        let temp_dir = std::env::temp_dir();
        let backup_file_path = temp_dir.join(format!("test_backup_{}{}", uuid_v4_simple(), BACKUP_FILE_EXTENSION));

        assert!(backup_file_path.to_str().unwrap().ends_with(BACKUP_FILE_EXTENSION));

        let passphrase = "file-roundtrip-passphrase";
        store
            .save_backup_file_with_params(
                Some(&keyring),
                passphrase,
                EncryptionCipher::Aes256Gcm,
                KdfParams::fast(),
                &backup_file_path,
            )
            .expect("Saving backup file should succeed");

        assert!(backup_file_path.exists());

        // Restore from file
        let (restored_store, restored_keyring) =
            VaultStore::restore_from_backup_file(&backup_file_path, passphrase)
                .expect("Restore from file should succeed");

        assert_eq!(restored_store.credentials.len(), 1);
        assert_eq!(restored_keyring.unwrap().key_id, keyring.key_id);

        // Clean up
        let _ = fs::remove_file(&backup_file_path);
    }

    #[test]
    fn test_vault_restore_into_merging() {
        let mut store = VaultStore::new();
        store.insert_credential(make_sample_credential("cred-initial", "pkg.initial"));

        let mut other_store = VaultStore::new();
        other_store.insert_credential(make_sample_credential("cred-imported", "pkg.imported"));
        let keyring = Keyring::generate();

        let backup = other_store
            .export_backup_with_params(
                Some(&keyring),
                "merge-passphrase",
                EncryptionCipher::Aes256Gcm,
                KdfParams::fast(),
            )
            .unwrap();

        let restored_keyring = store
            .restore_into(&backup, "merge-passphrase")
            .expect("Restore into should succeed");

        assert_eq!(store.credentials.len(), 2);
        assert!(store.get_credential("cred-initial").is_some());
        assert!(store.get_credential("cred-imported").is_some());
        assert_eq!(restored_keyring.unwrap().key_id, keyring.key_id);
    }

    #[test]
    fn test_vault_revocation_lifecycle() {
        let mut store = VaultStore::new();
        store.insert_credential(make_sample_credential("cred-active", "pkg.active-game"));
        store.insert_credential(make_sample_credential("cred-revoked", "pkg.revoked-game"));

        let mut rev_list = PublisherRevocationList::new("did:key:zPublisher123");
        rev_list.add_revocation("cred-revoked", Some("Refund issued"));

        // 1. Status checks
        assert_eq!(
            store.check_credential_revocation("cred-active", &rev_list),
            RevocationStatus::Active
        );
        match store.check_credential_revocation("cred-revoked", &rev_list) {
            RevocationStatus::Revoked { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("Refund issued"));
            }
            _ => panic!("Expected Revoked status"),
        }
        assert!(!store.is_credential_revoked("cred-active", &rev_list));
        assert!(store.is_credential_revoked("cred-revoked", &rev_list));

        // 2. Listing revoked credentials
        let revoked_list = store.list_revoked_credentials(&rev_list);
        assert_eq!(revoked_list, vec!["cred-revoked".to_string()]);

        // 3. Validation with revocation
        assert!(store.validate_credential_with_revocation("cred-active", &rev_list).is_ok());
        let err = store.validate_credential_with_revocation("cred-revoked", &rev_list).unwrap_err();
        match err {
            KryptotomeError::CredentialRevoked(msg) => {
                assert!(msg.contains("cred-revoked"));
                assert!(msg.contains("Refund issued"));
            }
            _ => panic!("Expected CredentialRevoked error, got {:?}", err),
        }

        // 4. Proof creation with revocation
        let keyring = Keyring::generate();
        let nonce_revoked = format!("nonce-revoked-{}", rand::random::<u64>());
        let nonce_active = format!("nonce-active-{}", rand::random::<u64>());
        let challenge_revoked =
            ChallengeNonce::new("pkg.revoked-game".to_string(), nonce_revoked, 60);
        let challenge_active =
            ChallengeNonce::new("pkg.active-game".to_string(), nonce_active, 60);

        let proof_err = store
            .create_proof_for_challenge_with_revocation(&keyring, &challenge_revoked, &rev_list)
            .unwrap_err();
        match proof_err {
            KryptotomeError::CredentialRevoked(_) => {}
            _ => panic!("Expected CredentialRevoked for challenge proof"),
        }

        let proof_ok = store
            .create_proof_for_challenge_with_revocation(&keyring, &challenge_active, &rev_list);
        assert!(proof_ok.is_ok());

        // 5. Purging revoked credentials
        let purged = store.purge_revoked_credentials(&rev_list);
        assert_eq!(purged, vec!["cred-revoked".to_string()]);
        assert_eq!(store.credentials.len(), 1);
        assert!(store.get_credential("cred-active").is_some());
        assert!(store.get_credential("cred-revoked").is_none());
    }

    #[test]
    fn test_create_proof_for_challenge_groth16() {
        let mut store = VaultStore::new();
        let cred = make_sample_credential("cred-arkworks", "pkg.elder-scrolls-skyrim");
        store.insert_credential(cred.clone());

        let keyring = Keyring::generate();
        let nonce_zkp = format!("nonce-zkp-{}", rand::random::<u64>());
        let challenge = ChallengeNonce::new(
            "pkg.elder-scrolls-skyrim".to_string(),
            nonce_zkp,
            120,
        );

        let start = std::time::Instant::now();
        let zk_proof = store
            .create_proof_for_challenge(&keyring, &challenge)
            .expect("Proof generation must succeed");
        let duration = start.elapsed();
        println!("create_proof_for_challenge duration: {:?}", duration);

        // Requirement: proof must be valid 192-byte compressed Groth16 representation
        assert_eq!(zk_proof.proof_bytes.len(), 192);
        assert_eq!(zk_proof.public_inputs.challenge_nonce, challenge.nonce);
        assert_eq!(zk_proof.public_inputs.package_id, challenge.package_id);

        // Verification against global circuit verifying key
        let (_, vk) = kryptotome_core::get_or_init_entitlement_setup();
        let groth16_proof =
            kryptotome_core::deserialize_proof_compressed(&zk_proof.proof_bytes)
                .expect("Failed to deserialize Groth16 proof");

        let entitlement = &cred.credential_subject.entitlements[0];
        let public_inputs = vec![
            kryptotome_core::string_to_scalar(&challenge.nonce),
            kryptotome_core::string_to_scalar(&challenge.package_id),
            kryptotome_core::string_to_scalar(&entitlement.content_digest),
            kryptotome_core::string_to_scalar(&cred.issuer.public_key),
            kryptotome_core::string_to_scalar(&cred.credential_subject.holder_commitment),
        ];

        let is_valid = kryptotome_core::verify_entitlement_proof(vk, &public_inputs, &groth16_proof)
            .expect("Verification must succeed");
        assert!(is_valid, "Generated Groth16 proof must verify against circuit VK");

        // Tamper test: tampered nonce fails
        let tampered_nonce = format!("tampered-nonce-{}", rand::random::<u64>());
        let tampered_inputs = vec![
            kryptotome_core::string_to_scalar(&tampered_nonce),
            public_inputs[1],
            public_inputs[2],
            public_inputs[3],
            public_inputs[4],
        ];
        let tampered_valid = kryptotome_core::verify_entitlement_proof(vk, &tampered_inputs, &groth16_proof)
            .unwrap();
        assert!(!tampered_valid, "Tampered inputs must fail verification");
    }

    #[test]
    fn test_create_proof_bundle_for_challenge() {
        let mut store = VaultStore::new();
        let cred = make_sample_credential("cred-bundle", "pkg.cyberpunk");
        store.insert_credential(cred);

        let keyring = Keyring::generate();
        let nonce_bundle = format!("nonce-bundle-{}", rand::random::<u64>());
        let challenge = ChallengeNonce::new(
            "pkg.cyberpunk".to_string(),
            nonce_bundle,
            120,
        );

        let bundle = store
            .create_proof_bundle_for_challenge(&keyring, &challenge)
            .expect("Bundle creation must succeed");

        assert_eq!(bundle.curve, "BLS12-381");
        assert_eq!(bundle.proof_system, "groth16");
        assert_eq!(bundle.package_id, "pkg.cyberpunk");
        assert_eq!(bundle.challenge_nonce, challenge.nonce);

        // Self-contained bundle verification
        let (_, vk) = kryptotome_core::get_or_init_entitlement_setup();
        assert!(bundle.verify(vk).expect("Bundle verification must succeed"));

        // URN and compact binary tests
        let urn = bundle.to_urn().expect("URN conversion must succeed");
        assert!(urn.starts_with("urn:kryptotome:zkproof:v1:"));
        let compact_bytes = bundle.to_compact_bytes().expect("Compact bytes must succeed");
        assert!(compact_bytes.starts_with(kryptotome_core::BUNDLE_MAGIC));
    }

    #[test]
    fn test_vault_store_credential_import_lookup_and_export() {
        let temp_dir = std::env::temp_dir().join(format!("ktome_store_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let store_file = temp_dir.join("vault_store.json");

        // 1. Creation and initial state
        let mut store = VaultStore::new();
        assert!(store.credentials.is_empty());
        assert!(store.get_credential("nonexistent").is_none());
        assert!(store.find_for_package("nonexistent-package").is_none());

        // 2. Credential Import via insert_credential
        let cred_1 = make_sample_credential("cred-id-001", "paizo/pathfinder-spells");
        let cred_2 = make_sample_credential("cred-id-002", "paizo/pathfinder-monsters");
        
        // Multi-entitlement credential
        let issuer = kryptotome_core::Issuer {
            id: "did:key:zPublisher789".to_string(),
            name: "Paizo Multi".to_string(),
            public_key: "ed25519:pubkey789".to_string(),
        };
        let multi_entitlements = vec![
            kryptotome_core::Entitlement {
                package_id: "paizo/rules-core".to_string(),
                content_digest: "sha256:digest-core".to_string(),
                scope: vec!["rules".to_string()],
            },
            kryptotome_core::Entitlement {
                package_id: "paizo/rules-expanded".to_string(),
                content_digest: "sha256:digest-expanded".to_string(),
                scope: vec!["advanced".to_string()],
            },
        ];
        let cred_multi = kryptotome_core::KryptotomeCredential::new(
            "cred-id-multi".to_string(),
            issuer,
            "did:key:zHolder999".to_string(),
            "urn:kryptotome:commitment:bls12381:holder999".to_string(),
            multi_entitlements,
            "sig-multi".to_string(),
        );

        store.insert_credential(cred_1.clone());
        store.insert_credential(cred_2.clone());
        store.insert_credential(cred_multi.clone());

        assert_eq!(store.credentials.len(), 3);

        // 3. Credential Lookup by ID
        let looked_up_1 = store.get_credential("cred-id-001").expect("cred-id-001 must be found");
        assert_eq!(looked_up_1.id, "cred-id-001");
        assert_eq!(looked_up_1.credential_subject.entitlements[0].package_id, "paizo/pathfinder-spells");

        let looked_up_2 = store.get_credential("cred-id-002").expect("cred-id-002 must be found");
        assert_eq!(looked_up_2.id, "cred-id-002");
        assert_eq!(looked_up_2.credential_subject.entitlements[0].package_id, "paizo/pathfinder-monsters");

        assert!(store.get_credential("cred-id-missing").is_none());

        // 4. Credential Lookup by Package ID (find_for_package)
        let found_spells = store.find_for_package("paizo/pathfinder-spells").expect("Spells cred must be found");
        assert_eq!(found_spells.id, "cred-id-001");

        let found_monsters = store.find_for_package("paizo/pathfinder-monsters").expect("Monsters cred must be found");
        assert_eq!(found_monsters.id, "cred-id-002");

        // Multi-entitlement lookups
        let found_core = store.find_for_package("paizo/rules-core").expect("Core rules cred must be found");
        assert_eq!(found_core.id, "cred-id-multi");

        let found_expanded = store.find_for_package("paizo/rules-expanded").expect("Expanded rules cred must be found");
        assert_eq!(found_expanded.id, "cred-id-multi");

        assert!(store.find_for_package("paizo/unowned-module").is_none());

        // 5. Credential Export to JSON string
        let exported_json = store.export_to_json().expect("Exporting to JSON must succeed");
        assert!(exported_json.contains("cred-id-001"));
        assert!(exported_json.contains("cred-id-002"));
        assert!(exported_json.contains("cred-id-multi"));
        assert!(exported_json.contains("paizo/rules-expanded"));

        // 6. Credential Import from JSON string
        let imported_from_json = VaultStore::import_from_json(&exported_json).expect("Importing from JSON must succeed");
        assert_eq!(imported_from_json, store);

        // Corrupted JSON import returns SerializationError
        assert!(VaultStore::import_from_json("{corrupted json").is_err());

        // 7. Credential Export to File (save_to_file) & Import from File (load_from_file)
        store.save_to_file(&store_file).expect("save_to_file must succeed");
        assert!(store_file.exists());

        let imported_from_file = VaultStore::load_from_file(&store_file).expect("load_from_file must succeed");
        assert_eq!(imported_from_file, store);
        assert_eq!(imported_from_file.credentials.len(), 3);
        assert!(imported_from_file.get_credential("cred-id-multi").is_some());

        // Cleanup
        std::fs::remove_dir_all(temp_dir).unwrap();
    }

    fn uuid_v4_simple() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex_encode(&bytes)
    }
}

