use crate::keyring::Keyring;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// Supported authenticated symmetric ciphers for keystore encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EncryptionCipher {
    /// AES-256-GCM (NIST SP 800-38D, hardware-accelerated AES-NI)
    #[default]
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,

    /// ChaCha20-Poly1305 (RFC 8439, constant-time software cipher)
    #[serde(rename = "ChaCha20-Poly1305")]
    ChaCha20Poly1305,
}

impl EncryptionCipher {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

/// Argon2id key derivation function parameters (RFC 9106)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    /// KDF algorithm identifier
    pub algorithm: String,
    /// Memory cost in KiB (e.g. 65,536 KiB = 64 MiB)
    pub memory_cost_kib: u32,
    /// Number of iterations / time passes
    pub time_cost_iterations: u32,
    /// Number of parallel threads
    pub parallelism: u32,
    /// 16-byte random salt encoded in hex
    pub salt_hex: String,
}

impl KdfParams {
    /// OWASP / RFC 9106 recommended interactive parameters (64 MiB memory, 3 iterations, 4 parallelism)
    pub fn recommended() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            algorithm: "argon2id".to_string(),
            memory_cost_kib: 65536, // 64 MiB
            time_cost_iterations: 3,
            parallelism: 4,
            salt_hex: hex_encode(&salt),
        }
    }

    /// Fast parameters for unit tests and resource-constrained environments (8 MiB, 1 iteration, 1 thread)
    pub fn fast() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            algorithm: "argon2id".to_string(),
            memory_cost_kib: 8192, // 8 MiB
            time_cost_iterations: 1,
            parallelism: 1,
            salt_hex: hex_encode(&salt),
        }
    }

    /// Derives a 256-bit symmetric encryption key from a passphrase
    pub fn derive_key(&self, passphrase: &str) -> Result<[u8; 32]> {
        if self.algorithm != "argon2id" {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                message: format!("Unsupported KDF algorithm: {}", self.algorithm),
            });
        }

        let salt_bytes = hex_decode(&self.salt_hex)?;
        if salt_bytes.len() < 8 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                message: "Argon2 salt must be at least 8 bytes".to_string(),
            });
        }

        let params = Params::new(
            self.memory_cost_kib,
            self.time_cost_iterations,
            self.parallelism,
            Some(32),
        )
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp604KeyCustodyError,
            message: format!("Invalid Argon2 parameters: {}", e),
        })?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut derived_key = [0u8; 32];
        OsRng.fill_bytes(&mut derived_key);
        argon2
            .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut derived_key)
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                message: format!("Argon2id key derivation failed: {}", e),
            })?;

        Ok(derived_key)
    }
}

/// A securely encrypted keystore representing an offline-protected holder key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKeystore {
    /// Schema format version
    pub version: u32,
    /// Public DID / Key ID
    pub key_id: String,
    /// Public key in hex (Ed25519)
    pub public_key_hex: String,
    /// Symmetric cipher used
    pub cipher: EncryptionCipher,
    /// Argon2id KDF derivation parameters
    pub kdf: KdfParams,
    /// 12-byte (96-bit) AEAD initialization vector / nonce in hex
    pub nonce_hex: String,
    /// Encrypted ciphertext with appended 16-byte authentication tag in hex
    pub ciphertext_hex: String,
}

impl EncryptedKeystore {
    /// Encrypts a Keyring using a passphrase and selected cipher (using recommended KDF settings)
    pub fn encrypt(
        keyring: &Keyring,
        passphrase: &str,
        cipher: EncryptionCipher,
    ) -> Result<Self> {
        Self::encrypt_with_params(keyring, passphrase, cipher, KdfParams::recommended())
    }

    /// Encrypts a Keyring using explicit KDF parameters
    pub fn encrypt_with_params(
        keyring: &Keyring,
        passphrase: &str,
        cipher: EncryptionCipher,
        kdf: KdfParams,
    ) -> Result<Self> {
        let mut derived_key = kdf.derive_key(passphrase)?;
        let plaintext = keyring.secret_bytes();

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
                    .encrypt(&nonce, plaintext)
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
                    .encrypt(&nonce, plaintext)
                    .map_err(|e| KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                        message: format!("ChaCha20-Poly1305 encryption failed: {}", e),
                    })?;
                (nonce.to_vec(), ct)
            }
        };

        derived_key.zeroize();

        Ok(Self {
            version: 1,
            key_id: keyring.key_id.clone(),
            public_key_hex: keyring.public_key_hex.clone(),
            cipher,
            kdf,
            nonce_hex: hex_encode(&nonce_bytes),
            ciphertext_hex: hex_encode(&ciphertext_bytes),
        })
    }

    /// Decrypts the keystore with a passphrase, recovering the original Keyring
    pub fn decrypt(&self, passphrase: &str) -> Result<Keyring> {
        let mut derived_key = self.kdf.derive_key(passphrase)?;
        let nonce_bytes = hex_decode(&self.nonce_hex)?;
        let ciphertext = hex_decode(&self.ciphertext_hex)?;

        if nonce_bytes.len() != 12 {
            derived_key.zeroize();
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp602VaultDecryptionFailed,
                message: "Invalid AEAD nonce length, expected 12 bytes".to_string(),
            });
        }

        let mut decrypted_secret = match self.cipher {
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
                        message: "Invalid passphrase or corrupted AES-256-GCM keystore".to_string(),
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
                        message: "Invalid passphrase or corrupted ChaCha20-Poly1305 keystore".to_string(),
                    }
                })?
            }
        };

        derived_key.zeroize();

        let keyring_res = Keyring::from_secret_bytes(&decrypted_secret).map_err(|e| {
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                message: e,
            }
        });

        decrypted_secret.zeroize();
        keyring_res
    }

    /// Serializes keystore to formatted JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp901SerializationError,
            message: format!("Failed to serialize keystore to JSON: {}", e),
        })
    }

    /// Deserializes keystore from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp901SerializationError,
            message: format!("Failed to deserialize keystore from JSON: {}", e),
        })
    }

    /// Saves keystore to a file on disk
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self.to_json()?;
        fs::write(path, json).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp902IoError,
            message: format!("Failed to save encrypted keystore to file: {}", e),
        })
    }

    /// Loads encrypted keystore from a file on disk
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp902IoError,
            message: format!("Failed to read encrypted keystore from file: {}", e),
        })?;
        Self::from_json(&content)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp604KeyCustodyError,
            message: "Invalid hex string length in keystore".to_string(),
        });
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                message: format!("Invalid hex byte in keystore: {}", e),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_256_gcm_keystore_encryption_and_decryption() {
        let keyring = Keyring::generate();
        let passphrase = format!("test-passphrase-{}", rand::random::<u64>());

        // Encrypt with fast params for instant test execution
        let keystore = EncryptedKeystore::encrypt_with_params(
            &keyring,
            &passphrase,
            EncryptionCipher::Aes256Gcm,
            KdfParams::fast(),
        )
        .unwrap();

        assert_eq!(keystore.cipher, EncryptionCipher::Aes256Gcm);
        assert_eq!(keystore.key_id, keyring.key_id);
        assert_eq!(keystore.public_key_hex, keyring.public_key_hex);

        // Decrypt successfully
        let decrypted = keystore.decrypt(&passphrase).unwrap();
        assert_eq!(decrypted.key_id, keyring.key_id);
        assert_eq!(decrypted.public_key_hex, keyring.public_key_hex);
        assert_eq!(decrypted.secret_bytes(), keyring.secret_bytes());

        // Decrypt with wrong passphrase must fail with Kryp602
        let wrong_passphrase = format!("wrong-passphrase-{}", rand::random::<u64>());
        let wrong_err = keystore.decrypt(&wrong_passphrase).unwrap_err();
        match wrong_err {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp602VaultDecryptionFailed);
            }
            _ => panic!("Expected Kryp602 error"),
        }
    }

    #[test]
    fn test_chacha20_poly1305_keystore_encryption_and_decryption() {
        let keyring = Keyring::generate();
        let passphrase = format!("test-passphrase-{}", rand::random::<u64>());

        let keystore = EncryptedKeystore::encrypt_with_params(
            &keyring,
            &passphrase,
            EncryptionCipher::ChaCha20Poly1305,
            KdfParams::fast(),
        )
        .unwrap();

        assert_eq!(keystore.cipher, EncryptionCipher::ChaCha20Poly1305);

        // Decrypt successfully
        let decrypted = keystore.decrypt(&passphrase).unwrap();
        assert_eq!(decrypted.key_id, keyring.key_id);
        assert_eq!(decrypted.secret_bytes(), keyring.secret_bytes());

        // Decrypt with wrong passphrase must fail with Kryp602
        let wrong_passphrase = format!("incorrect-secret-{}", rand::random::<u64>());
        let wrong_err = keystore.decrypt(&wrong_passphrase).unwrap_err();
        match wrong_err {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp602VaultDecryptionFailed);
            }
            _ => panic!("Expected Kryp602 error"),
        }
    }

    #[test]
    fn test_keystore_json_and_file_roundtrip() {
        let keyring = Keyring::generate();
        let passphrase = format!("test-passphrase-{}", rand::random::<u64>());

        let keystore = EncryptedKeystore::encrypt_with_params(
            &keyring,
            &passphrase,
            EncryptionCipher::Aes256Gcm,
            KdfParams::fast(),
        )
        .unwrap();

        // JSON roundtrip
        let json = keystore.to_json().unwrap();
        let from_json = EncryptedKeystore::from_json(&json).unwrap();
        assert_eq!(keystore, from_json);

        // File roundtrip in temporary directory
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("kryptotome_test_keystore_{}.json", keyring.key_id.replace(':', "_")));

        keystore.save_to_file(&file_path).unwrap();
        let loaded = EncryptedKeystore::load_from_file(&file_path).unwrap();
        assert_eq!(keystore, loaded);

        let decrypted = loaded.decrypt(&passphrase).unwrap();
        assert_eq!(decrypted.secret_bytes(), keyring.secret_bytes());

        let _ = fs::remove_file(file_path);
    }
}
