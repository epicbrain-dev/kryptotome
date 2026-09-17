use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Zeroizing wrapper for 32-byte secret seeds or private key material
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingSecretKey {
    bytes: [u8; 32],
}

impl ZeroizingSecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_zeroized(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for ZeroizingSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizingSecretKey([REDACTED])")
    }
}

/// Local key custody representing user's primary signing and commitment keys.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` to guarantee all sensitive secret key material
/// is cryptographically erased from memory upon drop or manual wiping.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Keyring {
    #[zeroize(skip)]
    pub key_id: String,
    #[serde(default, skip_serializing)]
    secret_bytes: Vec<u8>,
    #[zeroize(skip)]
    pub public_key_hex: String,
}

impl Keyring {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex_encode(verifying_key.as_bytes());

        let mut raw_secret = signing_key.to_bytes();
        let secret_bytes = raw_secret.to_vec();
        raw_secret.zeroize();

        Self {
            key_id: format!("did:key:z{}", &pub_hex[..16]),
            secret_bytes,
            public_key_hex: pub_hex,
        }
    }

    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self, String> {
        if secret.len() != 32 {
            return Err("Invalid secret key length, expected 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(secret);
        let signing_key = SigningKey::from_bytes(&arr);
        arr.zeroize();
        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex_encode(verifying_key.as_bytes());

        Ok(Self {
            key_id: format!("did:key:z{}", &pub_hex[..16]),
            secret_bytes: secret.to_vec(),
            public_key_hex: pub_hex,
        })
    }

    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret_bytes
    }

    /// Checks whether the secret key has been zeroized (wiped with all zeros)
    pub fn is_zeroized(&self) -> bool {
        self.secret_bytes.is_empty() || self.secret_bytes.iter().all(|&b| b == 0)
    }

    /// Derives a cryptographically binding Pedersen commitment to the user's secret key
    /// along with the secret scalar and blinding randomness.
    pub fn derive_holder_commitment(
        &self,
    ) -> (
        kryptotome_core::PedersenCommitment,
        kryptotome_core::ScalarField,
        kryptotome_core::ScalarField,
    ) {
        let scheme = kryptotome_core::PedersenCommitmentScheme::new();
        scheme.commit_secret_bytes(&self.secret_bytes)
    }

    /// Derives canonical URN representation of the holder commitment for W3C credentials
    pub fn derive_commitment_urn(
        &self,
    ) -> (
        String,
        kryptotome_core::ScalarField,
        kryptotome_core::ScalarField,
    ) {
        let (commitment, secret, blinding) = self.derive_holder_commitment();
        let urn = commitment
            .to_urn()
            .unwrap_or_else(|_| "urn:kryptotome:commitment:bls12381:unknown".to_string());
        (urn, secret, blinding)
    }

    /// Signs a message with the Keyring's Ed25519 private key.
    pub fn sign(&self, message: &[u8]) -> Result<ed25519_dalek::Signature, String> {
        if self.is_zeroized() || self.secret_bytes.len() != 32 {
            return Err("Cannot sign: secret key is zeroized or invalid length".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.secret_bytes);
        let signing_key = SigningKey::from_bytes(&arr);
        arr.zeroize();
        Ok(signing_key.sign(message))
    }

    /// Verifies an Ed25519 signature against this Keyring's public key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<bool, String> {
        let pub_bytes = hex_decode(&self.public_key_hex)?;
        if pub_bytes.len() != 32 {
            return Err("Invalid public key length, expected 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pub_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&arr).map_err(|e| format!("Invalid public key: {}", e))?;
        verifying_key
            .verify(message, signature)
            .map(|_| true)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }

    /// Exports key data for encrypted backup envelopes
    pub fn to_backup_data(&self) -> KeyringBackupData {
        KeyringBackupData {
            key_id: self.key_id.clone(),
            secret_bytes_hex: hex_encode(&self.secret_bytes),
            public_key_hex: self.public_key_hex.clone(),
        }
    }

    /// Restores a Keyring from encrypted backup data
    pub fn from_backup_data(data: &KeyringBackupData) -> Result<Self, String> {
        let secret = hex_decode(&data.secret_bytes_hex)?;
        Self::from_secret_bytes(&secret)
    }
}

/// Serialized representation of a Keyring inside an encrypted backup
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct KeyringBackupData {
    #[zeroize(skip)]
    pub key_id: String,
    pub secret_bytes_hex: String,
    #[zeroize(skip)]
    pub public_key_hex: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("Invalid hex string length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Invalid hex byte: {}", e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_generation_lifecycle() {
        // 1. Random generation
        let keyring1 = Keyring::generate();
        let keyring2 = Keyring::generate();

        assert_ne!(keyring1.key_id, keyring2.key_id);
        assert_ne!(keyring1.public_key_hex, keyring2.public_key_hex);
        assert_ne!(keyring1.secret_bytes(), keyring2.secret_bytes());
        assert!(keyring1.key_id.starts_with("did:key:z"));
        assert_eq!(keyring1.public_key_hex.len(), 64);
        assert_eq!(keyring1.secret_bytes().len(), 32);
        assert!(!keyring1.is_zeroized());

        // 2. Deterministic generation from 32-byte secret seed
        let seed = [0x5au8; 32];
        let keyring_from_seed1 = Keyring::from_secret_bytes(&seed).unwrap();
        let keyring_from_seed2 = Keyring::from_secret_bytes(&seed).unwrap();
        assert_eq!(keyring_from_seed1.key_id, keyring_from_seed2.key_id);
        assert_eq!(
            keyring_from_seed1.public_key_hex,
            keyring_from_seed2.public_key_hex
        );
        assert_eq!(
            keyring_from_seed1.secret_bytes(),
            keyring_from_seed2.secret_bytes()
        );

        // 3. Rejection of invalid secret length
        assert!(Keyring::from_secret_bytes(&[0u8; 31]).is_err());
        assert!(Keyring::from_secret_bytes(&[0u8; 33]).is_err());
        assert!(Keyring::from_secret_bytes(&[]).is_err());
    }

    #[test]
    fn test_keyring_serialization_roundtrip() {
        let keyring = Keyring::generate();

        // 1. Backup data serialization roundtrip
        let backup_data = keyring.to_backup_data();
        assert_eq!(backup_data.key_id, keyring.key_id);
        assert_eq!(backup_data.public_key_hex, keyring.public_key_hex);
        assert_eq!(
            backup_data.secret_bytes_hex,
            hex_encode(keyring.secret_bytes())
        );

        let json = serde_json::to_string(&backup_data).unwrap();
        let restored_backup: KeyringBackupData = serde_json::from_str(&json).unwrap();
        assert_eq!(restored_backup, backup_data);

        let restored_keyring = Keyring::from_backup_data(&restored_backup).unwrap();
        assert_eq!(restored_keyring.key_id, keyring.key_id);
        assert_eq!(restored_keyring.public_key_hex, keyring.public_key_hex);
        assert_eq!(restored_keyring.secret_bytes(), keyring.secret_bytes());

        // 2. Standard JSON serialization omits secret_bytes for memory safety
        let standard_json = serde_json::to_string(&keyring).unwrap();
        assert!(!standard_json.contains("secretBytes"));
        let deserialized_keyring: Keyring = serde_json::from_str(&standard_json).unwrap();
        assert_eq!(deserialized_keyring.key_id, keyring.key_id);
        assert_eq!(deserialized_keyring.public_key_hex, keyring.public_key_hex);
        // Secret bytes should be empty in deserialized standard JSON
        assert!(deserialized_keyring.is_zeroized());
    }

    #[test]
    fn test_keyring_signing_and_verification() {
        let keyring = Keyring::generate();
        let message = b"Kryptotome digital entitlement session auth challenge nonce: 987654321";

        // 1. Valid signature generation and verification
        let signature = keyring.sign(message).expect("Signing must succeed");
        let is_valid = keyring
            .verify(message, &signature)
            .expect("Verification must succeed");
        assert!(is_valid, "Valid signature must verify");

        // 2. Tampered message fails verification
        let tampered_message =
            b"Kryptotome digital entitlement session auth challenge nonce: 000000000";
        assert!(keyring.verify(tampered_message, &signature).is_err());

        // 3. Tampered signature fails verification
        let mut sig_bytes = signature.to_bytes();
        sig_bytes[0] ^= 0xFF;
        let tampered_signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(keyring.verify(message, &tampered_signature).is_err());

        // 4. Verification with a different keyring fails
        let other_keyring = Keyring::generate();
        assert!(other_keyring.verify(message, &signature).is_err());

        // 5. Zeroized keyring cannot sign
        let mut zeroized_keyring = keyring.clone();
        zeroized_keyring.zeroize();
        assert!(zeroized_keyring.sign(message).is_err());
    }
}
