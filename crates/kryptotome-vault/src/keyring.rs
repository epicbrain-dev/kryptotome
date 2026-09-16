use ed25519_dalek::SigningKey;
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
    #[serde(skip_serializing)]
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
    if s.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex byte: {}", e))
        })
        .collect()
}
