use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Local key custody representing user's primary signing and commitment keys
#[derive(Debug, Serialize, Deserialize)]
pub struct Keyring {
    pub key_id: String,
    #[serde(skip_serializing)]
    secret_bytes: Vec<u8>,
    pub public_key_hex: String,
}

impl Keyring {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex_encode(verifying_key.as_bytes());

        Self {
            key_id: format!("did:key:z{}", &pub_hex[..16]),
            secret_bytes: signing_key.to_bytes().to_vec(),
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
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
