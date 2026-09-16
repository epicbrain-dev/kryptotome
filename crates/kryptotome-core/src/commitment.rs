use crate::curve::{
    deserialize_g1_compressed, random_scalar, serialize_g1_compressed, G1Point, ScalarField,
};
use crate::error::{KryptotomeError, KryptotomeErrorCode, Result};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Domain separator for deriving the independent base generator H
const PEDERSEN_H_DOMAIN: &[u8] = b"KRYPTOTOME_PROTOCOL_PEDERSEN_GENERATOR_H_BLS12_381_V1";

/// A Pedersen commitment on BLS12-381 G1: C = s*G + r*H
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    #[serde(
        serialize_with = "serialize_g1_point",
        deserialize_with = "deserialize_g1_point"
    )]
    pub point: G1Point,
}

fn serialize_g1_point<S>(point: &G1Point, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = serialize_g1_compressed(point).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&hex_encode(&bytes))
}

fn deserialize_g1_point<'de, D>(deserializer: D) -> std::result::Result<G1Point, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;
    deserialize_g1_compressed(&bytes).map_err(serde::de::Error::custom)
}

impl PedersenCommitment {
    pub fn new(point: G1Point) -> Self {
        Self { point }
    }

    /// Serializes commitment point into 48-byte compressed G1 format
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serialize_g1_compressed(&self.point)
    }

    /// Deserializes commitment point from 48-byte compressed G1 format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let point = deserialize_g1_compressed(bytes)?;
        Ok(Self { point })
    }

    /// Hex-encoded compressed G1 representation
    pub fn to_hex(&self) -> Result<String> {
        let bytes = self.to_bytes()?;
        Ok(hex_encode(&bytes))
    }

    /// Parse from hex-encoded compressed G1 string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex_decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Format as canonical Kryptotome URN for W3C credential subject
    pub fn to_urn(&self) -> Result<String> {
        let hex = self.to_hex()?;
        Ok(format!("urn:kryptotome:commitment:bls12381:{}", hex))
    }

    /// Parse from canonical Kryptotome URN
    pub fn from_urn(urn: &str) -> Result<Self> {
        const PREFIX: &str = "urn:kryptotome:commitment:bls12381:";
        if let Some(hex_part) = urn.strip_prefix(PREFIX) {
            Self::from_hex(hex_part)
        } else {
            Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp103InvalidUriIdentifier,
                message: format!(
                    "Invalid commitment URN format: '{}'. Expected prefix '{}'",
                    urn, PREFIX
                ),
            })
        }
    }
}

impl fmt::Display for PedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_urn() {
            Ok(urn) => write!(f, "{}", urn),
            Err(_) => write!(f, "PedersenCommitment(<invalid>)"),
        }
    }
}

impl FromStr for PedersenCommitment {
    type Err = KryptotomeError;

    fn from_str(s: &str) -> Result<Self> {
        if s.starts_with("urn:") {
            Self::from_urn(s)
        } else {
            Self::from_hex(s)
        }
    }
}

/// Pedersen commitment scheme parameters over BLS12-381 G1
#[derive(Debug, Clone)]
pub struct PedersenCommitmentScheme {
    /// Generator G
    pub g: G1Point,
    /// Independent generator H where log_G(H) is unknown
    pub h: G1Point,
}

impl Default for PedersenCommitmentScheme {
    fn default() -> Self {
        Self::new()
    }
}

impl PedersenCommitmentScheme {
    /// Initializes Pedersen generators G and H
    pub fn new() -> Self {
        let g = G1Point::generator();
        let h = derive_generator_h();
        Self { g, h }
    }

    /// Computes Pedersen commitment: C = secret * G + blinding * H
    pub fn commit(&self, secret: &ScalarField, blinding: &ScalarField) -> PedersenCommitment {
        let g_proj = self.g * secret;
        let h_proj = self.h * blinding;
        let c_proj = g_proj + h_proj;
        PedersenCommitment::new(c_proj.into_affine())
    }

    /// Commits to a secret scalar, generating a fresh random blinding factor
    pub fn commit_with_random_blinding(
        &self,
        secret: &ScalarField,
    ) -> (PedersenCommitment, ScalarField) {
        let blinding = random_scalar();
        let commitment = self.commit(secret, &blinding);
        (commitment, blinding)
    }

    /// Maps arbitrary secret key bytes (e.g. Ed25519 seed or master key) to a field scalar
    /// and computes the commitment with a fresh random blinding factor.
    pub fn commit_secret_bytes(&self, secret_bytes: &[u8]) -> (PedersenCommitment, ScalarField, ScalarField) {
        let secret_scalar = scalar_from_bytes(secret_bytes);
        let blinding = random_scalar();
        let commitment = self.commit(&secret_scalar, &blinding);
        (commitment, secret_scalar, blinding)
    }

    /// Verifies opening of commitment: checks if C == secret * G + blinding * H
    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        secret: &ScalarField,
        blinding: &ScalarField,
    ) -> bool {
        let expected = self.commit(secret, blinding);
        commitment.point == expected.point
    }

    /// Additively combines two commitments: C(s1 + s2, r1 + r2) = C1 + C2
    pub fn add(&self, c1: &PedersenCommitment, c2: &PedersenCommitment) -> PedersenCommitment {
        let sum_proj = c1.point + c2.point;
        PedersenCommitment::new(sum_proj.into_affine())
    }
}

/// Derives generator H deterministically from domain separator with unknown discrete log
fn derive_generator_h() -> G1Point {
    let mut counter: u32 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(PEDERSEN_H_DOMAIN);
        hasher.update(&counter.to_be_bytes());
        let hash_output = hasher.finalize();

        // Interpret hash output as scalar multiplier for secondary generator
        let scalar = ScalarField::from_be_bytes_mod_order(&hash_output);
        let point_proj = G1Point::generator() * scalar;
        let affine = point_proj.into_affine();

        // Ensure non-zero and non-generator
        if !affine.is_zero() && affine != G1Point::generator() {
            return affine;
        }
        counter += 1;
    }
}

/// Hashes arbitrary byte slice into a uniform scalar in Fr
pub fn scalar_from_bytes(bytes: &[u8]) -> ScalarField {
    let mut hasher = Sha256::new();
    hasher.update(b"KRYPTOTOME_SECRET_TO_SCALAR_V1:");
    hasher.update(bytes);
    let digest = hasher.finalize();
    ScalarField::from_be_bytes_mod_order(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp901SerializationError,
            message: "Odd length hex string".to_string(),
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

    #[test]
    fn test_pedersen_commitment_correctness() {
        let scheme = PedersenCommitmentScheme::new();
        let secret = random_scalar();
        let blinding = random_scalar();

        let commitment = scheme.commit(&secret, &blinding);
        assert!(scheme.verify(&commitment, &secret, &blinding));

        // Wrong secret should fail
        let wrong_secret = random_scalar();
        assert!(!scheme.verify(&commitment, &wrong_secret, &blinding));

        // Wrong blinding should fail
        let wrong_blinding = random_scalar();
        assert!(!scheme.verify(&commitment, &secret, &wrong_blinding));
    }

    #[test]
    fn test_pedersen_information_theoretic_hiding() {
        let scheme = PedersenCommitmentScheme::new();
        let secret = random_scalar();

        // Two commitments to the same secret with different blindings must be distinct
        let (c1, b1) = scheme.commit_with_random_blinding(&secret);
        let (c2, b2) = scheme.commit_with_random_blinding(&secret);

        assert_ne!(b1, b2);
        assert_ne!(c1.point, c2.point);
        assert!(scheme.verify(&c1, &secret, &b1));
        assert!(scheme.verify(&c2, &secret, &b2));
    }

    #[test]
    fn test_pedersen_homomorphic_addition() {
        let scheme = PedersenCommitmentScheme::new();
        let s1 = random_scalar();
        let b1 = random_scalar();
        let c1 = scheme.commit(&s1, &b1);

        let s2 = random_scalar();
        let b2 = random_scalar();
        let c2 = scheme.commit(&s2, &b2);

        // Sum commitments
        let c_sum = scheme.add(&c1, &c2);

        // Sum secrets and blindings
        let s_sum = s1 + s2;
        let b_sum = b1 + b2;

        assert!(scheme.verify(&c_sum, &s_sum, &b_sum));
    }

    #[test]
    fn test_pedersen_serialization_and_urn_roundtrip() {
        let scheme = PedersenCommitmentScheme::new();
        let secret_bytes = b"sample_user_secret_key_from_vault_custody";
        let (commitment, _secret, _blinding) = scheme.commit_secret_bytes(secret_bytes);

        // 1. Raw bytes (48 bytes)
        let bytes = commitment.to_bytes().unwrap();
        assert_eq!(bytes.len(), 48);
        let recovered_bytes = PedersenCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(commitment, recovered_bytes);

        // 2. Hex
        let hex = commitment.to_hex().unwrap();
        assert_eq!(hex.len(), 96);
        let recovered_hex = PedersenCommitment::from_hex(&hex).unwrap();
        assert_eq!(commitment, recovered_hex);

        // 3. URN
        let urn = commitment.to_urn().unwrap();
        assert!(urn.starts_with("urn:kryptotome:commitment:bls12381:"));
        let recovered_urn = PedersenCommitment::from_urn(&urn).unwrap();
        assert_eq!(commitment, recovered_urn);
    }
}
