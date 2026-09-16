use crate::error::{KryptotomeError, KryptotomeErrorCode, Result};
use ark_bls12_381::{Bls12_381, Fq, Fq12, Fr, G1Affine, G2Affine};
pub use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::{One, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported pairing-friendly elliptic curve suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum CurveSuite {
    /// BLS12-381: ~128-bit security margin, conservative pairing-friendly curve
    /// Optimal for non-blockchain, privacy-preserving zero-knowledge credentials.
    #[default]
    #[serde(rename = "BLS12-381")]
    Bls12_381,

    /// BN254 (alt_bn128): ~100-bit security margin
    #[serde(rename = "BN254")]
    Bn254,
}

impl CurveSuite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bls12_381 => "BLS12-381",
            Self::Bn254 => "BN254",
        }
    }

    pub fn security_bits(&self) -> u32 {
        match self {
            Self::Bls12_381 => 128,
            Self::Bn254 => 100,
        }
    }

    pub fn g1_compressed_size_bytes(&self) -> usize {
        match self {
            Self::Bls12_381 => 48,
            Self::Bn254 => 32,
        }
    }

    pub fn g2_compressed_size_bytes(&self) -> usize {
        match self {
            Self::Bls12_381 => 96,
            Self::Bn254 => 64,
        }
    }
}

impl fmt::Display for CurveSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for CurveSuite {
    type Err = KryptotomeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().replace('_', "-").as_str() {
            "BLS12-381" | "BLS12381" => Ok(Self::Bls12_381),
            "BN254" | "ALT-BN128" => Ok(Self::Bn254),
            _ => Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: format!("Unsupported curve suite: '{}'. Expected 'BLS12-381' or 'BN254'", s),
            }),
        }
    }
}

/// Core types bound to standard production curve suite (BLS12-381)
pub type ProductionPairingEngine = Bls12_381;
pub type ScalarField = Fr;
pub type BaseField = Fq;
pub type TargetField = Fq12;
pub type G1Point = G1Affine;
pub type G2Point = G2Affine;

/// Generates a random scalar field element using OS CSPRNG
pub fn random_scalar() -> ScalarField {
    let mut rng = OsRng;
    ScalarField::rand(&mut rng)
}

/// Returns the canonical generator point for G1 on BLS12-381
pub fn g1_generator() -> G1Point {
    G1Point::generator()
}

/// Returns the canonical generator point for G2 on BLS12-381
pub fn g2_generator() -> G2Point {
    G2Point::generator()
}

/// Evaluates asymmetric pairing e(P, Q) using production curve BLS12-381
pub fn pairing(p: &G1Point, q: &G2Point) -> TargetField {
    Bls12_381::pairing(*p, *q).0
}

/// Verifies pairing relation: e(P1, Q1) == e(P2, Q2)
pub fn verify_pairing_equality(p1: &G1Point, q1: &G2Point, p2: &G1Point, q2: &G2Point) -> bool {
    let p1_prep = <Bls12_381 as Pairing>::G1Prepared::from(*p1);
    let q1_prep = <Bls12_381 as Pairing>::G2Prepared::from(*q1);

    let p2_neg = -p2.into_group();
    let p2_prep = <Bls12_381 as Pairing>::G1Prepared::from(p2_neg.into_affine());
    let q2_prep = <Bls12_381 as Pairing>::G2Prepared::from(*q2);

    let ml = Bls12_381::multi_miller_loop([p1_prep, p2_prep], [q1_prep, q2_prep]);
    let result = Bls12_381::final_exponentiation(ml);
    result.map(|f| f.0.is_one()).unwrap_or(false)
}

/// Evaluates a generalized multi-pairing: prod_{i} e(P_i, Q_i) into target field GT
pub fn evaluate_multi_pairing(pairs: &[(&G1Point, &G2Point)]) -> TargetField {
    let mut g1_prep = Vec::with_capacity(pairs.len());
    let mut g2_prep = Vec::with_capacity(pairs.len());
    for (p, q) in pairs {
        g1_prep.push(<Bls12_381 as Pairing>::G1Prepared::from(**p));
        g2_prep.push(<Bls12_381 as Pairing>::G2Prepared::from(**q));
    }
    let ml = Bls12_381::multi_miller_loop(g1_prep, g2_prep);
    Bls12_381::final_exponentiation(ml)
        .map(|f| f.0)
        .unwrap_or_else(ark_ff::Zero::zero)
}

/// Verifies whether the multi-pairing product equals the identity in GT: prod_{i} e(P_i, Q_i) == 1
pub fn verify_multi_pairing_identity(pairs: &[(&G1Point, &G2Point)]) -> bool {
    let mut g1_prep = Vec::with_capacity(pairs.len());
    let mut g2_prep = Vec::with_capacity(pairs.len());
    for (p, q) in pairs {
        g1_prep.push(<Bls12_381 as Pairing>::G1Prepared::from(**p));
        g2_prep.push(<Bls12_381 as Pairing>::G2Prepared::from(**q));
    }
    let ml = Bls12_381::multi_miller_loop(g1_prep, g2_prep);
    Bls12_381::final_exponentiation(ml)
        .map(|f| f.0.is_one())
        .unwrap_or(false)
}

/// Evaluates a KZG / Plonk polynomial commitment opening check:
/// Verifies that e(W, srs_g2_x - z * G_2) == e(commitment - y * G_1, G_2)
/// in under 2ms using a 2-element multi-Miller loop.
pub fn verify_kzg_opening(
    commitment: &G1Point,
    point_z: &ScalarField,
    value_y: &ScalarField,
    proof_w: &G1Point,
    srs_g2_x: &G2Point,
) -> bool {
    let g1_gen = G1Point::generator();
    let g2_gen = G2Point::generator();

    // Q_1 = srs_g2_x - z * G_2
    let z_g2 = (g2_gen * *point_z).into_affine();
    let q1 = (*srs_g2_x - z_g2).into_affine();

    // P_2 = -(commitment - y * G_1) = y * G_1 - commitment
    let y_g1 = (g1_gen * *value_y).into_affine();
    let p2 = (y_g1 - *commitment).into_affine();

    let p1_prep = <Bls12_381 as Pairing>::G1Prepared::from(*proof_w);
    let q1_prep = <Bls12_381 as Pairing>::G2Prepared::from(q1);
    let p2_prep = <Bls12_381 as Pairing>::G1Prepared::from(p2);
    let q2_prep = <Bls12_381 as Pairing>::G2Prepared::from(g2_gen);

    let ml = Bls12_381::multi_miller_loop([p1_prep, p2_prep], [q1_prep, q2_prep]);
    let result = Bls12_381::final_exponentiation(ml);
    result.map(|f| f.0.is_one()).unwrap_or(false)
}

/// Evaluates a batched Plonk KZG opening verification check:
/// e(W_z + u * W_zw, srs_g2_x) == e(z * W_z + u * z * omega * W_zw + folded_commitments, G_2)
pub fn verify_plonk_batch_opening(
    w_z: &G1Point,
    w_zw: &G1Point,
    folded_commitments: &G1Point,
    point_z: &ScalarField,
    omega: &ScalarField,
    challenge_u: &ScalarField,
    srs_g2_x: &G2Point,
) -> bool {
    let g2_gen = G2Point::generator();

    // P_1 = W_z + u * W_zw
    let u_w_zw = (*w_zw * *challenge_u).into_affine();
    let p1 = (*w_z + u_w_zw).into_affine();
    let q1 = *srs_g2_x;

    // zw = z * omega
    let zw = *point_z * *omega;
    // P_2 = -(z * W_z + (u * zw) * W_zw + folded_commitments)
    let z_w_z = (*w_z * *point_z).into_affine();
    let u_zw = *challenge_u * zw;
    let u_zw_w_zw = (*w_zw * u_zw).into_affine();
    let rhs_sum = (z_w_z + u_zw_w_zw + *folded_commitments).into_affine();
    let p2 = (-rhs_sum.into_group()).into_affine();
    let q2 = g2_gen;

    let p1_prep = <Bls12_381 as Pairing>::G1Prepared::from(p1);
    let q1_prep = <Bls12_381 as Pairing>::G2Prepared::from(q1);
    let p2_prep = <Bls12_381 as Pairing>::G1Prepared::from(p2);
    let q2_prep = <Bls12_381 as Pairing>::G2Prepared::from(q2);

    let ml = Bls12_381::multi_miller_loop([p1_prep, p2_prep], [q1_prep, q2_prep]);
    let result = Bls12_381::final_exponentiation(ml);
    result.map(|f| f.0.is_one()).unwrap_or(false)
}

/// Serializes G1 point into compact compressed byte vector (48 bytes)
pub fn serialize_g1_compressed(point: &G1Point) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(48);
    point
        .serialize_compressed(&mut bytes)
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to serialize G1 point: {}", e),
        })?;
    Ok(bytes)
}

/// Deserializes G1 point from compact compressed byte slice with subgroup validation
pub fn deserialize_g1_compressed(bytes: &[u8]) -> Result<G1Point> {
    G1Point::deserialize_compressed(bytes).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
        message: format!("Failed to deserialize G1 point: {}", e),
    })
}

/// Serializes G2 point into compact compressed byte vector (96 bytes)
pub fn serialize_g2_compressed(point: &G2Point) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(96);
    point
        .serialize_compressed(&mut bytes)
        .map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
            message: format!("Failed to serialize G2 point: {}", e),
        })?;
    Ok(bytes)
}

/// Deserializes G2 point from compact compressed byte slice with subgroup validation
pub fn deserialize_g2_compressed(bytes: &[u8]) -> Result<G2Point> {
    G2Point::deserialize_compressed(bytes).map_err(|e| KryptotomeError::Detailed {
        code: KryptotomeErrorCode::Kryp303MalformedProofEncoding,
        message: format!("Failed to deserialize G2 point: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_curve_suite_properties() {
        let bls = CurveSuite::Bls12_381;
        assert_eq!(bls.security_bits(), 128);
        assert_eq!(bls.g1_compressed_size_bytes(), 48);
        assert_eq!(bls.g2_compressed_size_bytes(), 96);
        assert_eq!(CurveSuite::from_str("BLS12-381").unwrap(), CurveSuite::Bls12_381);
    }

    #[test]
    fn test_pairing_bilinearity_and_equality() {
        let g1_gen = G1Point::generator();
        let g2_gen = G2Point::generator();

        let a = random_scalar();
        let b = random_scalar();

        // P1 = a * G1, Q1 = b * G2
        let p1 = (g1_gen * a).into_affine();
        let q1 = (g2_gen * b).into_affine();

        // P2 = (a * b) * G1, Q2 = G2
        let p2 = (g1_gen * (a * b)).into_affine();
        let q2 = g2_gen;

        // Verify bilinearity: e(a*G1, b*G2) == e((a*b)*G1, G2)
        let is_equal = verify_pairing_equality(&p1, &q1, &p2, &q2);
        assert!(is_equal, "Pairing bilinearity check failed");
    }

    #[test]
    fn test_point_compression_roundtrip() {
        let g1_point = (G1Point::generator() * random_scalar()).into_affine();
        let g1_bytes = serialize_g1_compressed(&g1_point).unwrap();
        assert_eq!(g1_bytes.len(), 48);

        let g1_recovered = deserialize_g1_compressed(&g1_bytes).unwrap();
        assert_eq!(g1_point, g1_recovered);

        let g2_point = (G2Point::generator() * random_scalar()).into_affine();
        let g2_bytes = serialize_g2_compressed(&g2_point).unwrap();
        assert_eq!(g2_bytes.len(), 96);

        let g2_recovered = deserialize_g2_compressed(&g2_bytes).unwrap();
        assert_eq!(g2_point, g2_recovered);
    }

    #[test]
    fn test_pairing_performance_latency() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let start = Instant::now();
        let _res = pairing(&g1, &g2);
        let elapsed = start.elapsed();

        println!("Single BLS12-381 pairing duration: {:?}", elapsed);
        // Requirement from PRD: verification must take < 10ms in release profile
        if cfg!(debug_assertions) {
            assert!(
                elapsed.as_millis() < 250,
                "Debug pairing latency unexpectedly high: {:?}",
                elapsed
            );
        } else {
            assert!(
                elapsed.as_millis() < 10,
                "Pairing latency exceeded 10ms target: {:?}",
                elapsed
            );
        }
    }

    #[test]
    fn test_multi_pairing_identity() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let a = random_scalar();
        let b = random_scalar();

        // e(a*G1, b*G2) * e(-(a*b)*G1, G2) == 1
        let p1 = (g1 * a).into_affine();
        let q1 = (g2 * b).into_affine();
        let p2 = (g1 * (-(a * b))).into_affine();
        let q2 = g2;

        assert!(verify_multi_pairing_identity(&[(&p1, &q1), (&p2, &q2)]));

        // Tamper with p2
        let p2_bad = (g1 * random_scalar()).into_affine();
        assert!(!verify_multi_pairing_identity(&[(&p1, &q1), (&p2_bad, &q2)]));
    }

    #[test]
    fn test_kzg_opening_verification() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        // Trapdoor x (from trusted setup / SRS)
        let srs_x = random_scalar();
        let srs_g2_x = (g2 * srs_x).into_affine();

        // Linear polynomial: p(X) = a * X + b
        let a = random_scalar();
        let b = random_scalar();

        // Commitment C = p(x) * G_1 = (a * x + b) * G_1
        let p_x = a * srs_x + b;
        let commitment = (g1 * p_x).into_affine();

        // Evaluation at z: y = p(z) = a * z + b
        let z = random_scalar();
        let y = a * z + b;

        // Quotient q(X) = (p(X) - y) / (X - z) = a
        let proof_w = (g1 * a).into_affine();

        let start = Instant::now();
        let is_valid = verify_kzg_opening(&commitment, &z, &y, &proof_w, &srs_g2_x);
        let elapsed = start.elapsed();
        println!("KZG / Plonk opening verification latency: {:?}", elapsed);

        assert!(is_valid, "Valid KZG polynomial commitment opening must verify");

        if !cfg!(debug_assertions) {
            assert!(elapsed.as_millis() < 10, "KZG verification must be < 10ms in release");
        }

        // Tampered evaluation value y
        let y_tampered = y + random_scalar();
        assert!(!verify_kzg_opening(&commitment, &z, &y_tampered, &proof_w, &srs_g2_x));

        // Tampered proof W
        let proof_w_tampered = (g1 * random_scalar()).into_affine();
        assert!(!verify_kzg_opening(&commitment, &z, &y, &proof_w_tampered, &srs_g2_x));
    }

    #[test]
    fn test_plonk_batch_opening_verification() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();

        let srs_x = random_scalar();
        let srs_g2_x = (g2 * srs_x).into_affine();

        let w_z = (g1 * random_scalar()).into_affine();
        let w_zw = (g1 * random_scalar()).into_affine();
        let z = random_scalar();
        let omega = random_scalar();
        let u = random_scalar();

        // Construct folded_commitments such that:
        // (W_z + u * W_zw) * x == z * W_z + u * z * omega * W_zw + folded_commitments
        let zw = z * omega;
        let lhs = (w_z.into_group() + w_zw * u) * srs_x;
        let rhs_part = w_z.into_group() * z + w_zw * (u * zw);
        let folded_commitments = (lhs - rhs_part).into_affine();

        let start = Instant::now();
        let valid = verify_plonk_batch_opening(&w_z, &w_zw, &folded_commitments, &z, &omega, &u, &srs_g2_x);
        let elapsed = start.elapsed();
        println!("Plonk batch opening verification latency: {:?}", elapsed);

        assert!(valid, "Valid Plonk batch opening must pass");
        if !cfg!(debug_assertions) {
            assert!(elapsed.as_millis() < 10, "Plonk batch verification must be < 10ms in release");
        }

        // Tampered challenge
        let u_tampered = u + random_scalar();
        assert!(!verify_plonk_batch_opening(&w_z, &w_zw, &folded_commitments, &z, &omega, &u_tampered, &srs_g2_x));
    }
}
