use ark_bls12_381::Bls12_381;
use ark_groth16::Proof;
use kryptotome_core::{
    circuit::{
        deserialize_pk_compressed, deserialize_proof_compressed,
        deserialize_public_inputs_compressed, deserialize_vk_compressed,
        get_or_init_entitlement_setup, serialize_proof_compressed, EntitlementProofBundle,
    },
    zkp::{ProofInputs, ZkProof},
};
use rand::{Rng, RngCore, SeedableRng};

/// Pseudo-random mutation generator for fuzzing
struct Mutator<R: RngCore> {
    rng: R,
}

impl<R: RngCore> Mutator<R> {
    fn new(rng: R) -> Self {
        Self { rng }
    }

    /// Generates completely random byte slice
    fn random_bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.rng.gen_range(0..=max_len);
        let mut buf = vec![0u8; len];
        self.rng.fill_bytes(&mut buf);
        buf
    }

    /// Mutates an existing valid buffer with bit flips, insertions, deletions, truncations
    fn mutate(&mut self, original: &[u8]) -> Vec<u8> {
        if original.is_empty() {
            return self.random_bytes(64);
        }

        let mut data = original.to_vec();
        let mutation_type = self.rng.gen_range(0..6);

        match mutation_type {
            0 => {
                // Bit flip
                let byte_idx = self.rng.gen_range(0..data.len());
                let bit_idx = self.rng.gen_range(0..8);
                data[byte_idx] ^= 1 << bit_idx;
            }
            1 => {
                // Truncation
                let cut_point = self.rng.gen_range(0..data.len());
                data.truncate(cut_point);
            }
            2 => {
                // Byte replacement with boundary values (0x00, 0xFF, 0x80, 0x7F)
                let byte_idx = self.rng.gen_range(0..data.len());
                let boundary_bytes = [0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE];
                let chosen = boundary_bytes[self.rng.gen_range(0..boundary_bytes.len())];
                data[byte_idx] = chosen;
            }
            3 => {
                // Byte insertion
                let insert_idx = self.rng.gen_range(0..=data.len());
                let val = self.rng.gen::<u8>();
                data.insert(insert_idx, val);
            }
            4 => {
                // Zero-out slice
                if data.len() > 4 {
                    let start = self.rng.gen_range(0..data.len() - 4);
                    let len = self.rng.gen_range(1..=(data.len() - start));
                    for b in &mut data[start..start + len] {
                        *b = 0;
                    }
                }
            }
            _ => {
                // Append random suffix
                let extra = self.random_bytes(32);
                data.extend_from_slice(&extra);
            }
        }
        data
    }
}

#[test]
fn test_fuzz_proof_deserialization_panic_freedom() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdead_beef_0001);
    let mut mutator = Mutator::new(&mut rng);

    // Create a real valid 192-byte proof to use as seed
    let (pk, _) = get_or_init_entitlement_setup();
    let blank_proof: Proof<Bls12_381> = Proof {
        a: pk.vk.alpha_g1,
        b: pk.vk.beta_g2,
        c: pk.vk.alpha_g1,
    };
    let seed_proof_bytes = serialize_proof_compressed(&blank_proof).unwrap();
    assert_eq!(seed_proof_bytes.len(), 192);

    let iterations = 1000;
    let mut rejected_count = 0;

    for _ in 0..iterations {
        // 50% mutated from seed, 50% pure random bytes
        let hostile_bytes = if mutator.rng.gen_bool(0.5) {
            mutator.mutate(&seed_proof_bytes)
        } else {
            mutator.random_bytes(256)
        };

        // Must never panic on untrusted inputs
        let result = deserialize_proof_compressed(&hostile_bytes);
        if result.is_err() {
            rejected_count += 1;
        }
    }

    println!(
        "Fuzz Proof Deserialization: tested {} inputs, safely rejected {} without panicking",
        iterations, rejected_count
    );
    assert!(
        rejected_count > 900,
        "Hostile inputs must be rejected safely"
    );
}

#[test]
fn test_fuzz_presentation_bundle_deserialization_panic_freedom() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdead_beef_0002);
    let mut mutator = Mutator::new(&mut rng);

    // Valid bundle seed
    let (pk, _) = get_or_init_entitlement_setup();
    let blank_proof: Proof<Bls12_381> = Proof {
        a: pk.vk.alpha_g1,
        b: pk.vk.beta_g2,
        c: pk.vk.alpha_g1,
    };
    let seed_bundle = EntitlementProofBundle::new(
        &blank_proof,
        &[kryptotome_core::curve::ScalarField::from(1u64)],
        "test/pkg",
        "sha256:abcd",
        "nonce123",
        "urn:kryptotome:commitment:bls12381:1234",
    )
    .unwrap();
    let seed_bytes = seed_bundle.to_compact_bytes().unwrap();

    let iterations = 1000;
    let mut rejected_count = 0;

    for _ in 0..iterations {
        let hostile_bytes = if mutator.rng.gen_bool(0.5) {
            mutator.mutate(&seed_bytes)
        } else {
            mutator.random_bytes(512)
        };

        // Must never panic on untrusted inputs
        let result = EntitlementProofBundle::from_compact_bytes(&hostile_bytes);
        if result.is_err() {
            rejected_count += 1;
        }

        // Also test JSON deserialization with hostile bytes
        let _ = serde_json::from_slice::<EntitlementProofBundle>(&hostile_bytes);
    }

    println!(
        "Fuzz Bundle Deserialization: tested {} inputs, safely rejected {} without panicking",
        iterations, rejected_count
    );
    assert!(
        rejected_count > 500,
        "Corrupted inputs must be rejected safely without panics"
    );
}

#[test]
fn test_fuzz_verifying_key_and_public_inputs_panic_freedom() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdead_beef_0003);
    let mut mutator = Mutator::new(&mut rng);

    let iterations = 1000;
    for _ in 0..iterations {
        let hostile_bytes = mutator.random_bytes(384);

        // Fuzz VK deserializer
        let _ = deserialize_vk_compressed(&hostile_bytes);

        // Fuzz PK deserializer
        let _ = deserialize_pk_compressed(&hostile_bytes);

        // Fuzz public inputs deserializer
        let _ = deserialize_public_inputs_compressed(&hostile_bytes);
    }
}

#[test]
fn test_fuzz_zkproof_base64_parser_panic_freedom() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdead_beef_0004);
    let mut mutator = Mutator::new(&mut rng);

    let dummy_inputs = ProofInputs {
        challenge_nonce: "test_nonce".to_string(),
        package_id: "test/pkg".to_string(),
        content_digest: "sha256:0000".to_string(),
        publisher_pubkey_hash: "pubkey".to_string(),
        holder_commitment: None,
    };

    let iterations = 1000;
    let mut rejected_count = 0;

    for _ in 0..iterations {
        let hostile_bytes = mutator.random_bytes(256);
        let s = String::from_utf8_lossy(&hostile_bytes);

        let result = ZkProof::from_base64(&s, dummy_inputs.clone());
        if result.is_err() {
            rejected_count += 1;
        }
    }

    println!(
        "Fuzz Base64 Proof Parser: tested {} inputs, safely rejected {} without panicking",
        iterations, rejected_count
    );
    assert!(rejected_count > 900);
}
