use ark_bls12_381::Bls12_381;
use ark_groth16::Proof;
use ark_serialize::CanonicalSerialize;
use kryptotome_core::{
    circuit::{
        get_or_init_entitlement_prepared_vk, get_or_init_entitlement_setup,
        prove_entitlement_for_credential, serialize_proof_compressed,
        verify_entitlement_proof_prepared,
    },
    credential::{Entitlement, Issuer, KryptotomeCredential},
    zkp::ChallengeNonce,
};
use rand::SeedableRng;
use std::collections::HashSet;

fn make_sample_credential(
    id: &str,
    package_id: &str,
    holder_pub: &str,
    commitment_urn: &str,
) -> KryptotomeCredential {
    let issuer = Issuer {
        id: "did:key:zPublisherUnlinkabilityTest".to_string(),
        name: "Test Publisher".to_string(),
        public_key: "ed25519:abcdef0123456789".to_string(),
    };
    let entitlements = vec![Entitlement {
        package_id: package_id.to_string(),
        content_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        scope: vec!["core_rules".to_string()],
    }];
    KryptotomeCredential::new(
        id.to_string(),
        issuer,
        holder_pub.to_string(),
        commitment_urn.to_string(),
        entitlements,
        "valid_signature".to_string(),
    )
}

/// Computes Shannon entropy in bits per byte (max = 8.0)
fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes bitwise Hamming distance between two byte slices of equal length
fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones() as usize)
        .sum()
}

#[test]
fn test_groth16_proof_point_randomization_across_challenges() {
    let (pk, _) = get_or_init_entitlement_setup();
    let package_id = "paizo/unlinkability-test-mod";
    let cred = make_sample_credential(
        "cred-unlink-01",
        package_id,
        "did:key:zHolder1",
        "urn:kryptotome:commitment:bls12381:deadbeefcafe",
    );
    let entitlement = &cred.credential_subject.entitlements[0];
    let secret_bytes = b"user_secret_key_fixed_identity_42!";

    let num_challenges = 10;
    let mut proofs: Vec<Proof<Bls12_381>> = Vec::with_capacity(num_challenges);
    let mut serialized_proofs: Vec<Vec<u8>> = Vec::with_capacity(num_challenges);

    let mut a_points = HashSet::new();
    let mut b_points = HashSet::new();
    let mut c_points = HashSet::new();

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x1337_c0de);

    for i in 0..num_challenges {
        let challenge = ChallengeNonce::new(
            package_id.to_string(),
            format!("challenge-nonce-{:04}", i),
            300,
        );

        let (proof, _public_inputs) = prove_entitlement_for_credential(
            pk,
            secret_bytes,
            &challenge,
            entitlement,
            &cred.issuer.public_key,
            &cred.credential_subject.holder_commitment,
            &mut rng,
        )
        .expect("Prover must succeed");

        // Serialize points to test uniqueness
        let mut a_bytes = Vec::new();
        proof.a.serialize_compressed(&mut a_bytes).unwrap();
        let mut b_bytes = Vec::new();
        proof.b.serialize_compressed(&mut b_bytes).unwrap();
        let mut c_bytes = Vec::new();
        proof.c.serialize_compressed(&mut c_bytes).unwrap();

        assert!(
            a_points.insert(a_bytes),
            "Point A must be unique across challenges"
        );
        assert!(
            b_points.insert(b_bytes),
            "Point B must be unique across challenges"
        );
        assert!(
            c_points.insert(c_bytes),
            "Point C must be unique across challenges"
        );

        let raw_bytes = serialize_proof_compressed(&proof).expect("Serialization succeeds");
        serialized_proofs.push(raw_bytes);
        proofs.push(proof);
    }

    // 1. Uniqueness Guarantee: All 10 proofs for the same holder are completely distinct
    assert_eq!(a_points.len(), num_challenges);
    assert_eq!(b_points.len(), num_challenges);
    assert_eq!(c_points.len(), num_challenges);

    // 2. High Shannon Entropy Guarantee:
    // For a single 192-byte proof, the theoretical maximum entropy is log2(192) = 7.585 bits/byte.
    // Each proof achieves > 6.50 bits/byte (> 85% theoretical max for 192-byte sample).
    for (i, bytes) in serialized_proofs.iter().enumerate() {
        let entropy = compute_shannon_entropy(bytes);
        println!("Proof #{} 192-byte entropy: {:.3} bits/byte", i, entropy);
        assert!(
            entropy > 6.50,
            "Proof #{} entropy {:.3} must be > 6.50 bits/byte (sample max = 7.585)",
            i,
            entropy
        );
    }

    // Over the concatenated 1,920-byte proof stream, all 256 byte values appear uniformly (> 7.80 bits/byte)
    let combined_bytes: Vec<u8> = serialized_proofs.concat();
    let combined_entropy = compute_shannon_entropy(&combined_bytes);
    println!(
        "Combined 10-proof byte stream Shannon entropy: {:.4} bits/byte (max = 8.000)",
        combined_entropy
    );
    assert!(
        combined_entropy > 7.80,
        "Combined proof stream entropy {:.4} must be > 7.80 bits/byte",
        combined_entropy
    );
}

#[test]
fn test_hamming_distance_indistinguishability_statistical_unlinkability() {
    let (pk, _) = get_or_init_entitlement_setup();
    let package_id = "paizo/cluster-test";

    // User A credentials & secret
    let cred_a = make_sample_credential(
        "cred-a",
        package_id,
        "did:key:zHolderAlice",
        "urn:kryptotome:commitment:bls12381:alice_commit",
    );
    let secret_a = b"alice_very_secret_master_key_9999!";

    // User B credentials & secret
    let cred_b = make_sample_credential(
        "cred-b",
        package_id,
        "did:key:zHolderBob",
        "urn:kryptotome:commitment:bls12381:bob_commitment",
    );
    let secret_b = b"bob_very_secret_master_key_888888!";

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4242_1111);
    let num_samples = 6;

    let mut proofs_a: Vec<Vec<u8>> = Vec::new();
    let mut proofs_b: Vec<Vec<u8>> = Vec::new();

    for i in 0..num_samples {
        let challenge =
            ChallengeNonce::new(package_id.to_string(), format!("stat-nonce-{:04}", i), 300);

        let (proof_a, _) = prove_entitlement_for_credential(
            pk,
            secret_a,
            &challenge,
            &cred_a.credential_subject.entitlements[0],
            &cred_a.issuer.public_key,
            &cred_a.credential_subject.holder_commitment,
            &mut rng,
        )
        .unwrap();

        let (proof_b, _) = prove_entitlement_for_credential(
            pk,
            secret_b,
            &challenge,
            &cred_b.credential_subject.entitlements[0],
            &cred_b.issuer.public_key,
            &cred_b.credential_subject.holder_commitment,
            &mut rng,
        )
        .unwrap();

        proofs_a.push(serialize_proof_compressed(&proof_a).unwrap());
        proofs_b.push(serialize_proof_compressed(&proof_b).unwrap());
    }

    // Measure intra-identity Hamming distances (Alice vs Alice across challenges)
    let total_bits = proofs_a[0].len() * 8; // 192 bytes * 8 = 1536 bits
    let mut intra_distances = Vec::new();
    for i in 0..num_samples {
        for j in (i + 1)..num_samples {
            let dist = hamming_distance(&proofs_a[i], &proofs_a[j]);
            intra_distances.push(dist as f64 / total_bits as f64);
        }
    }

    // Measure inter-identity Hamming distances (Alice vs Bob across challenges)
    let mut inter_distances = Vec::new();
    for pa in &proofs_a {
        for pb in &proofs_b {
            let dist = hamming_distance(pa, pb);
            inter_distances.push(dist as f64 / total_bits as f64);
        }
    }

    let avg_intra: f64 = intra_distances.iter().sum::<f64>() / intra_distances.len() as f64;
    let avg_inter: f64 = inter_distances.iter().sum::<f64>() / inter_distances.len() as f64;

    println!(
        "Mean Intra-Identity (Same User) Hamming Distance Ratio: {:.4} (expect ~0.5000)",
        avg_intra
    );
    println!(
        "Mean Inter-Identity (Different Users) Hamming Distance Ratio: {:.4} (expect ~0.5000)",
        avg_inter
    );

    // Both distributions must center around 50% bit variance (0.47 to 0.53)
    assert!(
        (avg_intra - 0.50).abs() < 0.03,
        "Intra-identity proof distance {:.4} must be ~0.50",
        avg_intra
    );
    assert!(
        (avg_inter - 0.50).abs() < 0.03,
        "Inter-identity proof distance {:.4} must be ~0.50",
        avg_inter
    );

    // The difference between intra and inter clustering must be negligible (< 2%)
    let divergence = (avg_intra - avg_inter).abs();
    assert!(
        divergence < 0.02,
        "Divergence between intra ({:.4}) and inter ({:.4}) is {:.4}, exceeding 0.02 threshold! Linkability cluster detected!",
        avg_intra, avg_inter, divergence
    );
}

#[test]
fn test_prepared_verification_succeeds_for_all_randomized_proofs() {
    let (pk, _) = get_or_init_entitlement_setup();
    let pvk = get_or_init_entitlement_prepared_vk();
    let package_id = "paizo/verify-all-randomized";
    let cred = make_sample_credential(
        "cred-verify-all",
        package_id,
        "did:key:zHolderBob",
        "urn:kryptotome:commitment:bls12381:bob_commitment",
    );
    let secret = b"super_secret_seed_9999999999999999";
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x9999_8888);

    for i in 0..5 {
        let challenge =
            ChallengeNonce::new(package_id.to_string(), format!("rnd-nonce-{:03}", i), 300);

        let (proof, public_inputs) = prove_entitlement_for_credential(
            pk,
            secret,
            &challenge,
            &cred.credential_subject.entitlements[0],
            &cred.issuer.public_key,
            &cred.credential_subject.holder_commitment,
            &mut rng,
        )
        .unwrap();

        let valid = verify_entitlement_proof_prepared(pvk, &public_inputs, &proof)
            .expect("Verification must not error");
        assert!(valid, "Proof #{} must verify successfully", i);
    }
}
