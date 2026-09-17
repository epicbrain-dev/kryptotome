use chrono::Utc;
use kryptotome_core::{
    curve::{g1_generator, g2_generator, random_scalar, AffineRepr, CurveGroup},
    error::{KryptotomeError, KryptotomeErrorCode},
    zkp::{ChallengeNonce, VerificationKey},
    Entitlement, Issuer, KryptotomeCredential,
};
use kryptotome_vault::{Keyring, VaultStore};
use kryptotome_verifier::EmbeddedVerifier;
use std::time::Instant;

fn make_sample_credential(id: &str, package_id: &str) -> KryptotomeCredential {
    let issuer = Issuer {
        id: "did:key:zPublisher123".to_string(),
        name: "Paizo Publishing".to_string(),
        public_key: "ed25519:abcdef0123456789".to_string(),
    };
    let entitlements = vec![Entitlement {
        package_id: package_id.to_string(),
        content_digest: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            .to_string(),
        scope: vec!["ruleset".to_string(), "compendium".to_string()],
    }];
    KryptotomeCredential::new(
        id.to_string(),
        issuer,
        "did:key:zHolderKey456".to_string(),
        "urn:kryptotome:commitment:bls12381:1234abcd".to_string(),
        entitlements,
        "signature-proof-bytes".to_string(),
    )
}

#[test]
fn test_groth16_verification_pipeline_success() {
    let mut store = VaultStore::new();
    let package_id = "paizo/pathfinder-player-core";
    let cred = make_sample_credential("cred-test-01", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let single_nonce = format!("single-use-nonce-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(package_id.to_string(), single_nonce, 300);

    // Vault generates Groth16 proof
    let zk_proof = store
        .create_proof_for_challenge(&keyring, &challenge)
        .expect("Prover must succeed");

    let mut verifier = EmbeddedVerifier::new();
    assert!(!verifier.is_package_unlocked(package_id));

    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![], // Uses default global prepared VK
    };

    let start = Instant::now();
    let is_valid = verifier
        .verify_zk_proof(&vk, &challenge, &zk_proof)
        .expect("Verification must succeed");
    let duration = start.elapsed();

    println!("Groth16 verification latency: {:?}", duration);
    assert!(is_valid, "Valid Groth16 proof must verify");
    assert!(
        verifier.is_package_unlocked(package_id),
        "Package must be unlocked after verification"
    );

    if !cfg!(debug_assertions) {
        assert!(
            duration.as_millis() < 10,
            "Verification latency {:?} must be < 10ms in release profile",
            duration
        );
    }
}

#[test]
fn test_groth16_bundle_verification_pipeline() {
    let mut store = VaultStore::new();
    let package_id = "paizo/starfinder-core";
    let cred = make_sample_credential("cred-bundle-01", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let bundle_nonce = format!("nonce-bundle-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(package_id.to_string(), bundle_nonce, 300);

    // Prover creates presentation bundle
    let bundle = store
        .create_proof_bundle_for_challenge(&keyring, &challenge)
        .expect("Bundle creation must succeed");

    let mut verifier = EmbeddedVerifier::new();
    assert!(!verifier.is_package_unlocked(package_id));

    let start = Instant::now();
    let is_valid = verifier
        .verify_proof_bundle(&bundle, &challenge)
        .expect("Bundle verification must succeed");
    let duration = start.elapsed();

    println!("Groth16 bundle verification latency: {:?}", duration);
    assert!(is_valid, "Valid bundle must verify");
    assert!(
        verifier.is_package_unlocked(package_id),
        "Package must be unlocked"
    );

    if !cfg!(debug_assertions) {
        assert!(
            duration.as_millis() < 10,
            "Bundle verification latency {:?} must be < 10ms in release profile",
            duration
        );
    }
}

#[test]
fn test_verification_fails_on_expired_challenge() {
    let mut store = VaultStore::new();
    let package_id = "paizo/pathfinder-gm-core";
    let cred = make_sample_credential("cred-expired-01", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let expired_nonce = format!("nonce-expired-{}", rand::random::<u64>());
    let valid_challenge = ChallengeNonce::new(package_id.to_string(), expired_nonce.clone(), 300);
    let zk_proof = store
        .create_proof_for_challenge(&keyring, &valid_challenge)
        .expect("Prover must succeed");

    // Construct expired challenge
    let expired_challenge = ChallengeNonce {
        nonce: expired_nonce,
        package_id: package_id.to_string(),
        timestamp: Utc::now() - chrono::Duration::seconds(600),
        expires_at: Utc::now() - chrono::Duration::seconds(10),
    };

    let mut verifier = EmbeddedVerifier::new();
    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![],
    };

    let err = verifier
        .verify_zk_proof(&vk, &expired_challenge, &zk_proof)
        .unwrap_err();

    match err {
        KryptotomeError::Detailed { code, .. } => {
            assert_eq!(code, KryptotomeErrorCode::Kryp401ChallengeExpired);
        }
        _ => panic!(
            "Expected Detailed KryptotomeError with Kryp401, got {:?}",
            err
        ),
    }
}

#[test]
fn test_verification_fails_on_package_mismatch() {
    let mut store = VaultStore::new();
    let package_id = "paizo/pathfinder-monster-core";
    let cred = make_sample_credential("cred-mismatch-01", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let mismatch_nonce = format!("nonce-mismatch-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(package_id.to_string(), mismatch_nonce.clone(), 300);
    let zk_proof = store
        .create_proof_for_challenge(&keyring, &challenge)
        .expect("Prover must succeed");

    let mismatched_challenge = ChallengeNonce::new(
        "other-publisher/other-package".to_string(),
        mismatch_nonce,
        300,
    );

    let mut verifier = EmbeddedVerifier::new();
    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![],
    };

    let err = verifier
        .verify_zk_proof(&vk, &mismatched_challenge, &zk_proof)
        .unwrap_err();

    match err {
        KryptotomeError::Detailed { code, .. } => {
            assert_eq!(code, KryptotomeErrorCode::Kryp403ChallengePackageMismatch);
        }
        _ => panic!(
            "Expected Detailed KryptotomeError with Kryp403, got {:?}",
            err
        ),
    }
}

#[test]
fn test_verification_fails_on_tampered_proof_bytes() {
    let mut store = VaultStore::new();
    let package_id = "paizo/pathfinder-lost-omens";
    let cred = make_sample_credential("cred-tamper-01", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let tamper_nonce = format!("nonce-tamper-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(package_id.to_string(), tamper_nonce, 300);
    let mut zk_proof = store
        .create_proof_for_challenge(&keyring, &challenge)
        .expect("Prover must succeed");

    // Corrupt proof bytes
    zk_proof.proof_bytes[10] ^= 0xff;

    let mut verifier = EmbeddedVerifier::new();
    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![],
    };

    let res = verifier.verify_zk_proof(&vk, &challenge, &zk_proof);
    // Either deserialization error or invalid pairing result
    assert!(res.is_err() || !res.unwrap());
}

#[test]
fn test_plonk_kzg_pairing_evaluation() {
    let verifier = EmbeddedVerifier::new();
    let g1 = g1_generator();
    let g2 = g2_generator();

    let srs_x = random_scalar();
    let srs_g2_x = (g2 * srs_x).into_affine();

    // Polynomial p(X) = a * X + b
    let a = random_scalar();
    let b = random_scalar();
    let commitment = (g1 * (a * srs_x + b)).into_affine();

    let z = random_scalar();
    let y = a * z + b;
    let proof_w = (g1 * a).into_affine();

    let start = Instant::now();
    let is_valid = verifier.verify_plonk_kzg(&commitment, &z, &y, &proof_w, &srs_g2_x);
    let duration = start.elapsed();

    println!("Plonk KZG opening verification latency: {:?}", duration);
    assert!(is_valid, "Valid KZG opening must verify");

    if !cfg!(debug_assertions) {
        assert!(
            duration.as_millis() < 10,
            "KZG verification latency {:?} must be < 10ms in release",
            duration
        );
    }

    // Tampered y must fail
    let y_tampered = y + random_scalar();
    assert!(!verifier.verify_plonk_kzg(&commitment, &z, &y_tampered, &proof_w, &srs_g2_x));
}

#[test]
fn test_plonk_batch_opening_evaluation() {
    let verifier = EmbeddedVerifier::new();
    let g1 = g1_generator();
    let g2 = g2_generator();

    let srs_x = random_scalar();
    let srs_g2_x = (g2 * srs_x).into_affine();

    let w_z = (g1 * random_scalar()).into_affine();
    let w_zw = (g1 * random_scalar()).into_affine();
    let z = random_scalar();
    let omega = random_scalar();
    let u = random_scalar();

    let zw = z * omega;
    let lhs = (w_z.into_group() + w_zw * u) * srs_x;
    let rhs_part = w_z.into_group() * z + w_zw * (u * zw);
    let folded_commitments = (lhs - rhs_part).into_affine();

    let start = Instant::now();
    let valid =
        verifier.verify_plonk_batch(&w_z, &w_zw, &folded_commitments, &z, &omega, &u, &srs_g2_x);
    let duration = start.elapsed();

    println!("Batched Plonk opening verification latency: {:?}", duration);
    assert!(valid, "Valid batched Plonk opening must pass");

    if !cfg!(debug_assertions) {
        assert!(
            duration.as_millis() < 10,
            "Batched Plonk latency {:?} must be < 10ms in release",
            duration
        );
    }
}

#[test]
fn test_verification_latency_target_sub_10ms() {
    let mut store = VaultStore::new();
    let package_id = "paizo/benchmark-package";
    let cred = make_sample_credential("cred-bench-01", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let bench_nonce = format!("nonce-bench-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(package_id.to_string(), bench_nonce, 300);

    let zk_proof = store
        .create_proof_for_challenge(&keyring, &challenge)
        .expect("Prover must succeed");

    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![],
    };

    let iterations = 10;
    let mut total_duration = std::time::Duration::ZERO;

    for _ in 0..iterations {
        let mut verifier = EmbeddedVerifier::new();
        let start = Instant::now();
        let valid = verifier
            .verify_zk_proof(&vk, &challenge, &zk_proof)
            .expect("Verification must succeed");
        let elapsed = start.elapsed();
        total_duration += elapsed;
        assert!(valid);
    }

    let avg_duration = total_duration / iterations as u32;
    println!(
        "Average Groth16 verification latency over {} runs: {:?}",
        iterations, avg_duration
    );

    if !cfg!(debug_assertions) {
        assert!(
            avg_duration.as_millis() < 10,
            "Average verification latency {:?} must be strictly < 10ms",
            avg_duration
        );
    }
}

#[test]
fn test_cache_timeout_invalidation_rule() {
    let mut verifier = EmbeddedVerifier::new();
    let pkg = "paizo/lost-omens-travel-guide";
    let digest = "sha256:fedcba9876543210";

    // Configure cache with a very short TTL: 1 second
    verifier.set_cache_ttl(chrono::Duration::seconds(1));
    verifier.cache_mut().mark_verified(pkg, digest);
    assert!(verifier.is_package_unlocked(pkg));

    // Manually mark an already expired item with negative TTL
    verifier.cache_mut().mark_verified_with_params(
        "paizo/expired-pkg",
        digest,
        chrono::Duration::seconds(-10),
        None,
    );
    assert!(!verifier.is_package_unlocked("paizo/expired-pkg"));

    // Prune sweeps expired item
    let pruned_count = verifier.prune_expired();
    assert_eq!(pruned_count, 1);
    assert!(verifier.is_package_unlocked(pkg));
}

#[test]
fn test_cache_package_reload_and_digest_invalidation_rule() {
    let mut verifier = EmbeddedVerifier::new();
    let pkg = "paizo/pathfinder-guns-and-gears";
    let digest_v1 = "sha256:aaaa111122223333";
    let digest_v2 = "sha256:bbbb444455556666";

    verifier.cache_mut().mark_verified(pkg, digest_v1);
    assert!(verifier.is_package_unlocked(pkg));

    // Package reload invalidates entry
    let reloaded = verifier.reload_package(pkg);
    assert!(reloaded);
    assert!(!verifier.is_package_unlocked(pkg));

    // Re-verify
    verifier.cache_mut().mark_verified(pkg, digest_v1);
    assert!(verifier.is_package_unlocked(pkg));

    // Content digest mismatch on asset scan
    let changed = verifier.invalidate_if_digest_mismatch(pkg, digest_v2);
    assert!(changed);
    assert!(!verifier.is_package_unlocked(pkg));

    // Same digest does not invalidate
    verifier.cache_mut().mark_verified(pkg, digest_v2);
    let unchanged = verifier.invalidate_if_digest_mismatch(pkg, digest_v2);
    assert!(!unchanged);
    assert!(verifier.is_package_unlocked(pkg));
}

#[test]
fn test_cache_game_session_exit_invalidation_rule() {
    let mut verifier = EmbeddedVerifier::new();
    verifier
        .cache_mut()
        .set_active_session_id(Some("table-session-1234".to_string()));

    verifier.cache_mut().mark_verified("pkg-1", "digest-1");
    verifier.cache_mut().mark_verified("pkg-2", "digest-2");

    assert!(verifier.is_package_unlocked("pkg-1"));
    assert!(verifier.is_package_unlocked("pkg-2"));

    // Exit active game session
    let purged = verifier.exit_session();
    assert_eq!(purged, 2);
    assert!(!verifier.is_package_unlocked("pkg-1"));
    assert!(!verifier.is_package_unlocked("pkg-2"));
}
