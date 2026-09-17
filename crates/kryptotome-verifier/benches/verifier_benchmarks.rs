use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kryptotome_core::{
    zkp::{ChallengeNonce, VerificationKey},
    Entitlement, Issuer, KryptotomeCredential,
};
use kryptotome_vault::{Keyring, VaultStore};
use kryptotome_verifier::EmbeddedVerifier;

fn make_benchmark_credential(package_id: &str) -> KryptotomeCredential {
    let issuer = Issuer {
        id: "did:key:zPublisher123".to_string(),
        name: "Paizo Publishing".to_string(),
        public_key: "ed25519:abcdef0123456789".to_string(),
    };
    let entitlements = vec![Entitlement {
        package_id: package_id.to_string(),
        content_digest: "sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f".to_string(),
        scope: vec!["ruleset".to_string(), "compendium".to_string()],
    }];
    KryptotomeCredential::new(
        "cred-bench-01".to_string(),
        issuer,
        "did:key:zHolderKey456".to_string(),
        "urn:kryptotome:commitment:bls12381:1234abcd".to_string(),
        entitlements,
        "signature-proof-bytes".to_string(),
    )
}

fn bench_zk_verification(c: &mut Criterion) {
    let package_id = "paizo/pathfinder-player-core";
    let mut store = VaultStore::new();
    let cred = make_benchmark_credential(package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let challenge_nonce = format!("bench-single-use-nonce-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(
        package_id.to_string(),
        challenge_nonce,
        300,
    );

    let zk_proof = store
        .create_proof_for_challenge(&keyring, &challenge)
        .expect("Prover must succeed");

    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![],
    };

    let mut verifier = EmbeddedVerifier::new();

    c.bench_function("zk_proof_verification_latency_target_sub_10ms", |b| {
        b.iter(|| {
            let res = verifier
                .verify_zk_proof(black_box(&vk), black_box(&challenge), black_box(&zk_proof))
                .expect("Verification must succeed");
            assert!(res);
        })
    });
}

fn bench_zk_proving(c: &mut Criterion) {
    let package_id = "paizo/pathfinder-player-core";
    let mut store = VaultStore::new();
    let cred = make_benchmark_credential(package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let proving_nonce = format!("bench-proving-nonce-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(
        package_id.to_string(),
        proving_nonce,
        300,
    );

    c.bench_function("zk_proof_generation_latency_target_sub_200ms", |b| {
        b.iter(|| {
            let proof = store
                .create_proof_for_challenge(black_box(&keyring), black_box(&challenge))
                .expect("Proof generation must succeed");
            black_box(proof);
        })
    });
}

fn bench_cache_lookup(c: &mut Criterion) {
    let mut verifier = EmbeddedVerifier::new();
    let package_id = "paizo/cached-package";
    verifier.cache_mut().mark_verified(package_id, "sha256:digest");

    c.bench_function("verifier_cache_lookup_latency", |b| {
        b.iter(|| {
            let unlocked = verifier.is_package_unlocked(black_box(package_id));
            assert!(unlocked);
        })
    });
}

criterion_group!(
    benches,
    bench_zk_verification,
    bench_zk_proving,
    bench_cache_lookup
);
criterion_main!(benches);
