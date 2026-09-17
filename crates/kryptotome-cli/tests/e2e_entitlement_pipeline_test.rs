use ed25519_dalek::SigningKey;
use kryptotome_cli::publisher::{verify_package_manifest, PackageLicense, PublisherToolchain};
use kryptotome_cli::scanner::ScanOptions;
use kryptotome_core::digest::DigestAlgorithm;
use kryptotome_core::zkp::{ChallengeNonce, VerificationKey};
use kryptotome_core::{Entitlement, Issuer, KryptotomeCredential};
use kryptotome_vault::{Keyring, VaultStore};
use kryptotome_verifier::EmbeddedVerifier;
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

struct TestModuleFixture {
    root_dir: PathBuf,
}

impl TestModuleFixture {
    fn new(name: &str) -> Self {
        let root_dir = std::env::temp_dir().join(format!("ktome_e2e_{}_{}", name, rand::random::<u64>()));
        fs::create_dir_all(&root_dir).expect("Failed to create module root dir");

        let rules_dir = root_dir.join("rules");
        fs::create_dir_all(&rules_dir).expect("Failed to create rules dir");
        let mut f1 = File::create(rules_dir.join("spells.json")).unwrap();
        f1.write_all(b"{\"spells\": [\"fireball\", \"heal\", \"teleport\"]}\n").unwrap();

        let assets_dir = root_dir.join("assets");
        fs::create_dir_all(&assets_dir).expect("Failed to create assets dir");
        let mut f2 = File::create(assets_dir.join("token.png")).unwrap();
        f2.write_all(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").unwrap();

        Self { root_dir }
    }
}

impl Drop for TestModuleFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

#[test]
fn test_end_to_end_entitlement_pipeline() {
    // =========================================================================
    // STEP 1: Publisher Signs Package
    // =========================================================================
    let fixture = TestModuleFixture::new("pf2e_advanced_spells");
    let package_id = "paizo/pf2e-advanced-spells";
    let package_title = "Pathfinder 2e Advanced Spells Compendium";
    let version = "1.0.0";
    let publisher_name = "Paizo Inc.";

    let mut csprng = OsRng;
    let publisher_signing_key = SigningKey::generate(&mut csprng);
    let publisher_verifying_key = publisher_signing_key.verifying_key();
    let publisher_pubkey_hex = publisher_verifying_key
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let publisher_id = format!("did:key:z{}", &publisher_pubkey_hex[..16]);

    let toolchain = PublisherToolchain::new(publisher_signing_key);
    let manifest = toolchain
        .build_and_sign_package_with_license(
            package_id,
            package_title,
            version,
            publisher_name,
            &fixture.root_dir,
            ScanOptions {
                algorithm: DigestAlgorithm::Sha256,
                show_progress: false,
            },
            PackageLicense::new_orc(publisher_name),
        )
        .expect("Publisher package signing must succeed");

    assert_eq!(manifest.package_id, package_id);
    assert!(manifest.signature.is_some(), "Manifest must be cryptographically signed");

    // Verify publisher signature on manifest
    let report = verify_package_manifest(&manifest, Some(&publisher_pubkey_hex))
        .expect("Manifest verification must succeed");
    assert!(report.is_valid, "Manifest signature must be valid");
    assert_eq!(report.root_digest, manifest.root_digest);

    let content_digest = manifest.root_digest.clone();
    assert!(!content_digest.is_empty());

    // =========================================================================
    // STEP 2: User Imports Credential
    // =========================================================================
    // User generates local custody Keyring (private key never leaves vault)
    let user_keyring = Keyring::generate();
    assert!(!user_keyring.is_zeroized());
    let user_holder_did = user_keyring.key_id.clone();
    let (holder_commitment_urn, _secret, _blinding) = user_keyring.derive_commitment_urn();

    // Publisher issues W3C-compliant Verifiable Credential bound to user's holder commitment
    let issuer = Issuer {
        id: publisher_id,
        name: publisher_name.to_string(),
        public_key: format!("ed25519:{}", publisher_pubkey_hex),
    };

    let entitlements = vec![Entitlement {
        package_id: package_id.to_string(),
        content_digest: content_digest.clone(),
        scope: vec!["spells".to_string(), "rules".to_string()],
    }];

    let credential = KryptotomeCredential::new(
        format!("urn:uuid:{}", rand::random::<u128>()),
        issuer,
        user_holder_did,
        holder_commitment_urn,
        entitlements,
        "sig-publisher-ed25519-proof-bytes".to_string(),
    );

    // Verify W3C compliance
    credential
        .validate_w3c_compliance()
        .expect("Credential must strictly adhere to W3C VC 2.0 specifications");

    // User initializes VaultStore and imports credential
    let mut user_vault = VaultStore::new();
    user_vault.insert_credential(credential.clone());

    // Verify credential lookup in vault
    assert_eq!(user_vault.credentials.len(), 1);
    let imported_cred = user_vault
        .find_for_package(package_id)
        .expect("User vault must contain credential for package");
    assert_eq!(imported_cred.id, credential.id);

    // =========================================================================
    // STEP 3: Host Issues Challenge
    // =========================================================================
    let mut verifier = EmbeddedVerifier::new();
    assert!(
        !verifier.is_package_unlocked(package_id),
        "Package must initially be locked on host"
    );

    let host_nonce_str = format!("challenge-nonce-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(package_id.to_string(), host_nonce_str.clone(), 300);
    assert!(!challenge.is_expired());

    // =========================================================================
    // STEP 4: Vault Generates Proof
    // =========================================================================
    // User vault creates a single-use Groth16 zero-knowledge proof for the host's challenge
    let zk_proof = user_vault
        .create_proof_for_challenge(&user_keyring, &challenge)
        .expect("Vault must generate valid ZK proof for challenge");

    assert_eq!(zk_proof.proof_bytes.len(), 192);
    assert_eq!(zk_proof.public_inputs.package_id, package_id);
    assert_eq!(zk_proof.public_inputs.challenge_nonce, host_nonce_str);

    // =========================================================================
    // STEP 5: Verifier Confirms Valid
    // =========================================================================
    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![], // Uses default prepared VK
    };

    let is_valid = verifier
        .verify_zk_proof(&vk, &challenge, &zk_proof)
        .expect("Verification must succeed");
    assert!(is_valid, "Verifier must confirm Groth16 proof is valid");

    // Compendium module is now unlocked on host
    assert!(
        verifier.is_package_unlocked(package_id),
        "Host must mark package unlocked after successful proof verification"
    );

    // =========================================================================
    // STEP 6: Replay Immunity Enforcement
    // =========================================================================
    // Replay attack: Re-submitting the consumed challenge nonce is rejected with Kryp402
    let replay_err = verifier
        .verify_zk_proof(&vk, &challenge, &zk_proof)
        .unwrap_err();
    match replay_err {
        kryptotome_core::KryptotomeError::Detailed { code, .. } => {
            assert_eq!(code, kryptotome_core::error::KryptotomeErrorCode::Kryp402NonceReplayDetected);
        }
        _ => panic!("Expected Kryp402NonceReplayDetected, got {:?}", replay_err),
    }

    // =========================================================================
    // STEP 7: Presentation Bundle End-to-End Flow
    // =========================================================================
    // Host issues a fresh challenge for presentation bundle verification
    let bundle_nonce_str = format!("bundle-nonce-{}", rand::random::<u64>());
    let bundle_challenge = ChallengeNonce::new(package_id.to_string(), bundle_nonce_str.clone(), 300);

    let proof_bundle = user_vault
        .create_proof_bundle_for_challenge(&user_keyring, &bundle_challenge)
        .expect("Vault must generate presentation bundle");
    assert_eq!(proof_bundle.package_id, package_id);
    assert_eq!(proof_bundle.challenge_nonce, bundle_nonce_str);

    let is_bundle_valid = verifier
        .verify_proof_bundle(&proof_bundle, &bundle_challenge)
        .expect("Bundle verification must succeed");
    assert!(is_bundle_valid, "Verifier must confirm presentation bundle is valid");

    // =========================================================================
    // STEP 8: Negative Verification Security Checks
    // =========================================================================
    // A) Tampered challenge nonce rejected
    let security_challenge = ChallengeNonce::new(
        package_id.to_string(),
        format!("security-nonce-{}", rand::random::<u64>()),
        300,
    );
    let fresh_proof = user_vault
        .create_proof_for_challenge(&user_keyring, &security_challenge)
        .unwrap();

    let tampered_challenge = ChallengeNonce::new(
        package_id.to_string(),
        format!("tampered-nonce-{}", rand::random::<u64>()),
        300,
    );
    let tampered_res = verifier.verify_zk_proof(&vk, &tampered_challenge, &fresh_proof);
    assert!(
        tampered_res.is_err(),
        "Verification must fail when challenge nonce doesn't match public inputs"
    );

    // B) Tampered proof bytes rejected
    let mut tampered_proof = fresh_proof.clone();
    tampered_proof.proof_bytes[0] ^= 0xFF;
    let tampered_proof_res = verifier.verify_zk_proof(&vk, &security_challenge, &tampered_proof);
    assert!(
        tampered_proof_res.is_err(),
        "Verification must fail when proof bytes are tampered"
    );
}
