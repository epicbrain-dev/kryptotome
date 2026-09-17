use chrono::Utc;
use kryptotome_core::{
    error::{KryptotomeError, KryptotomeErrorCode},
    zkp::{ChallengeNonce, VerificationKey},
    Entitlement, Issuer, KryptotomeCredential,
};
use kryptotome_vault::{Keyring, VaultStore};
use kryptotome_verifier::{
    EmbeddedVerifier, PeerAccessRequest, PeerSessionClient, SessionManager,
};

fn make_sample_credential(id: &str, package_id: &str) -> KryptotomeCredential {
    let issuer = Issuer {
        id: "did:key:zPublisherReplayTest".to_string(),
        name: "Test Publisher".to_string(),
        public_key: "ed25519:abcdef0123456789".to_string(),
    };
    let entitlements = vec![Entitlement {
        package_id: package_id.to_string(),
        content_digest: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
        scope: vec!["ruleset".to_string(), "compendium".to_string()],
    }];
    KryptotomeCredential::new(
        id.to_string(),
        issuer,
        "did:key:zHolderKey123".to_string(),
        "urn:kryptotome:commitment:bls12381:1234abcd".to_string(),
        entitlements,
        "signature-proof-value".to_string(),
    )
}

#[test]
fn test_verifier_zk_proof_replay_attack_rejected() {
    let mut store = VaultStore::new();
    let package_id = "paizo/pathfinder-replay-test";
    let cred = make_sample_credential("cred-replay-01", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let alpha_nonce = format!("unique-nonce-alpha-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(
        package_id.to_string(),
        alpha_nonce,
        300,
    );

    let zk_proof = store
        .create_proof_for_challenge(&keyring, &challenge)
        .expect("Prover must succeed");

    let mut verifier = EmbeddedVerifier::new();
    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![],
    };

    // First verification: must succeed
    let first_result = verifier
        .verify_zk_proof(&vk, &challenge, &zk_proof)
        .expect("First verification should succeed");
    assert!(first_result);

    // Immediate replay attack with the exact same nonce and proof: must be rejected with Kryp402
    let replay_result = verifier.verify_zk_proof(&vk, &challenge, &zk_proof);
    match replay_result {
        Err(KryptotomeError::Detailed { code, message }) => {
            println!("Got error code: {:?}, message: {}", code, message);
            assert_eq!(code, KryptotomeErrorCode::Kryp402NonceReplayDetected);
            assert!(message.contains("already been consumed") || message.contains("replay"));
        }
        other => panic!("Expected Kryp402NonceReplayDetected, got: {:?}", other),
    }

    // A fresh nonce with new proof should succeed
    let beta_nonce = format!("unique-nonce-beta-{}", rand::random::<u64>());
    let fresh_challenge = ChallengeNonce::new(
        package_id.to_string(),
        beta_nonce,
        300,
    );
    let fresh_proof = store
        .create_proof_for_challenge(&keyring, &fresh_challenge)
        .expect("Prover must succeed for fresh challenge");
    let fresh_result = verifier
        .verify_zk_proof(&vk, &fresh_challenge, &fresh_proof)
        .expect("Fresh verification should succeed");
    assert!(fresh_result);
}

#[test]
fn test_verifier_proof_bundle_replay_attack_rejected() {
    let mut store = VaultStore::new();
    let package_id = "paizo/bundle-replay-test";
    let cred = make_sample_credential("cred-replay-02", package_id);
    store.insert_credential(cred);

    let keyring = Keyring::generate();
    let bundle_nonce = format!("unique-bundle-nonce-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(
        package_id.to_string(),
        bundle_nonce,
        300,
    );

    let bundle = store
        .create_proof_bundle_for_challenge(&keyring, &challenge)
        .expect("Bundle creation must succeed");

    let mut verifier = EmbeddedVerifier::new();

    // First verification succeeds
    let first_result = verifier
        .verify_proof_bundle(&bundle, &challenge)
        .expect("First bundle verification should succeed");
    assert!(first_result);

    // Replay attack with exact same bundle and challenge: must fail with Kryp402
    let replay_result = verifier.verify_proof_bundle(&bundle, &challenge);
    match replay_result {
        Err(KryptotomeError::Detailed { code, message }) => {
            assert_eq!(code, KryptotomeErrorCode::Kryp402NonceReplayDetected);
            assert!(message.contains("already been consumed") || message.contains("replay"));
        }
        other => panic!("Expected Kryp402NonceReplayDetected, got: {:?}", other),
    }
}

#[test]
fn test_expired_challenge_nonce_rejected_before_replay() {
    let mut store = VaultStore::new();
    let package_id = "paizo/expired-replay-test";
    let cred = make_sample_credential("cred-replay-03", package_id);
    store.insert_credential(cred);

    let _keyring = Keyring::generate();
    // Challenge expired 10 seconds ago
    let expired_nonce = format!("expired-nonce-{}", rand::random::<u64>());
    let mut challenge = ChallengeNonce::new(
        package_id.to_string(),
        expired_nonce,
        -10,
    );
    challenge.expires_at = Utc::now() - chrono::Duration::seconds(10);

    let mut verifier = EmbeddedVerifier::new();
    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![],
    };

    // Construct dummy proof with the expired nonce
    let zk_proof = kryptotome_core::zkp::ZkProof {
        proof_bytes: vec![0u8; 192],
        public_inputs: kryptotome_core::zkp::ProofInputs {
            challenge_nonce: challenge.nonce.clone(),
            package_id: package_id.to_string(),
            content_digest: "sha256:dummy".to_string(),
            publisher_pubkey_hash: "dummy".to_string(),
            holder_commitment: None,
        },
    };

    let result = verifier.verify_zk_proof(&vk, &challenge, &zk_proof);
    match result {
        Err(KryptotomeError::Detailed { code, message }) => {
            assert_eq!(code, KryptotomeErrorCode::Kryp401ChallengeExpired);
            assert!(message.contains("expired"));
        }
        other => panic!("Expected Kryp401ChallengeExpired, got: {:?}", other),
    }
}

#[test]
fn test_session_handshake_access_request_replay_rejected() {
    let mut session_mgr = SessionManager::new("session-replay-table-1".to_string());
    let package_id = "paizo/handshake-replay-test";
    let provider = |_pkg: &str| Some("sha256:validcontentdigest".to_string());

    let fixed_handshake_nonce = format!("fixed-handshake-nonce-{}", rand::random::<u64>());
    let request = PeerAccessRequest::with_nonce(
        "peer-alice",
        package_id,
        &fixed_handshake_nonce,
    );

    // First request: valid, returns signed attestation
    let response1 = session_mgr
        .handle_peer_access_request(&request, &provider, None, None)
        .expect("First handshake request must succeed");
    assert_eq!(response1.nonce, fixed_handshake_nonce);

    // Replay request with the same nonce: must be rejected with Kryp402
    let replay_result = session_mgr.handle_peer_access_request(&request, &provider, None, None);
    match replay_result {
        Err(KryptotomeError::Detailed { code, message }) => {
            assert_eq!(code, KryptotomeErrorCode::Kryp402NonceReplayDetected);
            assert!(message.contains("already consumed"));
        }
        other => panic!("Expected Kryp402NonceReplayDetected, got: {:?}", other),
    }

    // Fresh request with a different nonce succeeds
    let fresh_handshake_nonce = format!("fresh-handshake-nonce-{}", rand::random::<u64>());
    let fresh_request = PeerAccessRequest::with_nonce(
        "peer-alice",
        package_id,
        &fresh_handshake_nonce,
    );
    let response2 = session_mgr
        .handle_peer_access_request(&fresh_request, &provider, None, None)
        .expect("Fresh handshake request must succeed");
    assert_eq!(response2.nonce, fresh_handshake_nonce);
}

#[test]
fn test_session_renewal_nonce_replay_rejected() {
    let mut session_mgr = SessionManager::new("session-replay-table-2".to_string());
    let package_id = "paizo/renewal-replay-test";
    let provider = |_pkg: &str| Some("sha256:validcontentdigest".to_string());

    // 1. Initial handshake
    let mut client = PeerSessionClient::new("peer-bob");
    let initial_req = client.create_access_request(package_id);
    let initial_resp = session_mgr
        .handle_peer_access_request(&initial_req, &provider, None, None)
        .expect("Initial access must succeed");
    client
        .process_handshake_response(&initial_resp, None)
        .expect("Client mount must succeed");

    // 2. First renewal request created via client
    let mut renewal_req = client
        .create_renewal_request(package_id)
        .expect("Create renewal request must succeed");
    let fixed_renewal_nonce = format!("renewal-fixed-nonce-{}", rand::random::<u64>());
    renewal_req.renewal_nonce = fixed_renewal_nonce.clone();

    let renewal_resp = session_mgr
        .handle_session_renewal(&renewal_req, None)
        .expect("First renewal must succeed");
    assert_eq!(renewal_resp.nonce, fixed_renewal_nonce);

    // 3. Replay renewal with same renewal nonce: must be rejected with Kryp402
    let replay_result = session_mgr.handle_session_renewal(&renewal_req, None);
    match replay_result {
        Err(KryptotomeError::Detailed { code, message }) => {
            assert_eq!(code, KryptotomeErrorCode::Kryp402NonceReplayDetected);
            assert!(message.contains("already consumed"));
        }
        other => panic!("Expected Kryp402NonceReplayDetected, got: {:?}", other),
    }

    // 4. Fresh renewal nonce succeeds
    let mut fresh_renewal_req = renewal_req.clone();
    let fresh_renewal_nonce = format!("renewal-fresh-nonce-{}", rand::random::<u64>());
    fresh_renewal_req.renewal_nonce = fresh_renewal_nonce.clone();
    let fresh_renewal_resp = session_mgr
        .handle_session_renewal(&fresh_renewal_req, None)
        .expect("Fresh renewal must succeed");
    assert_eq!(fresh_renewal_resp.nonce, fresh_renewal_nonce);
}
