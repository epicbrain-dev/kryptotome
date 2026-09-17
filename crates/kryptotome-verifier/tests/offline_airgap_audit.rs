use kryptotome_core::zkp::{ChallengeNonce, VerificationKey};
use kryptotome_core::{Entitlement, Issuer, KryptotomeCredential};
use kryptotome_vault::{Keyring, VaultStore};
use kryptotome_verifier::{EmbeddedVerifier, PeerSessionClient, SessionManager};

#[test]
fn test_rust_offline_airgap_proof_verification_and_table_sharing() {
    let package_id = "paizo/pathfinder-gm-core";

    // 1. Air-Gapped Key Custody & Holder Commitment Derivation
    let user_keyring = Keyring::generate();
    assert!(!user_keyring.is_zeroized());
    let (holder_commitment_urn, _, _) = user_keyring.derive_commitment_urn();

    // 2. Air-Gapped Credential Construction & W3C VC 2.0 Compliance
    let issuer = Issuer {
        id: "did:key:zPublisherAirGapOffline".to_string(),
        name: "Paizo Offline Publisher".to_string(),
        public_key: "ed25519:abcdef0123456789abcdef0123456789".to_string(),
    };

    let entitlements = vec![Entitlement {
        package_id: package_id.to_string(),
        content_digest: "sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f"
            .to_string(),
        scope: vec![
            "rules".to_string(),
            "monsters".to_string(),
            "gm_notes".to_string(),
        ],
    }];

    let credential = KryptotomeCredential::new(
        "urn:uuid:cred-offline-airgap-rust-1".to_string(),
        issuer,
        user_keyring.key_id.clone(),
        holder_commitment_urn,
        entitlements,
        "sig-proof-bytes-offline".to_string(),
    );

    credential
        .validate_w3c_compliance()
        .expect("Credential must validate W3C VC 2.0 compliance offline");

    // 3. Air-Gapped Vault Store Ingestion & Lookup
    let mut vault = VaultStore::new();
    vault.insert_credential(credential.clone());
    assert!(vault.find_for_package(package_id).is_some());

    // 4. Air-Gapped Host Challenge Nonce Issuance
    let mut verifier = EmbeddedVerifier::new();
    assert!(!verifier.is_package_unlocked(package_id));

    let airgap_nonce = format!("offline-nonce-airgap-{}", rand::random::<u64>());
    let challenge = ChallengeNonce::new(package_id.to_string(), airgap_nonce, 300);

    // 5. Air-Gapped Groth16 Zero-Knowledge Proof Generation
    let zk_proof = vault
        .create_proof_for_challenge(&user_keyring, &challenge)
        .expect("Vault must generate Groth16 proof offline without external prover service");

    assert_eq!(zk_proof.proof_bytes.len(), 192);
    assert_eq!(zk_proof.public_inputs.package_id, package_id);
    assert_eq!(zk_proof.public_inputs.challenge_nonce, challenge.nonce);

    // 6. Air-Gapped Embedded Proof Verification (<10ms)
    let vk = VerificationKey {
        publisher_id: "paizo".to_string(),
        key_bytes: vec![], // Uses global prepared VK
    };

    let is_valid = verifier
        .verify_zk_proof(&vk, &challenge, &zk_proof)
        .expect("Embedded verifier must evaluate proof offline");
    assert!(is_valid);
    assert!(verifier.is_package_unlocked(package_id));

    // 7. Air-Gapped Table Sharing & Ephemeral Attestation Issuance
    let mut host = SessionManager::new("table-session-airgap".to_string());
    let host_pubkey = host.host_public_key_hex();
    let mut peer_client = PeerSessionClient::new("peer:player:cleric");

    let access_request = peer_client.create_access_request(package_id);
    let store_lookup = |_pkg: &str| {
        Some("sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f".to_string())
    };

    // Host handles request with local dynamic scope policy
    let access_response = host
        .handle_peer_access_request(
            &access_request,
            &store_lookup,
            Some(vec!["rules".to_string(), "monsters".to_string()]),
            Some(120),
        )
        .expect("Host must issue session attestation offline");

    // Peer client mounts compendium in local client memory
    let mounted_session = peer_client
        .process_handshake_response(&access_response, Some(&host_pubkey))
        .expect("Peer client must verify and mount session offline");

    assert!(mounted_session.is_valid());
    assert!(peer_client.is_package_mounted(package_id));

    // Dynamic scope limiting enforces player boundaries offline
    assert!(mounted_session.allows_asset_path("rules/combat.json"));
    assert!(!mounted_session.allows_asset_path("gm_notes/secrets.md"));
}
