use kryptotome_core::credential::{Entitlement, Issuer, KryptotomeCredential};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode};
use kryptotome_vault::VaultStore;
use kryptotome_verifier::{
    EntitlementProvider, PeerSessionClient, SessionManager,
};

struct VaultEntitlementProvider<'a>(&'a VaultStore);

impl<'a> EntitlementProvider for VaultEntitlementProvider<'a> {
    fn get_package_entitlement(&self, package_id: &str) -> Option<String> {
        self.0.find_for_package(package_id).and_then(|cred| {
            cred.credential_subject
                .entitlements
                .iter()
                .find(|e| e.package_id == package_id)
                .map(|e| e.content_digest.clone())
        })
    }
}

fn sample_credential(id: &str, package_id: &str, content_digest: &str) -> KryptotomeCredential {
    let issuer = Issuer {
        id: "did:key:zPublisherGM".to_string(),
        name: "Paizo Publisher".to_string(),
        public_key: "ed25519:abcdef0123456789abcdef".to_string(),
    };
    let entitlements = vec![Entitlement {
        package_id: package_id.to_string(),
        content_digest: content_digest.to_string(),
        scope: vec!["ruleset".to_string(), "compendium".to_string()],
    }];
    KryptotomeCredential::new(
        id.to_string(),
        issuer,
        "did:key:zHolderGM123".to_string(),
        "urn:kryptotome:commitment:bls12381:holdergm".to_string(),
        entitlements,
        "signature_sample".to_string(),
    )
}

#[test]
fn test_full_peer_authorization_handshake_with_vault() {
    // 1. Setup Host GM Vault with an entitled package
    let mut gm_vault = VaultStore::new();
    let package_id = "paizo/pathfinder-2e-core";
    let root_digest = "sha256:4a8b7c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b";
    gm_vault.insert_credential(sample_credential("cred-gm-1", package_id, root_digest));

    let mut host_session = SessionManager::new("active-session-table-99".to_string());
    let host_pubkey = host_session.host_public_key_hex();

    // 2. Setup Player Peer
    let mut player_peer = PeerSessionClient::new("peer:player:valeros");
    assert_eq!(player_peer.peer_id(), "peer:player:valeros");

    // 3. Step 1: Peer requests module access
    let access_request = player_peer.create_access_request(package_id);
    assert_eq!(access_request.recipient_peer_id, "peer:player:valeros");
    assert_eq!(access_request.package_id, package_id);
    assert!(!access_request.nonce.is_empty());

    // 4. Step 2 & 3: Host checks vault entitlement & issues signed SessionAttestation (4h duration)
    let vault_provider = VaultEntitlementProvider(&gm_vault);
    let response = host_session
        .handle_peer_access_request(
            &access_request,
            &vault_provider,
            Some(vec!["compendium:read".to_string(), "actor:sheet".to_string()]),
            Some(240), // 4 hours
        )
        .expect("Host should verify vault entitlement and issue signed token");

    assert_eq!(response.attestation.package_id, package_id);
    assert_eq!(response.attestation.content_digest, root_digest);
    assert_eq!(response.attestation.recipient_peer_id, "peer:player:valeros");
    assert_eq!(response.host_public_key_hex, host_pubkey);
    assert_eq!(response.nonce, access_request.nonce);

    // 5. Step 4: Peer validates host signature locally and mounts in client memory
    let mounted_session = player_peer
        .process_handshake_response(&response, Some(&host_pubkey))
        .expect("Player peer should validate signature and mount compendium in memory");

    assert_eq!(mounted_session.package_id, package_id);
    assert_eq!(mounted_session.content_digest, root_digest);
    assert!(mounted_session.is_valid());
    assert!(mounted_session.has_scope("compendium:read"));
    assert!(mounted_session.has_scope("actor:sheet"));
    assert!(!mounted_session.has_scope("gm:admin"));

    // Verify peer has the compendium unlocked in memory
    assert!(player_peer.is_package_mounted(package_id));
    let retrieved = player_peer.get_mounted_session(package_id).unwrap();
    assert_eq!(retrieved.content_digest, root_digest);

    // 6. Test host rejects unowned module request
    let unowned_request = player_peer.create_access_request("paizo/unowned-secret-module");
    let unowned_err = host_session
        .handle_peer_access_request(&unowned_request, &vault_provider, None, None)
        .unwrap_err();

    match unowned_err {
        KryptotomeError::Detailed { code, .. } => {
            assert_eq!(code, KryptotomeErrorCode::Kryp603EntitlementNotFound);
        }
        _ => panic!("Expected Kryp603, got {:?}", unowned_err),
    }

    // 7. Test client memory unmounting
    assert!(player_peer.unmount_package(package_id));
    assert!(!player_peer.is_package_mounted(package_id));
    assert_eq!(player_peer.mounted_package_ids().len(), 0);
}
