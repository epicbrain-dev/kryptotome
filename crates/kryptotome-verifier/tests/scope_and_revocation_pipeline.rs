use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode};
use kryptotome_verifier::{PeerSessionClient, ScopePolicy, SessionManager};

#[test]
fn test_dynamic_scope_limiting_pipeline() {
    let mut host = SessionManager::new("table-session-scoping-pipeline".to_string());
    let mut policy = ScopePolicy::new_default();

    // GM explicitly configures allowed and restricted scopes
    policy.allowed_scopes = vec![
        "spells".to_string(),
        "classes".to_string(),
        "feats".to_string(),
    ];
    policy.restricted_scopes = vec![
        "gm_notes".to_string(),
        "monsters".to_string(),
        "adventures".to_string(),
    ];

    // Assistant GM peer override
    policy.set_peer_override(
        "peer:assistant-gm",
        vec![
            "spells".to_string(),
            "classes".to_string(),
            "monsters".to_string(),
        ],
    );

    host.set_scope_policy(policy);

    let mut player = PeerSessionClient::new("peer:player:fighter");
    let mut assistant_gm = PeerSessionClient::new("peer:assistant-gm");

    let package_id = "paizo/pathfinder-bestiary-and-core";
    let store = |_pkg: &str| Some("sha256:digest123".to_string());

    // 1. Regular player attempts to request all scopes including monsters and gm_notes
    let player_req = player.create_access_request(package_id);
    let player_resp = host
        .handle_peer_access_request(
            &player_req,
            &store,
            Some(vec![
                "spells".to_string(),
                "classes".to_string(),
                "monsters".to_string(),
                "gm_notes".to_string(),
            ]),
            Some(240),
        )
        .unwrap();

    let player_session = player
        .process_handshake_response(&player_resp, None)
        .unwrap();

    // Verify player only got spells and classes; monsters and gm_notes were shielded
    assert!(player_session.allows_scope("spells"));
    assert!(player_session.allows_scope("classes"));
    assert!(!player_session.allows_scope("monsters"));
    assert!(!player_session.allows_scope("gm_notes"));

    // Verify asset gatekeeping
    assert!(player_session.allows_asset_path("spells/heal.json"));
    assert!(player_session
        .check_asset_access("spells/heal.json")
        .is_ok());

    assert!(!player_session.allows_asset_path("monsters/red_dragon.json"));
    let err = player_session
        .check_asset_access("monsters/red_dragon.json")
        .unwrap_err();
    match err {
        KryptotomeError::Detailed { code, .. } => {
            assert_eq!(code, KryptotomeErrorCode::Kryp703PeerUnauthorized);
        }
        _ => panic!("Expected Kryp703, got {:?}", err),
    }

    assert!(!player_session.allows_asset_path("gm_notes/campaign_secrets.md"));
    assert!(player_session
        .check_asset_access("gm_notes/campaign_secrets.md")
        .is_err());

    // 2. Assistant GM connects: override allows them monsters
    let agm_req = assistant_gm.create_access_request(package_id);
    let agm_resp = host
        .handle_peer_access_request(&agm_req, &store, None, Some(240))
        .unwrap();

    let agm_session = assistant_gm
        .process_handshake_response(&agm_resp, None)
        .unwrap();
    assert!(agm_session.allows_scope("monsters"));
    assert!(agm_session.allows_asset_path("monsters/red_dragon.json"));
    assert!(agm_session
        .check_asset_access("monsters/red_dragon.json")
        .is_ok());
    // But assistant GM still lacks gm_notes
    assert!(!agm_session.allows_scope("gm_notes"));
}

#[test]
fn test_session_renewal_and_revocation_pipeline() {
    let mut host = SessionManager::new("table-session-renewal-revocation".to_string());
    let host_pubkey = host.host_public_key_hex();

    let mut peer = PeerSessionClient::new("peer:player:sorcerer");
    let package_id = "paizo/pathfinder-spells";
    let store = |_pkg: &str| Some("sha256:spellsdigest".to_string());

    // 1. Initial Handshake
    let req = peer.create_access_request(package_id);
    let resp = host
        .handle_peer_access_request(&req, &store, Some(vec!["spells".to_string()]), Some(60))
        .unwrap();

    peer.process_handshake_response(&resp, Some(&host_pubkey))
        .unwrap();
    assert!(peer.is_package_mounted(package_id));

    let initial_session = peer.get_mounted_session(package_id).unwrap();
    let initial_expiry = initial_session.expires_at;

    // 2. Peer creates renewal request before token expires
    let renewal_req = peer.create_renewal_request(package_id).unwrap();
    assert_eq!(renewal_req.session_id, "table-session-renewal-revocation");
    assert_eq!(renewal_req.recipient_peer_id, "peer:player:sorcerer");
    assert_eq!(renewal_req.package_id, package_id);

    // 3. Host processes renewal and issues extended token (+240 mins)
    let renewal_resp = host
        .handle_session_renewal(&renewal_req, Some(240))
        .expect("Session renewal should succeed");

    // 4. Peer processes renewal response and extends validity in client memory
    let renewed_session = peer
        .process_renewal_response(&renewal_resp, Some(&host_pubkey))
        .expect("Renewal validation should succeed");

    assert!(renewed_session.expires_at > initial_expiry);
    assert!(peer.is_package_mounted(package_id));

    // 5. Host revokes peer (player disconnects or is removed from table)
    let notice = host.revoke_peer(
        "peer:player:sorcerer",
        Some(package_id),
        "Player left table session",
    );
    assert!(host.is_peer_revoked("peer:player:sorcerer", package_id));

    // Notice has valid Ed25519 signature by host
    assert!(notice.verify_signature(&host_pubkey).unwrap());

    // 6. Peer processes revocation notice -> in-memory compendium is instantly purged
    let purged = peer
        .process_revocation_notice(&notice, Some(&host_pubkey))
        .unwrap();

    assert_eq!(purged, 1);
    assert!(!peer.is_package_mounted(package_id));
    assert!(peer.get_mounted_session(package_id).is_none());

    // 7. Revoked peer is blocked from renewing or re-requesting access
    let re_req = peer.create_access_request(package_id);
    let re_err = host
        .handle_peer_access_request(&re_req, &store, None, None)
        .unwrap_err();

    match re_err {
        KryptotomeError::Detailed { code, .. } => {
            assert_eq!(code, KryptotomeErrorCode::Kryp703PeerUnauthorized);
        }
        _ => panic!("Expected Kryp703, got {:?}", re_err),
    }

    // 8. Clean disconnect and purge
    let mut another_peer = PeerSessionClient::new("peer:player:cleric");
    let req2 = another_peer.create_access_request("paizo/pathfinder-core");
    let resp2 = host
        .handle_peer_access_request(&req2, &store, None, None)
        .unwrap();
    another_peer
        .process_handshake_response(&resp2, None)
        .unwrap();
    assert!(another_peer.is_package_mounted("paizo/pathfinder-core"));

    let purged_on_disconnect = another_peer.disconnect_and_purge();
    assert_eq!(purged_on_disconnect, 1);
    assert!(!another_peer.is_package_mounted("paizo/pathfinder-core"));
}
