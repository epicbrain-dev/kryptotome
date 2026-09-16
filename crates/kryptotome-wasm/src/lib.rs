use kryptotome_core::zkp::{ChallengeNonce, VerificationKey, ZkProof};
use kryptotome_verifier::{
    EmbeddedVerifier, PeerAccessRequest, PeerAccessResponse, PeerSessionClient, SessionAttestation,
    SessionManager,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
pub struct WasmVerifier {
    inner: EmbeddedVerifier,
}

#[wasm_bindgen]
impl WasmVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: EmbeddedVerifier::new(),
        }
    }

    /// Verifies a ZK proof against publisher key and challenge nonce JSON
    #[wasm_bindgen(js_name = verifyZkProof)]
    pub fn verify_zk_proof(
        &mut self,
        publisher_vk_hex: &str,
        challenge_json: &str,
        proof_json: &str,
    ) -> Result<bool, JsValue> {
        let challenge: ChallengeNonce = serde_json::from_str(challenge_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid challenge JSON: {}", e)))?;

        let proof: ZkProof = serde_json::from_str(proof_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid proof JSON: {}", e)))?;

        let vk = VerificationKey {
            publisher_id: "publisher".to_string(),
            key_bytes: publisher_vk_hex.as_bytes().to_vec(),
        };

        self.inner
            .verify_zk_proof(&vk, &challenge, &proof)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verifies a self-contained EntitlementProofBundle JSON string against a challenge JSON string
    #[wasm_bindgen(js_name = verifyProofBundle)]
    pub fn verify_proof_bundle(
        &mut self,
        bundle_json: &str,
        challenge_json: &str,
    ) -> Result<bool, JsValue> {
        let challenge: ChallengeNonce = serde_json::from_str(challenge_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid challenge JSON: {}", e)))?;

        let bundle: kryptotome_core::EntitlementProofBundle = serde_json::from_str(bundle_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid proof bundle JSON: {}", e)))?;

        self.inner
            .verify_proof_bundle(&bundle, &challenge)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Checks if a package is currently unlocked in the local session cache
    #[wasm_bindgen(js_name = isPackageUnlocked)]
    pub fn is_package_unlocked(&self, package_id: &str) -> bool {
        self.inner.is_package_unlocked(package_id)
    }

    /// Invalidates entitlement for a specific package
    #[wasm_bindgen(js_name = invalidatePackage)]
    pub fn invalidate_package(&mut self, package_id: &str) -> bool {
        self.inner.invalidate_package(package_id)
    }

    /// Invalidates entitlement when package assets are reloaded
    #[wasm_bindgen(js_name = reloadPackage)]
    pub fn reload_package(&mut self, package_id: &str) -> bool {
        self.inner.reload_package(package_id)
    }

    /// Invalidates entitlement if the current content digest has changed
    #[wasm_bindgen(js_name = invalidateIfDigestMismatch)]
    pub fn invalidate_if_digest_mismatch(&mut self, package_id: &str, current_digest: &str) -> bool {
        self.inner.invalidate_if_digest_mismatch(package_id, current_digest)
    }

    /// Exits the current active game session and purges all unlocked compendiums
    #[wasm_bindgen(js_name = exitSession)]
    pub fn exit_session(&mut self) -> usize {
        self.inner.exit_session()
    }

    /// Prunes expired entitlements from the cache
    #[wasm_bindgen(js_name = pruneExpired)]
    pub fn prune_expired(&mut self) -> usize {
        self.inner.prune_expired()
    }

    /// Configures the default cache TTL duration in seconds
    #[wasm_bindgen(js_name = setCacheTtlSeconds)]
    pub fn set_cache_ttl_seconds(&mut self, seconds: i64) {
        self.inner.set_cache_ttl_seconds(seconds);
    }
}

#[wasm_bindgen]
pub struct WasmSessionManager {
    inner: SessionManager,
}

#[wasm_bindgen]
impl WasmSessionManager {
    #[wasm_bindgen(constructor)]
    pub fn new(session_id: &str) -> Self {
        Self {
            inner: SessionManager::new(session_id.to_string()),
        }
    }

    #[wasm_bindgen(js_name = hostPublicKeyHex)]
    pub fn host_public_key_hex(&self) -> String {
        self.inner.host_public_key_hex()
    }

    /// Issues ephemeral session token for a table peer
    #[wasm_bindgen(js_name = issuePeerAttestation)]
    pub fn issue_peer_attestation(
        &self,
        recipient_peer_id: &str,
        package_id: &str,
        content_digest: &str,
        scopes_json: &str,
        duration_minutes: i32,
    ) -> Result<String, JsValue> {
        let scopes: Vec<String> = serde_json::from_str(scopes_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid scopes JSON: {}", e)))?;

        let attestation = self.inner.issue_peer_attestation(
            recipient_peer_id,
            package_id,
            content_digest,
            scopes,
            duration_minutes as i64,
        );

        serde_json::to_string(&attestation)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Host handles a PeerAccessRequest JSON, checks entitlement, and returns signed PeerAccessResponse JSON
    #[wasm_bindgen(js_name = handlePeerAccessRequest)]
    pub fn handle_peer_access_request(
        &mut self,
        request_json: &str,
        has_entitlement: bool,
        content_digest: &str,
        scopes_json: Option<String>,
        duration_minutes: Option<i32>,
    ) -> Result<String, JsValue> {
        let request: PeerAccessRequest = serde_json::from_str(request_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid request JSON: {}", e)))?;

        let scopes: Option<Vec<String>> = match scopes_json {
            Some(ref s) => Some(
                serde_json::from_str(s)
                    .map_err(|e| JsValue::from_str(&format!("Invalid scopes JSON: {}", e)))?,
            ),
            None => None,
        };

        let duration = duration_minutes.map(|d| d as i64);

        let response = self
            .inner
            .handle_peer_access_request_simple(
                &request,
                has_entitlement,
                content_digest,
                scopes,
                duration,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_json::to_string(&response)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Extends session validity for an authorized connected peer
    #[wasm_bindgen(js_name = handleSessionRenewal)]
    pub fn handle_session_renewal(
        &mut self,
        renewal_request_json: &str,
        duration_minutes: Option<i32>,
    ) -> Result<String, JsValue> {
        let request: kryptotome_verifier::PeerSessionRenewalRequest = serde_json::from_str(renewal_request_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid renewal request JSON: {}", e)))?;

        let duration = duration_minutes.map(|d| d as i64);
        let response = self
            .inner
            .handle_session_renewal(&request, duration)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_json::to_string(&response)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Revokes an individual peer or all peers, returning signed SessionRevocationNotice JSON
    #[wasm_bindgen(js_name = revokePeer)]
    pub fn revoke_peer(
        &mut self,
        recipient_peer_id: &str,
        package_id: Option<String>,
        reason: &str,
    ) -> Result<String, JsValue> {
        let notice = self.inner.revoke_peer(
            recipient_peer_id,
            package_id.as_deref(),
            reason,
        );
        serde_json::to_string(&notice)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Checks if a peer has been revoked from accessing the table session
    #[wasm_bindgen(js_name = isPeerRevoked)]
    pub fn is_peer_revoked(&self, recipient_peer_id: &str, package_id: &str) -> bool {
        self.inner.is_peer_revoked(recipient_peer_id, package_id)
    }

    /// Configures dynamic scope policy for table peers
    #[wasm_bindgen(js_name = setScopePolicy)]
    pub fn set_scope_policy(&mut self, policy_json: &str) -> Result<(), JsValue> {
        let policy: kryptotome_verifier::ScopePolicy = serde_json::from_str(policy_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid scope policy JSON: {}", e)))?;
        self.inner.set_scope_policy(policy);
        Ok(())
    }

    /// Peer validates received session token
    #[wasm_bindgen(js_name = verifyPeerAttestation)]
    pub fn verify_peer_attestation(
        attestation_json: &str,
        host_pubkey_hex: &str,
    ) -> Result<bool, JsValue> {
        let attestation: SessionAttestation = serde_json::from_str(attestation_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid attestation JSON: {}", e)))?;

        SessionManager::verify_peer_attestation(&attestation, host_pubkey_hex)
            .map_err(|e| JsValue::from_str(&e))
    }
}

/// WASM binding for peer-side compendium handshake and in-memory mounting
#[wasm_bindgen]
pub struct WasmPeerSessionClient {
    inner: PeerSessionClient,
}

#[wasm_bindgen]
impl WasmPeerSessionClient {
    #[wasm_bindgen(constructor)]
    pub fn new(peer_id: &str) -> Self {
        Self {
            inner: PeerSessionClient::new(peer_id),
        }
    }

    #[wasm_bindgen(js_name = peerId)]
    pub fn peer_id(&self) -> String {
        self.inner.peer_id().to_string()
    }

    /// Step 1: Initiates module access request with fresh challenge nonce
    #[wasm_bindgen(js_name = createAccessRequest)]
    pub fn create_access_request(&mut self, package_id: &str) -> Result<String, JsValue> {
        let req = self.inner.create_access_request(package_id);
        serde_json::to_string(&req)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Step 4: Validates host signature locally and mounts compendium session into memory
    #[wasm_bindgen(js_name = processHandshakeResponse)]
    pub fn process_handshake_response(
        &mut self,
        response_json: &str,
        expected_host_pubkey_hex: Option<String>,
    ) -> Result<String, JsValue> {
        let response: PeerAccessResponse = serde_json::from_str(response_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid response JSON: {}", e)))?;

        let mounted = self
            .inner
            .process_handshake_response(&response, expected_host_pubkey_hex.as_deref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_json::to_string(&mounted)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Creates a renewal request for an actively mounted compendium session
    #[wasm_bindgen(js_name = createRenewalRequest)]
    pub fn create_renewal_request(&mut self, package_id: &str) -> Result<String, JsValue> {
        let req = self
            .inner
            .create_renewal_request(package_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_json::to_string(&req)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Processes a renewal response, extending expiration time in client memory
    #[wasm_bindgen(js_name = processRenewalResponse)]
    pub fn process_renewal_response(
        &mut self,
        response_json: &str,
        expected_host_pubkey_hex: Option<String>,
    ) -> Result<String, JsValue> {
        let response: PeerAccessResponse = serde_json::from_str(response_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid response JSON: {}", e)))?;

        let mounted = self
            .inner
            .process_renewal_response(&response, expected_host_pubkey_hex.as_deref())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_json::to_string(&mounted)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Processes signed revocation notice and unmounts compendium from memory
    #[wasm_bindgen(js_name = processRevocationNotice)]
    pub fn process_revocation_notice(
        &mut self,
        notice_json: &str,
        expected_host_pubkey_hex: Option<String>,
    ) -> Result<usize, JsValue> {
        let notice: kryptotome_verifier::SessionRevocationNotice = serde_json::from_str(notice_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid notice JSON: {}", e)))?;

        self.inner
            .process_revocation_notice(&notice, expected_host_pubkey_hex.as_deref())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Disconnects from table and cleanly purges all mounted memory
    #[wasm_bindgen(js_name = disconnectAndPurge)]
    pub fn disconnect_and_purge(&mut self) -> usize {
        self.inner.disconnect_and_purge()
    }

    /// Checks if a package is currently mounted in memory
    #[wasm_bindgen(js_name = isPackageMounted)]
    pub fn is_package_mounted(&self, package_id: &str) -> bool {
        self.inner.is_package_mounted(package_id)
    }

    /// Checks if a mounted package allows a specific scope
    #[wasm_bindgen(js_name = allowsScope)]
    pub fn allows_scope(&self, package_id: &str, scope: &str) -> bool {
        self.inner
            .get_mounted_session(package_id)
            .map_or(false, |s| s.allows_scope(scope))
    }

    /// Checks if a mounted package allows access to a specific asset path
    #[wasm_bindgen(js_name = allowsAssetPath)]
    pub fn allows_asset_path(&self, package_id: &str, asset_path: &str) -> bool {
        self.inner
            .get_mounted_session(package_id)
            .map_or(false, |s| s.allows_asset_path(asset_path))
    }

    /// Verifies access to an asset path or returns error
    #[wasm_bindgen(js_name = checkAssetAccess)]
    pub fn check_asset_access(&self, package_id: &str, asset_path: &str) -> Result<bool, JsValue> {
        let session = self
            .inner
            .get_mounted_session(package_id)
            .ok_or_else(|| JsValue::from_str(&format!("Package '{}' is not mounted", package_id)))?;

        session
            .check_asset_access(asset_path)
            .map(|_| true)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Unmounts a compendium package from client memory
    #[wasm_bindgen(js_name = unmountPackage)]
    pub fn unmount_package(&mut self, package_id: &str) -> bool {
        self.inner.unmount_package(package_id)
    }

    /// Unmounts all compendium packages from client memory
    #[wasm_bindgen(js_name = unmountAll)]
    pub fn unmount_all(&mut self) -> usize {
        self.inner.unmount_all()
    }
}

