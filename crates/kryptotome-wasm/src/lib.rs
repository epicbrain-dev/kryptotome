use kryptotome_core::zkp::{ChallengeNonce, VerificationKey, ZkProof};
use kryptotome_verifier::{EmbeddedVerifier, SessionAttestation, SessionManager};
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
