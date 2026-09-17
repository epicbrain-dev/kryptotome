use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode};
use kryptotome_core::party::{
    AggregatedPartySessionProof, PartyMemberContribution, PartySessionPool,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard default session duration: 4 hours (typical game table session length)
pub const DEFAULT_SESSION_DURATION_MINUTES: i64 = 240;

/// Policy controlling dynamic scope limiting and gatekeeping for connected table peers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScopePolicy {
    /// Default scopes granted to regular connected players (e.g. spells, classes, items, feats)
    pub allowed_scopes: Vec<String>,
    /// Sensitive scopes strictly prohibited for players (e.g. gm_notes, monsters, adventures, secrets, admin)
    pub restricted_scopes: Vec<String>,
    /// Explicit scope overrides for specific peer IDs (e.g. assistant GM or co-host)
    pub peer_overrides: HashMap<String, Vec<String>>,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self::new_default()
    }
}

impl ScopePolicy {
    /// Standard TTRPG table policy granting player compendiums while shielding GM notes and monsters
    pub fn new_default() -> Self {
        Self {
            allowed_scopes: vec![
                "spells".to_string(),
                "classes".to_string(),
                "feats".to_string(),
                "items".to_string(),
                "character_builder".to_string(),
                "rules".to_string(),
                "compendium".to_string(),
                "actor".to_string(),
                "read".to_string(),
            ],
            restricted_scopes: vec![
                "gm_notes".to_string(),
                "monsters".to_string(),
                "adventures".to_string(),
                "traps".to_string(),
                "secrets".to_string(),
                "admin".to_string(),
            ],
            peer_overrides: HashMap::new(),
        }
    }

    /// Permissive policy (e.g. for co-GMs, solo mode, or unrestricted tables)
    pub fn permissive() -> Self {
        Self {
            allowed_scopes: vec!["*".to_string()],
            restricted_scopes: Vec::new(),
            peer_overrides: HashMap::new(),
        }
    }

    /// Sets explicit scope grants for a specific peer ID
    pub fn set_peer_override(&mut self, peer_id: impl Into<String>, scopes: Vec<String>) {
        self.peer_overrides.insert(peer_id.into(), scopes);
    }

    /// Evaluates requested scopes against allowed and restricted sets for a given peer
    pub fn evaluate_scopes(
        &self,
        peer_id: &str,
        requested_scopes: Option<&[String]>,
    ) -> Vec<String> {
        if let Some(overrides) = self.peer_overrides.get(peer_id) {
            return overrides.clone();
        }

        let candidates = match requested_scopes {
            Some(requested) => requested.to_vec(),
            None => self.allowed_scopes.clone(),
        };

        let wildcard_allowed = self.allowed_scopes.iter().any(|s| s == "*");
        candidates
            .into_iter()
            .filter(|scope| {
                let is_allowed = wildcard_allowed
                    || self
                        .allowed_scopes
                        .iter()
                        .any(|s| s == scope || scope.starts_with(&format!("{}:", s)));
                let is_restricted = self
                    .restricted_scopes
                    .iter()
                    .any(|s| s == scope || scope.starts_with(&format!("{}:", s)));
                is_allowed && !is_restricted
            })
            .collect()
    }
}

/// Ephemeral table-sharing session token issued by Host for a player peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAttestation {
    pub session_id: String,
    pub host_peer_id: String,
    pub recipient_peer_id: String,
    pub package_id: String,
    pub content_digest: String,
    pub permitted_scopes: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(alias = "signature")]
    pub signature_hex: String,
}

/// Handshake message Step 1: Peer requests compendium module access from Host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerAccessRequest {
    pub recipient_peer_id: String,
    pub package_id: String,
    pub nonce: String,
    pub timestamp: DateTime<Utc>,
}

impl PeerAccessRequest {
    /// Creates a fresh request with a random challenge nonce
    pub fn new(recipient_peer_id: impl Into<String>, package_id: impl Into<String>) -> Self {
        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        Self {
            recipient_peer_id: recipient_peer_id.into(),
            package_id: package_id.into(),
            nonce: hex_encode(&nonce_bytes),
            timestamp: Utc::now(),
        }
    }

    /// Creates a request with an explicit nonce (for deterministic testing)
    pub fn with_nonce(
        recipient_peer_id: impl Into<String>,
        package_id: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            recipient_peer_id: recipient_peer_id.into(),
            package_id: package_id.into(),
            nonce: nonce.into(),
            timestamp: Utc::now(),
        }
    }
}

/// Handshake message Step 3: Host response containing signed SessionAttestation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerAccessResponse {
    pub attestation: SessionAttestation,
    pub host_public_key_hex: String,
    pub nonce: String,
}

/// Step 1 of Renewal: Peer requests session extension before token expiry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerSessionRenewalRequest {
    pub session_id: String,
    pub recipient_peer_id: String,
    pub package_id: String,
    pub renewal_nonce: String,
    pub current_signature_hex: String,
    pub timestamp: DateTime<Utc>,
}

impl PeerSessionRenewalRequest {
    pub fn new(
        session_id: impl Into<String>,
        recipient_peer_id: impl Into<String>,
        package_id: impl Into<String>,
        current_signature_hex: impl Into<String>,
    ) -> Self {
        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        Self {
            session_id: session_id.into(),
            recipient_peer_id: recipient_peer_id.into(),
            package_id: package_id.into(),
            renewal_nonce: hex_encode(&nonce_bytes),
            current_signature_hex: current_signature_hex.into(),
            timestamp: Utc::now(),
        }
    }
}

/// Signed notice emitted by Host when a peer is revoked or table session is terminated
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionRevocationNotice {
    pub session_id: String,
    pub host_peer_id: String,
    pub recipient_peer_id: String,
    pub package_id: Option<String>,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
    #[serde(alias = "signature")]
    pub signature_hex: String,
}

impl SessionRevocationNotice {
    /// Validates the cryptographic Ed25519 signature of the revocation notice against host public key
    pub fn verify_signature(&self, host_pubkey_hex: &str) -> Result<bool, KryptotomeError> {
        let pubkey_bytes = hex_decode(host_pubkey_hex).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Invalid host public key hex: {}", e),
        })?;
        if pubkey_bytes.len() != 32 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: "Invalid host public key length, expected 32 bytes".to_string(),
            });
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&key_arr).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: format!("Failed to parse host public key: {}", e),
            })?;

        let sig_bytes = hex_decode(&self.signature_hex).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp203CorruptedSignature,
            message: format!("Invalid signature hex: {}", e),
        })?;
        if sig_bytes.len() != 64 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                message: "Invalid signature length, expected 64 bytes".to_string(),
            });
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        let pkg_str = self.package_id.as_deref().unwrap_or("*");
        let payload = format!(
            "REVOKE:{}:{}:{}:{}:{}",
            self.session_id,
            self.recipient_peer_id,
            pkg_str,
            self.reason,
            self.revoked_at.timestamp()
        );

        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map(|_| true)
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: format!("Revocation notice signature verification failed: {}", e),
            })
    }
}

/// Host internal revocation record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RevocationEntry {
    pub recipient_peer_id: String,
    pub package_id: Option<String>,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

/// Handshake Step 4: Active compendium session mounted in client memory on peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MountedCompendiumSession {
    pub package_id: String,
    pub content_digest: String,
    pub host_peer_id: String,
    pub recipient_peer_id: String,
    pub session_id: String,
    pub permitted_scopes: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub mounted_at: DateTime<Utc>,
}

impl MountedCompendiumSession {
    /// Checks if this mounted session is still within its validity window
    pub fn is_valid(&self) -> bool {
        Utc::now() <= self.expires_at
    }

    /// Returns remaining time until expiration (or zero if already expired)
    pub fn remaining_duration(&self) -> Duration {
        let now = Utc::now();
        if now >= self.expires_at {
            Duration::zero()
        } else {
            self.expires_at - now
        }
    }

    /// Checks if the session grants a specific permission scope (exact or wildcard match)
    pub fn has_scope(&self, scope: &str) -> bool {
        self.allows_scope(scope)
    }

    /// Checks if the session grants a specific scope (exact or wildcard match like 'spells:*')
    pub fn allows_scope(&self, target_scope: &str) -> bool {
        if self.permitted_scopes.iter().any(|s| s == "*") {
            return true;
        }
        self.permitted_scopes.iter().any(|scope| {
            if scope == target_scope {
                return true;
            }
            if let Some(prefix) = scope.strip_suffix(":*") {
                if target_scope.starts_with(&format!("{}:", prefix)) || target_scope == prefix {
                    return true;
                }
            }
            false
        })
    }

    /// Maps an asset file path (e.g. "spells/fireball.json", "gm_notes/plot.md", "monsters/dragon.json")
    /// to its scope category and checks if access is allowed under permitted scopes
    pub fn allows_asset_path(&self, asset_path: &str) -> bool {
        let category = Self::category_from_asset_path(asset_path);
        self.allows_scope(&category)
    }

    /// Enforces access to a compendium asset file, returning Kryp703PeerUnauthorized if restricted
    pub fn check_asset_access(&self, asset_path: &str) -> Result<(), KryptotomeError> {
        if !self.is_valid() {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp701SessionTokenExpired,
                message: format!("Session for package '{}' has expired", self.package_id),
            });
        }
        if !self.allows_asset_path(asset_path) {
            let category = Self::category_from_asset_path(asset_path);
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: format!(
                    "Access denied to asset '{}': scope '{}' is restricted for peer '{}'",
                    asset_path, category, self.recipient_peer_id
                ),
            });
        }
        Ok(())
    }

    /// Filters a list of asset paths, returning only those permitted under current session scopes
    pub fn filter_accessible_assets<'a>(&self, asset_paths: &[&'a str]) -> Vec<&'a str> {
        asset_paths
            .iter()
            .copied()
            .filter(|path| self.allows_asset_path(path))
            .collect()
    }

    fn category_from_asset_path(asset_path: &str) -> String {
        let normalized = asset_path.replace('\\', "/");
        let trimmed = normalized.trim_start_matches('/');
        if let Some((cat, _)) = trimmed.split_once('/') {
            cat.to_string()
        } else if let Some((cat, _)) = trimmed.split_once('.') {
            cat.to_string()
        } else {
            trimmed.to_string()
        }
    }
}

/// Trait implemented by vault stores or local entitlement caches to verify host ownership
pub trait EntitlementProvider {
    /// Returns the root content digest for a package if the host is entitled/owns it, or None
    fn get_package_entitlement(&self, package_id: &str) -> Option<String>;
}

impl<F> EntitlementProvider for F
where
    F: Fn(&str) -> Option<String>,
{
    fn get_package_entitlement(&self, package_id: &str) -> Option<String> {
        (self)(package_id)
    }
}

impl EntitlementProvider for crate::cache::EntitlementCache {
    fn get_package_entitlement(&self, package_id: &str) -> Option<String> {
        self.get(package_id)
            .map(|entry| entry.content_digest.clone())
    }
}

/// Host session manager (Game Master) managing table-sharing, scope policies, and peer revocations
pub struct SessionManager {
    host_signing_key: SigningKey,
    host_verifying_key: VerifyingKey,
    session_id: String,
    scope_policy: ScopePolicy,
    revoked_peers: HashMap<String, RevocationEntry>,
    active_attestations: HashMap<String, SessionAttestation>,
    consumed_request_nonces: HashMap<String, DateTime<Utc>>,
    consumed_renewal_nonces: HashMap<String, DateTime<Utc>>,
    party_pool: Option<PartySessionPool>,
}

impl SessionManager {
    pub fn new(session_id: String) -> Self {
        let mut csprng = OsRng;
        let host_signing_key = SigningKey::generate(&mut csprng);
        let host_verifying_key = host_signing_key.verifying_key();

        Self {
            host_signing_key,
            host_verifying_key,
            session_id,
            scope_policy: ScopePolicy::new_default(),
            revoked_peers: HashMap::new(),
            active_attestations: HashMap::new(),
            consumed_request_nonces: HashMap::new(),
            consumed_renewal_nonces: HashMap::new(),
            party_pool: None,
        }
    }

    pub fn with_signing_key(session_id: String, host_signing_key: SigningKey) -> Self {
        let host_verifying_key = host_signing_key.verifying_key();
        Self {
            host_signing_key,
            host_verifying_key,
            session_id,
            scope_policy: ScopePolicy::new_default(),
            revoked_peers: HashMap::new(),
            active_attestations: HashMap::new(),
            consumed_request_nonces: HashMap::new(),
            consumed_renewal_nonces: HashMap::new(),
            party_pool: None,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn host_public_key_hex(&self) -> String {
        hex_encode(self.host_verifying_key.as_bytes())
    }

    pub fn scope_policy(&self) -> &ScopePolicy {
        &self.scope_policy
    }

    pub fn set_scope_policy(&mut self, policy: ScopePolicy) {
        self.scope_policy = policy;
    }

    /// Initializes a collaborative party pool for multi-holder rulebook aggregation
    pub fn init_party_pool(&mut self, table_nonce: impl Into<String>) {
        self.party_pool = Some(PartySessionPool::new(
            self.session_id.clone(),
            self.host_public_key_hex(),
            table_nonce,
        ));
    }

    /// Returns a reference to the active party session pool if initialized
    pub fn party_pool(&self) -> Option<&PartySessionPool> {
        self.party_pool.as_ref()
    }

    /// Returns a mutable reference to the active party session pool if initialized
    pub fn party_pool_mut(&mut self) -> Option<&mut PartySessionPool> {
        self.party_pool.as_mut()
    }

    /// Registers a player's contributed rulebook into the party pool
    pub fn register_party_contribution(
        &mut self,
        contribution: PartyMemberContribution,
    ) -> Result<(), KryptotomeError> {
        match self.party_pool.as_mut() {
            Some(pool) => pool.register_contribution(contribution),
            None => Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: "Party pool has not been initialized for this session".to_string(),
            }),
        }
    }

    /// Finalizes the collective party pool into an AggregatedPartySessionProof signed by the GM/Host
    pub fn finalize_party_session(
        &self,
        duration_minutes: Option<i64>,
    ) -> Result<AggregatedPartySessionProof, KryptotomeError> {
        match self.party_pool.as_ref() {
            Some(pool) => Ok(pool.issue_aggregated_proof(
                &self.host_signing_key,
                duration_minutes.unwrap_or(DEFAULT_SESSION_DURATION_MINUTES),
            )),
            None => Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: "Party pool has not been initialized for this session".to_string(),
            }),
        }
    }

    /// Checks if a peer (or all peers) has been revoked for this session
    pub fn is_peer_revoked(&self, recipient_peer_id: &str, package_id: &str) -> bool {
        if self.revoked_peers.contains_key("*") {
            return true;
        }
        if self.revoked_peers.contains_key(recipient_peer_id) {
            return true;
        }
        let scoped_key = format!("{}:{}", recipient_peer_id, package_id);
        self.revoked_peers.contains_key(&scoped_key)
    }

    /// Revokes an individual peer from accessing the table (or a specific package)
    pub fn revoke_peer(
        &mut self,
        recipient_peer_id: &str,
        package_id: Option<&str>,
        reason: &str,
    ) -> SessionRevocationNotice {
        let now = Utc::now();
        let key = match package_id {
            Some(pkg) => format!("{}:{}", recipient_peer_id, pkg),
            None => recipient_peer_id.to_string(),
        };

        self.revoked_peers.insert(
            key,
            RevocationEntry {
                recipient_peer_id: recipient_peer_id.to_string(),
                package_id: package_id.map(String::from),
                revoked_at: now,
                reason: reason.to_string(),
            },
        );

        let pkg_str = package_id.unwrap_or("*");
        let payload = format!(
            "REVOKE:{}:{}:{}:{}:{}",
            self.session_id,
            recipient_peer_id,
            pkg_str,
            reason,
            now.timestamp()
        );
        let signature = self.host_signing_key.sign(payload.as_bytes());

        SessionRevocationNotice {
            session_id: self.session_id.clone(),
            host_peer_id: self.host_public_key_hex(),
            recipient_peer_id: recipient_peer_id.to_string(),
            package_id: package_id.map(String::from),
            revoked_at: now,
            reason: reason.to_string(),
            signature_hex: hex_encode(&signature.to_bytes()),
        }
    }

    /// Revokes all peers from the active table session (e.g. game session ending)
    pub fn revoke_all_peers(&mut self, reason: &str) -> SessionRevocationNotice {
        self.revoke_peer("*", None, reason)
    }

    /// Signs an ephemeral session token for a connected table peer
    pub fn issue_peer_attestation(
        &self,
        recipient_peer_id: &str,
        package_id: &str,
        content_digest: &str,
        scopes: Vec<String>,
        valid_duration_minutes: i64,
    ) -> SessionAttestation {
        let now = Utc::now();
        let expires_at = now + Duration::minutes(valid_duration_minutes);

        let payload_to_sign = format!(
            "{}:{}:{}:{}:{}",
            self.session_id,
            recipient_peer_id,
            package_id,
            content_digest,
            expires_at.timestamp()
        );

        let signature = self.host_signing_key.sign(payload_to_sign.as_bytes());

        SessionAttestation {
            session_id: self.session_id.clone(),
            host_peer_id: self.host_public_key_hex(),
            recipient_peer_id: recipient_peer_id.to_string(),
            package_id: package_id.to_string(),
            content_digest: content_digest.to_string(),
            permitted_scopes: scopes,
            issued_at: now,
            expires_at,
            signature_hex: hex_encode(&signature.to_bytes()),
        }
    }

    /// Checks if an access request nonce was already consumed
    pub fn is_request_nonce_consumed(&mut self, nonce: &str) -> bool {
        let now = Utc::now();
        self.consumed_request_nonces.retain(|_, exp| *exp > now);
        self.consumed_request_nonces.contains_key(nonce)
    }

    /// Checks if a session renewal nonce was already consumed
    pub fn is_renewal_nonce_consumed(&mut self, nonce: &str) -> bool {
        let now = Utc::now();
        self.consumed_renewal_nonces.retain(|_, exp| *exp > now);
        self.consumed_renewal_nonces.contains_key(nonce)
    }

    /// Handshake Step 2 & 3: Host receives peer request, verifies local entitlement and revocation status,
    /// applies dynamic scope policies, and issues signed SessionAttestation with short expiry.
    pub fn handle_peer_access_request<P: EntitlementProvider>(
        &mut self,
        request: &PeerAccessRequest,
        provider: &P,
        scopes: Option<Vec<String>>,
        valid_duration_minutes: Option<i64>,
    ) -> Result<PeerAccessResponse, KryptotomeError> {
        // Prevent replay attacks: check if request nonce was already consumed
        let now = Utc::now();
        self.consumed_request_nonces.retain(|_, exp| *exp > now);
        if self.consumed_request_nonces.contains_key(&request.nonce) {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                message: format!(
                    "Peer access request nonce '{}' already consumed (replay detected)",
                    request.nonce
                ),
            });
        }

        // Check if peer is revoked
        if self.is_peer_revoked(&request.recipient_peer_id, &request.package_id) {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: format!(
                    "Peer '{}' has been revoked from accessing table session '{}'",
                    request.recipient_peer_id, self.session_id
                ),
            });
        }

        // Verify host owns / is entitled to the requested module
        let content_digest = provider
            .get_package_entitlement(&request.package_id)
            .ok_or_else(|| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp603EntitlementNotFound,
                message: format!(
                    "Host has no local entitlement for requested package '{}'",
                    request.package_id
                ),
            })?;

        // Apply dynamic scope policy
        let permitted_scopes = self
            .scope_policy
            .evaluate_scopes(&request.recipient_peer_id, scopes.as_deref());

        let duration = valid_duration_minutes.unwrap_or(DEFAULT_SESSION_DURATION_MINUTES);
        let attestation = self.issue_peer_attestation(
            &request.recipient_peer_id,
            &request.package_id,
            &content_digest,
            permitted_scopes,
            duration,
        );

        // Mark nonce as consumed
        self.consumed_request_nonces
            .insert(request.nonce.clone(), attestation.expires_at);

        let attestation_key = format!("{}:{}", request.recipient_peer_id, request.package_id);
        self.active_attestations
            .insert(attestation_key, attestation.clone());

        Ok(PeerAccessResponse {
            attestation,
            host_public_key_hex: self.host_public_key_hex(),
            nonce: request.nonce.clone(),
        })
    }

    /// Simplified handler when entitlement status and content digest are known directly
    pub fn handle_peer_access_request_simple(
        &mut self,
        request: &PeerAccessRequest,
        has_entitlement: bool,
        content_digest: &str,
        scopes: Option<Vec<String>>,
        valid_duration_minutes: Option<i64>,
    ) -> Result<PeerAccessResponse, KryptotomeError> {
        if !has_entitlement {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp603EntitlementNotFound,
                message: format!(
                    "Host has no local entitlement for requested package '{}'",
                    request.package_id
                ),
            });
        }
        let provider = |_pkg: &str| Some(content_digest.to_string());
        self.handle_peer_access_request(request, &provider, scopes, valid_duration_minutes)
    }

    /// Handles a peer session renewal request, extending validity if peer remains connected and authorized
    pub fn handle_session_renewal(
        &mut self,
        request: &PeerSessionRenewalRequest,
        valid_duration_minutes: Option<i64>,
    ) -> Result<PeerAccessResponse, KryptotomeError> {
        // Prevent replay attacks: check if renewal nonce was already consumed
        let now = Utc::now();
        self.consumed_renewal_nonces.retain(|_, exp| *exp > now);
        if self
            .consumed_renewal_nonces
            .contains_key(&request.renewal_nonce)
        {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                message: format!(
                    "Session renewal nonce '{}' already consumed (replay detected)",
                    request.renewal_nonce
                ),
            });
        }

        // Validate session ID
        if request.session_id != self.session_id {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp704SessionIdMismatch,
                message: format!(
                    "Renewal session ID '{}' does not match active host session '{}'",
                    request.session_id, self.session_id
                ),
            });
        }

        // Verify revocation
        if self.is_peer_revoked(&request.recipient_peer_id, &request.package_id) {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: format!(
                    "Cannot renew session: peer '{}' has been revoked",
                    request.recipient_peer_id
                ),
            });
        }

        // Look up prior attestation
        let attestation_key = format!("{}:{}", request.recipient_peer_id, request.package_id);
        let prior = self
            .active_attestations
            .get(&attestation_key)
            .ok_or_else(|| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: format!(
                    "No active session attestation found for peer '{}' on package '{}'",
                    request.recipient_peer_id, request.package_id
                ),
            })?;

        // Re-evaluate scopes in case policy changed dynamically during game session
        let updated_scopes = self
            .scope_policy
            .evaluate_scopes(&request.recipient_peer_id, Some(&prior.permitted_scopes));

        let duration = valid_duration_minutes.unwrap_or(DEFAULT_SESSION_DURATION_MINUTES);
        let renewed_attestation = self.issue_peer_attestation(
            &request.recipient_peer_id,
            &request.package_id,
            &prior.content_digest,
            updated_scopes,
            duration,
        );

        // Mark renewal nonce as consumed
        self.consumed_renewal_nonces.insert(
            request.renewal_nonce.clone(),
            renewed_attestation.expires_at,
        );

        self.active_attestations
            .insert(attestation_key, renewed_attestation.clone());

        Ok(PeerAccessResponse {
            attestation: renewed_attestation,
            host_public_key_hex: self.host_public_key_hex(),
            nonce: request.renewal_nonce.clone(),
        })
    }

    /// Validates received session attestation against host public key using strong error codes
    pub fn verify_peer_attestation_crypto(
        attestation: &SessionAttestation,
        host_pubkey_hex: &str,
    ) -> Result<bool, KryptotomeError> {
        if Utc::now() > attestation.expires_at {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp701SessionTokenExpired,
                message: format!("Session attestation expired at {}", attestation.expires_at),
            });
        }

        let pubkey_bytes = hex_decode(host_pubkey_hex).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
            message: format!("Invalid host public key hex: {}", e),
        })?;
        if pubkey_bytes.len() != 32 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: "Invalid host public key length, expected 32 bytes".to_string(),
            });
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&key_arr).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                message: format!("Failed to parse host public key: {}", e),
            })?;

        let sig_bytes =
            hex_decode(&attestation.signature_hex).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                message: format!("Invalid signature hex: {}", e),
            })?;
        if sig_bytes.len() != 64 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                message: "Invalid signature length, expected 64 bytes".to_string(),
            });
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        let payload = format!(
            "{}:{}:{}:{}:{}",
            attestation.session_id,
            attestation.recipient_peer_id,
            attestation.package_id,
            attestation.content_digest,
            attestation.expires_at.timestamp()
        );

        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map(|_| true)
            .map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message: format!("Host session signature verification failed: {}", e),
            })
    }

    /// Peer validates received session attestation (returns String error for WASM compatibility)
    pub fn verify_peer_attestation(
        attestation: &SessionAttestation,
        host_pubkey_hex: &str,
    ) -> Result<bool, String> {
        Self::verify_peer_attestation_crypto(attestation, host_pubkey_hex)
            .map_err(|e| e.to_string())
    }
}

/// Client-side peer manager running on player devices.
/// Handles initiating access requests, renewals, gatekeeping, and memory purging upon revocation.
#[derive(Debug, Clone)]
pub struct PeerSessionClient {
    peer_id: String,
    mounted_sessions: HashMap<String, MountedCompendiumSession>,
    pending_requests: HashMap<String, PeerAccessRequest>,
    pending_renewals: HashMap<String, PeerSessionRenewalRequest>,
    last_signatures: HashMap<String, String>,
}

impl PeerSessionClient {
    /// Creates a new peer session client with the player's local peer ID
    pub fn new(peer_id: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            mounted_sessions: HashMap::new(),
            pending_requests: HashMap::new(),
            pending_renewals: HashMap::new(),
            last_signatures: HashMap::new(),
        }
    }

    /// Returns the local peer ID
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Handshake Step 1: Peer requests module access by generating a fresh request with challenge nonce
    pub fn create_access_request(&mut self, package_id: &str) -> PeerAccessRequest {
        let request = PeerAccessRequest::new(&self.peer_id, package_id);
        self.pending_requests
            .insert(package_id.to_string(), request.clone());
        request
    }

    /// Handshake Step 4: Peer receives host response, validates host signature locally,
    /// and mounts compendium session directly into client memory.
    pub fn process_handshake_response(
        &mut self,
        response: &PeerAccessResponse,
        expected_host_pubkey_hex: Option<&str>,
    ) -> Result<MountedCompendiumSession, KryptotomeError> {
        let package_id = &response.attestation.package_id;

        // 1. Verify recipient matches local peer
        if response.attestation.recipient_peer_id != self.peer_id {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: format!(
                    "Attestation recipient '{}' does not match local peer ID '{}'",
                    response.attestation.recipient_peer_id, self.peer_id
                ),
            });
        }

        // 2. Verify nonce matches pending request
        if let Some(pending) = self.pending_requests.get(package_id) {
            if pending.nonce != response.nonce {
                return Err(KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                    message: format!(
                        "Response nonce '{}' does not match pending request nonce '{}'",
                        response.nonce, pending.nonce
                    ),
                });
            }
        }

        // 3. Verify host public key matches expected host key if configured
        if let Some(expected_host) = expected_host_pubkey_hex {
            if response.host_public_key_hex != expected_host {
                return Err(KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp204UntrustedPublisherKey,
                    message: format!(
                        "Host public key '{}' does not match expected key '{}'",
                        response.host_public_key_hex, expected_host
                    ),
                });
            }
        }

        // 4. Verify host cryptographic signature and expiry bounds
        SessionManager::verify_peer_attestation_crypto(
            &response.attestation,
            &response.host_public_key_hex,
        )?;

        // 5. Mount compendium in client memory
        let mounted = MountedCompendiumSession {
            package_id: response.attestation.package_id.clone(),
            content_digest: response.attestation.content_digest.clone(),
            host_peer_id: response.host_public_key_hex.clone(),
            recipient_peer_id: response.attestation.recipient_peer_id.clone(),
            session_id: response.attestation.session_id.clone(),
            permitted_scopes: response.attestation.permitted_scopes.clone(),
            issued_at: response.attestation.issued_at,
            expires_at: response.attestation.expires_at,
            mounted_at: Utc::now(),
        };

        self.last_signatures.insert(
            mounted.package_id.clone(),
            response.attestation.signature_hex.clone(),
        );
        self.mounted_sessions
            .insert(mounted.package_id.clone(), mounted.clone());
        self.pending_requests.remove(package_id);

        Ok(mounted)
    }

    /// Step 4 (Party): Mounts all rulebooks from a verified aggregated party session proof into client memory
    pub fn mount_party_session(
        &mut self,
        proof: &AggregatedPartySessionProof,
        expected_host_pubkey_hex: Option<&str>,
    ) -> Result<Vec<MountedCompendiumSession>, KryptotomeError> {
        let is_valid = proof.verify(expected_host_pubkey_hex)?;
        if !is_valid {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                message:
                    "Aggregated party session proof signature verification failed or token expired"
                        .to_string(),
            });
        }

        let issued_at = DateTime::parse_from_rfc3339(&proof.issued_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let expires_at = DateTime::parse_from_rfc3339(&proof.valid_until)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now() + Duration::minutes(DEFAULT_SESSION_DURATION_MINUTES));

        let mut mounted_list = Vec::new();
        for package_id in &proof.pooled_packages {
            let mounted = MountedCompendiumSession {
                package_id: package_id.clone(),
                content_digest: proof.pool_digest.clone(),
                host_peer_id: proof.host_public_key_hex.clone(),
                recipient_peer_id: self.peer_id.clone(),
                session_id: proof.session_id.clone(),
                permitted_scopes: vec!["*".to_string()],
                issued_at,
                expires_at,
                mounted_at: Utc::now(),
            };
            self.last_signatures
                .insert(package_id.clone(), proof.host_signature_hex.clone());
            self.mounted_sessions
                .insert(package_id.clone(), mounted.clone());
            mounted_list.push(mounted);
        }

        Ok(mounted_list)
    }

    /// Creates a renewal request for an actively mounted compendium session
    pub fn create_renewal_request(
        &mut self,
        package_id: &str,
    ) -> Result<PeerSessionRenewalRequest, KryptotomeError> {
        let session =
            self.mounted_sessions
                .get(package_id)
                .ok_or_else(|| KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp603EntitlementNotFound,
                    message: format!("Package '{}' is not mounted in client memory", package_id),
                })?;

        let current_sig = self
            .last_signatures
            .get(package_id)
            .cloned()
            .unwrap_or_default();

        let request = PeerSessionRenewalRequest::new(
            &session.session_id,
            &self.peer_id,
            package_id,
            current_sig,
        );

        self.pending_renewals
            .insert(package_id.to_string(), request.clone());
        Ok(request)
    }

    /// Processes a renewal response, extending expiration time in client memory
    pub fn process_renewal_response(
        &mut self,
        response: &PeerAccessResponse,
        expected_host_pubkey_hex: Option<&str>,
    ) -> Result<MountedCompendiumSession, KryptotomeError> {
        let package_id = &response.attestation.package_id;

        // Verify recipient
        if response.attestation.recipient_peer_id != self.peer_id {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp703PeerUnauthorized,
                message: "Renewal recipient does not match local peer".to_string(),
            });
        }

        // Verify renewal nonce
        if let Some(pending) = self.pending_renewals.get(package_id) {
            if pending.renewal_nonce != response.nonce {
                return Err(KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp402NonceReplayDetected,
                    message: "Renewal response nonce mismatch".to_string(),
                });
            }
        }

        // Verify host public key
        if let Some(expected_host) = expected_host_pubkey_hex {
            if response.host_public_key_hex != expected_host {
                return Err(KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp204UntrustedPublisherKey,
                    message: "Host public key mismatch".to_string(),
                });
            }
        }

        // Verify signature
        SessionManager::verify_peer_attestation_crypto(
            &response.attestation,
            &response.host_public_key_hex,
        )?;

        // Update mounted compendium session in memory
        let mounted = MountedCompendiumSession {
            package_id: response.attestation.package_id.clone(),
            content_digest: response.attestation.content_digest.clone(),
            host_peer_id: response.host_public_key_hex.clone(),
            recipient_peer_id: response.attestation.recipient_peer_id.clone(),
            session_id: response.attestation.session_id.clone(),
            permitted_scopes: response.attestation.permitted_scopes.clone(),
            issued_at: response.attestation.issued_at,
            expires_at: response.attestation.expires_at,
            mounted_at: Utc::now(),
        };

        self.last_signatures.insert(
            mounted.package_id.clone(),
            response.attestation.signature_hex.clone(),
        );
        self.mounted_sessions
            .insert(mounted.package_id.clone(), mounted.clone());
        self.pending_renewals.remove(package_id);

        Ok(mounted)
    }

    /// Processes a signed revocation notice from the host, instantly unmounting and zeroizing memory
    pub fn process_revocation_notice(
        &mut self,
        notice: &SessionRevocationNotice,
        expected_host_pubkey_hex: Option<&str>,
    ) -> Result<usize, KryptotomeError> {
        let host_pubkey = expected_host_pubkey_hex.unwrap_or(&notice.host_peer_id);
        notice.verify_signature(host_pubkey)?;

        // Check if notice applies to this peer or all peers
        if notice.recipient_peer_id != self.peer_id && notice.recipient_peer_id != "*" {
            return Ok(0);
        }

        match &notice.package_id {
            Some(pkg) if pkg != "*" => {
                let removed = self.unmount_package(pkg);
                self.last_signatures.remove(pkg);
                self.pending_requests.remove(pkg);
                self.pending_renewals.remove(pkg);
                Ok(if removed { 1 } else { 0 })
            }
            _ => {
                let count = self.mounted_sessions.len();
                self.mounted_sessions.clear();
                self.last_signatures.clear();
                self.pending_requests.clear();
                self.pending_renewals.clear();
                Ok(count)
            }
        }
    }

    /// Disconnects from table session and cleanly purges all mounted compendiums from memory
    pub fn disconnect_and_purge(&mut self) -> usize {
        let count = self.mounted_sessions.len();
        self.mounted_sessions.clear();
        self.last_signatures.clear();
        self.pending_requests.clear();
        self.pending_renewals.clear();
        count
    }

    /// Checks if a compendium module is mounted and valid in client memory
    pub fn is_package_mounted(&self, package_id: &str) -> bool {
        self.mounted_sessions
            .get(package_id)
            .is_some_and(|m| m.is_valid())
    }

    /// Retrieves an active mounted compendium session from client memory
    pub fn get_mounted_session(&self, package_id: &str) -> Option<&MountedCompendiumSession> {
        self.mounted_sessions
            .get(package_id)
            .filter(|m| m.is_valid())
    }

    /// Returns list of all currently mounted and valid package IDs
    pub fn mounted_package_ids(&self) -> Vec<String> {
        self.mounted_sessions
            .iter()
            .filter(|(_, m)| m.is_valid())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Unmounts a compendium module from client memory
    pub fn unmount_package(&mut self, package_id: &str) -> bool {
        self.mounted_sessions.remove(package_id).is_some()
    }

    /// Unmounts all compendium modules from client memory
    pub fn unmount_all(&mut self) -> usize {
        let count = self.mounted_sessions.len();
        self.mounted_sessions.clear();
        count
    }

    /// Prunes expired compendiums from client memory
    pub fn prune_expired(&mut self) -> usize {
        let now = Utc::now();
        let expired_keys: Vec<String> = self
            .mounted_sessions
            .iter()
            .filter(|(_, m)| m.expires_at < now)
            .map(|(k, _)| k.clone())
            .collect();
        let count = expired_keys.len();
        for k in expired_keys {
            self.mounted_sessions.remove(&k);
        }
        count
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Odd hex length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Hex parse error: {}", e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_authorization_handshake_flow() {
        let mut host = SessionManager::new("table-session-42".to_string());
        let host_pubkey = host.host_public_key_hex();

        let mut peer = PeerSessionClient::new("peer:player:123");

        // Step 1: Peer requests module access
        let package_id = "paizo/starfinder-core";
        let request = peer.create_access_request(package_id);
        assert_eq!(request.recipient_peer_id, "peer:player:123");
        assert_eq!(request.package_id, package_id);
        assert!(!request.nonce.is_empty());

        // Step 2 & 3: Host checks local entitlement and issues signed SessionAttestation
        let entitlement_store = |pkg: &str| {
            if pkg == "paizo/starfinder-core" {
                Some("sha256:abc123fed456".to_string())
            } else {
                None
            }
        };

        let response = host
            .handle_peer_access_request(
                &request,
                &entitlement_store,
                Some(vec!["read".to_string(), "rules".to_string()]),
                Some(240), // 4 hours
            )
            .expect("Host entitlement verification should succeed");

        assert_eq!(response.nonce, request.nonce);
        assert_eq!(response.attestation.package_id, package_id);
        assert_eq!(response.attestation.recipient_peer_id, "peer:player:123");
        assert_eq!(response.host_public_key_hex, host_pubkey);

        // Step 4: Peer validates host signature locally and mounts in client memory
        let mounted = peer
            .process_handshake_response(&response, Some(&host_pubkey))
            .expect("Peer handshake validation and mounting should succeed");

        assert_eq!(mounted.package_id, package_id);
        assert_eq!(mounted.content_digest, "sha256:abc123fed456");
        assert!(mounted.is_valid());
        assert!(mounted.has_scope("read"));
        assert!(mounted.has_scope("rules"));
        assert!(!mounted.has_scope("admin"));

        // Confirm mounted in client memory
        assert!(peer.is_package_mounted(package_id));
        assert_eq!(peer.mounted_package_ids(), vec![package_id.to_string()]);

        // Unmount
        assert!(peer.unmount_package(package_id));
        assert!(!peer.is_package_mounted(package_id));
    }

    #[test]
    fn test_dynamic_scope_limiting_and_asset_gatekeeping() {
        let mut host = SessionManager::new("table-session-scope".to_string());
        let mut peer = PeerSessionClient::new("peer:player:rogue");

        // GM default policy allows player compendiums, restricts gm_notes and monsters
        let request = peer.create_access_request("paizo/pathfinder-core");
        let store = |_pkg: &str| Some("sha256:core".to_string());

        // Player requests spells, classes, but also tries to ask for gm_notes and monsters!
        let requested_scopes = vec![
            "spells".to_string(),
            "classes".to_string(),
            "gm_notes".to_string(),
            "monsters".to_string(),
        ];

        let response = host
            .handle_peer_access_request(&request, &store, Some(requested_scopes), None)
            .unwrap();

        // Verify GM policy filtered out restricted gm_notes and monsters
        assert!(response
            .attestation
            .permitted_scopes
            .contains(&"spells".to_string()));
        assert!(response
            .attestation
            .permitted_scopes
            .contains(&"classes".to_string()));
        assert!(!response
            .attestation
            .permitted_scopes
            .contains(&"gm_notes".to_string()));
        assert!(!response
            .attestation
            .permitted_scopes
            .contains(&"monsters".to_string()));

        let mounted = peer.process_handshake_response(&response, None).unwrap();

        // Allowed assets
        assert!(mounted.allows_asset_path("spells/fireball.json"));
        assert!(mounted.allows_asset_path("classes/wizard.json"));
        assert!(mounted.check_asset_access("spells/fireball.json").is_ok());

        // Restricted assets rejected with Kryp703
        assert!(!mounted.allows_asset_path("gm_notes/campaign_spoilers.md"));
        assert!(!mounted.allows_asset_path("monsters/red_dragon.json"));

        let err = mounted
            .check_asset_access("gm_notes/campaign_spoilers.md")
            .unwrap_err();
        match err {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp703PeerUnauthorized);
            }
            _ => panic!("Expected Kryp703, got {:?}", err),
        }

        // Filter list of assets
        let all_assets = vec![
            "spells/magic_missile.json",
            "gm_notes/secret_room.json",
            "classes/cleric.json",
            "monsters/lich.json",
        ];
        let accessible = mounted.filter_accessible_assets(&all_assets);
        assert_eq!(
            accessible,
            vec!["spells/magic_missile.json", "classes/cleric.json"]
        );
    }

    #[test]
    fn test_session_renewal_lifecycle() {
        let mut host = SessionManager::new("table-session-renewal".to_string());
        let mut peer = PeerSessionClient::new("peer:player:bard");

        let request = peer.create_access_request("paizo/bestiary");
        let store = |_pkg: &str| Some("sha256:bestiary".to_string());
        let host_pubkey = host.host_public_key_hex();

        // Host issues standard session
        let response = host
            .handle_peer_access_request(&request, &store, Some(vec!["rules".to_string()]), Some(60))
            .unwrap();

        peer.process_handshake_response(&response, Some(&host_pubkey))
            .unwrap();

        let initial_expiry = peer
            .get_mounted_session("paizo/bestiary")
            .unwrap()
            .expires_at;

        // Peer creates renewal request
        let renewal_req = peer.create_renewal_request("paizo/bestiary").unwrap();
        assert_eq!(renewal_req.package_id, "paizo/bestiary");
        assert_eq!(renewal_req.recipient_peer_id, "peer:player:bard");

        // Host handles renewal
        let renewal_resp = host
            .handle_session_renewal(&renewal_req, Some(120))
            .expect("Renewal should succeed");

        // Peer processes renewal
        let updated = peer
            .process_renewal_response(&renewal_resp, Some(&host_pubkey))
            .unwrap();

        assert!(updated.expires_at >= initial_expiry);
        assert!(peer.is_package_mounted("paizo/bestiary"));
    }

    #[test]
    fn test_session_revocation_purges_client_memory() {
        let mut host = SessionManager::new("table-session-revoke".to_string());
        let mut peer = PeerSessionClient::new("peer:player:kicked");

        let request = peer.create_access_request("paizo/core-rules");
        let store = |_pkg: &str| Some("sha256:core".to_string());
        let host_pubkey = host.host_public_key_hex();

        let response = host
            .handle_peer_access_request(&request, &store, None, None)
            .unwrap();

        peer.process_handshake_response(&response, Some(&host_pubkey))
            .unwrap();
        assert!(peer.is_package_mounted("paizo/core-rules"));

        // GM revokes peer
        let notice = host.revoke_peer(
            "peer:player:kicked",
            Some("paizo/core-rules"),
            "Player disconnected from table",
        );
        assert!(host.is_peer_revoked("peer:player:kicked", "paizo/core-rules"));

        // Peer processes revocation notice -> compendium is instantly purged from client memory
        let purged_count = peer
            .process_revocation_notice(&notice, Some(&host_pubkey))
            .expect("Revocation notice verification should succeed");

        assert_eq!(purged_count, 1);
        assert!(!peer.is_package_mounted("paizo/core-rules"));
        assert_eq!(peer.mounted_package_ids().len(), 0);

        // Subsequent renewal or access request by revoked peer is rejected
        let new_request = peer.create_access_request("paizo/core-rules");
        let err = host
            .handle_peer_access_request(&new_request, &store, None, None)
            .unwrap_err();

        match err {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp703PeerUnauthorized);
            }
            _ => panic!("Expected Kryp703, got {:?}", err),
        }
    }

    #[test]
    fn test_session_manager_attestation_issuance_expiry_and_signature_validation() {
        let host = SessionManager::new("table-session-101".to_string());
        let host_pubkey = host.host_public_key_hex();
        let peer_id = "peer:player:wizard";
        let package_id = "paizo/pathfinder-spells";
        let content_digest =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let scopes = vec!["spells".to_string(), "rules".to_string()];

        // 1. Attestation Issuance
        let attestation = host.issue_peer_attestation(
            peer_id,
            package_id,
            content_digest,
            scopes.clone(),
            120, // 2 hours
        );

        assert_eq!(attestation.session_id, "table-session-101");
        assert_eq!(attestation.recipient_peer_id, peer_id);
        assert_eq!(attestation.package_id, package_id);
        assert_eq!(attestation.content_digest, content_digest);
        assert_eq!(attestation.permitted_scopes, scopes);
        assert_eq!(attestation.host_peer_id, host_pubkey);
        assert_eq!(attestation.signature_hex.len(), 128); // 64 bytes = 128 hex chars
        assert!(attestation.expires_at > attestation.issued_at);
        assert_eq!(
            attestation.expires_at - attestation.issued_at,
            Duration::minutes(120)
        );

        // 2. Valid Signature Verification
        let valid_crypto =
            SessionManager::verify_peer_attestation_crypto(&attestation, &host_pubkey)
                .expect("Valid attestation crypto verification must succeed");
        assert!(valid_crypto);

        let valid_string = SessionManager::verify_peer_attestation(&attestation, &host_pubkey)
            .expect("Valid attestation string verification must succeed");
        assert!(valid_string);

        // 3. Expiry Enforcement
        let mut expired_attestation = attestation.clone();
        expired_attestation.expires_at = Utc::now() - Duration::minutes(10);

        let err_expiry =
            SessionManager::verify_peer_attestation_crypto(&expired_attestation, &host_pubkey)
                .unwrap_err();
        match err_expiry {
            KryptotomeError::Detailed { code, message } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp701SessionTokenExpired);
                assert!(message.contains("Session attestation expired"));
            }
            _ => panic!("Expected Kryp701SessionTokenExpired, got {:?}", err_expiry),
        }
        assert!(
            SessionManager::verify_peer_attestation(&expired_attestation, &host_pubkey).is_err()
        );

        // Mounted session expiry checks
        let mounted_valid = MountedCompendiumSession {
            package_id: package_id.to_string(),
            content_digest: content_digest.to_string(),
            host_peer_id: host_pubkey.clone(),
            recipient_peer_id: peer_id.to_string(),
            session_id: "table-session-101".to_string(),
            permitted_scopes: scopes.clone(),
            issued_at: Utc::now() - Duration::minutes(5),
            expires_at: Utc::now() + Duration::minutes(55),
            mounted_at: Utc::now() - Duration::minutes(5),
        };
        assert!(mounted_valid.is_valid());
        assert!(mounted_valid.remaining_duration() > Duration::zero());
        assert!(mounted_valid
            .check_asset_access("spells/magic_missile.json")
            .is_ok());

        let mounted_expired = MountedCompendiumSession {
            expires_at: Utc::now() - Duration::minutes(5),
            ..mounted_valid.clone()
        };
        assert!(!mounted_expired.is_valid());
        assert_eq!(mounted_expired.remaining_duration(), Duration::zero());
        let access_err = mounted_expired
            .check_asset_access("spells/magic_missile.json")
            .unwrap_err();
        match access_err {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp701SessionTokenExpired);
            }
            _ => panic!("Expected Kryp701, got {:?}", access_err),
        }

        // 4. Signature Validation Failure on Tampered Payload Fields
        // Tampered session_id
        let mut tampered = attestation.clone();
        tampered.session_id = "table-session-tampered".to_string();
        let err =
            SessionManager::verify_peer_attestation_crypto(&tampered, &host_pubkey).unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                ..
            }
        ));

        // Tampered recipient_peer_id
        let mut tampered = attestation.clone();
        tampered.recipient_peer_id = "peer:player:eavesdropper".to_string();
        let err =
            SessionManager::verify_peer_attestation_crypto(&tampered, &host_pubkey).unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                ..
            }
        ));

        // Tampered package_id
        let mut tampered = attestation.clone();
        tampered.package_id = "paizo/unauthorized-adventure".to_string();
        let err =
            SessionManager::verify_peer_attestation_crypto(&tampered, &host_pubkey).unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                ..
            }
        ));

        // Tampered content_digest
        let mut tampered = attestation.clone();
        tampered.content_digest =
            "sha256:9999999999999999999999999999999999999999999999999999999999999999".to_string();
        let err =
            SessionManager::verify_peer_attestation_crypto(&tampered, &host_pubkey).unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                ..
            }
        ));

        // 5. Signature Validation with Wrong Host Public Key
        let other_host = SessionManager::new("other-table".to_string());
        let err = SessionManager::verify_peer_attestation_crypto(
            &attestation,
            &other_host.host_public_key_hex(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
                ..
            }
        ));

        // 6. Corrupted Signature Hex Rejections
        let mut corrupted_sig = attestation.clone();
        corrupted_sig.signature_hex = "not-a-hex-string".to_string();
        let err = SessionManager::verify_peer_attestation_crypto(&corrupted_sig, &host_pubkey)
            .unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                ..
            }
        ));

        let mut short_sig = attestation.clone();
        short_sig.signature_hex = "abcd".to_string();
        let err =
            SessionManager::verify_peer_attestation_crypto(&short_sig, &host_pubkey).unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp203CorruptedSignature,
                ..
            }
        ));

        // 7. Corrupted Host Public Key Hex Rejections
        let err =
            SessionManager::verify_peer_attestation_crypto(&attestation, "invalid-hex-pubkey")
                .unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                ..
            }
        ));

        let err =
            SessionManager::verify_peer_attestation_crypto(&attestation, "1234abcd").unwrap_err();
        assert!(matches!(
            err,
            KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp202InvalidPublicKeyFormat,
                ..
            }
        ));
    }

    #[test]
    fn test_party_session_pool_lifecycle() {
        let mut session_mgr = SessionManager::new("session-party-123".to_string());
        session_mgr.init_party_pool("table-nonce-abc");

        // Player 1 contributes Player Core
        let p1_key = SigningKey::generate(&mut OsRng);
        let c1 = PartyMemberContribution::new_signed(
            "peer-alice",
            "paizo/pathfinder-player-core",
            "b3:pcore_digest",
            "table-nonce-abc",
            &p1_key,
        );
        session_mgr.register_party_contribution(c1).unwrap();

        // Player 2 contributes Monster Core
        let p2_key = SigningKey::generate(&mut OsRng);
        let c2 = PartyMemberContribution::new_signed(
            "peer-bob",
            "paizo/pathfinder-monster-core",
            "b3:mcore_digest",
            "table-nonce-abc",
            &p2_key,
        );
        session_mgr.register_party_contribution(c2).unwrap();

        assert_eq!(session_mgr.party_pool().unwrap().contribution_count(), 2);
        assert!(session_mgr
            .party_pool()
            .unwrap()
            .is_package_available("paizo/pathfinder-player-core"));
        assert!(session_mgr
            .party_pool()
            .unwrap()
            .is_package_available("paizo/pathfinder-monster-core"));

        // Host finalizes session
        let party_proof = session_mgr.finalize_party_session(Some(120)).unwrap();
        assert_eq!(party_proof.pooled_packages.len(), 2);

        // Player 3 (Charlie) joins table and mounts pooled modules
        let mut charlie_client = PeerSessionClient::new("peer-charlie");
        let mounted = charlie_client
            .mount_party_session(&party_proof, Some(&session_mgr.host_public_key_hex()))
            .unwrap();

        assert_eq!(mounted.len(), 2);
        assert!(charlie_client.is_package_mounted("paizo/pathfinder-player-core"));
        assert!(charlie_client.is_package_mounted("paizo/pathfinder-monster-core"));
        assert!(charlie_client
            .get_mounted_session("paizo/pathfinder-player-core")
            .unwrap()
            .is_valid());
        assert!(charlie_client
            .get_mounted_session("paizo/pathfinder-player-core")
            .unwrap()
            .has_scope("spells"));
    }
}
