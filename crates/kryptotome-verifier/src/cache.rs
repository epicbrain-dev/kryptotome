use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard default cache TTL: 4 hours (typical TTRPG game session length)
pub const DEFAULT_CACHE_TTL_SECONDS: i64 = 4 * 60 * 60;

/// Reasons why an entitlement was invalidated from the cache
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationReason {
    /// Invalidation triggered because TTL expired
    Timeout,
    /// Invalidation triggered because the compendium package asset was reloaded
    PackageReload,
    /// Invalidation triggered because content digest no longer matches manifest
    DigestMismatch,
    /// Invalidation triggered because the host or player exited the active game session
    SessionExit,
    /// Manual eviction by application or user
    ManualEviction,
}

/// Record of a cache invalidation event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationEvent {
    pub package_id: String,
    pub reason: InvalidationReason,
    pub timestamp: DateTime<Utc>,
    pub session_id: Option<String>,
}

/// Represents an unlocked package in the local session cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEntitlement {
    pub package_id: String,
    pub content_digest: String,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub session_id: Option<String>,
}

impl CachedEntitlement {
    /// Returns true if this cached entitlement has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
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
}

/// Local session entitlement cache with robust invalidation rules:
/// 1. Timeout invalidation (configurable TTL, default 4h)
/// 2. Package reload / digest mismatch invalidation
/// 3. Game session exit invalidation (scoped or global)
#[derive(Debug, Clone)]
pub struct EntitlementCache {
    entries: HashMap<String, CachedEntitlement>,
    default_ttl: Duration,
    invalidation_history: Vec<InvalidationEvent>,
    active_session_id: Option<String>,
}

impl Default for EntitlementCache {
    fn default() -> Self {
        Self::new()
    }
}

impl EntitlementCache {
    /// Creates a new cache with the default 4-hour TTL
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            default_ttl: Duration::seconds(DEFAULT_CACHE_TTL_SECONDS),
            invalidation_history: Vec::new(),
            active_session_id: None,
        }
    }

    /// Creates a new cache with a custom default TTL
    pub fn with_ttl(default_ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            default_ttl,
            invalidation_history: Vec::new(),
            active_session_id: None,
        }
    }

    /// Sets the active game session ID
    pub fn set_active_session_id(&mut self, session_id: Option<String>) {
        self.active_session_id = session_id;
    }

    /// Returns the active game session ID, if any
    pub fn active_session_id(&self) -> Option<&str> {
        self.active_session_id.as_deref()
    }

    /// Sets the default TTL duration for future verified entitlements
    pub fn set_default_ttl(&mut self, ttl: Duration) {
        self.default_ttl = ttl;
    }

    /// Returns the default TTL duration
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Marks a package as verified using the default TTL and current active session
    pub fn mark_verified(&mut self, package_id: &str, content_digest: &str) {
        let ttl = self.default_ttl;
        let session_id = self.active_session_id.clone();
        self.mark_verified_with_params(package_id, content_digest, ttl, session_id);
    }

    /// Marks a package as verified with an explicit TTL and optional session ID
    pub fn mark_verified_with_params(
        &mut self,
        package_id: &str,
        content_digest: &str,
        ttl: Duration,
        session_id: Option<String>,
    ) {
        let now = Utc::now();
        self.entries.insert(
            package_id.to_string(),
            CachedEntitlement {
                package_id: package_id.to_string(),
                content_digest: content_digest.to_string(),
                verified_at: now,
                expires_at: now + ttl,
                session_id,
            },
        );
    }

    /// Checks if a package is currently unlocked (valid and not expired)
    pub fn is_unlocked(&self, package_id: &str) -> bool {
        if let Some(entry) = self.entries.get(package_id) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Returns a reference to the cached entitlement for a package, if not expired
    pub fn get(&self, package_id: &str) -> Option<&CachedEntitlement> {
        self.entries.get(package_id).filter(|e| !e.is_expired())
    }

    /// Total number of active (non-expired) entries in the cache
    pub fn active_count(&self) -> usize {
        let now = Utc::now();
        self.entries.values().filter(|e| e.expires_at > now).count()
    }

    // --- Invalidation Rule 1: Timeout Invalidation ---

    /// Prunes all expired entries from the cache, recording Timeout invalidation events
    pub fn prune_expired(&mut self) -> Vec<InvalidationEvent> {
        let now = Utc::now();
        let mut expired_keys = Vec::new();

        for (pkg_id, entry) in &self.entries {
            if entry.expires_at <= now {
                expired_keys.push((pkg_id.clone(), entry.session_id.clone()));
            }
        }

        let mut events = Vec::with_capacity(expired_keys.len());
        for (pkg_id, session_id) in expired_keys {
            self.entries.remove(&pkg_id);
            let event = InvalidationEvent {
                package_id: pkg_id,
                reason: InvalidationReason::Timeout,
                timestamp: now,
                session_id,
            };
            self.invalidation_history.push(event.clone());
            events.push(event);
        }

        events
    }

    // --- Invalidation Rule 2: Package Reload Invalidation ---

    /// Invalidates a single package (e.g. when modified or manually reloaded)
    pub fn invalidate_package(&mut self, package_id: &str, reason: InvalidationReason) -> bool {
        if let Some(entry) = self.entries.remove(package_id) {
            let event = InvalidationEvent {
                package_id: package_id.to_string(),
                reason,
                timestamp: Utc::now(),
                session_id: entry.session_id,
            };
            self.invalidation_history.push(event);
            true
        } else {
            false
        }
    }

    /// Invalidates entitlement on package reload
    pub fn reload_package(&mut self, package_id: &str) -> bool {
        self.invalidate_package(package_id, InvalidationReason::PackageReload)
    }

    /// Invalidates entitlement if the current content digest differs from the cached digest
    pub fn invalidate_if_digest_mismatch(&mut self, package_id: &str, current_digest: &str) -> bool {
        if let Some(entry) = self.entries.get(package_id) {
            if entry.content_digest != current_digest {
                self.invalidate_package(package_id, InvalidationReason::DigestMismatch);
                return true;
            }
        }
        false
    }

    // --- Invalidation Rule 3: Game Session Exit Invalidation ---

    /// Exits the active game session, purging either all entries or only entries bound to the session
    pub fn exit_session(&mut self, session_id: Option<&str>) -> usize {
        let now = Utc::now();
        let target_keys: Vec<(String, Option<String>)> = if let Some(target_session) = session_id {
            self.entries
                .iter()
                .filter(|(_, entry)| entry.session_id.as_deref() == Some(target_session))
                .map(|(k, v)| (k.clone(), v.session_id.clone()))
                .collect()
        } else {
            self.entries
                .iter()
                .map(|(k, v)| (k.clone(), v.session_id.clone()))
                .collect()
        };

        let count = target_keys.len();
        for (pkg_id, sess_id) in target_keys {
            self.entries.remove(&pkg_id);
            self.invalidation_history.push(InvalidationEvent {
                package_id: pkg_id,
                reason: InvalidationReason::SessionExit,
                timestamp: now,
                session_id: sess_id,
            });
        }

        if session_id.is_none() || self.active_session_id.as_deref() == session_id {
            self.active_session_id = None;
        }

        count
    }

    /// Completely clears the cache and resets session state
    pub fn clear(&mut self) {
        self.entries.clear();
        self.active_session_id = None;
    }

    /// Returns recorded invalidation events
    pub fn invalidation_history(&self) -> &[InvalidationEvent] {
        &self.invalidation_history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_invalidation() {
        let mut cache = EntitlementCache::with_ttl(Duration::seconds(100));
        let pkg = "paizo/pathfinder-core";
        let digest = "sha256:1111222233334444";

        cache.mark_verified(pkg, digest);
        assert!(cache.is_unlocked(pkg));
        assert_eq!(cache.active_count(), 1);

        // Expired entry (negative TTL)
        let expired_pkg = "paizo/starfinder-core";
        cache.mark_verified_with_params(
            expired_pkg,
            digest,
            Duration::seconds(-10),
            None,
        );

        // is_unlocked should return false for expired entry
        assert!(!cache.is_unlocked(expired_pkg));
        assert_eq!(cache.active_count(), 1);

        // prune_expired sweeps expired item
        let pruned = cache.prune_expired();
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].package_id, expired_pkg);
        assert_eq!(pruned[0].reason, InvalidationReason::Timeout);

        // Valid package still intact
        assert!(cache.is_unlocked(pkg));
    }

    #[test]
    fn test_package_reload_and_digest_mismatch_invalidation() {
        let mut cache = EntitlementCache::new();
        let pkg = "paizo/bestiary-1";
        let initial_digest = "sha256:aaaa1111";

        cache.mark_verified(pkg, initial_digest);
        assert!(cache.is_unlocked(pkg));

        // Invalidate on reload
        let reloaded = cache.reload_package(pkg);
        assert!(reloaded);
        assert!(!cache.is_unlocked(pkg));

        // Re-verify
        cache.mark_verified(pkg, initial_digest);
        assert!(cache.is_unlocked(pkg));

        // Digest mismatch check
        let changed = cache.invalidate_if_digest_mismatch(pkg, "sha256:bbbb2222");
        assert!(changed);
        assert!(!cache.is_unlocked(pkg));

        // Matching digest does not invalidate
        cache.mark_verified(pkg, "sha256:bbbb2222");
        let same = cache.invalidate_if_digest_mismatch(pkg, "sha256:bbbb2222");
        assert!(!same);
        assert!(cache.is_unlocked(pkg));
    }

    #[test]
    fn test_game_session_exit_invalidation() {
        let mut cache = EntitlementCache::new();
        cache.set_active_session_id(Some("session-alpha".to_string()));

        cache.mark_verified("pkg-1", "digest-1");
        cache.mark_verified("pkg-2", "digest-2");

        // Add an entry in another session
        cache.mark_verified_with_params(
            "pkg-3",
            "digest-3",
            Duration::hours(2),
            Some("session-beta".to_string()),
        );

        assert_eq!(cache.active_count(), 3);

        // Exit session-alpha only
        let cleared = cache.exit_session(Some("session-alpha"));
        assert_eq!(cleared, 2);
        assert!(!cache.is_unlocked("pkg-1"));
        assert!(!cache.is_unlocked("pkg-2"));
        assert!(cache.is_unlocked("pkg-3"));

        // Global exit
        let cleared_all = cache.exit_session(None);
        assert_eq!(cleared_all, 1);
        assert!(!cache.is_unlocked("pkg-3"));
        assert_eq!(cache.active_count(), 0);
    }
}
