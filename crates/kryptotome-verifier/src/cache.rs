use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CachedEntitlement {
    pub package_id: String,
    pub content_digest: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct EntitlementCache {
    entries: HashMap<String, CachedEntitlement>,
}

impl EntitlementCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn mark_verified(&mut self, package_id: &str, content_digest: &str) {
        self.entries.insert(
            package_id.to_string(),
            CachedEntitlement {
                package_id: package_id.to_string(),
                content_digest: content_digest.to_string(),
                verified_at: Utc::now(),
            },
        );
    }

    pub fn is_unlocked(&self, package_id: &str) -> bool {
        self.entries.contains_key(package_id)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}
