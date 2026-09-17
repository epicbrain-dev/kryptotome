use chrono::Utc;
use kryptotome_verifier::session::{
    PeerAccessRequest, PeerAccessResponse, SessionManager,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableBeaconConfig {
    pub session_id: String,
    pub table_name: String,
    pub bind_address: String,
    pub advertised_service: String,
    pub campaign_package_ids: Vec<String>,
}

impl Default for TableBeaconConfig {
    fn default() -> Self {
        Self {
            session_id: format!("table-session-{}", Utc::now().timestamp()),
            table_name: "Friday Night Table".to_string(),
            bind_address: "127.0.0.1:8443".to_string(),
            advertised_service: "_kryptotome-table._tcp".to_string(),
            campaign_package_ids: vec!["paizo/player-core".to_string(), "paizo/gm-core".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableBeaconState {
    pub is_active: bool,
    pub session_id: String,
    pub table_name: String,
    pub bind_address: String,
    pub advertised_service: String,
    pub connected_peers: Vec<String>,
    pub started_at: String,
}

pub struct AirGappedTableBeaconDaemon {
    config: TableBeaconConfig,
    session_manager: Arc<Mutex<SessionManager>>,
    connected_peers: Arc<Mutex<HashSet<String>>>,
    is_active: Arc<Mutex<bool>>,
}

impl AirGappedTableBeaconDaemon {
    pub fn new(config: TableBeaconConfig) -> Self {
        let session_manager = Arc::new(Mutex::new(SessionManager::new(config.session_id.clone())));
        Self {
            config,
            session_manager,
            connected_peers: Arc::new(Mutex::new(HashSet::new())),
            is_active: Arc::new(Mutex::new(false)),
        }
    }

    pub fn start(&self) -> TableBeaconState {
        let mut active = self.is_active.lock().unwrap();
        *active = true;

        TableBeaconState {
            is_active: true,
            session_id: self.config.session_id.clone(),
            table_name: self.config.table_name.clone(),
            bind_address: self.config.bind_address.clone(),
            advertised_service: self.config.advertised_service.clone(),
            connected_peers: self
                .connected_peers
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect(),
            started_at: Utc::now().to_rfc3339(),
        }
    }

    pub fn stop(&self) -> bool {
        let mut active = self.is_active.lock().unwrap();
        if *active {
            *active = false;
            self.connected_peers.lock().unwrap().clear();
            true
        } else {
            false
        }
    }

    pub fn handle_peer_handshake(
        &self,
        request: &PeerAccessRequest,
    ) -> Result<PeerAccessResponse, String> {
        let start = Instant::now();

        if !*self.is_active.lock().unwrap() {
            return Err("Table beacon is currently inactive".to_string());
        }

        let is_entitled = self
            .config
            .campaign_package_ids
            .iter()
            .any(|pkg| pkg == &request.package_id);

        let dummy_digest = "blake3:table-content-digest-verified-8899aabbcc";

        let mut sm = self.session_manager.lock().unwrap();
        let response = sm
            .handle_peer_access_request_simple(
                request,
                is_entitled,
                dummy_digest,
                None,
                Some(120),
            )
            .map_err(|e| format!("Peer handshake rejected: {}", e))?;

        // Record peer connection
        self.connected_peers
            .lock()
            .unwrap()
            .insert(request.recipient_peer_id.clone());

        let elapsed = start.elapsed();
        if elapsed.as_millis() > 10 {
            eprintln!(
                "[WARN] Peer handshake took {:?}, exceeding 10ms target",
                elapsed
            );
        }

        Ok(response)
    }

    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers.lock().unwrap().len()
    }

    pub fn get_state(&self) -> TableBeaconState {
        TableBeaconState {
            is_active: *self.is_active.lock().unwrap(),
            session_id: self.config.session_id.clone(),
            table_name: self.config.table_name.clone(),
            bind_address: self.config.bind_address.clone(),
            advertised_service: self.config.advertised_service.clone(),
            connected_peers: self
                .connected_peers
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect(),
            started_at: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_beacon_lifecycle_and_state() {
        let config = TableBeaconConfig {
            session_id: "test-session-1".to_string(),
            table_name: "Dragon Heist Table".to_string(),
            bind_address: "0.0.0.0:8443".to_string(),
            advertised_service: "_kryptotome-table._tcp".to_string(),
            campaign_package_ids: vec!["paizo/player-core".to_string()],
        };

        let beacon = AirGappedTableBeaconDaemon::new(config);
        assert!(!beacon.get_state().is_active);

        let state = beacon.start();
        assert!(state.is_active);
        assert_eq!(state.session_id, "test-session-1");
        assert_eq!(state.table_name, "Dragon Heist Table");
        assert_eq!(state.advertised_service, "_kryptotome-table._tcp");

        assert!(beacon.stop());
        assert!(!beacon.get_state().is_active);
    }

    #[test]
    fn test_air_gapped_handshake_sub_10ms_guarantee() {
        let config = TableBeaconConfig::default();
        let beacon = AirGappedTableBeaconDaemon::new(config);
        beacon.start();

        // Construct sample peer access request using official constructor
        let request = PeerAccessRequest::new("peer-player-123", "paizo/player-core");

        let start = Instant::now();
        let response = beacon.handle_peer_handshake(&request).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(response.attestation.recipient_peer_id, "peer-player-123");
        assert_eq!(response.attestation.package_id, "paizo/player-core");
        assert_eq!(beacon.connected_peer_count(), 1);
        assert!(
            elapsed.as_millis() < 10,
            "Handshake must execute in < 10ms, took {:?}",
            elapsed
        );
    }
}
