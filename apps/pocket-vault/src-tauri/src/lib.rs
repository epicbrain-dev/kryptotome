use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PocketVaultError {
    #[error("Biometric authentication failed: {0}")]
    BiometricFailed(String),
    #[error("Hardware enclave error: {0}")]
    EnclaveError(String),
    #[error("QR frame corrupt or missing: {0}")]
    QrFrameError(String),
    #[error("Table beacon error: {0}")]
    BeaconError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// 1. Biometric & Secure Enclave / Android Keystore Security
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnclaveType {
    AppleSecureEnclave,
    AndroidKeystoreStrongBox,
    SoftwareFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricAuthResult {
    pub authenticated: bool,
    pub enclave_type: EnclaveType,
    pub key_tag: String,
    pub hardware_attestation: String,
    pub authenticated_at: String,
}

pub struct BiometricAuthManager {
    enclave_type: EnclaveType,
    biometric_enrolled: bool,
    master_key_tag: String,
}

impl BiometricAuthManager {
    pub fn new(enclave_type: EnclaveType) -> Self {
        Self {
            enclave_type,
            biometric_enrolled: true,
            master_key_tag: "org.kryptotome.pocketvault.master".to_string(),
        }
    }

    pub fn is_biometric_available(&self) -> bool {
        self.biometric_enrolled
    }

    pub fn authenticate(&self, user_prompt: &str) -> Result<BiometricAuthResult, PocketVaultError> {
        if !self.biometric_enrolled {
            return Err(PocketVaultError::BiometricFailed(
                "No biometric credentials enrolled on this device".to_string(),
            ));
        }

        // Generate synthetic cryptographic attestation signed by enclave
        let now = Utc::now().to_rfc3339();
        let mut hasher = Sha256::new();
        hasher.update(user_prompt.as_bytes());
        hasher.update(now.as_bytes());
        hasher.update(self.master_key_tag.as_bytes());
        let attestation_bytes = hasher.finalize();

        Ok(BiometricAuthResult {
            authenticated: true,
            enclave_type: self.enclave_type.clone(),
            key_tag: self.master_key_tag.clone(),
            hardware_attestation: hex::encode(attestation_bytes),
            authenticated_at: now,
        })
    }
}

// ---------------------------------------------------------------------------
// 2. Camera QR Code Ingestion & Chunked Assembly
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrFrameIngestResult {
    pub is_complete: bool,
    pub frames_received: usize,
    pub total_frames: usize,
    pub assembled_payload: Option<String>,
}

pub struct CameraQrManager {
    frame_buffers: Mutex<HashMap<String, HashMap<usize, String>>>,
    frame_totals: Mutex<HashMap<String, usize>>,
}

impl Default for CameraQrManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CameraQrManager {
    pub fn new() -> Self {
        Self {
            frame_buffers: Mutex::new(HashMap::new()),
            frame_totals: Mutex::new(HashMap::new()),
        }
    }

    /// Ingests a raw QR code frame string.
    /// Format: "KRYP:QR:<msg_id>:<frame_index>/<total_frames>:<payload>"
    pub fn ingest_frame(&self, raw_frame: &str) -> Result<QrFrameIngestResult, PocketVaultError> {
        let parts: Vec<&str> = raw_frame.splitn(5, ':').collect();
        if parts.len() < 5 || parts[0] != "KRYP" || parts[1] != "QR" {
            return Err(PocketVaultError::QrFrameError(
                "Invalid QR frame header prefix".to_string(),
            ));
        }

        let msg_id = parts[2].to_string();
        let frame_ratio: Vec<&str> = parts[3].split('/').collect();
        if frame_ratio.len() != 2 {
            return Err(PocketVaultError::QrFrameError(
                "Malformed frame ratio in QR header".to_string(),
            ));
        }

        let frame_index: usize = frame_ratio[0].parse().map_err(|_| {
            PocketVaultError::QrFrameError("Invalid frame index number".to_string())
        })?;
        let total_frames: usize = frame_ratio[1].parse().map_err(|_| {
            PocketVaultError::QrFrameError("Invalid total frames number".to_string())
        })?;
        let payload = parts[4].to_string();

        let mut buffers = self.frame_buffers.lock().unwrap();
        let mut totals = self.frame_totals.lock().unwrap();

        totals.insert(msg_id.clone(), total_frames);
        let msg_map = buffers.entry(msg_id.clone()).or_default();
        msg_map.insert(frame_index, payload);

        let received = msg_map.len();
        if received == total_frames {
            // All frames received! Assemble in deterministic order
            let mut assembled = String::new();
            for i in 1..=total_frames {
                if let Some(chunk) = msg_map.get(&i) {
                    assembled.push_str(chunk);
                } else {
                    return Err(PocketVaultError::QrFrameError(format!(
                        "Missing chunk {} during reassembly",
                        i
                    )));
                }
            }

            // Cleanup buffer
            buffers.remove(&msg_id);
            totals.remove(&msg_id);

            Ok(QrFrameIngestResult {
                is_complete: true,
                frames_received: total_frames,
                total_frames,
                assembled_payload: Some(assembled),
            })
        } else {
            Ok(QrFrameIngestResult {
                is_complete: false,
                frames_received: received,
                total_frames,
                assembled_payload: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Local Table BLE & mDNS Beacon Management
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableBeaconStatus {
    pub is_broadcasting: bool,
    pub session_id: String,
    pub table_name: String,
    pub protocol: String,
    pub service_type: String, // e.g. "_kryptotome-table._tcp"
    pub ble_service_uuid: String,
    pub connected_peers_count: usize,
    pub started_at: String,
}

pub struct TableBeaconManager {
    status: Mutex<Option<TableBeaconStatus>>,
    connected_peers: Mutex<HashSet<String>>,
}

impl Default for TableBeaconManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TableBeaconManager {
    pub fn new() -> Self {
        Self {
            status: Mutex::new(None),
            connected_peers: Mutex::new(HashSet::new()),
        }
    }

    pub fn start_beacon(
        &self,
        session_id: &str,
        table_name: &str,
    ) -> Result<TableBeaconStatus, PocketVaultError> {
        let mut status_lock = self.status.lock().unwrap();
        let status = TableBeaconStatus {
            is_broadcasting: true,
            session_id: session_id.to_string(),
            table_name: table_name.to_string(),
            protocol: "kryptotome/v1.1".to_string(),
            service_type: "_kryptotome-table._tcp".to_string(),
            ble_service_uuid: "7b42f360-1e58-45a8-8b07-0610e7a5b3a1".to_string(),
            connected_peers_count: 0,
            started_at: Utc::now().to_rfc3339(),
        };

        *status_lock = Some(status.clone());
        Ok(status)
    }

    pub fn stop_beacon(&self) -> bool {
        let mut status_lock = self.status.lock().unwrap();
        if status_lock.is_some() {
            *status_lock = None;
            self.connected_peers.lock().unwrap().clear();
            true
        } else {
            false
        }
    }

    pub fn register_peer_connection(&self, peer_id: &str) -> usize {
        let mut peers = self.connected_peers.lock().unwrap();
        peers.insert(peer_id.to_string());
        let count = peers.len();

        let mut status_lock = self.status.lock().unwrap();
        if let Some(ref mut st) = *status_lock {
            st.connected_peers_count = count;
        }
        count
    }

    pub fn get_status(&self) -> Option<TableBeaconStatus> {
        self.status.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// 4. Pocket Vault App State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntitlementSummary {
    pub package_id: String,
    pub title: String,
    pub publisher: String,
    pub digest: String,
    pub issued_at: String,
}

pub struct PocketVaultState {
    pub biometric: Arc<BiometricAuthManager>,
    pub qr_scanner: Arc<CameraQrManager>,
    pub beacon: Arc<TableBeaconManager>,
    pub entitlements: Mutex<Vec<VaultEntitlementSummary>>,
}

impl Default for PocketVaultState {
    fn default() -> Self {
        Self::new()
    }
}

impl PocketVaultState {
    pub fn new() -> Self {
        let default_entitlements = vec![
            VaultEntitlementSummary {
                package_id: "paizo/player-core".to_string(),
                title: "Pathfinder 2e: Player Core (Remaster)".to_string(),
                publisher: "Paizo Inc.".to_string(),
                digest: "sha256:73a85757532b62fd82a3b611d03ce5de2f2a3491f9b47568574afda042faeb8f"
                    .to_string(),
                issued_at: Utc::now().to_rfc3339(),
            },
            VaultEntitlementSummary {
                package_id: "open-rpg/core-spells".to_string(),
                title: "Core Spells & Cantrips Compendium".to_string(),
                publisher: "Open Gaming Foundation".to_string(),
                digest: "sha256:4b227777d4da1fc6e11e80a06451e67d3b43a50370f23ec14ff16a15f84ac524"
                    .to_string(),
                issued_at: Utc::now().to_rfc3339(),
            },
        ];

        Self {
            biometric: Arc::new(BiometricAuthManager::new(EnclaveType::AppleSecureEnclave)),
            qr_scanner: Arc::new(CameraQrManager::new()),
            beacon: Arc::new(TableBeaconManager::new()),
            entitlements: Mutex::new(default_entitlements),
        }
    }

    pub fn generate_presentation_proof(
        &self,
        package_id: &str,
        challenge_nonce: &str,
    ) -> Result<String, PocketVaultError> {
        let ents = self.entitlements.lock().unwrap();
        let ent = ents
            .iter()
            .find(|e| e.package_id == package_id)
            .ok_or_else(|| {
                PocketVaultError::BeaconError(format!(
                    "Credential for package '{}' not present in pocket vault",
                    package_id
                ))
            })?;

        let mut hasher = Sha256::new();
        hasher.update(ent.package_id.as_bytes());
        hasher.update(ent.digest.as_bytes());
        hasher.update(challenge_nonce.as_bytes());
        let digest = hasher.finalize();

        Ok(format!(
            "zkp:pocket-vault:{}:{}",
            package_id,
            hex::encode(digest)
        ))
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_authentication() {
        let auth = BiometricAuthManager::new(EnclaveType::AppleSecureEnclave);
        assert!(auth.is_biometric_available());

        let res = auth.authenticate("Unlock Kryptotome Vault").unwrap();
        assert!(res.authenticated);
        assert_eq!(res.enclave_type, EnclaveType::AppleSecureEnclave);
        assert!(!res.hardware_attestation.is_empty());
    }

    #[test]
    fn test_camera_qr_multi_frame_assembly() {
        let qr = CameraQrManager::new();

        // Feed 3 chunks out-of-order
        let frame2 = "KRYP:QR:msg-42:2/3:World!";
        let frame1 = "KRYP:QR:msg-42:1/3:Hello, ";
        let frame3 = "KRYP:QR:msg-42:3/3: [ZK-PROOF]";

        let r2 = qr.ingest_frame(frame2).unwrap();
        assert!(!r2.is_complete);
        assert_eq!(r2.frames_received, 1);

        let r1 = qr.ingest_frame(frame1).unwrap();
        assert!(!r1.is_complete);
        assert_eq!(r1.frames_received, 2);

        let r3 = qr.ingest_frame(frame3).unwrap();
        assert!(r3.is_complete);
        assert_eq!(r3.frames_received, 3);
        assert_eq!(r3.assembled_payload.unwrap(), "Hello, World! [ZK-PROOF]");
    }

    #[test]
    fn test_table_beacon_lifecycle() {
        let beacon = TableBeaconManager::new();
        assert!(beacon.get_status().is_none());

        let status = beacon
            .start_beacon("session-table-99", "Friday Night Pathfinder")
            .unwrap();
        assert!(status.is_broadcasting);
        assert_eq!(status.service_type, "_kryptotome-table._tcp");
        assert_eq!(status.connected_peers_count, 0);

        beacon.register_peer_connection("peer-alice");
        beacon.register_peer_connection("peer-bob");

        let updated = beacon.get_status().unwrap();
        assert_eq!(updated.connected_peers_count, 2);

        assert!(beacon.stop_beacon());
        assert!(beacon.get_status().is_none());
    }

    #[test]
    fn test_pocket_vault_proof_generation() {
        let state = PocketVaultState::new();
        let proof = state
            .generate_presentation_proof("paizo/player-core", "nonce-challenge-999")
            .unwrap();
        assert!(proof.starts_with("zkp:pocket-vault:paizo/player-core:"));
    }
}
