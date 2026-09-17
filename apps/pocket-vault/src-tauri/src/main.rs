#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kryptotome_pocket_vault::{
    BiometricAuthResult, PocketVaultState, QrFrameIngestResult, TableBeaconStatus,
    VaultEntitlementSummary,
};
use std::sync::Arc;

fn main() {
    let state = Arc::new(PocketVaultState::new());

    println!("==================================================");
    println!("  Kryptotome Pocket Vault (Tauri Mobile / Desktop)");
    println!("==================================================");
    println!(
        "Biometric security: active ({})",
        state.biometric.is_biometric_available()
    );
    println!(
        "Available entitlements: {}",
        state.entitlements.lock().unwrap().len()
    );
}

// Mobile/Desktop Command Handlers (bridge to webview via Tauri IPC / JS bridge)
pub fn authenticate_biometrics(
    state: &PocketVaultState,
    prompt: &str,
) -> Result<BiometricAuthResult, String> {
    state
        .biometric
        .authenticate(prompt)
        .map_err(|e| e.to_string())
}

pub fn process_camera_qr_frame(
    state: &PocketVaultState,
    frame: &str,
) -> Result<QrFrameIngestResult, String> {
    state
        .qr_scanner
        .ingest_frame(frame)
        .map_err(|e| e.to_string())
}

pub fn start_table_beacon(
    state: &PocketVaultState,
    session_id: &str,
    table_name: &str,
) -> Result<TableBeaconStatus, String> {
    state
        .beacon
        .start_beacon(session_id, table_name)
        .map_err(|e| e.to_string())
}

pub fn stop_table_beacon(state: &PocketVaultState) -> bool {
    state.beacon.stop_beacon()
}

pub fn get_vault_entitlements(state: &PocketVaultState) -> Vec<VaultEntitlementSummary> {
    state.entitlements.lock().unwrap().clone()
}

pub fn generate_presentation_proof(
    state: &PocketVaultState,
    package_id: &str,
    challenge_nonce: &str,
) -> Result<String, String> {
    state
        .generate_presentation_proof(package_id, challenge_nonce)
        .map_err(|e| e.to_string())
}
