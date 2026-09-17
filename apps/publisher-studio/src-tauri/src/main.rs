#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ed25519_dalek::SigningKey;
use kryptotome_publisher_studio::{
    format_ndef_payload, generate_batch_fulfillment, generate_voucher_batch, hash_asset_content,
    parse_backer_csv, sign_and_build_package, AuditLogEntry, BatchFulfillmentReport,
    BuiltPackageBundle, CrowdfundingPlatform, FulfillmentTierConfig, NfcTagPayload,
    PhysicalVoucherBatchSpec, PhysicalVoucherRecord, RulebookAsset, StudioPackageManifest,
    AUDIT_CHRONICLE,
};

fn main() {
    println!("==================================================");
    println!("  Kryptotome Publisher Studio (Tauri Desktop App)");
    println!("==================================================");
    println!("Packaging engine: Deterministic BLAKE3 hashing");
    println!("Hardware key signing: Ed25519");
    println!("Fulfillment: Kickstarter & BackerKit CSV bridge");
    println!("POD Physical: Scratch-off codes & NTAG213/215 NFC tags");
    println!("Enterprise Audit Chronicle: ACTIVE");
}

// IPC Command Bridge for Webview Frontend
pub fn scan_asset(path: &str, mime_type: &str, content: &[u8]) -> Result<RulebookAsset, String> {
    hash_asset_content(path, mime_type, content).map_err(|e| e.to_string())
}

pub fn build_package(
    manifest: StudioPackageManifest,
    signing_key_hex: &str,
) -> Result<BuiltPackageBundle, String> {
    let key_bytes =
        hex::decode(signing_key_hex).map_err(|e| format!("Invalid hex signing key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Signing key must be exactly 32 bytes (64 hex characters)".into());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    sign_and_build_package(manifest, &key_arr).map_err(|e| e.to_string())
}

pub fn ingest_crowdfunding(
    platform: CrowdfundingPlatform,
    csv_content: &str,
    tier_configs: &[FulfillmentTierConfig],
    publisher_id: &str,
    publisher_name: &str,
    signing_key_hex: &str,
) -> Result<BatchFulfillmentReport, String> {
    let key_bytes =
        hex::decode(signing_key_hex).map_err(|e| format!("Invalid hex signing key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Signing key must be 32 bytes".into());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_arr);

    let backers = parse_backer_csv(csv_content, platform).map_err(|e| e.to_string())?;
    generate_batch_fulfillment(
        &backers,
        tier_configs,
        publisher_id,
        publisher_name,
        platform,
        &signing_key,
    )
    .map_err(|e| e.to_string())
}

pub fn generate_vouchers(
    spec: &PhysicalVoucherBatchSpec,
    signing_key_hex: &str,
) -> Result<Vec<PhysicalVoucherRecord>, String> {
    let key_bytes =
        hex::decode(signing_key_hex).map_err(|e| format!("Invalid hex signing key: {}", e))?;
    if key_bytes.len() != 32 {
        return Err("Signing key must be 32 bytes".into());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_arr);

    generate_voucher_batch(spec, &signing_key).map_err(|e| e.to_string())
}

pub fn export_nfc_ndef(record: &PhysicalVoucherRecord) -> Result<NfcTagPayload, String> {
    format_ndef_payload(record).map_err(|e| e.to_string())
}

pub fn get_audit_log() -> Vec<AuditLogEntry> {
    AUDIT_CHRONICLE.get_entries()
}
