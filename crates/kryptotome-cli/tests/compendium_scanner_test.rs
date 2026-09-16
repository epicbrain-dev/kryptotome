use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use kryptotome_cli::publisher::PublisherToolchain;
use kryptotome_cli::scanner::{CompendiumScanner, ScanOptions};
use kryptotome_core::digest::DigestAlgorithm;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;

fn setup_test_compendium() -> (tempfile_guard::TempDirGuard, std::path::PathBuf) {
    let temp_dir = std::env::temp_dir().join(format!("ktome_compendium_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Create subdirectories mimicking a rich tabletop compendium
    std::fs::create_dir_all(temp_dir.join("rules")).unwrap();
    std::fs::create_dir_all(temp_dir.join("assets").join("tokens")).unwrap();
    std::fs::create_dir_all(temp_dir.join("maps")).unwrap();
    std::fs::create_dir_all(temp_dir.join("audio")).unwrap();

    // 1. JSON rule file
    std::fs::write(
        temp_dir.join("rules").join("combat.json"),
        b"{\"actions\": [\"strike\", \"stride\", \"cast\"]}",
    ).unwrap();

    // 2. Token PNG
    std::fs::write(
        temp_dir.join("assets").join("tokens").join("red_dragon.png"),
        vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x42],
    ).unwrap();

    // 3. WebM Map (simulating animated battlemap with 350KB to cross 128KB chunks)
    let large_map_data = vec![0x1a, 0x45, 0xdf, 0xa3];
    let mut large_buffer = vec![0x33u8; 350 * 1024];
    large_buffer[0..4].copy_from_slice(&large_map_data);
    std::fs::write(temp_dir.join("maps").join("dungeon_4k.webm"), &large_buffer).unwrap();

    // 4. Audio Ogg
    std::fs::write(
        temp_dir.join("audio").join("dungeon_ambience.ogg"),
        b"OggS\x00\x02test_audio_stream_data",
    ).unwrap();

    // 5. Compendium index markdown
    std::fs::write(
        temp_dir.join("README.md"),
        b"# Pathfinder Compendium Module\nOpen gaming digital assets.",
    ).unwrap();

    let path = temp_dir.clone();
    (tempfile_guard::TempDirGuard(temp_dir), path)
}

mod tempfile_guard {
    use std::path::PathBuf;

    pub struct TempDirGuard(pub PathBuf);

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn test_compendium_scanner_deterministic_sha256() {
    let (_guard, temp_dir) = setup_test_compendium();

    let options = ScanOptions {
        algorithm: DigestAlgorithm::Sha256,
        show_progress: false,
    };
    let scanner = CompendiumScanner::new(options);
    let result = scanner.scan_directory(&temp_dir).unwrap();

    // 1. Verify exact match with kryptotome-core root directory digest
    let core_digest = kryptotome_core::compute_directory_digest_with_algorithm(
        &temp_dir,
        DigestAlgorithm::Sha256,
    ).unwrap();
    assert_eq!(result.root_digest, core_digest);

    // 2. Verify total files and bytes
    assert_eq!(result.total_files, 5);
    assert!(result.total_bytes > 350 * 1024);

    // 3. Verify deterministically sorted file paths
    let paths: Vec<String> = result.files.iter().map(|f| f.path.clone()).collect();
    let mut sorted_paths = paths.clone();
    sorted_paths.sort();
    assert_eq!(paths, sorted_paths);

    // 4. Verify content types
    let find_entry = |path: &str| result.files.iter().find(|e| e.path == path).unwrap();
    assert_eq!(find_entry("rules/combat.json").content_type, "application/json");
    assert_eq!(find_entry("assets/tokens/red_dragon.png").content_type, "image/png");
    assert_eq!(find_entry("maps/dungeon_4k.webm").content_type, "video/webm");
    assert_eq!(find_entry("audio/dungeon_ambience.ogg").content_type, "audio/ogg");
    assert_eq!(find_entry("README.md").content_type, "text/markdown");

    // 5. Verify each individual file digest matches kryptotome-core
    for entry in &result.files {
        let abs_path = temp_dir.join(&entry.path);
        let expected = kryptotome_core::compute_file_digest(&abs_path).unwrap();
        assert_eq!(entry.digest, expected, "Digest mismatch for {}", entry.path);
    }
}

#[test]
fn test_compendium_scanner_deterministic_blake3() {
    let (_guard, temp_dir) = setup_test_compendium();

    let options = ScanOptions {
        algorithm: DigestAlgorithm::Blake3,
        show_progress: false,
    };
    let scanner = CompendiumScanner::new(options);
    let result = scanner.scan_directory(&temp_dir).unwrap();

    // 1. Verify exact match with kryptotome-core root directory BLAKE3 digest
    let core_digest = kryptotome_core::compute_directory_digest_with_algorithm(
        &temp_dir,
        DigestAlgorithm::Blake3,
    ).unwrap();
    assert_eq!(result.root_digest, core_digest);

    // 2. Verify individual BLAKE3 file digests match
    for entry in &result.files {
        let abs_path = temp_dir.join(&entry.path);
        let expected = kryptotome_core::compute_file_digest_blake3(&abs_path).unwrap();
        assert_eq!(entry.digest, expected, "BLAKE3 digest mismatch for {}", entry.path);
    }
}

#[test]
fn test_compendium_scanner_with_progress_enabled() {
    let (_guard, temp_dir) = setup_test_compendium();

    // Test with show_progress: true (indicatif bars active)
    let options = ScanOptions {
        algorithm: DigestAlgorithm::Sha256,
        show_progress: true,
    };
    let scanner = CompendiumScanner::new(options);
    let result = scanner.scan_directory(&temp_dir).unwrap();

    assert_eq!(result.total_files, 5);
    assert!(!result.root_digest.is_empty());
}

#[test]
fn test_publisher_build_and_sign_package_with_scanner() {
    let (_guard, temp_dir) = setup_test_compendium();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let toolchain = PublisherToolchain::new(signing_key);
    let manifest = toolchain.build_and_sign_package(
        "paizo.pf2e.core-rulebook",
        "Pathfinder 2e Core Rulebook",
        "2.0.0",
        "Paizo Inc.",
        &temp_dir,
        DigestAlgorithm::Sha256,
    ).unwrap();

    assert_eq!(manifest.package_id, "paizo.pf2e.core-rulebook");
    assert_eq!(manifest.title, "Pathfinder 2e Core Rulebook");
    assert_eq!(manifest.version, "2.0.0");
    assert_eq!(manifest.files.len(), 5);
    assert_eq!(manifest.digest_algorithm, "SHA-256");

    // Verify Ed25519 signature on (package_id:version:root_digest)
    let signature_entry = manifest.signature.expect("manifest must be signed");
    assert_eq!(signature_entry.algorithm, "Ed25519");

    let sig_bytes = hex::decode(&signature_entry.signature_value).unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    let payload = format!("{}:{}:{}", manifest.package_id, manifest.version, manifest.root_digest);

    assert!(verifying_key.verify(payload.as_bytes(), &signature).is_ok());
}

#[test]
fn test_compendium_scanner_nonexistent_directory() {
    let bogus_dir = std::env::temp_dir().join(format!("nonexistent_ktome_{}", rand::random::<u64>()));
    let scanner = CompendiumScanner::new(ScanOptions::default());
    let err = scanner.scan_directory(&bogus_dir);
    assert!(err.is_err());
}

#[test]
fn test_verify_package_manifest_valid() {
    let (_guard, temp_dir) = setup_test_compendium();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let pubkey_hex = hex_encode(signing_key.verifying_key().as_bytes());

    let toolchain = PublisherToolchain::new(signing_key);
    let manifest = toolchain.build_and_sign_package(
        "paizo.pf2e.core-rulebook",
        "Pathfinder 2e Core Rulebook",
        "2.0.0",
        "Paizo Inc.",
        &temp_dir,
        DigestAlgorithm::Sha256,
    ).unwrap();

    // 1. Verify with publisher key in manifest
    let report_auto = kryptotome_cli::publisher::verify_package_manifest(&manifest, None).unwrap();
    assert!(report_auto.is_valid);
    assert_eq!(report_auto.package_id, "paizo.pf2e.core-rulebook");
    assert_eq!(report_auto.verifying_key_hex, pubkey_hex);

    // 2. Verify with explicit matching expected pubkey
    let report_explicit = kryptotome_cli::publisher::verify_package_manifest(&manifest, Some(&pubkey_hex)).unwrap();
    assert!(report_explicit.is_valid);
}

#[test]
fn test_verify_package_manifest_tampered_fails() {
    let (_guard, temp_dir) = setup_test_compendium();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let toolchain = PublisherToolchain::new(signing_key);
    let mut manifest = toolchain.build_and_sign_package(
        "paizo.pf2e.core-rulebook",
        "Pathfinder 2e Core Rulebook",
        "2.0.0",
        "Paizo Inc.",
        &temp_dir,
        DigestAlgorithm::Sha256,
    ).unwrap();

    // Tamper with root digest
    manifest.root_digest = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let err = kryptotome_cli::publisher::verify_package_manifest(&manifest, None);
    assert!(err.is_err());
}

#[test]
fn test_verify_package_manifest_mismatching_pubkey_fails() {
    let (_guard, temp_dir) = setup_test_compendium();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let other_key = SigningKey::generate(&mut rng);
    let other_pubkey_hex = hex_encode(other_key.verifying_key().as_bytes());

    let toolchain = PublisherToolchain::new(signing_key);
    let manifest = toolchain.build_and_sign_package(
        "paizo.pf2e.core-rulebook",
        "Pathfinder 2e Core Rulebook",
        "2.0.0",
        "Paizo Inc.",
        &temp_dir,
        DigestAlgorithm::Sha256,
    ).unwrap();

    let err = kryptotome_cli::publisher::verify_package_manifest(&manifest, Some(&other_pubkey_hex));
    assert!(err.is_err());
}

#[test]
fn test_verify_package_directory_integrity() {
    let (_guard, temp_dir) = setup_test_compendium();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let toolchain = PublisherToolchain::new(signing_key);
    let manifest = toolchain.build_and_sign_package(
        "paizo.pf2e.core-rulebook",
        "Pathfinder 2e Core Rulebook",
        "2.0.0",
        "Paizo Inc.",
        &temp_dir,
        DigestAlgorithm::Sha256,
    ).unwrap();

    // 1. Pristine directory verification
    let pristine_report = kryptotome_cli::publisher::verify_package_directory(&manifest, &temp_dir, false).unwrap();
    assert!(pristine_report.is_valid);
    assert_eq!(pristine_report.matched_files, 5);
    assert!(pristine_report.missing_files.is_empty());
    assert!(pristine_report.altered_files.is_empty());

    // 2. Tampered file verification
    std::fs::write(temp_dir.join("rules").join("combat.json"), b"{\"actions\": [\"cheating\"] }").unwrap();
    let tampered_report = kryptotome_cli::publisher::verify_package_directory(&manifest, &temp_dir, false).unwrap();
    assert!(!tampered_report.is_valid);
    assert!(!tampered_report.root_digest_match);
    assert!(tampered_report.altered_files.contains(&"rules/combat.json".to_string()));
}

#[test]
fn test_license_metadata_validation_orc_cc_by_cc0() {
    let (_guard, temp_dir) = setup_test_compendium();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let toolchain = PublisherToolchain::new(signing_key);

    // 1. Paizo ORC License validation
    let orc_license = kryptotome_cli::publisher::PackageLicense::new_orc("Paizo Inc.");
    let manifest_orc = toolchain.build_and_sign_package_with_license(
        "paizo.pf2e.core",
        "Pathfinder Core",
        "2.0.0",
        "Paizo Inc.",
        &temp_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        orc_license,
    ).unwrap();
    assert_eq!(manifest_orc.license.r#type, "ORC-1.0");
    assert_eq!(manifest_orc.license.url, "https://paizo.com/orclicense");
    assert!(!manifest_orc.license.attribution.is_empty());
    let report_orc = kryptotome_cli::publisher::verify_package_manifest(&manifest_orc, None).unwrap();
    assert_eq!(report_orc.license.r#type, "ORC-1.0");

    // 2. Creative Commons CC-BY-4.0 validation
    let cc_by_license = kryptotome_cli::publisher::PackageLicense::new_cc_by("Attribution: 5e SRD Creative Commons CC-BY-4.0");
    let manifest_cc_by = toolchain.build_and_sign_package_with_license(
        "wizards.srd5",
        "System Reference Document 5.1",
        "5.1.0",
        "Open Gaming Publisher",
        &temp_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        cc_by_license,
    ).unwrap();
    assert_eq!(manifest_cc_by.license.r#type, "CC-BY-4.0");
    let report_cc_by = kryptotome_cli::publisher::verify_package_manifest(&manifest_cc_by, None).unwrap();
    assert_eq!(report_cc_by.license.r#type, "CC-BY-4.0");

    // 3. Creative Commons CC0-1.0 validation (public domain dedication with optional attribution)
    let cc0_license = kryptotome_cli::publisher::PackageLicense::new_cc0(None);
    let manifest_cc0 = toolchain.build_and_sign_package_with_license(
        "community.free-tokens",
        "Community Monster Tokens",
        "1.0.0",
        "Public Domain Artist",
        &temp_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        cc0_license,
    ).unwrap();
    assert_eq!(manifest_cc0.license.r#type, "CC0-1.0");
    let report_cc0 = kryptotome_cli::publisher::verify_package_manifest(&manifest_cc0, None).unwrap();
    assert_eq!(report_cc0.license.r#type, "CC0-1.0");
}

#[test]
fn test_license_metadata_validation_failures() {
    let (_guard, temp_dir) = setup_test_compendium();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let toolchain = PublisherToolchain::new(signing_key);

    // 1. Missing attribution on ORC license must fail validation
    let bad_orc = kryptotome_cli::publisher::PackageLicense {
        r#type: "ORC-1.0".to_string(),
        url: "https://paizo.com/orclicense".to_string(),
        attribution: "   ".to_string(),
    };
    let err = toolchain.build_and_sign_package_with_license(
        "pkg.test", "Test Title", "1.0.0", "Author", &temp_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        bad_orc,
    );
    assert!(err.is_err());

    // 2. Missing attribution on CC-BY-4.0 must fail validation
    let bad_cc_by = kryptotome_cli::publisher::PackageLicense {
        r#type: "CC-BY-4.0".to_string(),
        url: "https://creativecommons.org/licenses/by/4.0/".to_string(),
        attribution: "".to_string(),
    };
    let err_cc = toolchain.build_and_sign_package_with_license(
        "pkg.test", "Test Title", "1.0.0", "Author", &temp_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        bad_cc_by,
    );
    assert!(err_cc.is_err());

    // 3. Unsupported license type must fail validation
    let bad_type = kryptotome_cli::publisher::PackageLicense {
        r#type: "GPL-3.0".to_string(),
        url: "https://gnu.org/licenses/gpl-3.0.html".to_string(),
        attribution: "Author".to_string(),
    };
    let err_type = toolchain.build_and_sign_package_with_license(
        "pkg.test", "Test Title", "1.0.0", "Author", &temp_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        bad_type,
    );
    assert!(err_type.is_err());

    // 4. Malformed URL format must fail validation
    let bad_url = kryptotome_cli::publisher::PackageLicense {
        r#type: "CC0-1.0".to_string(),
        url: "not-a-valid-url".to_string(),
        attribution: "".to_string(),
    };
    let err_url = toolchain.build_and_sign_package_with_license(
        "pkg.test", "Test Title", "1.0.0", "Author", &temp_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        bad_url,
    );
    assert!(err_url.is_err());
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}
