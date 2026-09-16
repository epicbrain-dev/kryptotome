use ed25519_dalek::SigningKey;
use kryptotome_cli::batch::{auto_discover_batch_spec, execute_batch_sign, BatchPackageSpec, BatchSignSpec};
use kryptotome_cli::bundle::{build_ktome_archive, inspect_ktome_archive, unpack_ktome_archive};
use kryptotome_cli::publisher::{PackageLicense, PublisherToolchain};
use kryptotome_cli::scanner::ScanOptions;
use kryptotome_core::digest::DigestAlgorithm;
use rand::rngs::OsRng;
use std::path::PathBuf;

fn create_sample_module(base_dir: &std::path::Path, module_name: &str) -> PathBuf {
    let mod_dir = base_dir.join(module_name);
    std::fs::create_dir_all(mod_dir.join("rules")).unwrap();
    std::fs::create_dir_all(mod_dir.join("assets")).unwrap();

    std::fs::write(
        mod_dir.join("rules").join(format!("{}.json", module_name)),
        format!("{{\"module\": \"{}\", \"version\": \"1.0.0\"}}", module_name).as_bytes(),
    ).unwrap();

    std::fs::write(
        mod_dir.join("assets").join("icon.png"),
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01",
    ).unwrap();

    mod_dir
}

#[test]
fn test_build_inspect_and_unpack_ktome_archive() {
    let temp_root = std::env::temp_dir().join(format!("ktome_bundle_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_root).unwrap();

    let source_dir = create_sample_module(&temp_root, "pf2e_spells");
    let ktome_output = temp_root.join("pf2e_spells-1.0.0.ktome");
    let unpack_dest = temp_root.join("unpacked_spells");

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let toolchain = PublisherToolchain::new(signing_key);

    let manifest = toolchain.build_and_sign_package_with_license(
        "paizo/spells",
        "Pathfinder Spells Compendium",
        "1.0.0",
        "Paizo Inc.",
        &source_dir,
        ScanOptions { algorithm: DigestAlgorithm::Sha256, show_progress: false },
        PackageLicense::new_orc("Paizo Inc."),
    ).unwrap();

    // 1. Build .ktome archive
    let bundle_rep = build_ktome_archive(&manifest, &source_dir, &ktome_output, false).unwrap();
    assert!(bundle_rep.archive_size_bytes > 0);
    assert_eq!(bundle_rep.total_files_bundled, 3); // manifest.json + 2 assets

    // 2. Inspect manifest from .ktome archive directly without full extraction
    let inspected_manifest = inspect_ktome_archive(&ktome_output).unwrap();
    assert_eq!(inspected_manifest.package_id, "paizo/spells");
    assert_eq!(inspected_manifest.root_digest, manifest.root_digest);
    assert_eq!(inspected_manifest.files.len(), 2);
    assert_eq!(inspected_manifest.license.r#type, "ORC-1.0");

    // 3. Unpack and verify integrity
    let unpack_rep = unpack_ktome_archive(&ktome_output, &unpack_dest, true, false).unwrap();
    assert_eq!(unpack_rep.extracted_files, 3);
    assert!(unpack_rep.manifest_verified.unwrap().is_valid);
    assert!(unpack_rep.directory_integrity.unwrap().is_valid);

    // Verify file content on disk
    let extracted_json = std::fs::read_to_string(unpack_dest.join("rules").join("pf2e_spells.json")).unwrap();
    assert!(extracted_json.contains("pf2e_spells"));

    // Cleanup
    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn test_batch_signing_spec_and_packaging() {
    let temp_root = std::env::temp_dir().join(format!("ktome_batch_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_root).unwrap();

    let mod_a = create_sample_module(&temp_root, "bestiary_vol1");
    let mod_b = create_sample_module(&temp_root, "magic_items");
    let dist_dir = temp_root.join("dist");

    let spec = BatchSignSpec {
        publisher_name: "Paizo Publishing".to_string(),
        packages: vec![
            BatchPackageSpec {
                package_id: "paizo/bestiary-1".to_string(),
                title: "Pathfinder Bestiary 1".to_string(),
                version: "2.0.0".to_string(),
                dir: mod_a,
                license_type: Some("ORC-1.0".to_string()),
                license_url: None,
                license_attribution: None,
                algorithm: Some("sha-256".to_string()),
            },
            BatchPackageSpec {
                package_id: "paizo/magic-items".to_string(),
                title: "Magic Vault".to_string(),
                version: "1.5.0".to_string(),
                dir: mod_b,
                license_type: Some("CC-BY-4.0".to_string()),
                license_url: None,
                license_attribution: Some("Magic Items CC-BY Paizo".to_string()),
                algorithm: Some("sha-256".to_string()),
            },
        ],
    };

    let mut csprng = OsRng;
    let batch_key = SigningKey::generate(&mut csprng);

    let batch_rep = execute_batch_sign(spec, &dist_dir, Some(batch_key), false).unwrap();
    assert_eq!(batch_rep.total_packages, 2);
    assert_eq!(batch_rep.packages.len(), 2);

    // Verify .ktome bundles exist
    for pkg in &batch_rep.packages {
        assert!(pkg.bundle_path.is_file());
        assert!(pkg.manifest_path.is_file());
        assert!(pkg.bundle_size_bytes > 0);

        // Verify each bundle can be inspected and unpacked cleanly
        let inspected = inspect_ktome_archive(&pkg.bundle_path).unwrap();
        assert_eq!(inspected.package_id, pkg.package_id);
    }

    assert!(dist_dir.join("batch-summary.json").is_file());

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn test_auto_discover_batch_spec() {
    let temp_root = std::env::temp_dir().join(format!("ktome_autobatch_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_root).unwrap();

    let _ = create_sample_module(&temp_root, "core_rules");
    let _ = create_sample_module(&temp_root, "gamemastery_guide");

    let spec = auto_discover_batch_spec(&temp_root, "Paizo", "1.0.0", "ORC-1.0").unwrap();
    assert_eq!(spec.packages.len(), 2);
    assert_eq!(spec.publisher_name, "Paizo");

    let dist_dir = temp_root.join("auto_dist");
    let report = execute_batch_sign(spec, &dist_dir, None, false).unwrap();
    assert_eq!(report.total_packages, 2);

    let _ = std::fs::remove_dir_all(temp_root);
}
