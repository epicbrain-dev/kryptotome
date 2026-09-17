use kryptotome_core::digest::{
    compute_directory_digest, compute_directory_digest_blake3,
    compute_file_digest, compute_file_digest_blake3, compute_file_digest_with_algorithm,
    DigestAlgorithm,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

struct FixtureSetup {
    root_dir: PathBuf,
}

impl FixtureSetup {
    fn new(name: &str) -> Self {
        let root_dir = std::env::temp_dir().join(format!("ktome_fixtures_{}_{}", name, rand::random::<u64>()));
        fs::create_dir_all(&root_dir).expect("Failed to create fixture directory");

        // Populate deterministic fixture files
        Self::write_file(&root_dir.join("manifest.json"), b"{\"name\": \"core-rules\", \"version\": \"1.0.0\"}\n");

        let rules_dir = root_dir.join("rules");
        fs::create_dir_all(&rules_dir).expect("Failed to create rules directory");
        Self::write_file(&rules_dir.join("combat.json"), b"{\"action\": \"strike\", \"cost\": 1}\n");
        Self::write_file(&rules_dir.join("spells.json"), b"{\"spell\": \"fireball\", \"level\": 3}\n");

        let assets_dir = root_dir.join("assets");
        fs::create_dir_all(&assets_dir).expect("Failed to create assets directory");
        Self::write_file(&assets_dir.join("token.png"), b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR");

        Self { root_dir }
    }

    fn write_file(path: &Path, content: &[u8]) {
        let mut file = File::create(path).expect("Failed to create file");
        file.write_all(content).expect("Failed to write fixture content");
        file.sync_all().expect("Failed to sync file");
    }
}

impl Drop for FixtureSetup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

#[test]
fn test_compute_file_digest_deterministic_fixtures() {
    let fixture = FixtureSetup::new("file_digests");

    // 1. Deterministic SHA-256 comparison for manifest.json
    // content: b"{\"name\": \"core-rules\", \"version\": \"1.0.0\"}\n"
    let manifest_path = fixture.root_dir.join("manifest.json");
    let sha256_digest = compute_file_digest(&manifest_path).expect("SHA-256 digest computation failed");

    // Verify against independent standard sha2 computation
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"{\"name\": \"core-rules\", \"version\": \"1.0.0\"}\n");
    let expected_sha256 = format!("{:x}", hasher.finalize());
    assert_eq!(sha256_digest, expected_sha256);
    assert_eq!(sha256_digest.len(), 64);

    // 2. Deterministic BLAKE3 comparison for token.png
    let token_path = fixture.root_dir.join("assets").join("token.png");
    let blake3_digest = compute_file_digest_blake3(&token_path).expect("BLAKE3 digest computation failed");

    let mut b3_hasher = blake3::Hasher::new();
    b3_hasher.update(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR");
    let expected_blake3 = b3_hasher.finalize().to_hex().to_string();
    assert_eq!(blake3_digest, expected_blake3);
    assert_eq!(blake3_digest.len(), 64);

    // 3. Algorithm switching via compute_file_digest_with_algorithm
    let sha_via_alg = compute_file_digest_with_algorithm(&manifest_path, DigestAlgorithm::Sha256).unwrap();
    let b3_via_alg = compute_file_digest_with_algorithm(&manifest_path, DigestAlgorithm::Blake3).unwrap();
    assert_eq!(sha_via_alg, sha256_digest);
    assert_ne!(sha_via_alg, b3_via_alg);
}

#[test]
fn test_compute_directory_digest_deterministic_fixtures() {
    let fixture1 = FixtureSetup::new("dir_digests_1");
    let fixture2 = FixtureSetup::new("dir_digests_2");

    // 1. Two separately constructed fixture directory trees with identical content must yield identical root digests
    let sha_root_1 = compute_directory_digest(&fixture1.root_dir).expect("Directory SHA-256 digest failed");
    let sha_root_2 = compute_directory_digest(&fixture2.root_dir).expect("Directory SHA-256 digest failed");
    assert_eq!(sha_root_1, sha_root_2, "Directory digests must be bit-exact deterministic");
    assert_eq!(sha_root_1.len(), 64);

    let b3_root_1 = compute_directory_digest_blake3(&fixture1.root_dir).expect("Directory BLAKE3 digest failed");
    let b3_root_2 = compute_directory_digest_blake3(&fixture2.root_dir).expect("Directory BLAKE3 digest failed");
    assert_eq!(b3_root_1, b3_root_2, "BLAKE3 directory digests must be bit-exact deterministic");
    assert_eq!(b3_root_1.len(), 64);
    assert_ne!(sha_root_1, b3_root_1, "SHA-256 and BLAKE3 digests must differ");

    // 2. Verify exact canonical ordering calculation
    // Sorted relative paths:
    // assets/token.png
    // manifest.json
    // rules/combat.json
    // rules/spells.json
    let token_digest = compute_file_digest(fixture1.root_dir.join("assets").join("token.png")).unwrap();
    let manifest_digest = compute_file_digest(fixture1.root_dir.join("manifest.json")).unwrap();
    let combat_digest = compute_file_digest(fixture1.root_dir.join("rules").join("combat.json")).unwrap();
    let spells_digest = compute_file_digest(fixture1.root_dir.join("rules").join("spells.json")).unwrap();

    use sha2::{Digest, Sha256};
    let mut manual_hasher = Sha256::new();
    manual_hasher.update(format!("assets/token.png:{}\n", token_digest).as_bytes());
    manual_hasher.update(format!("manifest.json:{}\n", manifest_digest).as_bytes());
    manual_hasher.update(format!("rules/combat.json:{}\n", combat_digest).as_bytes());
    manual_hasher.update(format!("rules/spells.json:{}\n", spells_digest).as_bytes());
    let expected_root_sha = format!("{:x}", manual_hasher.finalize());

    assert_eq!(sha_root_1, expected_root_sha, "Directory digest must match canonical sorted hash computation");
}

#[test]
fn test_directory_digest_tamper_sensitivity() {
    let fixture = FixtureSetup::new("tamper_test");
    let baseline_sha = compute_directory_digest(&fixture.root_dir).unwrap();
    let baseline_b3 = compute_directory_digest_blake3(&fixture.root_dir).unwrap();

    // 1. Modifying 1 byte in nested file alters root digest
    let combat_path = fixture.root_dir.join("rules").join("combat.json");
    fs::write(&combat_path, b"{\"action\": \"strike\", \"cost\": 2}\n").unwrap();

    let tampered_sha = compute_directory_digest(&fixture.root_dir).unwrap();
    let tampered_b3 = compute_directory_digest_blake3(&fixture.root_dir).unwrap();
    assert_ne!(baseline_sha, tampered_sha, "Modifying file must change SHA-256 root digest");
    assert_ne!(baseline_b3, tampered_b3, "Modifying file must change BLAKE3 root digest");

    // 2. Adding an extra file alters root digest
    fs::write(fixture.root_dir.join("extra.txt"), b"extra data").unwrap();
    let extended_sha = compute_directory_digest(&fixture.root_dir).unwrap();
    assert_ne!(tampered_sha, extended_sha, "Adding file must change root digest");

    // 3. Removing a file alters root digest
    fs::remove_file(fixture.root_dir.join("extra.txt")).unwrap();
    let restored_sha = compute_directory_digest(&fixture.root_dir).unwrap();
    assert_eq!(tampered_sha, restored_sha, "Restoring tree must restore root digest");
}

#[test]
fn test_empty_directory_digest() {
    let empty_dir = std::env::temp_dir().join(format!("ktome_empty_{}", rand::random::<u64>()));
    fs::create_dir_all(&empty_dir).unwrap();

    let sha_empty = compute_directory_digest(&empty_dir).unwrap();
    let b3_empty = compute_directory_digest_blake3(&empty_dir).unwrap();

    // Empty dir hasher computes hash of 0 bytes
    use sha2::{Digest, Sha256};
    let hasher = Sha256::new();
    let expected_empty_sha = format!("{:x}", hasher.finalize());
    assert_eq!(sha_empty, expected_empty_sha);

    let expected_empty_b3 = blake3::Hasher::new().finalize().to_hex().to_string();
    assert_eq!(b3_empty, expected_empty_b3);

    fs::remove_dir_all(empty_dir).unwrap();
}
