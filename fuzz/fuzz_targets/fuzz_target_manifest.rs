#![no_main]

use libfuzzer_sys::fuzz_target;
use kryptotome_cli::publisher::PackageManifest;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz JSON manifest deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<PackageManifest>(s);
    }

    // 2. Fuzz raw slice deserialization
    let _ = serde_json::from_slice::<PackageManifest>(data);
});
