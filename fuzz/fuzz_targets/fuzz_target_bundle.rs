#![no_main]

use libfuzzer_sys::fuzz_target;
use kryptotome_core::circuit::EntitlementProofBundle;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz compact binary presentation bundle deserialization
    let _ = EntitlementProofBundle::from_compact_bytes(data);

    // 2. Fuzz JSON presentation bundle deserialization
    let _ = serde_json::from_slice::<EntitlementProofBundle>(data);
});
