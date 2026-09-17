#![no_main]

use libfuzzer_sys::fuzz_target;
use kryptotome_core::{
    deserialize_proof_compressed, deserialize_vk_compressed,
    zkp::{ProofInputs, ZkProof},
};

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz compressed Groth16 proof deserializer
    let _ = deserialize_proof_compressed(data);

    // 2. Fuzz verifying key deserializer
    let _ = deserialize_vk_compressed(data);

    // 3. Fuzz Base64 proof parser with arbitrary string
    if let Ok(s) = std::str::from_utf8(data) {
        let dummy_inputs = ProofInputs {
            challenge_nonce: "nonce".to_string(),
            package_id: "pkg".to_string(),
            content_digest: "digest".to_string(),
            publisher_pubkey_hash: "hash".to_string(),
            holder_commitment: None,
        };
        let _ = ZkProof::from_base64(s, dummy_inputs);
    }
});
