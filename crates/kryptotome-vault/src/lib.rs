//! Kryptotome Vault: Local Keychain and Credential Vault Runtime
//!
//! Provides zero-dependency local key custody, importing/exporting signed credentials,
//! and generating single-use zero-knowledge proofs on demand.

pub mod keyring;
pub mod store;

pub use keyring::Keyring;
pub use store::{EncryptedVaultFile, VaultStore};

#[cfg(test)]
mod tests {
    use super::*;
    use kryptotome_core::PedersenCommitmentScheme;

    #[test]
    fn test_keyring_commitment_derivation() {
        let keyring = Keyring::generate();
        let (commitment, secret, blinding) = keyring.derive_holder_commitment();

        let scheme = PedersenCommitmentScheme::new();
        assert!(scheme.verify(&commitment, &secret, &blinding));

        let (urn, sec2, bl2) = keyring.derive_commitment_urn();
        assert!(urn.starts_with("urn:kryptotome:commitment:bls12381:"));
        assert_eq!(secret, sec2);
        assert_ne!(blinding, bl2); // Fresh random blinding each derivation
    }
}
