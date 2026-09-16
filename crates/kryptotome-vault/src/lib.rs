//! Kryptotome Vault: Local Keychain and Credential Vault Runtime
//!
//! Provides zero-dependency local key custody, importing/exporting signed credentials,
//! and generating single-use zero-knowledge proofs on demand.

pub mod keyring;
pub mod keystore;
pub mod platform_keyring;
pub mod revocation;
pub mod store;

pub use keyring::{Keyring, KeyringBackupData, ZeroizingSecretKey};
pub use keystore::{EncryptedKeystore, EncryptionCipher, KdfParams};
pub use platform_keyring::{PlatformBackend, PlatformKeyring, DEFAULT_KEYCHAIN_SERVICE};
pub use revocation::{
    compute_leaf_hash, MerkleDirection, MerkleProof, MerkleProofStep, MerkleRevocationTree,
    PublisherRevocationList, RevocationEntry, RevocationStatus, REVOCATION_LIST_FILE_EXTENSION,
    REVOCATION_LIST_FORMAT,
};
pub use store::{
    EncryptedVaultBackup, EncryptedVaultFile, VaultBackupPayload, VaultStore,
    BACKUP_FILE_EXTENSION, BACKUP_FORMAT_IDENTIFIER,
};

#[cfg(test)]
mod tests {
    use super::*;
    use kryptotome_core::PedersenCommitmentScheme;
    use zeroize::Zeroize;

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

    #[test]
    fn test_keyring_manual_zeroize() {
        let mut keyring = Keyring::generate();
        assert!(!keyring.is_zeroized());
        assert_eq!(keyring.secret_bytes().len(), 32);
        assert_ne!(keyring.secret_bytes(), &[0u8; 32]);

        keyring.zeroize();
        assert!(keyring.is_zeroized());
        assert!(keyring.secret_bytes().is_empty());
    }

    #[test]
    fn test_zeroizing_secret_key_wrapper() {
        let secret = [0x42u8; 32];
        let mut holder = ZeroizingSecretKey::new(secret);
        assert_eq!(holder.as_slice(), &[0x42u8; 32]);
        assert!(!holder.is_zeroized());

        // Debug output must be redacted
        let debug_str = format!("{:?}", holder);
        assert_eq!(debug_str, "ZeroizingSecretKey([REDACTED])");

        holder.zeroize();
        assert!(holder.is_zeroized());
        assert_eq!(holder.as_slice(), &[0u8; 32]);
    }
}
