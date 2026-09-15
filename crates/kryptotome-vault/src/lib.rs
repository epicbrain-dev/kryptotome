//! Kryptotome Vault: Local Keychain and Credential Vault Runtime
//!
//! Provides zero-dependency local key custody, importing/exporting signed credentials,
//! and generating single-use zero-knowledge proofs on demand.

pub mod keyring;
pub mod store;

pub use keyring::Keyring;
pub use store::{EncryptedVaultFile, VaultStore};
