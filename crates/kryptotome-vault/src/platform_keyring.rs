use crate::keyring::{Keyring, ZeroizingSecretKey};
use kryptotome_core::error::{KryptotomeError, KryptotomeErrorCode, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Default service namespace used for storing Kryptotome credentials in the OS keychain
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "org.kryptotome.vault";

/// Platform credential store backend identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformBackend {
    /// Apple macOS Keychain (`Security.framework`)
    MacOsKeychain,
    /// Windows Credential Manager
    WindowsCredentialManager,
    /// Linux Freedesktop Secret Service (GNOME Keyring, KWallet via D-Bus)
    LinuxSecretService,
    /// In-memory mock store (for automated testing, headless CI, or ephemeral sessions)
    InMemoryMock,
}

impl PlatformBackend {
    /// Detects the active native OS keychain backend for the current compilation target
    pub fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::MacOsKeychain
        }
        #[cfg(target_os = "windows")]
        {
            Self::WindowsCredentialManager
        }
        #[cfg(target_os = "linux")]
        {
            Self::LinuxSecretService
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            Self::InMemoryMock
        }
    }

    /// User-facing label of the platform backend
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MacOsKeychain => "macOS Keychain",
            Self::WindowsCredentialManager => "Windows Credential Manager",
            Self::LinuxSecretService => "Linux Secret Service",
            Self::InMemoryMock => "In-Memory Mock",
        }
    }
}

#[derive(Clone)]
enum KeyringMode {
    Native,
    InMemory(Arc<RwLock<HashMap<String, Vec<u8>>>>),
}

/// Unified platform OS keychain interface for storing and retrieving holder secrets
/// across macOS Keychain, Windows Credential Manager, and Linux Secret Service.
#[derive(Clone)]
pub struct PlatformKeyring {
    service: String,
    mode: KeyringMode,
}

impl PlatformKeyring {
    /// Creates a platform keyring bound to the native OS secure keystore using the default service name
    pub fn new() -> Self {
        Self::with_service(DEFAULT_KEYCHAIN_SERVICE)
    }

    /// Creates a platform keyring bound to the native OS secure keystore using a custom service name
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            mode: KeyringMode::Native,
        }
    }

    /// Creates an in-memory simulated platform keychain for headless CI, unit tests, or ephemeral sessions
    pub fn in_memory() -> Self {
        Self::in_memory_with_service(DEFAULT_KEYCHAIN_SERVICE)
    }

    /// Creates an in-memory simulated platform keychain with a custom service name
    pub fn in_memory_with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            mode: KeyringMode::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    /// Returns the active service namespace identifier
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns the platform backend currently backing this instance
    pub fn backend(&self) -> PlatformBackend {
        match self.mode {
            KeyringMode::Native => PlatformBackend::current(),
            KeyringMode::InMemory(_) => PlatformBackend::InMemoryMock,
        }
    }

    /// Securely stores raw secret bytes for an account identifier in the platform keychain
    pub fn set_secret(&self, account: &str, secret_bytes: &[u8]) -> Result<()> {
        match &self.mode {
            KeyringMode::Native => {
                let hex_encoded = hex_encode(secret_bytes);
                #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
                {
                    let entry = keyring::Entry::new(&self.service, account).map_err(map_keyring_err)?;
                    entry.set_password(&hex_encoded).map_err(map_keyring_err)?;
                    Ok(())
                }
                #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
                {
                    Err(KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                        message: "Native OS keychain is not supported on this platform architecture".to_string(),
                    })
                }
            }
            KeyringMode::InMemory(store) => {
                let mut guard = store.write().map_err(|_| KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                    message: "In-memory keychain lock poisoned".to_string(),
                })?;
                guard.insert(account.to_string(), secret_bytes.to_vec());
                Ok(())
            }
        }
    }

    /// Securely loads secret bytes for an account identifier, returning a zeroizing wrapper
    pub fn get_secret(&self, account: &str) -> Result<ZeroizingSecretKey> {
        let raw_bytes = match &self.mode {
            KeyringMode::Native => {
                #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
                {
                    let entry = keyring::Entry::new(&self.service, account).map_err(map_keyring_err)?;
                    let hex_str = entry.get_password().map_err(map_keyring_err)?;
                    hex_decode(&hex_str)?
                }
                #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
                {
                    return Err(KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                        message: "Native OS keychain is not supported on this platform architecture".to_string(),
                    });
                }
            }
            KeyringMode::InMemory(store) => {
                let guard = store.read().map_err(|_| KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                    message: "In-memory keychain lock poisoned".to_string(),
                })?;
                guard.get(account).cloned().ok_or_else(|| KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                    message: format!("Key not found in platform keychain: {}", account),
                })?
            }
        };

        if raw_bytes.len() != 32 {
            return Err(KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                message: format!(
                    "Expected 32-byte secret key in keychain, found {} bytes",
                    raw_bytes.len()
                ),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw_bytes);
        Ok(ZeroizingSecretKey::new(arr))
    }

    /// Deletes a secret from the platform keychain
    pub fn delete_secret(&self, account: &str) -> Result<()> {
        match &self.mode {
            KeyringMode::Native => {
                #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
                {
                    let entry = keyring::Entry::new(&self.service, account).map_err(map_keyring_err)?;
                    entry.delete_credential().map_err(map_keyring_err)?;
                    Ok(())
                }
                #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
                {
                    Err(KryptotomeError::Detailed {
                        code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                        message: "Native OS keychain is not supported on this platform architecture".to_string(),
                    })
                }
            }
            KeyringMode::InMemory(store) => {
                let mut guard = store.write().map_err(|_| KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                    message: "In-memory keychain lock poisoned".to_string(),
                })?;
                guard.remove(account).ok_or_else(|| KryptotomeError::Detailed {
                    code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
                    message: format!("Key not found in platform keychain: {}", account),
                })?;
                Ok(())
            }
        }
    }

    /// Checks if a secret exists in the platform keychain
    pub fn has_secret(&self, account: &str) -> bool {
        self.get_secret(account).is_ok()
    }

    /// Stores a full Keyring in the platform secure store
    pub fn store_keyring(&self, keyring: &Keyring) -> Result<()> {
        self.set_secret(&keyring.key_id, keyring.secret_bytes())
    }

    /// Loads a full Keyring from the platform secure store by key ID
    pub fn load_keyring(&self, key_id: &str) -> Result<Keyring> {
        let secret = self.get_secret(key_id)?;
        Keyring::from_secret_bytes(secret.as_slice()).map_err(|e| KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp604KeyCustodyError,
            message: e,
        })
    }

    /// Deletes a full Keyring from the platform secure store
    pub fn delete_keyring(&self, key_id: &str) -> Result<()> {
        self.delete_secret(key_id)
    }
}

impl Default for PlatformKeyring {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn map_keyring_err(err: keyring::Error) -> KryptotomeError {
    match err {
        keyring::Error::NoEntry => KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
            message: "Key not found in platform keychain".to_string(),
        },
        other => KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp601KeyringAccessFailed,
            message: format!("Platform keychain access error: {}", other),
        },
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp604KeyCustodyError,
            message: "Invalid hex string length in platform keychain".to_string(),
        });
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| KryptotomeError::Detailed {
                code: KryptotomeErrorCode::Kryp604KeyCustodyError,
                message: format!("Invalid hex byte in platform keychain: {}", e),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_backend_identification() {
        let backend = PlatformBackend::current();
        #[cfg(target_os = "macos")]
        assert_eq!(backend, PlatformBackend::MacOsKeychain);
        #[cfg(target_os = "windows")]
        assert_eq!(backend, PlatformBackend::WindowsCredentialManager);
        #[cfg(target_os = "linux")]
        assert_eq!(backend, PlatformBackend::LinuxSecretService);

        let mem = PlatformKeyring::in_memory();
        assert_eq!(mem.backend(), PlatformBackend::InMemoryMock);
        assert_eq!(mem.service(), DEFAULT_KEYCHAIN_SERVICE);
    }

    #[test]
    fn test_in_memory_keyring_crud_lifecycle() {
        let keyring_store = PlatformKeyring::in_memory_with_service("org.kryptotome.test");
        let keyring = Keyring::generate();
        let key_id = keyring.key_id.clone();

        // 1. Store keyring
        assert!(!keyring_store.has_secret(&key_id));
        keyring_store.store_keyring(&keyring).unwrap();
        assert!(keyring_store.has_secret(&key_id));

        // 2. Load keyring
        let loaded = keyring_store.load_keyring(&key_id).unwrap();
        assert_eq!(loaded.key_id, keyring.key_id);
        assert_eq!(loaded.public_key_hex, keyring.public_key_hex);
        assert_eq!(loaded.secret_bytes(), keyring.secret_bytes());

        // 3. Raw secret retrieval
        let secret = keyring_store.get_secret(&key_id).unwrap();
        assert_eq!(secret.as_slice(), keyring.secret_bytes());

        // 4. Delete keyring
        keyring_store.delete_keyring(&key_id).unwrap();
        assert!(!keyring_store.has_secret(&key_id));

        // 5. Deleting nonexistent key returns error
        assert!(keyring_store.delete_keyring(&key_id).is_err());
    }

    #[test]
    fn test_corrupt_secret_handling() {
        let store = PlatformKeyring::in_memory();
        store.set_secret("corrupt_key", &[1, 2, 3, 4]).unwrap(); // not 32 bytes
        let err = store.get_secret("corrupt_key").unwrap_err();
        match err {
            KryptotomeError::Detailed { code, .. } => {
                assert_eq!(code, KryptotomeErrorCode::Kryp604KeyCustodyError);
            }
            _ => panic!("Expected Kryp604KeyCustodyError"),
        }
    }
}
