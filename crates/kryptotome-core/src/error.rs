use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standardized Kryptotome error code taxonomy (KRYP-100 through KRYP-900)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KryptotomeErrorCode {
    // 100 Series: Schema & W3C Standards Compliance
    #[serde(rename = "KRYP-101")]
    Kryp101InvalidContext,
    #[serde(rename = "KRYP-102")]
    Kryp102MissingCredentialType,
    #[serde(rename = "KRYP-103")]
    Kryp103InvalidUriIdentifier,
    #[serde(rename = "KRYP-104")]
    Kryp104InvalidTemporalBounds,
    #[serde(rename = "KRYP-105")]
    Kryp105MalformedProofStructure,
    #[serde(rename = "KRYP-106")]
    Kryp106InvalidManifestSchema,
    #[serde(rename = "KRYP-107")]
    Kryp107CredentialRevoked,

    // 200 Series: Cryptographic Signatures
    #[serde(rename = "KRYP-201")]
    Kryp201SignatureVerificationFailed,
    #[serde(rename = "KRYP-202")]
    Kryp202InvalidPublicKeyFormat,
    #[serde(rename = "KRYP-203")]
    Kryp203CorruptedSignature,
    #[serde(rename = "KRYP-204")]
    Kryp204UntrustedPublisherKey,

    // 300 Series: Zero-Knowledge Proofs & Circuits
    #[serde(rename = "KRYP-301")]
    Kryp301ZkProofVerificationFailed,
    #[serde(rename = "KRYP-302")]
    Kryp302PublicInputMismatch,
    #[serde(rename = "KRYP-303")]
    Kryp303MalformedProofEncoding,
    #[serde(rename = "KRYP-304")]
    Kryp304ProverSetupFailed,
    #[serde(rename = "KRYP-305")]
    Kryp305ConstraintUnsatisfied,

    // 400 Series: Challenge Nonce & Replay Defense
    #[serde(rename = "KRYP-401")]
    Kryp401ChallengeExpired,
    #[serde(rename = "KRYP-402")]
    Kryp402NonceReplayDetected,
    #[serde(rename = "KRYP-403")]
    Kryp403ChallengePackageMismatch,

    // 500 Series: Content Integrity & Digests
    #[serde(rename = "KRYP-501")]
    Kryp501DigestMismatch,
    #[serde(rename = "KRYP-502")]
    Kryp502MissingOrCorruptAsset,
    #[serde(rename = "KRYP-503")]
    Kryp503UnsupportedDigestAlgorithm,

    // 600 Series: Local Keychain & Vault Custody
    #[serde(rename = "KRYP-601")]
    Kryp601KeyringAccessFailed,
    #[serde(rename = "KRYP-602")]
    Kryp602VaultDecryptionFailed,
    #[serde(rename = "KRYP-603")]
    Kryp603EntitlementNotFound,
    #[serde(rename = "KRYP-604")]
    Kryp604KeyCustodyError,

    // 700 Series: Table-Sharing Ephemeral Sessions
    #[serde(rename = "KRYP-701")]
    Kryp701SessionTokenExpired,
    #[serde(rename = "KRYP-702")]
    Kryp702InvalidSessionSignature,
    #[serde(rename = "KRYP-703")]
    Kryp703PeerUnauthorized,
    #[serde(rename = "KRYP-704")]
    Kryp704SessionIdMismatch,

    // 800 Series: Merchant Bridge Integrations
    #[serde(rename = "KRYP-801")]
    Kryp801MerchantAuthFailed,
    #[serde(rename = "KRYP-802")]
    Kryp802MerchantPurchaseNotFound,
    #[serde(rename = "KRYP-803")]
    Kryp803MerchantRateLimitExceeded,
    #[serde(rename = "KRYP-804")]
    Kryp804MerchantNetworkError,

    // 900 Series: System, IO & Runtime
    #[serde(rename = "KRYP-901")]
    Kryp901SerializationError,
    #[serde(rename = "KRYP-902")]
    Kryp902IoError,
    #[serde(rename = "KRYP-903")]
    Kryp903WasmRuntimeError,
}

impl KryptotomeErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Kryp101InvalidContext => "KRYP-101",
            Self::Kryp102MissingCredentialType => "KRYP-102",
            Self::Kryp103InvalidUriIdentifier => "KRYP-103",
            Self::Kryp104InvalidTemporalBounds => "KRYP-104",
            Self::Kryp105MalformedProofStructure => "KRYP-105",
            Self::Kryp106InvalidManifestSchema => "KRYP-106",
            Self::Kryp107CredentialRevoked => "KRYP-107",

            Self::Kryp201SignatureVerificationFailed => "KRYP-201",
            Self::Kryp202InvalidPublicKeyFormat => "KRYP-202",
            Self::Kryp203CorruptedSignature => "KRYP-203",
            Self::Kryp204UntrustedPublisherKey => "KRYP-204",

            Self::Kryp301ZkProofVerificationFailed => "KRYP-301",
            Self::Kryp302PublicInputMismatch => "KRYP-302",
            Self::Kryp303MalformedProofEncoding => "KRYP-303",
            Self::Kryp304ProverSetupFailed => "KRYP-304",
            Self::Kryp305ConstraintUnsatisfied => "KRYP-305",

            Self::Kryp401ChallengeExpired => "KRYP-401",
            Self::Kryp402NonceReplayDetected => "KRYP-402",
            Self::Kryp403ChallengePackageMismatch => "KRYP-403",

            Self::Kryp501DigestMismatch => "KRYP-501",
            Self::Kryp502MissingOrCorruptAsset => "KRYP-502",
            Self::Kryp503UnsupportedDigestAlgorithm => "KRYP-503",

            Self::Kryp601KeyringAccessFailed => "KRYP-601",
            Self::Kryp602VaultDecryptionFailed => "KRYP-602",
            Self::Kryp603EntitlementNotFound => "KRYP-603",
            Self::Kryp604KeyCustodyError => "KRYP-604",

            Self::Kryp701SessionTokenExpired => "KRYP-701",
            Self::Kryp702InvalidSessionSignature => "KRYP-702",
            Self::Kryp703PeerUnauthorized => "KRYP-703",
            Self::Kryp704SessionIdMismatch => "KRYP-704",

            Self::Kryp801MerchantAuthFailed => "KRYP-801",
            Self::Kryp802MerchantPurchaseNotFound => "KRYP-802",
            Self::Kryp803MerchantRateLimitExceeded => "KRYP-803",
            Self::Kryp804MerchantNetworkError => "KRYP-804",

            Self::Kryp901SerializationError => "KRYP-901",
            Self::Kryp902IoError => "KRYP-902",
            Self::Kryp903WasmRuntimeError => "KRYP-903",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::Kryp101InvalidContext
            | Self::Kryp102MissingCredentialType
            | Self::Kryp103InvalidUriIdentifier
            | Self::Kryp104InvalidTemporalBounds
            | Self::Kryp105MalformedProofStructure
            | Self::Kryp106InvalidManifestSchema
            | Self::Kryp107CredentialRevoked => "Schema & Standards Compliance",

            Self::Kryp201SignatureVerificationFailed
            | Self::Kryp202InvalidPublicKeyFormat
            | Self::Kryp203CorruptedSignature
            | Self::Kryp204UntrustedPublisherKey => "Cryptographic Signatures",

            Self::Kryp301ZkProofVerificationFailed
            | Self::Kryp302PublicInputMismatch
            | Self::Kryp303MalformedProofEncoding
            | Self::Kryp304ProverSetupFailed
            | Self::Kryp305ConstraintUnsatisfied => "Zero-Knowledge Proofs & Circuits",

            Self::Kryp401ChallengeExpired
            | Self::Kryp402NonceReplayDetected
            | Self::Kryp403ChallengePackageMismatch => "Challenge Nonce & Replay Defense",

            Self::Kryp501DigestMismatch
            | Self::Kryp502MissingOrCorruptAsset
            | Self::Kryp503UnsupportedDigestAlgorithm => "Content Integrity & Digests",

            Self::Kryp601KeyringAccessFailed
            | Self::Kryp602VaultDecryptionFailed
            | Self::Kryp603EntitlementNotFound
            | Self::Kryp604KeyCustodyError => "Local Keychain & Vault Custody",

            Self::Kryp701SessionTokenExpired
            | Self::Kryp702InvalidSessionSignature
            | Self::Kryp703PeerUnauthorized
            | Self::Kryp704SessionIdMismatch => "Table-Sharing Ephemeral Sessions",

            Self::Kryp801MerchantAuthFailed
            | Self::Kryp802MerchantPurchaseNotFound
            | Self::Kryp803MerchantRateLimitExceeded
            | Self::Kryp804MerchantNetworkError => "Merchant Bridge Integrations",

            Self::Kryp901SerializationError
            | Self::Kryp902IoError
            | Self::Kryp903WasmRuntimeError => "System, IO & Runtime",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Kryp101InvalidContext => "@context must be an ordered array beginning with 'https://www.w3.org/ns/credentials/v2'",
            Self::Kryp102MissingCredentialType => "Credential type must include 'VerifiableCredential' and 'KryptotomeEntitlementCredential'",
            Self::Kryp103InvalidUriIdentifier => "Identifier must be a valid URI (urn:, did:, http:, https:)",
            Self::Kryp104InvalidTemporalBounds => "Temporal bounds invalid (validUntil must be strictly after validFrom)",
            Self::Kryp105MalformedProofStructure => "Proof structure is malformed or purpose is not 'assertionMethod'",
            Self::Kryp106InvalidManifestSchema => "Package manifest schema is invalid or malformed",
            Self::Kryp107CredentialRevoked => "Credential has been revoked by publisher revocation list or Merkle tree",

            Self::Kryp201SignatureVerificationFailed => "Asymmetric digital signature verification failed",
            Self::Kryp202InvalidPublicKeyFormat => "Public key format is invalid or key length mismatch",
            Self::Kryp203CorruptedSignature => "Signature bytes are corrupted or length is not 64 bytes",
            Self::Kryp204UntrustedPublisherKey => "Publisher public key is not trusted or recognized",

            Self::Kryp301ZkProofVerificationFailed => "Zero-knowledge proof verification failed",
            Self::Kryp302PublicInputMismatch => "Public inputs do not match challenge nonce or target package",
            Self::Kryp303MalformedProofEncoding => "ZK proof bytes are malformed or cannot be deserialized",
            Self::Kryp304ProverSetupFailed => "Failed to initialize prover circuit setup or CRS",
            Self::Kryp305ConstraintUnsatisfied => "Prover witness failed to satisfy circuit constraints",

            Self::Kryp401ChallengeExpired => "Challenge nonce has expired",
            Self::Kryp402NonceReplayDetected => "Challenge nonce was already used in a prior session",
            Self::Kryp403ChallengePackageMismatch => "Challenge package ID does not match target package",

            Self::Kryp501DigestMismatch => "Calculated content digest does not match manifest root digest",
            Self::Kryp502MissingOrCorruptAsset => "Required package file is missing or corrupted on disk",
            Self::Kryp503UnsupportedDigestAlgorithm => "Unsupported digest algorithm (only SHA-256 and BLAKE3 are supported)",

            Self::Kryp601KeyringAccessFailed => "Failed to access local operating system keychain or keyring",
            Self::Kryp602VaultDecryptionFailed => "Vault decryption failed (incorrect passphrase or corrupted data)",
            Self::Kryp603EntitlementNotFound => "No valid entitlement found in local vault for the requested package",
            Self::Kryp604KeyCustodyError => "Secret key custody error or zeroization failure",

            Self::Kryp701SessionTokenExpired => "Ephemeral table-sharing session token has expired",
            Self::Kryp702InvalidSessionSignature => "Session token signature could not be verified by host public key",
            Self::Kryp703PeerUnauthorized => "Connected peer is not authorized for the requested scope",
            Self::Kryp704SessionIdMismatch => "Session ID does not match active game table session",

            Self::Kryp801MerchantAuthFailed => "Failed to authenticate with merchant platform API",
            Self::Kryp802MerchantPurchaseNotFound => "No valid purchase record found on merchant platform for package",
            Self::Kryp803MerchantRateLimitExceeded => "Merchant API rate limit exceeded",
            Self::Kryp804MerchantNetworkError => "Network error occurred while communicating with merchant API",

            Self::Kryp901SerializationError => "JSON serialization or deserialization failed",
            Self::Kryp902IoError => "Filesystem input/output error",
            Self::Kryp903WasmRuntimeError => "WebAssembly runtime exception or memory boundary error",
        }
    }
}

impl std::fmt::Display for KryptotomeErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Error, Debug)]
pub enum KryptotomeError {
    #[error("[{code}] {message}")]
    Detailed {
        code: KryptotomeErrorCode,
        message: String,
    },

    #[error("[KRYP-101] W3C VC v2.0 compliance error: {0}")]
    W3cComplianceError(String),

    #[error("[KRYP-107] Credential has been revoked: {0}")]
    CredentialRevoked(String),

    #[error("[KRYP-201] Cryptographic signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("[KRYP-301] Zero-knowledge proof verification failed: {0}")]
    ZkProofVerificationFailed(String),

    #[error("[KRYP-401] Challenge nonce mismatch or expired: {0}")]
    InvalidChallenge(String),

    #[error("[KRYP-104] Credential expired or invalid time bounds: {0}")]
    InvalidTimeBounds(String),

    #[error("[KRYP-501] Content digest mismatch: expected {expected}, actual {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("[KRYP-603] Package entitlement not granted for package {0}")]
    EntitlementNotFound(String),

    #[error("[KRYP-901] Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("[KRYP-902] IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("[KRYP-601] Vault error: {0}")]
    VaultError(String),

    #[error("[KRYP-801] Merchant bridge error: {0}")]
    BridgeError(String),
}

impl KryptotomeError {
    pub fn code(&self) -> KryptotomeErrorCode {
        match self {
            Self::Detailed { code, .. } => *code,
            Self::W3cComplianceError(_) => KryptotomeErrorCode::Kryp101InvalidContext,
            Self::CredentialRevoked(_) => KryptotomeErrorCode::Kryp107CredentialRevoked,
            Self::SignatureVerificationFailed(_) => KryptotomeErrorCode::Kryp201SignatureVerificationFailed,
            Self::ZkProofVerificationFailed(_) => KryptotomeErrorCode::Kryp301ZkProofVerificationFailed,
            Self::InvalidChallenge(_) => KryptotomeErrorCode::Kryp401ChallengeExpired,
            Self::InvalidTimeBounds(_) => KryptotomeErrorCode::Kryp104InvalidTemporalBounds,
            Self::DigestMismatch { .. } => KryptotomeErrorCode::Kryp501DigestMismatch,
            Self::EntitlementNotFound(_) => KryptotomeErrorCode::Kryp603EntitlementNotFound,
            Self::SerializationError(_) => KryptotomeErrorCode::Kryp901SerializationError,
            Self::IoError(_) => KryptotomeErrorCode::Kryp902IoError,
            Self::VaultError(_) => KryptotomeErrorCode::Kryp601KeyringAccessFailed,
            Self::BridgeError(_) => KryptotomeErrorCode::Kryp801MerchantAuthFailed,
        }
    }
}


pub type Result<T> = std::result::Result<T, KryptotomeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_taxonomy() {
        let code = KryptotomeErrorCode::Kryp101InvalidContext;
        assert_eq!(code.as_str(), "KRYP-101");
        assert_eq!(code.category(), "Schema & Standards Compliance");

        let err = KryptotomeError::Detailed {
            code: KryptotomeErrorCode::Kryp301ZkProofVerificationFailed,
            message: "Pairing check returned false".to_string(),
        };
        assert_eq!(err.code(), KryptotomeErrorCode::Kryp301ZkProofVerificationFailed);
        assert_eq!(format!("{}", err), "[KRYP-301] Pairing check returned false");
    }
}
