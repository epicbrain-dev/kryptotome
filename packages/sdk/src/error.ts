/**
 * Standardized Kryptotome Error Codes Taxonomy (KRYP-100 through KRYP-900)
 */
export type KryptotomeErrorCode =
  // 100 Series: Schema & W3C Standards Compliance
  | 'KRYP-101' // InvalidContext
  | 'KRYP-102' // MissingCredentialType
  | 'KRYP-103' // InvalidUriIdentifier
  | 'KRYP-104' // InvalidTemporalBounds
  | 'KRYP-105' // MalformedProofStructure
  | 'KRYP-106' // InvalidManifestSchema

  // 200 Series: Cryptographic Signatures
  | 'KRYP-201' // SignatureVerificationFailed
  | 'KRYP-202' // InvalidPublicKeyFormat
  | 'KRYP-203' // CorruptedSignature
  | 'KRYP-204' // UntrustedPublisherKey

  // 300 Series: Zero-Knowledge Proofs & Circuits
  | 'KRYP-301' // ZkProofVerificationFailed
  | 'KRYP-302' // PublicInputMismatch
  | 'KRYP-303' // MalformedProofEncoding
  | 'KRYP-304' // ProverSetupFailed
  | 'KRYP-305' // ConstraintUnsatisfied

  // 400 Series: Challenge Nonce & Replay Defense
  | 'KRYP-401' // ChallengeExpired
  | 'KRYP-402' // NonceReplayDetected
  | 'KRYP-403' // ChallengePackageMismatch

  // 500 Series: Content Integrity & Digests
  | 'KRYP-501' // DigestMismatch
  | 'KRYP-502' // MissingOrCorruptAsset
  | 'KRYP-503' // UnsupportedDigestAlgorithm

  // 600 Series: Local Keychain & Vault Custody
  | 'KRYP-601' // KeyringAccessFailed
  | 'KRYP-602' // VaultDecryptionFailed
  | 'KRYP-603' // EntitlementNotFound
  | 'KRYP-604' // KeyCustodyError

  // 700 Series: Table-Sharing Ephemeral Sessions
  | 'KRYP-701' // SessionTokenExpired
  | 'KRYP-702' // InvalidSessionSignature
  | 'KRYP-703' // PeerUnauthorized
  | 'KRYP-704' // SessionIdMismatch

  // 800 Series: Merchant Bridge Integrations
  | 'KRYP-801' // MerchantAuthFailed
  | 'KRYP-802' // MerchantPurchaseNotFound
  | 'KRYP-803' // MerchantRateLimitExceeded
  | 'KRYP-804' // MerchantNetworkError

  // 900 Series: System, IO & Runtime
  | 'KRYP-901' // SerializationError
  | 'KRYP-902' // IoError
  | 'KRYP-903'; // WasmRuntimeError

export interface ErrorDefinition {
  code: KryptotomeErrorCode;
  category: string;
  description: string;
}

export const KRYPTOTOME_ERROR_METADATA: Record<KryptotomeErrorCode, Omit<ErrorDefinition, 'code'>> = {
  'KRYP-101': {
    category: 'Schema & Standards Compliance',
    description: "@context must be an ordered array beginning with 'https://www.w3.org/ns/credentials/v2'",
  },
  'KRYP-102': {
    category: 'Schema & Standards Compliance',
    description: "Credential type must include 'VerifiableCredential' and 'KryptotomeEntitlementCredential'",
  },
  'KRYP-103': {
    category: 'Schema & Standards Compliance',
    description: 'Identifier must be a valid URI (urn:, did:, http:, https:)',
  },
  'KRYP-104': {
    category: 'Schema & Standards Compliance',
    description: 'Temporal bounds invalid (validUntil must be strictly after validFrom)',
  },
  'KRYP-105': {
    category: 'Schema & Standards Compliance',
    description: "Proof structure is malformed or purpose is not 'assertionMethod'",
  },
  'KRYP-106': {
    category: 'Schema & Standards Compliance',
    description: 'Package manifest schema is invalid or malformed',
  },

  'KRYP-201': {
    category: 'Cryptographic Signatures',
    description: 'Asymmetric digital signature verification failed',
  },
  'KRYP-202': {
    category: 'Cryptographic Signatures',
    description: 'Public key format is invalid or key length mismatch',
  },
  'KRYP-203': {
    category: 'Cryptographic Signatures',
    description: 'Signature bytes are corrupted or length is not 64 bytes',
  },
  'KRYP-204': {
    category: 'Cryptographic Signatures',
    description: 'Publisher public key is not trusted or recognized',
  },

  'KRYP-301': {
    category: 'Zero-Knowledge Proofs & Circuits',
    description: 'Zero-knowledge proof verification failed',
  },
  'KRYP-302': {
    category: 'Zero-Knowledge Proofs & Circuits',
    description: 'Public inputs do not match challenge nonce or target package',
  },
  'KRYP-303': {
    category: 'Zero-Knowledge Proofs & Circuits',
    description: 'ZK proof bytes are malformed or cannot be deserialized',
  },
  'KRYP-304': {
    category: 'Zero-Knowledge Proofs & Circuits',
    description: 'Failed to initialize prover circuit setup or CRS',
  },
  'KRYP-305': {
    category: 'Zero-Knowledge Proofs & Circuits',
    description: 'Prover witness failed to satisfy circuit constraints',
  },

  'KRYP-401': {
    category: 'Challenge Nonce & Replay Defense',
    description: 'Challenge nonce has expired',
  },
  'KRYP-402': {
    category: 'Challenge Nonce & Replay Defense',
    description: 'Challenge nonce was already used in a prior session',
  },
  'KRYP-403': {
    category: 'Challenge Nonce & Replay Defense',
    description: 'Challenge package ID does not match target package',
  },

  'KRYP-501': {
    category: 'Content Integrity & Digests',
    description: 'Calculated content digest does not match manifest root digest',
  },
  'KRYP-502': {
    category: 'Content Integrity & Digests',
    description: 'Required package file is missing or corrupted on disk',
  },
  'KRYP-503': {
    category: 'Content Integrity & Digests',
    description: 'Unsupported digest algorithm (only SHA-256 and BLAKE3 are supported)',
  },

  'KRYP-601': {
    category: 'Local Keychain & Vault Custody',
    description: 'Failed to access local operating system keychain or keyring',
  },
  'KRYP-602': {
    category: 'Local Keychain & Vault Custody',
    description: 'Vault decryption failed (incorrect passphrase or corrupted data)',
  },
  'KRYP-603': {
    category: 'Local Keychain & Vault Custody',
    description: 'No valid entitlement found in local vault for the requested package',
  },
  'KRYP-604': {
    category: 'Local Keychain & Vault Custody',
    description: 'Secret key custody error or zeroization failure',
  },

  'KRYP-701': {
    category: 'Table-Sharing Ephemeral Sessions',
    description: 'Ephemeral table-sharing session token has expired',
  },
  'KRYP-702': {
    category: 'Table-Sharing Ephemeral Sessions',
    description: 'Session token signature could not be verified by host public key',
  },
  'KRYP-703': {
    category: 'Table-Sharing Ephemeral Sessions',
    description: 'Connected peer is not authorized for the requested scope',
  },
  'KRYP-704': {
    category: 'Table-Sharing Ephemeral Sessions',
    description: 'Session ID does not match active game table session',
  },

  'KRYP-801': {
    category: 'Merchant Bridge Integrations',
    description: 'Failed to authenticate with merchant platform API',
  },
  'KRYP-802': {
    category: 'Merchant Bridge Integrations',
    description: 'No valid purchase record found on merchant platform for package',
  },
  'KRYP-803': {
    category: 'Merchant Bridge Integrations',
    description: 'Merchant API rate limit exceeded',
  },
  'KRYP-804': {
    category: 'Merchant Bridge Integrations',
    description: 'Network error occurred while communicating with merchant API',
  },

  'KRYP-901': {
    category: 'System, IO & Runtime',
    description: 'JSON serialization or deserialization failed',
  },
  'KRYP-902': {
    category: 'System, IO & Runtime',
    description: 'Filesystem input/output error',
  },
  'KRYP-903': {
    category: 'System, IO & Runtime',
    description: 'WebAssembly runtime exception or memory boundary error',
  },
};

export class KryptotomeError extends Error {
  public readonly code: KryptotomeErrorCode;
  public readonly category: string;
  public readonly details?: unknown;

  constructor(code: KryptotomeErrorCode, customMessage?: string, details?: unknown) {
    const meta = KRYPTOTOME_ERROR_METADATA[code];
    const message = customMessage || meta?.description || 'Unknown Kryptotome error';
    super(`[${code}] ${message}`);

    this.name = 'KryptotomeError';
    this.code = code;
    this.category = meta?.category || 'General';
    this.details = details;

    Object.setPrototypeOf(this, new.target.prototype);
  }
}
