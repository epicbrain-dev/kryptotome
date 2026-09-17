export type DigestAlgorithm = 'SHA-256' | 'BLAKE3';

export interface Entitlement {
  packageId: string;
  contentDigest: string;
  scope: string[];
}

export interface CredentialSubject {
  id: string;
  holderCommitment: string;
  entitlements: Entitlement[];
}

export interface KryptotomeCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: {
    id: string;
    name: string;
    publicKey: string;
  };
  validFrom: string;
  validUntil?: string;
  credentialSubject: CredentialSubject;
  proof: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
  };
}

export interface ChallengeNonce {
  nonce: string;
  packageId: string;
  timestamp: string;
  expiresAt: string;
}

export interface ZkProof {
  proofBytes: string;
  publicInputs: {
    challengeNonce: string;
    packageId: string;
    contentDigest: string;
    publisherPubkeyHash: string;
  };
}

export interface SessionAttestation {
  sessionId: string;
  hostPeerId: string;
  recipientPeerId: string;
  packageId: string;
  contentDigest: string;
  permittedScopes: string[];
  issuedAt: string;
  expiresAt: string;
  signatureHex: string;
}

export interface EntitlementProofBundle {
  version: number;
  curve: string;
  proofSystem: string;
  proofBase64: string;
  publicInputsBase64: string;
  packageId: string;
  contentDigest: string;
  challengeNonce: string;
  holderCommitmentUrn: string;
}

export interface PeerAccessRequest {
  recipientPeerId: string;
  packageId: string;
  nonce: string;
  timestamp: string;
}

export interface PeerAccessResponse {
  attestation: SessionAttestation;
  hostPublicKeyHex: string;
  nonce: string;
}

export interface MountedCompendiumSession {
  packageId: string;
  contentDigest: string;
  hostPeerId: string;
  recipientPeerId: string;
  sessionId: string;
  permittedScopes: string[];
  issuedAt: string;
  expiresAt: string;
  mountedAt: string;
}

export interface PeerSessionRenewalRequest {
  sessionId: string;
  recipientPeerId: string;
  packageId: string;
  renewalNonce: string;
  currentSignatureHex: string;
  timestamp: string;
}

export interface SessionRevocationNotice {
  sessionId: string;
  hostPeerId: string;
  recipientPeerId: string;
  packageId?: string;
  revokedAt: string;
  reason: string;
  signatureHex: string;
}

export interface ScopePolicyConfig {
  allowedScopes: string[];
  restrictedScopes: string[];
  peerOverrides?: Record<string, string[]>;
}

export type JsonPatchOpType = 'add' | 'remove' | 'replace' | 'move' | 'copy' | 'test';

export interface JsonPatchOperation {
  op: JsonPatchOpType;
  path: string;
  value?: unknown;
  from?: string;
}

export interface ErrataPatchBundle {
  packageId: string;
  fromDigest: string;
  toDigest: string;
  patchVersion: string;
  publishedAt: string;
  publisherId: string;
  publisherSignatureHex: string;
  operations: JsonPatchOperation[];
  targetFiles?: Record<string, JsonPatchOperation[]>;
}

export interface CompendiumPackageData {
  packageId: string;
  version: string;
  contentDigest: string;
  items: Array<Record<string, unknown>>;
  schemas?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface ErrataApplyResult {
  packageId: string;
  previousDigest: string;
  newDigest: string;
  appliedPatchVersion: string;
  appliedAt: string;
  appliedOperationsCount: number;
  preservedHomebrewCount: number;
  compendium: CompendiumPackageData;
}

// ============================================================================
// Section 13.2: Advanced Cryptography & Table Privacy
// ============================================================================

export interface CompendiumItem {
  id: string;
  itemType: string;
  digest: string;
}

export interface MerklePathNode {
  hashHex: string;
  isLeft: boolean;
}

export interface MerkleInclusionProof {
  itemId: string;
  itemType: string;
  itemDigest: string;
  leafHashHex: string;
  path: MerklePathNode[];
  rootHex: string;
}

export interface SelectiveDisclosureProofBundle {
  version: number;
  curve: string;
  proofSystem: string;
  proofBase64: string;
  publicInputsBase64: string;
  challengeNonce: string;
  itemDigest: string;
  publisherPubkey: string;
  holderCommitmentUrn: string;
  compendiumRoot?: string;
}

export interface PartyMemberContribution {
  peerId: string;
  packageId: string;
  contentDigest: string;
  holderCommitment: string;
  proof: string;
  permittedScopes: string[];
  signature: string;
}

export interface AggregatedPartySessionProof {
  sessionId: string;
  tableNonce: string;
  hostPeerId: string;
  pooledPackages: string[];
  participantPeerIds: string[];
  poolDigest: string;
  hostPublicKeyHex: string;
  hostSignatureHex: string;
  issuedAt: string;
  validUntil: string;
}

export interface PasskeyBinding {
  credentialId: string;
  holderCommitmentUrn: string;
  publicKeyHex: string;
  rpId: string;
  algorithm: string;
  createdAt: string;
}

export interface PasskeyAssertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJson: string;
  signatureHex: string;
  userHandle?: string;
}

export interface PasskeyVerificationResult {
  verified: boolean;
  userPresent: boolean;
  userVerified: boolean;
  holderCommitmentUrn: string;
  verifiedAt: string;
}

// ============================================================================
// Section 13.3: Indie Publisher & Creator Tooling
// ============================================================================

export type CrowdfundingPlatform = 'kickstarter' | 'backerkit' | 'custom';

export interface BackerRecord {
  backerId: string;
  email: string;
  name: string;
  rewardTier: string;
  pledgeAmount?: number;
  rewardPackageIds: string[];
}

export interface FulfillmentTierConfig {
  tierName: string;
  packageIds: string[];
  contentDigests?: Record<string, string>;
}

export interface ClaimVoucher {
  voucherId: string;
  backerId: string;
  packageId: string;
  contentDigest: string;
  activationToken: string;
  claimUrl: string;
  publisherPubkeyHex: string;
  signatureHex: string;
  issuedAt: string;
  expiresAt?: string;
}

export interface BatchFulfillmentReport {
  platform: CrowdfundingPlatform;
  publisherId: string;
  totalBackers: number;
  fulfilledCredentialsCount: number;
  vouchers: ClaimVoucher[];
  credentials: KryptotomeCredential[];
}

export type PhysicalVoucherFormat = 'scratch-off-code' | 'nfc-tag' | 'hybrid';

export interface PhysicalVoucherBatchSpec {
  publisherId: string;
  packageId: string;
  contentDigest: string;
  quantity: number;
  format: PhysicalVoucherFormat;
  codePrefix?: string;
  validDurationDays?: number;
}

export interface PhysicalVoucherRecord {
  voucherId: string;
  code: string;
  packageId: string;
  contentDigest: string;
  format: PhysicalVoucherFormat;
  saltHex: string;
  publisherPubkeyHex: string;
  signatureHex: string;
  nfcNdefUri?: string;
  createdAt: string;
  expiresAt?: string;
}

export interface NfcTagPayload {
  ndefUri: string;
  ndefRecordBytes: Uint8Array;
  chipType: string;
  lockable: boolean;
}

export interface VoucherRedemptionResult {
  valid: boolean;
  code: string;
  packageId: string;
  contentDigest: string;
  publisherPubkeyHex: string;
  redeemedAt: string;
}


