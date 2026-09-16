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



