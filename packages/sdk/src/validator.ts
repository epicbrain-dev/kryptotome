import type { KryptotomeCredential } from './types.js';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

function isValidUri(s: string): boolean {
  return (
    s.startsWith('urn:') ||
    s.startsWith('did:') ||
    s.startsWith('http://') ||
    s.startsWith('https://')
  );
}

/**
 * Validates strict compliance with W3C Verifiable Credentials Data Model v2.0
 */
export function validateW3cCompliance(credential: KryptotomeCredential): ValidationResult {
  const errors: string[] = [];

  // 1. @context: must be an ordered array where first item is https://www.w3.org/ns/credentials/v2
  if (!credential['@context'] || !Array.isArray(credential['@context']) || credential['@context'].length < 2) {
    errors.push('@context must be an array with at least 2 context URIs');
  } else {
    if (credential['@context'][0] !== 'https://www.w3.org/ns/credentials/v2') {
      errors.push(
        `First element in @context must be 'https://www.w3.org/ns/credentials/v2', found '${credential['@context'][0]}'`
      );
    }
    if (!credential['@context'].includes('https://kryptotome.org/schemas/v1/context.jsonld')) {
      errors.push("@context must include 'https://kryptotome.org/schemas/v1/context.jsonld'");
    }
  }

  // 2. id: must be a valid URI
  if (!credential.id || !isValidUri(credential.id)) {
    errors.push(`Credential id must be a valid URI, found '${credential.id}'`);
  }

  // 3. type: must include 'VerifiableCredential' and 'KryptotomeEntitlementCredential'
  if (!credential.type || !Array.isArray(credential.type)) {
    errors.push('type must be an array of strings');
  } else {
    if (!credential.type.includes('VerifiableCredential')) {
      errors.push("Credential type must include 'VerifiableCredential'");
    }
    if (!credential.type.includes('KryptotomeEntitlementCredential')) {
      errors.push("Credential type must include 'KryptotomeEntitlementCredential'");
    }
  }

  // 4. issuer: id must be a URI
  if (!credential.issuer || !credential.issuer.id || !isValidUri(credential.issuer.id)) {
    errors.push(`Issuer id must be a valid URI, found '${credential.issuer?.id}'`);
  }

  // 5. validFrom: date-time check
  if (!credential.validFrom || isNaN(Date.parse(credential.validFrom))) {
    errors.push(`validFrom must be a valid RFC 3339 date-time string, found '${credential.validFrom}'`);
  }

  // 6. validUntil: if present, must be after validFrom
  if (credential.validUntil) {
    if (isNaN(Date.parse(credential.validUntil))) {
      errors.push(`validUntil must be a valid RFC 3339 date-time string, found '${credential.validUntil}'`);
    } else if (new Date(credential.validUntil) <= new Date(credential.validFrom)) {
      errors.push('validUntil must be strictly after validFrom');
    }
  }

  // 7. credentialSubject: id (URI), holderCommitment, entitlements
  if (!credential.credentialSubject) {
    errors.push('credentialSubject is required');
  } else {
    const subj = credential.credentialSubject;
    if (!subj.id || !isValidUri(subj.id)) {
      errors.push(`credentialSubject id must be a valid URI, found '${subj.id}'`);
    }
    if (!subj.holderCommitment || subj.holderCommitment.trim().length === 0) {
      errors.push('holderCommitment cannot be empty');
    }
    if (!subj.entitlements || !Array.isArray(subj.entitlements) || subj.entitlements.length === 0) {
      errors.push('credentialSubject must contain at least one entitlement');
    } else {
      for (let i = 0; i < subj.entitlements.length; i++) {
        const e = subj.entitlements[i];
        if (!e.packageId || e.packageId.trim().length === 0) {
          errors.push(`Entitlement at index ${i} packageId cannot be empty`);
        }
        if (!e.contentDigest || e.contentDigest.trim().length === 0) {
          errors.push(`Entitlement at index ${i} contentDigest cannot be empty`);
        }
        if (!e.scope || !Array.isArray(e.scope) || e.scope.length === 0) {
          errors.push(`Entitlement at index ${i} scope cannot be empty`);
        }
      }
    }
  }

  // 8. proof: verificationMethod (URI), proofPurpose === 'assertionMethod'
  if (!credential.proof) {
    errors.push('proof is required');
  } else {
    if (credential.proof.proofPurpose !== 'assertionMethod') {
      errors.push(`proofPurpose must be 'assertionMethod', found '${credential.proof.proofPurpose}'`);
    }
    if (!credential.proof.verificationMethod || !isValidUri(credential.proof.verificationMethod)) {
      errors.push(`proof verificationMethod must be a valid URI, found '${credential.proof.verificationMethod}'`);
    }
    if (!credential.proof.proofValue || credential.proof.proofValue.trim().length === 0) {
      errors.push('proofValue cannot be empty');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
