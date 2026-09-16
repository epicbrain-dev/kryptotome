import { WasmSessionManager } from './kryptotome_wasm.js';
import type { SessionAttestation } from '../types.js';
import { KryptotomeError } from '../error.js';
import { getWasmModule } from './loader.js';

/**
 * High-level typed table-sharing session manager powered by WebAssembly.
 * Enables the game table host (GM) to issue ephemeral, cryptographically-signed session tokens
 * to connected player peers without exposing master vault credentials.
 */
export class WasmSessionEngine {
  private raw: WasmSessionManager;
  private isDisposed = false;

  constructor(public readonly sessionId: string) {
    // Ensure WebAssembly module is initialized
    getWasmModule();
    this.raw = new WasmSessionManager(sessionId);
  }

  /**
   * Returns the ephemeral Ed25519 host signing public key in hexadecimal format.
   */
  public hostPublicKeyHex(): string {
    this.assertNotDisposed();
    return this.raw.hostPublicKeyHex();
  }

  /**
   * Issues an ephemeral, time-bounded session attestation token for a connected table peer.
   *
   * @param recipientPeerId Target peer ID (e.g. player socket or local peer identifier)
   * @param packageId Entitled compendium or module ID
   * @param contentDigest Cryptographic digest of the shared package content
   * @param scopes Array of permitted permission scopes (e.g. ["read", "spells", "character-sheet"])
   * @param durationMinutes Token validity lifetime in minutes
   */
  public issuePeerAttestation(
    recipientPeerId: string,
    packageId: string,
    contentDigest: string,
    scopes: string[],
    durationMinutes: number
  ): SessionAttestation {
    this.assertNotDisposed();

    try {
      const scopesJson = JSON.stringify(scopes);
      const attestationJson = this.raw.issuePeerAttestation(
        recipientPeerId,
        packageId,
        contentDigest,
        scopesJson,
        durationMinutes
      );
      return JSON.parse(attestationJson) as SessionAttestation;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      throw new KryptotomeError(
        'KRYP-702',
        `Failed to issue peer session attestation: ${message}`,
        err
      );
    }
  }

  /**
   * Validates an ephemeral table session attestation received from a table host.
   *
   * @param attestation The attestation object or raw JSON string
   * @param hostPubkeyHex The host GM's advertised public key in hex
   */
  public static verifyPeerAttestation(
    attestation: SessionAttestation | string,
    hostPubkeyHex: string
  ): boolean {
    // Ensure WebAssembly module is initialized
    getWasmModule();

    try {
      const attestationJson =
        typeof attestation === 'string' ? attestation : JSON.stringify(attestation);
      return WasmSessionManager.verifyPeerAttestation(attestationJson, hostPubkeyHex);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('expired')) {
        throw new KryptotomeError('KRYP-701', 'Session token has expired', err);
      }
      throw new KryptotomeError('KRYP-702', `Invalid session token signature: ${message}`, err);
    }
  }

  /**
   * Frees WebAssembly heap allocations associated with this session manager instance.
   */
  public dispose(): void {
    if (!this.isDisposed) {
      this.raw.free();
      this.isDisposed = true;
    }
  }

  public [Symbol.dispose](): void {
    this.dispose();
  }

  private assertNotDisposed(): void {
    if (this.isDisposed) {
      throw new KryptotomeError(
        'KRYP-903',
        'WasmSessionEngine instance has been disposed and cannot be used.'
      );
    }
  }
}
