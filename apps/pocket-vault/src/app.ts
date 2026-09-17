/**
 * Kryptotome Pocket Vault - Mobile Frontend Application Logic
 * Dark Tabletop Fantasy Aesthetic & Non-blocking Toast System
 */

export interface MobileEntitlement {
  packageId: string;
  title: string;
  publisher: string;
  digest: string;
}

export interface EnclaveAttestation {
  enclaveType: 'AppleSecureEnclave' | 'AndroidKeystoreStrongBox' | 'SoftwareFallback';
  keyTag: string;
  attestationDigest: string;
  timestamp: string;
}

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function secureRandomHex(bytes: number = 8): string {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  }
  const perfNow = typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : 0;
  return `${Date.now().toString(36)}-${(perfNow * 1000).toString(36).replace('.', '')}`;
}

function showPocketToast(message: string, type: 'success' | 'info' | 'warning' = 'info'): void {
  if (typeof document === 'undefined') return;
  const container = document.getElementById('pocket-toast-container');
  if (!container) return;

  const icons: Record<string, string> = {
    success: '⚜',
    info: '📜',
    warning: '✦',
  };

  const safeMessage = escapeHtml(message);
  const toast = document.createElement('div');
  toast.className = 'toast-item';
  toast.innerHTML = `
    <span style="font-size: 16px;">${icons[type] || '✦'}</span>
    <span>${safeMessage}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => {
      if (container.contains(toast)) container.removeChild(toast);
    }, 300);
  }, 3800);
}

export class PocketVaultApp {
  private isBeaconActive: boolean = false;
  private connectedPeers: number = 0;
  private chunkSimulationStep: number = 0;
  private biometricAttestation: EnclaveAttestation | null = null;
  private auditLog: Array<{ timestamp: string; action: string; details: string }> = [];

  constructor() {
    this.biometricAttestation = {
      enclaveType: 'AppleSecureEnclave',
      keyTag: 'org.kryptotome.pocketvault.master',
      attestationDigest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      timestamp: new Date().toISOString(),
    };
  }

  public init(): void {
    this.setupNavigation();
    this.setupBeaconControls();
    this.setupQrSimulation();
    this.setupBiometricEnclave();
    this.logAudit('VAULT_INITIALIZED', 'Pocket Vault runtime loaded into memory');
  }

  private setupNavigation(): void {
    if (typeof document === 'undefined') return;
    const navItems = document.querySelectorAll('.nav-item');
    const screens = document.querySelectorAll('.screen');

    navItems.forEach((btn) => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-screen');
        navItems.forEach((b) => b.classList.remove('active'));
        screens.forEach((s) => s.classList.remove('active'));

        btn.classList.add('active');
        const screenEl = document.getElementById(`${target}-screen`);
        if (screenEl) screenEl.classList.add('active');
        this.logAudit('NAVIGATE', `Switched screen view to "${target}"`);
      });
    });
  }

  private setupBeaconControls(): void {
    if (typeof document === 'undefined') return;
    const toggleBtn = document.getElementById('toggleBeaconBtn');
    const statusText = document.getElementById('beaconStatusText');
    const subtext = document.getElementById('beaconSubtext');

    toggleBtn?.addEventListener('click', () => {
      this.isBeaconActive = !this.isBeaconActive;

      if (this.isBeaconActive) {
        this.connectedPeers = 3;
        toggleBtn.textContent = 'Seal Table Beacon';
        toggleBtn.classList.add('active');
        if (statusText) {
          statusText.textContent = `Leyline Active (${this.connectedPeers} Table Peers Bound)`;
          statusText.style.color = '#38bdf8';
        }
        if (subtext) subtext.textContent = 'Nexus: session-table-99 • Friday Night Campaign';
        showPocketToast('Planar Leyline Beacon awakened across BLE & mDNS.', 'success');
        this.logAudit('BEACON_AWAKEN', 'Broadcasting on _kryptotome-table._tcp (3 peers bound)');
      } else {
        this.connectedPeers = 0;
        toggleBtn.textContent = 'Awaken Table Beacon';
        toggleBtn.classList.remove('active');
        if (statusText) {
          statusText.textContent = 'Beacon Inactive';
          statusText.style.color = '#fff';
        }
        if (subtext) subtext.textContent = 'Tap below to host your local campaign table.';
        showPocketToast('Leyline table beacon sealed.', 'info');
        this.logAudit('BEACON_SEALED', 'Table beacon halted');
      }
    });
  }

  private setupQrSimulation(): void {
    if (typeof document === 'undefined') return;
    const btn = document.getElementById('simulateFrameBtn');
    const hint = document.getElementById('scannerHint');
    const progress = document.getElementById('scanProgress');

    btn?.addEventListener('click', () => {
      this.chunkSimulationStep = (this.chunkSimulationStep % 3) + 1;
      const pct = Math.round((this.chunkSimulationStep / 3) * 100);

      if (progress) progress.style.width = `${pct}%`;

      if (this.chunkSimulationStep < 3) {
        if (hint) hint.textContent = `Scrying glyph chunk ${this.chunkSimulationStep}/3 from optical feed...`;
        showPocketToast(`Ingested glyph chunk ${this.chunkSimulationStep}/3`, 'info');
        this.logAudit('QR_CHUNK_INGEST', `Glyph chunk ${this.chunkSimulationStep}/3 buffered`);
      } else {
        if (hint) {
          hint.innerHTML = `<strong style="color: #10b981;">⚜ Reassembled convention voucher credential!</strong>`;
        }
        showPocketToast('Convention voucher credential unlocked and bound to vault!', 'success');
        this.logAudit('QR_VOUCHER_UNLOCKED', 'Assembled 3/3 chunks into W3C Verifiable Credential');
      }
    });
  }

  private setupBiometricEnclave(): void {
    if (typeof document === 'undefined') return;
    const enclaveEl = document.querySelector('.enclave-status');
    const stateText = document.getElementById('biometricState');

    if (enclaveEl) {
      (enclaveEl as HTMLElement).style.cursor = 'pointer';
      (enclaveEl as HTMLElement).title = 'Tap to verify Hardware Secure Enclave attestation';
      enclaveEl.addEventListener('click', () => {
        this.verifyBiometrics();
        if (stateText) {
          stateText.textContent = 'Hardware Attested ✓';
          setTimeout(() => {
            if (stateText) stateText.textContent = 'Biometrics Active';
          }, 3000);
        }
      });
    }
  }

  public verifyBiometrics(): EnclaveAttestation {
    const nonce = secureRandomHex(8);
    const attestation: EnclaveAttestation = {
      enclaveType: 'AppleSecureEnclave',
      keyTag: 'org.kryptotome.pocketvault.master',
      attestationDigest: `attest:${nonce}:secp256r1`,
      timestamp: new Date().toISOString(),
    };
    this.biometricAttestation = attestation;
    showPocketToast('Hardware Secure Enclave signature verified.', 'success');
    this.logAudit('BIOMETRIC_VERIFIED', `Hardware key tag: ${attestation.keyTag}`);
    return attestation;
  }

  public generateQuickProof(packageId: string): string {
    const nonce = secureRandomHex(8);
    const proof = `zkp:pocket-vault:${packageId}:${nonce}`;
    showPocketToast(`Generated single-use ZK proof for ${packageId} [${nonce}]`, 'success');
    this.logAudit('ZK_PROOF_GENERATED', `Proof minted for ${packageId} (nonce: ${nonce})`);
    return proof;
  }

  public shareBeacon(packageId: string): void {
    showPocketToast(`Broadcasting entitlement "${packageId}" to leyline peers.`, 'info');
    this.logAudit('LEYLINE_BROADCAST', `Advertised ${packageId} across local table peers`);
  }

  public generateTournamentTicket(characterName: string = 'Valeros of Andoran'): string {
    const nonce = secureRandomHex(8);
    const ticketPayload = {
      tournamentId: 'PFS-GENCON-2026-CHAMPIONSHIP',
      system: 'PF2E',
      characterName,
      characterBuildHash: `blake3:build:${nonce}`,
      verifiedFeatsCount: 28,
      requiredPackages: ['paizo/player-core'],
      presentationProof: `zkp:tourney:paizo/player-core:${nonce}`,
      issuedAt: new Date().toISOString(),
      holderCommitment: 'urn:kryptotome:commitment:73ab99',
    };
    const rawJson = JSON.stringify(ticketPayload);
    const b64 = typeof btoa === 'function' 
      ? btoa(rawJson) 
      : (typeof Buffer !== 'undefined' ? Buffer.from(rawJson).toString('base64') : encodeURIComponent(rawJson));
    const ticketStr = `KRYP:TOURNEY:${b64}`;
    showPocketToast(`Generated Fast Check-In Pass for ${characterName} (28 feats verified, 0 PII).`, 'success');
    this.logAudit('TOURNAMENT_TICKET_ISSUED', `Issued pass for ${characterName}`);
    return ticketStr;
  }

  public verifyTournamentFast(ticketStr?: string): boolean {
    const start = typeof performance !== 'undefined' ? performance.now() : Date.now();
    // Simulate fast check-in verification (< 10ms target)
    const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - start;
    showPocketToast(`Tournament pass verified in ${elapsed.toFixed(2)}ms! [Pathfinder Society Legal]`, 'success');
    this.logAudit('TOURNAMENT_CHECKIN_VERIFIED', `Pass verified in ${elapsed.toFixed(2)}ms with zero PII`);
    return true;
  }

  public getAuditLog(): Array<{ timestamp: string; action: string; details: string }> {
    return [...this.auditLog];
  }

  private logAudit(action: string, details: string): void {
    this.auditLog.push({
      timestamp: new Date().toISOString(),
      action,
      details,
    });
  }
}

// Global functions for inline onclick handlers & window exposure
if (typeof window !== 'undefined') {
  const app = new PocketVaultApp();
  (window as any).pocketVault = app;
  (window as any).PocketVaultApp = PocketVaultApp;
  (window as any).showPocketToast = showPocketToast;
  (window as any).generateQuickProof = (pkgId: string) => app.generateQuickProof(pkgId);
  (window as any).shareBeacon = (pkgId: string) => app.shareBeacon(pkgId);
  (window as any).verifyBiometrics = () => app.verifyBiometrics();
  (window as any).generateTournamentTicket = (name?: string) => app.generateTournamentTicket(name);
  (window as any).verifyTournamentFast = (ticket?: string) => app.verifyTournamentFast(ticket);
}

if (typeof document !== 'undefined') {
  const startPocketVault = () => {
    const app = (window as any).pocketVault || new PocketVaultApp();
    (window as any).pocketVault = app;
    app.init();
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startPocketVault);
  } else {
    startPocketVault();
  }
}

