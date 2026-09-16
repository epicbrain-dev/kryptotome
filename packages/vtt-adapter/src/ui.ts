/**
 * Reference UI Components and Aesthetics for Kryptotome VTT Integration
 * Dark-mode, glassmorphism, cryptographic badges, and micro-animations.
 */

export interface UnlockModalOptions {
  title?: string;
  publisherName?: string;
  expiresInSeconds?: number;
  onUnlock?: () => void;
  onCancel?: () => void;
}

export interface TableSharingBadgeState {
  isGameMaster: boolean;
  sessionId: string;
  connectedPeerCount: number;
  packageId?: string;
  allowedScopes: string[];
}

/**
 * Returns complete CSS stylesheet with glassmorphism, animations, and typography for VTT UI.
 */
export function renderUnlockAnimationCss(): string {
  return `
/* Kryptotome VTT Reference Stylesheet & Micro-Animations */
@keyframes ktome-pulse-glow {
  0%, 100% {
    box-shadow: 0 0 15px rgba(99, 102, 241, 0.4), inset 0 0 15px rgba(99, 102, 241, 0.2);
    border-color: rgba(129, 140, 248, 0.6);
  }
  50% {
    box-shadow: 0 0 30px rgba(99, 102, 241, 0.8), inset 0 0 25px rgba(99, 102, 241, 0.4);
    border-color: rgba(199, 210, 254, 0.9);
  }
}

@keyframes ktome-rotate-shield {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

@keyframes ktome-unlock-burst {
  0% {
    transform: scale(0.95);
    opacity: 0.8;
  }
  50% {
    transform: scale(1.05);
    opacity: 1;
    filter: brightness(1.3);
  }
  100% {
    transform: scale(1);
    opacity: 1;
  }
}

.ktome-glass-panel {
  background: rgba(15, 23, 42, 0.85);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 12px;
  color: #f8fafc;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

.ktome-modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(2, 6, 23, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10000;
}

.ktome-unlock-card {
  width: 440px;
  max-width: 90vw;
  padding: 24px;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
  animation: ktome-unlock-burst 0.35s cubic-bezier(0.16, 1, 0.3, 1);
}

.ktome-badge-crypto {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(99, 102, 241, 0.15);
  color: #a5b4fc;
  border: 1px solid rgba(99, 102, 241, 0.3);
  padding: 4px 10px;
  border-radius: 9999px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.ktome-status-indicator {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #10b981;
  box-shadow: 0 0 8px #10b981;
}

.ktome-btn-primary {
  background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
  color: #ffffff;
  border: none;
  padding: 10px 18px;
  border-radius: 8px;
  font-weight: 600;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s ease;
  box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
}

.ktome-btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(79, 70, 229, 0.45);
  filter: brightness(1.1);
}

.ktome-btn-secondary {
  background: rgba(51, 65, 85, 0.5);
  color: #cbd5e1;
  border: 1px solid rgba(255, 255, 255, 0.1);
  padding: 10px 16px;
  border-radius: 8px;
  font-weight: 500;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.ktome-btn-secondary:hover {
  background: rgba(71, 85, 105, 0.7);
  color: #f8fafc;
}

.ktome-compendium-lock-overlay {
  position: absolute;
  inset: 0;
  background: rgba(15, 23, 42, 0.88);
  backdrop-filter: blur(8px);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 20px;
  z-index: 50;
  border-radius: inherit;
}
`;
}

/**
 * Renders HTML for the cryptographic challenge unlock modal presented when a user
 * accesses a locked compendium module.
 */
export function renderUnlockModalHtml(
  packageId: string,
  challengeNonce: string,
  options?: UnlockModalOptions
): string {
  const title = options?.title || 'Unlock Protected Compendium Pack';
  const publisherName = options?.publisherName || 'Verified Publisher';
  const ttl = options?.expiresInSeconds || 60;

  return `
<div class="ktome-modal-backdrop" id="ktome-unlock-modal-${packageId}">
  <div class="ktome-glass-panel ktome-unlock-card">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
      <div>
        <span class="ktome-badge-crypto">
          <span class="ktome-status-indicator"></span>
          Kryptotome ZK Protocol
        </span>
        <h2 style="font-size: 18px; font-weight: 700; margin: 8px 0 2px 0;">${escapeHtml(title)}</h2>
        <p style="font-size: 12px; color: #94a3b8; margin: 0;">Publisher: <strong>${escapeHtml(publisherName)}</strong></p>
      </div>
      <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(99, 102, 241, 0.2); display: flex; align-items: center; justify-content: center;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
      </div>
    </div>

    <div style="background: rgba(2, 6, 23, 0.4); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 8px; padding: 12px; margin-bottom: 20px;">
      <div style="display: flex; justify-content: space-between; font-size: 11px; color: #64748b; margin-bottom: 4px;">
        <span>PACKAGE ID</span>
        <span>CHALLENGE FRESHNESS</span>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <code style="font-size: 12px; color: #38bdf8;">${escapeHtml(packageId)}</code>
        <span style="font-size: 11px; color: #f59e0b; font-weight: 600;">${ttl}s TTL</span>
      </div>
      <div style="font-size: 10px; color: #475569; margin-top: 6px; font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        NONCE: ${escapeHtml(challengeNonce)}
      </div>
    </div>

    <p style="font-size: 12px; line-height: 1.5; color: #94a3b8; margin-bottom: 20px;">
      This rule compendium is protected by cryptographic entitlement verification. Present a zero-knowledge ownership proof from your local key vault to unlock rule schemas into memory.
    </p>

    <div style="display: flex; justify-content: flex-end; gap: 10px;">
      <button type="button" class="ktome-btn-secondary" id="ktome-btn-cancel-${packageId}">
        Cancel
      </button>
      <button type="button" class="ktome-btn-primary" id="ktome-btn-unlock-${packageId}">
        Present Proof & Unlock
      </button>
    </div>
  </div>
</div>
`;
}

/**
 * Renders HTML for the floating table sharing status HUD badge.
 */
export function renderTableSharingStatusBadge(state: TableSharingBadgeState): string {
  const roleText = state.isGameMaster ? 'GM Host' : 'Player Client';
  const roleColor = state.isGameMaster ? '#818cf8' : '#38bdf8';
  const scopeTags = state.allowedScopes
    .slice(0, 3)
    .map((s) => `<span style="background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; font-size: 10px;">${escapeHtml(s)}</span>`)
    .join(' ');

  return `
<div class="ktome-glass-panel" style="display: inline-flex; align-items: center; gap: 12px; padding: 8px 14px; font-size: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.4);">
  <div style="display: flex; align-items: center; gap: 6px;">
    <span class="ktome-status-indicator"></span>
    <span style="font-weight: 700; color: ${roleColor};">${roleText}</span>
  </div>

  <span style="color: rgba(255,255,255,0.2);">|</span>

  <div style="display: flex; align-items: center; gap: 6px; color: #94a3b8;">
    <span>Peers:</span>
    <strong style="color: #f8fafc;">${state.connectedPeerCount}</strong>
  </div>

  ${state.packageId ? `
  <span style="color: rgba(255,255,255,0.2);">|</span>
  <span style="color: #cbd5e1; font-family: monospace; font-size: 11px;">${escapeHtml(state.packageId)}</span>
  ` : ''}

  <div style="display: flex; gap: 4px; margin-left: 4px;">
    ${scopeTags}
  </div>
</div>
`;
}

/**
 * Renders lock overlay placed directly over locked compendium pack lists in the VTT canvas.
 */
export function renderCompendiumLockOverlay(packageId: string, title?: string): string {
  return `
<div class="ktome-compendium-lock-overlay" id="ktome-lock-overlay-${packageId}">
  <div style="width: 48px; height: 48px; border-radius: 50%; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(129, 140, 248, 0.4); display: flex; align-items: center; justify-content: center; margin-bottom: 12px;">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
    </svg>
  </div>
  <h3 style="font-size: 14px; font-weight: 700; margin: 0 0 4px 0; color: #f8fafc;">${escapeHtml(title || 'Protected Compendium')}</h3>
  <p style="font-size: 11px; color: #94a3b8; margin: 0 0 14px 0; max-width: 260px;">
    Credential verification required to unlock rule mechanics.
  </p>
  <button type="button" class="ktome-btn-primary" style="padding: 6px 14px; font-size: 12px;" id="ktome-trigger-unlock-${packageId}">
    Unlock Module
  </button>
</div>
`;
}

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
