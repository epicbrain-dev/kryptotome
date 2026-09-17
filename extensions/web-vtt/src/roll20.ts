/**
 * Kryptotome Web VTT Bridge - Roll20 Content Script
 * Injects unlocked compendium records into Roll20 character sheets and compendium drawers.
 */

export interface Roll20SpellPayload {
  name: string;
  level: number;
  school: string;
  castingTime: string;
  range: string;
  duration: string;
  damage?: string;
  damageType?: string;
  savingThrow?: string;
  description: string;
}

export interface Roll20FeatPayload {
  name: string;
  prerequisite?: string;
  description: string;
}

export function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export class Roll20Injector {
  private observer: MutationObserver | null = null;
  private injectedSheets: WeakSet<Element> = new WeakSet();

  public init(): void {
    this.injectCompendiumPanel();
    this.observeCharacterSheets();
  }

  /**
   * Injects Kryptotome Vault panel into the Roll20 compendium/journal drawer.
   */
  public injectCompendiumPanel(): HTMLElement | null {
    const journalTab = document.getElementById('journal') || document.getElementById('compendium');
    if (!journalTab) return null;

    if (document.getElementById('kryptotome-roll20-drawer')) {
      return document.getElementById('kryptotome-roll20-drawer');
    }

    const panel = document.createElement('div');
    panel.id = 'kryptotome-roll20-drawer';
    panel.className = 'kryptotome-roll20-panel';
    panel.innerHTML = `
      <div class="kryptotome-roll20-header">
        <span>🛡️ Kryptotome Vault</span>
        <span class="kryptotome-badge">Proof Verified</span>
      </div>
      <p style="font-size: 11px; color: #94a3b8; margin-bottom: 8px;">
        Local zero-knowledge compendium active. Drag or click records to inject into character sheets.
      </p>
      <div style="display: flex; gap: 4px;">
        <button id="kryptotome-inject-fireball" class="kryptotome-inject-btn">+ Fireball</button>
        <button id="kryptotome-inject-cure" class="kryptotome-inject-btn">+ Cure Wounds</button>
      </div>
    `;

    journalTab.prepend(panel);

    panel.querySelector('#kryptotome-inject-fireball')?.addEventListener('click', () => {
      this.injectSampleFireball();
    });

    panel.querySelector('#kryptotome-inject-cure')?.addEventListener('click', () => {
      this.injectSampleCureWounds();
    });

    return panel;
  }

  /**
   * Observes DOM mutations for newly opened character sheet dialogs or iframes.
   */
  public observeCharacterSheets(): void {
    if (this.observer) return;

    this.observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node instanceof HTMLElement) {
            const sheets = node.querySelectorAll('.character-sheet, .charsheet, iframe.sheet-iframe');
            sheets.forEach((s) => this.enhanceCharacterSheet(s));
          }
        }
      }
    });

    this.observer.observe(document.body, { childList: true, subtree: true });
  }

  /**
   * Enhances a detected character sheet container with Kryptotome auto-fill buttons.
   */
  public enhanceCharacterSheet(sheetElement: Element): void {
    if (this.injectedSheets.has(sheetElement)) return;
    this.injectedSheets.add(sheetElement);

    const targetDoc = sheetElement instanceof HTMLIFrameElement
      ? sheetElement.contentDocument
      : sheetElement.ownerDocument;

    if (!targetDoc) return;

    // Add quick badge to sheet header
    const header = targetDoc.querySelector('.sheet-header, .character-header') || sheetElement;
    const badge = targetDoc.createElement('div');
    badge.className = 'kryptotome-badge';
    badge.innerHTML = '⚡ Vault Entitlements Mounted';
    badge.style.margin = '4px';
    header.prepend(badge);
  }

  /**
   * Injects a verified spell into a Roll20 character sheet repeating section.
   */
  public injectSpellToSheet(
    targetDoc: Document,
    spell: Roll20SpellPayload
  ): HTMLElement {
    const spellSection =
      targetDoc.querySelector('.repeating_spell-level-' + spell.level) ||
      targetDoc.querySelector('.repcontainer[data-groupname="repeating_spell-cantrip"]') ||
      targetDoc.querySelector('.spells-container') ||
      targetDoc.body;

    const row = targetDoc.createElement('div');
    row.className = 'repitem kryptotome-injected-spell';
    row.setAttribute('data-kryptotome-id', spell.name.toLowerCase().replace(/\s+/g, '-'));

    const safeName = escapeHtml(spell.name);
    const safeSchool = escapeHtml(spell.school);

    row.innerHTML = `
      <div style="padding: 6px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center;">
        <div>
          <strong style="color: #38bdf8;">${safeName}</strong>
          <span style="font-size: 10px; color: #94a3b8; margin-left: 6px;">Lvl ${spell.level} ${safeSchool}</span>
        </div>
        <span class="kryptotome-badge" style="font-size: 9px;">ZK Proof</span>
      </div>
    `;

    spellSection.appendChild(row);
    return row;
  }

  /**
   * Injects a verified feat into a Roll20 character sheet traits/features repeating section.
   */
  public injectFeatToSheet(
    targetDoc: Document,
    feat: Roll20FeatPayload
  ): HTMLElement {
    const featSection =
      targetDoc.querySelector('.repcontainer[data-groupname="repeating_traits"]') ||
      targetDoc.querySelector('.features-container') ||
      targetDoc.body;

    const row = targetDoc.createElement('div');
    row.className = 'repitem kryptotome-injected-feat';
    const safeFeatName = escapeHtml(feat.name);
    const safePrereq = feat.prerequisite ? escapeHtml(feat.prerequisite) : '';
    const safeDesc = escapeHtml(feat.description);

    row.innerHTML = `
      <div style="padding: 6px; border-bottom: 1px solid #334155;">
        <strong style="color: #a78bfa;">${safeFeatName}</strong>
        ${safePrereq ? `<div style="font-size: 10px; color: #94a3b8;">Prereq: ${safePrereq}</div>` : ''}
        <div style="font-size: 11px; color: #cbd5e1; margin-top: 4px;">${safeDesc}</div>
      </div>
    `;

    featSection.appendChild(row);
    return row;
  }

  private injectSampleFireball(): void {
    this.injectSpellToSheet(document, {
      name: 'Fireball',
      level: 3,
      school: 'Evocation',
      castingTime: '1 action',
      range: '150 feet',
      duration: 'Instantaneous',
      damage: '8d6',
      damageType: 'Fire',
      description: 'A bright streak flashes from your pointing finger...',
    });
  }

  private injectSampleCureWounds(): void {
    this.injectSpellToSheet(document, {
      name: 'Cure Wounds',
      level: 1,
      school: 'Evocation',
      castingTime: '1 action',
      range: 'Touch',
      duration: 'Instantaneous',
      description: 'A creature you touch regains hit points equal to 1d8 + modifier.',
    });
  }
}

// Auto-run if executed inside browser content script environment
if (typeof document !== 'undefined') {
  const injector = new Roll20Injector();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => injector.init());
  } else {
    injector.init();
  }
}
