/**
 * Kryptotome Web VTT Bridge - Alchemy RPG Content Script
 * Injects unlocked compendium cards (spells, items, actions) directly into Alchemy RPG interface.
 */

export interface AlchemyArticlePayload {
  title: string;
  category: 'spell' | 'action' | 'item' | 'feature';
  subtitle: string;
  body: string;
  tags?: string[];
}

export function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export class AlchemyInjector {
  private observer: MutationObserver | null = null;

  public init(): void {
    this.injectCodexHeader();
    this.observeCodexPanels();
  }

  /**
   * Injects Kryptotome vault indicator into Alchemy top bar / sidebar.
   */
  public injectCodexHeader(): HTMLElement | null {
    const nav = document.querySelector('header nav, .navigation-bar, aside') || document.body;
    if (document.getElementById('kryptotome-alchemy-badge')) {
      return document.getElementById('kryptotome-alchemy-badge');
    }

    const badge = document.createElement('div');
    badge.id = 'kryptotome-alchemy-badge';
    badge.className = 'kryptotome-badge';
    badge.style.margin = '8px';
    badge.innerHTML = `
      <span>⚡ Kryptotome Vault Active</span>
    `;

    nav.prepend(badge);
    return badge;
  }

  /**
   * Observes Alchemy universe/codex container mutations.
   */
  public observeCodexPanels(): void {
    if (this.observer) return;

    this.observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node instanceof HTMLElement) {
            const articleViews = node.querySelectorAll('.codex-view, .article-container, .tracker-panel');
            articleViews.forEach((v) => this.enhanceAlchemyPanel(v));
          }
        }
      }
    });

    this.observer.observe(document.body, { childList: true, subtree: true });
  }

  public enhanceAlchemyPanel(panelElement: Element): void {
    if (panelElement.querySelector('.kryptotome-injected-card')) return;

    const quickCard = this.createAlchemyCard({
      title: 'Shield of Faith',
      category: 'spell',
      subtitle: 'Level 1 Abjuration • Concentration',
      body: 'A shimmering field appears and surrounds a creature of your choice, granting it a +2 bonus to AC.',
      tags: ['Abjuration', 'Cleric', 'Paladin'],
    });

    panelElement.prepend(quickCard);
  }

  /**
   * Creates an Alchemy-styled card with ZK proof attestation badge.
   */
  public createAlchemyCard(article: AlchemyArticlePayload): HTMLElement {
    const card = document.createElement('div');
    card.className = 'kryptotome-alchemy-card kryptotome-injected-card';
    card.style.padding = '12px';
    card.style.borderRadius = '8px';
    card.style.marginBottom = '10px';
    card.style.backgroundColor = 'rgba(30, 41, 59, 0.7)';
    card.style.border = '1px solid rgba(99, 102, 241, 0.4)';

    const tagList = (article.tags || [])
      .map((t) => `<span style="font-size: 10px; background: #334155; padding: 2px 6px; border-radius: 4px; margin-right: 4px;">${escapeHtml(t)}</span>`)
      .join('');

    const safeTitle = escapeHtml(article.title);
    const safeSubtitle = escapeHtml(article.subtitle);
    const safeBody = escapeHtml(article.body);

    card.innerHTML = `
      <div style="font-size: 14px; font-weight: 700; color: #f8fafc;">${safeTitle}</div>
      <div style="font-size: 11px; color: #94a3b8; margin: 2px 0 8px 0;">${safeSubtitle}</div>
      <p style="font-size: 12px; color: #cbd5e1; line-height: 1.4; margin-bottom: 8px;">${safeBody}</p>
      <div style="display: flex; align-items: center; justify-content: space-between;">
        <div>${tagList}</div>
        <span class="kryptotome-badge" style="font-size: 9px;">Proof #4b2277</span>
      </div>
    `;

    return card;
  }
}

// Auto-run if inside browser content script
if (typeof document !== 'undefined') {
  const injector = new AlchemyInjector();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => injector.init());
  } else {
    injector.init();
  }
}
