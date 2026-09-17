/**
 * Kryptotome Web VTT Bridge - Action Popup Logic
 */

export function initPopup(): void {
  const searchInput = document.getElementById('searchInput') as HTMLInputElement | null;
  const packagesContainer = document.getElementById('packagesContainer');

  if (searchInput && packagesContainer) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase().trim();
      const cards = packagesContainer.querySelectorAll('.package-card');

      cards.forEach((card) => {
        const title = (card.querySelector('.pkg-title')?.textContent || '').toLowerCase();
        if (title.includes(q)) {
          (card as HTMLElement).style.display = 'block';
        } else {
          (card as HTMLElement).style.display = 'none';
        }
      });
    });
  }
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => initPopup());
}
