# Kryptotome Web VTT Bridge

The **Kryptotome Web VTT Bridge** is a lightweight Manifest V3 browser extension for Google Chrome, Brave, Microsoft Edge, and Mozilla Firefox. It connects your browser directly to your local Kryptotome vault and injects verified compendium records, spells, and feats directly into virtual tabletop character sheets on **Roll20** and **Alchemy RPG**.

---

## Supported Platforms

- **Roll20**: Injects verified spells and feats directly into 5e / D&D character sheet repeating spellbook and feature sections.
- **Alchemy RPG**: Injects verified compendium article cards and statblocks with cryptographic verification badges.

---

## Installation Guide (Chrome / Brave / Edge)

1. Build the extension bundle from the repository root:
   ```bash
   npm run build
   ```
2. Open your browser and navigate to `chrome://extensions/` (or `brave://extensions/` / `edge://extensions/`).
3. Enable **Developer mode** using the toggle switch in the top-right corner.
4. Click **Load unpacked** in the top-left toolbar.
5. Select the directory:
   `/path/to/kryptotome/extensions/web-vtt`
6. The extension is now active. You will see the gilded Kryptotome icon in your browser toolbar!

---

## How to Use

1. Click the **Kryptotome Web VTT Bridge** icon in your browser toolbar to verify that your local vault is connected.
2. Navigate to an active game room on **Roll20** (`app.roll20.net`) or **Alchemy RPG** (`alchemyrpg.com`).
3. Open any character sheet.
4. The bridge injects a **Kryptotome Compendium Drawer**:
   - Spells and feats unlocked in your local vault display a **⚡ Kryptotome Verified** badge.
   - Click **Add Spell** or **Add Feat** to instantly mount the verified entry into your character sheet without manual typing or subscription fees.
