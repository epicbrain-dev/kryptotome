# Kryptotome Tabletop Vault - Owlbear Rodeo 2.0 Extension

The **Kryptotome Tabletop Vault** extension for [Owlbear Rodeo 2.0](https://www.owlbear.rodeo/) connects your room canvas to your decentralized Kryptotome vault. Game Masters and players can mount unlocked creature tokens, high-resolution battlemaps, and interactive spell cards directly onto the tabletop with zero platform lock-in.

---

## Features

- **Token Mounting**: Mount character and monster tokens with automatically configured HP bars, AC, and grid scale (Medium, Large, Gargantuan).
- **Battlemap Integration**: Mount 4K and ultra-wide battlemaps locked directly to the MAP layer with accurate DPI and grid alignment.
- **Spell Cards**: Mount interactive spell cards onto the canvas with school, casting time, range, and description for party reference.
- **Zero-Knowledge Room Sync**: Share table tokens via WebRTC / OBR Broadcast channels (`kryptotome:table-sync`) so players can inspect mounted assets without possessing the GM's private keys.

---

## Installation into Owlbear Rodeo 2.0

### Option 1: Local Development / Testing

1. Compile the extension:
   ```bash
   npm run build
   ```
2. Start a local static file server inside `extensions/owlbear`:
   ```bash
   npx serve -p 8080 extensions/owlbear
   ```
3. Open [Owlbear Rodeo](https://www.owlbear.rodeo/) in your browser and enter any game room.
4. Open the **Extensions** menu (bottom-left gear icon or extension manager) and click **Add Extension (+)**.
5. In the Extension URL field, enter:
   ```text
   http://localhost:8080/manifest.json
   ```
6. Click **Install**. The gilded Kryptotome Vault icon will appear in your room action bar.

### Option 2: Production Deployment

Host the `extensions/owlbear` directory on any HTTPS host (e.g. GitHub Pages, Vercel, Cloudflare Pages), then add the hosted `manifest.json` URL to Owlbear Rodeo.

---

## Usage

1. Click the **Kryptotome Vault** icon in the Owlbear Rodeo action bar to open the side panel.
2. Select **Tokens**, **Battlemaps**, or **Spell Cards**.
3. Click **Mount** next to any unlocked asset to place it directly at your current scene cursor position.
