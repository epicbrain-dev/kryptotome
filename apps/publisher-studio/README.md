# Kryptotome Publisher Studio

The **Kryptotome Publisher Studio** is an enterprise-grade desktop authoring and release management studio for TTRPG creators, publishers, and independent game designers. It empowers publishers to package, cryptographically seal, and distribute digital rulebooks with zero platform lock-in.

---

## Key Features

- **Rulebook Asset Manifest Builder**: Compile PDFs, Markdown grimoires, JSON compendiums, and WebP battlemaps into a single cryptographically attested package.
- **Deterministic BLAKE3 Digests**: Compute root package digests and verify file integrity across distributed mirrors.
- **Ed25519 Cryptographic Signing**: Seal `.kryptopkg` bundles with your organization's sovereign Ed25519 signing key.
- **Crowdfunding Batch Fulfillment**: Import Kickstarter or BackerKit backer survey CSVs and export thousands of signed claim vouchers in seconds.
- **Print-on-Demand (POD) & NFC Cards**: Generate scratch-off claim codes (`KRYP-XXXX-YYYY`) and NDEF-formatted payloads for NTAG213 / NTAG215 smart physical book inserts.
- **Enterprise Audit Chronicle**: Real-time cryptographic ledger logging all packaging, signing, and fulfillment actions.

---

## Getting Started

### Running in Development (Web / Browser Mode)

```bash
# Build the TypeScript bundles
npm run build

# Open apps/publisher-studio/index.html in your browser or run:
npx serve apps/publisher-studio
```

### Running with Tauri (Desktop Binary)

```bash
# Run desktop development window:
cargo tauri dev --config apps/publisher-studio/src-tauri/tauri.conf.json

# Build release bundle (macOS, Windows, Linux):
cargo tauri build --config apps/publisher-studio/src-tauri/tauri.conf.json
```

---

## Publisher Guide

### 1. Sealing a New Rulebook Release
1. Enter your **Package Identifier** (e.g., `pkg-eldritch-vault-5e`), **Title**, **Version**, and **Publisher Organization**.
2. Select your gaming license (**Paizo ORC**, **Creative Commons BY 4.0**, or **Open Gaming License 1.0a**) and enter the required attribution text.
3. Drag & drop your book's assets (PDFs, JSON monster bestiaries, spell lists, or battlemaps) into the ingestion dropzone.
4. Click **Forge New Ed25519 Keypair** or paste your publisher private key.
5. Click **Seal & Sign Manifest**. The studio will generate a signed, tamper-proof manifest bundle ready for distribution.

### 2. Fulfilling a Crowdfunding Campaign
1. Switch to the **Crowdfunding Fulfillment** tab.
2. Select **Kickstarter** or **BackerKit** from the platform dropdown (or click "Load Sample CSV" to test).
3. Paste your backer survey CSV export.
4. Click **Process Backer Fulfillment**.
5. Click **Export Claim CSV** to generate backer-ready claim URLs.

### 3. Printing Scratch-Off Cards or NFC Book Bookmarks
1. Switch to the **POD Physical Vouchers** tab.
2. Select your desired voucher format (**Scratch-off Code** or **NFC NDEF Tag**).
3. Set your batch quantity and click **Generate Batch**.
4. The generated NDEF hex bytes can be written directly to NTAG213 or NTAG215 adhesive tags using any standard NFC writer app (e.g., NFC Tools).
