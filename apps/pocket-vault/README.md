# Kryptotome Pocket Vault

The **Kryptotome Pocket Vault** is an enterprise-grade, biometric-secured, local-first mobile and desktop vault for tabletop RPG players and Game Masters. It stores digital rulebook entitlements as W3C Verifiable Credentials (v2.0) and generates zero-knowledge proofs (Groth16 & PlonK) completely offline.

---

## Key Features

- **Biometric Security**: Hardware-bound to Apple Secure Enclave (iOS/macOS) or Android Keystore StrongBox.
- **Air-Gapped QR Import**: Scan single-frame or multi-frame animated QR codes from physical books, Kickstarter vouchers, or convention passes.
- **Air-Gapped Table Beacon**: Local BLE and mDNS broadcast service allowing nearby table participants to verify unlocked compendiums without sharing private keys or using an internet connection.
- **Tournament Pass (Section 13.5)**: Instant, zero-PII check-in pass for official convention and league play (e.g., Pathfinder Society, Adventurers League) verifying legal character build entitlements in under 10ms.
- **Dark Tabletop Fantasy UI**: Mystical leyline astrolabes, parchment-gilded cards, and non-blocking toast notifications.

---

## Getting Started

### Running in Development (Web / Browser Mode)

To launch the web interface locally:

```bash
# Build the application bundle
npm run build

# Open apps/pocket-vault/index.html in any modern browser, or serve with your favorite static server:
npx serve apps/pocket-vault
```

### Running with Tauri (Desktop / Mobile)

Pocket Vault is configured for native cross-platform execution via [Tauri 2.0](https://tauri.app/):

```bash
# In the repository root:
cargo tauri dev --config apps/pocket-vault/src-tauri/tauri.conf.json
```

To build production binaries (macOS `.dmg` / `.app`, Linux `.deb` / `.AppImage`, Windows `.msi`):

```bash
cargo tauri build --config apps/pocket-vault/src-tauri/tauri.conf.json
```

---

## User Workflows

### 1. Reassemble Air-Gapped Physical Voucher
1. Open the **Air-Gapped Scanning** card.
2. If your voucher has multiple animated QR frames (e.g. from an air-gapped terminal or convention booklet), paste or scan each frame token (e.g., `KRYP:QR:1:2:vch-con-2026-pass:...`).
3. The vault automatically reassembles and validates the SHA-256 frame checksum.
4. Click **Redeem Voucher** to add the rulebook or tournament pass to your vault.

### 2. Verify Biometric Attestation
1. In the **Biometric Enclave Status** card, click **Re-verify Biometrics**.
2. Touch ID, Face ID, or your biometric prompt verifies your physical presence.
3. The cryptographic key tag and SHA-256 attestation digest are refreshed and recorded in the audit chronicle.

### 3. Convention Tournament Check-In
1. Navigate to the **Tournament Pass** section.
2. Present your zero-knowledge QR pass to the tournament marshal.
3. The marshal's scanner verifies in < 10ms that your character's feats and spells are legally owned with zero personal data transmitted.
