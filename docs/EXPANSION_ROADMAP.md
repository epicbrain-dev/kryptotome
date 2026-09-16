# Kryptotome Protocol: Future Horizons & Expansion Roadmap

This document outlines the post-v1.0 engineering roadmap for the Kryptotome Protocol once the core protocol checklist ([CHECKLIST.md](file:///Volumes/External/Labs/kryptotome/CHECKLIST.md)) is completed.

---

## 1. Ecosystem & Client Runtime Expansion

- [ ] **Owlbear Rodeo 2.0 Extension**:
  - Build an official Owlbear Rodeo extension leveraging the Owlbear Extension SDK.
  - Implement WebRTC data channel handshakes to mount unlocked token packs, maps, and spell cards directly into the room canvas.
- [ ] **Browser Extension for Web VTTs (Roll20 & Alchemy)**:
  - Develop a lightweight browser extension (Manifest V3) that interfaces with the local vault.
  - Inject unlocked compendium entries directly into character sheets and journal tabs on-the-fly.
- [ ] **Open Character Builder Adapters**:
  - Provide reference plugins for open character builders (e.g., Pathbuilder 2e, Wanderer's Guide, Demiplane-style open architectures).
  - Enable local unlocking of feats, classes, and spells without transmitting user keys to centralized builder servers.
- [ ] **Standalone "Pocket Vault" Mobile App (Tauri / iOS / Android)**:
  - Native mobile key vault utilizing iOS Secure Enclave and Android Keystore for biometric protection.
  - Continuous camera scanner for instant physical convention and retail QR code ingestion.
  - Local Wi-Fi / Bluetooth Low Energy (BLE) beacon for hosting or joining in-person game tables.

---

## 2. Advanced Cryptography & Table Privacy

- [ ] **Attribute-Level Selective Disclosure**:
  - Extend the ZK-SNARK circuit with Merkle inclusion proofs over compendium item trees.
  - Allow a player to prove ownership of a single spell or monster stat block from a 500-page bestiary without disclosing the specific bundle or edition purchased.
- [ ] **Collective Party Pooling (Multi-Holder Aggregation)**:
  - Implement cryptographic session aggregation where multiple players at the table contribute individual entitlements (e.g., Player A contributes *Core Rules*, Player B contributes *Bestiary*, GM contributes *Campaign Guide*).
  - Issue an aggregated session proof allowing the entire party to share the combined library for the duration of the campaign.
- [ ] **Passkey & FIDO2 / WebAuthn Hardware Binding**:
  - Enable binding user Pedersen holder commitments directly to hardware security keys (YubiKeys) or OS Passkeys.
  - Mitigate host compromise risk by requiring hardware biometric approval for proof generation.

---

## 3. Indie Publisher & Creator Tooling

- [ ] **Kryptotome Publisher Studio (GUI Desktop App)**:
  - Build an indie-creator desktop app (Tauri + Rust + Slint / Webview) for drag-and-drop packaging of rulebook PDFs, Markdown, and JSON data.
  - Deterministic BLAKE3 content hashing, schema validation against Paizo ORC / CC-BY schemas, and cryptographic package signing via local hardware keys.
- [ ] **Crowdfunding Fulfillment Bridge (Kickstarter & BackerKit)**:
  - Automated connector that ingests backer reward tiers and generates batch-signed W3C VC credentials or digital activation links.
  - Backers import credentials directly into their local vault with a single click.
- [ ] **Print-on-Demand (POD) Physical Vouchers & NFC Book Tags**:
  - Specification and tooling for embedding cryptographic claim vouchers in physical hardcover books (scratch-off activation codes or NFC tags).
  - Bridge physical book purchases into digital compendium entitlements without double-charging consumers.

---

## 4. Decentralized Content Distribution & Dependency Graphs

- [ ] **Peer-to-Peer Compendium Asset Swarms (BitTorrent / Libp2p)**:
  - Distribute multi-gigabyte compendium assets (4K battlemaps, audio tracks, VTT tokens) over decentralized content-addressed swarms.
  - Asset blobs are keyed to publisher manifest digests and mounted only when the local verifier confirms valid proof.
- [ ] **Homebrew Lineage & Attribution Graph**:
  - Standardize cryptographic dependency declarations for third-party creators (e.g., *"Requires entitlement to 'Core Rules v1.2' or later"*).
  - Maintain a verifiable, open creator attribution tree preserving upstream copyright while enabling downstream homebrew monetization.
- [ ] **Universal Cross-VTT Schema Transpiler**:
  - Automated translation pipeline converting open game data schemas (ORC, SRD 5.1 JSON) directly into Foundry VTT LevelDB packs, Roll20 JSON formats, or Markdown compendiums on-the-fly.

---

## 5. In-Person & Convention Play

- [ ] **Air-Gapped Table Beacons**:
  - Lightweight verifier daemon capable of running on a battery-powered Raspberry Pi or GM laptop.
  - Broadcasts an offline local Wi-Fi hotspot or BLE beacon; players sitting down at a table automatically handshake and mount the GM's campaign setting without Internet access.
- [ ] **Organized Play & Tournament Fast Check-In**:
  - Specialized scanner app for convention tournament check-ins (e.g., Pathfinder Society, Adventurers League).
  - Verify character sheet build legality and official rulebook ownership in $< 10\text{ms}$ via QR code scan with zero personal identity revealed.
