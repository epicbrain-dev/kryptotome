# @kryptotome/vtt-adapter

**Virtual Tabletop (VTT) client adapter and Foundry VTT compendium hooks for the Kryptotome Protocol.**

`@kryptotome/vtt-adapter` bridges Kryptotome entitlements with virtual tabletop platforms. It provides automated compendium interception, interactive unlock modals, real-time table session sharing via WebRTC / SocketLib, and HUD status badges.

---

## Features

- **Compendium Collection Hooking**: Seamlessly intercepts Foundry VTT `CompendiumCollection` calls (`load()`, `getData()`), preventing unauthorized rendering while locked and unlocking on-demand.
- **On-Demand ZK Proof Unlock**: Prompts users with a modern glassmorphic unlock modal to present single-use ZK proofs from their local vault.
- **Fast-Path Caching**: Caches validated compendiums in memory during active game sessions, bypassing repeated cryptographic verification on subsequent loads.
- **Table Session Sharing (SocketLib / WebRTC)**: Allows the Game Master to issue ephemeral Ed25519 table tokens to connected players over SocketLib or WebRTC channels.
- **Reference UI Components**: CSS glassmorphism, responsive unlock dialogs, and floating table sharing HUD badges.

---

## Installation

```bash
npm install @kryptotome/vtt-adapter
```

---

## Usage

### 1. Hooking Foundry VTT Compendiums

```typescript
import { FoundryVttAdapter } from '@kryptotome/vtt-adapter';

const adapter = new FoundryVttAdapter({
  verifier: wasmVerifierInstance,
  promptUserForProof: async (packageId, challengeNonce) => {
    // Open UI modal and retrieve proof bundle from local vault
    return await vault.generateProofBundle(packageId, challengeNonce);
  },
  renderNotification: (msg, type) => ui.notifications.info(msg)
});

// Hook into Foundry VTT compendium collection
adapter.hookCompendiumCollection(game.packs.get('open-rpg.core-rules'), 'open-rpg/core-rules');
```

### 2. Multi-User Table Sharing via SocketLib

```typescript
import { VttSocketDispatcher } from '@kryptotome/vtt-adapter';

const socketDispatcher = new VttSocketDispatcher({
  socketlib: game.socket,
  sessionManager: wasmSessionManager,
  isGM: game.user.isGM,
  userId: game.user.id
});

// GM authorizes and broadcasts session token to player
await socketDispatcher.dispatchSessionToken(peerUserId, 'open-rpg/core-rules', ['rules:read', 'spells:read']);
```

### 3. Glassmorphic UI Components

```typescript
import { renderUnlockModalHtml, renderUnlockAnimationCss, renderTableSharingHudHtml } from '@kryptotome/vtt-adapter';

// Render unlock modal for locked compendium
const modalHtml = renderUnlockModalHtml({
  packageId: 'open-rpg/core-rules',
  title: 'Core Rules Supplement',
  publisher: 'Independent Publisher',
  digest: 'sha256-4b2277...'
});

// Inject into DOM with CSS animations
document.head.insertAdjacentHTML('beforeend', `<style>${renderUnlockAnimationCss()}</style>`);
document.body.insertAdjacentHTML('beforeend', modalHtml);
```

---

## License

Apache-2.0
