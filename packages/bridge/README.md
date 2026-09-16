# @kryptotome/bridge

**Merchant connectors and air-gapped bridges for the Kryptotome Protocol.**

`@kryptotome/bridge` enables creators, publishers, and virtual tabletop runtimes to ingest purchases from external storefronts (itch.io, DriveThruRPG) or physical air-gapped points of sale (conventions, physical retail) and locally derive standardized [W3C Verifiable Credentials v2.0](https://www.w3.org/TR/vc-data-model-2.0/).

---

## Key Principles

- **Zero Network Egress for Keys**: Private keys, holder commitments, and derived credentials **never** leave the user's local client runtime.
- **Local Credential Derivation**: Bridges authenticate purchases against vendor APIs or verified digital invoices, and derive W3C VC v2.0 credentials bound to the user's local key custody.
- **Standardized Error Taxonomy**: All bridge failures propagate standard protocol error codes (`KRYP-801` through `KRYP-804`, `KRYP-104`, `KRYP-201`).

---

## Bridges

### 1. itch.io Bridge (`ItchIoBridge`)
Connects to the itch.io API (`/key/me`, `/key/my-owned-keys`) using OAuth access tokens or API keys.

```typescript
import { ItchIoBridge, InMemoryPublisherRegistry } from '@kryptotome/bridge';

const registry = new InMemoryPublisherRegistry();
registry.registerMapping({
  packageId: 'open-rpg/core-rules',
  publisherId: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
  merchant: 'itch.io',
  externalGameId: '12345',
  contentDigest: 'sha256-4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'
});

const bridge = new ItchIoBridge(registry);
await bridge.authenticate({ apiKey: 'itch_api_key' });

// Fetch purchases and derive credentials locally
const records = await bridge.fetchPurchasedPackages();
const credential = await bridge.deriveCredential(records[0], {
  holderCommitment: 'urn:kryptotome:commitment:pedersen:sample',
  publisherSigner: async (data) => signWithEd25519(data)
});
```

### 2. DriveThruRPG Bridge (`DriveThruRpgBridge`)
Connects to DriveThruRPG's digital library using Account Application Keys.

```typescript
import { DriveThruRpgBridge, InMemoryPublisherRegistry } from '@kryptotome/bridge';

const bridge = new DriveThruRpgBridge(registry);
await bridge.authenticate({ applicationKey: 'dtrpg_app_key' });

const records = await bridge.fetchPurchasedPackages();
const credential = await bridge.deriveCredential(records[0], {
  holderCommitment: 'urn:kryptotome:commitment:pedersen:sample',
  publisherSigner: async (data) => signWithEd25519(data)
});
```

### 3. Offline & Physical Bridges (`OfflineBridge`)
Provides air-gapped entitlement import for convention booths, physical game stores, and paper receipts.

- **Signed Digital Invoices**: Ed25519 digitally signed receipts verified against known publisher keys.
- **Chunked QR Codes**: Multi-frame QR code generator and reassembler supporting animated QR streams with frame sequencing, chunk CRC/checksum validation, and out-of-order frame reassembly.

```typescript
import { OfflineBridge } from '@kryptotome/bridge';

const bridge = new OfflineBridge(publisherPublicKeyResolver);

// 1. Import signed invoice
const invoice = await bridge.importReceipt(rawSignedInvoiceJson);

// 2. Export multi-frame QR frames for camera scanning
const frames = bridge.exportQrFrames(invoice, { maxPayloadSize: 200 });

// 3. Ingest frames from camera scanner in any order
const receiver = new OfflineBridge(publisherPublicKeyResolver);
for (const frame of frames) {
  const result = receiver.ingestQrFrame(frame);
  if (result.complete) {
    const verifiedCredential = result.credential;
  }
}
```

---

## License

Apache-2.0
