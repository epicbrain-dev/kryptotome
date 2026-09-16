import test from 'node:test';
import assert from 'node:assert';
import { PeerSessionClient, ScopePolicy, TableSessionManager } from '../dist/session.js';

test('Peer Handshake: Successful 4-step authorization and compendium mounting', () => {
  const host = new TableSessionManager({
    sessionId: 'session-table-abc',
    hostPeerId: 'host-ed25519-public-key-hex',
    packageId: 'paizo/pathfinder-2e-core',
    contentDigest: 'sha256:1122334455667788',
    sessionDurationMinutes: 240,
  });

  const peer = new PeerSessionClient('peer-player-valeros');
  assert.strictEqual(peer.getPeerId(), 'peer-player-valeros');

  // Step 1: Peer requests module access
  const request = peer.createAccessRequest('paizo/pathfinder-2e-core');
  assert.strictEqual(request.recipientPeerId, 'peer-player-valeros');
  assert.strictEqual(request.packageId, 'paizo/pathfinder-2e-core');
  assert.ok(request.nonce && request.nonce.length > 0);

  // Step 2 & 3: Host checks local entitlement and issues signed SessionAttestation
  const response = host.handleAccessRequest(request, true, ['read', 'character_builder']);
  assert.strictEqual(response.nonce, request.nonce);
  assert.strictEqual(response.hostPublicKeyHex, 'host-ed25519-public-key-hex');
  assert.strictEqual(response.attestation.packageId, 'paizo/pathfinder-2e-core');
  assert.strictEqual(response.attestation.recipientPeerId, 'peer-player-valeros');

  // Step 4: Peer validates host signature locally and mounts compendium in client memory
  const mounted = peer.processHandshakeResponse(response, 'host-ed25519-public-key-hex');
  assert.strictEqual(mounted.packageId, 'paizo/pathfinder-2e-core');
  assert.strictEqual(mounted.contentDigest, 'sha256:1122334455667788');
  assert.ok(peer.isPackageMounted('paizo/pathfinder-2e-core'));
  assert.deepStrictEqual(peer.mountedPackageIds(), ['paizo/pathfinder-2e-core']);

  // Unmount
  assert.strictEqual(peer.unmountPackage('paizo/pathfinder-2e-core'), true);
  assert.strictEqual(peer.isPackageMounted('paizo/pathfinder-2e-core'), false);
});

test('Dynamic Scopes: Host shields restricted GM content and peer gatekeeps assets', () => {
  const policy = new ScopePolicy({
    allowedScopes: ['spells', 'classes', 'items'],
    restrictedScopes: ['gm_notes', 'monsters', 'adventures'],
  });

  const host = new TableSessionManager({
    sessionId: 'session-table-scoped',
    hostPeerId: 'host-pubkey',
    packageId: 'paizo/core',
    contentDigest: 'sha256:core-digest',
    scopePolicy: policy,
  });

  const peer = new PeerSessionClient('peer-player-kyra');
  const request = peer.createAccessRequest('paizo/core');

  // Player asks for spells, but also attempts to request gm_notes and monsters
  const response = host.handleAccessRequest(request, true, [
    'spells',
    'gm_notes',
    'monsters',
  ]);

  // Host policy should have filtered out gm_notes and monsters
  assert.ok(response.attestation.permittedScopes.includes('spells'));
  assert.ok(!response.attestation.permittedScopes.includes('gm_notes'));
  assert.ok(!response.attestation.permittedScopes.includes('monsters'));

  peer.processHandshakeResponse(response);

  // Peer scope checks
  assert.strictEqual(peer.allowsScope('paizo/core', 'spells'), true);
  assert.strictEqual(peer.allowsScope('paizo/core', 'gm_notes'), false);

  // Peer asset path gatekeeping
  assert.strictEqual(peer.allowsAssetPath('paizo/core', 'spells/heal.json'), true);
  assert.strictEqual(peer.allowsAssetPath('paizo/core', 'gm_notes/secrets.md'), false);
  assert.strictEqual(peer.allowsAssetPath('paizo/core', 'monsters/dragon.json'), false);

  assert.doesNotThrow(() => peer.checkAssetAccess('paizo/core', 'spells/heal.json'));
  assert.throws(
    () => peer.checkAssetAccess('paizo/core', 'gm_notes/secrets.md'),
    /\[KRYP-703\]/
  );

  const filtered = peer.filterAccessibleAssets('paizo/core', [
    'spells/heal.json',
    'gm_notes/secret_plan.md',
    'monsters/goblin.json',
  ]);
  assert.deepStrictEqual(filtered, ['spells/heal.json']);
});

test('Session Renewal: Peer requests renewal and extends memory expiration', () => {
  const host = new TableSessionManager({
    sessionId: 'session-renewal',
    hostPeerId: 'host-key',
    packageId: 'paizo/rules',
    contentDigest: 'sha256:digest',
    sessionDurationMinutes: 60,
  });

  const peer = new PeerSessionClient('peer-player-ezren');
  const req = peer.createAccessRequest('paizo/rules');
  const resp = host.handleAccessRequest(req, true);
  peer.processHandshakeResponse(resp, 'host-key');

  const initialExpiry = peer.getMountedSession('paizo/rules')?.expiresAt;
  assert.ok(initialExpiry);

  // Renewal
  const renewalReq = peer.createRenewalRequest('paizo/rules');
  assert.strictEqual(renewalReq.sessionId, 'session-renewal');
  assert.strictEqual(renewalReq.packageId, 'paizo/rules');

  const renewalResp = host.handleRenewalRequest(renewalReq, 180);
  const renewedSession = peer.processRenewalResponse(renewalResp, 'host-key');

  assert.ok(new Date(renewedSession.expiresAt) >= new Date(initialExpiry));
  assert.strictEqual(peer.isPackageMounted('paizo/rules'), true);
});

test('Session Revocation: Host revokes peer and client memory is purged', () => {
  const host = new TableSessionManager({
    sessionId: 'session-revoke',
    hostPeerId: 'host-key',
    packageId: 'paizo/spells',
    contentDigest: 'sha256:spells',
  });

  const peer = new PeerSessionClient('peer-player-lem');
  const req = peer.createAccessRequest('paizo/spells');
  const resp = host.handleAccessRequest(req, true);
  peer.processHandshakeResponse(resp, 'host-key');
  assert.strictEqual(peer.isPackageMounted('paizo/spells'), true);

  // Host revokes player
  const notice = host.revokePeer('peer-player-lem', 'paizo/spells', 'Player disconnected');
  assert.strictEqual(host.isPeerRevoked('peer-player-lem', 'paizo/spells'), true);

  // Peer processes notice
  const purged = peer.processRevocationNotice(notice, 'host-key');
  assert.strictEqual(purged, 1);
  assert.strictEqual(peer.isPackageMounted('paizo/spells'), false);
  assert.strictEqual(peer.getMountedSession('paizo/spells'), undefined);

  // Host rejects renewed access request from revoked peer
  const reReq = peer.createAccessRequest('paizo/spells');
  assert.throws(
    () => host.handleAccessRequest(reReq, true),
    /\[KRYP-703\]/
  );
});

test('Peer Handshake: Host rejects request when lacking entitlement', () => {
  const host = new TableSessionManager({
    sessionId: 'session-table-xyz',
    hostPeerId: 'host-pubkey',
    packageId: 'paizo/licensed-core',
    contentDigest: 'sha256:aaaa',
  });

  const peer = new PeerSessionClient('peer-player-seoni');
  const request = peer.createAccessRequest('paizo/unowned-module');

  assert.throws(
    () => host.handleAccessRequest(request, false),
    /\[KRYP-603\]/
  );
});

test('Peer Handshake: Peer rejects mismatched nonce replay or recipient', () => {
  const host = new TableSessionManager({
    sessionId: 'session-table-xyz',
    hostPeerId: 'host-pubkey',
    packageId: 'paizo/core',
    contentDigest: 'sha256:bbbb',
  });

  const peer = new PeerSessionClient('peer-player-amiri');
  const request = peer.createAccessRequest('paizo/core');
  const response = host.handleAccessRequest(request, true);

  // Mismatch nonce
  const tamperedResponse = {
    ...response,
    nonce: 'tampered-nonce-replay',
  };

  assert.throws(
    () => peer.processHandshakeResponse(tamperedResponse),
    /\[KRYP-402\]/
  );

  // Mismatch recipient
  const wrongRecipientResponse = {
    ...response,
    attestation: {
      ...response.attestation,
      recipientPeerId: 'other-player',
    },
  };

  assert.throws(
    () => peer.processHandshakeResponse(wrongRecipientResponse),
    /\[KRYP-703\]/
  );
});
