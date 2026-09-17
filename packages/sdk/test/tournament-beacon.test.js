import test from 'node:test';
import assert from 'node:assert';
import { AirGappedTableBeacon } from '../dist/beacon.js';
import { TournamentCheckInManager } from '../dist/tournament.js';

test('AirGappedTableBeacon: lifecycle, state, and connected peers', () => {
  const beacon = new AirGappedTableBeacon({
    sessionId: 'session-table-test-1',
    tableName: 'Crown of the Kobold King',
    campaignPackageIds: ['paizo/player-core', 'paizo/gm-core'],
  });

  assert.strictEqual(beacon.getState().isActive, false);

  const state = beacon.start();
  assert.strictEqual(state.isActive, true);
  assert.strictEqual(state.sessionId, 'session-table-test-1');
  assert.strictEqual(state.tableName, 'Crown of the Kobold King');
  assert.strictEqual(state.advertisedService, '_kryptotome-table._tcp');

  const handshake = beacon.handlePeerHandshake({
    peerId: 'peer-table-55',
    packageId: 'paizo/player-core',
    presentationProof: 'zkp:proof:paizo/player-core:nonce999',
    timestamp: new Date().toISOString(),
  });

  assert.strictEqual(handshake.accessGranted, true);
  assert.strictEqual(handshake.peerId, 'peer-table-55');
  assert.strictEqual(beacon.getConnectedPeerCount(), 1);
  assert.ok(handshake.latencyMs < 10, `Handshake latency ${handshake.latencyMs}ms must be < 10ms`);

  assert.strictEqual(beacon.stop(), true);
  assert.strictEqual(beacon.getState().isActive, false);
  assert.strictEqual(beacon.getConnectedPeerCount(), 0);
});

test('AirGappedTableBeacon: rejects unentitled packages and invalid proofs', () => {
  const beacon = new AirGappedTableBeacon({
    sessionId: 'session-table-restricted',
    campaignPackageIds: ['paizo/player-core'],
  });
  beacon.start();

  assert.throws(
    () =>
      beacon.handlePeerHandshake({
        peerId: 'peer-rogue',
        packageId: 'forbidden/restricted-tome',
        presentationProof: 'zkp:proof:nonce1',
        timestamp: new Date().toISOString(),
      }),
    /Package "forbidden\/restricted-tome" not entitled/
  );

  assert.throws(
    () =>
      beacon.handlePeerHandshake({
        peerId: 'peer-rogue',
        packageId: 'paizo/player-core',
        presentationProof: 'invalid-plain-proof',
        timestamp: new Date().toISOString(),
      }),
    /Invalid zero-knowledge presentation proof format/
  );
});

test('TournamentCheckInManager: generates and verifies tickets in < 10ms with zero PII', () => {
  const ticket = TournamentCheckInManager.generateTicket({
    tournamentId: 'PFS-GENCON-2026-ROUND-1',
    system: 'PF2E',
    characterName: 'Valeros of Andoran',
    characterBuildHash: 'c4e3b2a198765432...',
    verifiedFeatsCount: 18,
    requiredPackages: ['paizo/player-core'],
    holderCommitment: 'urn:kryptotome:commitment:73ab9900',
  });

  assert.ok(ticket.presentationProof.startsWith('zkp:tourney:'));
  assert.strictEqual(ticket.tournamentId, 'PFS-GENCON-2026-ROUND-1');

  // Fast verify in < 10ms
  const result = TournamentCheckInManager.verifyTicket(ticket);
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(result.characterName, 'Valeros of Andoran');
  assert.strictEqual(result.verifiedFeatsCount, 18);
  assert.strictEqual(result.containsPii, false, 'Must contain zero PII');
  assert.ok(result.latencyMs < 10, `Check-in latency ${result.latencyMs}ms must be < 10ms`);
});

test('TournamentCheckInManager: QR string roundtrip encoding and decoding', () => {
  const ticket = TournamentCheckInManager.generateTicket({
    tournamentId: 'AL-PAIZOCON-2026',
    system: 'PF2E',
    characterName: 'Seoni the Sorceress',
    characterBuildHash: 'f8e7d6...',
    verifiedFeatsCount: 22,
    requiredPackages: ['paizo/player-core', 'paizo/gm-core'],
    holderCommitment: 'urn:kryptotome:commitment:112233',
  });

  const qrStr = TournamentCheckInManager.encodeQrString(ticket);
  assert.ok(qrStr.startsWith('KRYP:TOURNEY:'));

  const decoded = TournamentCheckInManager.decodeQrString(qrStr);
  assert.strictEqual(decoded.tournamentId, 'AL-PAIZOCON-2026');
  assert.strictEqual(decoded.characterName, 'Seoni the Sorceress');
  assert.strictEqual(decoded.verifiedFeatsCount, 22);

  const result = TournamentCheckInManager.verifyTicket(decoded);
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(result.containsPii, false);
});
