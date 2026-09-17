import test from 'node:test';
import assert from 'node:assert';
import { WebVttServiceWorker } from '../dist/service-worker.js';
import { Roll20Injector } from '../dist/roll20.js';
import { AlchemyInjector } from '../dist/alchemy.js';


// Setup minimal mock DOM environment for content script tests
class MockElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.id = '';
    this.className = '';
    this.children = [];
    this.innerHTML = '';
    this.style = {};
    this.attributes = new Map();
  }

  setAttribute(name, val) {
    this.attributes.set(name, val);
  }

  getAttribute(name) {
    return this.attributes.get(name);
  }

  prepend(el) {
    this.children.unshift(el);
  }

  appendChild(el) {
    this.children.push(el);
  }

  querySelector(selector) {
    if (selector.startsWith('#')) {
      const id = selector.slice(1);
      return this.id === id ? this : this.children.find((c) => c.id === id) || null;
    }
    if (selector.startsWith('.')) {
      const cls = selector.slice(1);
      return this.className.includes(cls) ? this : this.children.find((c) => c.className.includes(cls)) || null;
    }
    return null;
  }

  querySelectorAll(selector) {
    const results = [];
    if (selector.startsWith('.')) {
      const cls = selector.slice(1);
      if (this.className.includes(cls)) results.push(this);
      for (const c of this.children) {
        if (c.className?.includes(cls)) results.push(c);
      }
    }
    return results;
  }
}

class MockDocument {
  constructor() {
    this.body = new MockElement('body');
    this.elements = new Map();
  }

  createElement(tagName) {
    return new MockElement(tagName);
  }

  getElementById(id) {
    return this.elements.get(id) || null;
  }

  registerElement(id, el) {
    el.id = id;
    this.elements.set(id, el);
  }

  querySelector(selector) {
    return this.body.querySelector(selector);
  }
}

test('Web VTT Service Worker: getVaultStatus reports connected state and package library', async () => {
  const worker = new WebVttServiceWorker();
  const status = await worker.getVaultStatus();

  assert.strictEqual(status.connected, true);
  assert.ok(status.vaultAddress);
  assert.strictEqual(status.unlockedPackages.length, 2);
  assert.strictEqual(status.unlockedPackages[0].packageId, 'open-rpg/core-spells');
});

test('Web VTT Service Worker: generateProofForChallenge produces valid cached ZK proof', async () => {
  const worker = new WebVttServiceWorker();
  const pkgId = 'open-rpg/core-spells';
  const nonce = 'nonce-test-12345';

  const p1 = await worker.generateProofForChallenge(pkgId, nonce);
  assert.ok(p1.proofBytes.startsWith('zkp:webrtc:'));
  assert.strictEqual(p1.challengeNonce, nonce);

  // Second call with same nonce returns cached proof
  const p2 = await worker.generateProofForChallenge(pkgId, nonce);
  assert.strictEqual(p1.proofBytes, p2.proofBytes);
});

test('Web VTT Service Worker: queryCompendiumRecords searches verified spells and feats', async () => {
  const worker = new WebVttServiceWorker();
  const allRecords = await worker.queryCompendiumRecords();
  assert.ok(allRecords.length >= 3);

  const fireballSearch = await worker.queryCompendiumRecords('Fireball');
  assert.strictEqual(fireballSearch.length, 1);
  assert.strictEqual(fireballSearch[0].name, 'Fireball');
  assert.strictEqual(fireballSearch[0].data.level, 3);

  const featSearch = await worker.queryCompendiumRecords('War Caster');
  assert.strictEqual(featSearch.length, 1);
  assert.strictEqual(featSearch[0].type, 'feat');
});

test('Roll20Injector: injectSpellToSheet generates verified repeating section row', () => {
  const mockDoc = new MockDocument();
  const spellsContainer = mockDoc.createElement('div');
  spellsContainer.className = 'spells-container';
  mockDoc.body.appendChild(spellsContainer);

  const injector = new Roll20Injector();
  const row = injector.injectSpellToSheet(mockDoc, {
    name: 'Fireball',
    level: 3,
    school: 'Evocation',
    castingTime: '1 action',
    range: '150 feet',
    duration: 'Instantaneous',
    description: 'A bright streak flashes...',
  });

  assert.ok(row.className.includes('kryptotome-injected-spell'));
  assert.strictEqual(row.getAttribute('data-kryptotome-id'), 'fireball');
  assert.ok(row.innerHTML.includes('Fireball'));
  assert.ok(row.innerHTML.includes('Lvl 3 Evocation'));
  assert.ok(row.innerHTML.includes('ZK Proof'));
});

test('AlchemyInjector: createAlchemyCard creates card with ZK verified badge', () => {
  // Use mock document for createElement
  const origDoc = globalThis.document;
  globalThis.document = new MockDocument();

  try {
    const injector = new AlchemyInjector();
    const card = injector.createAlchemyCard({
      title: 'Shield of Faith',
      category: 'spell',
      subtitle: 'Level 1 Abjuration',
      body: 'A shimmering field appears...',
      tags: ['Abjuration', 'Cleric'],
    });

    assert.ok(card.className.includes('kryptotome-alchemy-card'));
    assert.ok(card.innerHTML.includes('Shield of Faith'));
    assert.ok(card.innerHTML.includes('Level 1 Abjuration'));
    assert.ok(card.innerHTML.includes('Proof #4b2277'));
  } finally {
    globalThis.document = origDoc;
  }
});
