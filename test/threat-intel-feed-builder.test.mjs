import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  buildThreatIntelDefinitions,
  createSignedDefinitionEnvelope,
  fetchMalwareBazaar,
  fetchThreatFox
} from '../src/threat-intel-feed-builder.mjs';
import { verifySignedDefinitionEnvelope } from '../src/definition-security.mjs';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);
const HASH_OLD = 'd'.repeat(64);

test('feed builder merges confirmed exact hashes, retains provenance and expires old entries', () => {
  const base = { version: 3, generatedAt: '2026-08-20T00:00:00.000Z', sha256: {}, puaSha256: {}, patterns: [] };
  const previous = buildThreatIntelDefinitions({
    baseDefinitions: base,
    malwareBazaarPayload: { data: [
      { sha256_hash: HASH_A, signature: 'OldFamily', first_seen: '2026-01-01 00:00:00 UTC' },
      { sha256_hash: HASH_OLD, signature: 'ExpiredFamily', first_seen: '2026-01-01 00:00:00 UTC' }
    ] },
    generatedAt: '2026-01-02T00:00:00.000Z',
    version: 100,
    retentionDays: 30
  });
  const next = buildThreatIntelDefinitions({
    baseDefinitions: base,
    previousDefinitions: previous,
    malwareBazaarPayload: { data: [{ sha256_hash: HASH_A, signature: 'NewFamily', first_seen: '2026-08-20 00:00:00 UTC' }, { sha256_hash: 'not-a-hash' }] },
    threatFoxPayload: {
      data: [
        { confidence_level: 100, malware_printable: 'Dridex', malware_samples: [{ sha256_hash: HASH_B }] },
        { confidence_level: 20, ioc_type: 'sha256_hash', ioc: HASH_C }
      ]
    },
    generatedAt: '2026-08-21T00:00:00.000Z',
    retentionDays: 30
  });

  assert.equal(next.version, 101);
  assert.equal(next.sha256[HASH_A].includes('MalwareBazaar'), true);
  assert.equal(next.threatIntel.entries[HASH_A].providers.includes('malwarebazaar'), true);
  assert.equal(next.threatIntel.entries[HASH_A].families.includes('OldFamily'), true);
  assert.equal(next.sha256[HASH_B].includes('ThreatFox'), true);
  assert.equal(next.threatIntel.entries[HASH_C], undefined);
  assert.equal(next.threatIntel.entries[HASH_OLD], undefined);
  assert.equal(next.threatIntel.entries[HASH_A].families.includes('NewFamily'), true);
});

test('provider clients send metadata-only requests with the expected contracts', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, text: async () => JSON.stringify({ query_status: 'ok', data: [] }) };
  };
  await fetchMalwareBazaar({ authKey: 'test-key', fetchImpl, hours: 24 });
  await fetchThreatFox({ authKey: 'test-key', fetchImpl, days: 3 });
  assert.equal(calls.length, 2);
  assert.match(calls[0].url, /mb-api\.abuse\.ch/);
  assert.equal(calls[0].options.headers['Auth-Key'], 'test-key');
  assert.match(String(calls[0].options.body), /query=recent_detections/);
  assert.match(calls[1].url, /threatfox-api\.abuse\.ch/);
  assert.equal(JSON.parse(calls[1].options.body).query, 'get_iocs');
  assert.equal(JSON.parse(calls[1].options.body).days, 3);
});

test('feed envelope is Ed25519-verifiable by the desktop trust store', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const definitions = { version: 10, generatedAt: '2026-08-21T00:00:00.000Z', sha256: {}, puaSha256: {}, patterns: [] };
  const envelope = createSignedDefinitionEnvelope(definitions, { keyId: 'github-actions-test', privateKey });
  const verified = verifySignedDefinitionEnvelope(envelope, {
    publicKeys: { 'github-actions-test': publicKey.export({ type: 'spki', format: 'pem' }) }
  });
  assert.equal(verified.version, 10);
});
