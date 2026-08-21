import test from 'node:test';
import assert from 'node:assert/strict';
import { NetworkProtector } from '../src/network-protection.mjs';

test('network protector applies only validated IP rules and keeps domains pending', async () => {
  const calls = [];
  const protector = new NetworkProtector({ runner: async request => { calls.push(request); return { Applied: 2, Rules: ['rule-a', 'rule-b'] }; }, now: () => new Date('2026-08-20T10:00:00.000Z') });
  const result = await protector.apply({ ips: ['203.0.113.10', '203.0.113.10', 'bad-value', '2001:db8::1'], domains: ['bad.example', '*.c2.example'] });
  assert.equal(calls[0].operation, 'apply');
  assert.deepEqual(calls[0].addresses, ['203.0.113.10', '2001:db8::1']);
  assert.equal(result.active, true);
  assert.equal(result.addressesBlocked, 2);
  assert.equal(result.domainsPending, 2);
  assert.equal(result.reversible, true);
});

test('network protector rollback removes only its own group and reports failures', async () => {
  const calls = [];
  const protector = new NetworkProtector({ runner: async request => { calls.push(request); if (request.operation === 'remove') throw new Error('access denied'); return { Applied: 1, Rules: ['rule-a'] }; } });
  await protector.apply({ ips: ['198.51.100.8'] });
  const result = await protector.remove();
  assert.equal(calls[1].operation, 'remove');
  assert.equal(result.active, true);
  assert.match(result.error, /access denied/i);
  assert.equal(result.group, 'Aegis Guard 0.7.0 Indicators');
});

test('reapplying an empty indicator set clears the owned rules state', async () => {
  const calls = [];
  const protector = new NetworkProtector({ runner: async request => { calls.push(request); return request.addresses.length ? { Applied: 1, Rules: ['rule-a'] } : { Applied: 0, Rules: [] }; } });
  await protector.apply({ ips: ['203.0.113.7'] });
  const cleared = await protector.apply({ ips: [] });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1].addresses, []);
  assert.equal(cleared.active, false);
  assert.equal(cleared.addressesBlocked, 0);
});
