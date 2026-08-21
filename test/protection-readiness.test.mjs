import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectProtectionReadiness } from '../src/protection-readiness.mjs';

test('replacement readiness keeps Defender enabled while critical gates are missing', () => {
  const report = inspectProtectionReadiness({ now: '2026-08-21T00:00:00.000Z' });
  assert.equal(report.ready, false);
  assert.equal(report.canReplaceDefender, false);
  assert.equal(report.keepDefenderEnabled, true);
  assert.equal(report.productMode, 'complementary-scanner');
  assert.ok(report.blockers.includes('nativeWindowsService'));
  assert.ok(report.blockers.includes('independentAudit'));
});

test('readiness becomes a candidate only when every gate has explicit evidence', () => {
  const signals = Object.fromEntries([
    'portableEngine', 'quarantineRecovery', 'signedInstaller', 'signedDefinitions',
    'nativeWindowsService', 'realtimeTelemetry', 'performanceEvidence',
    'detectionCorpus', 'independentAudit', 'incidentSupport'
  ].map(id => [id, true]));
  const report = inspectProtectionReadiness({ signals, now: '2026-08-21T00:00:00.000Z' });
  assert.equal(report.ready, true);
  assert.equal(report.canReplaceDefender, true);
  assert.equal(report.keepDefenderEnabled, false);
  assert.deepEqual(report.blockers, []);
});
