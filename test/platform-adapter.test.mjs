import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultScanRoot, getPlatformProfile, isPortablePlatform, normalizePlatformPath } from '../src/platform-adapter.mjs';

test('Linux profile exposes the portable analysis preview without enforcement claims', () => {
  const profile = getPlatformProfile({ platform: 'linux', arch: 'x64', release: '6.8.0-test', homeDirectory: '/home/demo' });
  assert.equal(profile.family, 'linux');
  assert.equal(profile.mode, 'linux-analysis-preview');
  assert.equal(profile.defaultRoot, '/home/demo');
  assert.equal(profile.capabilities.portableScan, true);
  assert.equal(profile.capabilities.enforcement, false);
  assert.equal(profile.capabilities.realtimeAudit, false);
});

test('Windows path identity remains case-insensitive while Linux stays case-sensitive', () => {
  assert.equal(normalizePlatformPath('C:\\Users\\Demo\\File.DLL', { platform: 'win32' }), 'c:\\users\\demo\\file.dll');
  assert.equal(normalizePlatformPath('/Home/Demo/File.DLL', { platform: 'linux' }), '/Home/Demo/File.DLL');
});

test('portable platform helpers use an explicit supported set', () => {
  assert.equal(isPortablePlatform('win32'), true);
  assert.equal(isPortablePlatform('linux'), true);
  assert.equal(isPortablePlatform('darwin'), false);
  assert.equal(defaultScanRoot({ platform: 'linux', homeDirectory: '/home/test' }), '/home/test');
});
