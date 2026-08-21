import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { validateDefinitions, verifySignedDefinitionEnvelope } from '../src/definition-security.mjs';

const definitions = { version: 4, generatedAt: '2026-08-20T00:00:00.000Z', sha256: {}, puaSha256: {}, patterns: [] };

test('validates the bounded definition schema', () => {
  assert.equal(validateDefinitions(definitions), definitions);
  assert.throws(() => validateDefinitions({ ...definitions, sha256: { bad: 'x' } }), /hash/);
});
test('accepts an Ed25519-signed definition bundle and rejects rollback or tampering', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const payload = Buffer.from(JSON.stringify(definitions));
  const envelope = {
    keyId: 'release-1',
    payloadBase64: payload.toString('base64'),
    signatureBase64: crypto.sign(null, payload, privateKey).toString('base64')
  };
  const options = { publicKeys: { 'release-1': publicKey.export({ type: 'spki', format: 'pem' }) }, minimumVersion: 4 };
  assert.equal(verifySignedDefinitionEnvelope(envelope, options).version, 4);
  assert.throws(() => verifySignedDefinitionEnvelope(envelope, { ...options, minimumVersion: 5 }), /rollback/);
  const tampered = { ...envelope, payloadBase64: Buffer.from(JSON.stringify({ ...definitions, version: 5 })).toString('base64') };
  assert.throws(() => verifySignedDefinitionEnvelope(tampered, options), /signature/);
});

