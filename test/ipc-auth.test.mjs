import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { signWorkerMessage, verifyWorkerMessage } from '../desktop/ipc-auth.mjs';

test('worker IPC messages require a valid HMAC and reject tampering', () => {
  const key = crypto.randomBytes(32).toString('base64');
  const signed = signWorkerMessage({ kind:'request',id:'x',action:'scan.start',payload:{mode:'quick'} },key);
  assert.deepEqual(verifyWorkerMessage(signed,key),{kind:'request',id:'x',action:'scan.start',payload:{mode:'quick'}});
  assert.equal(verifyWorkerMessage({...signed,action:'service.shutdown'},key),null);
  assert.equal(verifyWorkerMessage(signed,crypto.randomBytes(32).toString('base64')),null);
  assert.equal(verifyWorkerMessage({kind:'request'},key),null);
});

