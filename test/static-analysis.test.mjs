import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeStaticContent } from '../src/static-analysis.mjs';

test('PE analysis reports structural anomalies with bounded metadata', () => {
  const pe = Buffer.alloc(512);
  pe.writeUInt16LE(0x5a4d, 0);
  pe.writeUInt32LE(0x80, 0x3c);
  pe.writeUInt32LE(0x00004550, 0x80);
  pe.writeUInt16LE(0x8664, 0x84);
  pe.writeUInt16LE(1, 0x86);
  pe.writeUInt16LE(0xf0, 0x94);
  pe.writeUInt16LE(0x20b, 0x98);
  pe.writeUInt32LE(0x5000, 0x98 + 16);
  const section = 0x98 + 0xf0;
  pe.write('.text', section, 'ascii');
  pe.writeUInt32LE(0x1000, section + 8);
  pe.writeUInt32LE(0x1000, section + 12);
  pe.writeUInt32LE(0x100, section + 16);
  pe.writeUInt32LE(0x200, section + 20);
  pe.writeUInt32LE(0xe0000020, section + 36);
  const result = analyzeStaticContent({ file: 'sample.exe', head: pe });
  assert.equal(result.format, 'pe');
  assert.ok(result.findings.some(item => item.id === 'static.pe.entry-point'));
  assert.ok(result.findings.some(item => item.id === 'static.pe.rwx-section'));
  assert.equal(result.metadata.pe.sections.length, 1);
});
test('ZIP metadata detects Office macros and extreme declared ratios without extraction', () => {
  const name = Buffer.from('word/vbaProject.bin');
  const entry = Buffer.alloc(46 + name.length);
  entry.writeUInt32LE(0x02014b50, 0);
  entry.writeUInt32LE(1, 20);
  entry.writeUInt32LE(1000, 24);
  entry.writeUInt16LE(name.length, 28);
  name.copy(entry, 46);
  const result = analyzeStaticContent({ file: 'macro.docx', head: Buffer.from('PK\x03\x04'), tail: entry });
  assert.ok(result.findings.some(item => item.id === 'static.office.macro'));
  assert.ok(result.findings.some(item => item.id === 'static.archive.ratio'));
});

test('script obfuscation requires encoded content and a dynamic execution primitive', () => {
  const benign = analyzeStaticContent({ file: 'normal.ps1', head: Buffer.from(`$text = '${'A'.repeat(700)}'`) });
  const suspicious = analyzeStaticContent({ file: 'dropper.ps1', head: Buffer.from(`Invoke-Expression([Text.Encoding]::UTF8.GetString('${'A'.repeat(700)}'))`) });
  assert.equal(benign.findings.length, 0);
  assert.ok(suspicious.findings.some(item => item.id === 'static.script.obfuscation'));
});
