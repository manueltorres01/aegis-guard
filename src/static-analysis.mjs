import path from 'node:path';

const PE_SIGNATURE = 0x00004550;
const MAX_PE_SECTIONS = 96;
const MAX_ARCHIVE_ENTRIES = 20_000;
const MAX_ARCHIVE_UNCOMPRESSED = 2 * 1024 * 1024 * 1024;
const MAX_COMPRESSION_RATIO = 250;
const SCRIPT_EXTENSIONS = new Set(['.ps1', '.vbs', '.js', '.jse', '.bat', '.cmd', '.hta']);
const ZIP_EXTENSIONS = new Set(['.zip', '.docx', '.xlsx', '.pptx', '.jar']);

export function analyzeStaticContent({ file, head, tail = head }) {
  const extension = path.extname(file).toLowerCase();
  const analysis = { format: 'unknown', findings: [], metadata: {} };
  if (isPe(head)) analyzePe(head, analysis);
  if (ZIP_EXTENSIONS.has(extension) || isZip(head)) analyzeZip(tail, analysis);
  else if (extension === '.7z' && head.subarray(0, 6).equals(Buffer.from('377abcaf271c', 'hex'))) analysis.format = '7z';
  else if (extension === '.rar' && (head.subarray(0, 7).equals(Buffer.from('526172211a0700', 'hex')) || head.subarray(0, 8).equals(Buffer.from('526172211a070100', 'hex')))) analysis.format = 'rar';
  else if (extension === '.msi' && head.subarray(0, 8).equals(Buffer.from('d0cf11e0a1b11ae1', 'hex'))) analysis.format = 'msi';
  if (SCRIPT_EXTENSIONS.has(extension)) analyzeScript(head, analysis);
  if (['.doc', '.xls', '.ppt'].includes(extension)) analyzeLegacyOffice(head, analysis);
  return analysis;
}

function isPe(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 0x40 || buffer.readUInt16LE(0) !== 0x5a4d) return false;
  const offset = buffer.readUInt32LE(0x3c);
  return offset <= buffer.length - 24 && buffer.readUInt32LE(offset) === PE_SIGNATURE;
}

function isZip(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 4 && [0x04034b50, 0x06054b50, 0x08074b50].includes(buffer.readUInt32LE(0));
}

function analyzePe(buffer, analysis) {
  analysis.format = 'pe';
  const peOffset = buffer.readUInt32LE(0x3c);
  const coff = peOffset + 4;
  const machine = buffer.readUInt16LE(coff);
  const sectionCount = buffer.readUInt16LE(coff + 2);
  const optionalSize = buffer.readUInt16LE(coff + 16);
  const characteristics = buffer.readUInt16LE(coff + 18);
  const optional = coff + 20;
  const magic = optionalSize >= 2 && optional + optionalSize <= buffer.length ? buffer.readUInt16LE(optional) : 0;
  const entryPoint = optionalSize >= 20 ? buffer.readUInt32LE(optional + 16) : 0;
  analysis.metadata.pe = { machine, sectionCount, entryPoint, dll: Boolean(characteristics & 0x2000), sections: [] };

  if (sectionCount === 0 || sectionCount > MAX_PE_SECTIONS) {
    add(analysis, 'static.pe.sections-invalid', 'PE section count is structurally invalid', 35);
    return;
  }
  if (![0x10b, 0x20b].includes(magic)) add(analysis, 'static.pe.optional-header', 'PE optional header is missing or invalid', 35);
  const table = optional + optionalSize;
  if (table + sectionCount * 40 > buffer.length) {
    add(analysis, 'static.pe.section-table', 'PE section table is truncated', 30);
    return;
  }

  let entrySection = null;
  let executableWritable = 0;
  const ranges = [];
  for (let index = 0; index < sectionCount; index++) {
    const offset = table + index * 40;
    const name = buffer.subarray(offset, offset + 8).toString('ascii').replace(/\0.*$/, '');
    const virtualSize = buffer.readUInt32LE(offset + 8);
    const virtualAddress = buffer.readUInt32LE(offset + 12);
    const rawSize = buffer.readUInt32LE(offset + 16);
    const rawOffset = buffer.readUInt32LE(offset + 20);
    const flags = buffer.readUInt32LE(offset + 36);
    const section = { name, virtualAddress, virtualSize, rawOffset, rawSize, executable: Boolean(flags & 0x20000000), writable: Boolean(flags & 0x80000000) };
    analysis.metadata.pe.sections.push(section);
    if (section.executable && section.writable) executableWritable++;
    if (entryPoint >= virtualAddress && entryPoint < virtualAddress + Math.max(virtualSize, rawSize)) entrySection = section;
    if (rawSize && rawOffset) ranges.push([rawOffset, rawOffset + rawSize]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  if (ranges.some((range, index) => index > 0 && range[0] < ranges[index - 1][1])) add(analysis, 'static.pe.overlapping-sections', 'PE contains overlapping raw sections', 28);
  if (executableWritable) add(analysis, 'static.pe.rwx-section', 'PE contains a writable and executable section', 22);
  if (entryPoint && !entrySection) add(analysis, 'static.pe.entry-point', 'PE entry point is outside declared sections', 35);
  if (entrySection?.writable) add(analysis, 'static.pe.writable-entry', 'PE entry point is located in a writable section', 18);
  analyzeImports(buffer, optional, magic, analysis);
}

function analyzeImports(buffer, optional, magic, analysis) {
  const directoryBase = optional + (magic === 0x20b ? 112 : 96);
  if (directoryBase + 16 > buffer.length) return;
  const importRva = buffer.readUInt32LE(directoryBase + 8);
  if (!importRva) return;
  const sections = analysis.metadata.pe.sections;
  const importOffset = rvaToOffset(importRva, sections);
  if (importOffset === null || importOffset >= buffer.length) return;
  const imports = [];
  for (let cursor = importOffset, count = 0; cursor + 20 <= buffer.length && count < 512; cursor += 20, count++) {
    const nameRva = buffer.readUInt32LE(cursor + 12);
    const thunk = buffer.readUInt32LE(cursor) || buffer.readUInt32LE(cursor + 16);
    if (!nameRva && !thunk) break;
    const nameOffset = rvaToOffset(nameRva, sections);
    if (nameOffset !== null) {
      const name = readCString(buffer, nameOffset, 260);
      if (name) imports.push(name.toLowerCase());
    }
  }
  analysis.metadata.pe.imports = imports;
}

function analyzeZip(buffer, analysis) {
  analysis.format = analysis.format === 'pe' ? analysis.format : 'zip';
  let entries = 0;
  let totalCompressed = 0;
  let totalUncompressed = 0;
  let macros = false;
  let nestedExecutables = 0;
  for (let offset = 0; offset + 46 <= buffer.length;) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) { offset++; continue; }
    const compressed = buffer.readUInt32LE(offset + 20);
    const uncompressed = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const end = offset + 46 + nameLength + extraLength + commentLength;
    if (end > buffer.length) break;
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString('utf8').toLowerCase();
    entries++;
    totalCompressed += compressed;
    totalUncompressed += uncompressed;
    if (/(^|\/)vbaproject\.bin$/.test(name)) macros = true;
    if (/\.(?:exe|dll|scr|com|ps1|vbs|js|jse|bat|cmd|hta)$/i.test(name)) nestedExecutables++;
    offset = end;
  }
  analysis.metadata.archive = { entries, totalCompressed, totalUncompressed, nestedExecutables };
  if (entries > MAX_ARCHIVE_ENTRIES || totalUncompressed > MAX_ARCHIVE_UNCOMPRESSED) add(analysis, 'static.archive.limit', 'Archive metadata exceeds safe inspection limits', 30);
  if (totalCompressed > 0 && totalUncompressed / totalCompressed > MAX_COMPRESSION_RATIO) add(analysis, 'static.archive.ratio', 'Archive has an extreme declared compression ratio', 35);
  if (macros) add(analysis, 'static.office.macro', 'Office container includes a VBA macro project', 25);
  if (nestedExecutables >= 10) add(analysis, 'static.archive.executables', 'Archive contains an unusual number of executable entries', 18);
}

function analyzeScript(buffer, analysis) {
  analysis.format = 'script';
  const text = buffer.toString('utf8');
  const longEncoded = text.match(/[A-Za-z0-9+/]{600,}={0,2}/g)?.length ?? 0;
  const escapes = text.match(/(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|`[A-Za-z])/gi)?.length ?? 0;
  const dynamic = (text.match(/(?:eval|invoke-expression|frombase64string)\s*\(/gi) ?? []).length;
  if (longEncoded && dynamic) add(analysis, 'static.script.obfuscation', 'Script combines a long encoded payload with dynamic execution', 40);
  else if (escapes >= 25 && dynamic) add(analysis, 'static.script.escapes', 'Script combines heavy escaping with dynamic execution', 28);
}

function analyzeLegacyOffice(buffer, analysis) {
  if (buffer.length < 8 || !buffer.subarray(0, 8).equals(Buffer.from('d0cf11e0a1b11ae1', 'hex'))) return;
  analysis.format = 'ole';
  const folded = buffer.toString('latin1').toLowerCase();
  if (folded.includes('vba') && /(?:autoopen|document_open|workbook_open)/i.test(folded)) add(analysis, 'static.office.legacy-macro', 'Legacy Office document contains VBA auto-execution indicators', 35);
}

function rvaToOffset(rva, sections) {
  for (const section of sections) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) return section.rawOffset + (rva - section.virtualAddress);
  }
  return null;
}

function readCString(buffer, offset, maximum) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= buffer.length) return '';
  const end = Math.min(buffer.length, offset + maximum);
  let cursor = offset;
  while (cursor < end && buffer[cursor] !== 0) cursor++;
  return buffer.subarray(offset, cursor).toString('ascii').replace(/[^\x20-\x7e]/g, '');
}

function add(analysis, id, description, score) {
  analysis.findings.push({ id, description, score });
}
