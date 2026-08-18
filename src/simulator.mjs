import fs from 'node:fs/promises';
import path from 'node:path';

// Kept encoded so scanning the Aegis source tree does not trigger its own marker.
const MARKER_BASE64 = 'QUVHSVMtR1VBUkQtSEFSTUxFU1MtU0lNVUxBVElPTi04RjFDMkE3RS1ETy1OT1QtRVhFQ1VURQ==';

export async function createHarmlessSimulation(directory) {
  const root = path.resolve(directory);
  await fs.mkdir(root, { recursive: true });
  const file = path.join(root, 'aegis-harmless-simulation.txt');
  const marker = Buffer.from(MARKER_BASE64, 'base64').toString('utf8');
  const content = [
    'Aegis Guard harmless malware simulation',
    'This text file contains no executable code and performs no actions.',
    `Detection marker: ${marker}`,
    ''
  ].join('\r\n');
  await fs.writeFile(file, content, { flag: 'wx' });
  return file;
}
