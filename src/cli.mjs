#!/usr/bin/env node
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScanEngine } from './engine.mjs';
import { Quarantine } from './quarantine.mjs';
import { createHarmlessSimulation } from './simulator.mjs';
import { WatchService } from './watch-service.mjs';
import { formatBytes, loadJson } from './util.mjs';

const base = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const config = await loadJson(path.join(base, 'config', 'default.json'));
const definitions = await loadJson(path.join(base, 'definitions', 'signatures.json'));
const engine = new ScanEngine({ ...config, definitions });
const quarantine = new Quarantine(process.env.AEGIS_QUARANTINE || path.join(base, config.quarantineDirectory));
const [command = 'help', target = '.', ...flags] = process.argv.slice(2);
const json = flags.includes('--json');

function printResult(r) {
  if (json) return;
  const icon = r.verdict === 'malicious' ? 'THREAT' : r.verdict === 'suspicious' ? 'WARN' : r.verdict.toUpperCase();
  console.log(`[${icon}] ${r.path}${r.size != null ? ` (${formatBytes(r.size)})` : ''} score=${r.score}`);
  for (const finding of r.findings ?? []) console.log(`  - ${finding.description} (+${finding.score})`);
}

async function scan(targetPath, isolate, { updateExitCode = true } = {}) {
  const absolute = path.resolve(targetPath);
  const results = await engine.scanPath(absolute, { concurrency: config.concurrency, onResult: printResult });
  const quarantined = [];
  if (isolate) for (const result of results.filter(x => x.verdict === 'malicious')) {
    quarantined.push(await quarantine.isolate(result.path, result));
  }
  const summary = {
    scanned: results.length,
    malicious: results.filter(x => x.verdict === 'malicious').length,
    suspicious: results.filter(x => x.verdict === 'suspicious').length,
    errors: results.filter(x => x.verdict === 'error').length,
    quarantined: quarantined.length
  };
  if (json) console.log(JSON.stringify({ summary, results, quarantined }, null, 2));
  else console.log(`\nScanned ${summary.scanned}; threats ${summary.malicious}; suspicious ${summary.suspicious}; errors ${summary.errors}; quarantined ${summary.quarantined}.`);
  if (updateExitCode) process.exitCode = summary.malicious ? 2 : summary.errors ? 1 : 0;
  return { summary, results, quarantined };
}

async function watch(targetPath, autoQuarantine) {
  const root = path.resolve(targetPath);
  console.log(`Watching ${root}. Press Ctrl+C to stop.`);
  const service = new WatchService({
    engine,
    quarantine,
    emit: event => {
      if (event.type === 'monitor-result') {
        const result = event.payload.result;
        printResult(result);
        if (result.action === 'quarantined') console.log(`  Quarantined safely as ${result.quarantineId}.`);
        else if (result.verdict === 'malicious') {
          console.log('  Action required: run scan with --quarantine to isolate it.');
        }
      } else if (event.type === 'monitor-error' || event.type === 'monitor-warning') {
        console.warn(`Aegis monitor: ${event.payload.message}`);
      }
    }
  });
  await service.start(root, { autoQuarantine });
  process.once('SIGINT', () => { void service.stop(); });
}

try {
  if (command === 'scan') await scan(target, flags.includes('--quarantine'));
  else if (command === 'watch') await watch(target, flags.includes('--quarantine'));
  else if (command === 'demo') {
    const demoDirectory = target === '.' ? path.join(os.tmpdir(), 'aegis-guard-demo') : target;
    const sample = await createHarmlessSimulation(demoDirectory);
    console.log(`Created harmless simulation: ${sample}`);
    const report = await scan(sample, true, { updateExitCode: false });
    if (report.summary.quarantined !== 1) throw new Error('Demo failed: simulation was not quarantined');
    console.log('Demo passed: the simulation was detected and moved to encrypted quarantine.');
  }
  else if (command === 'quarantine' && target === 'list') console.log(JSON.stringify(await quarantine.list(), null, 2));
  else if (command === 'quarantine' && target === 'restore') {
    const id = flags[0];
    if (!id) throw new Error('Usage: quarantine restore <id> [destination]');
    console.log(`Restored to ${await quarantine.restore(id, flags[1])}`);
  } else {
    console.log(`Aegis Guard — defensive Windows scanner\n\nCommands:\n  demo [directory]\n  scan <path> [--quarantine] [--json]\n  watch <directory> [--quarantine]\n  quarantine list\n  quarantine restore <id> [destination]\n\nExit codes: 0 clean, 1 operational error, 2 threat detected.`);
  }
} catch (error) {
  console.error(`Aegis error: ${error.message}`);
  process.exitCode = 1;
}
