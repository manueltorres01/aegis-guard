# Aegis Guard

Aegis Guard is an auditable, dependency-free malware scanning MVP for Windows. It combines exact signatures with explainable heuristics and moves detected files into authenticated encrypted quarantine instead of permanently deleting them.

> [!WARNING]
> Aegis Guard is experimental. It is not a replacement for Microsoft Defender or another supported endpoint security product. Never disable existing protection to test it, and never use an experimental scanner as the only response to a suspected infection.

## Highlights

- SHA-256 and encoded literal signatures
- Explainable detection scoring
- Heuristics for disguised executables, suspicious scripts, macro auto-execution, ransomware commands and packed files
- Concurrent directory scanning with safe exclusions and symbolic-link avoidance
- AES-256-GCM quarantine with integrity verification and no-overwrite restoration
- Real-time directory monitoring on supported Node.js/Windows versions
- Machine-readable JSON reports and automation-friendly exit codes
- A completely harmless built-in malware simulation
- Zero runtime dependencies

## Requirements

- Windows 10 or 11
- Node.js 20 or later
- Microsoft Defender should remain enabled

## Quick start

```powershell
git clone https://github.com/YOUR-USERNAME/aegis-guard.git
cd aegis-guard
npm ci
npm test
npm run demo
```

The demo creates a plain-text simulation in the operating system's temporary directory, detects it, encrypts it and moves it into quarantine. It contains no executable code, persistence, network behavior or system modifications.

## Usage

Analyze without changing files:

```powershell
node .\src\cli.mjs scan "$env:USERPROFILE\Downloads"
```

Automatically quarantine high-confidence detections:

```powershell
node .\src\cli.mjs scan "$env:USERPROFILE\Downloads" --quarantine
```

Monitor new and modified files, reporting only:

```powershell
node .\src\cli.mjs watch "$env:USERPROFILE\Downloads"
```

Monitor and automatically quarantine high-confidence detections:

```powershell
node .\src\cli.mjs watch "$env:USERPROFILE\Downloads" --quarantine
```

Use `Ctrl+C` to stop monitoring. For machine-readable scan output, add `--json`.

### Quarantine

```powershell
node .\src\cli.mjs quarantine list
node .\src\cli.mjs quarantine restore <id> [destination]
```

Quarantine is stored in `.aegis-quarantine` by default. Set `AEGIS_QUARANTINE` to use another directory. Items are encrypted with a locally generated AES-256-GCM key. Restoration checks both authentication and SHA-256 integrity and refuses to overwrite an existing file.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed without a high-confidence detection |
| `1` | Operational error |
| `2` | Threat detected |

## How detection works

Each finding adds an explainable score. A score of 60 or more is classified as `malicious`; 25–59 is `suspicious`; lower scores are `clean`. Only `malicious` results are automatically quarantined when explicitly enabled. Thresholds, maximum file size, concurrency and exclusions live in `config/default.json`.

The engine never executes scanned content. Test literals are Base64-encoded in the repository so the definitions file does not detect itself. Base64 is not treated as a security boundary; it only avoids accidental self-matches.

## Safe testing

```powershell
npm run ci
npm run demo
```

The automated suite covers EICAR recognition, benign content, the built-in simulation, encrypted quarantine, restoration and self-detection prevention. Do not add live malware to this repository. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules.

## Suspect a real infection?

Disconnect the machine from untrusted networks, avoid entering passwords, keep Defender enabled, and run Microsoft Defender Offline from Windows Security. Use a separate trusted device to rotate important credentials if compromise is plausible. Aegis can provide a second opinion, but its output alone is not proof that a machine is clean. See [docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md).

## Current limitations

Aegis does not yet include a signed Windows minifilter driver, Windows service isolation, AMSI/ETW sensors, Authenticode reputation, archive unpacking, cloud intelligence, behavioral sandboxing, anti-tamper controls or a continuously curated signature feed. High entropy and scripting patterns can have legitimate uses, so suspicious findings require human review.

## Roadmap

1. Signed and rollback-safe definition updates
2. PE parsing, Authenticode checks, archive scanning and YARA-compatible rules
3. Least-privilege Windows service with AMSI/ETW integration
4. Privacy-preserving reputation and behavioral correlation
5. Corpus evaluation, fuzzing, external audit and reproducible signed releases

## Security and contributing

Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities and [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Never open a public issue containing live malware, credentials or personal data.

## License

MIT — see [LICENSE](LICENSE).
