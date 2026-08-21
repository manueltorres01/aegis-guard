# Aegis Guard

Aegis Guard is an auditable malware-scanning MVP for Windows with both a command-line engine and a modern desktop interface. It combines exact signatures with explainable heuristics and moves detected files into authenticated encrypted quarantine instead of permanently deleting them.

> [!WARNING]
> Aegis Guard is experimental. It is not a replacement for Microsoft Defender or another supported endpoint security product. Never disable existing protection to test it, and never use an experimental scanner as the only response to a suspected infection.

## Highlights

- SHA-256, encoded literal and constrained YARA-compatible hex signatures
- Explainable detection scoring
- Heuristics for disguised executables, suspicious scripts, macro auto-execution, ransomware commands and packed files
- Bounded PE structural analysis, ZIP/Office metadata inspection and separate PUA classification
- Authenticode publisher, chain/revocation evidence, timestamp identity and application provenance
- Optional ransomware audit for rapid changes, deletions, appended extensions and identifiable canary documents
- On-demand local EDR audit for bounded process trees, startup persistence, scheduled tasks, services and explainable MITRE ATT&CK correlations
- Read-only network anomaly indicators plus an explicit, reversible Windows Firewall action for validated IP indicators
- Read-only exposure inventory for removable volumes, installed applications, Windows defensive settings and camera/microphone consent
- Release-time SHA-256 integrity audit for security components, with local audit trail and JSON/CSV evidence
- Resource-bounded scanning with identity-aware session caching, coalesced watcher queues and measured performance diagnostics
- Concurrent directory scanning with safe exclusions and symbolic-link avoidance
- Modern Spanish desktop dashboard with light, dark and system themes
- Cancelable scans with discovery and scanning progress
- Sandboxed Electron renderer, validated IPC and an isolated utility process
- AES-256-GCM quarantine with integrity verification and no-overwrite restoration
- Manual quarantine by opaque result identifiers; the renderer never supplies destructive paths
- Real-time directory monitoring on supported Node.js/Windows versions
- Machine-readable JSON reports and automation-friendly exit codes
- A completely harmless built-in malware simulation
- Linux headless analysis preview with explicit platform capabilities and limitations
- Replacement-readiness report that keeps Defender enabled until every security gate is evidenced
- Dependency-free core engine; Electron is only required for the desktop application

## Requirements

- Windows 10 or 11 for the desktop application and Windows-native audits
- Ubuntu LTS is the initial Linux CLI/audit-preview baseline; no real-time enforcement is claimed
- Node.js 20 or later for the CLI; Node.js 24 LTS is recommended for desktop builds
- Microsoft Defender should remain enabled

## Quick start

```powershell
git clone https://github.com/manueltorres01/aegis-guard.git
cd aegis-guard
npm ci
npm test
npm run demo
```

The demo creates a plain-text simulation in the operating system's temporary directory, detects it, encrypts it and moves it into quarantine. It contains no executable code, persistence, network behavior or system modifications.

## Desktop interface

The interface includes **Inicio**, **Analizar**, **Protección**, **Red**, **Incidentes**, **Resultados**, **Cuarentena** and **Ajustes**. It deliberately says “Sin amenazas detectadas por Aegis” instead of claiming that the whole computer is protected. Folder monitoring continues in the user session when the window is hidden to the Windows tray. **Incidentes** is an on-demand, read-only audit snapshot; it does not terminate processes or remove persistence.

Review the interface without Electron or access to real files:

```powershell
npm run ui:preview
```

Open `http://127.0.0.1:4173/?preview=1`. Preview mode uses in-memory example data and is never enabled in the packaged `aegis://` application URL.

Before running the real desktop shell, install the pinned desktop toolchain:

```powershell
npm install --save-exact electron-updater@6.8.9
npm install --save-dev --save-exact electron@43.4.0 electron-builder@26.15.7
npm run desktop
```

The desktop renderer has no Node.js access, cannot navigate to remote content and exposes only a small allowlisted API. File and folder choices are made through native Windows dialogs and become opaque IDs that expire after ten minutes and are consumed on their first use; the target is revalidated before access. Scans, monitoring and quarantine run in a separate Electron utility process so heavy work does not freeze the window.

Desktop quarantine, settings and activity live under the per-user application-data directory. In a packaged Windows build, the master key is protected with Windows DPAPI through Electron `safeStorage`; the application fails closed if secure storage is unavailable. Automatic quarantine is disabled by default, and detections can be isolated manually after confirmation.

Each desktop session starts with protection for the Windows **Downloads** folder active. Browser partial files ending in `.crdownload` or `.part` are ignored until they receive their final name; stable `.tmp`, `.partial` and `.download` files are not excluded merely by suffix. Once eligible, a watched regular file is read exhaustively in chunks without Quick scan's 128 MiB cap. Pausing protection also pauses any manually selected folder monitor, but does not cancel a scan that is already running; the pause is deliberately session-only and protection starts active again after relaunch. **Launch at startup** is applied only by the packaged application, not by the development shell or UI preview.

Desktop scan modes have deliberately different scope: **Quick** scans regular files only at the top level of Downloads, **Deep** recursively scans one natively selected file or folder, and **Full** streams accessible regular files on the ready, local lettered drives Windows enumerates. Deep and Full include hidden items and do not impose a file-count or file-size cutoff, but they never follow symbolic links, junctions or other reparse points. The quarantine vault, complete-report store and exactly registered active staging files are excluded; unrelated files under Aegis's data directory remain in scope. Full scans can take a long time; Windows may deny protected paths, which are counted separately while accessible content continues. If Windows cannot enumerate the drive set, Full fails explicitly and never silently degrades to scanning only `C:`. See [docs/DESKTOP-USAGE.md](docs/DESKTOP-USAGE.md) for exact behavior and reporting limits.

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

On the Linux preview, inspect the detected distribution and the capabilities that are actually available:

```bash
npm run platform:linux
```

The preview reuses the portable scanner and encrypted quarantine, but it does not install a systemd service, use fanotify/eBPF or block traffic.

There is also an isolated Android UI prototype in [android-test/README.md](android-test/README.md). It is a safe, simulated interface only; it does not scan device storage or replace Android security.

To see whether Aegis is ready to replace Defender, run:

```bash
npm run protection:readiness
```

The command is intentionally conservative: the current result is `complementary-scanner` and explicitly keeps Defender enabled.

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

Each finding adds an explainable score. A score of 60 or more is classified as `malicious`; 25–59 is `suspicious`; lower scores are `clean`. Script-content rules apply only to script formats; PE files require the complete configured API group before receiving the process-injection heuristic. On Windows, suspicious PE-like files can be enriched with Authenticode status. A valid signature from an explicitly configured publisher can neutralize only low-confidence entropy/API-reference findings; it never overrides an exact malware signature or script behavior, and names or paths alone are never trusted. Only `malicious` results are automatically quarantined when explicitly enabled. Thresholds, trusted publisher organizations, Quick-scan maximum file size, concurrency and Quick/CLI exclusions live in `config/default.json`; Deep and Full scans use streaming reads without that size or name-based exclusion policy.

The engine never executes scanned content. Test literals are Base64-encoded in the repository so the definitions file does not detect itself. Base64 is not treated as a security boundary; it only avoids accidental self-matches.

## Safe testing

```powershell
npm run ci
npm run demo
```

The automated suite covers EICAR recognition, benign content, hidden and deeply nested files, disappearing and inaccessible paths, link avoidance, scan-scope boundaries, progress, cancellation, full-drive aggregation, session-only protection pause, temporary-download exclusion, startup-setting persistence, encrypted quarantine, authenticated metadata, restoration, no-overwrite behavior and self-detection prevention. Do not add live malware to this repository. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules.

## Windows installer and updates

The supported distribution format is a signed, per-user NSIS installer—not a portable executable. Once a real Authenticode identity is configured:

```powershell
npm run dist:win
```

For local smoke testing only, `npm run dist:win:unsigned` overrides the production signing requirement. Never publish that unsigned output. Application updates use signed GitHub Release assets and require an explicit **Reiniciar y actualizar** action. Definition updates use the 0.10.0/0.11.0 Ed25519 envelope, manual import, minimum-version check and bounded rollback path; the default public-key trust store remains empty until a release key is provisioned. The repository now includes a serverless GitHub Actions collector that refreshes MalwareBazaar/ThreatFox hashes into `feeds/definitions.bundle.json`; it uses Actions secrets, never ships provider credentials and requires no Aegis server. Before packaging, `npm run release:readiness` validates the local release gates and `npm run sbom` creates an SPDX inventory from the locked dependencies. Until those secrets are provisioned, `npm run definitions:keygen` and `npm run definitions:bundle` exercise the same signed update path locally without contacting an external provider. See [docs/DESKTOP-BUILD.md](docs/DESKTOP-BUILD.md) for exact release and signing steps.

## Suspect a real infection?

Disconnect the machine from untrusted networks, avoid entering passwords, keep Defender enabled, and run Microsoft Defender Offline from Windows Security. Use a separate trusted device to rotate important credentials if compromise is plausible. Aegis can provide a second opinion, but its output alone is not proof that a machine is clean. See [docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md).

## Current limitations

Aegis does not yet include a signed Windows minifilter driver, background Windows service, AMSI/ETW sensors, complete Authenticode reputation, archive unpacking, NTFS alternate-data-stream scanning, behavioral sandboxing or a signed anti-tamper root of trust. Linux support is currently a headless analysis/audit preview for an Ubuntu LTS baseline; it has no systemd service, fanotify/eBPF telemetry, network enforcement or Windows-equivalent real-time prevention. The daily signed intelligence collector exists but remains disabled until its public key, GitHub secrets and provider access are provisioned. Its optional reputation layer sends only an exact SHA-256 after explicit consent and uses CIRCL context plus opt-in abuse.ch providers; it does not upload files, use VirusTotal as a backend or turn an external “known file” result into a clean verdict. Its 0.7.0 network control is limited to explicit, reversible IP rules in Windows Firewall; it does not inspect URLs, isolate the whole host or mitigate volumetric DDoS attacks. The 0.8.0 exposure inventory is an on-demand, read-only snapshot: it does not block USB, uninstall applications, provide CVE/reputation verdicts from a version alone or intercept camera/microphone use. The 0.9.0 integrity audit detects differences against a release-time local manifest but does not repair or block tampering. It does not inspect files stored inside archives, and its safe root confinement deliberately avoids reparse points and mount-only targets. Quick scans intentionally skip files larger than 128 MiB; protection remains active while the packaged app is hidden in the tray and stops only when the user exits Aegis, signs out or shuts down Windows. A forced process or system shutdown during isolation or restore can leave a recoverable staging file; a later Deep or Full scan treats an unregistered leftover as ordinary content rather than silently excluding it. High entropy and scripting patterns can have legitimate uses, so suspicious findings require human review.

## Roadmap

Version 0.13.0 adds a replacement-readiness gate on top of the Linux portability foundation. It remains separate from the Windows desktop and does not claim Linux real-time protection or permission to disable Defender. The ordered security and commercialization plan through 1.0.0 is maintained in [docs/ROADMAP.md](docs/ROADMAP.md).

## Security and contributing

Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities and [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Never open a public issue containing live malware, credentials or personal data.

## License

MIT — see [LICENSE](LICENSE).
