# Aegis Guard roadmap to 1.0.0

This roadmap is ordered by dependency and risk. A version number is not a security claim: every blocking feature must first ship in audit mode, collect false-positive and performance evidence, and provide a reversible recovery path.

## 0.2.2 — Results, reports and trustworthy exceptions

- Results filters: **All**, **Suspicious**, **Not scanned** and **Malicious**.
- Native in-app download of complete JSON and spreadsheet-safe CSV reports.
- Streaming reports that include every scanned file without retaining an unbounded list in memory.
- Report evidence: paths, hashes, verdicts, scores, findings, actions, timestamps, scope, summary and Authenticode trust details.
- Verified application policies that require a valid signature, exact publisher and expected installation root. Initial locally validated policies cover Discord and FACEIT publishers.
- Restore quarantined files directly to their authenticated original path, with no-overwrite protection and no destination picker.

## 0.2.3 — Network visibility in audit mode

- Includes the complete 0.2.2 feature set.
- Attribute outbound destinations to the responsible process and its signature identity.
- Audit known-malicious domain/IP indicators with bounded local event retention.
- Explain every network event and allow report export.
- Read and report Windows Firewall and Microsoft Defender protection state without disabling or replacing either product.
- Explicitly avoid volumetric-DDoS claims; upstream DDoS mitigation belongs at the router, ISP, host or scrubbing/CDN provider.

Implementation note: the local indicator file intentionally ships empty until a signed, maintained intelligence update channel exists. Administrators can audit locally supplied indicators without Aegis presenting stale examples as current threat intelligence.

## 0.3.0 — Durable endpoint foundation

- User-session background agent and Windows tray so closing the UI does not stop protection; a true least-privilege Windows SCM service remains a post-0.3.0 hardening gate.
- HMAC-authenticated IPC protocol between the desktop broker and isolated scan worker.
- Scheduled Quick, Deep and Full scans with battery/CPU limits and game/silent modes.
- Reliable crash recovery for scans, reports, quarantine and updates.
- Event-log integration, health diagnostics and clear degraded-protection states.

Implementation boundary: 0.3.0 provides local diagnostics and recovery history but does not register an Event Log source or Windows service because doing either correctly requires an elevated, signed installation path and tested service ACL/upgrade design. These remain mandatory before commercial readiness.

## 0.4.0 — Deeper static detection

- Real PE parsing: imports, sections, resources, entry point and structural anomalies.
- Full Authenticode chain, timestamp, revocation and Windows catalog validation.
- Signed, rollback-safe definitions and YARA-compatible rules.
- Bounded archive/container inspection for ZIP, 7z, RAR and MSI with anti-zip-bomb limits.
- Office macro, script-obfuscation and NTFS alternate-data-stream inspection.
- Potentially unwanted application classification separate from malware.

Implementation boundary: 0.4.0 ships bounded PE structure/import parsing, ZIP central-directory and Office macro metadata, compound script-obfuscation checks, Authenticode chain/timestamp evidence, constrained YARA-compatible hex strings, signed-envelope/rollback primitives and separate PUA results. 7z, RAR and MSI are identified but their contents are not yet recursively decoded. General NTFS alternate-stream enumeration, production signing-key operations and remote signed-definition delivery remain hardening work; the UI and reports must not describe those files as fully inspected.

## 0.5.0 — Ransomware protection

- Controlled-folder protection introduced in audit mode.
- Detect high-rate encryption, rename, deletion and extension-change behavior.
- Canary documents and per-process write correlation.
- Block mode only after audit validation, with explicit allow rules based on identity rather than path alone.
- Bounded, encrypted recovery copies and tested rollback after a confirmed event.

Implementation boundary: 0.5.0 introduces an opt-in user-session audit for rapid distinct changes, high-rate disappearance, appended-extension rename correlation and identifiable canary tampering across Documents, Desktop and Pictures. Events are bounded, rate-limited, persisted and explicitly marked observed-only. Process attribution, block mode and encrypted pre-write recovery remain gated on signed native service/minifilter telemetry; the application must not claim those controls are active.

## 0.5.1 — Resource-efficient scanning

- Bounded session cache keyed by file identity, scan limits, definitions version and trust policy; changed files and policy changes always invalidate cached results.
- Coalesced and bounded real-time watcher queues with rate-limited capacity warnings and observable queue metrics.
- Lazy static-analysis buffers so ordinary files retain only a small probe while supported PE/script/archive formats keep their required evidence windows.
- Conservative scan concurrency capped by available parallelism, with per-scan cache/bytes/concurrency metrics in the report.
- Debounced, serialized background-state persistence so bursts of detections do not cause one disk write per event; shutdown flushes pending activity.
- Renderer result updates are batched into animation frames and use document fragments to avoid repeated layout work.

Implementation boundary: 0.5.1 optimizes work already performed by Aegis; it does not skip files, weaken signatures or replace Windows power/thermal policy. Cache entries are process-local and time-limited, errors and size-limited results are never cached, and the UI reports measurements rather than promising a fixed CPU or memory percentage across hardware.

## 0.6.0 — Behavioral detection and local EDR

- Process trees and incident timelines.
- Correlate file, process, registry, service, scheduled-task and startup persistence events.
- Detect common fileless, credential-access, injection and defense-evasion behavior.
- MITRE ATT&CK technique labels and explainable correlation rules.
- Response actions: terminate a process, remove confirmed persistence, quarantine related artifacts and export an investigation bundle.

Implementation boundary: 0.6.0 ships a bounded, on-demand Windows PowerShell snapshot of process trees, startup entries, Run/RunOnce keys, scheduled tasks and services. It correlates that snapshot with the existing network and ransomware audit history, labels explainable observations with MITRE ATT&CK identifiers and persists a JSON investigation report. It is not continuous ETW/native EDR telemetry: file-write authors remain unattributed, credential-access and injection claims are not made without stronger evidence, and process termination, persistence removal, automatic quarantine and blocking remain disabled until a signed least-privilege service and recovery tests exist.

## 0.7.0 — Enforced network and web protection

- Promote validated malicious-domain/IP rules from audit to reversible block mode.
- Phishing, malicious-download and command-and-control protection.
- Windows Firewall integration with transactional rule changes and rollback.
- Emergency full/selective network isolation with essential-service safeguards.
- Detect anomalous outbound repetition, port scans and probable exfiltration without claiming upstream DDoS mitigation.

Implementation boundary: 0.7.0 implements a bounded, read-only network audit with contextual anomaly labels and an explicit, reversible Windows Firewall action for validated IP indicators. The application stays in audit mode by default; the user must select **Bloqueo reversible** and press **Aplicar bloqueo**. Rules use the dedicated `Aegis Guard 0.7.0 Indicators` group and rollback removes only that group. Domains are reported as pending and are never resolved or blocked implicitly. Full network isolation, web/URL inspection, volumetric DDoS mitigation, automatic blocking and kernel-level traffic interception remain future work and must not be advertised as shipped capabilities.

## 0.8.0 — Device and exposure management

- Read-only inventory of removable volumes, installed applications, Windows Firewall/Defender/UAC/Secure Boot state and camera/microphone consent entries.
- Application policy foundations with local publisher/hash indicators and expiring exceptions; default mode remains audit-only.
- Complete JSON/CSV exposure reports without requiring users to browse the internal application data directory.
- Explicit limits: no USB blocking, application removal, CVE/reputation verdict or active camera/microphone interception is claimed in this version.
- Multi-device policy and reporting foundations remain a later managed-deployment milestone.

Implementation boundary: 0.8.0 is an on-demand local snapshot. It reports removable volumes that Windows exposes with drive letters, installed application metadata and defensive settings; it does not enumerate every raw USB device, infer vulnerability from a version alone, or modify Windows policy. Publisher/hash indicators and exceptions are validated and displayed as audit evidence only until a signed policy channel and recovery-tested enforcement service exist.

## 0.9.0 — Product self-protection and managed intelligence

- Bounded integrity audit for the service, configuration, definitions and quarantine decision path, with JSON/CSV evidence.
- Privacy-preserving reputation consent stored locally and disabled by default; no hash or path is uploaded by this release.
- Signed-update status, staged rollout metadata and recovery/rollback diagnostics remain explicit in the desktop update path.
- Activity history as a local audit trail, health diagnostics and performance evidence without pretending to be a kernel anti-tamper service.
- Accessibility/localization groundwork and a release-time integrity-manifest generator.
- SBOM and dependency/vulnerability-response documentation foundations.
- Local release-readiness checks and an SPDX SBOM generator for the exact locked dependency graph.

Implementation boundary: 0.9.0 detects modifications against a release-time local SHA-256 manifest, but the manifest is not yet a signed root of trust and Aegis does not repair or block tampering automatically. Reputation sharing is an opt-in consent record only; there is no remote reputation endpoint in this build. Signed update delivery remains available only to packaged builds with the configured publisher, while rollback and recovery are surfaced as state and diagnostics rather than guaranteed transactional restoration. A signed least-privilege service, policy locking and managed multi-user roles remain 0.9.5/1.0.0 gates.

## 0.9.5 — Release-candidate validation

- Large benign/malicious corpus evaluation with published detection and false-positive methodology.
- Long-running stability, resource, race-condition and recovery testing.
- Fuzzing for parsers, archives, IPC and quarantine metadata.
- Independent security assessment and remediation of findings.
- Authenticode-signed installer/binaries, timestamp verification and reproducible release evidence.
- Final privacy policy, EULA/licensing review, support process and incident-response plan.

## 0.10.0 — Signed definitions and reversible intelligence updates

- Ed25519-signed definition envelopes with a configured public-key trust store.
- Atomic local installation outside the packaged application, with minimum-version checks and bounded backups.
- Explicit manual import for the first release channel; the desktop UI must never fetch raw definitions from a branch or untrusted URL.
- Verified rollback to the bundled release or the immediately previous signed bundle, with cache invalidation and an activity entry.
- Release tooling to build bundles without placing private signing keys in the repository.

Implementation boundary: 0.10.0 provides the verified storage and rollback protocol plus a local import path. The packaged default trust store is empty until a release key is provisioned, and no remote feed, cloud reputation or automatic definition download is claimed until the key ceremony, feed hosting, update review and operational monitoring are ready.

## 0.11.0 — Local threat-intelligence cache and explicit reputation lookups

- Keep a bounded, expiring local cache of normalized hash lookups outside the packaged application.
- Query CIRCL Hash Lookup without an API key for known-file context; treat its trust score as evidence, never as a clean verdict.
- Add opt-in MalwareBazaar and ThreatFox adapters for confirmed malware/IOC matches when the operator supplies an abuse.ch Auth-Key.
- Send only an exact SHA-256 after explicit consent; never upload samples, paths, telemetry or arbitrary URLs.
- Expose a manual **Reputación** action in Resultados and a CLI lookup for testing; do not query every scanned file.
- Add an opt-in daily signed-definition feed: clients make one conditional HTTPS request every 24 hours, persist `ETag`/`Last-Modified`, apply exponential backoff after failures and pass every envelope through the existing Ed25519/rollback gate.
- Provide a serverless GitHub Actions collector that queries only metadata from MalwareBazaar and ThreatFox, retains hashes with explicit expiry, signs the normalized bundle and publishes it as a static repository asset; provider credentials remain runner-only.

Implementation boundary: this milestone is a reputation/enrichment layer plus the transport and serverless collector for a maintainer-signed feed, not a direct abuse.ch client in the desktop application. The default feed is disabled until a release key, HTTPS endpoint, review process and monitoring are provisioned. abuse.ch community APIs are subject to fair-use and commercial terms; VirusTotal public API is deliberately excluded from the product backend because its published terms prohibit commercial integration. The GitHub Action must ingest only metadata, generate the existing signed bundle and publish it; clients never receive abuse.ch credentials or samples.

Free development path: until a licensed feed is available, keep the remote feed
disabled, use CIRCL only for explicit hash context, and generate local Ed25519
bundles from the repository's reviewed definitions with `npm run
definitions:keygen` and `npm run definitions:bundle`. This exercises the complete
verification and rollback path without pretending that a free public lookup is
a complete malware database.

## Parallel Linux migration track — 0.10.x to 1.1.x

- Keep the scanning engine, definitions, reports, quarantine format and policy model portable through an OS adapter layer.
- Add Linux CI coverage and supported distribution targets before shipping a user-facing package; start with a documented Ubuntu LTS baseline rather than claiming every distribution.
- Ship a headless Linux scanner/CLI and a read-only desktop preview first, using native path, permissions, ELF and package-signature evidence instead of Windows-only Authenticode assumptions.
- Add a least-privilege systemd service and fanotify/inotify-backed real-time audit only after privilege separation, upgrade, uninstall and recovery tests are complete.
- Treat nftables/eBPF network controls, SELinux/AppArmor integration and broad distro packaging as separate hardening milestones.

Implementation boundary: the first Linux milestone can reuse the portable analysis, reporting and encrypted-quarantine layers, but it cannot claim Windows-equivalent real-time prevention. Linux support should initially be an analysis/audit preview with explicit distribution and kernel requirements; enforcement requires a reviewed native service and separate recovery tests.

## 1.0.0 — Commercial readiness gate

1. No unresolved critical/high audit findings.
2. Signed installer, binaries, definitions and updates with tested rollback.
3. Independently reviewed quarantine, service, IPC and update threat models.
4. Measured false-positive, detection, performance and recovery results against defined release thresholds.
5. Clear product scope: Aegis may be marketed as primary endpoint protection only when its always-on prevention and recovery layers meet those thresholds; otherwise it remains an explicitly complementary scanner.
6. Supported upgrade/uninstall paths that preserve or safely export quarantine and reports.
7. Operational monitoring, security-contact, vulnerability-disclosure and customer-support readiness.
