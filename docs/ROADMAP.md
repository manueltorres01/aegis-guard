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

## 0.6.0 — Behavioral detection and local EDR

- Process trees and incident timelines.
- Correlate file, process, registry, service, scheduled-task and startup persistence events.
- Detect common fileless, credential-access, injection and defense-evasion behavior.
- MITRE ATT&CK technique labels and explainable correlation rules.
- Response actions: terminate a process, remove confirmed persistence, quarantine related artifacts and export an investigation bundle.

## 0.7.0 — Enforced network and web protection

- Promote validated malicious-domain/IP rules from audit to reversible block mode.
- Phishing, malicious-download and command-and-control protection.
- Windows Firewall integration with transactional rule changes and rollback.
- Emergency full/selective network isolation with essential-service safeguards.
- Detect anomalous outbound repetition, port scans and probable exfiltration without claiming upstream DDoS mitigation.

## 0.8.0 — Device and exposure management

- USB/removable-media scan and device-control policies.
- Inventory vulnerable or obsolete applications and unsafe Windows settings.
- Application-control policies with certificate/hash indicators and expiring exceptions.
- Optional camera/microphone access visibility.
- Multi-device policy and reporting foundations for business deployments.

## 0.9.0 — Product self-protection and managed intelligence

- Anti-tamper controls for the service, configuration, definitions and quarantine.
- Privacy-preserving reputation with explicit opt-in and documented retention.
- Signed update channels, staged rollout, automatic rollback and recovery mode.
- Administrative roles, policy locking and audit trails.
- Accessibility, localization, support diagnostics and performance budgets.
- SBOM generation, dependency monitoring and a documented vulnerability-response process.

## 0.9.5 — Release-candidate validation

- Large benign/malicious corpus evaluation with published detection and false-positive methodology.
- Long-running stability, resource, race-condition and recovery testing.
- Fuzzing for parsers, archives, IPC and quarantine metadata.
- Independent security assessment and remediation of findings.
- Authenticode-signed installer/binaries, timestamp verification and reproducible release evidence.
- Final privacy policy, EULA/licensing review, support process and incident-response plan.

## 1.0.0 — Commercial readiness gate

1. No unresolved critical/high audit findings.
2. Signed installer, binaries, definitions and updates with tested rollback.
3. Independently reviewed quarantine, service, IPC and update threat models.
4. Measured false-positive, detection, performance and recovery results against defined release thresholds.
5. Clear product scope: Aegis may be marketed as primary endpoint protection only when its always-on prevention and recovery layers meet those thresholds; otherwise it remains an explicitly complementary scanner.
6. Supported upgrade/uninstall paths that preserve or safely export quarantine and reports.
7. Operational monitoring, security-contact, vulnerability-disclosure and customer-support readiness.
