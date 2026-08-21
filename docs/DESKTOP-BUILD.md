# Desktop builds and releases

This document defines the supported Windows packaging and update path for the
Aegis Guard desktop application. The downloadable artifact is a normal NSIS
installer (`.exe`), not a portable executable or a web installer.

## Supported toolchain

The versions selected on 18 August 2026 are:

| Component | Pinned version | Package role |
| --- | ---: | --- |
| Electron | `43.4.0` | Development dependency |
| electron-builder | `26.15.7` | Development dependency |
| electron-updater | `6.8.9` | Production dependency |
| Node.js | 24 LTS | Local and CI build runtime |

Install the packages with exact versions and commit the resulting lockfile:

```powershell
npm install --save-exact electron-updater@6.8.9
npm install --save-dev --save-exact electron@43.4.0 electron-builder@26.15.7
```

Do not replace these with alpha, beta, nightly, or unpinned versions in a
release build. Re-check the official stable releases immediately before the
first public build and on every Electron security upgrade. Electron ships its
own Node.js runtime, so end users do not need to install Node.js.

The `package.json` entry point must resolve to the desktop main process before
packaging. Keep `electron-updater` in `dependencies`; electron-builder and
Electron belong in `devDependencies`.

## Package layout

[`../electron-builder.yml`](../electron-builder.yml) deliberately packages only
the desktop code, scanner engine, configuration, definitions, and production
dependencies. Tests, repository automation, and documentation are not runtime
application files.

The production target is:

- Windows x64.
- A full offline NSIS installer.
- Per-user installation without elevation.
- Assisted setup (`oneClick: false`).
- ASAR packaging with embedded integrity validation.

Do not change `appId` after the first public installer. electron-builder derives
the NSIS application identity from it; changing it can break upgrades and
uninstallation. Do not add an `ia32` target. Electron 44 removes Windows 32-bit
artifacts, so x64 is the forward-compatible baseline. A separately tested
ARM64 target can be added later.

The user downloads one file named like:

```text
Aegis-Guard-Setup-0.2.0-x64.exe
```

The installed application contains the Electron runtime and supporting files.
The `portable` target is not a substitute for this installer because it is not
an auto-updatable Windows target. Do not use Squirrel.Windows, MSI, `nsis-web`,
or the portable target for the primary release channel.

## Writable data

Packaged application files and `app.asar` are read-only. The desktop main
process must read bundled configuration and definitions through the packaged
application path, and it must store mutable state elsewhere.

Quarantine data, its key, preferences, and logs must live under a dedicated
per-user application-data directory. Never derive the quarantine directory
from the source tree or `app.asar`. Updates must preserve this directory, and
the NSIS configuration intentionally does not delete application data during
uninstall. Any UI action that purges quarantine must be explicit and separately
confirmed.

On Windows, protect the local quarantine key with Electron `safeStorage` after
the app is ready. The asynchronous safe-storage API is preferred. This uses
Windows DPAPI and protects the key from other Windows accounts, although it
does not protect against another malicious process already running as the same
user.

## Local packaging

Production configuration fails closed when no signing identity is available:

```yaml
forceCodeSigning: true
```

That is intentional. An unsigned local smoke build may temporarily override
the setting, but it must never be uploaded, distributed, or used to validate
the production updater:

```powershell
npm exec -- electron-builder --config electron-builder.yml --win nsis --x64 --publish never -c.forceCodeSigning=false
```

The `dist:win` and `dist:win:unsigned` scripts generate the 0.9.0
release-time integrity manifest automatically. If electron-builder is invoked
directly, run this first:

```powershell
npm run integrity:manifest
```

## Daily signed definition feed

The desktop client must not poll abuse.ch or another intelligence provider
directly. A maintainer/CI job should fetch the licensed upstream data, review
and normalize the indicators, then generate the same signed envelope used by
the local importer:

```powershell
npm run definitions:bundle -- --key-id release-2026 --private-key C:\secure\aegis-definition-release.pem --input .\definitions\signatures.json --output .\dist\definitions.bundle.json
```

Publish that envelope at a stable HTTPS URL and provision the matching public
key in `config/definition-keys.json`. The packaged client keeps the feed off by
default; a release-specific `config/definition-feed.json` can enable it:

For local development, the key pair can be created without paying for a
certificate or a provider. Keep the private key outside the repository and
write only the public trust file into the checkout:

```powershell
npm run definitions:keygen -- --key-id local-dev --private-key "$env:USERPROFILE\.aegis-guard\definition-release-private.pem" --public-config .\config\definition-keys.json
```

Use the resulting private key only with the bundle command. This is suitable
for local testing, not for a public release: a production key must be held in
an offline or protected CI secret and rotated under a documented ceremony.

```json
{
  "schemaVersion": 1,
  "enabled": true,
  "url": "https://updates.example.com/aegis/definitions.bundle.json",
  "intervalHours": 24,
  "timeoutMs": 8000,
  "maxBackoffHours": 72
}
```

The updater performs at most one conditional request per day, sends no API
credentials, enforces HTTPS and a 16 MiB response limit, caches `ETag` and
`Last-Modified`, and backs off after failures. A `304 Not Modified` response
does not download or validate a second copy. Every changed package is still
verified by the Ed25519 trust store, version floor and rollback logic before
the scanner adopts it. Keep the endpoint behind a CDN/object store with
immutable versioned artifacts and a small stable pointer; do not put private
signing keys or abuse.ch Auth-Keys in the application package.

### Serverless daily collection with GitHub Actions

This repository includes `.github/workflows/definitions-feed.yml`. It runs
once per day (and can be started manually), queries only metadata from
MalwareBazaar and ThreatFox, merges hashes with the reviewed local definitions,
removes expired entries, signs the result with Ed25519 and commits it to
`feeds/definitions.bundle.json`. GitHub hosts the static file, so no Aegis
server or database needs to be operated.

Before enabling the workflow:

1. Generate a key pair and commit only the public key:

   ```powershell
   npm run definitions:keygen -- --key-id github-actions-2026 --private-key "$env:USERPROFILE\.aegis-guard\definition-release-private.pem" --public-config .\config\definition-keys.json
   ```

2. In the repository settings, create these Actions secrets:
   `AEGIS_DEFINITION_KEY_ID` (the key ID above), `AEGIS_DEFINITION_PRIVATE_KEY`
   (the complete PEM file) and `AEGIS_ABUSECH_AUTH_KEY` (the free abuse.ch
   Auth-Key). The private key and Auth-Key are used only inside the runner and
   are never sent to desktop clients.

3. Run **Actions → Daily signed threat-intelligence feed → Run workflow** once
   and confirm that `feeds/definitions.bundle.json` appears. The client feed
   URL for this repository is:

   ```text
   https://raw.githubusercontent.com/manueltorres01/aegis-guard/main/feeds/definitions.bundle.json
   ```

   Enable it only in a release configuration after the public key has been
   reviewed:

   ```json
   {"schemaVersion":1,"enabled":true,"url":"https://raw.githubusercontent.com/manueltorres01/aegis-guard/main/feeds/definitions.bundle.json","intervalHours":24,"timeoutMs":8000,"maxBackoffHours":72}
   ```

The community APIs are free under fair-use rules but may require an enhanced
commercial plan when Aegis is sold. Scheduled GitHub jobs can be delayed and
are disabled after 60 days without repository activity, so the workflow also
supports manual runs and the desktop updater refuses to treat an unavailable
feed as a clean result.

### Release readiness and SBOM

Before creating a public installer, run:

```powershell
npm run ci
npm run release:readiness
npm run sbom
```

`release:readiness` writes `dist/release-readiness.json` and blocks a strict
release when the package/lock versions differ, the feed is enabled without a
trusted public key, the collector workflow is missing or a private key file
has been left in the project tree. It reports the GitHub secrets as an
unverifiable external prerequisite rather than pretending they exist locally.
`sbom` writes an SPDX 2.3 inventory of the exact `package-lock.json` graph to
`dist/aegis-guard-<version>.spdx.json`; set `SOURCE_DATE_EPOCH` in CI when a
stable creation timestamp is required.

The signed production build is created with:

```powershell
npm exec -- electron-builder --config electron-builder.yml --win nsis --x64 --publish never
```

Run unit tests before packaging and smoke-test the installed application, not
only the unpacked development build. In particular, verify folder selection,
scan cancellation, quarantine persistence, restore behavior, and clean exit
while a downloaded update is waiting.

## Windows code signing

Every public installer and executable must be Authenticode-signed with a
publicly trusted RSA/SHA-256 code-signing identity and an RFC 3161 timestamp.
Self-signed certificates are suitable only for controlled development systems.

The build configuration intentionally contains no `publisherName`: the exact
publisher is not known until a real certificate has been issued. Never invent
this value. When a certificate is selected, use its exact subject/Common Name
where the signing provider requires it. Keep the same publisher identity across
releases so that Windows reputation and updater signature validation remain
stable.

For a conventional certificate, provide credentials only through the build
environment or protected CI secrets:

```text
WIN_CSC_LINK
WIN_CSC_KEY_PASSWORD
```

`WIN_CSC_LINK` may reference the protected certificate material supported by
electron-builder. Never commit a PFX file, certificate password, Azure secret,
or signing token. Azure Artifact Signing can instead be configured with
`win.azureSignOptions` after the real account, endpoint, profile, and publisher
name exist; those values are intentionally absent from the shared config.

Before promoting a release, verify both the application and installer:

```powershell
Get-AuthenticodeSignature .\dist\Aegis-Guard-Setup-*-x64.exe |
  Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid`, the signer must be the expected publisher, and the
timestamp must be present. The release process must fail instead of publishing
if signing is missing or invalid. Code signing proves origin and integrity; it
does not guarantee that SmartScreen will immediately have reputation for a new
publisher or file.

## Auto-update behavior

Windows auto-update is provided by `electron-updater` and the regular NSIS
target. electron-builder writes the provider configuration into the packaged
application and generates release metadata such as `latest.yml` and the NSIS
blockmap. Do not call `setFeedURL()` in application code.

With electron-updater 6.8.9, configure the updater in the main process with the
following production policy:

```js
autoUpdater.allowPrerelease = false
autoUpdater.allowDowngrade = false
autoUpdater.disableWebInstaller = true
autoUpdater.autoInstallOnAppQuit = false
```

Only check for updates when `app.isPackaged` is true. The updater may download
an update in the background, but the UI must present an explicit “Restart and
update” action after the `update-downloaded` event. Do not install while a scan,
quarantine, or restore operation is active. After all mutable state has been
flushed, electron-updater 6 uses:

```js
autoUpdater.quitAndInstall(false, true)
```

Disabling automatic installation on an arbitrary app quit avoids starting the
NSIS replacement process during Windows shutdown or logoff. When
electron-updater 7 becomes stable, reassess its `autoInstallEvent` /
`onNextLaunch` flow. Version 7 changes `quitAndInstall` to an options object, so
do not adopt its examples while the project remains on 6.8.9.

Do not disable Windows update-signature verification. The SHA-512 value in
`latest.yml` detects a corrupt or mismatched download, while Authenticode
validates the publisher. Metadata, installer, and blockmap must always come
from the same build.

Application auto-update does not make an unsigned remote
`definitions/signatures.json` trustworthy. The 0.10.0 definitions protocol
accepts only an Ed25519-signed envelope with a provisioned public key, writes
it outside the packaged application, rejects rollback versions and keeps a
bounded previous bundle. The default trust store is empty until the release
key ceremony is complete, so the signed application still ships with its
bundled definitions. Never update definitions from a raw branch URL.

Create a release bundle without putting the private key in the repository:

```text
npm run definitions:bundle -- --key-id release-2026 --private-key C:\secure\aegis-definition-release.pem --input definitions\signatures.json --output dist\definitions.bundle.json
```

The maintainer must provision only the matching public key in
`config/definition-keys.json`; private keys belong in an offline or protected
release environment. The desktop import action validates the envelope before
activating it and exposes a rollback action when a previous bundle exists.

## Threat-intelligence lookups

The reputation layer is deliberately opt-in and hash-only. CIRCL Hash Lookup
is enabled in `config/threat-intel.json` because its public service does not
require an API key. MalwareBazaar and ThreatFox are disabled until an operator
has reviewed the abuse.ch terms and configured both the provider flags and the
`AEGIS_ABUSECH_AUTH_KEY` environment variable in the worker environment. The
key is never written to settings, reports or the repository.

For a controlled manual test:

```text
npm run intel:lookup -- <sha256>
npm run intel:lookup -- <sha256> --offline
```

This sends only the supplied SHA-256 when online. It does not upload samples,
download malware or turn a known-file match into a clean verdict. The desktop
button is blocked until the user enables **Permitir consultas de reputación**.

## GitHub Releases publishing

The configured provider is the public repository:

```text
https://github.com/manueltorres01/aegis-guard
```

Publishing requires a token in the build environment:

```text
GH_TOKEN
```

`GH_TOKEN` is a publisher credential only. Never place it in
`electron-builder.yml`, package it in the application, write it to logs, or ask
end users to create one. Installed clients need no token to read public GitHub
Releases. The repository's `.github/workflows/cd.yml` maps the short-lived
`GITHUB_TOKEN` to `GH_TOKEN` only in the signed release job. Its job-level
permission is `contents: write`; the default workflow permission remains
`contents: read`. Protect the `release` environment with approval and store
`WIN_CSC_LINK` and `WIN_CSC_KEY_PASSWORD` there, never in the repository.

To upload a signed build to a draft release:

```powershell
npm exec -- electron-builder --config electron-builder.yml --win nsis --x64 --publish always
```

electron-builder is configured with `releaseType: draft`. Draft releases are
invisible to normal updater clients. Review all assets and validation results,
then publish the draft manually. A release must contain at least the signed
installer, its blockmap, and `latest.yml` generated together.

Use semantic versions and require an exact match:

```text
package.json version: 0.11.0
Git tag:              v0.11.0
GitHub Release:       v0.11.0
```

Enable GitHub immutable releases before the first public release. The safe
sequence is: create draft, upload every asset, verify, then publish. Once
published, the tag and assets cannot be replaced. If a release is defective,
publish a higher version; never overwrite an existing installer or reuse its
tag.

Immutable assets also mean a staged-rollout percentage in `latest.yml` cannot
be edited upward after publication. Prefer a separately tested prerelease/beta
cycle followed by an immutable stable release. Keep stable clients on
`allowPrerelease = false`.

## Release checklist

Before publishing a draft:

1. Confirm the version and `vX.Y.Z` tag match exactly.
2. Build from the protected release commit with the pinned lockfile and Node 24.
3. Run all tests and an installed-app smoke test.
4. Confirm the installer is per-user NSIS x64, not portable or `nsis-web`.
5. Verify valid Authenticode signatures and timestamps.
6. Verify the packaged Electron fuses and ASAR integrity settings.
7. Confirm the release contains matching installer, blockmap, and `latest.yml`.
8. Test an update from the previous installed version on a clean Windows VM.
9. Confirm quarantine survives the update and is not modified mid-operation.
10. Review the draft, then publish it; do not publish directly from an
    unreviewed pull request or unprotected branch.

The CD workflow runs only for a protected `vX.Y.Z` tag already contained in
`main`. It runs the full CI suite, builds with `forceCodeSigning: true`, checks
the Authenticode status and required `latest.yml`/blockmap, then creates a
draft GitHub Release. Review the draft and publish it manually after the
release checklist passes; unsigned builds are never uploaded by CD.
