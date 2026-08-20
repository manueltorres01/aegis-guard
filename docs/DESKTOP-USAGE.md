# Desktop protection and scan behavior

This document describes the safety boundaries of the Aegis Guard desktop
application. Aegis is an experimental, on-demand second-opinion scanner. It
does not replace Microsoft Defender, a supported endpoint security product or
an incident-response process.

## Network audit (0.2.3)

The **Network** page takes a bounded, read-only snapshot of established or pending outbound TCP connections on Windows. It records the remote IP and port, correlates a domain only when the Windows DNS cache provides one, attributes the owning process, and records that executable's Authenticode publisher when accessible. It also reads the Windows Firewall profiles and Microsoft Defender status without changing either product.

Events are compared with `definitions/network-indicators.json`. The bundled list is intentionally empty until Aegis has a signed, maintained intelligence-update channel; matching an administrator-supplied local indicator produces a suspicious audit event, not an automatic block. The latest capture is retained with native JSON and spreadsheet-safe CSV export, and the UI is capped at 500 events.

This is endpoint visibility, not DDoS protection. A desktop application cannot absorb an upstream volumetric attack after the connection is saturated; that mitigation belongs at the router, ISP, hosting provider or scrubbing/CDN service.

## Protection for Downloads

Every new desktop session starts a watcher for the Windows **Downloads**
folder. New or changed files are scanned after they finish changing. The
watcher reports detections; it quarantines a malicious file automatically only
when **Automatic quarantine** is explicitly enabled.

Incomplete browser downloads ending in `.crdownload` or `.part` are ignored.
They are not treated as clean: once the browser gives a completed download its
final name, that final file is eligible for scanning. Those are the only
suffix-based deferrals: stable `.tmp`, `.partial` and `.download` files are
scanned, and paths under `.git` or `node_modules` are not excluded merely by
directory name. The quarantine vault and an operation's exactly registered
staging path remain the narrow safety exclusions.

An eligible stable regular file is hashed and pattern-matched exhaustively in
streaming chunks. The 128 MiB Quick-scan cutoff does not apply to Downloads or
manual-folder protection; large files can therefore take longer to inspect.

This protection runs in the Aegis user-session background process. Closing the window hides it in the Windows tray, so monitoring and enabled schedules continue; choosing **Salir y detener protección** from the tray ends it. It is not yet a Windows SCM service, file-system driver or system-wide interception layer. Signing out, shutting down Windows or explicitly exiting Aegis stops protection. Keep Microsoft Defender enabled.

## Scheduled scans and recovery (0.3.0)

Daily Quick or Full scans can be enabled in Settings and are disabled by default. Aegis can skip a scheduled run on battery; scans use bounded streaming concurrency and never start while another scan is active. Scheduling depends on Aegis running in the user session.

Before a scan starts, Aegis records a bounded operation journal. If the process or Windows stops unexpectedly, the next start clears the incomplete operation safely, records a recovery event and exposes degraded health for review. The broker/worker protocol uses a per-session 256-bit HMAC key and rejects altered or unauthenticated messages.

Quarantine offers **Ruta** to show the authenticated original location and **Restaurar** to return the file to that exact location. Restore never opens a destination selector and refuses to overwrite an existing file.

## Pause is session-only

**Pause protection** pauses both the automatic Downloads watcher and a manual
folder monitor. Resuming restores the manual folder that was active when the
pause began. If the user explicitly stops or removes that pending monitor while
paused, resuming does not recreate it. Pausing does not cancel an on-demand
Quick, Deep or Full scan that is already running.

The paused state is intentionally not written to settings. A newly launched
Aegis session starts unpaused and activates Downloads protection again. This
prevents an old, forgotten pause from silently carrying over after a restart.

## Launch at startup

The **Launch at startup** preference is stored across sessions and defaults to
enabled. Only the packaged Windows application applies it through the Windows
login-item mechanism; `npm run desktop` and the browser-based UI preview do not
register a startup entry. The installed application launches in the background
so Downloads protection can start without forcing the main window in front of
the user.

Windows and the user remain in control of startup applications. Disabling
Aegis in Windows Settings, uninstalling it or removing its startup entry means
it will not be running and Downloads protection will not be active.

## Scan modes and scope

### Quick

A Quick scan examines regular files directly inside the Windows **Downloads**
folder. It includes dotfiles and files carrying the Windows hidden attribute,
but it deliberately does not descend into subfolders. Configured Quick-scan
exclusions remain active, and files larger than 128 MiB are counted as
`skipped` rather than read. This bounded mode is useful for a fast check; it is
not a scan of every downloaded file in nested folders.

### Deep

A Deep scan accepts one file or folder chosen through the native Windows
dialog. The renderer receives an opaque target identifier, never a filesystem
path. The identifier expires after ten minutes and is consumed by the first
attempt to start a Deep scan; choosing the same target again produces a new
identifier. Before use, the main process revalidates the path, real path, type
and filesystem identity and rejects links or a target that changed after the
dialog closed. A selected folder is traversed recursively with no file-count
or file-size cutoff. Hidden files, dot-directories and directories whose names
are excluded from Quick scans are included.

Deep scan traversal remains confined to the selected root. Symbolic links,
Windows junctions and other reparse points are not followed, so they cannot
redirect the scan to a sibling or unrelated location. The canonical quarantine
vault, the internal complete-report directory and exactly registered staging
files belonging to an active isolate or restore operation are excluded. Other
files under Aegis's data directory are not broadly excluded. The legacy `custom` mode name is accepted for
compatibility but is normalized and reported as `deep`. Files are hashed in
full and pattern matching preserves overlap between streaming chunks,
including signatures that cross a chunk boundary.

The same ten-minute, one-use target rule applies when starting a manual folder
monitor. An expired, previously used, replaced or otherwise changed selection
must be chosen again; the renderer cannot turn an identifier back into an
arbitrary path.

### Full

A Full scan enumerates supported ready Windows drive-letter roots (fixed,
removable, optical and RAM drives) and combines them into one exact summary.
Mapped network/UNC roots and volumes available only through mount points are
out of scope. Like a Deep scan, it recursively streams accessible regular
files without a file-count, file-size or directory-name cutoff, includes
hidden items, does not follow links, junctions or reparse points, and applies
the same narrow quarantine/staging exclusions described above. It runs with
the current user's normal permissions and does not request elevation.
Depending on disk size, file count and storage speed, it can take a long time.

If Windows drive enumeration fails, a Full scan does not start. Aegis reports
the operational failure instead of silently falling back to `C:` and presenting
that partial scope as a full-computer scan.

## Errors, progress and cancellation

Windows can deny access to operating-system, another user's or otherwise
protected paths. A file can also disappear or change between discovery and
reading. Aegis counts directory and traversal failures separately from
file-analysis errors and continues with roots and files it can still read.
These failures mean the scan was partial; a completed Aegis scan is not proof
that every file on the computer is clean.

Links, outside-root paths and duplicate/reparse traversal are safety skips, not
clean files. Reports expose `traversalSkipped` for all such skips and
`linksSkipped` for link or outside-root cases; `traversalErrors` remains the
separate count for paths that could not be accessed.

All desktop scan modes stream discovery and analysis instead of first building
an unbounded in-memory file list. Progress therefore reports monotonically
increasing discovered and completed counters with an indeterminate total
(`total: null`). Live counters distinguish malicious and suspicious findings,
skipped files, file-analysis errors and traversal errors; the combined `errors`
counter includes both error classes. Scans remain cancelable and return the
partial summary and retained findings accumulated before cancellation. Pausing
protection is a separate control and does not pause or cancel an on-demand
scan.

The interactive Results table remains bounded by 5,000 attention results and
an estimated 8 MiB per scan. Retention priority is malicious, suspicious, file
error, then skipped, so the most important findings remain reviewable without
an unbounded renderer payload. Separately, every scan streams all file results,
including clean files, to complete JSON and spreadsheet-safe CSV reports under
the application data directory. The Results view can copy either format to a
user-selected destination through **Download report**; users do not need to
browse internal application files. The internal report directory is excluded
from scanning to prevent self-analysis. Manual isolation identifiers remain
available for at most the four most recent scan jobs; an older result must be
scanned again before it can be isolated through that identifier.

## Content and crash-recovery limits

Deep and Full hash the bytes of each accessible regular file in scope, but do
not enumerate NTFS alternate data streams and do not inspect the contents of
ZIP, RAR, 7z or other container/archive formats. Their refusal to cross
reparse and mount-only boundaries is deliberate root-confinement behavior, not
evidence that content behind those boundaries is clean.

Isolation and restore authenticate and stream their content, but they are not
guaranteed to be transactionally crash-safe against a forced process or system
shutdown at every intermediate instruction. Such an interruption can leave a
recoverable staging file. While an operation is live its exact staging path is
excluded to avoid racing the scanner; after a restart that path is no longer
registered, so a later Deep or Full scan analyzes the leftover as ordinary
content.

## Quarantine inventory limits

The quarantine view returns at most 5,000 valid entries and an aggregate 8 MiB
of metadata per refresh, and does not currently offer cursor pagination. It
also returns the exact number of valid entries and an explicit
truncated/`hasMore` indication, so the interface does not present a partial
list as complete. Invalid metadata or a missing or invalid encrypted payload
is omitted and counted as corrupt; metadata larger than 64 KiB per item is not
loaded and is counted separately as oversized. These conditions do not prevent
other valid quarantine entries from being listed, and the interface keeps a
visible warning while any warning count is nonzero.

## Safe interpretation

- Leave Microsoft Defender and Windows security features enabled.
- Review suspicious heuristic findings before isolating them; legitimate tools
  can match scripting, entropy or macro heuristics.
- Automatic quarantine is off by default. Quarantine is encrypted and
  authenticated. Restore returns to the authenticated original path without a
  destination picker and refuses to overwrite an existing file.
- If compromise is plausible, follow [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md)
  rather than relying on a single Aegis result.
