# LanGateway

Windows desktop tool for managing `netsh interface portproxy` TCP forwarding rules with an [egui](https://github.com/emilk/egui)-based native GUI.

## Features

- **Dashboard** - Hostname, Gateway IP, usable IPv4 addresses, active interface, admin status, rule count, and update status.
- **Forward Rules** - Add, edit, enable, disable, delete, and adopt Windows PortProxy rules with TOML persistence.
- **Responsive Interface** - Consistent navigation and spacing, a gateway summary card, and scrollable pages for long rule lists and smaller windows.
- **TCP Proxy Modes** - Supports `v4tov4`, `v4tov6`, `v6tov4`, and `v6tov6` Windows PortProxy modes.
- **Rule Preflight** - Checks duplicate managed rules, existing Windows rules, target DNS/address family, admin permission, and TCP-only support.
- **Firewall Automation** - Optional per-rule inbound TCP firewall rule management using stable names like `LanGateway-<rule-id>`.
- **Orphan Adoption** - Detect and import existing PortProxy rules not yet tracked in local config.
- **Health Check** - TCP connectivity test for managed rules and orphan rules on a background thread.
- **Network Page** - Shows adapter priority, IPv4/IPv6 addresses, suspected virtual adapters, sync diff hints, firewall state, and diagnostics export.
- **mDNS Responder** - Responds to `<hostname>.local` on the LAN, pointing to the current Gateway IP and refreshing when the PC IP changes.
- **Fast Startup Refresh** - Shows saved configuration immediately, then applies quick IPv4/v4tov4 results before full adapter and PortProxy diagnostics finish.
- **Diagnostics Export** - Writes a sanitized report with version, paths, adapters, rules, firewall state, mDNS state, and recent logs.
- **Settings** - zh-CN / en-US language switching, Preferred Gateway IP, adapter list, and mDNS controls.
- **CJK Fonts** - Auto-loaded from Windows system fonts.
- **UAC Elevation** - Restart as Administrator for non-admin mode.
- **Auto Update** - Automatic update check on startup, manual check from Dashboard, proxy fallback, and PowerShell self-replacement.

## Requirements

- Windows 10 or later
- Administrator privileges are required for adding, editing, deleting, syncing PortProxy rules, and managing firewall rules.
- Read-only mode can still inspect rules, network state, health state, and diagnostics.

## Configuration and Logs

Configuration is stored at:

```text
C:\ProgramData\LanGateway\config.toml
```

Logs are stored at:

```text
C:\ProgramData\LanGateway\logs\langateway.log
```

Diagnostics export writes:

```text
C:\ProgramData\LanGateway\logs\diagnostics.txt
```

If a `config.toml` exists next to the executable from an older version, it is copied to the ProgramData location on first launch when the ProgramData config does not already exist.

Configuration saves write a complete temporary file in the same directory and then replace the previous file with a [rename](https://doc.rust-lang.org/std/fs/fn.rename.html). If the configuration cannot be loaded, the app displays the error and disables changes and update installation to protect the existing file. Correct the TOML file or restore a backup, then restart the app.

## Usage

| Action | Description |
|--------|-------------|
| Add Rule | Choose protocol/mode, fill listen port, target address, target port, and click "Add Rule". |
| Edit Rule | Click "Edit"; fields pre-fill with current values, including the listen address. Modify and click "Update Rule". |
| Disable Rule | Click "Disable" on a managed rule to remove the Windows PortProxy entry while keeping the saved configuration. |
| Enable Rule | Click "Enable" on a disabled rule to rerun preflight and recreate the Windows PortProxy entry. |
| Delete Rule | Click "Delete" on a managed rule. Requires admin. |
| Adopt Orphan | Click "Adopt" on an orphan rule or "Adopt All" to import all into config. |
| Refresh Status | Reload PortProxy rules and network information. |
| Run Health Check | Test TCP reachability for managed rules and orphans. |
| Manage Firewall | Check "Manage Firewall" on a TCP rule to create/update an inbound rule for the listen port. |
| Export Diagnostics | Open Network, click "Export Diagnostics". |

Rule changes, rule refresh, mDNS startup/shutdown, and diagnostics collection run in the background. Conflicting edits are temporarily disabled while rules are being changed. Closing the window during a rule operation waits for its result before exiting. Operation messages remain visible until dismissed or replaced by another result.

Before changing a rule, LanGateway reads the current Windows entries and checks listener conflicts across modes sharing the same IP family, including wildcard listeners. Configuration is committed after the Windows and firewall operations succeed. On failure, the app keeps the previous configuration and attempts to restore the affected Windows entries and firewall rules. If restoration also fails, the error includes the rollback failure; refresh status and inspect the affected rules before retrying. A missing Windows entry does not prevent deleting its saved configuration.

IPv6 literals from Windows and configuration use the same canonical form, so equivalent expanded or uppercase addresses remain associated with their managed rules after adoption and can be disabled correctly.

Health checks test target TCP reachability only for enabled TCP rules with an exact matching Windows entry. Disabled rules, UDP metadata, and missing entries are reported as metadata only. Results from a previous rule or network snapshot are discarded after changes; an unchanged refresh preserves existing health results.

## TCP and UDP

Windows `netsh interface portproxy` supports TCP forwarding only. Adding or enabling UDP rules is unavailable in the interface. UDP entries loaded from older configurations remain metadata-only placeholders for a future user-mode relay feature.

Supported TCP modes:

| Mode | Listen Side | Target Side |
|------|-------------|-------------|
| `v4tov4` | IPv4 | IPv4 |
| `v4tov6` | IPv4 | IPv6 |
| `v6tov4` | IPv6 | IPv4 |
| `v6tov6` | IPv6 | IPv6 |

## mDNS

Enable mDNS in Settings to make the gateway reachable by name on the LAN:

1. Check "Enable mDNS".
2. Set a hostname, such as `gateway`; `.local` is appended automatically.
3. LanGateway binds the responder to the current Gateway IP.
4. Devices on the LAN can use URLs like `http://gateway.local:8080`.

mDNS hostnames must be a single label under `.local`. Valid examples are `gateway` and `gateway.local`; normal custom domains such as `gateway.example.com` require DNS, a hosts-file entry, VPN DNS, router DNS, or campus DNS support.

mDNS currently provides host A-record resolution. The per-rule "Publish mDNS" flag is reserved metadata; its control is disabled because service publishing has not been implemented. The responder bounds DNS name decoding and query sampling, handles matching questions in multi-question packets, and sends legacy unicast replies to clients using an ephemeral source port.

For campus networks where the PC IP changes, keep LanGateway running with mDNS enabled. It periodically refreshes the selected Gateway IP and restarts the responder when the IP changes, so new mDNS answers point at the new address. Client devices may still cache the old answer briefly.

mDNS uses standard UDP port 5353. LanGateway attempts a shared bind with `SO_REUSEADDR` and can create a firewall rule named `LanGateway-mDNS`, but some systems or processes may still prevent mDNS from starting.

Common UDP 5353 occupants include Chrome Cast Discovery, Steam, and Windows DNS Client (`Dnscache`). If mDNS cannot start, use direct IP access, a client hosts-file entry, router DNS, or campus DNS as a fallback. If the campus network blocks multicast between clients, `.local` discovery may not work across that network segment.

For a quick manual mDNS check from this repo, run:

```bash
python scripts/query_mdns.py gateway.local
```

## Startup Refresh

LanGateway renders the window immediately with saved configuration data. Startup refresh then proceeds in stages:

1. Quick stage: hostname, lightweight IPv4 detection, and `v4tov4` PortProxy rules.
2. Full stage: PowerShell adapter details, IPv6 addresses, and all PortProxy modes.
3. Deferred checks: health checks and update checks start only after the full startup refresh completes.

This means the first screen should appear quickly, while exact system state continues to settle in the background.

Late quick-stage results cannot overwrite a completed full refresh or a newer refresh. A quick-stage IPv4 refresh preserves cached entries from the other PortProxy modes. If reading Windows rules fails, the app keeps its last rule snapshot and displays the failure instead of reporting an empty successful result.

## Auto Update

LanGateway checks the latest GitHub Release after startup refresh completes. Manual checks are also available from Dashboard.

Release requirements:

- GitHub tags should use `vX.Y.Z`, while `Cargo.toml` uses `X.Y.Z`.
- The release asset must be named exactly `langateway.exe`.
- The updater creates a unique `.update-<job-id>` directory next to the actual running executable and stages `candidate.exe` there. Renaming the installed executable is supported.

Network behavior:

- Release API checks try a direct GitHub connection first, then fall back to system proxy settings.
- Asset downloads try system proxy settings first, then fall back to direct GitHub download.
- All update network work runs on a background thread and never blocks the UI thread.

Replacement behavior:

- Before replacing the exe, LanGateway saves the current config.
- A config save failure stops the update. Rule and settings edits are disabled during update installation.
- Release versions and asset URLs are checked against the expected repository and release. Downloads are limited to 64 MiB and must pass size and Windows MZ/PE header checks before the app exits; these checks do not verify a cryptographic signature.
- The app waits for the PowerShell helper to validate its job and capture the exact parent process before requesting normal window closure. Helper startup failure leaves the app open. A parent-exit timeout aborts replacement; other copies with the same process name are unaffected.
- The updater keeps `updater.log`, `result.json`, and `previous.exe` in the job directory. It excludes duplicate helpers for the same target and preserves recovery files after success.
- Replacement uses [File.Replace](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace?view=netframework-4.8.1), with bounded retries. A failed launch, early exit, or missing startup acknowledgement restores and restarts the backup even when the failed candidate occupies the installed path.
- The new app acknowledges startup after configuration loads and its first UI frame completes. This confirms that milestone, not every subsequent Windows/network operation. Irreversible configuration migrations would require a separate recovery design.
- The helper inherits the existing app permissions and does not request elevation. Keep the install directory and job files trusted for that privilege level. The existing helper-only execution policy option does not override enterprise Group Policy.
- If LanGateway is installed under a protected directory such as `C:\Program Files`, replacement may fail unless the process has write permission. The app does not silently request elevation for updates.

## Build from Source

```bash
# Prerequisites: Rust toolchain (https://rustup.rs)

git clone https://github.com/uchihazzj/LanGateway.git
cd LanGateway
cargo build --release
# Binary at: target/release/langateway.exe
```

## Validation

```bash
cargo check
cargo test
```

The updater can also be tested without changing an installed application. Run `scripts/test_update.ps1 -ScratchRoot <existing-writable-scratch-directory>` from PowerShell. It compiles disposable fixture programs and tests only files in a fresh scratch subdirectory. On machines where Windows PowerShell 5.1 disables local scripts, the explicit `-AllowLocalFixtureScripts` test option sets `RemoteSigned` only for fixture helper processes; it changes no persistent policy.

## License

MIT
