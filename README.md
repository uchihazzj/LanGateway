# LanGateway

Windows desktop tool for managing `netsh interface portproxy` TCP forwarding rules with an [egui](https://github.com/emilk/egui)-based native GUI.

## Features

- **Dashboard** - Hostname, Gateway IP, usable IPv4 addresses, active interface, admin status, rule count, and update status.
- **Forward Rules** - Add, edit, enable, disable, delete, and adopt Windows PortProxy rules with TOML persistence.
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

## Usage

| Action | Description |
|--------|-------------|
| Add Rule | Choose protocol/mode, fill listen port, target address, target port, and click "Add Rule". |
| Edit Rule | Click "Edit"; fields pre-fill with current values. Modify and click "Update Rule". |
| Disable Rule | Click "Disable" on a managed rule to remove the Windows PortProxy entry while keeping the saved configuration. |
| Enable Rule | Click "Enable" on a disabled rule to rerun preflight and recreate the Windows PortProxy entry. |
| Delete Rule | Click "Delete" on a managed rule. Requires admin. |
| Adopt Orphan | Click "Adopt" on an orphan rule or "Adopt All" to import all into config. |
| Refresh Status | Reload PortProxy rules and network information. |
| Run Health Check | Test TCP reachability for managed rules and orphans. |
| Manage Firewall | Check "Manage Firewall" on a TCP rule to create/update an inbound rule for the listen port. |
| Export Diagnostics | Open Network, click "Export Diagnostics". |

## TCP and UDP

Windows `netsh interface portproxy` supports TCP forwarding only. LanGateway therefore applies TCP rules to Windows PortProxy and treats UDP rules as metadata-only placeholders for a future user-mode relay feature.

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

For campus networks where the PC IP changes, keep LanGateway running with mDNS enabled. It periodically refreshes the selected Gateway IP and restarts the responder when the IP changes, so new mDNS answers point at the new address. Client devices may still cache the old answer briefly.

mDNS uses standard UDP port 5353. LanGateway attempts a shared bind with `SO_REUSEADDR` and can create a firewall rule named `LanGateway-mDNS`, but some systems or processes may still prevent mDNS from starting.

Common UDP 5353 occupants include Chrome Cast Discovery, Steam, and Windows DNS Client (`Dnscache`). If mDNS cannot start, use direct IP access, a client hosts-file entry, router DNS, or campus DNS as a fallback. If the campus network blocks multicast between clients, `.local` discovery may not work across that network segment.

## Startup Refresh

LanGateway renders the window immediately with saved configuration data. Startup refresh then proceeds in stages:

1. Quick stage: hostname, lightweight IPv4 detection, and `v4tov4` PortProxy rules.
2. Full stage: PowerShell adapter details, IPv6 addresses, and all PortProxy modes.
3. Deferred checks: health checks and update checks start only after the full startup refresh completes.

This means the first screen should appear quickly, while exact system state continues to settle in the background.

## Auto Update

LanGateway checks the latest GitHub Release after startup refresh completes. Manual checks are also available from Dashboard.

Release requirements:

- GitHub tags should use `vX.Y.Z`, while `Cargo.toml` uses `X.Y.Z`.
- The release asset must be named exactly `langateway.exe`.
- The updater downloads the asset next to the running executable as `langateway-vX.Y.Z.exe`, then uses `updater.ps1` to replace the fixed `langateway.exe`.

Network behavior:

- Release API checks try a direct GitHub connection first, then fall back to system proxy settings.
- Asset downloads try system proxy settings first, then fall back to direct GitHub download.
- All update network work runs on a background thread and never blocks the UI thread.

Replacement behavior:

- Before replacing the exe, LanGateway saves the current config.
- The PowerShell updater writes `updater.log` next to the executable.
- The updater verifies the downloaded exe is not suspiciously small, backs up the old exe as `langateway.exe.bak`, retries locked-file replacement, and attempts rollback on failure.
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

## License

MIT
