# LanGateway

Windows desktop tool for managing `netsh interface portproxy` TCP forwarding rules with an [egui](https://github.com/emilk/egui)-based native GUI.

## Features

- **Dashboard** — Hostname, Gateway IP, usable IPv4 addresses, active interface, admin status, rule count
- **Forward Rules** — Add / edit / delete `netsh interface portproxy v4tov4` rules with TOML config persistence
- **Orphan Adoption** — Detect and import existing portproxy rules not yet tracked in local config
- **Health Check** — TCP connectivity test for each rule (background thread, non-blocking)
- **Settings** — zh-CN / en-US language switching, Preferred Gateway IP (auto or manual), adapter list
- **CJK Fonts** — Auto-loaded from Windows system fonts
- **UAC Elevation** — Restart as Administrator for non-admin mode

## Download

Download the latest `langateway.exe` from [Releases](https://github.com/uchihazzj/LanGateway/releases).

## Requirements

- Windows 10 or later
- Administrator privileges required for adding / editing / deleting portproxy rules (read-only otherwise)

## Configuration

Configuration is stored at:

```
C:\ProgramData\LanGateway\config.toml
```

If a `config.toml` exists next to the executable (legacy location), it will be automatically migrated to the ProgramData location on first launch.

## Usage

| Action | Description |
|--------|-------------|
| **Add Rule** | Fill in listen port, target address, target port — click "Add Rule" |
| **Edit Rule** | Click "Edit" on a managed rule — fields pre-fill with current values — modify and click "Update Rule" |
| **Delete Rule** | Click "Delete" (requires admin) |
| **Adopt Orphan** | Click "Adopt" on an orphan rule or "Adopt All" to import all into config |
| **Refresh Status** | Reload portproxy rules and network info |
| **Run Health Check** | TCP connectivity test for all managed rules and orphans |

## Build from Source

```bash
# Prerequisites: Rust toolchain (https://rustup.rs)

git clone https://github.com/uchihazzj/LanGateway.git
cd LanGateway
cargo build --release
# Binary at: target/release/langateway.exe
```

## License

MIT
