use crate::core::model::{DashboardInfo, PortproxyEntry};
use crate::service::mdns::MdnsStatus;
use crate::storage::config::Config;
use crate::system::{firewall, logger};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    pub text: String,
}

pub fn build_report(
    config: &Config,
    config_path: &Path,
    dashboard: &DashboardInfo,
    entries: &[PortproxyEntry],
    mdns_status: &MdnsStatus,
) -> DiagnosticReport {
    let mut out = String::new();
    push_line(&mut out, "# LanGateway Diagnostics");
    push_line(&mut out, "");
    push_line(&mut out, &format!("Version: {}", env!("CARGO_PKG_VERSION")));
    push_line(&mut out, &format!("Admin: {}", dashboard.is_admin));
    push_line(&mut out, &format!("Config path: {}", config_path.display()));
    push_line(
        &mut out,
        &format!("Log path: {}", logger::log_path().display()),
    );
    push_line(&mut out, &format!("Hostname: {}", dashboard.hostname));
    push_line(&mut out, &format!("Gateway IP: {}", dashboard.gateway_ip));
    push_line(
        &mut out,
        &format!("Active interface: {}", dashboard.active_interface),
    );
    push_line(&mut out, &format!("mDNS status: {}", mdns_status));
    push_line(&mut out, "");

    push_line(&mut out, "## Interfaces");
    if dashboard.interfaces.is_empty() {
        push_line(&mut out, "- none");
    }
    for iface in &dashboard.interfaces {
        push_line(
            &mut out,
            &format!(
                "- {} | IPv4={} | IPv6={} | MAC={} | virtual={}",
                iface.name,
                iface.ipv4,
                if iface.ipv6.is_empty() {
                    "-".into()
                } else {
                    iface.ipv6.join(", ")
                },
                iface.mac,
                iface.is_virtual
            ),
        );
    }

    push_line(&mut out, "");
    push_line(&mut out, "## Managed Rules");
    if config.rules.is_empty() {
        push_line(&mut out, "- none");
    }
    for rule in &config.rules {
        push_line(
            &mut out,
            &format!(
                "- {} [{} {}] {}:{} -> {}:{} enabled={} firewall={} mdns={}",
                rule.name,
                rule.protocol.label(),
                rule.proxy_mode.netsh_name(),
                rule.listen_address,
                rule.listen_port,
                rule.connect_address,
                rule.connect_port,
                rule.enabled,
                rule.firewall_managed,
                rule.mdns_publish
            ),
        );
    }

    push_line(&mut out, "");
    push_line(&mut out, "## Windows PortProxy");
    if entries.is_empty() {
        push_line(&mut out, "- none");
    }
    for entry in entries {
        push_line(
            &mut out,
            &format!(
                "- [{}] {}:{} -> {}:{}",
                entry.proxy_mode.netsh_name(),
                entry.listen_address,
                entry.listen_port,
                entry.connect_address,
                entry.connect_port
            ),
        );
    }

    push_line(&mut out, "");
    push_line(&mut out, "## Firewall");
    for rule in &config.rules {
        if rule.firewall_managed {
            let name = firewall::tcp_rule_name(rule);
            let status = firewall::query_rule(&name);
            push_line(
                &mut out,
                &format!(
                    "- {} {}",
                    status.name,
                    status.error.as_ref().map_or_else(
                        || format!("exists={}", status.exists),
                        |error| format!("query_failed={error}")
                    )
                ),
            );
        }
    }
    let mdns_fw = firewall::query_rule(firewall::MDNS_FIREWALL_RULE);
    push_line(
        &mut out,
        &format!(
            "- {} {}",
            mdns_fw.name,
            mdns_fw.error.as_ref().map_or_else(
                || format!("exists={}", mdns_fw.exists),
                |error| format!("query_failed={error}")
            )
        ),
    );

    push_line(&mut out, "");
    push_line(&mut out, "## Recent Log");
    let recent = logger::read_recent_lines(40);
    if recent.is_empty() {
        push_line(&mut out, "- no log lines available");
    }
    for line in recent {
        push_line(&mut out, &line);
    }

    DiagnosticReport { text: out }
}

pub fn save_report(report: &DiagnosticReport) -> Result<std::path::PathBuf, String> {
    let path = logger::log_dir().join("diagnostics.txt");
    std::fs::write(&path, &report.text)
        .map_err(|e| format!("Failed to write diagnostics report: {}", e))?;
    Ok(path)
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}
