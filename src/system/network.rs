use crate::core::model::InterfaceInfo;
use crate::system::{encoding, logger, process};
use serde::Deserialize;

pub fn get_hostname() -> Option<String> {
    let output = process::run_command("hostname", &[]).ok()?;
    if output.status.success() {
        Some(encoding::decode(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Primary: PowerShell Get-NetIPAddress + Get-NetAdapter → JSON, joined by InterfaceIndex.
/// Falls back to ipconfig /all if PowerShell fails.
pub fn get_active_interfaces() -> Vec<InterfaceInfo> {
    if let Some(ifaces) = get_interfaces_via_powershell() {
        if !ifaces.is_empty() {
            logger::log_to_file(&format!(
                "PowerShell: got {} interfaces, {} IPs",
                ifaces.iter().map(|i| i.name.as_str()).collect::<std::collections::HashSet<_>>().len(),
                ifaces.len()
            ));
            return ifaces;
        }
        logger::log_to_file("PowerShell: parsed 0 interfaces, falling back to ipconfig");
    } else {
        logger::log_to_file("PowerShell: failed to get interfaces, falling back to ipconfig");
    }
    get_interfaces_via_ipconfig()
}

fn get_interfaces_via_powershell() -> Option<Vec<InterfaceInfo>> {
    // Command: Get IP addresses
    let ip_output = process::run_command(
        "powershell",
        &[
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState | ConvertTo-Json -Depth 5",
        ],
    ).ok()?;

    logger::log_to_file(&format!(
        "PowerShell IP: exit={}, stdout_len={}, stderr_len={}",
        ip_output.status.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
        ip_output.stdout.len(),
        ip_output.stderr.len()
    ));
    if !ip_output.status.success() {
        logger::log_to_file(&format!("PowerShell IP stderr: {}", encoding::decode(&ip_output.stderr)));
        return None;
    }

    let ip_json = encoding::decode(&ip_output.stdout);
    logger::log_to_file(&format!("PowerShell IP JSON (first 300): {}", &ip_json[..ip_json.len().min(300)]));

    // Command: Get adapters
    let ad_output = process::run_command(
        "powershell",
        &[
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
            "Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceIndex,MacAddress,Status | ConvertTo-Json -Depth 5",
        ],
    ).ok()?;

    let ad_json = if ad_output.status.success() {
        let json = encoding::decode(&ad_output.stdout);
        logger::log_to_file(&format!("PowerShell Adapter JSON (first 200): {}", &json[..json.len().min(200)]));
        json
    } else {
        logger::log_to_file(&format!("PowerShell Adapter stderr: {}", encoding::decode(&ad_output.stderr)));
        String::new()
    };

    parse_powershell_output(&ip_json, &ad_json)
}

#[derive(Deserialize)]
struct PsIpAddr {
    #[serde(default)]
    #[serde(rename = "InterfaceAlias")]
    interface_alias: String,
    #[serde(default)]
    #[serde(rename = "InterfaceIndex")]
    interface_index: i32,
    #[serde(default)]
    #[serde(rename = "IPAddress")]
    ip_address: String,
}

#[derive(Deserialize)]
struct PsAdapter {
    #[serde(default)]
    #[serde(rename = "Name")]
    name: String,
    #[serde(default)]
    #[serde(rename = "InterfaceDescription")]
    interface_description: String,
    #[serde(default)]
    #[serde(rename = "InterfaceIndex")]
    interface_index: i32,
    #[serde(default)]
    #[serde(rename = "MacAddress")]
    mac_address: String,
}

/// Parse JSON that may be a single object or array.
fn parse_json_array_or_single<'a, T: Deserialize<'a>>(json: &'a str) -> Option<Vec<T>> {
    if let Ok(arr) = serde_json::from_str::<Vec<T>>(json) {
        return Some(arr);
    }
    if let Ok(obj) = serde_json::from_str::<T>(json) {
        return Some(vec![obj]);
    }
    None
}

fn parse_powershell_output(ip_json: &str, ad_json: &str) -> Option<Vec<InterfaceInfo>> {
    let ip_addrs = parse_json_array_or_single::<PsIpAddr>(ip_json)?;
    logger::log_to_file(&format!("PowerShell: parsed {} IP addresses from JSON", ip_addrs.len()));

    let adapters: Vec<PsAdapter> = if ad_json.is_empty() {
        Vec::new()
    } else {
        parse_json_array_or_single::<PsAdapter>(ad_json).unwrap_or_default()
    };
    logger::log_to_file(&format!("PowerShell: parsed {} adapters from JSON", adapters.len()));

    let mut interfaces = Vec::new();

    for ip in &ip_addrs {
        if ip.ip_address.is_empty() || ip.ip_address == "0.0.0.0" {
            logger::log_to_file(&format!("  IP skip: {} (empty or 0.0.0.0)", ip.ip_address));
            continue;
        }

        // Find matching adapter by InterfaceIndex
        let adapter = if ip.interface_index != 0 {
            adapters.iter().find(|a| a.interface_index == ip.interface_index)
        } else {
            None
        };

        let name = match adapter {
            Some(ad) if !ad.name.is_empty() => ad.name.clone(),
            _ if !ip.interface_alias.is_empty() => ip.interface_alias.clone(),
            _ => {
                logger::log_to_file(&format!("  IP {}: no adapter name found (index={})", ip.ip_address, ip.interface_index));
                continue;
            }
        };

        let mac = adapter.map(|a| a.mac_address.clone()).unwrap_or_default();

        logger::log_to_file(&format!(
            "  IP {} -> adapter '{}' (idx={}, virtual={}, mac={})",
            ip.ip_address, name, ip.interface_index, is_virtual_adapter(&name), mac
        ));

        interfaces.push(InterfaceInfo {
            name,
            ipv4: ip.ip_address.clone(),
            mac,
            is_virtual: is_virtual_adapter(&ip.interface_alias),
        });
    }

    Some(interfaces)
}

/// Fallback: parse `ipconfig /all` text output.
fn get_interfaces_via_ipconfig() -> Vec<InterfaceInfo> {
    let output = match process::run_command("ipconfig", &["/all"]) {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let text = encoding::decode(&output.stdout);
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_ipv4 = String::new();
    let mut current_mac = String::new();

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            if !current_name.is_empty() && !current_ipv4.is_empty() {
                interfaces.push(InterfaceInfo {
                    name: current_name.clone(),
                    ipv4: current_ipv4.clone(),
                    mac: current_mac.clone(),
                    is_virtual: is_virtual_adapter(&current_name),
                });
            }
            current_name.clear();
            current_ipv4.clear();
            current_mac.clear();
            continue;
        }

        if line.starts_with("Windows IP") {
            continue;
        }

        if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
            if !current_name.is_empty() && !current_ipv4.is_empty() {
                interfaces.push(InterfaceInfo {
                    name: current_name.clone(),
                    ipv4: current_ipv4.clone(),
                    mac: current_mac.clone(),
                    is_virtual: is_virtual_adapter(&current_name),
                });
            }
            current_name = trimmed.trim_end_matches(':').to_string();
            current_ipv4.clear();
            current_mac.clear();
        } else if trimmed.starts_with("IPv4 Address") || trimmed.contains("IPv4 地址") {
            if let Some(addr) = trimmed.split(':').last() {
                let addr = addr.trim().replace("(Preferred)", "").replace("(首选)", "").trim().to_string();
                if !addr.is_empty() {
                    current_ipv4 = addr;
                }
            }
        } else if trimmed.starts_with("Physical Address") || trimmed.contains("物理地址") {
            if let Some(addr) = trimmed.split(':').last() {
                current_mac = addr.trim().to_string();
            }
        }
    }

    if !current_name.is_empty() && !current_ipv4.is_empty() {
        let is_virt = is_virtual_adapter(&current_name);
        interfaces.push(InterfaceInfo {
            is_virtual: is_virt,
            name: current_name,
            ipv4: current_ipv4,
            mac: current_mac,
        });
    }

    interfaces
}

pub fn ipv4_addresses_from(interfaces: &[InterfaceInfo]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    interfaces
        .iter()
        .map(|i| i.ipv4.clone())
        .filter(|ip| ip != "0.0.0.0" && seen.insert(ip.clone()))
        .collect()
}

pub fn is_virtual_adapter(name: &str) -> bool {
    let lower = name.to_lowercase();
    let keywords = [
        "hyper-v", "wsl", "docker", "vpn", "virtual", "tun", "tap",
        "clash", "vethernet", "vmware", "virtualbox", "tailscale",
        "zerotier", "wireguard", "pangp", "sangfor", "easyconnect",
        "loopback", "pseudo", "tunnel", "6to4", "teredo", "isatap",
        "bluetooth", "wan miniport", "vbox", "host-only",
    ];
    keywords.iter().any(|k| lower.contains(k))
}

/// Select the best LAN IP as gateway entry point.
/// Returns empty string if no usable IP found.
pub fn select_preferred_ip(
    ipv4s: &[String],
    preferred: &str,
    interfaces: &[InterfaceInfo],
) -> String {
    if preferred != "auto" && !preferred.is_empty() {
        if ipv4s.iter().any(|ip| ip == preferred) {
            logger::log_to_file(&format!("select_preferred_ip: manual override -> {}", preferred));
            return preferred.to_string();
        }
        logger::log_to_file(&format!("select_preferred_ip: manual '{}' not found, falling back to auto", preferred));
    }

    let candidates: Vec<&String> = ipv4s
        .iter()
        .filter(|ip| {
            let ip = ip.as_str();
            !ip.starts_with("127.")
                && !ip.starts_with("169.254.")
                && !ip.starts_with("198.18.")
                && ip != "0.0.0.0"
        })
        .collect();

    logger::log_to_file(&format!("select_preferred_ip: {} total, {} candidates after filter", ipv4s.len(), candidates.len()));

    if candidates.is_empty() {
        logger::log_to_file("select_preferred_ip: no candidates, returning empty");
        return String::new();
    }

    fn is_lan_ip(ip: &str) -> bool {
        ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || {
                ip.starts_with("172.")
                    && ip
                        .split('.')
                        .nth(1)
                        .and_then(|s| s.parse::<u8>().ok())
                        .map(|n| (16..=31).contains(&n))
                        .unwrap_or(false)
            }
    }

    fn lan_priority(ip: &str) -> u8 {
        if ip.starts_with("10.") { return 1; }
        if ip.starts_with("172.") {
            if let Some(n) = ip.split('.').nth(1).and_then(|s| s.parse::<u8>().ok()) {
                if (16..=31).contains(&n) { return 2; }
            }
        }
        if ip.starts_with("192.168.") { return 3; }
        4
    }

    let mut best: Option<&String> = None;
    let mut best_prio = 99u8;
    for ip in &candidates {
        let iface = interfaces.iter().find(|i| &i.ipv4 == *ip);
        if is_lan_ip(ip) && iface.map(|i| !i.is_virtual).unwrap_or(true) {
            let p = lan_priority(ip);
            if p < best_prio { best_prio = p; best = Some(ip); }
        }
    }
    if let Some(ip) = best {
        logger::log_to_file(&format!("select_preferred_ip: LAN non-virt -> {}", ip));
        return (*ip).clone();
    }

    for ip in &candidates {
        if is_lan_ip(ip) {
            logger::log_to_file(&format!("select_preferred_ip: any LAN -> {}", ip));
            return (*ip).clone();
        }
    }

    for ip in &candidates {
        let iface = interfaces.iter().find(|i| &i.ipv4 == *ip);
        if iface.map(|i| !i.is_virtual).unwrap_or(false) {
            logger::log_to_file(&format!("select_preferred_ip: non-virt -> {}", ip));
            return (*ip).clone();
        }
    }

    let fallback = candidates.first().map(|s| (*s).clone()).unwrap_or_default();
    logger::log_to_file(&format!("select_preferred_ip: fallback -> {}", fallback));
    fallback
}

pub fn get_interface_for_ip<'a>(ip: &str, interfaces: &'a [InterfaceInfo]) -> &'a str {
    if ip.is_empty() { return "Unknown"; }
    interfaces.iter().find(|i| i.ipv4 == ip)
        .map(|i| i.name.as_str())
        .unwrap_or("Unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_iface(name: &str, ip: &str, is_virtual: bool) -> InterfaceInfo {
        InterfaceInfo { name: name.into(), ipv4: ip.into(), mac: String::new(), is_virtual }
    }

    #[test]
    fn parse_single_object_json() {
        let json = r#"{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"IPAddress":"10.0.0.1"}"#;
        let result = parse_json_array_or_single::<PsIpAddr>(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ip_address, "10.0.0.1");
        assert_eq!(result[0].interface_index, 12);
    }

    #[test]
    fn parse_array_json() {
        let json = r#"[{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"IPAddress":"10.0.0.1"},{"InterfaceAlias":"Wi-Fi","InterfaceIndex":5,"IPAddress":"192.168.1.1"}]"#;
        let result = parse_json_array_or_single::<PsIpAddr>(json).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn parse_empty_array_json() {
        let json = "[]";
        let result = parse_json_array_or_single::<PsIpAddr>(json).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn join_by_interface_index() {
        let ip_json = r#"{"InterfaceAlias":"Wi-Fi","InterfaceIndex":5,"IPAddress":"192.168.1.1"}"#;
        let ad_json = r#"{"Name":"Wi-Fi","InterfaceDescription":"Intel Wi-Fi","InterfaceIndex":5,"MacAddress":"AA-BB-CC-DD-EE-FF","Status":"Up"}"#;
        let result = parse_powershell_output(ip_json, ad_json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "Wi-Fi");
        assert_eq!(result[0].ipv4, "192.168.1.1");
        assert_eq!(result[0].mac, "AA-BB-CC-DD-EE-FF");
    }

    #[test]
    fn select_preferred_ip_prioritizes_lan() {
        let ips = vec!["198.18.0.1".to_string(), "192.168.100.6".to_string(), "10.108.18.68".to_string()];
        let ifaces = vec![
            make_iface("TUN", "198.18.0.1", true),
            make_iface("Wi-Fi", "192.168.100.6", false),
            make_iface("Ethernet", "10.108.18.68", false),
        ];
        assert_eq!(select_preferred_ip(&ips, "auto", &ifaces), "10.108.18.68");
    }

    #[test]
    fn select_preferred_ip_excludes_apipa() {
        assert_eq!(select_preferred_ip(&["169.254.1.1".into(), "10.0.0.1".into()], "auto", &[make_iface("Ethernet", "10.0.0.1", false)]), "10.0.0.1");
    }

    #[test]
    fn select_preferred_ip_manual_override() {
        assert_eq!(select_preferred_ip(&["10.0.0.1".into(), "192.168.1.1".into()], "192.168.1.1", &[]), "192.168.1.1");
    }

    #[test]
    fn select_preferred_ip_manual_missing_falls_back() {
        assert_eq!(select_preferred_ip(&["10.0.0.1".into()], "10.99.99.99", &[make_iface("Ethernet", "10.0.0.1", false)]), "10.0.0.1");
    }

    #[test]
    fn select_preferred_ip_no_usable_returns_empty() {
        assert_eq!(select_preferred_ip(&[], "auto", &[]), "");
    }

    #[test]
    fn select_preferred_ip_excludes_zeros() {
        assert_eq!(select_preferred_ip(&["0.0.0.0".into(), "127.0.0.1".into(), "10.0.0.1".into()], "auto", &[make_iface("Ethernet", "10.0.0.1", false)]), "10.0.0.1");
    }

    #[test]
    fn detected_ips_include_all_non_loopback() {
        let ifaces = vec![
            make_iface("TUN", "198.18.0.1", true),
            make_iface("Wi-Fi", "192.168.100.6", false),
            make_iface("Ethernet", "10.108.18.68", false),
        ];
        let ips = ipv4_addresses_from(&ifaces);
        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"198.18.0.1".to_string()));
        assert!(ips.contains(&"192.168.100.6".to_string()));
        assert!(ips.contains(&"10.108.18.68".to_string()));
    }

    #[test]
    fn get_interface_for_ip_returns_name() {
        let ifaces = vec![
            make_iface("Ethernet", "10.0.0.1", false),
            make_iface("Wi-Fi", "192.168.1.1", false),
        ];
        assert_eq!(get_interface_for_ip("10.0.0.1", &ifaces), "Ethernet");
        assert_eq!(get_interface_for_ip("10.99.99.99", &ifaces), "Unknown");
    }
}
