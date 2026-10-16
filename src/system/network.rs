use std::net::{Ipv4Addr, Ipv6Addr};

use crate::core::model::InterfaceInfo;
use crate::system::{encoding, logger, process};
use serde::Deserialize;

pub fn get_hostname() -> Option<String> {
    let output = process::run_query("hostname", &[]).ok()?;
    if output.status.success() {
        Some(encoding::decode(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Fast startup path: parse plain ipconfig output for IPv4 addresses without
/// waiting for the heavier PowerShell adapter join.
pub fn get_quick_interfaces() -> Vec<InterfaceInfo> {
    let output = match process::run_query("ipconfig", &[]) {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let text = encoding::decode(&output.stdout);
    parse_ipconfig_interfaces(&text)
}

/// Primary: PowerShell Get-NetIPAddress + Get-NetAdapter → JSON, joined by InterfaceIndex.
/// Falls back to ipconfig /all if PowerShell fails.
pub fn get_active_interfaces() -> Result<Vec<InterfaceInfo>, String> {
    if let Some(ifaces) = get_interfaces_via_powershell() {
        logger::log_to_file(&format!(
            "PowerShell: got {} interfaces, {} IPs",
            ifaces
                .iter()
                .map(|i| i.name.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            ifaces.len()
        ));
        return Ok(ifaces);
    } else {
        logger::log_to_file("PowerShell: failed to get interfaces, falling back to ipconfig");
    }
    get_interfaces_via_ipconfig()
}

fn get_interfaces_via_powershell() -> Option<Vec<InterfaceInfo>> {
    // Query both data sets in one PowerShell host instead of starting it twice.
    let output = process::run_query(
        "powershell",
        &[
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
            "$ErrorActionPreference = 'Stop'; $ips = @(Get-NetIPAddress | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '::1' } | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,AddressFamily); $adapters = @(try { Get-NetAdapter | Select-Object Name,InterfaceIndex,MacAddress } catch {}); @{ IPAddresses = $ips; Adapters = $adapters } | ConvertTo-Json -Depth 5 -Compress",
        ],
    ).ok()?;

    logger::log_to_file(&format!(
        "PowerShell network: exit={}, stdout_len={}, stderr_len={}",
        output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".into()),
        output.stdout.len(),
        output.stderr.len()
    ));
    if !output.status.success() {
        logger::log_to_file(&format!(
            "PowerShell network stderr: {}",
            encoding::decode(&output.stderr)
        ));
        return None;
    }
    parse_powershell_snapshot(&encoding::decode(&output.stdout))
}

fn parse_powershell_snapshot(json: &str) -> Option<Vec<InterfaceInfo>> {
    let snapshot: serde_json::Value = serde_json::from_str(json).ok()?;
    let ips = snapshot.get("IPAddresses")?.to_string();
    let adapters = snapshot
        .get("Adapters")
        .filter(|value| !value.is_null())
        .map(ToString::to_string)
        .unwrap_or_default();
    parse_powershell_output(&ips, &adapters)
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
    #[serde(default)]
    #[serde(rename = "AddressFamily")]
    address_family: serde_json::Value,
}

#[derive(Deserialize)]
struct PsAdapter {
    #[serde(default)]
    #[serde(rename = "Name")]
    name: String,
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
    logger::log_to_file(&format!(
        "PowerShell: parsed {} IP addresses from JSON",
        ip_addrs.len()
    ));

    let adapters: Vec<PsAdapter> = if ad_json.is_empty() {
        Vec::new()
    } else {
        parse_json_array_or_single::<PsAdapter>(ad_json).unwrap_or_default()
    };
    logger::log_to_file(&format!(
        "PowerShell: parsed {} adapters from JSON",
        adapters.len()
    ));

    let mut by_key: std::collections::BTreeMap<(i32, String), InterfaceInfo> =
        std::collections::BTreeMap::new();

    for ip in &ip_addrs {
        if ip.ip_address.is_empty() || ip.ip_address == "0.0.0.0" {
            logger::log_to_file(&format!("  IP skip: {} (empty or 0.0.0.0)", ip.ip_address));
            continue;
        }

        // Find matching adapter by InterfaceIndex
        let adapter = if ip.interface_index != 0 {
            adapters
                .iter()
                .find(|a| a.interface_index == ip.interface_index)
        } else {
            None
        };

        let mac = adapter.map(|a| a.mac_address.clone()).unwrap_or_default();

        let name = match adapter {
            Some(ad) if !ad.name.is_empty() => ad.name.clone(),
            _ if !ip.interface_alias.is_empty() => ip.interface_alias.clone(),
            _ => {
                logger::log_to_file(&format!(
                    "  IP {}: no adapter name found (index={})",
                    ip.ip_address, ip.interface_index
                ));
                continue;
            }
        };

        let is_virt = is_virtual_adapter(&name);

        let key = (ip.interface_index, name.clone());
        let entry = by_key.entry(key).or_insert_with(|| InterfaceInfo {
            name: name.clone(),
            ipv4: String::new(),
            ipv6: Vec::new(),
            mac: mac.clone(),
            is_virtual: is_virt,
        });

        if is_ipv6_address(&ip.ip_address) {
            if !is_usable_ipv6(&ip.ip_address) {
                logger::log_to_file(&format!("  IPv6 skip: {} (not usable)", ip.ip_address));
                continue;
            }
            if !entry.ipv6.contains(&ip.ip_address) {
                entry.ipv6.push(ip.ip_address.clone());
            }
        } else {
            entry.ipv4 = ip.ip_address.clone();
        }

        logger::log_to_file(&format!(
            "  IP {} ({}) -> adapter '{}' (idx={}, virtual={}, mac={})",
            ip.ip_address,
            ps_address_family(&ip.address_family),
            name,
            ip.interface_index,
            is_virt,
            mac
        ));
    }

    Some(by_key.into_values().collect())
}

fn ps_address_family(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Number(n) if n.as_u64() == Some(2) => "IPv4",
        serde_json::Value::Number(n) if n.as_u64() == Some(23) => "IPv6",
        serde_json::Value::String(s) if s.eq_ignore_ascii_case("IPv6") => "IPv6",
        _ => "IPv4",
    }
}

/// Fallback: parse `ipconfig /all` text output.
fn get_interfaces_via_ipconfig() -> Result<Vec<InterfaceInfo>, String> {
    let output = process::run_query("ipconfig", &["/all"])
        .map_err(|error| format!("Network detection failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Network detection failed: ipconfig exited with {:?}",
            output.status.code()
        ));
    }
    let text = encoding::decode(&output.stdout);
    parse_ipconfig_fallback(&text)
}

fn parse_ipconfig_fallback(text: &str) -> Result<Vec<InterfaceInfo>, String> {
    let interfaces = parse_ipconfig_interfaces(text);
    if interfaces.is_empty() {
        // Text output is localized, so an empty parse is not proof of a disconnection.
        // Only a successful PowerShell snapshot can confirm an empty network.
        Err("Network detection failed: ipconfig returned no recognized IPv4 addresses".into())
    } else {
        Ok(interfaces)
    }
}

fn parse_ipconfig_interfaces(text: &str) -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_ipv4 = String::new();
    let mut current_mac = String::new();

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
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
                    ipv6: Vec::new(),
                    mac: current_mac.clone(),
                    is_virtual: is_virtual_adapter(&current_name),
                });
            }
            current_name = trimmed.trim_end_matches(':').to_string();
            current_ipv4.clear();
            current_mac.clear();
        } else if trimmed.starts_with("IPv4 Address") || trimmed.contains("IPv4 地址") {
            if let Some(addr) = trimmed.split(':').next_back() {
                let addr = addr
                    .trim()
                    .replace("(Preferred)", "")
                    .replace("(首选)", "")
                    .trim()
                    .to_string();
                if !addr.is_empty() {
                    current_ipv4 = addr;
                }
            }
        } else if trimmed.starts_with("Physical Address") || trimmed.contains("物理地址") {
            if let Some(addr) = trimmed.split(':').next_back() {
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
            ipv6: Vec::new(),
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
        .filter(|ip| ip.parse::<Ipv4Addr>().is_ok() && ip != "0.0.0.0" && seen.insert(ip.clone()))
        .collect()
}

pub fn is_apipa_ipv4(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>()
        .map(|a| {
            let o = a.octets();
            o[0] == 169 && o[1] == 254
        })
        .unwrap_or(false)
}

pub fn is_usable_gateway_ipv4(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<Ipv4Addr>() {
        let o = addr.octets();
        if o == [0, 0, 0, 0] {
            return false;
        }
        if o[0] == 127 {
            return false;
        }
        if o[0] == 169 && o[1] == 254 {
            return false;
        }
        if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
            return false;
        }
        if o[0] >= 224 {
            return false;
        }
        if o == [255, 255, 255, 255] {
            return false;
        }
        true
    } else {
        false
    }
}

pub fn gateway_ip_priority(ip: &str) -> u8 {
    if let Ok(addr) = ip.parse::<Ipv4Addr>() {
        let o = addr.octets();
        if o[0] == 10 {
            return 1;
        }
        if o[0] == 172 && (16..=31).contains(&o[1]) {
            return 2;
        }
        if o[0] == 192 && o[1] == 168 {
            return 3;
        }
        return 4;
    }
    5
}

pub fn usable_gateway_ipv4_addresses(interfaces: &[InterfaceInfo]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    interfaces
        .iter()
        .map(|i| i.ipv4.clone())
        .filter(|ip| is_usable_gateway_ipv4(ip) && seen.insert(ip.clone()))
        .collect()
}

pub fn ipv6_addresses_from(interfaces: &[InterfaceInfo]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    interfaces
        .iter()
        .flat_map(|i| i.ipv6.iter().cloned())
        .filter(|ip| seen.insert(ip.clone()))
        .collect()
}

pub fn is_ipv6_address(ip: &str) -> bool {
    ip.parse::<Ipv6Addr>().is_ok()
}

pub fn is_usable_ipv6(ip: &str) -> bool {
    ip.parse::<Ipv6Addr>()
        .map(|addr| {
            !addr.is_loopback()
                && !addr.is_unspecified()
                && !addr.is_multicast()
                && !addr.is_unique_local()
        })
        .unwrap_or(false)
}

pub fn is_virtual_adapter(name: &str) -> bool {
    let lower = name.to_lowercase();
    let keywords = [
        "hyper-v",
        "wsl",
        "docker",
        "vpn",
        "virtual",
        "tun",
        "tap",
        "clash",
        "vethernet",
        "vmware",
        "virtualbox",
        "tailscale",
        "zerotier",
        "wireguard",
        "pangp",
        "sangfor",
        "easyconnect",
        "loopback",
        "pseudo",
        "tunnel",
        "6to4",
        "teredo",
        "isatap",
        "bluetooth",
        "wan miniport",
        "vbox",
        "host-only",
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
            logger::log_to_file(&format!(
                "select_preferred_ip: manual override -> {}",
                preferred
            ));
            return preferred.to_string();
        }
        logger::log_to_file(&format!(
            "select_preferred_ip: manual '{}' not found, falling back to auto",
            preferred
        ));
    }

    let candidates: Vec<&String> = ipv4s
        .iter()
        .filter(|ip| is_usable_gateway_ipv4(ip))
        .collect();

    logger::log_to_file(&format!(
        "select_preferred_ip: {} total, {} candidates after filter",
        ipv4s.len(),
        candidates.len()
    ));

    if candidates.is_empty() {
        logger::log_to_file("select_preferred_ip: no candidates, returning empty");
        return String::new();
    }

    fn is_lan_ip(ip: &str) -> bool {
        matches!(gateway_ip_priority(ip), 1..=3)
    }

    let mut best: Option<&String> = None;
    let mut best_prio = 99u8;
    for ip in &candidates {
        let iface = interfaces.iter().find(|i| &i.ipv4 == *ip);
        if is_lan_ip(ip) && iface.map(|i| !i.is_virtual).unwrap_or(true) {
            let p = gateway_ip_priority(ip);
            if p < best_prio {
                best_prio = p;
                best = Some(ip);
            }
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
    if ip.is_empty() {
        return "Unknown";
    }
    interfaces
        .iter()
        .find(|i| i.ipv4 == ip)
        .map(|i| i.name.as_str())
        .unwrap_or("Unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrecognized_ipconfig_fallback_is_not_a_confirmed_empty_network() {
        let text = "Windows-IP-Konfiguration\n\nEthernet-Adapter Ethernet:\n   IPv4-Adresse. . . . . . . . . . . : 192.0.2.10(Bevorzugt)\n";
        assert!(parse_ipconfig_fallback(text).is_err());
        assert!(parse_ipconfig_fallback("").is_err());
        let english = "Ethernet adapter Ethernet:\n   IPv4 Address. . . . . . . . . . . : 192.0.2.10(Preferred)\n";
        assert_eq!(
            parse_ipconfig_fallback(english).unwrap()[0].ipv4,
            "192.0.2.10"
        );
    }

    #[test]
    fn ipconfig_preserves_adapter_across_blank_lines() {
        let text = "Windows IP Configuration\n\nEthernet adapter Ethernet:\n\n   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF\n   IPv4 Address. . . . . . . . . . . : 192.168.1.10(Preferred)\n\nWireless LAN adapter Wi-Fi:\n\n   IPv4 Address. . . . . . . . . . . : 10.0.0.10(Preferred)\n";
        let interfaces = parse_ipconfig_interfaces(text);
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].ipv4, "192.168.1.10");
        assert_eq!(interfaces[0].mac, "AA-BB-CC-DD-EE-FF");
        assert_eq!(interfaces[1].ipv4, "10.0.0.10");
    }

    #[test]
    fn ipv4_addresses_exclude_empty_ipv6_only_adapters() {
        assert!(ipv4_addresses_from(&[make_iface("IPv6 only", "", false)]).is_empty());
    }

    fn make_iface(name: &str, ip: &str, is_virtual: bool) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            ipv4: ip.into(),
            ipv6: Vec::new(),
            mac: String::new(),
            is_virtual,
        }
    }

    // --- JSON parsing ---

    #[test]
    fn combined_powershell_snapshot_joins_addresses_and_adapters() {
        let json = r#"{"IPAddresses":[{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"IPAddress":"192.0.2.10","AddressFamily":2},{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"IPAddress":"2001:db8::10","AddressFamily":23}],"Adapters":[{"Name":"Ethernet","InterfaceIndex":12,"MacAddress":"00-00-5E-00-53-01"}]}"#;
        let result = parse_powershell_snapshot(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ipv4, "192.0.2.10");
        assert_eq!(result[0].ipv6, vec!["2001:db8::10"]);
        assert_eq!(result[0].mac, "00-00-5E-00-53-01");
    }

    #[test]
    fn combined_snapshot_handles_missing_adapters_empty_arrays_and_invalid_json() {
        let json = r#"{"IPAddresses":{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"IPAddress":"192.0.2.10"},"Adapters":null}"#;
        let result = parse_powershell_snapshot(json).unwrap();
        assert_eq!(result[0].name, "Ethernet");
        assert!(result[0].mac.is_empty());
        assert!(
            parse_powershell_snapshot(r#"{"IPAddresses":[],"Adapters":[]}"#)
                .unwrap()
                .is_empty()
        );
        assert!(parse_powershell_snapshot("invalid").is_none());
        assert!(parse_powershell_snapshot(r#"{"Adapters":[]}"#).is_none());
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
    fn join_ipv4_and_ipv6_on_same_adapter() {
        let ip_json = r#"[{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"IPAddress":"10.0.0.1","AddressFamily":"IPv4"},{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"IPAddress":"2001:db8::10","AddressFamily":"IPv6"}]"#;
        let ad_json = r#"{"Name":"Ethernet","InterfaceIndex":12,"MacAddress":"AA-BB"}"#;
        let result = parse_powershell_output(ip_json, ad_json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ipv4, "10.0.0.1");
        assert_eq!(result[0].ipv6, vec!["2001:db8::10".to_string()]);
    }

    // --- IP classification ---

    #[test]
    fn apipa_ipv4_is_detected() {
        assert!(is_apipa_ipv4("169.254.1.2"));
        assert!(is_apipa_ipv4("169.254.0.1"));
        assert!(!is_apipa_ipv4("169.253.1.1"));
        assert!(!is_apipa_ipv4("10.0.0.1"));
    }

    #[test]
    fn usable_gateway_ipv4_filters_specials() {
        assert!(is_usable_gateway_ipv4("10.0.0.1"));
        assert!(is_usable_gateway_ipv4("172.16.0.1"));
        assert!(is_usable_gateway_ipv4("192.168.1.1"));
        assert!(is_usable_gateway_ipv4("100.64.0.1"));
        assert!(!is_usable_gateway_ipv4("0.0.0.0"));
        assert!(!is_usable_gateway_ipv4("127.0.0.1"));
        assert!(!is_usable_gateway_ipv4("169.254.1.2"));
        assert!(!is_usable_gateway_ipv4("198.18.0.1"));
        assert!(!is_usable_gateway_ipv4("198.19.0.1"));
        assert!(!is_usable_gateway_ipv4("224.0.0.1"));
        assert!(!is_usable_gateway_ipv4("255.255.255.255"));
    }

    #[test]
    fn usable_ipv6_filters_loopback_and_local_only() {
        assert!(!is_usable_ipv6("::1"));
        assert!(!is_usable_ipv6("::"));
        assert!(!is_usable_ipv6("ff02::1"));
        assert!(!is_usable_ipv6("fd00::1"));
        assert!(is_usable_ipv6("2001:db8::1"));
    }

    #[test]
    fn gateway_ip_priority_order() {
        assert_eq!(gateway_ip_priority("10.0.0.1"), 1);
        assert_eq!(gateway_ip_priority("172.16.0.1"), 2);
        assert_eq!(gateway_ip_priority("172.31.255.255"), 2);
        assert_eq!(gateway_ip_priority("172.15.0.1"), 4); // not 172.16/12
        assert_eq!(gateway_ip_priority("192.168.1.1"), 3);
        assert_eq!(gateway_ip_priority("100.64.0.1"), 4);
        assert_eq!(gateway_ip_priority("invalid"), 5);
    }

    #[test]
    fn usable_gateway_ipv4_addresses_filters_apipa() {
        let ifaces = vec![
            make_iface("Ethernet1", "169.254.1.2", false),
            make_iface("Ethernet2", "10.0.0.1", false),
        ];
        let usable = usable_gateway_ipv4_addresses(&ifaces);
        assert!(!usable.contains(&"169.254.1.2".to_string()));
        assert!(usable.contains(&"10.0.0.1".to_string()));
    }

    // --- Preferred IP selection ---

    #[test]
    fn select_preferred_ip_prioritizes_lan() {
        let ips = vec![
            "198.18.0.1".to_string(),
            "192.168.100.6".to_string(),
            "10.108.18.68".to_string(),
        ];
        let ifaces = vec![
            make_iface("TUN", "198.18.0.1", true),
            make_iface("Wi-Fi", "192.168.100.6", false),
            make_iface("Ethernet", "10.108.18.68", false),
        ];
        assert_eq!(select_preferred_ip(&ips, "auto", &ifaces), "10.108.18.68");
    }

    #[test]
    fn select_preferred_ip_excludes_apipa() {
        assert_eq!(
            select_preferred_ip(
                &["169.254.1.1".into(), "10.0.0.1".into()],
                "auto",
                &[make_iface("Ethernet", "10.0.0.1", false)]
            ),
            "10.0.0.1"
        );
    }

    #[test]
    fn select_preferred_ip_excludes_198_18_and_198_19() {
        let ips = vec![
            "169.254.1.2".into(),
            "198.18.0.1".into(),
            "198.19.0.1".into(),
            "192.168.100.6".into(),
            "10.108.18.68".into(),
        ];
        let result = select_preferred_ip(
            &ips,
            "auto",
            &[make_iface("Ethernet", "10.108.18.68", false)],
        );
        assert_eq!(result, "10.108.18.68");
    }

    #[test]
    fn select_preferred_ip_all_apipa_returns_empty() {
        let result =
            select_preferred_ip(&["169.254.1.2".into(), "169.254.200.1".into()], "auto", &[]);
        assert_eq!(result, "");
    }

    #[test]
    fn select_preferred_ip_manual_override() {
        assert_eq!(
            select_preferred_ip(
                &["10.0.0.1".into(), "192.168.1.1".into()],
                "192.168.1.1",
                &[]
            ),
            "192.168.1.1"
        );
    }

    #[test]
    fn select_preferred_ip_manual_missing_falls_back() {
        assert_eq!(
            select_preferred_ip(
                &["10.0.0.1".into()],
                "10.99.99.99",
                &[make_iface("Ethernet", "10.0.0.1", false)]
            ),
            "10.0.0.1"
        );
    }

    #[test]
    fn select_preferred_ip_no_usable_returns_empty() {
        assert_eq!(select_preferred_ip(&[], "auto", &[]), "");
    }

    #[test]
    fn select_preferred_ip_excludes_zeros() {
        assert_eq!(
            select_preferred_ip(
                &["0.0.0.0".into(), "127.0.0.1".into(), "10.0.0.1".into()],
                "auto",
                &[make_iface("Ethernet", "10.0.0.1", false)]
            ),
            "10.0.0.1"
        );
    }

    #[test]
    fn select_preferred_ip_excludes_multicast() {
        let result = select_preferred_ip(
            &["224.0.0.1".into(), "10.0.0.1".into()],
            "auto",
            &[make_iface("Ethernet", "10.0.0.1", false)],
        );
        assert_eq!(result, "10.0.0.1");
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
