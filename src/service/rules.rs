use crate::core::health;
use crate::core::model::{
    ForwardRule, HealthStatus, OrphanKey, PortproxyEntry, ProxyMode, ProxyProtocol,
};
use crate::storage::config::Config;
use crate::system::{firewall, portproxy};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RuleForm {
    pub id: String,
    pub name: String,
    pub notes: String,
    pub listen_address: String,
    pub listen_port: u16,
    pub connect_address: String,
    pub connect_port: u16,
    pub protocol: ProxyProtocol,
    pub proxy_mode: ProxyMode,
    pub enabled: bool,
    pub firewall_managed: bool,
    pub mdns_publish: bool,
    pub tags: Vec<String>,
}

impl RuleForm {
    pub fn into_rule(mut self) -> ForwardRule {
        if self.listen_address.trim().is_empty() {
            self.listen_address = self.proxy_mode.listen_any_address().into();
        }
        let mut rule = ForwardRule {
            id: self.id,
            name: if self.name.trim().is_empty() {
                format!("Rule-{}", self.listen_port)
            } else {
                self.name.trim().into()
            },
            notes: self.notes.trim().into(),
            listen_address: self.listen_address.trim().into(),
            listen_port: self.listen_port,
            connect_address: self.connect_address.trim().into(),
            connect_port: self.connect_port,
            managed: true,
            protocol: self.protocol,
            proxy_mode: self.proxy_mode,
            enabled: self.enabled,
            firewall_managed: self.firewall_managed,
            mdns_publish: self.mdns_publish,
            tags: self.tags,
        };
        rule.ensure_id();
        rule
    }
}

pub struct RuleService {
    config_path: PathBuf,
}

impl RuleService {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }

    pub fn add_rule(
        &self,
        config: &mut Config,
        actual_entries: &[PortproxyEntry],
        form: RuleForm,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        let rule = form.into_rule();
        self.preflight(config, actual_entries, &rule, None, is_admin)?;
        self.apply_add(&rule)?;
        config.rules.push(rule);
        config.normalize();
        self.save_config(config)?;
        portproxy::show_all()
    }

    pub fn update_rule(
        &self,
        config: &mut Config,
        actual_entries: &[PortproxyEntry],
        index: usize,
        form: RuleForm,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        if index >= config.rules.len() {
            return Err("Invalid rule index".into());
        }
        let new_rule = form.into_rule();
        self.preflight(config, actual_entries, &new_rule, Some(index), is_admin)?;

        let old_rule = config.rules[index].clone();
        if old_rule.netsh_entry() != new_rule.netsh_entry()
            || old_rule.enabled != new_rule.enabled
            || old_rule.protocol != new_rule.protocol
        {
            if old_rule.enabled && old_rule.protocol == ProxyProtocol::Tcp {
                let _ = portproxy::delete_entry(&old_rule.netsh_entry());
            }
            self.apply_add(&new_rule)?;
        }

        if old_rule.firewall_managed && old_rule.id != new_rule.id {
            firewall::delete_rule(&firewall::tcp_rule_name(&old_rule)).ok();
        }

        config.rules[index] = new_rule;
        config.normalize();
        self.save_config(config)?;
        portproxy::show_all()
    }

    pub fn set_rule_enabled(
        &self,
        config: &mut Config,
        actual_entries: &[PortproxyEntry],
        index: usize,
        enabled: bool,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        if !is_admin {
            return Err("Administrator permission is required".into());
        }
        if index >= config.rules.len() {
            return Err("Invalid rule index".into());
        }

        let current_rule = config.rules[index].clone();
        if current_rule.enabled == enabled {
            return Ok(actual_entries.to_vec());
        }

        let mut next_rule = current_rule.clone();
        next_rule.enabled = enabled;

        if enabled {
            self.preflight(config, actual_entries, &next_rule, Some(index), is_admin)?;
            let entry = next_rule.netsh_entry();
            if actual_contains_entry(actual_entries, &entry) {
                if next_rule.firewall_managed {
                    firewall::ensure_tcp_rule(&next_rule)?;
                }
            } else {
                self.apply_add(&next_rule)?;
            }
        } else {
            let entry = current_rule.netsh_entry();
            if current_rule.protocol == ProxyProtocol::Tcp
                && actual_contains_entry(actual_entries, &entry)
            {
                portproxy::delete_entry(&entry)?;
            }
            if current_rule.firewall_managed {
                firewall::delete_rule(&firewall::tcp_rule_name(&current_rule)).ok();
            }
        }

        config.rules[index] = next_rule;
        config.normalize();
        self.save_config(config)?;
        portproxy::show_all()
    }

    pub fn delete_rule(
        &self,
        config: &mut Config,
        index: usize,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        if !is_admin {
            return Err("Administrator permission is required".into());
        }
        if index >= config.rules.len() {
            return Err("Invalid rule index".into());
        }
        let rule = config.rules.remove(index);
        if rule.enabled && rule.protocol == ProxyProtocol::Tcp {
            portproxy::delete_entry(&rule.netsh_entry())?;
        }
        if rule.firewall_managed {
            firewall::delete_rule(&firewall::tcp_rule_name(&rule)).ok();
        }
        self.save_config(config)?;
        portproxy::show_all()
    }

    pub fn delete_orphan(
        &self,
        entry: &PortproxyEntry,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        if !is_admin {
            return Err("Administrator permission is required".into());
        }
        portproxy::delete_entry(entry)?;
        portproxy::show_all()
    }

    pub fn adopt_orphan(&self, config: &mut Config, entry: &PortproxyEntry) -> Result<(), String> {
        let mut rule = ForwardRule {
            id: String::new(),
            name: format!("Adopted-{}", entry.listen_port),
            notes: "Imported from existing Windows PortProxy rule".into(),
            listen_address: entry.listen_address.clone(),
            listen_port: entry.listen_port,
            connect_address: entry.connect_address.clone(),
            connect_port: entry.connect_port,
            managed: true,
            protocol: ProxyProtocol::Tcp,
            proxy_mode: entry.proxy_mode,
            enabled: true,
            firewall_managed: false,
            mdns_publish: false,
            tags: vec!["adopted".into()],
        };
        rule.ensure_id();
        config.rules.push(rule);
        config.normalize();
        self.save_config(config)
    }

    pub fn adopt_all_orphans(
        &self,
        config: &mut Config,
        entries: &[PortproxyEntry],
    ) -> Result<usize, String> {
        let orphans = orphan_entries(config, entries);
        let count = orphans.len();
        for entry in orphans {
            self.adopt_orphan(config, &entry)?;
        }
        Ok(count)
    }

    pub fn save_config(&self, config: &Config) -> Result<(), String> {
        config.save(&self.config_path)
    }

    fn apply_add(&self, rule: &ForwardRule) -> Result<(), String> {
        if rule.protocol == ProxyProtocol::Udp {
            return Err(
                "UDP is not supported by Windows portproxy; use TCP or a future relay mode".into(),
            );
        }
        if rule.enabled {
            portproxy::add_entry(&rule.netsh_entry())?;
            if rule.firewall_managed {
                firewall::ensure_tcp_rule(rule)?;
            }
        }
        Ok(())
    }

    fn preflight(
        &self,
        config: &Config,
        actual_entries: &[PortproxyEntry],
        rule: &ForwardRule,
        editing_index: Option<usize>,
        is_admin: bool,
    ) -> Result<(), String> {
        if !is_admin {
            return Err("Administrator permission is required".into());
        }
        if rule.listen_port == 0 || rule.connect_port == 0 {
            return Err("Ports must be in the range 1-65535".into());
        }
        if rule.connect_address.trim().is_empty() {
            return Err("Target address is required".into());
        }
        if rule.protocol == ProxyProtocol::Udp {
            return Err("UDP is not supported by Windows portproxy; TCP only for now".into());
        }
        validate_address_for_mode(rule)?;
        detect_duplicate_config_rule(config, rule, editing_index)?;
        detect_actual_port_conflict(
            actual_entries,
            rule,
            editing_index.map(|i| &config.rules[i]),
        )?;
        validate_target_resolves(rule)?;
        Ok(())
    }
}

fn actual_contains_entry(entries: &[PortproxyEntry], wanted: &PortproxyEntry) -> bool {
    entries
        .iter()
        .any(|entry| entry.stable_key() == wanted.stable_key())
}

pub fn orphan_entries(config: &Config, entries: &[PortproxyEntry]) -> Vec<PortproxyEntry> {
    entries
        .iter()
        .filter(|e| {
            !config.rules.iter().any(|r| {
                r.proxy_mode == e.proxy_mode
                    && r.listen_address == e.listen_address
                    && r.listen_port == e.listen_port
                    && r.connect_address == e.connect_address
                    && r.connect_port == e.connect_port
            })
        })
        .cloned()
        .collect()
}

pub fn run_health_checks(
    rules: &[ForwardRule],
    proxy_entries: &[PortproxyEntry],
) -> (
    HashMap<usize, HealthStatus>,
    HashMap<OrphanKey, HealthStatus>,
) {
    let mut health_map = HashMap::new();
    for (i, rule) in rules.iter().enumerate() {
        let status = health::check_rule(rule, proxy_entries);
        health_map.insert(i, status);
    }

    let cfg = Config {
        rules: rules.to_vec(),
        ..Default::default()
    };
    let mut orphan_health = HashMap::new();
    for entry in orphan_entries(&cfg, proxy_entries) {
        orphan_health.insert(OrphanKey::from_entry(&entry), health::check_orphan(&entry));
    }

    (health_map, orphan_health)
}

fn detect_duplicate_config_rule(
    config: &Config,
    rule: &ForwardRule,
    editing_index: Option<usize>,
) -> Result<(), String> {
    let duplicate = config.rules.iter().enumerate().any(|(idx, existing)| {
        Some(idx) != editing_index
            && existing.enabled
            && existing.protocol == rule.protocol
            && existing.proxy_mode == rule.proxy_mode
            && existing.listen_address == rule.listen_address
            && existing.listen_port == rule.listen_port
    });
    if duplicate {
        Err(format!(
            "A managed rule already listens on {}:{} ({})",
            rule.listen_address,
            rule.listen_port,
            rule.proxy_mode.netsh_name()
        ))
    } else {
        Ok(())
    }
}

fn detect_actual_port_conflict(
    entries: &[PortproxyEntry],
    rule: &ForwardRule,
    old_rule: Option<&ForwardRule>,
) -> Result<(), String> {
    let old_key = old_rule.map(|r| r.netsh_entry().stable_key());
    let conflict = entries.iter().any(|entry| {
        old_key.as_ref() != Some(&entry.stable_key())
            && entry.proxy_mode == rule.proxy_mode
            && entry.listen_address == rule.listen_address
            && entry.listen_port == rule.listen_port
    });
    if conflict {
        Err(format!(
            "Windows already has a portproxy rule on {}:{} ({})",
            rule.listen_address,
            rule.listen_port,
            rule.proxy_mode.netsh_name()
        ))
    } else {
        Ok(())
    }
}

fn validate_address_for_mode(rule: &ForwardRule) -> Result<(), String> {
    match rule.proxy_mode {
        ProxyMode::V4ToV4 => {
            require_ip_family(&rule.listen_address, 4)?;
            require_target_family(&rule.connect_address, rule.connect_port, 4)
        }
        ProxyMode::V4ToV6 => {
            require_ip_family(&rule.listen_address, 4)?;
            require_target_family(&rule.connect_address, rule.connect_port, 6)
        }
        ProxyMode::V6ToV4 => {
            require_ip_family(&rule.listen_address, 6)?;
            require_target_family(&rule.connect_address, rule.connect_port, 4)
        }
        ProxyMode::V6ToV6 => {
            require_ip_family(&rule.listen_address, 6)?;
            require_target_family(&rule.connect_address, rule.connect_port, 6)
        }
    }
}

fn require_ip_family(address: &str, family: u8) -> Result<(), String> {
    if address == "0.0.0.0" && family == 4 {
        return Ok(());
    }
    if address == "::" && family == 6 {
        return Ok(());
    }
    let parsed: IpAddr = address
        .parse()
        .map_err(|_| format!("Invalid listen address: {}", address))?;
    match (parsed, family) {
        (IpAddr::V4(_), 4) | (IpAddr::V6(_), 6) => Ok(()),
        _ => Err(format!("Listen address does not match v{} mode", family)),
    }
}

fn require_target_family(address: &str, port: u16, family: u8) -> Result<(), String> {
    if let Ok(parsed) = address.parse::<IpAddr>() {
        return match (parsed, family) {
            (IpAddr::V4(_), 4) | (IpAddr::V6(_), 6) => Ok(()),
            _ => Err(format!("Target address does not match v{} mode", family)),
        };
    }

    let has_family = (address, port)
        .to_socket_addrs()
        .map(|mut addrs| {
            addrs.any(|addr| matches!((addr.ip(), family), (IpAddr::V4(_), 4) | (IpAddr::V6(_), 6)))
        })
        .unwrap_or(false);
    if has_family {
        Ok(())
    } else {
        Err(format!("Target host does not resolve to IPv{}", family))
    }
}

fn validate_target_resolves(rule: &ForwardRule) -> Result<(), String> {
    if rule.connect_address.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    (rule.connect_address.as_str(), rule.connect_port)
        .to_socket_addrs()
        .map_err(|e| format!("Target DNS resolve failed: {}", e))
        .and_then(|mut a| {
            if a.next().is_some() {
                Ok(())
            } else {
                Err("Target DNS resolved no addresses".into())
            }
        })
}

#[allow(dead_code)]
pub fn service_for_path(path: &Path) -> RuleService {
    RuleService::new(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(port: u16) -> ForwardRule {
        let mut rule = ForwardRule {
            id: String::new(),
            name: "Web".into(),
            notes: String::new(),
            listen_address: "0.0.0.0".into(),
            listen_port: port,
            connect_address: "127.0.0.1".into(),
            connect_port: 80,
            managed: true,
            protocol: ProxyProtocol::Tcp,
            proxy_mode: ProxyMode::V4ToV4,
            enabled: true,
            firewall_managed: false,
            mdns_publish: false,
            tags: vec![],
        };
        rule.ensure_id();
        rule
    }

    #[test]
    fn orphan_detection_uses_proxy_mode() {
        let mut config = Config::default();
        config.rules.push(make_rule(8080));
        let entries = vec![
            config.rules[0].netsh_entry(),
            PortproxyEntry {
                proxy_mode: ProxyMode::V6ToV4,
                listen_address: "::".into(),
                listen_port: 8080,
                connect_address: "127.0.0.1".into(),
                connect_port: 80,
            },
        ];
        let orphans = orphan_entries(&config, &entries);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].proxy_mode, ProxyMode::V6ToV4);
    }

    #[test]
    fn duplicate_config_rule_is_rejected() {
        let mut config = Config::default();
        config.rules.push(make_rule(8080));
        let err = detect_duplicate_config_rule(&config, &make_rule(8080), None).unwrap_err();
        assert!(err.contains("already listens"));
    }

    #[test]
    fn v4_rule_rejects_v6_listen_address() {
        let mut rule = make_rule(8080);
        rule.listen_address = "::".into();
        assert!(validate_address_for_mode(&rule).is_err());
    }

    #[test]
    fn v6_to_v4_accepts_ipv6_listen_and_ipv4_target() {
        let mut rule = make_rule(8080);
        rule.proxy_mode = ProxyMode::V6ToV4;
        rule.listen_address = "::".into();
        rule.connect_address = "127.0.0.1".into();
        assert!(validate_address_for_mode(&rule).is_ok());
    }
}
