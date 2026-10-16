use crate::core::health;
use crate::core::model::{
    ForwardRule, HealthStatus, OrphanKey, PortproxyEntry, ProxyMode, ProxyProtocol,
};
use crate::storage::config::Config;
use crate::system::process::{CommandExecutor, SystemCommandExecutor};
use crate::system::{firewall, portproxy};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
            listen_address: self
                .listen_address
                .trim()
                .parse::<IpAddr>()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| self.listen_address.trim().into()),
            listen_port: self.listen_port,
            connect_address: self
                .connect_address
                .trim()
                .parse::<IpAddr>()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| self.connect_address.trim().into()),
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

#[derive(Clone)]
pub struct RuleService {
    config_path: PathBuf,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
}

impl RuleService {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            executor: Arc::new(SystemCommandExecutor),
        }
    }

    pub fn add_rule(
        &self,
        config: &mut Config,
        form: RuleForm,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        let mut rule = form.into_rule();
        let entries = self.read_entries(is_admin)?;
        self.preflight(config, &entries, &rule, None, is_admin)?;
        let mut next = config.clone();
        next.rules.push(rule.clone());
        next.normalize();
        rule = next.rules.last().unwrap().clone();
        self.commit_change(config, next, None, Some(&rule), entries)
    }

    pub fn update_rule(
        &self,
        config: &mut Config,
        index: usize,
        form: RuleForm,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        if index >= config.rules.len() {
            return Err("Invalid rule index".into());
        }
        let old_rule = config.rules[index].clone();
        let mut new_rule = form.into_rule();
        new_rule.id = old_rule.id.clone();
        let entries = self.read_entries(is_admin)?;
        self.preflight(config, &entries, &new_rule, Some(index), is_admin)?;
        let mut next = config.clone();
        next.rules[index] = new_rule.clone();
        self.commit_change(config, next, Some(&old_rule), Some(&new_rule), entries)
    }

    pub fn set_rule_enabled(
        &self,
        config: &mut Config,
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

        let entries = self.read_entries(is_admin)?;
        let current_rule = config.rules[index].clone();
        if current_rule.enabled == enabled {
            return Ok(entries);
        }

        let mut next_rule = current_rule.clone();
        next_rule.enabled = enabled;

        if enabled {
            self.preflight(config, &entries, &next_rule, Some(index), is_admin)?;
        }
        let mut next = config.clone();
        next.rules[index] = next_rule.clone();
        self.commit_change(config, next, Some(&current_rule), Some(&next_rule), entries)
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
        let entries = self.read_entries(is_admin)?;
        let rule = config.rules[index].clone();
        let mut next = config.clone();
        next.rules.remove(index);
        self.commit_change(config, next, Some(&rule), None, entries)
    }

    pub fn delete_orphan(
        &self,
        entry: &PortproxyEntry,
        is_admin: bool,
    ) -> Result<Vec<PortproxyEntry>, String> {
        if !is_admin {
            return Err("Administrator permission is required".into());
        }
        let mut entries = self.read_entries(is_admin)?;
        if !entries.contains(entry) {
            return Err("The Windows rule changed; refresh before deleting it".into());
        }
        portproxy::delete_entry_with(self.executor.as_ref(), entry)?;
        entries.retain(|existing| existing != entry);
        Ok(entries)
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
        if config.rules.iter().any(|existing| {
            existing.protocol == ProxyProtocol::Tcp && existing.netsh_entry() == *entry
        }) {
            return Ok(());
        }
        let mut next = config.clone();
        next.rules.push(rule);
        next.normalize();
        self.save_config(&next)?;
        *config = next;
        Ok(())
    }

    pub fn adopt_all_orphans(
        &self,
        config: &mut Config,
        entries: &[PortproxyEntry],
    ) -> Result<usize, String> {
        let orphans = orphan_entries(config, entries);
        let count = orphans.len();
        let mut next = config.clone();
        for entry in orphans {
            // Build the imported config in memory; save the batch only once.
            let mut rule = RuleForm {
                id: String::new(),
                name: format!("Adopted-{}", entry.listen_port),
                notes: "Imported from existing Windows PortProxy rule".into(),
                listen_address: entry.listen_address,
                listen_port: entry.listen_port,
                connect_address: entry.connect_address,
                connect_port: entry.connect_port,
                protocol: ProxyProtocol::Tcp,
                proxy_mode: entry.proxy_mode,
                enabled: true,
                firewall_managed: false,
                mdns_publish: false,
                tags: vec!["adopted".into()],
            }
            .into_rule();
            rule.ensure_id();
            next.rules.push(rule);
        }
        if count > 0 {
            next.normalize();
            self.save_config(&next)?;
            *config = next;
        }
        Ok(count)
    }

    pub fn save_config(&self, config: &Config) -> Result<(), String> {
        config.save(&self.config_path)
    }

    fn read_entries(&self, is_admin: bool) -> Result<Vec<PortproxyEntry>, String> {
        if !is_admin {
            return Err("Administrator permission is required".into());
        }
        portproxy::show_all_with(self.executor.as_ref())
    }

    fn commit_change(
        &self,
        config: &mut Config,
        mut next: Config,
        old_rule: Option<&ForwardRule>,
        new_rule: Option<&ForwardRule>,
        mut entries: Vec<PortproxyEntry>,
    ) -> Result<Vec<PortproxyEntry>, String> {
        let exec = self.executor.as_ref();
        let active_entry = |rule: &ForwardRule| {
            (rule.enabled && rule.protocol == ProxyProtocol::Tcp).then(|| rule.netsh_entry())
        };
        let old_entry = old_rule.and_then(active_entry);
        let new_entry = new_rule.and_then(active_entry);
        let remove_old = old_entry
            .as_ref()
            .filter(|e| Some(*e) != new_entry.as_ref() && entries.contains(e));
        let add_new = new_entry.as_ref().filter(|e| !entries.contains(e));
        let new_firewall = new_rule
            .filter(|r| r.enabled && r.protocol == ProxyProtocol::Tcp && r.firewall_managed);
        let mut firewall_before = Vec::new();
        if let Some(rule) = old_rule.filter(|r| r.firewall_managed) {
            let exists = firewall::query_rule_with(exec, &firewall::tcp_rule_name(rule)).exists;
            firewall_before.push((rule.clone(), exists));
        }
        if let Some(rule) = new_firewall {
            if !firewall_before
                .iter()
                .any(|(r, _)| firewall::tcp_rule_name(r) == firewall::tcp_rule_name(rule))
            {
                let exists = firewall::query_rule_with(exec, &firewall::tcp_rule_name(rule)).exists;
                firewall_before.push((rule.clone(), exists));
            }
        }
        let mut removed_old = false;
        let mut added_new = false;
        let mut firewall_changed = false;
        let result = (|| {
            if let Some(entry) = remove_old {
                portproxy::delete_entry_with(exec, entry)?;
                removed_old = true;
            }
            if let Some(entry) = add_new {
                portproxy::add_entry_with(exec, entry)?;
                added_new = true;
            }
            firewall_changed = true;
            for (rule, exists) in &firewall_before {
                let name = firewall::tcp_rule_name(rule);
                if *exists && new_firewall.map(firewall::tcp_rule_name).as_ref() != Some(&name) {
                    firewall::delete_rule_with(exec, &name)?;
                }
            }
            if let Some(rule) = new_firewall {
                firewall::ensure_tcp_rule_with(exec, rule)?;
            }
            next.normalize();
            self.save_config(&next)
        })();
        if let Err(error) = result {
            let mut rollback_errors = Vec::new();
            let mut record = |result: Result<(), String>| {
                if let Err(e) = result {
                    rollback_errors.push(e);
                }
            };
            if added_new {
                record(portproxy::delete_entry_with(exec, add_new.unwrap()));
            }
            if removed_old {
                record(portproxy::add_entry_with(exec, remove_old.unwrap()));
            }
            if firewall_changed {
                for (rule, existed) in &firewall_before {
                    let name = firewall::tcp_rule_name(rule);
                    if *existed {
                        record(firewall::ensure_tcp_rule_with(exec, rule));
                    } else if firewall::query_rule_with(exec, &name).exists {
                        record(firewall::delete_rule_with(exec, &name));
                    }
                }
            }
            return Err(if rollback_errors.is_empty() {
                error
            } else {
                format!(
                    "{}; rollback failed: {}. Refresh status before retrying",
                    error,
                    rollback_errors.join("; ")
                )
            });
        }
        if let Some(entry) = remove_old {
            entries.retain(|e| e != entry);
        }
        if let Some(entry) = add_new {
            entries.push(entry.clone());
        }
        *config = next;
        Ok(entries)
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

pub fn orphan_entries(config: &Config, entries: &[PortproxyEntry]) -> Vec<PortproxyEntry> {
    entries
        .iter()
        .filter(|e| {
            !config.rules.iter().any(|r| {
                r.protocol == ProxyProtocol::Tcp
                    && r.proxy_mode == e.proxy_mode
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
    if !rule.enabled {
        return Ok(());
    }
    let duplicate = config.rules.iter().enumerate().any(|(idx, existing)| {
        Some(idx) != editing_index
            && existing.enabled
            && existing.protocol == rule.protocol
            && listeners_overlap(&existing.netsh_entry(), &rule.netsh_entry())
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
    if !rule.enabled {
        return Ok(());
    }
    let old_key = old_rule.map(|r| r.netsh_entry().stable_key());
    let conflict = entries.iter().any(|entry| {
        old_key.as_ref() != Some(&entry.stable_key())
            && listeners_overlap(entry, &rule.netsh_entry())
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

fn listeners_overlap(a: &PortproxyEntry, b: &PortproxyEntry) -> bool {
    let addresses_overlap = match (
        a.listen_address.parse::<IpAddr>(),
        b.listen_address.parse::<IpAddr>(),
    ) {
        (Ok(a), Ok(b)) => a == b || a.is_unspecified() || b.is_unspecified(),
        _ => a.listen_address == b.listen_address,
    };
    a.listen_port == b.listen_port
        && a.proxy_mode.listen_any_address() == b.proxy_mode.listen_any_address()
        && addresses_overlap
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
    use crate::system::process::CommandOutput;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockWindows {
        entries: Vec<PortproxyEntry>,
        firewall: HashMap<String, u16>,
        fail_add: bool,
        fail_delete: bool,
        fail_firewall_add: bool,
        fail_firewall_delete: bool,
    }

    #[derive(Default)]
    struct MockExecutor(Mutex<MockWindows>);

    impl CommandExecutor for MockExecutor {
        fn run(&self, _: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
            let mut state = self.0.lock().unwrap();
            let value = |key: &str| -> String {
                args.iter()
                    .find_map(|arg| arg.strip_prefix(key))
                    .unwrap_or("")
                    .to_string()
            };
            let mut stdout = String::new();
            let mut success = true;
            if args.contains(&"portproxy") {
                let mode = *ProxyMode::variants()
                    .iter()
                    .find(|mode| mode.netsh_name() == args[3])
                    .unwrap();
                match args[2] {
                    "show" => {
                        stdout = "---\n".into();
                        for entry in state.entries.iter().filter(|e| e.proxy_mode == mode) {
                            stdout.push_str(&format!(
                                "{} {} {} {}\n",
                                entry.listen_address,
                                entry.listen_port,
                                entry.connect_address,
                                entry.connect_port
                            ));
                        }
                    }
                    "add" => {
                        if std::mem::take(&mut state.fail_add) {
                            success = false;
                        } else {
                            state.entries.push(PortproxyEntry {
                                proxy_mode: mode,
                                listen_address: value("listenaddress="),
                                listen_port: value("listenport=").parse().unwrap(),
                                connect_address: value("connectaddress="),
                                connect_port: value("connectport=").parse().unwrap(),
                            });
                        }
                    }
                    "delete" => {
                        if std::mem::take(&mut state.fail_delete) {
                            success = false;
                        } else {
                            let previous_count = state.entries.len();
                            state.entries.retain(|e| {
                                !(e.proxy_mode == mode
                                    && e.listen_address == value("listenaddress=")
                                    && e.listen_port.to_string() == value("listenport="))
                            });
                            success = state.entries.len() != previous_count;
                        }
                    }
                    _ => unreachable!(),
                }
            } else if args.contains(&"firewall") {
                let name = value("name=");
                match args[2] {
                    "show" => success = state.firewall.contains_key(&name),
                    "delete" => {
                        if std::mem::take(&mut state.fail_firewall_delete) {
                            success = false;
                        } else {
                            state.firewall.remove(&name);
                        }
                    }
                    "add" => {
                        if std::mem::take(&mut state.fail_firewall_add) {
                            success = false;
                        } else {
                            state
                                .firewall
                                .insert(name, value("localport=").parse().unwrap());
                        }
                    }
                    _ => unreachable!(),
                }
            } else {
                panic!("unexpected command: {args:?}");
            }
            Ok(CommandOutput {
                status_success: success,
                status_code: Some(if success { 0 } else { 1 }),
                stdout: stdout.into_bytes(),
                stderr: Vec::new(),
            })
        }
    }

    fn test_service() -> (RuleService, Arc<MockExecutor>) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "langateway-transaction-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let executor = Arc::new(MockExecutor::default());
        (
            RuleService {
                config_path: path,
                executor: executor.clone(),
            },
            executor,
        )
    }

    fn form(rule: &ForwardRule) -> RuleForm {
        RuleForm {
            id: rule.id.clone(),
            name: rule.name.clone(),
            notes: rule.notes.clone(),
            listen_address: rule.listen_address.clone(),
            listen_port: rule.listen_port,
            connect_address: rule.connect_address.clone(),
            connect_port: rule.connect_port,
            protocol: rule.protocol,
            proxy_mode: rule.proxy_mode,
            enabled: rule.enabled,
            firewall_managed: rule.firewall_managed,
            mdns_publish: rule.mdns_publish,
            tags: rule.tags.clone(),
        }
    }

    #[test]
    fn failed_delete_keeps_the_saved_and_in_memory_rule() {
        let (service, executor) = test_service();
        let mut config = Config {
            rules: vec![make_rule(8080)],
            ..Default::default()
        };
        config.save(&service.config_path).unwrap();
        executor.0.lock().unwrap().entries = vec![config.rules[0].netsh_entry()];
        executor.0.lock().unwrap().fail_delete = true;
        assert!(service.delete_rule(&mut config, 0, true).is_err());
        assert_eq!(config.rules.len(), 1);
        assert_eq!(Config::load(&service.config_path).unwrap().rules.len(), 1);
        let _ = std::fs::remove_file(&service.config_path);
    }

    #[test]
    fn failed_replacement_restores_the_previous_windows_rule() {
        let (service, executor) = test_service();
        let mut config = Config {
            rules: vec![make_rule(8080)],
            ..Default::default()
        };
        let old = config.rules[0].netsh_entry();
        executor.0.lock().unwrap().entries = vec![old.clone()];
        executor.0.lock().unwrap().fail_add = true;
        let mut next = form(&config.rules[0]);
        next.connect_port = 81;
        assert!(service.update_rule(&mut config, 0, next, true).is_err());
        assert_eq!(executor.0.lock().unwrap().entries, vec![old]);
        assert_eq!(config.rules[0].connect_port, 80);
    }

    #[test]
    fn firewall_only_edits_are_applied_and_removed() {
        let (service, executor) = test_service();
        let mut config = Config {
            rules: vec![make_rule(8080)],
            ..Default::default()
        };
        let entry = config.rules[0].netsh_entry();
        executor.0.lock().unwrap().entries = vec![entry.clone()];
        let mut next = form(&config.rules[0]);
        next.firewall_managed = true;
        service.update_rule(&mut config, 0, next, true).unwrap();
        assert_eq!(executor.0.lock().unwrap().firewall.len(), 1);
        let mut next = form(&config.rules[0]);
        next.firewall_managed = false;
        service.update_rule(&mut config, 0, next, true).unwrap();
        assert!(executor.0.lock().unwrap().firewall.is_empty());
        let _ = std::fs::remove_file(&service.config_path);
    }

    #[test]
    fn firewall_failure_rolls_back_a_new_proxy() {
        let (service, executor) = test_service();
        let mut config = Config::default();
        executor.0.lock().unwrap().fail_firewall_add = true;
        let mut rule = make_rule(8080);
        rule.firewall_managed = true;
        assert!(service.add_rule(&mut config, form(&rule), true).is_err());
        assert!(config.rules.is_empty());
        assert!(executor.0.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn save_failure_rolls_back_system_changes_and_memory() {
        let (mut service, executor) = test_service();
        std::fs::write(&service.config_path, "block parent directory").unwrap();
        let blocker = service.config_path.clone();
        service.config_path = blocker.join("config.toml");
        let mut config = Config::default();
        assert!(service
            .add_rule(&mut config, form(&make_rule(8080)), true)
            .is_err());
        assert!(config.rules.is_empty());
        assert!(executor.0.lock().unwrap().entries.is_empty());
        std::fs::remove_file(blocker).unwrap();
    }

    #[test]
    fn metadata_deletion_does_not_require_a_missing_system_rule() {
        let (service, _) = test_service();
        let mut config = Config {
            rules: vec![make_rule(8080)],
            ..Default::default()
        };
        assert!(service.delete_rule(&mut config, 0, true).is_ok());
        assert!(config.rules.is_empty());
        let _ = std::fs::remove_file(&service.config_path);
    }

    #[test]
    fn ipv6_identity_survives_adoption_and_disable() {
        let (service, executor) = test_service();
        executor.0.lock().unwrap().entries = vec![PortproxyEntry {
            proxy_mode: ProxyMode::V6ToV6,
            listen_address: "::".into(),
            listen_port: 8080,
            connect_address: "FD00:0:0:0:0:0:0:10".into(),
            connect_port: 80,
        }];
        let mut config = Config::default();
        let entries = service.read_entries(true).unwrap();
        service.adopt_orphan(&mut config, &entries[0]).unwrap();
        assert_eq!(config.rules[0].connect_address, "fd00::10");
        let adopted_is_managed = orphan_entries(&config, &entries).is_empty();

        let remaining = service
            .set_rule_enabled(&mut config, 0, false, true)
            .unwrap();
        assert!(!config.rules[0].enabled);
        assert!(
            remaining.is_empty(),
            "disabling must remove the Windows entry"
        );
        assert!(executor.0.lock().unwrap().entries.is_empty());
        assert!(adopted_is_managed, "adoption must claim the Windows entry");
        let _ = std::fs::remove_file(&service.config_path);
    }

    #[test]
    fn deleting_metadata_does_not_delete_a_foreign_replacement_on_the_same_listener() {
        let (service, executor) = test_service();
        let mut config = Config {
            rules: vec![make_rule(8080)],
            ..Default::default()
        };
        let mut foreign = config.rules[0].netsh_entry();
        foreign.connect_port = 81;
        executor.0.lock().unwrap().entries = vec![foreign.clone()];
        service.delete_rule(&mut config, 0, true).unwrap();
        assert_eq!(executor.0.lock().unwrap().entries, vec![foreign]);
        let _ = std::fs::remove_file(service.config_path);
    }

    #[test]
    fn failed_firewall_replacement_restores_the_old_port_and_proxy() {
        let (service, executor) = test_service();
        let mut rule = make_rule(8080);
        rule.firewall_managed = true;
        let old_entry = rule.netsh_entry();
        let name = firewall::tcp_rule_name(&rule);
        let mut config = Config {
            rules: vec![rule],
            ..Default::default()
        };
        {
            let mut state = executor.0.lock().unwrap();
            state.entries = vec![old_entry.clone()];
            state.firewall.insert(name.clone(), 8080);
            state.fail_firewall_add = true;
        }
        let mut next = form(&config.rules[0]);
        next.listen_port = 8081;
        assert!(service.update_rule(&mut config, 0, next, true).is_err());
        let state = executor.0.lock().unwrap();
        assert_eq!(state.entries, vec![old_entry]);
        assert_eq!(state.firewall.get(&name), Some(&8080));
        assert_eq!(config.rules[0].listen_port, 8080);
    }

    #[test]
    fn disabling_rolls_back_when_firewall_cleanup_fails() {
        let (service, executor) = test_service();
        let mut rule = make_rule(8080);
        rule.firewall_managed = true;
        let entry = rule.netsh_entry();
        let name = firewall::tcp_rule_name(&rule);
        let mut config = Config {
            rules: vec![rule],
            ..Default::default()
        };
        {
            let mut state = executor.0.lock().unwrap();
            state.entries = vec![entry.clone()];
            state.firewall.insert(name.clone(), 8080);
            state.fail_firewall_delete = true;
        }
        assert!(service
            .set_rule_enabled(&mut config, 0, false, true)
            .is_err());
        assert!(config.rules[0].enabled);
        let state = executor.0.lock().unwrap();
        assert_eq!(state.entries, vec![entry]);
        assert_eq!(state.firewall.get(&name), Some(&8080));
    }

    #[test]
    fn listener_conflicts_include_wildcards_and_target_family_modes() {
        let existing = make_rule(8080);
        let config = Config {
            rules: vec![existing.clone()],
            ..Default::default()
        };
        let mut rule = make_rule(8080);
        rule.listen_address = "127.0.0.1".into();
        assert!(detect_duplicate_config_rule(&config, &rule, None).is_err());
        rule.listen_address = "0.0.0.0".into();
        rule.proxy_mode = ProxyMode::V4ToV6;
        assert!(detect_actual_port_conflict(&[existing.netsh_entry()], &rule, None).is_err());
    }

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
