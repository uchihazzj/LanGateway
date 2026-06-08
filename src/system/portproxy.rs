use crate::core::model::{ForwardRule, PortproxyEntry, ProxyMode, ProxyProtocol};
use crate::system::{
    encoding,
    process::{CommandExecutor, SystemCommandExecutor},
};

#[derive(Debug, Clone, PartialEq)]
pub enum RuleDiffAction {
    Add(PortproxyEntry),
    Delete(PortproxyEntry),
}

pub fn show_all() -> Result<Vec<PortproxyEntry>, String> {
    let modes = [
        ProxyMode::V4ToV4,
        ProxyMode::V4ToV6,
        ProxyMode::V6ToV4,
        ProxyMode::V6ToV6,
    ];
    let handles: Vec<_> = modes
        .into_iter()
        .map(|mode| std::thread::spawn(move || show_mode_with(&SystemCommandExecutor, mode)))
        .collect();

    let mut entries = Vec::new();
    for handle in handles {
        let mut mode_entries = handle
            .join()
            .map_err(|_| "netsh show worker thread panicked".to_string())??;
        entries.append(&mut mode_entries);
    }
    Ok(entries)
}

pub fn show_v4tov4() -> Result<Vec<PortproxyEntry>, String> {
    show_mode_with(&SystemCommandExecutor, ProxyMode::V4ToV4)
}

#[allow(dead_code)]
pub fn show_all_with(exec: &dyn CommandExecutor) -> Result<Vec<PortproxyEntry>, String> {
    let mut entries = show_mode_with(exec, ProxyMode::V4ToV4)?;
    entries.extend(show_mode_with(exec, ProxyMode::V4ToV6)?);
    entries.extend(show_mode_with(exec, ProxyMode::V6ToV4)?);
    entries.extend(show_mode_with(exec, ProxyMode::V6ToV6)?);
    Ok(entries)
}

fn show_mode_with(
    exec: &dyn CommandExecutor,
    proxy_mode: ProxyMode,
) -> Result<Vec<PortproxyEntry>, String> {
    let output = exec
        .run(
            "netsh",
            &["interface", "portproxy", "show", proxy_mode.netsh_name()],
        )
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if !output.status_success {
        let stderr = encoding::decode(&output.stderr);
        let stdout = encoding::decode(&output.stdout);
        return Err(format!(
            "netsh show {} failed (exit {:?}): stdout={}, stderr={}",
            proxy_mode.netsh_name(),
            output.status_code,
            stdout.trim(),
            stderr.trim()
        ));
    }

    let stdout = encoding::decode(&output.stdout);
    Ok(parse_show_output(proxy_mode, &stdout))
}

pub fn parse_show_output(proxy_mode: ProxyMode, output: &str) -> Vec<PortproxyEntry> {
    let mut entries = Vec::new();
    let mut in_table = false;

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("---") || line.starts_with("===") {
            in_table = true;
            continue;
        }

        if !in_table || line.is_empty() {
            continue;
        }

        if line.contains("Listen on") || line.contains("Address") || line.contains("Port") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let listen_port: u16 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let connect_port: u16 = match parts[3].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            entries.push(PortproxyEntry {
                proxy_mode,
                listen_address: parts[0].to_string(),
                listen_port,
                connect_address: parts[2].to_string(),
                connect_port,
            });
        }
    }

    entries
}

pub fn add_entry(entry: &PortproxyEntry) -> Result<(), String> {
    add_entry_with(&SystemCommandExecutor, entry)
}

pub fn add_entry_with(exec: &dyn CommandExecutor, entry: &PortproxyEntry) -> Result<(), String> {
    run_netsh_entry_command(exec, "add", entry)
}

pub fn delete_entry(entry: &PortproxyEntry) -> Result<(), String> {
    delete_entry_with(&SystemCommandExecutor, entry)
}

pub fn delete_entry_with(exec: &dyn CommandExecutor, entry: &PortproxyEntry) -> Result<(), String> {
    run_netsh_entry_command(exec, "delete", entry)
}

fn run_netsh_entry_command(
    exec: &dyn CommandExecutor,
    action: &str,
    entry: &PortproxyEntry,
) -> Result<(), String> {
    let listen_port_arg = format!("listenport={}", entry.listen_port);
    let listen_addr_arg = format!("listenaddress={}", entry.listen_address);
    let connect_port_arg = format!("connectport={}", entry.connect_port);
    let connect_addr_arg = format!("connectaddress={}", entry.connect_address);

    let args = if action == "delete" {
        vec![
            "interface",
            "portproxy",
            "delete",
            entry.proxy_mode.netsh_name(),
            &listen_port_arg,
            &listen_addr_arg,
        ]
    } else {
        vec![
            "interface",
            "portproxy",
            "add",
            entry.proxy_mode.netsh_name(),
            &listen_port_arg,
            &listen_addr_arg,
            &connect_port_arg,
            &connect_addr_arg,
        ]
    };

    let output = exec
        .run("netsh", &args)
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if output.status_success {
        Ok(())
    } else {
        let stderr = encoding::decode(&output.stderr);
        let stdout = encoding::decode(&output.stdout);
        Err(format!(
            "netsh {} failed (exit {:?}): args={:?} stdout={} stderr={}",
            action,
            output.status_code,
            args,
            stdout.trim(),
            stderr.trim()
        ))
    }
}

#[allow(dead_code)]
pub fn add_v4tov4(
    listen_port: u16,
    connect_address: &str,
    connect_port: u16,
) -> Result<(), String> {
    let entry = PortproxyEntry {
        proxy_mode: ProxyMode::V4ToV4,
        listen_address: "0.0.0.0".into(),
        listen_port,
        connect_address: connect_address.into(),
        connect_port,
    };
    add_entry(&entry)
}

#[allow(dead_code)]
pub fn delete_v4tov4(listen_port: u16, listen_address: &str) -> Result<(), String> {
    let entry = PortproxyEntry {
        proxy_mode: ProxyMode::V4ToV4,
        listen_address: listen_address.into(),
        listen_port,
        connect_address: String::new(),
        connect_port: 0,
    };
    delete_entry(&entry)
}

pub fn expected_entries(rules: &[ForwardRule]) -> Vec<PortproxyEntry> {
    rules
        .iter()
        .filter(|r| r.enabled && r.protocol == ProxyProtocol::Tcp)
        .map(ForwardRule::netsh_entry)
        .collect()
}

pub fn diff_rules(expected: &[PortproxyEntry], actual: &[PortproxyEntry]) -> Vec<RuleDiffAction> {
    let actual_keys: std::collections::HashSet<_> =
        actual.iter().map(PortproxyEntry::stable_key).collect();
    let expected_keys: std::collections::HashSet<_> =
        expected.iter().map(PortproxyEntry::stable_key).collect();

    let mut actions = Vec::new();
    for entry in expected {
        if !actual_keys.contains(&entry.stable_key()) {
            actions.push(RuleDiffAction::Add(entry.clone()));
        }
    }
    for entry in actual {
        if !expected_keys.contains(&entry.stable_key()) {
            actions.push(RuleDiffAction::Delete(entry.clone()));
        }
    }
    actions
}

#[allow(dead_code)]
pub fn entry_matches_rule(entry: &PortproxyEntry, rule: &ForwardRule) -> bool {
    entry.proxy_mode == rule.proxy_mode
        && entry.listen_port == rule.listen_port
        && (entry.listen_address == rule.listen_address
            || entry.listen_address == rule.proxy_mode.listen_any_address()
            || rule.listen_address == rule.proxy_mode.listen_any_address())
        && entry.connect_port == rule.connect_port
        && entry.connect_address == rule.connect_address
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::process::CommandOutput;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct MockExecutor {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        stdout: Vec<u8>,
        fail: bool,
    }

    impl CommandExecutor for MockExecutor {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|s| s.to_string()));
            self.calls.lock().unwrap().push(call);
            Ok(CommandOutput {
                status_success: !self.fail,
                status_code: Some(if self.fail { 1 } else { 0 }),
                stdout: self.stdout.clone(),
                stderr: Vec::new(),
            })
        }
    }

    fn make_entry(
        mode: ProxyMode,
        listen_addr: &str,
        listen_port: u16,
        connect_addr: &str,
        connect_port: u16,
    ) -> PortproxyEntry {
        PortproxyEntry {
            proxy_mode: mode,
            listen_address: listen_addr.into(),
            listen_port,
            connect_address: connect_addr.into(),
            connect_port,
        }
    }

    #[test]
    fn add_entry_uses_mode_and_equals_sign_format() {
        let exec = MockExecutor::default();
        let entry = make_entry(ProxyMode::V6ToV4, "::", 5000, "10.0.0.1", 80);
        add_entry_with(&exec, &entry).unwrap();
        let calls = exec.calls.lock().unwrap();
        assert_eq!(calls[0][4], "v6tov4");
        assert!(calls[0].contains(&"listenport=5000".to_string()));
        assert!(calls[0].contains(&"listenaddress=::".to_string()));
        assert!(calls[0].contains(&"connectaddress=10.0.0.1".to_string()));
    }

    #[test]
    fn delete_entry_only_uses_listen_side() {
        let exec = MockExecutor::default();
        let entry = make_entry(ProxyMode::V4ToV6, "0.0.0.0", 5000, "::1", 80);
        delete_entry_with(&exec, &entry).unwrap();
        let calls = exec.calls.lock().unwrap();
        assert_eq!(
            calls[0],
            vec![
                "netsh",
                "interface",
                "portproxy",
                "delete",
                "v4tov6",
                "listenport=5000",
                "listenaddress=0.0.0.0",
            ]
        );
    }

    #[test]
    fn parse_ipv4_show_output() {
        let sample = "\
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
0.0.0.0         8080        192.168.1.100   80
0.0.0.0         4433        10.0.0.50       443
127.0.0.1       3000        192.168.1.200   3000
";

        let entries = parse_show_output(ProxyMode::V4ToV4, sample);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].proxy_mode, ProxyMode::V4ToV4);
        assert_eq!(entries[0].listen_address, "0.0.0.0");
        assert_eq!(entries[0].listen_port, 8080);
        assert_eq!(entries[0].connect_address, "192.168.1.100");
        assert_eq!(entries[0].connect_port, 80);
    }

    #[test]
    fn parse_ipv6_show_output() {
        let sample = "\
Listen on ipv6:             Connect to ipv6:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
::              8443        fd00::10        443
";
        let entries = parse_show_output(ProxyMode::V6ToV6, sample);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].listen_address, "::");
        assert_eq!(entries[0].connect_address, "fd00::10");
    }

    #[test]
    fn diff_rules_adds_and_deletes() {
        let expected = vec![make_entry(ProxyMode::V4ToV4, "0.0.0.0", 80, "10.0.0.2", 80)];
        let actual = vec![make_entry(ProxyMode::V4ToV4, "0.0.0.0", 81, "10.0.0.3", 80)];
        let diff = diff_rules(&expected, &actual);
        assert_eq!(diff.len(), 2);
        assert!(matches!(diff[0], RuleDiffAction::Add(_)));
        assert!(matches!(diff[1], RuleDiffAction::Delete(_)));
    }

    #[test]
    fn expected_entries_skips_disabled_rules() {
        let mut rule = ForwardRule {
            id: "rule-web".into(),
            name: "Web".into(),
            notes: String::new(),
            listen_address: "0.0.0.0".into(),
            listen_port: 8080,
            connect_address: "10.0.0.2".into(),
            connect_port: 80,
            managed: true,
            protocol: ProxyProtocol::Tcp,
            proxy_mode: ProxyMode::V4ToV4,
            enabled: true,
            firewall_managed: false,
            mdns_publish: false,
            tags: Vec::new(),
        };
        assert_eq!(expected_entries(&[rule.clone()]).len(), 1);
        rule.enabled = false;
        assert!(expected_entries(&[rule]).is_empty());
    }

    #[test]
    fn parse_empty_output() {
        let entries = parse_show_output(ProxyMode::V4ToV4, "");
        assert_eq!(entries.len(), 0);
    }
}
