use crate::core::model::{ForwardRule, ProxyProtocol};
use crate::system::{
    encoding,
    process::{CommandExecutor, SystemCommandExecutor},
};

pub const MDNS_FIREWALL_RULE: &str = "LanGateway-mDNS";

#[derive(Debug, Clone, PartialEq)]
pub struct FirewallRuleStatus {
    pub name: String,
    pub exists: bool,
}

pub fn tcp_rule_name(rule: &ForwardRule) -> String {
    let id = if rule.id.trim().is_empty() {
        rule.stable_key()
    } else {
        rule.id.clone()
    };
    format!("LanGateway-{}", sanitize_rule_name(&id))
}

fn sanitize_rule_name(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub fn ensure_tcp_rule_with(exec: &dyn CommandExecutor, rule: &ForwardRule) -> Result<(), String> {
    if rule.protocol != ProxyProtocol::Tcp {
        return Err("Windows portproxy firewall automation only supports TCP".into());
    }

    let name = tcp_rule_name(rule);
    if query_rule_with(exec, &name).exists {
        delete_rule_with(exec, &name)?;
    }
    let port_arg = format!("localport={}", rule.listen_port);
    let name_arg = format!("name={}", name);
    run_firewall_command(
        exec,
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &name_arg,
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &port_arg,
        ],
    )
}

pub fn ensure_mdns_rule() -> Result<(), String> {
    ensure_mdns_rule_with(&SystemCommandExecutor)
}

pub fn ensure_mdns_rule_with(exec: &dyn CommandExecutor) -> Result<(), String> {
    delete_rule_with(exec, MDNS_FIREWALL_RULE).ok();
    let name_arg = format!("name={}", MDNS_FIREWALL_RULE);
    run_firewall_command(
        exec,
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &name_arg,
            "dir=in",
            "action=allow",
            "protocol=UDP",
            "localport=5353",
        ],
    )
}

pub fn delete_rule_with(exec: &dyn CommandExecutor, name: &str) -> Result<(), String> {
    let name_arg = format!("name={}", name);
    run_firewall_command(
        exec,
        &["advfirewall", "firewall", "delete", "rule", &name_arg],
    )
}

pub fn query_rule(name: &str) -> FirewallRuleStatus {
    query_rule_with(&SystemCommandExecutor, name)
}

pub fn query_rule_with(exec: &dyn CommandExecutor, name: &str) -> FirewallRuleStatus {
    let name_arg = format!("name={}", name);
    let output = exec.run(
        "netsh",
        &["advfirewall", "firewall", "show", "rule", &name_arg],
    );

    FirewallRuleStatus {
        name: name.to_string(),
        exists: output.map(|o| o.status_success).unwrap_or(false),
    }
}

fn run_firewall_command(exec: &dyn CommandExecutor, args: &[&str]) -> Result<(), String> {
    let output = exec
        .run("netsh", args)
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if output.status_success {
        Ok(())
    } else {
        Err(format!(
            "netsh firewall command failed (exit {:?}): args={:?} stdout={} stderr={}",
            output.status_code,
            args,
            encoding::decode(&output.stdout).trim(),
            encoding::decode(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{ForwardRule, ProxyMode};
    use crate::system::process::CommandOutput;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct MockExecutor {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl CommandExecutor for MockExecutor {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|s| s.to_string()));
            self.calls.lock().unwrap().push(call);
            Ok(CommandOutput {
                status_success: true,
                status_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    fn make_rule() -> ForwardRule {
        ForwardRule {
            id: "web-8080".into(),
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
            firewall_managed: true,
            mdns_publish: false,
            tags: vec![],
        }
    }

    #[test]
    fn tcp_rule_name_is_stable_and_prefixed() {
        assert_eq!(tcp_rule_name(&make_rule()), "LanGateway-web-8080");
    }

    #[test]
    fn ensure_tcp_rule_builds_netsh_firewall_command() {
        let exec = MockExecutor::default();
        ensure_tcp_rule_with(&exec, &make_rule()).unwrap();
        let calls = exec.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[2].contains(&"protocol=TCP".to_string()));
        assert!(calls[2].contains(&"localport=8080".to_string()));
        assert!(calls[2].contains(&"name=LanGateway-web-8080".to_string()));
    }

    #[test]
    fn ensure_mdns_rule_builds_udp_5353_command() {
        let exec = MockExecutor::default();
        ensure_mdns_rule_with(&exec).unwrap();
        let calls = exec.calls.lock().unwrap();
        assert!(calls[1].contains(&"protocol=UDP".to_string()));
        assert!(calls[1].contains(&"localport=5353".to_string()));
    }
}
