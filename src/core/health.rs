use crate::core::model::{ForwardRule, HealthStatus, PortproxyEntry, ProxyMode, ProxyProtocol};
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub fn check_tcp(host: &str, port: u16, timeout_ms: u64, mode: ProxyMode) -> Result<(), String> {
    let target_is_v6 = matches!(mode, ProxyMode::V4ToV6 | ProxyMode::V6ToV6);
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolve failed: {}", e))?
        .filter(|addr| addr.is_ipv6() == target_is_v6);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut last_error = "No address resolved for the target address family".to_string();
    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("TCP check timed out".into());
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(_) => return Ok(()),
            Err(e) => {
                let msg = match e.kind() {
                    io::ErrorKind::TimedOut => "timeout",
                    io::ErrorKind::ConnectionRefused => "connection refused",
                    io::ErrorKind::ConnectionReset => "connection reset",
                    io::ErrorKind::HostUnreachable => "host unreachable",
                    io::ErrorKind::NetworkUnreachable => "network unreachable",
                    _ => "unreachable",
                };
                last_error = format!("{}: {}", msg, e);
            }
        }
    }
    Err(last_error)
}

pub fn check_rule(rule: &ForwardRule, proxy_entries: &[PortproxyEntry]) -> HealthStatus {
    if !rule.enabled
        || rule.protocol != ProxyProtocol::Tcp
        || !proxy_entries.contains(&rule.netsh_entry())
    {
        return HealthStatus::MetadataOnly;
    }
    match check_tcp(
        &rule.connect_address,
        rule.connect_port,
        1000,
        rule.proxy_mode,
    ) {
        Ok(()) => HealthStatus::Healthy,
        Err(e) => HealthStatus::TargetUnreachable(e),
    }
}

pub fn check_orphan(entry: &PortproxyEntry) -> HealthStatus {
    match check_tcp(
        &entry.connect_address,
        entry.connect_port,
        1000,
        entry.proxy_mode,
    ) {
        Ok(()) => HealthStatus::Healthy,
        Err(e) => HealthStatus::TargetUnreachable(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{ProxyMode, ProxyProtocol};
    use std::net::TcpListener;

    fn rule(port: u16) -> ForwardRule {
        ForwardRule {
            id: "health-test".into(),
            name: "Health test".into(),
            notes: String::new(),
            listen_address: "127.0.0.1".into(),
            listen_port: 8080,
            connect_address: "127.0.0.1".into(),
            connect_port: port,
            managed: true,
            protocol: ProxyProtocol::Tcp,
            proxy_mode: ProxyMode::V4ToV4,
            enabled: true,
            firewall_managed: false,
            mdns_publish: false,
            tags: vec![],
        }
    }

    #[test]
    fn tcp_check_accepts_ipv6_literals() {
        let listener = TcpListener::bind(("::1", 0)).unwrap();
        assert!(check_tcp(
            "::1",
            listener.local_addr().unwrap().port(),
            200,
            ProxyMode::V6ToV6
        )
        .is_ok());
    }

    #[test]
    fn disabled_and_udp_rules_are_metadata_only() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut rule = rule(listener.local_addr().unwrap().port());
        let entries = vec![rule.netsh_entry()];
        rule.enabled = false;
        assert_eq!(check_rule(&rule, &entries), HealthStatus::MetadataOnly);
        rule.enabled = true;
        rule.protocol = ProxyProtocol::Udp;
        assert_eq!(check_rule(&rule, &entries), HealthStatus::MetadataOnly);
    }

    #[test]
    fn health_requires_the_exact_mode_and_listen_address() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let rule = rule(listener.local_addr().unwrap().port());
        let mut entry = rule.netsh_entry();
        entry.proxy_mode = ProxyMode::V4ToV6;
        assert_eq!(check_rule(&rule, &[entry]), HealthStatus::MetadataOnly);
        let mut entry = rule.netsh_entry();
        entry.listen_address = "0.0.0.0".into();
        assert_eq!(check_rule(&rule, &[entry]), HealthStatus::MetadataOnly);
    }
}
