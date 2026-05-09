use crate::core::model::{HealthStatus, PortproxyEntry, ForwardRule};
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub fn check_tcp(host: &str, port: u16, timeout_ms: u64) -> Result<(), String> {
    let addr_str = format!("{}:{}", host, port);
    let mut addrs = addr_str.to_socket_addrs()
        .map_err(|e| format!("DNS resolve failed: {}", e))?;
    let addr = addrs.next()
        .ok_or_else(|| "No address resolved".to_string())?;
    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = match e.kind() {
                io::ErrorKind::TimedOut => "timeout",
                io::ErrorKind::ConnectionRefused => "connection refused",
                io::ErrorKind::ConnectionReset => "connection reset",
                io::ErrorKind::HostUnreachable => "host unreachable",
                io::ErrorKind::NetworkUnreachable => "network unreachable",
                _ => "unreachable",
            };
            Err(format!("{}: {}", msg, e))
        }
    }
}

pub fn check_rule(rule: &ForwardRule, proxy_entries: &[PortproxyEntry]) -> HealthStatus {
    let proxy_exists = proxy_entries.iter().any(|e| {
        e.listen_port == rule.listen_port
            && (e.listen_address == rule.listen_address
                || e.listen_address == "0.0.0.0"
                || rule.listen_address == "0.0.0.0")
            && e.connect_port == rule.connect_port
            && e.connect_address == rule.connect_address
    });

    let target_result = check_tcp(&rule.connect_address, rule.connect_port, 1000);

    match (proxy_exists, target_result) {
        (true, Ok(())) => HealthStatus::Healthy,
        (true, Err(e)) => HealthStatus::TargetUnreachable(e),
        (false, _) => HealthStatus::MetadataOnly,
    }
}

pub fn check_orphan(entry: &PortproxyEntry) -> HealthStatus {
    match check_tcp(&entry.connect_address, entry.connect_port, 1000) {
        Ok(()) => HealthStatus::Healthy,
        Err(e) => HealthStatus::TargetUnreachable(e),
    }
}
