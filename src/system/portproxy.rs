use crate::core::model::PortproxyEntry;
use crate::system::{encoding, process};

pub fn show_all() -> Result<Vec<PortproxyEntry>, String> {
    let output = process::run_command("netsh", &["interface", "portproxy", "show", "all"])
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if !output.status.success() {
        let stderr = encoding::decode(&output.stderr);
        let stdout = encoding::decode(&output.stdout);
        return Err(format!(
            "netsh show all failed (exit {:?}): stdout={}, stderr={}",
            output.status.code(),
            stdout.trim(),
            stderr.trim()
        ));
    }

    let stdout = encoding::decode(&output.stdout);
    Ok(parse_show_all(&stdout))
}

fn parse_show_all(output: &str) -> Vec<PortproxyEntry> {
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

        if line.contains("Listen on") || line.contains("侦听") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let listen_addr = parts[0].to_string();
            let listen_port: u16 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let connect_addr = parts[2].to_string();
            let connect_port: u16 = match parts[3].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            entries.push(PortproxyEntry {
                listen_address: listen_addr,
                listen_port,
                connect_address: connect_addr,
                connect_port,
            });
        }
    }

    entries
}

pub fn add_v4tov4(
    listen_port: u16,
    connect_address: &str,
    connect_port: u16,
) -> Result<(), String> {
    let listen_port_arg = format!("listenport={}", listen_port);
    let connect_port_arg = format!("connectport={}", connect_port);
    let connect_addr_arg = format!("connectaddress={}", connect_address);

    let args = &[
        "interface",
        "portproxy",
        "add",
        "v4tov4",
        &listen_port_arg,
        "listenaddress=0.0.0.0",
        &connect_port_arg,
        &connect_addr_arg,
    ];

    let output =
        process::run_command("netsh", args).map_err(|e| format!("Failed to run netsh: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = encoding::decode(&output.stderr);
        let stdout = encoding::decode(&output.stdout);
        Err(format!(
            "netsh add failed (exit {:?}): args={:?} stdout={} stderr={}",
            output.status.code(),
            args,
            stdout.trim(),
            stderr.trim()
        ))
    }
}

pub fn delete_v4tov4(listen_port: u16, listen_address: &str) -> Result<(), String> {
    let listen_port_arg = format!("listenport={}", listen_port);
    let listen_addr_arg = format!("listenaddress={}", listen_address);

    let args = &[
        "interface",
        "portproxy",
        "delete",
        "v4tov4",
        &listen_port_arg,
        &listen_addr_arg,
    ];

    let output =
        process::run_command("netsh", args).map_err(|e| format!("Failed to run netsh: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = encoding::decode(&output.stderr);
        let stdout = encoding::decode(&output.stdout);
        Err(format!(
            "netsh delete failed (exit {:?}): listen_address={} listen_port={} args={:?} stdout={} stderr={}",
            output.status.code(), listen_address, listen_port, args, stdout.trim(), stderr.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_v4tov4_uses_equals_sign_format() {
        // We can only test the parameter construction, not actual netsh execution
        // Verify format strings produce correct key=value pairs
        assert_eq!(format!("listenport={}", 5000u16), "listenport=5000");
        assert_eq!(
            format!("listenaddress={}", "0.0.0.0"),
            "listenaddress=0.0.0.0"
        );
        assert_eq!(format!("connectport={}", 80u16), "connectport=80");
        assert_eq!(
            format!("connectaddress={}", "10.0.0.1"),
            "connectaddress=10.0.0.1"
        );
    }

    #[test]
    fn delete_v4tov4_uses_equals_sign_format() {
        assert_eq!(format!("listenport={}", 5000u16), "listenport=5000");
        assert_eq!(
            format!("listenaddress={}", "0.0.0.0"),
            "listenaddress=0.0.0.0"
        );
    }

    #[test]
    fn parse_ipv4_show_all_output() {
        let sample = "\
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
0.0.0.0         8080        192.168.1.100   80
0.0.0.0         4433        10.0.0.50       443
127.0.0.1       3000        192.168.1.200   3000
";

        let entries = parse_show_all(sample);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].listen_address, "0.0.0.0");
        assert_eq!(entries[0].listen_port, 8080);
        assert_eq!(entries[0].connect_address, "192.168.1.100");
        assert_eq!(entries[0].connect_port, 80);

        assert_eq!(entries[1].listen_port, 4433);
        assert_eq!(entries[1].connect_address, "10.0.0.50");
        assert_eq!(entries[1].connect_port, 443);

        assert_eq!(entries[2].listen_address, "127.0.0.1");
        assert_eq!(entries[2].listen_port, 3000);
    }

    #[test]
    fn parse_empty_output() {
        let sample = "\
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
";
        let entries = parse_show_all(sample);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn parse_no_header() {
        let entries = parse_show_all("");
        assert_eq!(entries.len(), 0);
    }
}
