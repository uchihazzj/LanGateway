use crate::core::model::PortproxyEntry;
use crate::system::{encoding, process};

pub fn show_all() -> Result<Vec<PortproxyEntry>, String> {
    let output = process::run_command("netsh", &["interface", "portproxy", "show", "all"])
        .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if !output.status.success() {
        return Ok(vec![]);
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

pub fn add_v4tov4(listen_port: u16, connect_address: &str, connect_port: u16) -> Result<(), String> {
    let output = process::run_command(
        "netsh",
        &[
            "interface", "portproxy", "add", "v4tov4",
            "listenport", &listen_port.to_string(),
            "listenaddress", "0.0.0.0",
            "connectport", &connect_port.to_string(),
            "connectaddress", connect_address,
        ],
    )
    .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = encoding::decode(&output.stderr);
        Err(format!("netsh add failed: {}", stderr.trim()))
    }
}

pub fn delete_v4tov4(listen_port: u16, listen_address: &str) -> Result<(), String> {
    let output = process::run_command(
        "netsh",
        &[
            "interface", "portproxy", "delete", "v4tov4",
            "listenport", &listen_port.to_string(),
            "listenaddress", listen_address,
        ],
    )
    .map_err(|e| format!("Failed to run netsh: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = encoding::decode(&output.stderr);
        Err(format!("netsh delete failed: {}", stderr.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
