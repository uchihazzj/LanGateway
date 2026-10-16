use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MDNS_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const DNS_TYPE_A: u16 = 1;
const DNS_TTL_SECS: u32 = 30;
const RECV_BUF_LEN: usize = 1500;

// ---------------------------------------------------------------------------
// Snapshot / status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct MdnsConfigSnapshot {
    pub enabled: bool,
    pub hostname: String,
    pub gateway_ip: String,
}

impl MdnsConfigSnapshot {
    pub fn needs_restart(&self, other: &MdnsConfigSnapshot) -> bool {
        self != other
    }
}

#[derive(Debug, Clone)]
pub enum MdnsStatus {
    Disabled,
    Starting,
    Running,
    Failed(String),
    #[allow(dead_code)]
    Conflict(String),
    WaitingForIp,
}

impl fmt::Display for MdnsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MdnsStatus::Disabled => write!(f, "Disabled"),
            MdnsStatus::Starting => write!(f, "Starting"),
            MdnsStatus::Running => write!(f, "Running"),
            MdnsStatus::Failed(e) => write!(f, "Failed: {}", e),
            MdnsStatus::Conflict(e) => write!(f, "Conflict: {}", e),
            MdnsStatus::WaitingForIp => write!(f, "Waiting for usable IP"),
        }
    }
}

/// Own the socket lifecycle on one worker so restarting or stopping mDNS never
/// waits for PowerShell or the responder's read timeout on the UI thread.
pub struct MdnsController {
    commands: std::sync::mpsc::Sender<MdnsConfigSnapshot>,
    results: std::sync::mpsc::Receiver<(MdnsConfigSnapshot, MdnsStatus)>,
}

impl MdnsController {
    pub fn new() -> Self {
        let (commands, requests) = std::sync::mpsc::channel::<MdnsConfigSnapshot>();
        let (updates, results) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut handle: Option<MdnsHandle> = None;
            while let Ok(mut snapshot) = requests.recv() {
                while let Ok(latest) = requests.try_recv() {
                    snapshot = latest;
                }
                if let Some(previous) = handle.take() {
                    previous.shutdown();
                }
                let status = if !snapshot.enabled {
                    MdnsStatus::Disabled
                } else if snapshot.gateway_ip.is_empty() {
                    MdnsStatus::WaitingForIp
                } else {
                    match validate_mdns_hostname(&snapshot.hostname)
                        .and_then(|hostname| MdnsHandle::start(&hostname, &snapshot.gateway_ip))
                    {
                        Ok(next) => {
                            if let Err(e) = crate::system::firewall::ensure_mdns_rule() {
                                crate::system::logger::log_to_file(&format!(
                                    "mDNS firewall rule setup failed: {}",
                                    e
                                ));
                            }
                            handle = Some(next);
                            MdnsStatus::Running
                        }
                        Err(e) => {
                            crate::system::logger::log_to_file(&format!(
                                "mDNS: start failed: {}",
                                e
                            ));
                            MdnsStatus::Failed(e)
                        }
                    }
                };
                if updates.send((snapshot, status)).is_err() {
                    break;
                }
            }
        });
        Self { commands, results }
    }

    pub fn configure(&self, snapshot: MdnsConfigSnapshot) -> Result<(), String> {
        self.commands
            .send(snapshot)
            .map_err(|_| "mDNS worker stopped".into())
    }

    pub fn try_result(&self) -> Option<(MdnsConfigSnapshot, MdnsStatus)> {
        self.results.try_recv().ok()
    }
}

// ---------------------------------------------------------------------------
// Hostname validation
// ---------------------------------------------------------------------------

pub fn validate_mdns_hostname(input: &str) -> Result<String, String> {
    let raw = input.trim().trim_end_matches('.');
    if raw.is_empty() {
        return Err("Hostname must not be empty".into());
    }
    let suffix_start = raw.len().saturating_sub(6);
    let label = if raw
        .get(suffix_start..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".local"))
    {
        let stripped = &raw[..suffix_start];
        if stripped.contains('.') {
            return Err("mDNS names must be a single label under .local".into());
        }
        stripped.trim().to_string()
    } else if raw.contains('.') {
        return Err("mDNS only supports names like gateway or gateway.local".into());
    } else {
        raw.to_string()
    };
    if label.is_empty() {
        return Err("Hostname must not be empty".into());
    }
    if label.len() > 63 {
        return Err(format!("Hostname too long: {} chars, max 63", label.len()));
    }
    let mut chars = label.chars();
    if let Some(first) = chars.next() {
        if first == '-' {
            return Err("Hostname must not start with '-'".into());
        }
        if !first.is_ascii_alphanumeric() {
            return Err(format!(
                "Invalid character '{}' in hostname -- only A-Z, a-z, 0-9, and '-' allowed",
                first
            ));
        }
    }
    let mut last = ' ';
    for ch in label.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' {
            return Err(format!(
                "Invalid character '{}' in hostname -- only A-Z, a-z, 0-9, and '-' allowed",
                ch
            ));
        }
        last = ch;
    }
    if last == '-' {
        return Err("Hostname must not end with '-'".into());
    }
    Ok(label)
}

// ---------------------------------------------------------------------------
// Minimal DNS helpers
// ---------------------------------------------------------------------------

/// Encode a dot-separated name (e.g. "uchihazzj.local") into DNS label format,
/// including the trailing root label (zero byte).
fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let trimmed = name.trim_end_matches('.');
    for label in trimmed.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
}

/// Returns true if `data[offset..]` contains a label-encoded name matching
/// `target`, where `target` is a dotted string like "uchihazzj.local".
/// Handles both lower-case and the exact bytes provided.
#[cfg(test)]
fn dns_name_matches(data: &[u8], offset: usize, target: &str) -> bool {
    let target = target.trim_end_matches('.');
    let labels: Vec<&str> = target.split('.').collect();
    let mut pos = offset;
    for (i, wanted) in labels.iter().enumerate() {
        if pos >= data.len() {
            return false;
        }
        let len = data[pos] as usize;
        if len & 0xC0 == 0xC0 {
            // Compression — not expected in queries we care about; bail.
            return false;
        }
        if len != wanted.len() {
            return false;
        }
        if pos + 1 + len > data.len() {
            return false;
        }
        if !data[pos + 1..pos + 1 + len].eq_ignore_ascii_case(wanted.as_bytes()) {
            return false;
        }
        pos += 1 + len;
        // After the last label we expect a zero root label
        if i == labels.len() - 1 {
            return pos < data.len() && data[pos] == 0;
        }
    }
    false
}

/// Build an A response for our own host. A legacy query echoes its transaction
/// ID and question; regular mDNS and TTL-zero goodbyes contain only the answer.
fn build_a_response(
    host_fqdn: &str,
    ip: &str,
    tx_id: u16,
    legacy_question: Option<(u16, u16)>,
    ttl: u32,
) -> Vec<u8> {
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return Vec::new();
    };
    let name = encode_dns_name(host_fqdn);
    let mut resp = Vec::new();
    resp.extend_from_slice(&tx_id.to_be_bytes());
    resp.extend_from_slice(&[0x84, 0x00]);
    resp.extend_from_slice(&u16::from(legacy_question.is_some()).to_be_bytes());
    resp.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    if let Some((qtype, qclass)) = legacy_question {
        resp.extend_from_slice(&name);
        resp.extend_from_slice(&qtype.to_be_bytes());
        resp.extend_from_slice(&qclass.to_be_bytes());
    }
    // Encode the owned hostname, never a question or compression pointer copied
    // from an untrusted packet (which may contain several different questions).
    resp.extend_from_slice(&name);
    resp.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    let class: u16 = if legacy_question.is_some() { 1 } else { 0x8001 };
    resp.extend_from_slice(&class.to_be_bytes());
    let ttl = if legacy_question.is_some() {
        ttl.min(10)
    } else {
        ttl
    };
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip.octets());
    resp
}

// ---------------------------------------------------------------------------
// Socket setup
// ---------------------------------------------------------------------------

/// Create a UDP socket bound to 0.0.0.0:5353 with SO_REUSEADDR and joined to
/// the mDNS multicast group on `interface_ip`.
fn create_mdns_socket(interface_ip: &str) -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};

    let gateway: Ipv4Addr = interface_ip
        .parse()
        .map_err(|e| format!("parse gateway IP '{}': {}", interface_ip, e))?;

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("socket create: {}", e))?;

    // Must be set before bind for sharing with Dnscache/Chrome/Steam.
    sock.set_reuse_address(true)
        .map_err(|e| format!("SO_REUSEADDR: {}", e))?;
    crate::system::logger::log_to_file("mDNS: SO_REUSEADDR set on IPv4 socket");

    sock.bind(&socket2::SockAddr::from(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        MDNS_PORT,
    )))
    .map_err(|e| format!("bind 0.0.0.0:5353: {}", e))?;
    crate::system::logger::log_to_file("mDNS: socket bound to 0.0.0.0:5353");

    sock.join_multicast_v4(&MDNS_MULTICAST_V4, &gateway)
        .map_err(|e| {
            format!(
                "join multicast group {} on {}: {}",
                MDNS_MULTICAST_V4, interface_ip, e
            )
        })?;
    crate::system::logger::log_to_file(&format!(
        "mDNS: joined multicast {} on interface {}",
        MDNS_MULTICAST_V4, interface_ip
    ));

    sock.set_multicast_ttl_v4(255)
        .map_err(|e| format!("set multicast TTL: {}", e))?;
    sock.set_multicast_if_v4(&gateway)
        .map_err(|e| format!("set multicast interface: {}", e))?;

    // Don't receive our own multicast packets.
    sock.set_multicast_loop_v4(false)
        .map_err(|e| format!("set multicast loop off: {}", e))?;

    sock.set_nonblocking(false)
        .map_err(|e| format!("set blocking: {}", e))?;

    // Convert socket2 to std::net::UdpSocket for convenience.
    Ok(std::net::UdpSocket::from(sock))
}

// ---------------------------------------------------------------------------
// Responder handle
// ---------------------------------------------------------------------------

pub struct MdnsHandle {
    stop_flag: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MdnsHandle {
    fn drop(&mut self) {
        crate::system::logger::log_to_file("mDNS: MdnsHandle dropping, signalling stop");
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
        crate::system::logger::log_to_file("mDNS: MdnsHandle dropped, responder thread joined");
    }
}

impl MdnsHandle {
    pub fn start(hostname: &str, gateway_ip: &str) -> Result<Self, String> {
        crate::system::logger::log_to_file(&format!(
            "mDNS: starting A-record responder for {}.local -> {}",
            hostname, gateway_ip
        ));

        // Diagnostic: log who else is on 5353, but do NOT fail.
        // Our socket2 socket with SO_REUSEADDR can share the port.
        if let Some(occupants) = get_5353_owner_info() {
            crate::system::logger::log_to_file(&format!(
                "mDNS: UDP 5353 is also used by {} — attempting shared bind with SO_REUSEADDR",
                occupants
            ));
        }

        // Parse the gateway IP upfront.
        let _: Ipv4Addr = gateway_ip
            .parse()
            .map_err(|e| format!("invalid gateway IP '{}': {}", gateway_ip, e))?;

        let host_fqdn = format!("{}.local", hostname);
        let host_fqdn_owned = host_fqdn.clone();
        let ip_owned = gateway_ip.to_string();

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop = stop_flag.clone();

        let socket = match create_mdns_socket(gateway_ip) {
            Ok(s) => s,
            Err(e) => {
                // Augment the error with occupant info for the UI.
                let mut msg = e;
                if let Some(occupants) = get_5353_owner_info() {
                    msg.push_str(&format!(" (current occupants: {})", occupants));
                }
                msg.push_str(
                    ". UDP 5353 cannot be shared on this system. See README for workarounds.",
                );
                return Err(msg);
            }
        };

        // Set a 1 s read timeout so we can poll the stop flag periodically.
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|e| format!("set read timeout: {}", e))?;

        let thread = std::thread::Builder::new()
            .name("mDNS_responder".into())
            .spawn(move || {
                responder_loop(socket, &host_fqdn_owned, &ip_owned, &stop);
            })
            .map_err(|e| format!("spawn mDNS thread: {}", e))?;

        crate::system::logger::log_to_file(&format!(
            "mDNS: responder thread started for {}.local -> {}",
            hostname, gateway_ip
        ));

        Ok(MdnsHandle {
            stop_flag,
            thread: Some(thread),
        })
    }

    /// Send goodbye and shut down.
    pub fn shutdown(mut self) {
        crate::system::logger::log_to_file("mDNS: shutdown requested");
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
        crate::system::logger::log_to_file("mDNS: shutdown complete");
    }
}

// ---------------------------------------------------------------------------
// Responder thread
// ---------------------------------------------------------------------------

fn responder_loop(socket: UdpSocket, host_fqdn: &str, ip: &str, stop: &AtomicBool) {
    let mut buf = [0u8; RECV_BUF_LEN];
    let multicast_dest = SocketAddrV4::new(MDNS_MULTICAST_V4, MDNS_PORT);
    let mut query_count: u64 = 0;
    let mut response_count: u64 = 0;
    let mut last_logged = std::time::Instant::now();
    let mut sampled: std::collections::HashMap<(String, u16, u16), u64> =
        std::collections::HashMap::new(); // (name, type, class) -> count

    loop {
        if stop.load(Ordering::SeqCst) {
            let goodbye = build_a_response(host_fqdn, ip, 0, None, 0);
            let _ = socket.send_to(&goodbye, multicast_dest);
            crate::system::logger::log_to_file("mDNS: goodbye sent, responder exiting");
            return;
        }

        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let data = &buf[..len];
                query_count += 1;

                // Parse all questions for sampling and matching.
                let src_v4 = match src {
                    std::net::SocketAddr::V4(a) => a,
                    _ => continue, // skip IPv6 sources for now
                };
                let matched = process_queries(
                    data,
                    host_fqdn,
                    ip,
                    &socket,
                    &mut response_count,
                    &mut sampled,
                    src_v4,
                );

                if matched {
                    // Already counted in process_queries.
                }

                // Periodic summary.
                let now = std::time::Instant::now();
                if now.duration_since(last_logged).as_secs() >= 60 {
                    log_periodic_summary(query_count, response_count, &mut sampled);
                    query_count = 0;
                    response_count = 0;
                    last_logged = now;
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                crate::system::logger::log_to_file(&format!("mDNS: recv error: {}", e));
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// Iterate over all questions in a DNS packet, log samples, and send
/// responses for matching A queries. Returns true if at least one response
/// was sent.
fn process_queries(
    data: &[u8],
    host_fqdn: &str,
    ip: &str,
    socket: &UdpSocket,
    response_count: &mut u64,
    sampled: &mut std::collections::HashMap<(String, u16, u16), u64>,
    src: SocketAddrV4,
) -> bool {
    if data.len() < 12 {
        return false;
    }
    // Skip responses.
    if data[2] & 0x80 != 0 {
        return false;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    if qdcount == 0 {
        return false;
    }

    // Normalise our hostname: lowercase, trailing dot for exact FQDN match.
    let our_fqdn = host_fqdn.trim_end_matches('.').to_lowercase();
    let our_fqdn_dot = format!("{}.", our_fqdn);

    let mut offset = 12; // start of question section
    let mut matched = false;

    for _qi in 0..qdcount {
        if offset + 5 > data.len() {
            break;
        }

        let (qname, next) = match decode_dns_name(data, offset) {
            Some(v) => v,
            None => break, // compression or parse error — skip
        };
        if next + 4 > data.len() {
            break;
        }

        let qtype = u16::from_be_bytes([data[next], data[next + 1]]);
        let qclass_raw = u16::from_be_bytes([data[next + 2], data[next + 3]]);
        let qclass_base = qclass_raw & 0x7FFF;
        let has_uc = (qclass_raw & 0x8000) != 0;

        offset = next + 4;

        // Sample (deduplicate by name + type + class_base).
        let qname_lower = qname.to_lowercase();
        let sample_key = (qname_lower.clone(), qtype, qclass_base);
        if sampled.len() < 512 || sampled.contains_key(&sample_key) {
            *sampled.entry(sample_key).or_insert(0) += 1;
        }

        // ----- matching -----
        let name_match = qname_lower == our_fqdn || qname_lower == our_fqdn_dot;
        let class_ok = qclass_base == 1; // IN class (strip unicast bit)

        if !name_match || !class_ok {
            continue;
        }

        match qtype {
            DNS_TYPE_A | 255 => {
                // A query — respond.
                // RFC 6762 section 6.7: clients using an ephemeral source port
                // require a legacy unicast response, even without the QU bit.
                let legacy = src.port() != MDNS_PORT;
                let tx_id = if legacy {
                    u16::from_be_bytes([data[0], data[1]])
                } else {
                    0
                };
                let question = legacy.then_some((qtype, qclass_raw));
                let resp = build_a_response(host_fqdn, ip, tx_id, question, DNS_TTL_SECS);
                // If the query requested a unicast response, reply directly;
                // otherwise multicast.
                let dest = if has_uc || legacy {
                    src
                } else {
                    SocketAddrV4::new(MDNS_MULTICAST_V4, MDNS_PORT)
                };
                match socket.send_to(&resp, dest) {
                    Ok(_) => {
                        *response_count += 1;
                        matched = true;
                    }
                    Err(e) => {
                        crate::system::logger::log_to_file(&format!(
                            "mDNS: send A response to {} failed: {}",
                            dest, e
                        ));
                    }
                }
            }
            28 => {
                // AAAA — log once per period.
                sampled
                    .entry(("_aaaa_ignored".to_string(), 28, 1))
                    .or_insert_with(|| {
                        crate::system::logger::log_to_file(&format!(
                            "mDNS: AAAA query for {} ignored (IPv6 not yet supported)",
                            qname
                        ));
                        0
                    });
            }
            _ => {}
        }
    }

    matched
}

/// Decode a DNS label-encoded name starting at `offset`.
/// Returns `(name_string, next_offset)` on success, or `None` on parse error.
fn decode_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut jump_target = offset;
    let mut steps = 0;
    let mut name_len = 1; // terminating root label

    loop {
        if pos >= data.len() || steps >= data.len() {
            return None;
        }
        steps += 1;
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped {
                pos += 1;
            } else {
                pos = jump_target;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 2 > data.len() {
                return None;
            }
            let ptr = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize & 0x3FFF;
            if !jumped {
                jump_target = pos + 2;
            }
            pos = ptr;
            jumped = true;
            continue;
        }
        if len & 0xC0 != 0 || name_len + 1 + len > 255 {
            return None;
        }
        name_len += 1 + len;
        if pos + 1 + len > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]).to_string());
        pos += 1 + len;
    }

    let name = labels.join(".");
    Some((name, if jumped { jump_target } else { pos }))
}

fn log_periodic_summary(
    query_count: u64,
    response_count: u64,
    sampled: &mut std::collections::HashMap<(String, u16, u16), u64>,
) {
    crate::system::logger::log_to_file(&format!(
        "mDNS: {} queries received, {} responses sent in last period",
        query_count, response_count
    ));

    // Log up to 20 most-frequent unique queries.
    let mut entries: Vec<(&(String, u16, u16), &u64)> = sampled.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1));
    for ((name, qtype, qclass), count) in entries.iter().take(20) {
        let type_str = match qtype {
            1 => "A",
            12 => "PTR",
            28 => "AAAA",
            33 => "SRV",
            255 => "ANY",
            _ => "?",
        };
        crate::system::logger::log_to_file(&format!(
            "mDNS: sample name={} type={} ({}) class={} count={}",
            name, type_str, qtype, qclass, count
        ));
    }
    sampled.clear();
}

/// Diagnostic helper: return a human-readable list of processes on UDP 5353.
fn get_5353_owner_info() -> Option<String> {
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetUDPEndpoint -LocalPort 5353 -ErrorAction SilentlyContinue | \
             ForEach-Object { \
               $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; \
               Write-Output \"$($p.ProcessName) (PID $($_.OwningProcess))\" \
             }",
        ])
        .creation_flags(0x0800_0000)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.replace("\r\n", ", ").replace('\n', ", "))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_response_and_goodbye_name_the_owned_host() {
        let legacy = build_a_response(
            "gateway.local",
            "192.0.2.10",
            0xabcd,
            Some((1, 1)),
            DNS_TTL_SECS,
        );
        let (question, end) = decode_dns_name(&legacy, 12).unwrap();
        let (answer, answer_end) = decode_dns_name(&legacy, end + 4).unwrap();
        assert_eq!(question, "gateway.local");
        assert_eq!(answer, question);
        assert_eq!(&legacy[0..2], &[0xab, 0xcd]);
        assert_eq!(&legacy[answer_end + 2..answer_end + 4], &[0, 1]);
        assert_eq!(
            u32::from_be_bytes(legacy[answer_end + 4..answer_end + 8].try_into().unwrap()),
            10
        );
        let goodbye = build_a_response("gateway.local", "192.0.2.10", 0, None, 0);
        assert_eq!(&goodbye[4..8], &[0, 0, 0, 1]);
        let (name, end) = decode_dns_name(&goodbye, 12).unwrap();
        assert_eq!(name, "gateway.local");
        assert_eq!(&goodbye[end + 4..end + 8], &[0, 0, 0, 0]);
    }

    #[test]
    fn multi_question_queries_answer_only_the_matching_host_by_unicast() {
        let responder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let src = match client.local_addr().unwrap() {
            std::net::SocketAddr::V4(addr) => addr,
            _ => unreachable!(),
        };
        let mut query = vec![0; 12];
        query[0..2].copy_from_slice(&0xabcd_u16.to_be_bytes());
        query[4..6].copy_from_slice(&2u16.to_be_bytes());
        for name in ["unrelated.local", "gateway.local"] {
            query.extend_from_slice(&encode_dns_name(name));
            query.extend_from_slice(&[0, 1, 0, 1]);
        }
        let mut responses = 0;
        let mut samples = std::collections::HashMap::new();
        assert!(process_queries(
            &query,
            "gateway.local",
            "192.0.2.10",
            &responder,
            &mut responses,
            &mut samples,
            src
        ));
        let mut buf = [0; 1500];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        let (name, next) = decode_dns_name(&buf[..len], 12).unwrap();
        let (answer, _) = decode_dns_name(&buf[..len], next + 4).unwrap();
        assert_eq!(name, "gateway.local");
        assert_eq!(answer, name);
        assert_eq!(responses, 1);
    }

    #[test]
    fn disabled_mdns_ignores_invalid_hostnames_without_network_setup() {
        let controller = MdnsController::new();
        controller
            .configure(MdnsConfigSnapshot {
                enabled: false,
                hostname: "invalid.example.com".into(),
                gateway_ip: "192.0.2.10".into(),
            })
            .unwrap();
        let (_, status) = controller
            .results
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(matches!(status, MdnsStatus::Disabled));
        assert_eq!(validate_mdns_hostname("Gateway.LOCAL").unwrap(), "Gateway");
    }

    #[test]
    fn dns_decoder_rejects_compression_cycles_without_hanging() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let results = [
                decode_dns_name(&[0xc0, 0], 0),
                decode_dns_name(&[0xc0, 2, 0xc0, 0], 0),
            ];
            let _ = tx.send(results);
        });
        let results = rx
            .recv_timeout(Duration::from_millis(500))
            .expect("DNS decoder hung on a compression cycle");
        assert!(results.iter().all(Option::is_none));
    }

    #[test]
    fn dns_decoder_rejects_reserved_label_types_and_overlong_names() {
        let mut invalid_label = vec![64];
        invalid_label.extend_from_slice(&[b'a'; 64]);
        invalid_label.push(0);
        assert!(decode_dns_name(&invalid_label, 0).is_none());
        let overlong = encode_dns_name(&vec!["a".repeat(63); 5].join("."));
        assert!(decode_dns_name(&overlong, 0).is_none());
    }

    // --- hostname validation ---

    #[test]
    fn valid_simple_hostname() {
        assert_eq!(validate_mdns_hostname("gateway").unwrap(), "gateway");
    }

    #[test]
    fn valid_with_hyphen() {
        assert_eq!(validate_mdns_hostname("my-gateway").unwrap(), "my-gateway");
    }

    #[test]
    fn valid_with_digits() {
        assert_eq!(validate_mdns_hostname("gw01").unwrap(), "gw01");
    }

    #[test]
    fn valid_mixed_case() {
        assert_eq!(validate_mdns_hostname("MyGateway").unwrap(), "MyGateway");
    }

    #[test]
    fn normalizes_dot_local_suffix() {
        assert_eq!(validate_mdns_hostname("gateway.local").unwrap(), "gateway");
    }

    #[test]
    fn rejects_other_domain() {
        assert!(validate_mdns_hostname("gateway.local.domain").is_err());
        assert!(validate_mdns_hostname("gateway.example.com").is_err());
    }

    #[test]
    fn empty_input_rejected() {
        assert!(validate_mdns_hostname("").is_err());
    }

    #[test]
    fn whitespace_only_rejected() {
        assert!(validate_mdns_hostname("   ").is_err());
    }

    #[test]
    fn hyphen_at_start_rejected() {
        assert!(validate_mdns_hostname("-gateway").is_err());
    }

    #[test]
    fn hyphen_at_end_rejected() {
        assert!(validate_mdns_hostname("gateway-").is_err());
    }

    #[test]
    fn too_long_rejected() {
        let long = "a".repeat(64);
        assert!(validate_mdns_hostname(&long).is_err());
    }

    #[test]
    fn max_length_accepted() {
        let just_right = "a".repeat(63);
        assert!(validate_mdns_hostname(&just_right).is_ok());
    }

    #[test]
    fn invalid_chars_rejected() {
        assert!(validate_mdns_hostname("gate way").is_err());
        assert!(validate_mdns_hostname("gate_way").is_err());
    }

    #[test]
    fn chinese_chars_rejected() {
        assert!(validate_mdns_hostname("网关").is_err());
    }

    // --- DNS encoding / name matching ---

    #[test]
    fn encode_simple_name() {
        let encoded = encode_dns_name("uchihazzj.local");
        // uchihazzj (9) + local (5) + root (0)
        assert_eq!(encoded[0], 9);
        assert_eq!(&encoded[1..10], b"uchihazzj");
        assert_eq!(encoded[10], 5);
        assert_eq!(&encoded[11..16], b"local");
        assert_eq!(encoded[16], 0);
    }

    #[test]
    fn dns_name_matches_exact() {
        let encoded = encode_dns_name("uchihazzj.local");
        assert!(dns_name_matches(&encoded, 0, "uchihazzj.local"));
        assert!(dns_name_matches(&encoded, 0, "uchihazzj.local."));
        assert!(!dns_name_matches(&encoded, 0, "other.local"));
        assert!(!dns_name_matches(&encoded, 0, "uchihazzj.loca"));
    }

    #[test]
    fn dns_name_matches_case_insensitive() {
        let encoded = encode_dns_name("MyHost.Local");
        assert!(dns_name_matches(&encoded, 0, "myhost.local"));
        assert!(dns_name_matches(&encoded, 0, "MYHOST.LOCAL"));
    }

    #[test]
    fn decode_dns_name_parses_simple_fqdn() {
        let encoded = encode_dns_name("uchihazzj.local");
        let mut query = Vec::new();
        query.extend_from_slice(&[0x00, 0x00]); // TXID
        query.extend_from_slice(&[0x00, 0x00]); // Flags
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&encoded);
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        query.extend_from_slice(&[0x80, 0x01]); // QCLASS IN + unicast-response

        let (qname, next) = decode_dns_name(&query, 12).unwrap();
        assert_eq!(qname, "uchihazzj.local");
        let qtype = u16::from_be_bytes([query[next], query[next + 1]]);
        let qclass_raw = u16::from_be_bytes([query[next + 2], query[next + 3]]);
        assert_eq!(qtype, 1); // A
        assert_eq!(qclass_raw & 0x8000, 0x8000); // unicast-response bit set
        assert_eq!(qclass_raw & 0x7FFF, 1); // class IN after stripping bit
    }

    #[test]
    fn qclass_without_unicast_bit_is_in() {
        let encoded = encode_dns_name("test.local");
        let mut query = Vec::new();
        query.extend_from_slice(&[0x00; 12]); // header
        query.extend_from_slice(&encoded);
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS IN (no unicast bit)

        let (_qname, next) = decode_dns_name(&query, 12).unwrap();
        let qclass_raw = u16::from_be_bytes([query[next + 2], query[next + 3]]);
        assert_eq!(qclass_raw & 0x7FFF, 1); // IN
        assert_eq!(qclass_raw & 0x8000, 0);
    }

    #[test]
    fn decode_dns_name_normalizes_to_lowercase() {
        let encoded = encode_dns_name("MyHost.Local");
        let mut query = Vec::new();
        query.extend_from_slice(&[0x00; 12]);
        query.extend_from_slice(&encoded);
        query.extend_from_slice(&[0x00, 0x01]);
        query.extend_from_slice(&[0x00, 0x01]);

        let (qname, _) = decode_dns_name(&query, 12).unwrap();
        // decode_dns_name returns the raw labels; matching is done
        // by the caller via .to_lowercase() comparison.
        assert_eq!(qname.to_lowercase(), "myhost.local");
    }

    #[test]
    fn build_a_response_is_valid_dns() {
        let name = encode_dns_name("uchihazzj.local");
        let mut query = Vec::new();
        query.extend_from_slice(&[0xAB, 0xCD]); // TXID
        query.extend_from_slice(&[0x00, 0x00]); // Flags
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&name);
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        let resp = build_a_response(
            "uchihazzj.local",
            "192.0.2.10",
            0xABCD,
            Some((1, 1)),
            DNS_TTL_SECS,
        );

        // TXID should be echoed
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
        // QR + AA
        assert_eq!(resp[2], 0x84);
        assert_eq!(resp[3], 0x00);
        // QDCOUNT = 1, ANCOUNT = 1
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    // --- MdnsConfigSnapshot ---

    #[test]
    fn snapshot_needs_restart_when_disabled_changes() {
        let a = MdnsConfigSnapshot {
            enabled: false,
            hostname: "gateway".into(),
            gateway_ip: "10.0.0.1".into(),
        };
        let b = MdnsConfigSnapshot {
            enabled: true,
            hostname: "gateway".into(),
            gateway_ip: "10.0.0.1".into(),
        };
        assert!(a.needs_restart(&b));
    }

    #[test]
    fn snapshot_needs_restart_when_hostname_changes() {
        let a = MdnsConfigSnapshot {
            enabled: true,
            hostname: "gateway".into(),
            gateway_ip: "10.0.0.1".into(),
        };
        let b = MdnsConfigSnapshot {
            enabled: true,
            hostname: "gw2".into(),
            gateway_ip: "10.0.0.1".into(),
        };
        assert!(a.needs_restart(&b));
    }

    #[test]
    fn snapshot_needs_restart_when_ip_changes() {
        let a = MdnsConfigSnapshot {
            enabled: true,
            hostname: "gateway".into(),
            gateway_ip: "10.0.0.1".into(),
        };
        let b = MdnsConfigSnapshot {
            enabled: true,
            hostname: "gateway".into(),
            gateway_ip: "10.0.0.2".into(),
        };
        assert!(a.needs_restart(&b));
    }

    #[test]
    fn snapshot_no_restart_when_identical() {
        let a = MdnsConfigSnapshot {
            enabled: true,
            hostname: "gateway".into(),
            gateway_ip: "10.0.0.1".into(),
        };
        let b = a.clone();
        assert!(!a.needs_restart(&b));
    }
}
