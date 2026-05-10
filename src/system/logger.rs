use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn log_dir() -> PathBuf {
    let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(appdata).join("LanGateway").join("logs")
}

fn log_path() -> PathBuf {
    log_dir().join("langateway.log")
}

pub fn ensure_log_dir() {
    if let Err(e) = fs::create_dir_all(log_dir()) {
        eprintln!("WARNING: Failed to create log directory: {}", e);
    }
}

pub fn log_to_file(msg: &str) {
    ensure_log_dir();
    let ts = chrono_now();
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
        let _ = writeln!(f, "[{}] {}", ts, msg);
    }
}

fn chrono_now() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = t.as_secs();
    let mins = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    let days = secs / 86400;
    // Simple date/time from UNIX timestamp
    // days since 1970 is good enough for logging
    format!("{}d {:02}:{:02}", days, hours, mins)
}
