use std::fs;
use std::io::Write;
use std::path::PathBuf;

pub fn log_dir() -> PathBuf {
    PathBuf::from("C:\\ProgramData\\LanGateway\\logs")
}

pub fn log_path() -> PathBuf {
    log_dir().join("langateway.log")
}

pub fn ensure_log_dir() {
    if let Err(e) = fs::create_dir_all(log_dir()) {
        eprintln!("WARNING: Failed to create log directory: {}", e);
    }
}

pub fn log_to_file(msg: &str) {
    ensure_log_dir();
    let path = log_path();
    // Write UTF-8 BOM only if the file is new or empty.
    // This keeps the BOM at the very start of the file so that
    // PowerShell 5.1's Get-Content can auto-detect the encoding.
    let write_bom = !path.exists() || path.metadata().map(|m| m.len() == 0).unwrap_or(true);
    let ts = chrono_now();
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        if write_bom {
            let _ = f.write_all(&[0xEF, 0xBB, 0xBF]);
        }
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
    format!("{}d {:02}:{:02}", days, hours, mins)
}

pub fn read_recent_lines(max_lines: usize) -> Vec<String> {
    let content = match fs::read_to_string(log_path()) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut lines: Vec<String> = content
        .lines()
        .map(|l| l.trim_start_matches('\u{feff}').to_string())
        .collect();
    if lines.len() > max_lines {
        lines.drain(0..lines.len() - max_lines);
    }
    lines
}
