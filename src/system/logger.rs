use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, SyncSender, TrySendError},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};

const MAX_LOG_TAIL_BYTES: u64 = 256 * 1024;
const MAX_LOG_MESSAGE_BYTES: usize = 8 * 1024;
const LOG_QUEUE_CAPACITY: usize = 128;
static LOGGER: OnceLock<Option<AsyncLogger>> = OnceLock::new();

enum LogMessage {
    Line(String),
    Flush(SyncSender<()>),
}

struct AsyncLogger {
    sender: SyncSender<LogMessage>,
    dropped: Arc<AtomicUsize>,
}

impl AsyncLogger {
    fn new(capacity: usize, mut write: impl FnMut(&str) + Send + 'static) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicUsize::new(0));
        let worker_dropped = dropped.clone();
        std::thread::Builder::new()
            .name("LanGateway_log".into())
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    match message {
                        LogMessage::Line(line) => {
                            let count = worker_dropped.swap(0, Ordering::Relaxed);
                            if count > 0 {
                                write(&format!(
                                    "[{}] Logging queue full: dropped {count} message(s)",
                                    chrono_now()
                                ));
                            }
                            write(&line);
                        }
                        LogMessage::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })?;
        Ok(Self { sender, dropped })
    }

    fn log(&self, message: &str) {
        let mut end = message.len().min(MAX_LOG_MESSAGE_BYTES);
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        let suffix = if end < message.len() {
            " [truncated]"
        } else {
            ""
        };
        let line = format!("[{}] {}{suffix}", chrono_now(), &message[..end]);
        if self.sender.try_send(LogMessage::Line(line)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Used only by diagnostics workers and after the native event loop exits.
    fn flush(&self, timeout: Duration) -> bool {
        let started = Instant::now();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut message = LogMessage::Flush(sender);
        loop {
            match self.sender.try_send(message) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(pending)) => message = pending,
            }
            if started.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        receiver
            .recv_timeout(timeout.saturating_sub(started.elapsed()))
            .is_ok()
    }
}

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
    let logger = LOGGER.get_or_init(|| AsyncLogger::new(LOG_QUEUE_CAPACITY, write_line).ok());
    if let Some(logger) = logger {
        logger.log(msg);
    }
}

pub fn flush(timeout: Duration) {
    if let Some(Some(logger)) = LOGGER.get() {
        logger.flush(timeout);
    }
}

fn write_line(line: &str) {
    ensure_log_dir();
    let path = log_path();
    // Write UTF-8 BOM only if the file is new or empty.
    // This keeps the BOM at the very start of the file so that
    // PowerShell 5.1's Get-Content can auto-detect the encoding.
    let write_bom = !path.exists() || path.metadata().map(|m| m.len() == 0).unwrap_or(true);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        if write_bom {
            let _ = f.write_all(&[0xEF, 0xBB, 0xBF]);
        }
        let _ = writeln!(f, "{line}");
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
    flush(Duration::from_millis(250));
    fs::File::open(log_path())
        .and_then(|mut file| read_log_tail(&mut file, max_lines))
        .unwrap_or_default()
}

fn read_log_tail(reader: &mut (impl Read + Seek), max_lines: usize) -> io::Result<Vec<String>> {
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let end = reader.seek(SeekFrom::End(0))?;
    let start = end.saturating_sub(MAX_LOG_TAIL_BYTES);
    reader.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    reader.take(MAX_LOG_TAIL_BYTES).read_to_end(&mut bytes)?;
    // Ignore a partial first line and tolerate an old file's invalid UTF-8.
    let bytes = if start > 0 {
        bytes
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(&[][..], |offset| &bytes[offset + 1..])
    } else {
        &bytes
    };
    let content = String::from_utf8_lossy(bytes);
    let mut lines: Vec<String> = content
        .lines()
        .rev()
        .take(max_lines)
        .map(|l| l.trim_start_matches('\u{feff}').to_string())
        .collect();
    lines.reverse();
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountedReader {
        inner: io::Cursor<Vec<u8>>,
        read_bytes: usize,
    }
    impl Read for CountedReader {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(bytes)?;
            self.read_bytes += read;
            Ok(read)
        }
    }
    impl Seek for CountedReader {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn recent_logs_read_only_a_bounded_tail() {
        let content = format!("{}latest one\nlatest two\n", "old line\n".repeat(100_000));
        let mut reader = CountedReader {
            inner: io::Cursor::new(content.into_bytes()),
            read_bytes: 0,
        };
        assert_eq!(
            read_log_tail(&mut reader, 2).unwrap(),
            ["latest one", "latest two"]
        );
        assert!(
            reader.read_bytes <= MAX_LOG_TAIL_BYTES as usize,
            "read {} bytes",
            reader.read_bytes
        );
    }

    #[test]
    fn slow_disk_and_full_logging_queue_do_not_block_the_caller() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut first = true;
        let logger = AsyncLogger::new(2, move |_| {
            if first {
                first = false;
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
            }
        })
        .unwrap();
        logger.log("block the test writer");
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        for _ in 0..1000 {
            logger.log("background event");
        }
        let elapsed = started.elapsed();
        let dropped = logger.dropped.load(Ordering::Relaxed);
        // Release the fake disk before assertions, including on an unexpected result.
        release_tx.send(()).unwrap();
        assert!(
            elapsed < Duration::from_millis(200),
            "logging blocked for {elapsed:?}"
        );
        assert!(dropped > 0);
        assert!(logger.flush(Duration::from_secs(1)));
    }

    #[test]
    fn log_messages_are_bounded_without_splitting_unicode() {
        let (tx, rx) = mpsc::channel();
        let logger = AsyncLogger::new(2, move |line| {
            let _ = tx.send(line.to_owned());
        })
        .unwrap();
        logger.log(&"测试".repeat(MAX_LOG_MESSAGE_BYTES));
        assert!(logger.flush(Duration::from_secs(1)));
        let line = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(line.len() < MAX_LOG_MESSAGE_BYTES + 64);
        assert!(line.ends_with(" [truncated]"));
    }

    #[test]
    fn log_tail_handles_empty_bom_and_truncated_or_invalid_text() {
        assert!(read_log_tail(&mut io::Cursor::new(b""), 40)
            .unwrap()
            .is_empty());
        assert_eq!(
            read_log_tail(&mut io::Cursor::new("\u{feff}中文\r\nlast\n"), 2).unwrap(),
            ["中文", "last"]
        );
        assert_eq!(
            read_log_tail(&mut io::Cursor::new(b"\xff\nbad\nlast\n"), 1).unwrap(),
            ["last"]
        );
        let mut empty_request = CountedReader {
            inner: io::Cursor::new(vec![0; 100]),
            read_bytes: 0,
        };
        assert!(read_log_tail(&mut empty_request, 0).unwrap().is_empty());
        assert_eq!(empty_request.read_bytes, 0);
    }
}
