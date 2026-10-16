use std::io;
use std::process::{Command, Output};
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::{
    io::Read,
    os::windows::io::AsRawHandle,
    process::{Child, Stdio},
    time::Instant,
};

const CREATE_NO_WINDOW: u32 = 0x08000000;
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_QUERY_OUTPUT: usize = 1024 * 1024;

pub fn run_command(program: &str, args: &[&str]) -> io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.output()
}

/// For read-only commands only: callers must not treat a timed-out mutation as cancelled.
pub fn run_query(program: &str, args: &[&str]) -> io::Result<Output> {
    #[cfg(windows)]
    {
        run_query_with_limits(program, args, QUERY_TIMEOUT, MAX_QUERY_OUTPUT)
    }
    #[cfg(not(windows))]
    {
        run_command(program, args)
    }
}

#[cfg(windows)]
fn run_query_with_limits(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_output: usize,
) -> io::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    collect_query_output(&mut child, timeout, max_output)
        .map_err(|error| io::Error::new(error.kind(), format!("Query {program}: {error}")))
}

#[cfg(windows)]
fn collect_query_output(
    child: &mut Child,
    timeout: Duration,
    max_output: usize,
) -> io::Result<Output> {
    let mut stdout_pipe = child.stdout.take().expect("query stdout must be piped");
    let mut stderr_pipe = child.stderr.take().expect("query stderr must be piped");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let started = Instant::now();
    let (mut stdout_closed, mut stderr_closed) = (false, false);
    let result = (|| loop {
        // Drain both pipes fairly, with no blocking reader threads left behind on timeout.
        if !stdout_closed {
            stdout_closed =
                read_available(&mut stdout_pipe, &mut stdout, max_output - stderr.len())?;
        }
        if !stderr_closed {
            stderr_closed =
                read_available(&mut stderr_pipe, &mut stderr, max_output - stdout.len())?;
        }
        if let Some(status) = child.try_wait()? {
            if stdout_closed && stderr_closed {
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
        }
        if started.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system query timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    })();
    if let Err(error) = &result {
        // This child is a read-only query created by us; do not leave it running.
        let termination = child.kill();
        if !matches!(wait_for_query_exit(child, Duration::from_secs(1)), Ok(true)) {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "{error}; query PID {} did not finish cleanup: {}",
                    child.id(),
                    termination.err().map_or_else(
                        || "termination requested, still waiting".into(),
                        |error| format!("termination failed: {error}")
                    )
                ),
            ));
        }
    }
    result
}

#[cfg(windows)]
fn wait_for_query_exit(child: &mut Child, timeout: Duration) -> io::Result<bool> {
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(true);
        }
        if started.elapsed() >= timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(windows)]
fn read_available(
    pipe: &mut (impl Read + AsRawHandle),
    out: &mut Vec<u8>,
    limit: usize,
) -> io::Result<bool> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn PeekNamedPipe(
            pipe: *mut std::ffi::c_void,
            buffer: *mut std::ffi::c_void,
            size: u32,
            read: *mut u32,
            available: *mut u32,
            left: *mut u32,
        ) -> i32;
    }
    let mut available = 0;
    // Only this worker reads this handle, and no read is pending while we peek.
    let ok = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(109 | 232)) {
            Ok(true)
        } else {
            Err(error)
        };
    }
    if available == 0 {
        return Ok(false);
    }
    if out.len() >= limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system query output exceeds limit",
        ));
    }
    let mut buffer = [0; 16 * 1024];
    let count = (available as usize)
        .min(buffer.len())
        .min(limit - out.len());
    let count = pipe.read(&mut buffer[..count])?;
    out.extend_from_slice(&buffer[..count]);
    Ok(count == 0)
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status_success: bool,
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl From<Output> for CommandOutput {
    fn from(output: Output) -> Self {
        Self {
            status_success: output.status.success(),
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }
}

pub trait CommandExecutor {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput>;

    fn query(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        self.run(program, args)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        run_command(program, args).map(CommandOutput::from)
    }

    fn query(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        run_query(program, args).map(CommandOutput::from)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn query_limits_stop_a_hung_child() {
        let started = Instant::now();
        let result = run_query_with_limits(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 2",
            ],
            Duration::from_millis(100),
            1024,
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn query_limits_reject_excessive_output() {
        let result = run_query_with_limits(
            "cmd",
            &[
                "/D",
                "/C",
                "for /L %i in (1,1,1000) do @echo abcdefghijklmnopqrstuvwxyz",
            ],
            Duration::from_secs(5),
            128,
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn query_captures_both_pipes_and_the_exit_status() {
        let output = run_query(
            "cmd",
            &["/D", "/C", "echo output&echo error 1>&2&exit /b 7"],
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert!(String::from_utf8(output.stdout).unwrap().contains("output"));
        assert!(String::from_utf8(output.stderr).unwrap().contains("error"));
    }

    #[test]
    fn timed_out_query_child_is_reaped() {
        let mut child = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 2",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let error = collect_query_output(&mut child, Duration::from_millis(100), 1024).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn query_drains_stdout_and_stderr_larger_than_a_pipe_buffer() {
        let output = run_query(
            "cmd",
            &[
                "/D",
                "/C",
                "for /L %i in (1,1,1000) do @(echo output&echo error 1>&2)",
            ],
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().lines().count(),
            1000
        );
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().lines().count(),
            1000
        );
    }

    #[test]
    fn query_cleanup_wait_is_bounded_even_when_a_child_keeps_running() {
        let mut child = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 2",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let finished = wait_for_query_exit(&mut child, Duration::from_millis(20)).unwrap();
        let elapsed = started.elapsed();
        let _ = child.kill();
        let _ = child.wait();
        assert!(!finished);
        assert!(elapsed < Duration::from_millis(500));
    }
}
