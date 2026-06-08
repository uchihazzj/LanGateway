use std::io;
use std::process::{Command, Output};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn run_command(program: &str, args: &[&str]) -> io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.output()
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
}

#[derive(Debug, Clone, Copy)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        run_command(program, args).map(CommandOutput::from)
    }
}
