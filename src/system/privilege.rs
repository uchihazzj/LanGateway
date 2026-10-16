use crate::system::process;

pub fn is_admin() -> bool {
    process::run_query("net", &["session"])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn restart_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("Failed to get exe path: {}", e))?;
    let dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    let script = elevation_script(&exe, &dir);

    let output = process::run_command("powershell", &["-NoProfile", "-Command", &script])
        .map_err(|e| format!("Failed to launch elevation: {}", e))?;

    if output.status.success() {
        std::process::exit(0);
    } else {
        let stderr = crate::system::encoding::decode(&output.stderr);
        if stderr.trim().is_empty() {
            Err("UAC elevation was cancelled.".into())
        } else {
            Err(format!("UAC elevation failed: {}", stderr.trim()))
        }
    }
}

fn elevation_script(exe: &std::path::Path, dir: &std::path::Path) -> String {
    format!(
        "Start-Process -FilePath '{}' -WorkingDirectory '{}' -Verb RunAs",
        exe.to_string_lossy().replace('\'', "''"),
        dir.to_string_lossy().replace('\'', "''")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_quotes_apostrophes_in_paths_as_powershell_literals() {
        let script = elevation_script(
            std::path::Path::new("C:\\Tools\\O'Brien\\langateway.exe"),
            std::path::Path::new("C:\\Tools\\O'Brien"),
        );
        assert_eq!(script, "Start-Process -FilePath 'C:\\Tools\\O''Brien\\langateway.exe' -WorkingDirectory 'C:\\Tools\\O''Brien' -Verb RunAs");
    }
}
