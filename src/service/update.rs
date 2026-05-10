/// State machine for the auto-update flow.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    Idle,
    Checking,
    UpToDate,
    Available {
        latest: String,
        release_url: String,
        download_url: String,
    },
    Downloading,
    PreparingUpdate,
    Restarting,
    Failed(String),
}

impl UpdateStatus {
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            UpdateStatus::Checking
                | UpdateStatus::Downloading
                | UpdateStatus::PreparingUpdate
                | UpdateStatus::Restarting
        )
    }
}

const GITHUB_REPO: &str = "uchihazzj/LanGateway";
const ASSET_NAME: &str = "langateway.exe";
const PROCESS_NAME: &str = "langateway";

#[derive(Debug, serde::Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, serde::Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

/// Parse version numbers for comparison. Strips leading 'v'.
fn is_newer(local: &str, remote: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.trim_start_matches('v')
            .split('.')
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let a = parse(local);
    let b = parse(remote);
    let n = a.len().max(b.len());
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match bv.cmp(&av) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

/// Query the GitHub API for the latest release. Returns (latest_version, release_url, download_url) if newer.
pub fn check_update() -> Result<Option<(String, String, String)>, String> {
    let local_version = env!("CARGO_PKG_VERSION");

    let body: String = ureq::get(&format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    ))
    .header("Accept", "application/vnd.github+json")
    .header("User-Agent", "langateway")
    .call()
    .map_err(|e| format!("Request failed: {}", e))?
    .into_body()
    .read_to_string()
    .map_err(|e| format!("Failed to read response: {}", e))?;

    let release: GitHubRelease =
        serde_json::from_str(&body).map_err(|e| format!("Failed to parse release JSON: {}", e))?;

    if !is_newer(local_version, &release.tag_name) {
        return Ok(None);
    }

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == ASSET_NAME)
        .ok_or_else(|| format!("No '{}' asset found in release", ASSET_NAME))?;

    Ok(Some((
        release.tag_name,
        release.html_url,
        asset.browser_download_url.clone(),
    )))
}

/// Download the new exe, write updater.ps1, and exit.
/// The updater script handles exe replacement after this process exits.
pub fn perform_update(download_url: &str, latest_version: &str) -> Result<(), String> {
    let exe_dir = std::env::current_exe()
        .map_err(|e| format!("Failed to get exe path: {}", e))?
        .parent()
        .ok_or_else(|| "Failed to get exe directory".to_string())?
        .to_path_buf();

    let old_exe = exe_dir.join("langateway.exe");
    let new_exe = exe_dir.join(format!("langateway-v{}.exe", latest_version));
    let bak_exe = exe_dir.join("langateway.exe.bak");
    let download_tmp = exe_dir.join(format!("langateway-v{}.exe.download", latest_version));

    // Download
    let download_bytes = ureq::get(download_url)
        .header("User-Agent", "langateway")
        .call()
        .map_err(|e| format!("Download failed: {}", e))?
        .into_body()
        .read_to_vec()
        .map_err(|e| format!("Failed to read download: {}", e))?;

    std::fs::write(&download_tmp, &download_bytes)
        .map_err(|e| format!("Failed to write download: {}", e))?;

    // Rename .download → final
    std::fs::rename(&download_tmp, &new_exe)
        .map_err(|e| format!("Failed to rename download: {}", e))?;

    // Write updater.ps1
    let script = updater_script();
    let script_path = exe_dir.join("updater.ps1");
    std::fs::write(&script_path, &script)
        .map_err(|e| format!("Failed to write updater script: {}", e))?;

    // Launch updater
    std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &script_path.to_string_lossy(),
            "-OldExe",
            &old_exe.to_string_lossy(),
            "-NewExe",
            &new_exe.to_string_lossy(),
            "-BakExe",
            &bak_exe.to_string_lossy(),
        ])
        .spawn()
        .map_err(|e| format!("Failed to launch updater: {}", e))?;

    std::process::exit(0);
}

fn updater_script() -> String {
    // Use string replacement to avoid format!() conflicts with PowerShell {} syntax.
    let script = r#"param(
    [string]$OldExe,
    [string]$NewExe,
    [string]$BakExe
)

$ErrorActionPreference = "Stop"

Start-Sleep -Seconds 2
$timeout = 30
while ($timeout -gt 0) {
    $proc = Get-Process -Name "PROCESS_NAME" -ErrorAction SilentlyContinue
    if (-not $proc) { break }
    Start-Sleep -Seconds 1
    $timeout--
}

try {
    if (Test-Path -LiteralPath $OldExe) {
        Move-Item -LiteralPath $OldExe -Destination $BakExe -Force -ErrorAction Stop
    }
    Move-Item -LiteralPath $NewExe -Destination $OldExe -Force -ErrorAction Stop
    Start-Process -FilePath $OldExe
    Start-Sleep -Seconds 3
    if (Test-Path -LiteralPath $BakExe) {
        Remove-Item -LiteralPath $BakExe -Force
    }
} catch {
    if ((Test-Path -LiteralPath $BakExe) -and (-not (Test-Path -LiteralPath $OldExe))) {
        Move-Item -LiteralPath $BakExe -Destination $OldExe -Force -ErrorAction SilentlyContinue
    }
}

Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"#;
    script.replace("PROCESS_NAME", PROCESS_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_detects_minor_bump() {
        assert!(is_newer("0.2.1", "v0.3.0"));
    }

    #[test]
    fn is_newer_detects_patch_bump() {
        assert!(is_newer("0.2.1", "v0.2.2"));
    }

    #[test]
    fn is_newer_equal_with_v_prefix() {
        assert!(!is_newer("0.2.1", "v0.2.1"));
    }

    #[test]
    fn is_newer_equal_without_v_prefix() {
        assert!(!is_newer("0.2.1", "0.2.1"));
    }

    #[test]
    fn is_newer_major_bump() {
        assert!(is_newer("0.2.1", "v1.0.0"));
    }

    #[test]
    fn is_newer_remote_is_older() {
        assert!(!is_newer("0.3.0", "v0.2.1"));
    }

    #[test]
    fn is_newer_handles_missing_components() {
        assert!(!is_newer("1.0", "v1.0.0"));
    }

    #[test]
    fn update_status_is_busy_when_checking() {
        assert!(UpdateStatus::Checking.is_busy());
    }

    #[test]
    fn update_status_is_not_busy_when_idle() {
        assert!(!UpdateStatus::Idle.is_busy());
    }

    #[test]
    fn update_status_is_not_busy_when_uptodate() {
        assert!(!UpdateStatus::UpToDate.is_busy());
    }
}
