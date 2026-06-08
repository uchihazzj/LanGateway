use std::path::{Path, PathBuf};
use std::time::Duration;

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
const MIN_EXE_SIZE_BYTES: u64 = 102_400;

/// Proxy strategy order for GitHub requests. Tests assert these choices without
/// making real network requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum GithubCheckOrder {
    DirectThenSystem,
    SystemThenDirect,
}

#[allow(dead_code)]
pub const API_CHECK_ORDER: GithubCheckOrder = GithubCheckOrder::DirectThenSystem;

#[allow(dead_code)]
pub const DOWNLOAD_ORDER: GithubCheckOrder = GithubCheckOrder::SystemThenDirect;

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

fn log_update(message: &str) {
    crate::system::logger::log_to_file(&format!("[Update] {}", message));
}

fn user_agent() -> String {
    format!(
        "langateway/{} (+https://github.com/{})",
        env!("CARGO_PKG_VERSION"),
        GITHUB_REPO
    )
}

fn build_github_agent(use_proxy: bool, timeout_secs: u64) -> ureq::Agent {
    let proxy = if use_proxy {
        ureq::Proxy::try_from_env()
    } else {
        None
    };

    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(false)
        .user_agent(user_agent())
        .proxy(proxy)
        .build()
        .into()
}

fn safe_truncate(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

fn header_value(headers: &ureq::http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string()
}

fn is_rate_limit_response(status: u16, body: &str) -> bool {
    status == 429 || (status == 403 && body.to_lowercase().contains("rate limit"))
}

fn format_rate_limit_error(
    status: u16,
    remaining: &str,
    reset: &str,
    request_id: &str,
    body: &str,
) -> String {
    format!(
        "GitHub API rate limit exceeded (HTTP {}). Remaining: {}, Reset: {}, Request-ID: {}. Body: {}",
        status, remaining, reset, request_id, body
    )
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

fn do_check_update(use_proxy: bool) -> Result<Option<(String, String, String)>, String> {
    let local_version = env!("CARGO_PKG_VERSION");
    let agent = build_github_agent(use_proxy, 8);
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    let mut response = agent
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let remaining = header_value(response.headers(), "x-ratelimit-remaining");
        let reset = header_value(response.headers(), "x-ratelimit-reset");
        let request_id = header_value(response.headers(), "x-github-request-id");
        let body = response.body_mut().read_to_string().unwrap_or_default();
        let body_msg = safe_truncate(body.trim(), 300);

        if is_rate_limit_response(status.as_u16(), &body_msg) {
            return Err(format_rate_limit_error(
                status.as_u16(),
                &remaining,
                &reset,
                &request_id,
                &body_msg,
            ));
        }
        return Err(format!("HTTP {}: {}", status.as_u16(), body_msg));
    }

    let body = response
        .body_mut()
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

/// Query the GitHub API for the latest release. Returns
/// (latest_version, release_url, download_url) if newer.
pub fn check_update() -> Result<Option<(String, String, String)>, String> {
    match do_check_update(false) {
        Ok(result) => Ok(result),
        Err(direct_err) => {
            log_update(&format!(
                "Direct API check failed: {}; falling back to system proxy",
                direct_err
            ));
            do_check_update(true).map_err(|proxy_err| {
                format!(
                    "direct check failed: {}; system proxy check failed: {}",
                    direct_err, proxy_err
                )
            })
        }
    }
}

fn do_download(download_url: &str, use_proxy: bool) -> Result<Vec<u8>, String> {
    let agent = build_github_agent(use_proxy, 120);
    let mut response = agent
        .get(download_url)
        .call()
        .map_err(|e| format!("download request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.body_mut().read_to_string().unwrap_or_default();
        let body_msg = safe_truncate(body.trim(), 200);
        return Err(format!("HTTP {}: {}", status.as_u16(), body_msg));
    }

    response
        .body_mut()
        .read_to_vec()
        .map_err(|e| format!("download read failed: {}", e))
}

fn download_asset(download_url: &str) -> Result<Vec<u8>, String> {
    match do_download(download_url, true) {
        Ok(bytes) => Ok(bytes),
        Err(proxy_err) => {
            log_update(&format!(
                "System proxy download failed: {}; falling back to direct",
                proxy_err
            ));
            do_download(download_url, false).map_err(|direct_err| {
                format!(
                    "system proxy download failed: {}; direct download failed: {}",
                    proxy_err, direct_err
                )
            })
        }
    }
}

fn exe_dir() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|e| format!("Failed to get exe path: {}", e))?
        .parent()
        .ok_or_else(|| "Failed to get exe directory".to_string())
        .map(Path::to_path_buf)
}

fn version_without_v(version: &str) -> &str {
    version.trim_start_matches('v')
}

fn download_filename(latest_version: &str) -> String {
    format!("langateway-v{}.exe", version_without_v(latest_version))
}

fn write_download(bytes: &[u8], download_path: &Path, final_path: &Path) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("Downloaded file is empty (0 bytes)".to_string());
    }

    std::fs::write(download_path, bytes).map_err(|e| format!("Failed to write download: {}", e))?;

    match std::fs::metadata(download_path) {
        Ok(meta) if meta.len() as usize == bytes.len() => {}
        Ok(meta) => {
            let _ = std::fs::remove_file(download_path);
            return Err(format!(
                "Download size mismatch: expected {} bytes, got {} bytes on disk",
                bytes.len(),
                meta.len()
            ));
        }
        Err(e) => {
            let _ = std::fs::remove_file(download_path);
            return Err(format!("Failed to verify downloaded file: {}", e));
        }
    }

    if final_path.exists() {
        let _ = std::fs::remove_file(final_path);
    }

    std::fs::rename(download_path, final_path).map_err(|e| {
        let _ = std::fs::remove_file(download_path);
        format!("Failed to rename download: {}", e)
    })
}

/// Download the new exe, write updater.ps1, and exit.
/// The updater script handles exe replacement after this process exits.
pub fn perform_update<F>(
    download_url: &str,
    latest_version: &str,
    mut set_status: F,
) -> Result<(), String>
where
    F: FnMut(UpdateStatus),
{
    let dir = exe_dir()?;
    let filename = download_filename(latest_version);
    let download_tmp = dir.join(format!("{}.download", filename));
    let new_exe = dir.join(&filename);
    let old_exe = dir.join(ASSET_NAME);
    let bak_exe = dir.join(format!("{}.bak", ASSET_NAME));
    let script_path = dir.join("updater.ps1");
    let updater_log_path = dir.join("updater.log");

    log_update(&format!("Downloading {}", filename));
    let download_bytes = download_asset(download_url)?;
    write_download(&download_bytes, &download_tmp, &new_exe)?;
    log_update(&format!(
        "Downloaded {} bytes to {}",
        download_bytes.len(),
        new_exe.display()
    ));

    set_status(UpdateStatus::PreparingUpdate);

    let script = updater_script();
    std::fs::write(&script_path, &script)
        .map_err(|e| format!("Failed to write updater script: {}", e))?;

    set_status(UpdateStatus::Restarting);

    let script_path_str = script_path.to_string_lossy().to_string();
    let old_exe_str = old_exe.to_string_lossy().to_string();
    let new_exe_str = new_exe.to_string_lossy().to_string();
    let bak_exe_str = bak_exe.to_string_lossy().to_string();
    let updater_log_str = updater_log_path.to_string_lossy().to_string();

    use std::os::windows::process::CommandExt;
    std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-File",
            &script_path_str,
            "-OldExe",
            &old_exe_str,
            "-NewExe",
            &new_exe_str,
            "-BakExe",
            &bak_exe_str,
            "-LogFile",
            &updater_log_str,
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| format!("Failed to launch updater: {}", e))?;

    log_update(&format!(
        "Updater launched for {}, exiting for self-replacement",
        latest_version
    ));
    std::process::exit(0);
}

fn updater_script() -> String {
    // Use string replacement to avoid format!() conflicts with PowerShell syntax.
    let script = r#"param(
    [string]$OldExe,
    [string]$NewExe,
    [string]$BakExe,
    [string]$LogFile
)

$ErrorActionPreference = "Continue"

function Write-Log($msg) {
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$stamp $msg" | Out-File -LiteralPath $LogFile -Append -Encoding utf8
}

Write-Log "Updater started"
Write-Log "OldExe=$OldExe"
Write-Log "NewExe=$NewExe"
Write-Log "BakExe=$BakExe"

if (-not (Test-Path -LiteralPath $NewExe)) {
    Write-Log "FATAL: NewExe not found at $NewExe"
    exit 1
}

$newSize = (Get-Item -LiteralPath $NewExe).Length
if ($newSize -lt MIN_EXE_SIZE_BYTES) {
    Write-Log "FATAL: NewExe too small ($newSize bytes), likely corrupt download"
    exit 1
}
Write-Log "NewExe size: $newSize bytes"

Start-Sleep -Seconds 2
$timeout = 30
while ($timeout -gt 0) {
    $proc = Get-Process -Name "PROCESS_NAME" -ErrorAction SilentlyContinue
    if (-not $proc) { break }
    Write-Log "Waiting for PROCESS_NAME to exit... ($timeout attempts left)"
    Start-Sleep -Seconds 1
    $timeout--
}

if ($timeout -eq 0) {
    Write-Log "WARN: process still running after 30 seconds, attempting replacement"
}

$maxRetries = 5
$success = $false
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        if (Test-Path -LiteralPath $OldExe) {
            Write-Log "Moving $OldExe -> $BakExe (attempt $i)"
            Move-Item -LiteralPath $OldExe -Destination $BakExe -Force -ErrorAction Stop
        }
        Write-Log "Moving $NewExe -> $OldExe (attempt $i)"
        Move-Item -LiteralPath $NewExe -Destination $OldExe -Force -ErrorAction Stop
        $success = $true
        Write-Log "File replacement succeeded"
        break
    } catch {
        Write-Log "ERROR (attempt $i): $_"
        Start-Sleep -Seconds 2
    }
}

if (-not $success) {
    Write-Log "FATAL: all file replacement attempts failed"
    if ((Test-Path -LiteralPath $BakExe) -and (-not (Test-Path -LiteralPath $OldExe))) {
        Write-Log "Rolling back: $BakExe -> $OldExe"
        Move-Item -LiteralPath $BakExe -Destination $OldExe -Force -ErrorAction SilentlyContinue
    }
    exit 1
}

Write-Log "Starting $OldExe"
Start-Process -FilePath $OldExe
Start-Sleep -Seconds 3

if (Test-Path -LiteralPath $BakExe) {
    Write-Log "Removing backup $BakExe"
    Remove-Item -LiteralPath $BakExe -Force -ErrorAction SilentlyContinue
}

Write-Log "Updater completed successfully"
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"#;
    script
        .replace("PROCESS_NAME", PROCESS_NAME)
        .replace("MIN_EXE_SIZE_BYTES", &MIN_EXE_SIZE_BYTES.to_string())
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
    fn api_check_order_is_direct_then_system() {
        assert_eq!(API_CHECK_ORDER, GithubCheckOrder::DirectThenSystem);
    }

    #[test]
    fn download_order_is_system_then_direct() {
        assert_eq!(DOWNLOAD_ORDER, GithubCheckOrder::SystemThenDirect);
    }

    #[test]
    fn rate_limit_429_is_detected() {
        assert!(is_rate_limit_response(429, ""));
    }

    #[test]
    fn rate_limit_403_with_rate_limit_body_is_detected() {
        assert!(is_rate_limit_response(
            403,
            "API rate limit exceeded for user"
        ));
    }

    #[test]
    fn regular_403_is_not_rate_limit() {
        assert!(!is_rate_limit_response(403, "forbidden"));
    }

    #[test]
    fn format_rate_limit_error_includes_headers() {
        let message = format_rate_limit_error(403, "0", "1717200000", "ABC123", "rate limit");
        assert!(message.contains("HTTP 403"));
        assert!(message.contains("Remaining: 0"));
        assert!(message.contains("Reset: 1717200000"));
        assert!(message.contains("Request-ID: ABC123"));
    }

    #[test]
    fn user_agent_includes_version_and_repo() {
        let value = user_agent();
        assert!(value.contains("langateway/"));
        assert!(value.contains("github.com/uchihazzj/LanGateway"));
    }

    #[test]
    fn download_filename_strips_v_prefix() {
        assert_eq!(download_filename("v0.3.5"), "langateway-v0.3.5.exe");
        assert_eq!(download_filename("0.3.5"), "langateway-v0.3.5.exe");
    }

    #[test]
    fn updater_script_contains_log_retry_and_rollback() {
        let script = updater_script();
        assert!(script.contains("[string]$LogFile"));
        assert!(script.contains("$maxRetries = 5"));
        assert!(script.contains("Rolling back"));
        assert!(script.contains("102400"));
        assert!(script.contains("Get-Process -Name \"langateway\""));
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
