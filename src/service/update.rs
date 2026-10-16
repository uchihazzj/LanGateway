use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
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
const MIN_EXE_SIZE_BYTES: u64 = 102_400;
static INSTALL_RUNNING: AtomicBool = AtomicBool::new(false);

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
        .https_only(true)
        .max_redirects(5)
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

fn stable_version(value: &str) -> Result<[u32; 3], String> {
    let parts: Vec<_> = value
        .strip_prefix('v')
        .unwrap_or(value)
        .split('.')
        .collect();
    if parts.len() != 3 {
        return Err("Release version must be X.Y.Z or vX.Y.Z".into());
    }
    let mut version = [0; 3];
    for (index, part) in parts.into_iter().enumerate() {
        if part.is_empty()
            || !part.bytes().all(|c| c.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return Err("Unsupported or invalid stable release version".into());
        }
        version[index] = part
            .parse()
            .map_err(|_| "Release version number overflow")?;
    }
    Ok(version)
}

fn is_newer(local: &str, remote: &str) -> bool {
    match (stable_version(local), stable_version(remote)) {
        (Ok(local), Ok(remote)) => remote > local,
        _ => false,
    }
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
        .with_config()
        .limit(1024 * 1024)
        .read_to_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;
    let release: GitHubRelease =
        serde_json::from_str(&body).map_err(|e| format!("Failed to parse release JSON: {}", e))?;

    stable_version(local_version)?;
    stable_version(&release.tag_name)?;
    if !is_newer(local_version, &release.tag_name) {
        return Ok(None);
    }

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == ASSET_NAME)
        .ok_or_else(|| format!("No '{}' asset found in release", ASSET_NAME))?;
    validate_update_source(&asset.browser_download_url, &release.tag_name)?;

    Ok(Some((
        release.tag_name.clone(),
        format!(
            "https://github.com/{}/releases/tag/{}",
            GITHUB_REPO, release.tag_name
        ),
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
        .with_config()
        .limit(64 * 1024 * 1024)
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

fn validate_update_source(download_url: &str, version: &str) -> Result<(), String> {
    stable_version(version)?;
    let expected = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, version, ASSET_NAME
    );
    if download_url != expected {
        return Err("Update asset URL does not belong to this repository and release".into());
    }
    Ok(())
}

fn validate_executable(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < MIN_EXE_SIZE_BYTES as usize {
        return Err(format!(
            "Downloaded executable is too small ({} bytes)",
            bytes.len()
        ));
    }
    if !bytes.starts_with(b"MZ") {
        return Err("Download is not a Windows executable (missing MZ header)".into());
    }
    let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    if offset < 0x40 || bytes.get(offset..offset.saturating_add(4)) != Some(b"PE\0\0".as_slice()) {
        return Err("Download has an invalid PE header".into());
    }
    Ok(())
}

fn write_download(bytes: &[u8], download_path: &Path, final_path: &Path) -> Result<(), String> {
    validate_executable(bytes)?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(download_path)
        .map_err(|e| format!("Failed to create download: {}", e))?;
    if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(download_path);
        return Err(format!("Failed to write download: {}", e));
    }
    drop(file);

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

    std::fs::rename(download_path, final_path).map_err(|e| {
        let _ = std::fs::remove_file(download_path);
        format!("Failed to rename download: {}", e)
    })
}

/// A helper is cancelled if preparation fails or the UI goes away before handoff.
pub struct PreparedUpdate {
    helper: Child,
    committed: bool,
    _claim: InstallClaim,
}

impl PreparedUpdate {
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PreparedUpdate {
    fn drop(&mut self) {
        if !self.committed
            && self.helper.try_wait().ok().flatten().is_none()
            && self.helper.kill().is_ok()
        {
            let _ = self.helper.wait();
        }
    }
}

struct InstallClaim;
impl InstallClaim {
    fn acquire() -> Result<Self, String> {
        INSTALL_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| "An update installation is already running".into())
    }
}
impl Drop for InstallClaim {
    fn drop(&mut self) {
        INSTALL_RUNNING.store(false, Ordering::Release);
    }
}

fn new_job_directory(exe: &Path) -> Result<(String, PathBuf), String> {
    let directory = exe.parent().ok_or("Executable has no parent directory")?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    for attempt in 0..16 {
        let job_id = format!("{:032x}", nonce + attempt);
        let path = directory.join(format!(".update-{job_id}"));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok((job_id, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("Cannot create update job: {e}")),
        }
    }
    Err("Cannot allocate a unique update directory".into())
}

fn powershell_path() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Cannot locate the Windows system directory".into());
    }
    Ok(
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]))
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    )
}

/// Prepare the existing update flow without terminating the GUI worker thread.
/// The UI requests real framework closure only after this helper is ready.
pub fn perform_update<F>(
    download_url: &str,
    latest_version: &str,
    mut set_status: F,
) -> Result<PreparedUpdate, String>
where
    F: FnMut(UpdateStatus),
{
    let claim = InstallClaim::acquire()?;
    validate_update_source(download_url, latest_version)?;
    if !is_newer(env!("CARGO_PKG_VERSION"), latest_version) {
        return Err("Update is not newer than the installed version".into());
    }
    let installed =
        std::env::current_exe().map_err(|e| format!("Cannot locate executable: {e}"))?;
    let (job_id, directory) = new_job_directory(&installed)?;
    let download_bytes = download_asset(download_url)?;
    write_download(
        &download_bytes,
        &directory.join("candidate.download"),
        &directory.join("candidate.exe"),
    )?;
    set_status(UpdateStatus::PreparingUpdate);

    let manifest = serde_json::json!({
        "job_id": job_id,
        "installed_exe": installed,
        "parent_pid": std::process::id(),
        "expected_size": download_bytes.len(),
        "parent_timeout_ms": 30000,
        "startup_timeout_ms": 30000,
        "replace_attempts": 5,
        "retry_delay_ms": 200
    });
    let manifest_path = directory.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Cannot write updater manifest: {e}"))?;
    let script_path = directory.join("updater.ps1");
    std::fs::write(&script_path, updater_script())
        .map_err(|e| format!("Cannot write updater script: {e}"))?;

    use std::os::windows::process::CommandExt;
    let helper = std::process::Command::new(powershell_path()?)
        // Preserve the existing process-local policy choice; enterprise policy
        // can still block it, in which case readiness fails and the app stays.
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script_path)
        .arg("-ManifestPath")
        .arg(&manifest_path)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| format!("Cannot launch updater: {e}"))?;
    let mut prepared = PreparedUpdate {
        helper,
        committed: false,
        _claim: claim,
    };
    let expected = format!("{job_id}:{}", std::process::id());
    let ready = directory.join("helper-ready.txt");
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if let Some(exit) = prepared.helper.try_wait().map_err(|e| e.to_string())? {
            return Err(format!(
                "Updater preflight failed ({exit}); see {}",
                directory.join("updater.log").display()
            ));
        }
        if std::fs::read_to_string(&ready).is_ok_and(|value| value == expected) {
            log_update("Updater initialized; requesting application shutdown");
            set_status(UpdateStatus::Restarting);
            return Ok(prepared);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "Updater did not initialize; see {}",
        directory.join("updater.log").display()
    ))
}

fn updater_script() -> &'static str {
    include_str!("updater.ps1")
}

/// The restarted child acknowledges successful config loading and first UI frame.
pub struct StartupReady {
    path: PathBuf,
    job_id: String,
}

impl StartupReady {
    /// Call on the main thread before starting any worker threads.
    pub fn capture() -> Result<Option<Self>, String> {
        let job = std::env::var_os("RUST_APP_UPDATE_JOB_ID");
        let path = std::env::var_os("RUST_APP_UPDATE_READY_FILE");
        std::env::remove_var("RUST_APP_UPDATE_JOB_ID");
        std::env::remove_var("RUST_APP_UPDATE_READY_FILE");
        let (job, path) = match (job, path) {
            (None, None) => return Ok(None),
            (Some(job), Some(path)) => (job, PathBuf::from(path)),
            _ => return Err("Incomplete update startup environment".into()),
        };
        let job_id = job
            .into_string()
            .map_err(|_| "Invalid update job identifier")?;
        let installed = std::env::current_exe().map_err(|e| e.to_string())?;
        Self::from_paths(&installed, path, job_id).map(Some)
    }

    fn from_paths(installed: &Path, path: PathBuf, job_id: String) -> Result<Self, String> {
        if job_id.len() != 32
            || !job_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Invalid update job identifier".into());
        }
        let expected = installed
            .parent()
            .ok_or("Executable has no parent")?
            .join(format!(".update-{job_id}"))
            .join("ready.txt");
        if !installed.is_absolute() || path != expected {
            return Err("Unexpected update startup acknowledgement path".into());
        }
        Ok(Self { path, job_id })
    }

    pub fn acknowledge(self) -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        write!(file, "{}:{}", self.job_id, std::process::id()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_or_prerelease_tags_are_not_offered_as_stable_updates() {
        for remote in [
            "v1.2.3-beta.1",
            "v1.2.3/../../other",
            "v1.2.invalid",
            "vv1.2.3",
            "v01.2.3",
            "v1.2",
        ] {
            assert!(
                !is_newer("0.3.7", remote),
                "accepted invalid version: {remote}"
            );
        }
    }

    #[test]
    fn invalid_download_preserves_the_previously_staged_file() {
        let dir = std::env::temp_dir();
        let staged = dir.join(format!(
            "langateway-invalid-download-{}.exe",
            std::process::id()
        ));
        let temporary = staged.with_extension("download");
        std::fs::write(&staged, b"previous staged version").unwrap();
        let result = write_download(
            &vec![b'x'; MIN_EXE_SIZE_BYTES as usize],
            &temporary,
            &staged,
        );
        let contents = std::fs::read(&staged).unwrap();
        let _ = std::fs::remove_file(&temporary);
        std::fs::remove_file(&staged).unwrap();
        assert!(result.is_err());
        assert_eq!(contents, b"previous staged version");
    }

    #[test]
    fn update_source_rejects_other_repositories_and_path_traversal() {
        let url = "https://github.com/uchihazzj/LanGateway/releases/download/v1.2.3/langateway.exe";
        assert!(validate_update_source(url, "v1.2.3").is_ok());
        assert!(validate_update_source(url, "v1.2.3/../../other").is_err());
        assert!(validate_update_source(&url.replace("LanGateway", "other"), "v1.2.3").is_err());
        assert!(validate_update_source(&url.replace("https:", "http:"), "v1.2.3").is_err());
    }

    #[test]
    fn executable_validation_checks_size_and_pe_pointer_bounds() {
        assert!(validate_executable(b"MZ").is_err());
        let mut bytes = vec![0; MIN_EXE_SIZE_BYTES as usize];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_executable(&bytes).is_err());
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(validate_executable(&bytes).is_err());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(validate_executable(&bytes).is_ok());
    }

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
    fn update_jobs_are_distinct_and_independent_of_the_executable_name() {
        let exe = std::env::temp_dir().join("renamed tool [test].exe");
        let (first_id, first) = new_job_directory(&exe).unwrap();
        let (second_id, second) = new_job_directory(&exe).unwrap();
        assert_ne!(first, second);
        assert_ne!(first_id, second_id);
        assert_eq!(first.parent(), exe.parent());
        std::fs::remove_dir(first).unwrap();
        std::fs::remove_dir(second).unwrap();
    }

    #[test]
    fn startup_ticket_rejects_unrelated_paths_and_invalid_identifiers() {
        let installed = std::env::temp_dir().join("renamed.exe");
        let id = "0123456789abcdef0123456789abcdef";
        assert!(
            StartupReady::from_paths(&installed, installed.with_extension("txt"), id.into())
                .is_err()
        );
        assert!(StartupReady::from_paths(
            &installed,
            installed.with_extension("txt"),
            "../escape".into()
        )
        .is_err());
    }

    #[test]
    fn startup_ticket_acknowledges_exact_job_and_process_only_once() {
        let installed = std::env::temp_dir().join("renamed.exe");
        let (id, directory) = new_job_directory(&installed).unwrap();
        let ready = directory.join("ready.txt");
        StartupReady::from_paths(&installed, ready.clone(), id.clone())
            .unwrap()
            .acknowledge()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&ready).unwrap(),
            format!("{}:{}", id, std::process::id())
        );
        assert!(StartupReady::from_paths(&installed, ready.clone(), id)
            .unwrap()
            .acknowledge()
            .is_err());
        std::fs::remove_file(ready).unwrap();
        std::fs::remove_dir(directory).unwrap();
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
