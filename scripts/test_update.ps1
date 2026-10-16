# Local regression tests. Only disposable binaries under a fresh scratch child.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ScratchRoot,
    [switch] $AllowLocalFixtureScripts
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$skillRoot = Split-Path -Parent $PSScriptRoot
$helper = Join-Path $skillRoot 'src\service\updater.ps1'
$scratch = [IO.Path]::GetFullPath($ScratchRoot)
if (-not (Test-Path -LiteralPath $scratch -PathType Container)) {
    throw 'Provide an existing writable scratch directory.'
}
$runDir = Join-Path $scratch ('.langateway-update-fixtures-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($runDir)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$windowsPowerShell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $windowsPowerShell)) { throw 'Windows PowerShell 5.1 is required for this test.' }
$processPolicyArgument = if ($AllowLocalFixtureScripts) { '-ExecutionPolicy RemoteSigned ' } else { '' }
$syntaxErrors = $null
$syntaxTokens = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($helper, [ref] $syntaxTokens, [ref] $syntaxErrors)
if ($syntaxErrors.Count -gt 0) { throw ($syntaxErrors | Out-String) }

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}
function Stop-OwnedProcess($Process) {
    if ($null -ne $Process) {
        if (-not $Process.HasExited) { $Process.Kill(); $null = $Process.WaitForExit(5000) }
        $Process.Dispose()
    }
}
function Start-Helper([string] $Manifest) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $windowsPowerShell
    $info.Arguments = '-NoProfile -NonInteractive ' + $processPolicyArgument + '-File "' + $helper + '" -ManifestPath "' + $Manifest + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardError = $true
    return [Diagnostics.Process]::Start($info)
}
function Wait-File([string] $Path, [int] $Timeout = 6000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $Timeout) {
        if (Test-Path -LiteralPath $Path) { return }
        Start-Sleep -Milliseconds 25
    }
    throw ('Timed out waiting for fixture: ' + [IO.Path]::GetFileName($Path))
}

$fixture = @'
use std::{env, fs, thread, time::{Duration, Instant}};
fn main() {
    if cfg!(new_fixture) {
        let mode = env::var("FIXTURE_MODE").unwrap_or_default();
        if mode == "early_exit" { return; }
        if mode != "no_ack" {
            let job_id = env::var("RUST_APP_UPDATE_JOB_ID").unwrap();
            let ready_file = env::var("RUST_APP_UPDATE_READY_FILE").unwrap();
            if mode == "wrong_ack" {
                // Simulate a descendant/stale PID acknowledging the same job.
                let job = env::var("FIXTURE_JOB").unwrap();
                let ready = env::var("FIXTURE_READY").unwrap();
                fs::write(ready, format!("{job}:0")).unwrap();
            } else {
                fs::write(ready_file, format!("{job_id}:{}", std::process::id())).unwrap();
            }
        }
        thread::sleep(Duration::from_millis(2000));
    } else {
        if let Ok(job) = env::var("FIXTURE_PARENT_DIR") {
            let path = std::path::Path::new(&job).join("helper-ready.txt");
            let start = Instant::now();
            while !path.exists() && start.elapsed() < Duration::from_secs(10) {
                thread::sleep(Duration::from_millis(10));
            }
        }
        let hold = env::var("FIXTURE_HOLD_MS").ok().and_then(|x| x.parse().ok()).unwrap_or(0);
        thread::sleep(Duration::from_millis(hold));
    }
}
'@
$fixtureFile = Join-Path $runDir 'fixture.rs'
[IO.File]::WriteAllText($fixtureFile, $fixture, $utf8)
$oldFixture = Join-Path $runDir 'old.exe'
$newFixture = Join-Path $runDir 'new.exe'
& rustc --edition=2024 $fixtureFile -o $oldFixture
if ($LASTEXITCODE -ne 0) { throw 'Old fixture compilation failed.' }
& rustc --edition=2024 --cfg new_fixture $fixtureFile -o $newFixture
if ($LASTEXITCODE -ne 0) { throw 'Candidate fixture compilation failed.' }

function New-Job([string] $Directory, [string] $Installed, [string] $CandidateSource, [int] $ParentId) {
    $id = [Guid]::NewGuid().ToString('N')
    $dir = Join-Path $Directory ('.update-' + $id)
    $null = [IO.Directory]::CreateDirectory($dir)
    $candidate = Join-Path $dir 'candidate.exe'
    [IO.File]::Copy($CandidateSource, $candidate, $false)
    $data = [ordered]@{
        job_id = $id
        installed_exe = $Installed
        parent_pid = $ParentId
        expected_size = (Get-Item -LiteralPath $candidate).Length
        expected_sha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
        parent_timeout_ms = 1200
        startup_timeout_ms = 500
        replace_attempts = 2
        retry_delay_ms = 50
    }
    return @{ Id = $id; Dir = $dir; Data = $data; Path = (Join-Path $dir 'manifest.json') }
}
function Save-Manifest($Job) {
    [IO.File]::WriteAllText($Job.Path, ($Job.Data | ConvertTo-Json), $utf8)
}
function Read-Outcome($Job, $Process) {
    Assert-True ($Process.WaitForExit(12000)) 'Fixture helper did not finish in time.'
    $errorText = $Process.StandardError.ReadToEnd()
    [IO.File]::WriteAllText((Join-Path $Job.Dir 'stderr.txt'), $errorText, $utf8)
    if (-not (Test-Path -LiteralPath (Join-Path $Job.Dir 'result.json'))) {
        throw ('Helper produced no outcome: ' + $errorText)
    }
    return (Get-Content -LiteralPath (Join-Path $Job.Dir 'result.json') -Raw -Encoding UTF8 | ConvertFrom-Json)
}

$caseNames = @('success', 'parent_timeout', 'bad_hash', 'launch_failure', 'early_exit',
               'no_ack', 'wrong_ack', 'replace_failure', 'duplicate_helper', 'duplicate_job', 'wrong_parent')
foreach ($case in $caseNames) {
    $dir = Join-Path $runDir ($case + " [one] ' spaces")
    $null = [IO.Directory]::CreateDirectory($dir)
    $installed = Join-Path $dir 'renamed app.exe'
    [IO.File]::Copy($oldFixture, $installed, $false)
    $oldHash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
    $job = New-Job $dir $installed $newFixture 1
    $parentProcess = $null
    $helperProcess = $null
    $otherProcess = $null
    $secondHelper = $null
    $fileLock = $null
    try {
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $installed
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.EnvironmentVariables['FIXTURE_PARENT_DIR'] = $job.Dir
        if ($case -in @('parent_timeout', 'duplicate_helper', 'duplicate_job')) {
            $startInfo.EnvironmentVariables['FIXTURE_HOLD_MS'] = '5000'
        }
        if ($case -in @('duplicate_helper', 'duplicate_job')) {
            # Keep the first helper armed while the second PowerShell starts.
            $startInfo.EnvironmentVariables['FIXTURE_HOLD_MS'] = '15000'
            $job.Data.parent_timeout_ms = 6000
        }
        $parentProcess = [Diagnostics.Process]::Start($startInfo)
        $job.Data.parent_pid = $parentProcess.Id
        if ($case -eq 'wrong_parent') { $job.Data.parent_pid = $PID }
        if ($case -eq 'bad_hash') { $job.Data.expected_sha256 = '0' * 64 }
        if ($case -eq 'launch_failure') {
            # PE-shaped bytes pass basic sanity, but Windows cannot launch them.
            $bytes = New-Object byte[] 256
            $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[60] = 64
            $bytes[64] = 0x50; $bytes[65] = 0x45
            [IO.File]::WriteAllBytes((Join-Path $job.Dir 'candidate.exe'), $bytes)
            $job.Data.expected_size = 256
            $job.Data.expected_sha256 = (Get-FileHash -LiteralPath (Join-Path $job.Dir 'candidate.exe') -Algorithm SHA256).Hash
        }
        if ($case -eq 'replace_failure') {
            $fileLock = [IO.File]::Open($installed, 'Open', 'Read', 'Read')
        }
        if ($case -eq 'success') {
            # Same filename, different installation: must not delay/kill it.
            $otherDir = Join-Path $dir 'other'
            $null = [IO.Directory]::CreateDirectory($otherDir)
            $otherExe = Join-Path $otherDir 'renamed app.exe'
            [IO.File]::Copy($oldFixture, $otherExe, $false)
            $otherInfo = New-Object Diagnostics.ProcessStartInfo
            $otherInfo.FileName = $otherExe
            $otherInfo.UseShellExecute = $false
            $otherInfo.CreateNoWindow = $true
            $otherInfo.EnvironmentVariables['FIXTURE_HOLD_MS'] = '15000'
            $otherProcess = [Diagnostics.Process]::Start($otherInfo)
        }
        Save-Manifest $job
        # Fixture controls are environment for this helper's candidate only.
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $windowsPowerShell
        $info.Arguments = '-NoProfile -NonInteractive ' + $processPolicyArgument + '-File "' + $helper + '" -ManifestPath "' + $job.Path + '"'
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardError = $true
        $info.EnvironmentVariables['FIXTURE_MODE'] = $case
        $info.EnvironmentVariables['FIXTURE_JOB'] = $job.Id
        $info.EnvironmentVariables['FIXTURE_READY'] = (Join-Path $job.Dir 'ready.txt')
        $helperProcess = [Diagnostics.Process]::Start($info)

        if ($case -eq 'duplicate_helper') {
            Wait-File (Join-Path $job.Dir 'helper-ready.txt')
            $second = New-Job $dir $installed $newFixture $parentProcess.Id
            Save-Manifest $second
            $secondHelper = Start-Helper $second.Path
            $secondResult = Read-Outcome $second $secondHelper
            Assert-True ($secondResult.status -eq 'failed') 'Duplicate target helper was not excluded.'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $second.Dir 'helper-ready.txt'))) 'Busy helper signalled readiness.'
        }
        if ($case -eq 'duplicate_job') {
            Wait-File (Join-Path $job.Dir 'helper-ready.txt')
            $secondHelper = Start-Helper $job.Path
            Assert-True ($secondHelper.WaitForExit(5000)) 'Duplicate job helper did not stop.'
            Assert-True ($secondHelper.ExitCode -ne 0) 'Duplicate job was accepted.'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $job.Dir 'result.json'))) 'Duplicate job overwrote the active outcome.'
        }
        $outcome = Read-Outcome $job $helperProcess
        if ($null -ne $fileLock) { $fileLock.Dispose(); $fileLock = $null }
        $currentHash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
        $backup = Join-Path $job.Dir 'previous.exe'
        if ($case -eq 'success') {
            Assert-True ($outcome.status -eq 'succeeded' -and $helperProcess.ExitCode -eq 0) 'Successful fixture did not acknowledge startup.'
            Assert-True ($currentHash -ne $oldHash) 'Candidate was not installed.'
            Assert-True (Test-Path -LiteralPath $backup) 'Success deleted the backup.'
            Assert-True (-not $otherProcess.HasExited) 'Unrelated same-name fixture was stopped or waited for.'
        } elseif ($case -in @('launch_failure', 'early_exit', 'no_ack', 'wrong_ack')) {
            Assert-True ($outcome.status -eq 'rolled_back') ('Rollback failed: ' + $outcome.message)
            Assert-True ($currentHash -eq $oldHash) 'Rollback did not restore the occupied destination.'
            Assert-True (Test-Path -LiteralPath $backup) 'Rollback removed recovery copy.'
        } else {
            Assert-True ($outcome.status -eq 'failed') ('Expected unchanged failure: ' + $outcome.message)
            Assert-True ($currentHash -eq $oldHash) 'Preflight/timeout/replace failure changed the installed file.'
        }
        if ($case -in @('bad_hash', 'wrong_parent')) {
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $job.Dir 'helper-ready.txt'))) 'Invalid preflight signalled readiness.'
        }
        Write-Output ('PASS ' + $case)
    } finally {
        if ($null -ne $fileLock) { $fileLock.Dispose() }
        Stop-OwnedProcess $helperProcess
        Stop-OwnedProcess $secondHelper
        Stop-OwnedProcess $parentProcess
        Stop-OwnedProcess $otherProcess
    }
}
Write-Output ('PASS: ' + $caseNames.Count + ' helper scenarios; fixtures retained at ' + $runDir)
