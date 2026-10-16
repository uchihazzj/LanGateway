# LanGateway helper; see README.md for the update protocol and recovery behavior.
# Same-privilege single-exe installs; never a user-writable elevation broker.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $ManifestPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$jobDir = $null
$jobId = $null
$lockStream = $null
$jobLock = $null
$ownsJob = $false
$parent = $null
$child = $null
$installed = $null
$backup = $null
$changed = $false
$success = $false
$status = 'failed'
$phase = 'preflight'
$message = 'Preflight failed.'
$delay = 200
$attempts = 5
$expectedHash = $null
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-JobFile([string] $Name, [string] $Text) {
    $path = Join-Path $jobDir $Name
    $stream = [System.IO.File]::Open($path, 'CreateNew', 'Write', 'None')
    try {
        $bytes = $utf8.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Write-JobLog([string] $Text) {
    if ($jobDir -and $ownsJob) {
        [System.IO.File]::AppendAllText(
            (Join-Path $jobDir 'updater.log'),
            ("{0:o} {1}{2}" -f [DateTime]::UtcNow, $Text, [Environment]::NewLine), $utf8)
    }
}

function Assert-PlainPath([string] $Path) {
    $cursor = Get-Item -LiteralPath $Path -Force
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse-point paths need a separately reviewed installation model.'
        }
        if ($cursor -is [System.IO.FileInfo]) { $cursor = $cursor.Directory }
        else { $cursor = $cursor.Parent }
    }
}

function Assert-Candidate {
    $item = Get-Item -LiteralPath $candidate -Force
    if ($item.Length -ne $expectedSize -or $item.Length -lt 64) {
        throw 'Candidate size mismatch.'
    }
    $stream = [System.IO.File]::OpenRead($candidate)
    $sha = [Security.Cryptography.SHA256]::Create()
    $reader = New-Object System.IO.BinaryReader($stream)
    try {
        $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '')
        # The app currently verifies origin/PE/size, but has no signature policy.
        # Pin preflight bytes to detect changes while waiting for the parent.
        if ($null -eq $expectedHash) { $script:expectedHash = $hash }
        elseif (-not [string]::Equals($hash, $expectedHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Candidate hash mismatch.'
        }
        $stream.Position = 0
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Missing DOS header.' }
        $stream.Position = 60
        $offset = $reader.ReadUInt32()
        if ($offset -lt 64 -or ([long] $offset + 24) -gt $stream.Length) {
            throw 'Invalid PE offset.'
        }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Missing PE header.' }
    } finally { $sha.Dispose(); $reader.Dispose(); $stream.Dispose() }
}

function Start-App([bool] $WithReadyEnvironment) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $installed
    $info.WorkingDirectory = [System.IO.Path]::GetDirectoryName($installed)
    $info.UseShellExecute = $false
    # CreateNoWindow prevents a console fixture flashing; it does not hide a GUI window.
    $info.CreateNoWindow = $true
    $info.EnvironmentVariables.Remove('RUST_APP_UPDATE_JOB_ID')
    $info.EnvironmentVariables.Remove('RUST_APP_UPDATE_READY_FILE')
    if ($WithReadyEnvironment) {
        $info.EnvironmentVariables['RUST_APP_UPDATE_JOB_ID'] = $jobId
        $info.EnvironmentVariables['RUST_APP_UPDATE_READY_FILE'] = $readyFile
    }
    return [System.Diagnostics.Process]::Start($info)
}

try {
    $manifestFull = [System.IO.Path]::GetFullPath($ManifestPath)
    $manifest = Get-Content -LiteralPath $manifestFull -Raw -Encoding UTF8 | ConvertFrom-Json
    $jobId = [string] $manifest.job_id
    if ($jobId -cnotmatch '^[0-9a-f]{32}$') { throw 'Invalid job id.' }
    $installed = [string] $manifest.installed_exe
    if (-not [System.IO.Path]::IsPathRooted($installed)) { throw 'Installed path must be absolute.' }
    $installed = [System.IO.Path]::GetFullPath($installed)
    if ([System.IO.Path]::GetExtension($installed) -ine '.exe') { throw 'Expected an exe destination.' }
    $installDir = [System.IO.Path]::GetDirectoryName($installed)
    $jobDir = Join-Path $installDir ('.update-' + $jobId)
    $expectedManifest = Join-Path $jobDir 'manifest.json'
    if (-not [string]::Equals($manifestFull, $expectedManifest, [StringComparison]::OrdinalIgnoreCase)) {
        $jobDir = $null
        throw 'Manifest must be inside its expected sibling job directory.'
    }
    Assert-PlainPath $manifestFull
    Assert-PlainPath $installed
    $candidate = Join-Path $jobDir 'candidate.exe'
    $backup = Join-Path $jobDir 'previous.exe'
    $readyFile = Join-Path $jobDir 'ready.txt'
    Assert-PlainPath $candidate
    $jobLock = [System.IO.File]::Open((Join-Path $jobDir 'job.lock'), 'CreateNew', 'Write', 'None')
    $ownsJob = $true
    foreach ($name in @('previous.exe', 'helper-ready.txt', 'ready.txt', 'result.json', 'rollback.exe')) {
        if (Test-Path -LiteralPath (Join-Path $jobDir $name)) { throw 'Job has already been used.' }
    }
    $expectedSize = [long] $manifest.expected_size
    $hashField = $manifest.PSObject.Properties['expected_sha256']
    if ($null -ne $hashField) { $expectedHash = [string] $hashField.Value }
    $parentId = [int] $manifest.parent_pid
    $parentTimeout = [int] $manifest.parent_timeout_ms
    $startupTimeout = [int] $manifest.startup_timeout_ms
    $attempts = [int] $manifest.replace_attempts
    $delay = [int] $manifest.retry_delay_ms
    if ($expectedSize -le 0 -or
        ($null -ne $expectedHash -and $expectedHash -notmatch '^[0-9a-fA-F]{64}$')) {
        throw 'Invalid candidate metadata.'
    }
    if ($parentId -le 0 -or $parentId -eq $PID -or $parentTimeout -lt 100 -or
        $parentTimeout -gt 300000 -or $startupTimeout -lt 100 -or $startupTimeout -gt 300000 -or
        $attempts -lt 1 -or $attempts -gt 10 -or $delay -lt 10 -or $delay -gt 2000) {
        throw 'Invalid bounded wait/retry settings.'
    }
    $lockStream = [System.IO.File]::Open(
        ($installed + '.update.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    Assert-Candidate
    $parent = Get-Process -Id $parentId
    # Open/cache the exact process handle before the app can see readiness.
    $null = $parent.Handle
    $parentPath = $parent.MainModule.FileName
    if ($parent.HasExited -or
        -not [string]::Equals($parentPath, $installed, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Parent image does not match the installation.'
    }
    Write-JobLog 'Preflight complete; waiting for original parent.'
    Write-JobFile 'helper-ready.txt' ($jobId + ':' + $parentId)
    $phase = 'waiting_parent'
    if (-not $parent.WaitForExit($parentTimeout)) {
        throw 'Original parent did not exit; installation unchanged.'
    }

    $phase = 'replacing'
    Assert-Candidate
    for ($index = 1; $index -le $attempts; $index++) {
        try {
            [System.IO.File]::Replace($candidate, $installed, $backup, $false)
            $changed = $true
            break
        } catch {
            # A backup may mean replacement partly succeeded. Never retry over it.
            if (Test-Path -LiteralPath $backup) {
                $status = 'recovery_required'
                throw 'Replace reported an ambiguous result; recovery copy retained.'
            }
            if (-not (Test-Path -LiteralPath $installed) -or
                -not (Test-Path -LiteralPath $candidate) -or $index -eq $attempts) { throw }
            Write-JobLog ('Replace retry ' + $index)
            Start-Sleep -Milliseconds $delay
        }
    }
    $phase = 'starting'
    $child = Start-App $true
    if ($null -eq $child) { throw 'No candidate process was started.' }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $expectedAck = $jobId + ':' + $child.Id
    while ($watch.ElapsedMilliseconds -lt $startupTimeout) {
        if ($child.HasExited) { throw 'Candidate exited before startup acknowledgement.' }
        if (Test-Path -LiteralPath $readyFile) {
            $ack = Get-Content -LiteralPath $readyFile -Raw -Encoding UTF8
            if ($ack -ceq $expectedAck) { $success = $true; break }
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $success) { throw 'Candidate startup acknowledgement timed out.' }
    $status = 'succeeded'
    $message = 'Application acknowledged startup; recovery copy retained.'
    Write-JobLog $message
} catch {
    $success = $false
    $message = $_.Exception.Message
    try { Write-JobLog ($phase + ': ' + $message) } catch { }
    if ($changed) {
        try {
            if ($null -ne $child -and -not $child.HasExited) {
                # Only the child process we created; never terminate by name.
                $child.Kill()
                if (-not $child.WaitForExit(5000)) { throw 'Candidate could not be stopped.' }
            }
            $rollback = Join-Path $jobDir 'rollback.exe'
            [System.IO.File]::Copy($backup, $rollback, $false)
            $restored = $false
            for ($index = 1; $index -le $attempts; $index++) {
                try {
                    if (Test-Path -LiteralPath $installed) {
                        # PowerShell 5.1 converts bare $null to an empty string
                        # for this overload; NullString passes an actual null.
                        [System.IO.File]::Replace($rollback, $installed, [NullString]::Value, $false)
                    } else { [System.IO.File]::Move($rollback, $installed) }
                    $restored = $true
                    break
                } catch {
                    if ($index -eq $attempts) { throw }
                    Start-Sleep -Milliseconds $delay
                }
            }
            if (-not $restored) { throw 'Recovery copy could not be restored.' }
            $restarted = Start-App $false
            if ($null -eq $restarted) { throw 'Old executable restored but could not be restarted.' }
            $recoveryPid = $restarted.Id
            $restarted.Dispose()
            $status = 'rolled_back'
            Write-JobLog 'Previous executable restored and restart requested; backup retained.'
        } catch {
            $status = 'recovery_required'
            $message += ' Recovery: ' + $_.Exception.Message
            try { Write-JobLog 'Automatic recovery incomplete; preserve job files.' } catch { }
        }
    }
} finally {
    if ($jobDir -and $ownsJob) {
        try {
            $result = [ordered]@{
                status = $status
                phase = $phase
                message = $message
                job_id = $jobId
                child_pid = if ($null -ne $child) { $child.Id } else { $null }
                recovery_pid = if (Get-Variable -Name recoveryPid -ErrorAction SilentlyContinue) { $recoveryPid } else { $null }
            }
            Write-JobFile 'result.json' ($result | ConvertTo-Json -Compress)
        } catch {
            # Success cannot be claimed if no durable outcome can be recorded.
            $success = $false
            [Console]::Error.WriteLine('Could not write updater outcome.')
        }
    }
    if ($null -ne $child) { $child.Dispose() }
    if ($null -ne $parent) { $parent.Dispose() }
    if ($null -ne $lockStream) { $lockStream.Dispose() }
    if ($null -ne $jobLock) { $jobLock.Dispose() }
}
if (-not $success) {
    [Console]::Error.WriteLine($message)
    exit 1
}
exit 0
