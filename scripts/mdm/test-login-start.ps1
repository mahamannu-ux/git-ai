# End-to-end lifecycle test for mdm/windows/install-login-start.ps1.
#
# Installs git-ai into $HOME, registers the logon task, starts it as the logon
# trigger would, and checks that the daemon (a) comes up, (b) survives the task
# instance ending, and (c) the task stays healthy throughout, including a
# re-trigger (idempotency), an unusual --bin path, and the logon-time lock race
# covered by `bg start --retry-secs`.
#
# Usage: test-login-start.ps1 [-Scenario lifecycle]
#
# Environment: BINARY_SOURCE (local|release), GIT_AI_LOCAL_BINARY,
# GIT_AI_RELEASE_TAG, MDM_TEST_LOG_DIR — same meaning as in
# test-login-start.sh.
#
# Task9b scope: Windows lifecycle only. There is no auto-update scenario and no
# configuration-tuning surface (the launchers carry no configuration; Task9c
# owns it). Ported from upstream snapshot 0670e7ef27590af0e8ff5409267f3f4b09b8fcb4
# (same Apache-2.0 project) with the auto-update and configuration-transport
# surface removed.
param(
    [ValidateSet('lifecycle')]
    [string]$Scenario = 'lifecycle'
)

$ErrorActionPreference = 'Stop'

$BinarySource = if ($env:BINARY_SOURCE) { $env:BINARY_SOURCE } else { 'local' }
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$LogOut = if ($env:MDM_TEST_LOG_DIR) { $env:MDM_TEST_LOG_DIR } else { Join-Path ($env:RUNNER_TEMP, $env:TEMP | Where-Object { $_ } | Select-Object -First 1) 'mdm-logs' }
$Bin = Join-Path $HOME '.git-ai\bin\git-ai.exe'
$DaemonDir = Join-Path $HOME '.git-ai\internal\daemon'
$TaskPath = '\GitAI\'
$TaskName = 'Start bg at logon'
$MdmScript = Join-Path $RepoRoot 'mdm\windows\install-login-start.ps1'
$StatusRepo = Join-Path ([IO.Path]::GetTempPath()) ("mdm-status-" + [guid]::NewGuid().ToString('N'))

function Write-Log([string]$Message) { Write-Host "[mdm-test] $Message" }
function Fail([string]$Message) { throw "[mdm-test] FAIL: $Message" }

# --- helpers -----------------------------------------------------------------

function Install-Binary {
    switch ($BinarySource) {
        'local' {
            if (-not ($env:GIT_AI_LOCAL_BINARY -and (Test-Path $env:GIT_AI_LOCAL_BINARY))) {
                Fail 'GIT_AI_LOCAL_BINARY must point at a built git-ai.exe'
            }
        }
        'release' { }
        default { Fail 'BINARY_SOURCE must be local or release' }
    }
    Push-Location $RepoRoot
    try {
        # install.ps1 honors GIT_AI_LOCAL_BINARY for local builds.
        pwsh -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
        if ($LASTEXITCODE -ne 0) { Fail "install.ps1 exited $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    if (-not (Test-Path $Bin)) { Fail "$Bin missing after install" }
    Write-Log "installed $(& $Bin --version)"
}

function Get-DaemonPid {
    $file = Join-Path $DaemonDir 'daemon.pid.json'
    if (-not (Test-Path $file)) { return $null }
    try { return (Get-Content -Raw $file | ConvertFrom-Json).pid } catch { return $null }
}

function Test-PidAlive($ProcessId) {
    return $ProcessId -and (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

function Test-DaemonUp {
    if (-not (Test-PidAlive (Get-DaemonPid))) { return $false }
    Push-Location $StatusRepo
    try {
        & $Bin bg status *> $null
        return $LASTEXITCODE -eq 0
    } finally {
        Pop-Location
    }
}

function Get-DaemonProcesses {
    Get-CimInstance Win32_Process -Filter "Name = 'git-ai.exe'" |
        Where-Object { $_.CommandLine -match 'bg run' -and $_.ExecutablePath -like "$HOME\*" }
}

# `bg shutdown` returns before the old process has released the daemon lock;
# a logon start racing that window would have to retry.
function Stop-Daemon {
    & $Bin bg shutdown *> $null
    Wait-For 30 'previous daemon exited' { -not (Get-DaemonProcesses) }
}

function Wait-For([int]$Seconds, [string]$What, [scriptblock]$Condition) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while (-not (& $Condition)) {
        if ((Get-Date) -ge $deadline) { Fail "timed out after ${Seconds}s waiting for $What" }
        Start-Sleep -Seconds 1
    }
    Write-Log $What
}

function Invoke-MdmScript {
    # Windows PowerShell, as MDM tooling and `irm | iex` would use it.
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $MdmScript @args
    if ($LASTEXITCODE -ne 0) { Fail "install-login-start.ps1 $args exited $LASTEXITCODE" }
}

function Get-Task {
    return Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
}

function Test-Registered { return [bool](Get-Task) }

function Wait-TaskIdle {
    Wait-For 60 'task instance finished' { (Get-Task).State -ne 'Running' }
}

function Test-MechanismSane {
    $task = Get-Task
    if (-not $task) { Fail 'scheduled task missing' }
    Wait-TaskIdle
    $info = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName
    if ($info.LastTaskResult -ne 0) { Fail "task last result 0x$($info.LastTaskResult.ToString('X'))" }
    Write-Log 'login mechanism healthy'
}

function Invoke-Lint {
    if (Get-Module -ListAvailable PSScriptAnalyzer) {
        $findings = Invoke-ScriptAnalyzer -Path $MdmScript -Severity Error
        if ($findings) { $findings | Format-Table | Out-String | Write-Host; Fail 'PSScriptAnalyzer errors' }
    }
}

function Invoke-Cleanup {
    New-Item -ItemType Directory -Path $LogOut -Force | Out-Null
    Copy-Item (Join-Path $DaemonDir 'logs') (Join-Path $LogOut 'daemon-logs') -Recurse -Force -ErrorAction SilentlyContinue
    Get-Task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue | Out-File (Join-Path $LogOut 'task-info.txt')
    Copy-Item (Join-Path $HOME '.git-ai\login\start-bg.ps1') $LogOut -Force -ErrorAction SilentlyContinue
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $MdmScript --uninstall *> $null
    if (Test-Path $Bin) { & $Bin bg shutdown *> $null }
    Remove-Item $StatusRepo -Recurse -Force -ErrorAction SilentlyContinue
}

# --- scenarios ---------------------------------------------------------------

function Register-AndWaitForDaemon {
    Invoke-MdmScript @args
    if (-not (Test-Registered)) { Fail 'login start not registered after install' }
    Wait-For 45 'daemon up after logon trigger' { Test-DaemonUp }
}

function Invoke-LifecycleScenario {
    Install-Binary
    # Keep the uptime restart deterministic: no network update checks.
    & $Bin config set disable_auto_updates true
    Stop-Daemon

    Register-AndWaitForDaemon
    $pid1 = Get-DaemonPid

    Start-Sleep -Seconds 10
    if (-not (Test-PidAlive $pid1)) { Fail "daemon $pid1 died after the task instance ended (job object torn down?)" }
    if (-not (Test-DaemonUp)) { Fail 'daemon not answering after task instance ended' }
    Write-Log 'daemon survived task instance ending'

    Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
    Wait-TaskIdle
    Start-Sleep -Seconds 3
    if (-not (Test-DaemonUp)) { Fail 'daemon unhealthy after re-trigger' }
    if ((Get-DaemonPid) -ne $pid1) { Fail "re-triggering logon restarted the daemon (pid $pid1 -> $(Get-DaemonPid))" }
    Test-MechanismSane
    Write-Log 're-triggered logon start was a no-op'

    Invoke-Lint

    Invoke-MdmScript --uninstall
    if (Test-Registered) { Fail 'task still registered after --uninstall' }
    Write-Log 'uninstall clean'

    # A relative --bin must be rejected without touching the daemon.
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $MdmScript --bin 'relative\path' *> $null
    if ($LASTEXITCODE -eq 0) { Fail 'relative --bin path was accepted' }
    Write-Log 'relative --bin rejected'

    Stop-Daemon
    Invoke-UnusualBinaryPathScenario
    Invoke-LauncherRetryScenario
}

# --bin must cope with every path an admin might install to: spaces, quotes,
# parentheses, percent signs, non-ASCII.
function Invoke-UnusualBinaryPathScenario {
    $dir = Join-Path $HOME "mdm test (weird) 100% 'quoted' ünïcode"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item $Bin (Join-Path $dir 'git-ai.exe') -Force

    Invoke-MdmScript --bin (Join-Path $dir 'git-ai.exe')
    if (-not (Test-Registered)) { Fail 'login start not registered with unusual --bin' }
    Wait-For 45 'daemon up from unusual binary path' { Test-DaemonUp }
    $running = @(Get-DaemonProcesses | Where-Object { $_.ExecutablePath -like "$dir\*" })
    if (-not $running) { Fail "daemon is not running from $dir" }
    Write-Log 'daemon runs from the unusual path'
    Test-MechanismSane

    Invoke-MdmScript --uninstall
    Stop-Daemon
}

# Writes a fake git-ai.cmd that always fails and counts its invocations in a
# file next to it.
function Write-FailingBinary([string]$Path) {
    $lines = @(
        '@echo off',
        'setlocal',
        'set n=0',
        'if exist "%~dp0attempts" set /p n=<"%~dp0attempts"',
        'set /a n+=1',
        '>"%~dp0attempts" echo %n%',
        'exit /b 1'
    )
    Set-Content -LiteralPath $Path -Value ($lines -join "`r`n") -Encoding ASCII
}

function Get-Attempts([string]$Dir) {
    $file = Join-Path $Dir 'attempts'
    if (Test-Path $file) { return [int](Get-Content $file | Select-Object -First 1).Trim() }
    return 0
}

# Holds the daemon lock (exclusive open, like the daemon) for a few seconds in
# the background, the state a logon start sees while a previous daemon is still
# shutting down.
function Hold-DaemonLock([int]$Seconds) {
    New-Item -ItemType Directory -Path $DaemonDir -Force | Out-Null
    $lockPath = Join-Path $DaemonDir 'daemon.lock'
    return Start-Job -ScriptBlock {
        param($Path, $Secs)
        $stream = [IO.File]::Open($Path, 'OpenOrCreate', 'ReadWrite', 'None')
        Start-Sleep -Seconds $Secs
        $stream.Dispose()
    } -ArgumentList $lockPath, $Seconds
}

# `bg start --retry-secs` must ride out a lock held at logon, and a binary that
# keeps failing must surface as a failed logon task.
function Test-SupportsRetry {
    return [bool]((& $Bin bg --help 2>&1 | Out-String) -match '--retry-secs')
}

function Invoke-LauncherRetryScenario {
    if (Test-SupportsRetry) {
        $holder = Hold-DaemonLock 4
        Start-Sleep -Seconds 1
        Invoke-MdmScript
        Wait-For 60 'daemon up despite a lock held at logon' { Test-DaemonUp }
        Receive-Job $holder -Wait | Out-Null
        Test-MechanismSane
        Invoke-MdmScript --uninstall
        Stop-Daemon
    } else {
        # Published releases without --retry-secs cannot ride out the lock race.
        Write-Log "SKIP held-lock phase: $(& $Bin --version) predates bg start --retry-secs"
    }

    $fakeDir = Join-Path $HOME 'mdm-fake'
    New-Item -ItemType Directory -Path $fakeDir -Force | Out-Null
    Remove-Item (Join-Path $fakeDir 'attempts') -Force -ErrorAction SilentlyContinue
    $fake = Join-Path $fakeDir 'git-ai.cmd'
    Write-FailingBinary $fake
    Invoke-MdmScript --bin $fake --no-start
    Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
    Wait-TaskIdle
    $info = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName
    if ($info.LastTaskResult -eq 0) { Fail 'persistent launcher failure was reported as success' }
    $attempts = Get-Attempts $fakeDir
    if ($attempts -ne 1) { Fail "launcher should invoke the binary once, got $attempts" }
    if (Test-DaemonUp) { Fail 'no daemon should be running after persistent failure' }
    Invoke-MdmScript --uninstall
    Write-Log 'launcher retry semantics verified'
}

New-Item -ItemType Directory -Path $StatusRepo -Force | Out-Null
git -C $StatusRepo init -q
try {
    switch ($Scenario) {
        'lifecycle' { Invoke-LifecycleScenario }
    }
    Write-Log "PASS $Scenario on windows"
} finally {
    Invoke-Cleanup
}
# Cleanup's best-effort `bg shutdown` leaves a non-zero $LASTEXITCODE when no
# daemon is running; do not let pwsh -File report that as the script's result.
exit 0
