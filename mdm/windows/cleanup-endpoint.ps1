# Explicit, dry-run-first TrackAI endpoint cleanup for one Windows user.
#
# Usage (run as the user, NOT elevated):
#   cleanup-endpoint.ps1 [--dry-run] [--apply] [--bin PATH]
#
# The default is --dry-run: print the bounded cleanup plan and change nothing.
# --apply first removes the login-start registration via install-login-start.ps1
# --uninstall (best effort), then runs `git-ai fleet cleanup --apply`, which
# removes only Task9-owned state: the TrackAI machine credential, managed
# bootstrap/configuration state and login-start registration.
#
# Preserved: evidence queue, authorship notes, repositories, user login
# credentials, ordinary GitAI data and the GitAI binary. This script never
# erases ~/.git-ai wholesale and never uninstalls git-ai. MDM transports this
# command; MDM state itself is not authority. There is no Linux support.

$ErrorActionPreference = 'Stop'

$Mode = 'dry-run'
$Bin = ''

function Fail([string]$Message) {
    [Console]::Error.WriteLine("git-ai cleanup-endpoint: $Message")
    exit 1
}

function Show-Usage {
    @'
Usage:
  cleanup-endpoint.ps1 [--dry-run] [--apply] [--bin PATH]

Explicit TrackAI endpoint cleanup (default --dry-run). Run as the user, not
from an elevated shell.
'@
}

# $args is $null when the script body is piped through iex.
$remaining = @($args | Where-Object { $null -ne $_ })
while ($remaining.Count -gt 0) {
    $arg = $remaining[0]
    $remaining = @($remaining | Select-Object -Skip 1)
    switch -Regex ($arg) {
        '^--dry-run$' { $Mode = 'dry-run' }
        '^--apply$' { $Mode = 'apply' }
        '^(--bin|-Bin)$' {
            if ($remaining.Count -eq 0) { Fail '--bin requires a path' }
            $Bin = $remaining[0]
            $remaining = @($remaining | Select-Object -Skip 1)
        }
        '^--bin=' { $Bin = $arg.Substring(6) }
        '^(-h|--help|-Help)$' { Show-Usage; exit 0 }
        default { Show-Usage | Write-Host; Fail "unknown argument: $arg" }
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principalObj = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principalObj.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'git-ai cleanup-endpoint: running elevated. Cleanup is per-user; run as the target user from a non-elevated shell for MDM rollouts.'
}

if (-not $Bin) { $Bin = Join-Path $HOME '.git-ai\bin\git-ai.exe' }
if ($Bin -notmatch '^([a-zA-Z]:[\\/]|\\\\)') {
    Fail '--bin must be an absolute path'
}
if ($Bin.Contains("`r") -or $Bin.Contains("`n")) {
    Fail '--bin path must not contain a newline or carriage return'
}
if (-not (Test-Path -LiteralPath $Bin -PathType Leaf)) {
    Fail "$Bin not found; install git-ai first or pass --bin"
}

if ($Mode -eq 'dry-run') {
    & $Bin fleet cleanup --dry-run
    exit $LASTEXITCODE
}

$uninstallFailed = $false
$uninstall = Join-Path $PSScriptRoot 'install-login-start.ps1'
if (Test-Path -LiteralPath $uninstall -PathType Leaf) {
    # Run in a child process so the callee's `exit` cannot end this wrapper;
    # propagate its failure instead of masking it.
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $uninstall --uninstall
    if ($LASTEXITCODE -ne 0) { $uninstallFailed = $true }
}
& $Bin fleet cleanup --apply
$cleanupOk = ($LASTEXITCODE -eq 0)
if ($uninstallFailed -or -not $cleanupOk) {
    [Console]::Error.WriteLine("git-ai cleanup-endpoint: incomplete (uninstall_failed=$uninstallFailed cleanup_ok=$cleanupOk)")
    exit 1
}
exit 0
