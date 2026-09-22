<#
.SYNOPSIS
    SysTriage — Windows Persistence & Anomaly Triage Tool

.DESCRIPTION
    SysTriage performs a comprehensive, single-pass enumeration of Windows
    persistence mechanisms, live process state, and active network connections.
    It applies a curated set of heuristic rules to surface high-signal anomalies
    worthy of manual investigation, and exports a structured JSON report suitable
    for offline analysis, timeline reconstruction, or SIEM pipeline integration.

    Inspection Surface
      [1] Registry Run / RunOnce keys   — HKCU + HKLM (including WOW64 32-bit view)
      [2] Startup folders               — Per-user and all-users shell:startup paths
      [3] Scheduled Tasks               — All enabled, non-Microsoft-namespace tasks
      [4] Windows Services              — Auto-start services with binary path audit
      [5] WMI Event Subscriptions       — Permanent consumers (fileless persistence)
      [6] Running Processes             — Executable path, digital signature, SHA-256
      [7] Remote Access Tool Detection  — Known RAT/RMM process names (T1219)
      [8] RDP Configuration State       — Registry-level enable/disable check
      [9] Active Network Connections    — Established TCP sessions mapped to PID

    MITRE ATT&CK Coverage
      T1547.001  Boot/Logon Autostart Execution: Registry Run Keys / Startup Folder
      T1053.005  Scheduled Task/Job: Scheduled Task
      T1543.003  Create or Modify System Process: Windows Service
      T1546.003  Event Triggered Execution: Windows Management Instrumentation
      T1219      Remote Access Software
      T1021.001  Remote Services: Remote Desktop Protocol
      T1049      System Network Connections Discovery

.PARAMETER SkipHashing
    Skip SHA-256 hashing of process executables to improve execution speed.
    Useful in time-constrained triage scenarios or on systems with large numbers
    of running processes where hashing would be prohibitively slow. Hashes are
    still recorded in the JSON report when this flag is absent.

.PARAMETER NoJson
    Suppresses writing the JSON report to disk. All findings are still printed
    to the console. Use this flag in read-only environments or when console-only
    output is the desired operational mode.

.PARAMETER OutDir
    Destination directory for the timestamped JSON triage report.
    Defaults to ".\SysTriage_Reports" relative to the script working directory.
    The directory is created automatically if it does not exist.

.OUTPUTS
    System.String (console)
        Color-coded output: Red = anomaly; Yellow = review; Green = expected safe.

    JSON file at <OutDir>\SysTriage_<yyyyMMdd_HHmmss>.json
        Schema keys: ScanTime, Hostname, RanElevated, StartupEntries,
        ScheduledTasks, Services, WmiSubscriptions, Processes, RemoteAccessHits,
        RdpStatus, NetworkConns, Findings.

.NOTES
    Tool        : SysTriage v1.0
    Author      : Techienerd
    Category    : Incident Response / Endpoint Forensics
    Platform    : Windows (PowerShell 5.1+ or PowerShell 7+)
    Privileges  : Administrator recommended — some surfaces require elevation.

    Usage Examples
      # Standard elevated triage (recommended)
      powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1

      # Fast run — skip SHA-256 hashing of process executables
      powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -SkipHashing

      # Console-only output — no report file written to disk
      powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -NoJson

      # Custom report output directory
      powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -OutDir "D:\IR\Evidence"

    Operational Notes
      - A "flag" is an invitation to investigate, NOT a confirmed malicious finding.
        Cross-validate every finding against signer, file path, parent process,
        and VirusTotal SHA-256 before drawing conclusions or taking action.
      - For periodic monitoring, run before and after a reboot, then diff the two
        JSON reports to isolate newly introduced persistence mechanisms.
      - This script performs read-only operations and makes no system changes.

.DISCLAIMER
    FOR AUTHORIZED USE ONLY. Execute only on systems you own or have explicit
    written authorization to assess. Unauthorized use may violate applicable
    computer fraud and abuse laws.
#>

# =============================================================================
# Script Parameters
# =============================================================================
[CmdletBinding()]
param(
    # Skip SHA-256 hashing to improve speed on systems with many processes.
    # Recommended in latency-sensitive triage where hash lookup is deferred.
    [switch]$SkipHashing,

    # Suppress JSON report generation. Useful for console-only review or
    # when the analyst lacks write permissions to the output directory.
    [switch]$NoJson,

    # Destination directory for the timestamped JSON triage report.
    # Created automatically if the path does not already exist.
    [string]$OutDir = ".\SysTriage_Reports"
)

# =============================================================================
# Global Execution Context
# =============================================================================

# Suppress non-fatal errors from WMI, registry, and file-system queries so that
# a single inaccessible resource does not abort the entire triage pass.
$ErrorActionPreference = 'SilentlyContinue'

# Determine privilege level at startup. Several surfaces (WMI subscriptions,
# certain registry hives, system-level PID path resolution) require admin rights.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# =============================================================================
# Report Object — Structured Output Schema
# =============================================================================
# $Report accumulates all findings and is serialized to JSON at end of run.
# [ordered] preserves key insertion sequence for consistent, readable output.
$Report = [ordered]@{
    ScanTime         = (Get-Date).ToString("s")  # ISO 8601 sortable timestamp
    Hostname         = $env:COMPUTERNAME
    RanElevated      = $isAdmin
    StartupEntries   = @()   # Registry Run keys + startup folder entries
    ScheduledTasks   = @()   # Non-Microsoft enabled scheduled tasks
    Services         = @()   # Auto-start running Windows services
    WmiSubscriptions = @()   # Permanent WMI event consumers (fileless persistence)
    Processes        = @()   # Running processes with signature and hash data
    RemoteAccessHits = @()   # Subset: processes matching remote-access tool names
    RdpStatus        = $null # 'Enabled' | 'Disabled' | null (unreadable)
    NetworkConns     = @()   # Established TCP connections mapped to owning PID
    Findings         = @()   # Consolidated human-readable anomaly strings
}

# =============================================================================
# Console Output Helpers
# =============================================================================

function Write-Section($title) {
    # Prints a visually distinct section header to separate triage output areas.
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}

function Write-Flag($msg) {
    # Emits a high-signal anomaly to the console (red) and appends it to
    # $Report.Findings so all anomalies are surfaced together in the summary.
    Write-Host "  [!] $msg" -ForegroundColor Red
    $Report.Findings += $msg
}

function Write-Info($msg) {
    # Emits an informational status note (dark grey) for non-anomalous messages.
    Write-Host "  [i] $msg" -ForegroundColor DarkGray
}

# =============================================================================
# Suspicious Path Detection
# =============================================================================
# These regex patterns match file system paths associated with attacker staging
# and execution tradecraft. Legitimate enterprise software rarely installs or
# runs from these locations; their presence in auto-start mechanisms or active
# processes is a meaningful triage signal warranting further investigation.
#
#   \AppData\Local\Temp\         Abused for dropper staging/execution (T1036)
#   \Users\Public\               World-writable; used for lateral movement staging
#   \ProgramData\ (non-Microsoft) Common malware drop; Microsoft paths excluded
#   \Windows\Temp\               Abused by privilege-escalation tooling
#   \$Recycle.Bin\               Execution from recycle bin has no legitimate use
$SuspiciousPathPatterns = @(
    '\\AppData\\Local\\Temp\\',
    '\\Users\\Public\\',
    '\\ProgramData\\(?!Microsoft)',
    '\\Windows\\Temp\\',
    '\\\$Recycle\.Bin\\'
)

function Test-SuspiciousPath($path) {
    # Returns $true if $path matches any suspicious location pattern.
    # This is a heuristic filter — a match indicates elevated risk, not confirmed
    # compromise. Cross-reference with process signature and parent context.
    if (-not $path) { return $false }
    foreach ($pattern in $SuspiciousPathPatterns) {
        if ($path -match $pattern) { return $true }
    }
    return $false
}

# =============================================================================
# Remote Access / Remote Management Tool Name List
# =============================================================================
# Process names associated with legitimate RAT/RMM tools frequently abused by
# threat actors for persistence, lateral movement, and C2 (T1219).
# Presence here is NOT a confirmed indicator of compromise — the goal is to
# surface these for explicit "yes, I authorized this" review.
$RemoteAccessNames = @(
    'teamviewer', 'anydesk', 'vncserver', 'winvnc', 'tvnserver', 'ammyy',
    'supremo', 'quickassist', 'ultraviewer', 'remoteutilities', 'dwservice',
    'ngrok', 'radmin', 'logmein', 'splashtop', 'gotomypc', 'showmypc',
    'netsupport'
)

# =============================================================================
# [1] Registry Run / RunOnce Persistence Keys
# =============================================================================
# MITRE ATT&CK: T1547.001 — Registry Run Keys / Startup Folder
#
# Run and RunOnce keys under HKCU (per-user) and HKLM (system-wide) are the most
# commonly abused persistence mechanism on Windows. Both 64-bit (default) and
# 32-bit (WOW6432Node) views are inspected to catch 32-bit malware registering
# persistence exclusively in the WOW64 registry path on 64-bit systems.
# =============================================================================
Write-Section "Startup Registry Keys (Run / RunOnce)"

# Include WOW6432Node to detect 32-bit malware on 64-bit Windows systems.
$runKeyPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)

foreach ($keyPath in $runKeyPaths) {
    $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    if ($null -eq $props) { continue }

    # Filter out PowerShell-internal PS* metadata properties that are auto-
    # injected into PSObject wrappers of registry key objects, not actual values.
    $props.PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider)$' } |
        ForEach-Object {
            $entry = [ordered]@{ Key = $keyPath; Name = $_.Name; Command = $_.Value }
            $Report.StartupEntries += $entry

            $suspicious = Test-SuspiciousPath $_.Value
            $color = if ($suspicious) { 'Red' } else { 'White' }

            Write-Host "  [$keyPath]" -ForegroundColor DarkGray
            Write-Host "    $($_.Name)  ->  $($_.Value)" -ForegroundColor $color

            if ($suspicious) {
                Write-Flag "Run key '$($_.Name)' points to a suspicious path: $($_.Value)"
            }
        }
}

# Startup folders — files placed here execute automatically at every user logon.
# Per-user and All Users folders are both inspected; this is a simpler but still
# actively exploited persistence vector used by commodity malware.
$startupFolders = @(
    [Environment]::GetFolderPath('Startup'),       # Per-user:  %APPDATA%\...\Startup
    [Environment]::GetFolderPath('CommonStartup')  # All users: %ProgramData%\...\Startup
)
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem $folder -File | ForEach-Object {
            Write-Host "  [Startup Folder] $($_.FullName)" -ForegroundColor White
            $Report.StartupEntries += [ordered]@{
                Key = 'StartupFolder'; Name = $_.Name; Command = $_.FullName
            }
        }
    }
}

if ($Report.StartupEntries.Count -eq 0) { Write-Info "No entries found." }

# =============================================================================
# [2] Scheduled Tasks
# =============================================================================
# MITRE ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
#
# Enumerates all enabled tasks outside the \Microsoft\ namespace to filter the
# large volume of legitimate OS tasks. Disabled tasks are excluded — they pose
# no active execution risk and inflate output noise on managed workstations.
# =============================================================================
Write-Section "Scheduled Tasks (enabled, non-Microsoft)"

$tasks = Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '\\Microsoft\\'
}

if ($tasks) {
    foreach ($task in $tasks) {
        # Inspect only the first action; multi-action tasks are uncommon outside
        # complex legitimate automation but worth noting in deeper forensic passes.
        $action     = ($task.Actions | Select-Object -First 1)
        $exe        = $action.Execute
        $args       = $action.Arguments
        $suspicious = Test-SuspiciousPath $exe
        $color      = if ($suspicious) { 'Red' } else { 'White' }

        Write-Host "  $($task.TaskPath)$($task.TaskName)" -ForegroundColor $color
        Write-Host "    Runs: $exe $args" -ForegroundColor DarkGray

        $Report.ScheduledTasks += [ordered]@{
            Name = $task.TaskName; Path = $task.TaskPath; State = [string]$task.State
            Execute = $exe; Arguments = $args
        }

        if ($suspicious) {
            Write-Flag "Scheduled task '$($task.TaskName)' runs from a suspicious path: $exe"
        }
    }
} else {
    Write-Info "No non-Microsoft enabled tasks found."
}

# =============================================================================
# [3] Windows Services (Auto-Start)
# =============================================================================
# MITRE ATT&CK: T1543.003 — Create or Modify System Process: Windows Service
#
# Enumerates Auto-start services currently in Running state. Legitimate services
# almost universally run from %SystemRoot%\System32 or %ProgramFiles% — any
# deviation from expected vendor paths is a meaningful triage signal.
# CIM is used over legacy WMI cmdlets for better cross-version compatibility.
# =============================================================================
Write-Section "Auto-Start Services (currently running)"

$services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' }

foreach ($svc in $services) {
    $suspicious = Test-SuspiciousPath $svc.PathName
    $color      = if ($suspicious) { 'Red' } else { 'White' }

    Write-Host "  $($svc.Name)  [$($svc.DisplayName)]" -ForegroundColor $color
    Write-Host "    $($svc.PathName)" -ForegroundColor DarkGray

    $Report.Services += [ordered]@{
        Name = $svc.Name; DisplayName = $svc.DisplayName; PathName = $svc.PathName
    }

    if ($suspicious) {
        Write-Flag "Service '$($svc.Name)' binary runs from a suspicious path: $($svc.PathName)"
    }
}

# =============================================================================
# [4] WMI Permanent Event Subscriptions
# =============================================================================
# MITRE ATT&CK: T1546.003 — WMI Event Subscription
#
# WMI permanent event subscriptions (Filter + Consumer + Binding) provide
# fileless, reboot-persistent execution that does not appear in Run keys,
# startup folders, or the task scheduler. Associated with APTs and post-
# exploitation frameworks (Empire, Cobalt Strike). Legitimate enterprise
# software very rarely uses this technique — any finding warrants priority triage.
# Requires administrator privileges; returns no results silently without elevation.
# =============================================================================
Write-Section "WMI Permanent Event Subscriptions"

$wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
if ($wmiConsumers) {
    foreach ($c in $wmiConsumers) {
        Write-Flag "WMI event consumer present: $($c.Name) — rare in legitimate enterprise use; inspect manually"
        $Report.WmiSubscriptions += [ordered]@{ Name = $c.Name; Type = $c.CimClass.CimClassName }
    }
} else {
    Write-Info "No WMI permanent event consumers found."
}

# =============================================================================
# [5] Running Processes — Signature and Hash Audit
# =============================================================================
# MITRE ATT&CK: T1036 — Masquerading; T1219 — Remote Access Software
#
# Each unique running process (deduplicated by name) is evaluated against:
#   (a) Suspicious path  — Executable in a user-writable or temp directory?
#   (b) Signature status — Valid Authenticode chain from a trusted root CA?
#   (c) RAT/RMM name     — Name matches a known remote-access tool?
#
# Processes with no triggered heuristics are silently recorded in the JSON
# report only, keeping console output focused on signals worth investigating.
# =============================================================================
Write-Section "Running Processes (signature + hash check)"

# Warn if non-elevated — system-level process paths may not be resolvable.
if (-not $isAdmin) { Write-Info "Not running elevated — some process paths may be inaccessible." }
if ($SkipHashing)  { Write-Info "SHA-256 hashing skipped (-SkipHashing flag active)." }

# Deduplicate by name to reduce noise for multi-instance processes (svchost, etc.).
# Individual PIDs are preserved in the JSON report for post-analysis correlation.
$procs = Get-Process | Where-Object { $_.Path } | Sort-Object ProcessName -Unique

foreach ($p in $procs) {
    # 'Valid' Authenticode status requires an intact trust chain and unmodified
    # binary. Any other status (NotSigned, HashMismatch, etc.) is flagged.
    $sig    = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue
    $signer = if ($sig -and $sig.Status -eq 'Valid') {
                  $sig.SignerCertificate.Subject
              } else { 'UNSIGNED/INVALID' }

    # SHA-256 for VirusTotal lookups. Use -SkipHashing to bypass in urgent triage.
    $hash = if (-not $SkipHashing) {
                (Get-FileHash -Path $p.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            } else { $null }

    $suspiciousPath = Test-SuspiciousPath $p.Path

    # -match is case-insensitive by default; catches variations in exe name casing.
    $isRat = $RemoteAccessNames | Where-Object { $p.ProcessName -match $_ }

    $entry = [ordered]@{
        Name = $p.ProcessName; Pid = $p.Id; Path = $p.Path; Signer = $signer; Sha256 = $hash
    }
    $Report.Processes += $entry

    # Emit console output only for processes triggering at least one heuristic.
    if ($suspiciousPath -or $signer -eq 'UNSIGNED/INVALID' -or $isRat) {
        $color = if ($suspiciousPath) { 'Red' } else { 'Yellow' }  # Red > Yellow severity

        Write-Host "  $($p.ProcessName) (PID $($p.Id))" -ForegroundColor $color
        Write-Host "    Path:   $($p.Path)"              -ForegroundColor DarkGray
        Write-Host "    Signer: $signer"                 -ForegroundColor DarkGray
        if ($hash) { Write-Host "    SHA256: $hash"      -ForegroundColor DarkGray }

        # Discrete finding per heuristic for actionable, specific summary output.
        if ($suspiciousPath) {
            Write-Flag "Process '$($p.ProcessName)' (PID $($p.Id)) runs from a suspicious path: $($p.Path)"
        }
        if ($signer -eq 'UNSIGNED/INVALID') {
            Write-Flag "Process '$($p.ProcessName)' (PID $($p.Id)) is unsigned or has an invalid signature — verify manually"
        }
        if ($isRat) {
            Write-Flag "Remote-access tool detected: '$($p.ProcessName)' (PID $($p.Id)) — confirm intentional installation"
            $Report.RemoteAccessHits += $entry
        }
    }
}
Write-Info "Full process list written to JSON report; only anomalous entries printed above."

# =============================================================================
# [6] Remote Desktop Protocol (RDP) Configuration
# =============================================================================
# MITRE ATT&CK: T1021.001 — Remote Services: Remote Desktop Protocol
#
# RDP (TCP 3389) is one of the most exploited initial-access vectors in
# ransomware and data-extortion attacks. The fDenyTSConnections registry value
# is the definitive control flag:
#   0 = RDP ENABLED  (connections accepted)
#   1 = RDP DISABLED (connections rejected)
# Requires administrator privileges to read; reports inability to read if unelevated.
# =============================================================================
Write-Section "Remote Desktop (RDP) Configuration"

$rdpDeny = Get-ItemProperty `
    -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name fDenyTSConnections -ErrorAction SilentlyContinue

if ($rdpDeny) {
    $rdpEnabled       = ($rdpDeny.fDenyTSConnections -eq 0)
    $Report.RdpStatus = if ($rdpEnabled) { 'Enabled' } else { 'Disabled' }

    if ($rdpEnabled) {
        Write-Flag "RDP is ENABLED — disable if not operationally required: Settings > System > Remote Desktop."
    } else {
        Write-Host "  RDP is disabled." -ForegroundColor Green
    }
} else {
    Write-Info "Unable to read RDP registry state — administrator privileges required."
}

# =============================================================================
# [7] Active Network Connections
# =============================================================================
# MITRE ATT&CK: T1049 — System Network Connections Discovery
#
# Enumerates all currently established TCP connections and maps each to its
# owning process (by PID). Useful for identifying unexpected outbound channels
# (e.g., C2 beaconing), correlating connections to suspicious processes, and
# establishing a network baseline for comparison against future scans.
#
# Note: this is a point-in-time snapshot. Low-jitter beacons may connect and
# disconnect between scan passes. Supplement with firewall logging or EDR
# NetFlow for continuous coverage.
# =============================================================================
Write-Section "Established Network Connections"

$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
foreach ($c in $conns) {
    # Map owning PID to process name. Unresolvable PIDs (e.g., recently
    # terminated or system-restricted processes) are shown as "PID <N>".
    $proc     = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    $procName = if ($proc) { $proc.ProcessName } else { "PID $($c.OwningProcess)" }

    Write-Host "  $procName  $($c.LocalAddress):$($c.LocalPort)  ->  $($c.RemoteAddress):$($c.RemotePort)" -ForegroundColor White
    $Report.NetworkConns += [ordered]@{
        Process = $procName; Pid = $c.OwningProcess
        Local   = "$($c.LocalAddress):$($c.LocalPort)"
        Remote  = "$($c.RemoteAddress):$($c.RemotePort)"
    }
}
if ($conns.Count -eq 0) { Write-Info "No established TCP connections found at time of scan." }

# =============================================================================
# Triage Summary
# =============================================================================
# Consolidates all Write-Flag events into a numbered list for rapid review.
# A clean result (0 findings) does NOT guarantee a clean system — it means no
# heuristic rules fired. Always review the full JSON for unfamiliar entries.
# =============================================================================
Write-Section "Triage Summary"

if ($Report.Findings.Count -eq 0) {
    Write-Host "  No high-signal anomalies flagged by automated heuristics." -ForegroundColor Green
    Write-Host "  This result does NOT guarantee a clean system. Review the full JSON" -ForegroundColor Green
    Write-Host "  report for unfamiliar entries and verify hashes via VirusTotal." -ForegroundColor Green
} else {
    Write-Host "  $($Report.Findings.Count) item(s) flagged for manual review:" -ForegroundColor Yellow
    $i = 1
    foreach ($f in $Report.Findings) { Write-Host "   $i. $f" -ForegroundColor Yellow; $i++ }
    Write-Host ""
    Write-Host "  A flag is an invitation to investigate, NOT a confirmed malicious finding." -ForegroundColor Yellow
    Write-Host "  Validate: signer, file path, parent process, and SHA-256 (VirusTotal)" -ForegroundColor Yellow
    Write-Host "  before taking any remediation action." -ForegroundColor Yellow
}

# =============================================================================
# JSON Report Export
# =============================================================================
# Serializes $Report to JSON at depth 6 so nested objects (task action details,
# certificate subjects) are fully expanded rather than collapsed to type strings.
# File naming: SysTriage_<yyyyMMdd_HHmmss>.json — sortable chronological order.
# UTF-8 (no BOM) encoding for compatibility with SIEM ingestors, jq, Python, etc.
# =============================================================================
if (-not $NoJson) {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
    $stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
    $outFile = Join-Path $OutDir "SysTriage_$stamp.json"
    $Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $outFile -Encoding utf8
    Write-Host ""
    Write-Host "  Report saved : $outFile" -ForegroundColor Cyan
    Write-Host "  Tip: re-run after a system reboot and diff the two JSON files to" -ForegroundColor DarkGray
    Write-Host "  isolate new persistence entries introduced since the last scan." -ForegroundColor DarkGray
}
