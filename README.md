<div align="center">

# SysTriage

### Windows Persistence & Anomaly Triage Tool

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red?logo=mitre&logoColor=white)](https://attack.mitre.org)
[![Category](https://img.shields.io/badge/Category-Incident%20Response-orange)](https://github.com)

**A single-script Windows triage tool that enumerates persistence mechanisms,
audits running processes, and flags high-signal anomalies — designed for incident
responders, security engineers, and SOC analysts who need fast, auditable findings.**

</div>

---

## Overview

SysTriage performs a comprehensive, read-only, single-pass sweep of a Windows
endpoint. It surfaces the persistence mechanisms, process anomalies, and network
activity that matter during active incident response — without requiring any
third-party dependencies, agent installation, or elevated cloud connectivity.

Every detection is backed by an explicit, documented rule mapped to a MITRE
ATT&CK technique. There is no hidden scoring engine. If a finding fires, you
can read the code and see exactly why.

The tool produces:
- **Color-coded console output** for immediate analyst situational awareness
- **A timestamped JSON report** for offline analysis, timeline reconstruction,
  or ingestion into a SIEM pipeline

---

## Inspection Surface

| # | Area | What Is Checked |
|---|------|-----------------|
| 1 | **Registry Run / RunOnce** | HKCU + HKLM (64-bit and WOW64 32-bit views) |
| 2 | **Startup Folders** | Per-user and All Users shell:startup paths |
| 3 | **Scheduled Tasks** | All enabled tasks outside the `\Microsoft\` namespace |
| 4 | **Windows Services** | Auto-start services with binary path validation |
| 5 | **WMI Event Subscriptions** | Permanent `__EventConsumer` instances (fileless persistence) |
| 6 | **Running Processes** | Executable path, Authenticode signature, SHA-256 hash |
| 7 | **Remote Access Tools** | Process name matching against known RAT/RMM tool list |
| 8 | **RDP Configuration** | Registry-level enable/disable state of Remote Desktop |
| 9 | **Network Connections** | All established TCP sessions mapped to owning PID |

---

## MITRE ATT&CK Coverage

| Technique ID | Name |
|---|---|
| **T1547.001** | Boot/Logon Autostart: Registry Run Keys / Startup Folder |
| **T1053.005** | Scheduled Task/Job: Scheduled Task |
| **T1543.003** | Create or Modify System Process: Windows Service |
| **T1546.003** | Event Triggered Execution: WMI Event Subscription |
| **T1219** | Remote Access Software |
| **T1021.001** | Remote Services: Remote Desktop Protocol |
| **T1049** | System Network Connections Discovery |

---

## Quick Start

```powershell
# Clone or download the repository
git clone https://github.com/tiwarirst/SysTriage.git
cd SysTriage

# Run a full triage (elevated PowerShell window recommended)
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1
```

> **Privilege Requirement**: Run in an elevated (Administrator) PowerShell session
> for full visibility. Without elevation, WMI event subscriptions, certain registry
> hives, and system-level process paths may be inaccessible — the script will note
> this at runtime rather than silently failing.

---

## Usage

```powershell
# Standard elevated triage — full output and JSON report (recommended)
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1

# Fast triage — skip SHA-256 hashing (useful on high-process-count systems)
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -SkipHashing

# Console-only — no JSON report written to disk (read-only environments)
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -NoJson

# Custom report output directory
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -OutDir "D:\IR\Evidence"

# Combine flags
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -SkipHashing -OutDir "E:\Triage"
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SkipHashing` | Switch | `$false` | Skip SHA-256 hashing of process executables for faster execution |
| `-NoJson` | Switch | `$false` | Suppress JSON report file generation; console output only |
| `-OutDir` | String | `.\SysTriage_Reports` | Directory for timestamped JSON report output |

---

## Output

### Console

Console output is color-coded to convey severity at a glance:

| Color | Meaning |
|---|---|
| 🔴 Red | High-signal anomaly flagged — investigate promptly |
| 🟡 Yellow | Warrants manual review — not necessarily malicious |
| ⚪ White | Nominal entry, recorded for reference |
| 🟢 Green | Expected safe state (e.g., RDP disabled) |
| ⬛ Dark Grey | Informational notes and status messages |

### JSON Report

Each run produces a timestamped report in `.\SysTriage_Reports\`:

```
SysTriage_Reports\
└── SysTriage_20260922_214500.json
```

**Report schema:**

```jsonc
{
  "ScanTime":         "2026-09-22T21:45:00",   // ISO 8601 scan start timestamp
  "Hostname":         "WORKSTATION-01",
  "RanElevated":      true,
  "StartupEntries":   [ { "Key": "...", "Name": "...", "Command": "..." } ],
  "ScheduledTasks":   [ { "Name": "...", "Path": "...", "Execute": "..." } ],
  "Services":         [ { "Name": "...", "DisplayName": "...", "PathName": "..." } ],
  "WmiSubscriptions": [ { "Name": "...", "Type": "..." } ],
  "Processes":        [ { "Name": "...", "Pid": 1234, "Path": "...", "Signer": "...", "Sha256": "..." } ],
  "RemoteAccessHits": [ /* subset of Processes matching RAT/RMM names */ ],
  "RdpStatus":        "Disabled",
  "NetworkConns":     [ { "Process": "...", "Local": "...", "Remote": "..." } ],
  "Findings":         [ "Human-readable anomaly string 1", "..." ]
}
```

---

## Detection Heuristics

### Suspicious Path Detection

Processes and auto-start entries executing from the following paths are flagged:

| Path Pattern | Rationale |
|---|---|
| `\AppData\Local\Temp\` | Primary dropper staging location (T1036, T1204) |
| `\Users\Public\` | World-writable; used for lateral movement staging |
| `\ProgramData\` *(non-Microsoft)* | Common malware drop location |
| `\Windows\Temp\` | Abused by privilege-escalation tooling |
| `\$Recycle.Bin\` | No legitimate software executes from the recycle bin |

### Remote Access Tool Detection

Processes are name-matched against a curated list of known RAT and RMM tools:

```
TeamViewer · AnyDesk · VNC variants · Ammyy Admin · Supremo · UltraViewer
ngrok · Radmin · LogMeIn · Splashtop · GoToMyPC · ShowMyPC · NetSupport
QuickAssist · RemoteUtilities · DWService
```

> Detection here is advisory, not conclusive. These tools are widely used
> legitimately. The goal is a deliberate "yes, I installed this" confirmation.

### Process Signature Validation

Every resolvable process executable is checked for a valid Authenticode signature.
`UNSIGNED/INVALID` status is flagged for manual verification — unsigned binaries
are not inherently malicious, but are not expected in a well-managed environment.

---

## Threat Model & Scope

### What This Tool Is

- A **fast, lightweight first-pass triage tool** for incident responders who
  need immediate situational awareness on a Windows endpoint
- A **read-only forensic instrument** — it makes no system modifications
- A **transparent detection system** where every rule is a documented, auditable
  condition rather than a black-box score

### What This Tool Is Not

- A replacement for a commercial EDR (CrowdStrike, SentinelOne, Defender for Endpoint)
- A kernel-level or real-time monitoring agent
- An exhaustive forensic platform (for full forensics, pair with tools like
  Volatility, KAPE, or Magnet Axiom)

---

## Known Limitations

| Limitation | Notes |
|---|---|
| No kernel visibility | A sufficiently privileged attacker can terminate or evade this userspace tool |
| No tamper protection | Nothing prevents an attacker from killing the process or clearing its output |
| Point-in-time snapshot | Low-jitter C2 beacons may connect/disconnect between scan passes |
| No real-time event monitoring | Polling-based; supplement with ETW or Sysmon for process creation events |
| Static rule set | No ML-based anomaly baselining beyond the detection heuristics listed |
| Userspace-only signature checks | Does not detect code-signing certificate theft or kernel-mode tampering |

---

## Operational Workflow

### Single Triage Pass

```
1. Open an elevated PowerShell window
2. Run: powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1
3. Review console output for red (anomaly) and yellow (review) entries
4. Examine the generated JSON report for any unfamiliar baseline entries
5. Cross-reference SHA-256 hashes against VirusTotal for unsigned processes
```

### Comparative Analysis (Recommended)

For maximum signal-to-noise ratio, run SysTriage before and after a reboot (or
after a suspected compromise event), then diff the two JSON reports:

```powershell
# Run 1 — pre-event or clean baseline
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -OutDir ".\Baseline"

# Run 2 — post-event or post-reboot
powershell -ExecutionPolicy Bypass -File .\SysTriage.ps1 -OutDir ".\PostEvent"

# Diff the two Findings arrays with any JSON comparison tool, or use jq:
# jq '.Findings' .\Baseline\SysTriage_*.json
# jq '.Findings' .\PostEvent\SysTriage_*.json
```

New entries in `StartupEntries`, `ScheduledTasks`, `Services`, or
`WmiSubscriptions` between the two runs are your highest-priority leads.

---

## Project Structure

```
SysTriage/
├── SysTriage.ps1          # Main triage script (single-file, no dependencies)
├── SysTriage_Reports/     # Auto-created output directory for JSON reports
│   └── SysTriage_<timestamp>.json
└── README.md
```

---

## Requirements

| Requirement | Details |
|---|---|
| **Operating System** | Windows 7 / Server 2008 R2 or later |
| **PowerShell** | 5.1+ (built-in on Windows 10/11/Server 2016+) or PowerShell 7+ |
| **Privileges** | Administrator recommended for full coverage |
| **Dependencies** | None — uses only built-in PowerShell cmdlets and Windows APIs |
| **Network** | Not required — fully offline capable |

---

## Roadmap

Planned enhancements for future iterations:

- [ ] **ETW Integration** — Consume Event Tracing for Windows via `pywin32` or
  `Microsoft-Windows-Kernel-Process` provider for real-time process creation
  events instead of polling snapshots
- [ ] **YARA Rule Support** — On-disk file scanning against custom or community
  YARA rulesets for known malware signatures
- [ ] **Persistent Baseline** — `--baseline-file` option to persist baseline
  state across runs, enabling delta detection without requiring paired reports
- [ ] **Sysmon Log Parsing** — Ingest and correlate Sysmon event logs for
  parent-process chain analysis and enhanced masquerading detection
- [ ] **HTML Report Export** — Browser-viewable report with sortable tables,
  severity filtering, and VirusTotal deep-link buttons

---

## Disclaimer

> **FOR AUTHORIZED USE ONLY.**
> This tool must only be executed against systems you own or have explicit
> written authorization to assess. Unauthorized use against systems without
> permission may violate applicable computer fraud and abuse laws, including
> (but not limited to) the Computer Fraud and Abuse Act (CFAA) and equivalent
> legislation in your jurisdiction.
>
> A finding from this tool is an invitation to investigate — **not** a
> confirmed indicator of compromise. All flagged items must be manually
> validated before any remediation action is taken.

---


<div align="center">

*Built for speed. Designed for analysts. Backed by ATT&CK.*

</div>
