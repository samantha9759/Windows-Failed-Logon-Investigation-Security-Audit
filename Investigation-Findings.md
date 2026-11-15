# Windows Failed Logon Investigation

## 1. Investigation Overview

**Project:** Windows Failed Logon Investigation  
**Operating System:** Windows 10/11  
**Log Source:** Windows Security Event Log  
**Event ID:** 4625 — An account failed to log on  
**Investigation Type:** Windows Security Log Analysis  

### Objective

Investigate a recorded failed Windows logon event, extract relevant security information, and identify indicators that may require further investigation.

## 2. Evidence Collected

The PowerShell audit script identified one failed logon event.

| Field | Finding |
|---|---|
| Event ID | 4625 |
| Timestamp | October 8, 2026, 8:13:35 PM |
| Target User | - (Not recorded) |
| Target Domain | - (Not recorded) |
| Logon Type | 2 (Interactive) |
| Source IP | 127.0.0.1 |
| Process Name | C:\Windows\System32\svchost.exe |
| Process ID | 0x72c (1836) |
| Status | 0xc000006d |
| SubStatus | 0xc0000380 |

## 3. Technical Analysis

### Failed Logon Event

Windows Security Event ID 4625 records unsuccessful logon attempts.

The event contained the following indicators:

- **Logon Type 2:** Indicates an interactive logon attempt.
- **Source IP 127.0.0.1:** Indicates a loopback address associated with the local system.
- **Process Name:** The event identified `svchost.exe` as the calling process.
- **Process ID:** The recorded process ID was 1836.

### Process Investigation

The process ID was investigated using PowerShell:

```powershell
Get-Process -Id 1836
```

The system returned no matching process.

A second check was performed:

```powershell
tasklist /svc /fi "PID eq 1836"
```

No active process matched the recorded PID.

This does not establish that the process was malicious. The process may have exited since the event was recorded.

## 4. PowerShell Automation

A custom PowerShell script was developed to:

1. Retrieve Windows Security Event ID 4625.
2. Parse event XML data.
3. Extract relevant logon and process information.
4. Organize the collected information into structured objects.
5. Export the results to a CSV report.

**Output:** `Failed-Logon-Report.csv`

The script successfully executed and collected one event during validation.

## 5. Findings and Limitations

The investigation confirmed that Windows recorded one failed logon event in the available Security log.

The event originated from the local system's loopback address. The target account was not recorded in the available event data.

The recorded process ID was no longer active when investigated.

The available evidence is insufficient to determine the exact cause of the failed logon or establish malicious activity.

## 6. Recommended Next Steps

Further investigation could include:

- Reviewing nearby Security events for additional authentication activity.
- Correlating Event ID 4625 with successful logon events (4624).
- Reviewing process creation events (4688), if auditing was enabled.
- Checking for repeated failed logons or suspicious account activity.
- Reviewing endpoint security alerts and other available system logs.

## 7. Skills Demonstrated

- Windows Security Event Log analysis
- Event ID 4625 investigation
- PowerShell scripting and automation
- XML event data parsing
- CSV report generation
- Process identification and investigation
- Basic incident response documentation
- Evidence-based security analysis

---

**Disclaimer:** This project uses a locally collected Windows Security event for educational and portfolio purposes. Findings are limited to the evidence available on the test system.
