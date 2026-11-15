# Windows Failed Logon Investigation & Security Audit

## Project Overview

This project demonstrates a Windows security investigation using PowerShell and Windows Security Event Logs.

The investigation focuses on **Event ID 4625**, generated when a logon attempt fails.

## Objectives

- Identify failed logon events.
- Examine authentication details.
- Investigate the originating process.
- Identify patterns in failed authentication attempts.
- Export findings into a CSV report.

## Tools Used

- Windows 10/11
- PowerShell
- Windows Event Viewer
- Windows Security Event Logs
- CSV reporting

## Investigation Steps

### 1. Retrieve Failed Logon Events

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -MaxEvents 10
```

### 2. Examine Authentication Details

Reviewed:
- Event ID
- Logon Type
- Failure Reason
- Status and SubStatus
- Process Name and Process ID
- Source Network Address

### 3. Investigate the Originating Process

The event identified `svchost.exe` with process ID `1836` (hexadecimal `0x72c`).

```powershell
Get-Process -Id 1836
tasklist /svc /fi "PID eq 1836"
```

The process was no longer running when investigated.

### 4. Identify Failed Logon Patterns

Grouped failed logon events by target account:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -ErrorAction SilentlyContinue |
Group-Object {
    $_.Properties[5].Value
} |
Select-Object Name, Count |
Sort-Object Count -Descending
```

### 5. Export Findings to CSV

```powershell
$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -ErrorAction SilentlyContinue

$Events | Select-Object TimeCreated, Id,
@{Name='TargetAccount';Expression={$_.Properties[5].Value}},
@{Name='LogonType';Expression={$_.Properties[10].Value}},
@{Name='ProcessName';Expression={$_.Properties[18].Value}},
@{Name='ProcessId';Expression={$_.Properties[17].Value}},
@{Name='SourceIP';Expression={$_.Properties[19].Value}} |
Export-Csv "$env:USERPROFILE\Desktop\Failed-Logon-Report.csv" -NoTypeInformation
```

## Investigation Findings

One failed logon event was returned from the currently retained Security log.

| Field | Finding |
|---|---|
| Event ID | 4625 |
| Date | October 8, 2026 |
| Logon Type | 2 — Interactive |
| Target Account | Not recorded |
| Process | svchost.exe |
| Process ID | 1836 |
| Source Address | 127.0.0.1 |
| CSV Export | Successful |

## Analysis

The event originated from the local computer (`127.0.0.1`). Windows identified `svchost.exe` as the requesting process.

The process was no longer active when investigated, preventing further live-process inspection.

The available evidence was insufficient to classify the event as malicious.

## Security Considerations

- Monitor repeated failed authentication attempts.
- Investigate unusual logon patterns.
- Review unexpected processes and services.
- Correlate authentication events with other security logs.
- Avoid classifying isolated events as malicious without supporting evidence.

## Skills Demonstrated

- Windows Event Log Analysis
- PowerShell
- Authentication Monitoring
- Process Investigation
- Security Event Analysis
- CSV Reporting
- Incident Investigation

## Limitations

This investigation reflects events available in the Security log at the time of collection. It does not establish that only one failed logon has ever occurred.

The historical process could not be inspected while running.

## Conclusion

This project demonstrates a practical Windows security monitoring workflow using native PowerShell commands and Windows Event Logs, from identifying a failed authentication event to documenting and exporting findings.
