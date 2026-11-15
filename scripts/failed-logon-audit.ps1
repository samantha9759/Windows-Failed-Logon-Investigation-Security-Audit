
# Windows Failed Logon Investigation
# Event ID: 4625
# Purpose: Collect, analyze, and export failed logon events.

Write-Host "Starting Windows Failed Logon Audit..." -ForegroundColor Cyan

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -ErrorAction SilentlyContinue

if (-not $Events) {
    Write-Host "No failed logon events found." -ForegroundColor Yellow
    return
}

$Report = $Events | ForEach-Object {
    $Event = $_
    $Xml = [xml]$Event.ToXml()
    $Fields = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Fields[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventID     = $Event.Id
        TargetUser  = $Fields['TargetUserName']
        TargetDomain = $Fields['TargetDomainName']
        LogonType   = $Fields['LogonType']
        FailureReason = $Fields['FailureReason']
        Status      = $Fields['Status']
        SubStatus   = $Fields['SubStatus']
        ProcessName = $Fields['ProcessName']
        ProcessID   = $Fields['ProcessId']
        SourceIP    = $Fields['IpAddress']
    }
}

$OutputPath = "$env:USERPROFILE\Desktop\Failed-Logon-Report.csv"

$Report | Export-Csv -Path $OutputPath -NoTypeInformation

Write-Host "Investigation complete." -ForegroundColor Green
Write-Host "Events collected: $($Report.Count)"
Write-Host "Report saved to: $OutputPath"
