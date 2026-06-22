<#
.SYNOPSIS
    SOAR-lite suspicious PowerShell triage playbook.

.DESCRIPTION
    Creates a case folder, collects recent PowerShell processes and logs,
    checks for common suspicious command indicators, and generates a Markdown report.
#>

[CmdletBinding()]
param(
    [string]$RuleId = "100102",
    [string]$RootPath = "C:\Wazuh-SOAR",
    [int]$MaxEvents = 30
)

function New-CaseFolder {
    param(
        [string]$CaseType,
        [string]$RootPath
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $caseId = "CASE-$timestamp-$CaseType"
    $caseRoot = Join-Path $RootPath "Cases"
    $casePath = Join-Path $caseRoot $caseId
    New-Item -Path $casePath -ItemType Directory -Force | Out-Null
    return $casePath
}

function Write-CaseLog {
    param(
        [string]$CasePath,
        [string]$Message
    )

    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path (Join-Path $CasePath "case-log.txt") -Value $line
}

New-Item -Path (Join-Path $RootPath "Cases") -ItemType Directory -Force | Out-Null
$casePath = New-CaseFolder -CaseType "PowerShell" -RootPath $RootPath

Write-CaseLog -CasePath $casePath -Message "Started suspicious PowerShell triage playbook."
Write-CaseLog -CasePath $casePath -Message "Rule ID: $RuleId"

$processPath = Join-Path $casePath "powershell-processes.txt"
$eventPath = Join-Path $casePath "powershell-events.txt"
$indicatorPath = Join-Path $casePath "indicator-review.txt"

try {
    Get-CimInstance Win32_Process |
        Where-Object { $_.Name -match 'powershell|pwsh' } |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
        Format-List |
        Out-File -FilePath $processPath -Encoding UTF8

    Write-CaseLog -CasePath $casePath -Message "Collected running PowerShell process details."
}
catch {
    "Error collecting PowerShell processes: $($_.Exception.Message)" | Out-File -FilePath $processPath -Encoding UTF8
    Write-CaseLog -CasePath $casePath -Message "Error collecting PowerShell processes."
}

try {
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents $MaxEvents -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message |
        Format-List |
        Out-File -FilePath $eventPath -Encoding UTF8

    Write-CaseLog -CasePath $casePath -Message "Collected recent PowerShell operational events."
}
catch {
    "PowerShell operational log not available or could not be read: $($_.Exception.Message)" |
        Out-File -FilePath $eventPath -Encoding UTF8
    Write-CaseLog -CasePath $casePath -Message "Could not read PowerShell operational log."
}

$indicatorText = ""
if (Test-Path $processPath) {
    $indicatorText += Get-Content $processPath -Raw
}
if (Test-Path $eventPath) {
    $indicatorText += "`n"
    $indicatorText += Get-Content $eventPath -Raw
}

$indicators = @(
    "EncodedCommand",
    "FromBase64String",
    "Invoke-WebRequest",
    "DownloadString",
    "Invoke-Expression",
    "IEX",
    "Start-BitsTransfer",
    "-nop",
    "-w hidden",
    "bypass"
)

$foundIndicators = foreach ($indicator in $indicators) {
    if ($indicatorText -match [regex]::Escape($indicator)) {
        $indicator
    }
}

if ($foundIndicators) {
    $foundIndicators | Out-File -FilePath $indicatorPath -Encoding UTF8
    Write-CaseLog -CasePath $casePath -Message "Potential suspicious indicators found: $($foundIndicators -join ', ')"
}
else {
    "No basic suspicious indicators were found in the collected sample." |
        Out-File -FilePath $indicatorPath -Encoding UTF8
    Write-CaseLog -CasePath $casePath -Message "No basic suspicious indicators found in collected sample."
}

$report = @"
# Suspicious PowerShell Triage Incident Report

## Summary

A Wazuh PowerShell alert was reviewed using the PowerShell SOAR-lite triage playbook.

## Case Details

| Field | Value |
|---|---|
| Case Folder | $casePath |
| Rule ID | $RuleId |
| Hostname | $env:COMPUTERNAME |
| User | $env:USERNAME |
| Max Events Reviewed | $MaxEvents |
| Potential Indicators Found | $($foundIndicators -join ', ') |
| Timestamp | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |

## Evidence Files

- powershell-processes.txt
- powershell-events.txt
- indicator-review.txt
- case-log.txt

## Analyst Notes

- Check whether the PowerShell activity came from expected lab scripts.
- Review command line, parent process, and script block details if available.
- Escalate if encoded commands, download cradles, credential theft, or persistence activity is found.

## Closure Recommendation

Close as lab validation if the activity matches expected testing. Escalate if commands are unexpected or suspicious.
"@

$reportPath = Join-Path $casePath "incident-report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "PowerShell triage playbook complete." -ForegroundColor Green
Write-Host "Case folder: $casePath"
Write-Host "Report: $reportPath"
