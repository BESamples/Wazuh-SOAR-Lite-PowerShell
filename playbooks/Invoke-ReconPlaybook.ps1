<#
.SYNOPSIS
    SOAR-lite recon / Nmap incident response playbook.

.DESCRIPTION
    Creates a case folder, documents the scan source IP, captures basic network evidence,
    and optionally creates a Windows Firewall block rule for lab-only containment.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SourceIp = "192.168.56.50",

    [string]$RuleId = "100200",
    [string]$RootPath = "C:\Wazuh-SOAR",
    [switch]$BlockIp
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
$casePath = New-CaseFolder -CaseType "Recon" -RootPath $RootPath

Write-CaseLog -CasePath $casePath -Message "Started recon / Nmap playbook."
Write-CaseLog -CasePath $casePath -Message "Rule ID: $RuleId"
Write-CaseLog -CasePath $casePath -Message "Source IP: $SourceIp"

$networkPath = Join-Path $casePath "network-connections.txt"
$firewallPath = Join-Path $casePath "firewall-action.txt"
$blockRuleName = "Wazuh-SOAR-Lab-Block-$SourceIp"
$actionTaken = "No firewall block created. Documentation only."

try {
    Get-NetTCPConnection -ErrorAction Stop |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Sort-Object RemoteAddress, RemotePort |
        Out-File -FilePath $networkPath -Encoding UTF8
    Write-CaseLog -CasePath $casePath -Message "Collected current TCP connections."
}
catch {
    "Could not collect TCP connections: $($_.Exception.Message)" |
        Out-File -FilePath $networkPath -Encoding UTF8
    Write-CaseLog -CasePath $casePath -Message "Could not collect TCP connections."
}

if ($BlockIp) {
    try {
        New-NetFirewallRule `
            -DisplayName $blockRuleName `
            -Direction Inbound `
            -RemoteAddress $SourceIp `
            -Action Block `
            -Profile Any `
            -Description "Lab block created by Wazuh SOAR-Lite Recon Playbook" |
            Out-Null

        $actionTaken = "Created inbound Windows Firewall block rule: $blockRuleName"
        Write-CaseLog -CasePath $casePath -Message $actionTaken
    }
    catch {
        $actionTaken = "Failed to create firewall block rule: $($_.Exception.Message)"
        Write-CaseLog -CasePath $casePath -Message $actionTaken
    }
}

$actionTaken | Out-File -FilePath $firewallPath -Encoding UTF8

$report = @"
# Recon / Nmap Incident Report

## Summary

A Wazuh recon-style alert was reviewed using the PowerShell SOAR-lite recon playbook.

## Case Details

| Field | Value |
|---|---|
| Case Folder | $casePath |
| Rule ID | $RuleId |
| Hostname | $env:COMPUTERNAME |
| User | $env:USERNAME |
| Source IP | $SourceIp |
| Firewall Action | $actionTaken |
| Timestamp | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |

## Evidence Files

- network-connections.txt
- firewall-action.txt
- case-log.txt

## Analyst Notes

- Confirm whether the source IP belongs to the Kali lab VM.
- If this was expected testing, document as lab validation.
- If unexpected, review network logs, open ports, and endpoint activity.

## Closure Recommendation

Close as lab validation if the source IP was the approved Kali test machine. Escalate if scan activity came from an unknown source.
"@

$reportPath = Join-Path $casePath "incident-report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "Recon playbook complete." -ForegroundColor Green
Write-Host "Case folder: $casePath"
Write-Host "Report: $reportPath"
