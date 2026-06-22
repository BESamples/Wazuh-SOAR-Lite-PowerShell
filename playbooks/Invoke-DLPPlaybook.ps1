<#
.SYNOPSIS
    SOAR-lite DLP / sensitive file incident response playbook.

.DESCRIPTION
    Creates a case folder, collects file evidence, identifies basic sensitive data type,
    copies the file to quarantine, and generates a Markdown report.

.NOTES
    Lab-safe default: this script copies files to quarantine and does not delete originals.
#>

[CmdletBinding()]
param(
    [string]$FilePath = "C:\SensitiveData\Scan\sample_pii.txt",
    [string]$RuleId = "100103",
    [string]$RootPath = "C:\Wazuh-SOAR",
    [switch]$MoveOriginal
)

function New-CaseFolder {
    param(
        [string]$CaseType,
        [string]$RootPath
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeType = $CaseType -replace '[^a-zA-Z0-9_-]', '-'
    $caseId = "CASE-$timestamp-$safeType"
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

function Get-SensitiveType {
    param([string]$Path)

    $name = Split-Path $Path -Leaf
    $contentSample = ""

    if (Test-Path $Path) {
        try {
            $contentSample = Get-Content -Path $Path -TotalCount 50 -ErrorAction Stop | Out-String
        }
        catch {
            $contentSample = "Unable to read file content sample: $($_.Exception.Message)"
        }
    }

    $combined = "$name `n $contentSample"

    if ($combined -match '(?i)(ssn|social security|\b\d{3}-\d{2}-\d{4}\b|pii)') {
        return "PII"
    }
    elseif ($combined -match '(?i)(credit card|cardholder|pci|\b(?:\d[ -]*?){13,16}\b)') {
        return "PCI"
    }
    elseif ($combined -match '(?i)(confidential|secret|internal use only|payroll|password)') {
        return "Confidential"
    }
    else {
        return "Unknown"
    }
}

function Save-HostEvidence {
    param([string]$CasePath)

    $hostInfo = [ordered]@{
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        Domain = $env:USERDOMAIN
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }

    $hostInfo.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" } |
        Out-File -FilePath (Join-Path $CasePath "host-info.txt") -Encoding UTF8
}

# Main playbook starts here
New-Item -Path (Join-Path $RootPath "Cases") -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $RootPath "Quarantine") -ItemType Directory -Force | Out-Null

$casePath = New-CaseFolder -CaseType "DLP" -RootPath $RootPath
Write-CaseLog -CasePath $casePath -Message "Started DLP / Sensitive File playbook."
Write-CaseLog -CasePath $casePath -Message "Rule ID: $RuleId"
Write-CaseLog -CasePath $casePath -Message "File path: $FilePath"

Save-HostEvidence -CasePath $casePath

$fileExists = Test-Path $FilePath
$sensitiveType = Get-SensitiveType -Path $FilePath
$hashValue = "N/A"
$quarantinePath = "N/A"
$actionTaken = "No file action taken. File was not found."

if ($fileExists) {
    try {
        $hashValue = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $fileName = Split-Path $FilePath -Leaf
        $quarantineFolder = Join-Path $RootPath "Quarantine"
        $quarantineName = "{0}-{1}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), $fileName
        $quarantinePath = Join-Path $quarantineFolder $quarantineName

        if ($MoveOriginal) {
            Move-Item -Path $FilePath -Destination $quarantinePath -Force
            $actionTaken = "Moved original file to quarantine."
        }
        else {
            Copy-Item -Path $FilePath -Destination $quarantinePath -Force
            $actionTaken = "Copied file to quarantine. Original file left in place."
        }

        Write-CaseLog -CasePath $casePath -Message "Sensitive type guess: $sensitiveType"
        Write-CaseLog -CasePath $casePath -Message "SHA256: $hashValue"
        Write-CaseLog -CasePath $casePath -Message "Quarantine path: $quarantinePath"
        Write-CaseLog -CasePath $casePath -Message "Action taken: $actionTaken"
    }
    catch {
        $actionTaken = "Error during file handling: $($_.Exception.Message)"
        Write-CaseLog -CasePath $casePath -Message $actionTaken
    }
}
else {
    Write-CaseLog -CasePath $casePath -Message "File not found. Evidence collection limited."
}

$report = @"
# DLP / Sensitive File Incident Report

## Summary

A Wazuh DLP/FIM-style alert was reviewed using the PowerShell SOAR-lite DLP playbook.

## Case Details

| Field | Value |
|---|---|
| Case Folder | $casePath |
| Rule ID | $RuleId |
| Hostname | $env:COMPUTERNAME |
| User | $env:USERNAME |
| File Path | $FilePath |
| File Exists | $fileExists |
| Sensitive Type Guess | $sensitiveType |
| SHA256 | $hashValue |
| Quarantine Path | $quarantinePath |
| Action Taken | $actionTaken |
| Timestamp | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |

## Analyst Notes

- Confirm whether this was a lab test or expected business file.
- If this was production, validate data owner, permissions, and exposure.
- If needed, attach Wazuh alert screenshot and dashboard screenshot.

## Closure Recommendation

Close as lab validation if this was generated by the test script. Escalate if this occurred unexpectedly on a production host.
"@

$reportPath = Join-Path $casePath "incident-report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "DLP playbook complete." -ForegroundColor Green
Write-Host "Case folder: $casePath"
Write-Host "Report: $reportPath"
