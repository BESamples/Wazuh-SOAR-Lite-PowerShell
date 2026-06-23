<#
.SYNOPSIS
    SOAR-lite folder scan playbook for sensitive data triage.

.DESCRIPTION
    Scans a lab folder for sensitive-looking filenames and content, creates
    a SOAR case folder, writes scan-results.csv, optionally copies matching
    files to quarantine, and generates a Markdown incident report.

.NOTES
    Lab-safe default: this script does not delete or move original files.
    Use -QuarantineMatches to copy matching files to quarantine.
#>

[CmdletBinding()]
param(
    [string]$FolderPath = "C:\SensitiveData\Scan",
    [string]$RuleId = "100103",
    [string]$RootPath = "C:\Wazuh-SOAR",
    [switch]$Recurse,
    [switch]$QuarantineMatches,
    [int]$MaxFiles = 500
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

function Save-HostEvidence {
    param([string]$CasePath)

    $hostInfo = [ordered]@{
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        Domain = $env:USERDOMAIN
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        FolderScanned = $FolderPath
        RecursiveScan = [bool]$Recurse
        MaxFiles = $MaxFiles
    }

    $hostInfo.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" } |
        Out-File -FilePath (Join-Path $CasePath "host-info.txt") -Encoding UTF8
}

function Get-ContentSampleSafe {
    param([System.IO.FileInfo]$File)

    $readableExtensions = @(
        ".txt", ".csv", ".log", ".md", ".json", ".xml", ".html", ".htm",
        ".ps1", ".bat", ".cmd", ".ini", ".conf", ".yml", ".yaml", ".config"
    )

    if ($readableExtensions -notcontains $File.Extension.ToLower()) {
        return ""
    }

    if ($File.Length -gt 2MB) {
        return "File over 2 MB. Content sample skipped."
    }

    try {
        return (Get-Content -Path $File.FullName -TotalCount 80 -ErrorAction Stop | Out-String)
    }
    catch {
        return "Unable to read content sample: $($_.Exception.Message)"
    }
}

function Get-SensitiveFinding {
    param(
        [System.IO.FileInfo]$File,
        [string]$ContentSample
    )

    $combined = "$($File.Name)`n$($File.FullName)`n$ContentSample"
    $types = New-Object System.Collections.Generic.List[string]
    $reasons = New-Object System.Collections.Generic.List[string]

    if ($combined -match '(?i)(ssn|social security|\b\d{3}-\d{2}-\d{4}\b|pii)') {
        $types.Add("PII")
        $reasons.Add("SSN/PII pattern or keyword")
    }

    if ($combined -match '(?i)(credit card|cardholder|pci|\b(?:\d[ -]*?){13,16}\b)') {
        $types.Add("PCI")
        $reasons.Add("Credit card/PCI pattern or keyword")
    }

    if ($combined -match '(?i)(confidential|secret|internal use only|payroll|password|classified)') {
        $types.Add("Confidential")
        $reasons.Add("Confidential keyword")
    }

    if ($types.Count -eq 0) {
        return [pscustomobject]@{
            SensitiveType = "None"
            MatchReason = "No sensitive lab pattern matched"
        }
    }

    return [pscustomobject]@{
        SensitiveType = ($types | Select-Object -Unique) -join ";"
        MatchReason = ($reasons | Select-Object -Unique) -join "; "
    }
}

# Main playbook starts here
New-Item -Path (Join-Path $RootPath "Cases") -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $RootPath "Quarantine") -ItemType Directory -Force | Out-Null

$casePath = New-CaseFolder -CaseType "FolderScan" -RootPath $RootPath
Write-CaseLog -CasePath $casePath -Message "Started folder scan playbook."
Write-CaseLog -CasePath $casePath -Message "Rule ID: $RuleId"
Write-CaseLog -CasePath $casePath -Message "Folder path: $FolderPath"
Write-CaseLog -CasePath $casePath -Message "Recursive scan: $([bool]$Recurse)"
Write-CaseLog -CasePath $casePath -Message "Quarantine matches: $([bool]$QuarantineMatches)"

Save-HostEvidence -CasePath $casePath

$folderExists = Test-Path -Path $FolderPath -PathType Container
$results = New-Object System.Collections.Generic.List[object]
$totalFiles = 0
$matchCount = 0
$quarantineScanFolder = Join-Path (Join-Path $RootPath "Quarantine") ("FolderScan-" + (Get-Date -Format "yyyyMMdd-HHmmss"))

if ($folderExists) {
    if ($Recurse) {
        $files = Get-ChildItem -Path $FolderPath -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First $MaxFiles
    }
    else {
        $files = Get-ChildItem -Path $FolderPath -File -ErrorAction SilentlyContinue | Select-Object -First $MaxFiles
    }

    foreach ($file in $files) {
        $totalFiles++
        $hashValue = "N/A"
        $quarantinePath = "N/A"
        $errorText = ""

        try {
            $sample = Get-ContentSampleSafe -File $file
            $finding = Get-SensitiveFinding -File $file -ContentSample $sample

            if ($finding.SensitiveType -ne "None") {
                $matchCount++
                $hashValue = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash

                if ($QuarantineMatches) {
                    New-Item -Path $quarantineScanFolder -ItemType Directory -Force | Out-Null
                    $safeName = $file.FullName.Replace(":", "").Replace("\", "_").Replace("/", "_")
                    $quarantinePath = Join-Path $quarantineScanFolder $safeName
                    Copy-Item -Path $file.FullName -Destination $quarantinePath -Force -ErrorAction Stop
                }
            }

            $results.Add([pscustomobject]@{
                FileName = $file.Name
                FullName = $file.FullName
                SizeBytes = $file.Length
                LastWriteTime = $file.LastWriteTime
                SensitiveType = $finding.SensitiveType
                MatchReason = $finding.MatchReason
                SHA256 = $hashValue
                QuarantinePath = $quarantinePath
                Error = $errorText
            })
        }
        catch {
            $errorText = $_.Exception.Message
            $results.Add([pscustomobject]@{
                FileName = $file.Name
                FullName = $file.FullName
                SizeBytes = $file.Length
                LastWriteTime = $file.LastWriteTime
                SensitiveType = "Error"
                MatchReason = "Scan error"
                SHA256 = "N/A"
                QuarantinePath = "N/A"
                Error = $errorText
            })
            Write-CaseLog -CasePath $casePath -Message "Error scanning $($file.FullName): $errorText"
        }
    }
}
else {
    Write-CaseLog -CasePath $casePath -Message "Folder not found. Scan could not run."
}

$csvPath = Join-Path $casePath "scan-results.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$matchesCsvPath = Join-Path $casePath "matching-files.csv"
$results | Where-Object { $_.SensitiveType -ne "None" -and $_.SensitiveType -ne "Error" } |
    Export-Csv -Path $matchesCsvPath -NoTypeInformation -Encoding UTF8

Write-CaseLog -CasePath $casePath -Message "Files scanned: $totalFiles"
Write-CaseLog -CasePath $casePath -Message "Matching files: $matchCount"
Write-CaseLog -CasePath $casePath -Message "Scan results: $csvPath"

$actionTaken = if ($QuarantineMatches) {
    "Matching files were copied to quarantine. Originals were left in place."
}
else {
    "Document-only scan. No files were copied, moved, or deleted."
}

$report = @"
# Folder Scan Incident Report

## Summary

A Wazuh SOAR-lite folder scan was run against a lab folder to identify sensitive-looking files.

## Case Details

| Field | Value |
|---|---|
| Case Folder | $casePath |
| Rule ID | $RuleId |
| Hostname | $env:COMPUTERNAME |
| User | $env:USERNAME |
| Folder Path | $FolderPath |
| Folder Exists | $folderExists |
| Recursive Scan | $([bool]$Recurse) |
| Max Files | $MaxFiles |
| Files Scanned | $totalFiles |
| Matching Files | $matchCount |
| Quarantine Matches | $([bool]$QuarantineMatches) |
| Quarantine Folder | $quarantineScanFolder |
| Action Taken | $actionTaken |
| Scan Results | $csvPath |
| Matching Files CSV | $matchesCsvPath |
| Timestamp | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |

## Analyst Notes

- Review matching-files.csv first.
- Confirm whether each finding was a lab test file or an unexpected sensitive file.
- Attach Wazuh alert screenshots, dashboard screenshots, and this report to the lab write-up.
- This script only checks lab-style patterns and should not be treated as enterprise DLP.

## Closure Recommendation

Close as lab validation if the findings were created by the test script. Escalate if the files were unexpected or located in a shared folder.
"@

$reportPath = Join-Path $casePath "incident-report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "Folder scan playbook complete." -ForegroundColor Green
Write-Host "Case folder: $casePath"
Write-Host "Files scanned: $totalFiles"
Write-Host "Matching files: $matchCount"
Write-Host "Scan results: $csvPath"
Write-Host "Report: $reportPath"
