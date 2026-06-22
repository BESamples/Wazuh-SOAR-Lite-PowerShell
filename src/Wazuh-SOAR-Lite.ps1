<#
.SYNOPSIS
    Main menu for the Wazuh SOAR-Lite PowerShell Playbook Lab.

.DESCRIPTION
    This script launches lab-safe PowerShell playbooks for DLP, YARA,
    suspicious PowerShell activity, and recon/Nmap-style activity.

.NOTES
    Run from the src folder:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\Wazuh-SOAR-Lite.ps1
#>

[CmdletBinding()]
param(
    [string]$RootPath = "C:\Wazuh-SOAR"
)

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptRoot
$PlaybookRoot = Join-Path $RepoRoot "playbooks"
$ToolRoot = Join-Path $RepoRoot "tools"

function Initialize-SOARFolders {
    param([string]$RootPath)

    New-Item -Path $RootPath -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $RootPath "Cases") -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $RootPath "Quarantine") -ItemType Directory -Force | Out-Null
}

function Show-Header {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " WAZUH SOAR-LITE POWERSHELL PLAYBOOK LAB" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Root Path: $RootPath"
    Write-Host "Cases:     $(Join-Path $RootPath 'Cases')"
    Write-Host "Quarantine:$(Join-Path $RootPath 'Quarantine')"
    Write-Host ""
}

function Invoke-PlaybookFile {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    if (-not (Test-Path $FilePath)) {
        Write-Host "Playbook not found: $FilePath" -ForegroundColor Red
        return
    }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $FilePath @Arguments
}

function Pause-Menu {
    Write-Host ""
    Read-Host "Press Enter to return to the menu"
}

Initialize-SOARFolders -RootPath $RootPath

while ($true) {
    Show-Header
    Write-Host "1. Run DLP / Sensitive File Playbook"
    Write-Host "2. Run YARA Malware Triage Playbook"
    Write-Host "3. Run Suspicious PowerShell Triage Playbook"
    Write-Host "4. Run Recon / Nmap Playbook"
    Write-Host "5. Open Cases Folder"
    Write-Host "6. Create Lab Test Files"
    Write-Host "7. Open Quarantine Folder"
    Write-Host "8. Exit"
    Write-Host ""

    $choice = Read-Host "Choose an option"

    switch ($choice) {
        "1" {
            $filePath = Read-Host "Sensitive file path [default: C:\SensitiveData\Scan\sample_pii.txt]"
            if ([string]::IsNullOrWhiteSpace($filePath)) { $filePath = "C:\SensitiveData\Scan\sample_pii.txt" }

            $ruleId = Read-Host "Wazuh Rule ID [default: 100103]"
            if ([string]::IsNullOrWhiteSpace($ruleId)) { $ruleId = "100103" }

            Invoke-PlaybookFile `
                -FilePath (Join-Path $PlaybookRoot "Invoke-DLPPlaybook.ps1") `
                -Arguments @("-FilePath", $filePath, "-RuleId", $ruleId, "-RootPath", $RootPath)
            Pause-Menu
        }

        "2" {
            $filePath = Read-Host "YARA matched file path [default: C:\Wazuh-Test\evil.txt]"
            if ([string]::IsNullOrWhiteSpace($filePath)) { $filePath = "C:\Wazuh-Test\evil.txt" }

            $ruleId = Read-Host "Wazuh Rule ID [default: 100302]"
            if ([string]::IsNullOrWhiteSpace($ruleId)) { $ruleId = "100302" }

            Invoke-PlaybookFile `
                -FilePath (Join-Path $PlaybookRoot "Invoke-YARAPlaybook.ps1") `
                -Arguments @("-FilePath", $filePath, "-RuleId", $ruleId, "-RootPath", $RootPath)
            Pause-Menu
        }

        "3" {
            $ruleId = Read-Host "Wazuh Rule ID [default: 100102]"
            if ([string]::IsNullOrWhiteSpace($ruleId)) { $ruleId = "100102" }

            Invoke-PlaybookFile `
                -FilePath (Join-Path $PlaybookRoot "Invoke-PowerShellTriagePlaybook.ps1") `
                -Arguments @("-RuleId", $ruleId, "-RootPath", $RootPath)
            Pause-Menu
        }

        "4" {
            $sourceIp = Read-Host "Source IP from alert [default: 192.168.56.50]"
            if ([string]::IsNullOrWhiteSpace($sourceIp)) { $sourceIp = "192.168.56.50" }

            $ruleId = Read-Host "Wazuh Rule ID [default: 100200]"
            if ([string]::IsNullOrWhiteSpace($ruleId)) { $ruleId = "100200" }

            $blockAnswer = Read-Host "Create lab firewall block? Type YES to block, anything else to document only"

            if ($blockAnswer -eq "YES") {
                Invoke-PlaybookFile `
                    -FilePath (Join-Path $PlaybookRoot "Invoke-ReconPlaybook.ps1") `
                    -Arguments @("-SourceIp", $sourceIp, "-RuleId", $ruleId, "-RootPath", $RootPath, "-BlockIp")
            }
            else {
                Invoke-PlaybookFile `
                    -FilePath (Join-Path $PlaybookRoot "Invoke-ReconPlaybook.ps1") `
                    -Arguments @("-SourceIp", $sourceIp, "-RuleId", $ruleId, "-RootPath", $RootPath)
            }
            Pause-Menu
        }

        "5" {
            Start-Process explorer.exe (Join-Path $RootPath "Cases")
            Pause-Menu
        }

        "6" {
            Invoke-PlaybookFile -FilePath (Join-Path $ToolRoot "New-LabTestFiles.ps1") -Arguments @()
            Pause-Menu
        }

        "7" {
            Start-Process explorer.exe (Join-Path $RootPath "Quarantine")
            Pause-Menu
        }

        "8" {
            Write-Host "Exiting Wazuh SOAR-Lite." -ForegroundColor Yellow
            break
        }

        default {
            Write-Host "Invalid option." -ForegroundColor Red
            Pause-Menu
        }
    }
}
