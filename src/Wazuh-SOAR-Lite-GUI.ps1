<#
.SYNOPSIS
    Windows Forms GUI for the Wazuh SOAR-Lite PowerShell Playbook Lab.

.DESCRIPTION
    This GUI launches lab-safe PowerShell playbooks for DLP, YARA,
    suspicious PowerShell activity, and recon/Nmap-style activity.

.NOTES
    Save this file in the src folder:
    C:\Wazuh-SOAR-Lite-PowerShell\src\Wazuh-SOAR-Lite-GUI.ps1

    Run with:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\Wazuh-SOAR-Lite-GUI.ps1
#>

[CmdletBinding()]
param(
    [string]$RootPath = "C:\Wazuh-SOAR"
)

# ============================================================
# SECTION 1 - LOAD WINDOWS FORMS
# ============================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# SECTION 2 - PATH SETUP
# ============================================================

$ScriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
}
else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

$RepoRoot = Split-Path -Parent $ScriptRoot
$PlaybookRoot = Join-Path $RepoRoot "playbooks"
$ToolRoot = Join-Path $RepoRoot "tools"

# ============================================================
# SECTION 3 - FOLDER SETUP
# ============================================================

function Initialize-SOARFolders {
    param([string]$Path)

    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $Path "Cases") -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $Path "Quarantine") -ItemType Directory -Force | Out-Null
}

# ============================================================
# SECTION 4 - OUTPUT BOX HELPER
# ============================================================

function Write-OutputBox {
    param([string]$Message)

    $timestamp = Get-Date -Format "HH:mm:ss"
    $txtOutput.AppendText("[$timestamp] $Message`r`n")
    $txtOutput.SelectionStart = $txtOutput.Text.Length
    $txtOutput.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================
# SECTION 5 - PLAYBOOK RUNNER
# ============================================================

function Invoke-PlaybookFile {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    if (-not (Test-Path $FilePath)) {
        Write-OutputBox "ERROR: Playbook not found: $FilePath"
        Write-OutputBox "Repo root detected as: $RepoRoot"
        return
    }

    Write-OutputBox "Running: $FilePath"

    try {
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $FilePath @Arguments 2>&1

        if ($output) {
            foreach ($line in $output) {
                Write-OutputBox ($line | Out-String).Trim()
            }
        }
        else {
            Write-OutputBox "Playbook finished with no output."
        }
    }
    catch {
        Write-OutputBox "ERROR: $($_.Exception.Message)"
    }

    Write-OutputBox "Done."
}

# ============================================================
# SECTION 6 - BUTTON ACTIONS
# ============================================================

function Start-DLPPlaybook {
    $currentRoot = $txtRootPath.Text.Trim()
    Initialize-SOARFolders -Path $currentRoot

    $filePath = $txtDlpFile.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($filePath)) {
        $filePath = "C:\SensitiveData\Scan\sample_pii.txt"
    }

    $ruleId = $txtDlpRule.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($ruleId)) {
        $ruleId = "100103"
    }

    Invoke-PlaybookFile `
        -FilePath (Join-Path $PlaybookRoot "Invoke-DLPPlaybook.ps1") `
        -Arguments @("-FilePath", $filePath, "-RuleId", $ruleId, "-RootPath", $currentRoot)
}

function Start-YARAPlaybook {
    $currentRoot = $txtRootPath.Text.Trim()
    Initialize-SOARFolders -Path $currentRoot

    $filePath = $txtYaraFile.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($filePath)) {
        $filePath = "C:\Wazuh-Test\evil.txt"
    }

    $ruleId = $txtYaraRule.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($ruleId)) {
        $ruleId = "100302"
    }

    Invoke-PlaybookFile `
        -FilePath (Join-Path $PlaybookRoot "Invoke-YARAPlaybook.ps1") `
        -Arguments @("-FilePath", $filePath, "-RuleId", $ruleId, "-RootPath", $currentRoot)
}

function Start-PowerShellTriagePlaybook {
    $currentRoot = $txtRootPath.Text.Trim()
    Initialize-SOARFolders -Path $currentRoot

    $ruleId = $txtPsRule.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($ruleId)) {
        $ruleId = "100102"
    }

    Invoke-PlaybookFile `
        -FilePath (Join-Path $PlaybookRoot "Invoke-PowerShellTriagePlaybook.ps1") `
        -Arguments @("-RuleId", $ruleId, "-RootPath", $currentRoot)
}

function Start-ReconPlaybook {
    $currentRoot = $txtRootPath.Text.Trim()
    Initialize-SOARFolders -Path $currentRoot

    $sourceIp = $txtSourceIp.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($sourceIp)) {
        $sourceIp = "192.168.56.50"
    }

    $ruleId = $txtReconRule.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($ruleId)) {
        $ruleId = "100200"
    }

    if ($chkBlockIp.Checked) {
        Invoke-PlaybookFile `
            -FilePath (Join-Path $PlaybookRoot "Invoke-ReconPlaybook.ps1") `
            -Arguments @("-SourceIp", $sourceIp, "-RuleId", $ruleId, "-RootPath", $currentRoot, "-BlockIp")
    }
    else {
        Invoke-PlaybookFile `
            -FilePath (Join-Path $PlaybookRoot "Invoke-ReconPlaybook.ps1") `
            -Arguments @("-SourceIp", $sourceIp, "-RuleId", $ruleId, "-RootPath", $currentRoot)
    }
}

function New-LabFiles {
    Invoke-PlaybookFile -FilePath (Join-Path $ToolRoot "New-LabTestFiles.ps1") -Arguments @()
}

function Open-CasesFolder {
    $currentRoot = $txtRootPath.Text.Trim()
    Initialize-SOARFolders -Path $currentRoot
    Start-Process explorer.exe (Join-Path $currentRoot "Cases")
}

function Open-QuarantineFolder {
    $currentRoot = $txtRootPath.Text.Trim()
    Initialize-SOARFolders -Path $currentRoot
    Start-Process explorer.exe (Join-Path $currentRoot "Quarantine")
}

function Test-RepoPaths {
    Write-OutputBox "Checking repo paths..."
    Write-OutputBox "Script root: $ScriptRoot"
    Write-OutputBox "Repo root:   $RepoRoot"
    Write-OutputBox "Playbooks:   $PlaybookRoot"
    Write-OutputBox "Tools:       $ToolRoot"

    $requiredFiles = @(
        (Join-Path $PlaybookRoot "Invoke-DLPPlaybook.ps1"),
        (Join-Path $PlaybookRoot "Invoke-YARAPlaybook.ps1"),
        (Join-Path $PlaybookRoot "Invoke-PowerShellTriagePlaybook.ps1"),
        (Join-Path $PlaybookRoot "Invoke-ReconPlaybook.ps1"),
        (Join-Path $ToolRoot "New-LabTestFiles.ps1")
    )

    foreach ($file in $requiredFiles) {
        if (Test-Path $file) {
            Write-OutputBox "OK: $file"
        }
        else {
            Write-OutputBox "MISSING: $file"
        }
    }
}

# ============================================================
# SECTION 7 - MAIN FORM
# ============================================================

Initialize-SOARFolders -Path $RootPath

$form = New-Object System.Windows.Forms.Form
$form.Text = "Wazuh SOAR-Lite PowerShell Playbook Lab"
$form.Size = New-Object System.Drawing.Size(920, 760)
$form.StartPosition = "CenterScreen"
$form.TopMost = $false

$fontNormal = New-Object System.Drawing.Font("Segoe UI", 9)
$fontHeader = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$form.Font = $fontNormal

# ============================================================
# SECTION 8 - HEADER LABELS
# ============================================================

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Wazuh SOAR-Lite PowerShell Playbook Lab"
$lblTitle.Font = $fontHeader
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(15, 15)
$form.Controls.Add($lblTitle)

$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text = "Lab-safe playbooks for DLP, YARA, suspicious PowerShell, and recon/Nmap alerts."
$lblSubtitle.AutoSize = $true
$lblSubtitle.Location = New-Object System.Drawing.Point(17, 45)
$form.Controls.Add($lblSubtitle)

$lblRoot = New-Object System.Windows.Forms.Label
$lblRoot.Text = "SOAR Root Path:"
$lblRoot.AutoSize = $true
$lblRoot.Location = New-Object System.Drawing.Point(18, 78)
$form.Controls.Add($lblRoot)

$txtRootPath = New-Object System.Windows.Forms.TextBox
$txtRootPath.Text = $RootPath
$txtRootPath.Location = New-Object System.Drawing.Point(125, 75)
$txtRootPath.Size = New-Object System.Drawing.Size(500, 24)
$form.Controls.Add($txtRootPath)

$btnCheckPaths = New-Object System.Windows.Forms.Button
$btnCheckPaths.Text = "Check Repo Paths"
$btnCheckPaths.Location = New-Object System.Drawing.Point(640, 73)
$btnCheckPaths.Size = New-Object System.Drawing.Size(130, 28)
$btnCheckPaths.Add_Click({ Test-RepoPaths })
$form.Controls.Add($btnCheckPaths)

# ============================================================
# SECTION 9 - DLP GROUP
# ============================================================

$grpDlp = New-Object System.Windows.Forms.GroupBox
$grpDlp.Text = "DLP / Sensitive File Playbook"
$grpDlp.Location = New-Object System.Drawing.Point(20, 115)
$grpDlp.Size = New-Object System.Drawing.Size(420, 140)
$form.Controls.Add($grpDlp)

$lblDlpFile = New-Object System.Windows.Forms.Label
$lblDlpFile.Text = "File Path:"
$lblDlpFile.AutoSize = $true
$lblDlpFile.Location = New-Object System.Drawing.Point(15, 30)
$grpDlp.Controls.Add($lblDlpFile)

$txtDlpFile = New-Object System.Windows.Forms.TextBox
$txtDlpFile.Text = "C:\SensitiveData\Scan\sample_pii.txt"
$txtDlpFile.Location = New-Object System.Drawing.Point(80, 27)
$txtDlpFile.Size = New-Object System.Drawing.Size(315, 24)
$grpDlp.Controls.Add($txtDlpFile)

$lblDlpRule = New-Object System.Windows.Forms.Label
$lblDlpRule.Text = "Rule ID:"
$lblDlpRule.AutoSize = $true
$lblDlpRule.Location = New-Object System.Drawing.Point(15, 62)
$grpDlp.Controls.Add($lblDlpRule)

$txtDlpRule = New-Object System.Windows.Forms.TextBox
$txtDlpRule.Text = "100103"
$txtDlpRule.Location = New-Object System.Drawing.Point(80, 59)
$txtDlpRule.Size = New-Object System.Drawing.Size(110, 24)
$grpDlp.Controls.Add($txtDlpRule)

$btnDlp = New-Object System.Windows.Forms.Button
$btnDlp.Text = "Run DLP Playbook"
$btnDlp.Location = New-Object System.Drawing.Point(80, 95)
$btnDlp.Size = New-Object System.Drawing.Size(150, 30)
$btnDlp.Add_Click({ Start-DLPPlaybook })
$grpDlp.Controls.Add($btnDlp)

# ============================================================
# SECTION 10 - YARA GROUP
# ============================================================

$grpYara = New-Object System.Windows.Forms.GroupBox
$grpYara.Text = "YARA Malware Triage Playbook"
$grpYara.Location = New-Object System.Drawing.Point(460, 115)
$grpYara.Size = New-Object System.Drawing.Size(420, 140)
$form.Controls.Add($grpYara)

$lblYaraFile = New-Object System.Windows.Forms.Label
$lblYaraFile.Text = "File Path:"
$lblYaraFile.AutoSize = $true
$lblYaraFile.Location = New-Object System.Drawing.Point(15, 30)
$grpYara.Controls.Add($lblYaraFile)

$txtYaraFile = New-Object System.Windows.Forms.TextBox
$txtYaraFile.Text = "C:\Wazuh-Test\evil.txt"
$txtYaraFile.Location = New-Object System.Drawing.Point(80, 27)
$txtYaraFile.Size = New-Object System.Drawing.Size(315, 24)
$grpYara.Controls.Add($txtYaraFile)

$lblYaraRule = New-Object System.Windows.Forms.Label
$lblYaraRule.Text = "Rule ID:"
$lblYaraRule.AutoSize = $true
$lblYaraRule.Location = New-Object System.Drawing.Point(15, 62)
$grpYara.Controls.Add($lblYaraRule)

$txtYaraRule = New-Object System.Windows.Forms.TextBox
$txtYaraRule.Text = "100302"
$txtYaraRule.Location = New-Object System.Drawing.Point(80, 59)
$txtYaraRule.Size = New-Object System.Drawing.Size(110, 24)
$grpYara.Controls.Add($txtYaraRule)

$btnYara = New-Object System.Windows.Forms.Button
$btnYara.Text = "Run YARA Playbook"
$btnYara.Location = New-Object System.Drawing.Point(80, 95)
$btnYara.Size = New-Object System.Drawing.Size(150, 30)
$btnYara.Add_Click({ Start-YARAPlaybook })
$grpYara.Controls.Add($btnYara)

# ============================================================
# SECTION 11 - POWERSHELL TRIAGE GROUP
# ============================================================

$grpPs = New-Object System.Windows.Forms.GroupBox
$grpPs.Text = "Suspicious PowerShell Triage Playbook"
$grpPs.Location = New-Object System.Drawing.Point(20, 270)
$grpPs.Size = New-Object System.Drawing.Size(420, 120)
$form.Controls.Add($grpPs)

$lblPsRule = New-Object System.Windows.Forms.Label
$lblPsRule.Text = "Rule ID:"
$lblPsRule.AutoSize = $true
$lblPsRule.Location = New-Object System.Drawing.Point(15, 32)
$grpPs.Controls.Add($lblPsRule)

$txtPsRule = New-Object System.Windows.Forms.TextBox
$txtPsRule.Text = "100102"
$txtPsRule.Location = New-Object System.Drawing.Point(80, 29)
$txtPsRule.Size = New-Object System.Drawing.Size(110, 24)
$grpPs.Controls.Add($txtPsRule)

$btnPs = New-Object System.Windows.Forms.Button
$btnPs.Text = "Run PowerShell Triage"
$btnPs.Location = New-Object System.Drawing.Point(80, 68)
$btnPs.Size = New-Object System.Drawing.Size(170, 30)
$btnPs.Add_Click({ Start-PowerShellTriagePlaybook })
$grpPs.Controls.Add($btnPs)

# ============================================================
# SECTION 12 - RECON GROUP
# ============================================================

$grpRecon = New-Object System.Windows.Forms.GroupBox
$grpRecon.Text = "Recon / Nmap Playbook"
$grpRecon.Location = New-Object System.Drawing.Point(460, 270)
$grpRecon.Size = New-Object System.Drawing.Size(420, 120)
$form.Controls.Add($grpRecon)

$lblSourceIp = New-Object System.Windows.Forms.Label
$lblSourceIp.Text = "Source IP:"
$lblSourceIp.AutoSize = $true
$lblSourceIp.Location = New-Object System.Drawing.Point(15, 30)
$grpRecon.Controls.Add($lblSourceIp)

$txtSourceIp = New-Object System.Windows.Forms.TextBox
$txtSourceIp.Text = "192.168.56.50"
$txtSourceIp.Location = New-Object System.Drawing.Point(90, 27)
$txtSourceIp.Size = New-Object System.Drawing.Size(130, 24)
$grpRecon.Controls.Add($txtSourceIp)

$lblReconRule = New-Object System.Windows.Forms.Label
$lblReconRule.Text = "Rule ID:"
$lblReconRule.AutoSize = $true
$lblReconRule.Location = New-Object System.Drawing.Point(235, 30)
$grpRecon.Controls.Add($lblReconRule)

$txtReconRule = New-Object System.Windows.Forms.TextBox
$txtReconRule.Text = "100200"
$txtReconRule.Location = New-Object System.Drawing.Point(290, 27)
$txtReconRule.Size = New-Object System.Drawing.Size(90, 24)
$grpRecon.Controls.Add($txtReconRule)

$chkBlockIp = New-Object System.Windows.Forms.CheckBox
$chkBlockIp.Text = "Create lab firewall block"
$chkBlockIp.AutoSize = $true
$chkBlockIp.Location = New-Object System.Drawing.Point(90, 58)
$grpRecon.Controls.Add($chkBlockIp)

$btnRecon = New-Object System.Windows.Forms.Button
$btnRecon.Text = "Run Recon Playbook"
$btnRecon.Location = New-Object System.Drawing.Point(90, 83)
$btnRecon.Size = New-Object System.Drawing.Size(160, 28)
$btnRecon.Add_Click({ Start-ReconPlaybook })
$grpRecon.Controls.Add($btnRecon)

# ============================================================
# SECTION 13 - UTILITY BUTTONS
# ============================================================

$btnCreateFiles = New-Object System.Windows.Forms.Button
$btnCreateFiles.Text = "Create Lab Test Files"
$btnCreateFiles.Location = New-Object System.Drawing.Point(20, 405)
$btnCreateFiles.Size = New-Object System.Drawing.Size(160, 35)
$btnCreateFiles.Add_Click({ New-LabFiles })
$form.Controls.Add($btnCreateFiles)

$btnCases = New-Object System.Windows.Forms.Button
$btnCases.Text = "Open Cases Folder"
$btnCases.Location = New-Object System.Drawing.Point(190, 405)
$btnCases.Size = New-Object System.Drawing.Size(150, 35)
$btnCases.Add_Click({ Open-CasesFolder })
$form.Controls.Add($btnCases)

$btnQuarantine = New-Object System.Windows.Forms.Button
$btnQuarantine.Text = "Open Quarantine Folder"
$btnQuarantine.Location = New-Object System.Drawing.Point(350, 405)
$btnQuarantine.Size = New-Object System.Drawing.Size(170, 35)
$btnQuarantine.Add_Click({ Open-QuarantineFolder })
$form.Controls.Add($btnQuarantine)

$btnClearOutput = New-Object System.Windows.Forms.Button
$btnClearOutput.Text = "Clear Output"
$btnClearOutput.Location = New-Object System.Drawing.Point(530, 405)
$btnClearOutput.Size = New-Object System.Drawing.Size(120, 35)
$btnClearOutput.Add_Click({ $txtOutput.Clear() })
$form.Controls.Add($btnClearOutput)

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Exit"
$btnExit.Location = New-Object System.Drawing.Point(760, 405)
$btnExit.Size = New-Object System.Drawing.Size(120, 35)
$btnExit.Add_Click({ $form.Close() })
$form.Controls.Add($btnExit)

# ============================================================
# SECTION 14 - OUTPUT BOX
# ============================================================

$lblOutput = New-Object System.Windows.Forms.Label
$lblOutput.Text = "Output:"
$lblOutput.AutoSize = $true
$lblOutput.Location = New-Object System.Drawing.Point(20, 455)
$form.Controls.Add($lblOutput)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Location = New-Object System.Drawing.Point(20, 480)
$txtOutput.Size = New-Object System.Drawing.Size(860, 225)
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($txtOutput)

# ============================================================
# SECTION 15 - STARTUP MESSAGE
# ============================================================

$form.Add_Shown({
    Write-OutputBox "Wazuh SOAR-Lite GUI started."
    Write-OutputBox "Click 'Check Repo Paths' first if any button fails."
    Write-OutputBox "Recommended first step: Create Lab Test Files."
})

[void]$form.ShowDialog()
