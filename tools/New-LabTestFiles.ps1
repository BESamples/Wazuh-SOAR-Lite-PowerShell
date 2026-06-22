<#
.SYNOPSIS
    Creates safe lab test files for the Wazuh SOAR-Lite PowerShell project.

.DESCRIPTION
    This script creates fake test data only. Do not place real PII, PCI, passwords,
    customer data, or company data in this repo or in screenshots.
#>

[CmdletBinding()]
param(
    [string]$SensitivePath = "C:\SensitiveData\Scan",
    [string]$YaraTestPath = "C:\Wazuh-Test"
)

New-Item -Path $SensitivePath -ItemType Directory -Force | Out-Null
New-Item -Path $YaraTestPath -ItemType Directory -Force | Out-Null

$piiFile = Join-Path $SensitivePath "sample_pii.txt"
$pciFile = Join-Path $SensitivePath "sample_pci.txt"
$confidentialFile = Join-Path $SensitivePath "confidential_payroll_notes.txt"
$yaraFile = Join-Path $YaraTestPath "evil.txt"

@"
LAB TEST DATA ONLY
Name: John Doe
Fake SSN: 123-45-6789
Purpose: Trigger a lab DLP/FIM test.
"@ | Out-File -FilePath $piiFile -Encoding UTF8

@"
LAB TEST DATA ONLY
Fake credit card number: 4111 1111 1111 1111
Purpose: Trigger a lab PCI test.
"@ | Out-File -FilePath $pciFile -Encoding UTF8

@"
LAB TEST DATA ONLY
Confidential payroll planning notes.
Purpose: Trigger a lab confidential keyword test.
"@ | Out-File -FilePath $confidentialFile -Encoding UTF8

@"
LAB TEST DATA ONLY
This is not malware.
This file exists to trigger a YARA lab rule if your YARA rule matches this text.
EICAR-STANDARD-ANTIVIRUS-TEST-FILE
"@ | Out-File -FilePath $yaraFile -Encoding UTF8

Write-Host "Lab test files created:" -ForegroundColor Green
Write-Host $piiFile
Write-Host $pciFile
Write-Host $confidentialFile
Write-Host $yaraFile
