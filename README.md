# Wazuh SOAR-Lite PowerShell Playbook Lab

This is a lab-safe PowerShell SOAR-lite project designed to connect Wazuh alerts to repeatable incident response playbooks.

The goal is not to replace an enterprise SOAR platform. The goal is to demonstrate a practical workflow:

**Detection → Triage → Containment → Evidence Collection → Case Report**

## Project Summary

This lab uses PowerShell scripts to simulate SOAR playbooks for common Wazuh lab alerts:

- Sensitive file / DLP-style finding
- YARA malware-style finding
- Suspicious PowerShell activity
- Reconnaissance / Nmap-style scan activity

Each playbook creates a case folder, collects evidence, writes notes, and generates a Markdown incident report.

## Why This Project Exists

A SIEM alert by itself is not the full story. A SOC analyst also needs to know:

- What triggered the alert?
- What evidence should be collected?
- What containment action is safe?
- What should be documented?
- How should the incident be closed?

This project shows that process using Wazuh and PowerShell.

## Repo Layout

```text
Wazuh-SOAR-Lite-PowerShell/
├── src/
│   └── Wazuh-SOAR-Lite.ps1
├── playbooks/
│   ├── Invoke-DLPPlaybook.ps1
│   ├── Invoke-YARAPlaybook.ps1
│   ├── Invoke-PowerShellTriagePlaybook.ps1
│   └── Invoke-ReconPlaybook.ps1
├── tools/
│   └── New-LabTestFiles.ps1
├── docs/
│   ├── Playbook-Templates.md
│   └── Lab-Report-Template.md
├── samples/
│   └── sample-wazuh-alerts.json
├── .gitignore
├── LICENSE
└── README.md
```

## Requirements

- Windows 10, Windows 11, or Windows Server 2019/2022 lab machine
- PowerShell 5.1 or later
- Administrator PowerShell recommended for firewall-block testing
- Wazuh agent optional for Phase 1 manual testing

## Quick Start

Open PowerShell as Administrator and run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd .\Wazuh-SOAR-Lite-PowerShell\src
.\Wazuh-SOAR-Lite.ps1
```

The main menu lets you run these playbooks:

1. DLP / Sensitive File Playbook
2. YARA Malware Triage Playbook
3. Suspicious PowerShell Triage Playbook
4. Recon / Nmap Playbook
5. Open Cases Folder
6. Create Lab Test Files

## Default Runtime Folders

The scripts use these lab folders by default:

```text
C:\Wazuh-SOAR\Cases
C:\Wazuh-SOAR\Quarantine
C:\SensitiveData\Scan
C:\Wazuh-Test
```

These folders are intentionally ignored by Git so real case files are not accidentally uploaded.

## Safe Defaults

This project is written with safe lab defaults:

- Files are copied to quarantine by default instead of deleted.
- Firewall blocking is optional and must be requested with `-BlockIp`.
- No API keys, company data, user data, or real customer data is included.
- Sample alerts are fake lab examples.

## Example Commands

Run a DLP playbook against a test file:

```powershell
.\playbooks\Invoke-DLPPlaybook.ps1 -FilePath "C:\SensitiveData\Scan\sample_pii.txt" -RuleId "100103"
```

Run a YARA-style playbook:

```powershell
.\playbooks\Invoke-YARAPlaybook.ps1 -FilePath "C:\Wazuh-Test\evil.txt" -RuleId "100302"
```

Run PowerShell triage:

```powershell
.\playbooks\Invoke-PowerShellTriagePlaybook.ps1 -RuleId "100102"
```

Run recon playbook without blocking:

```powershell
.\playbooks\Invoke-ReconPlaybook.ps1 -SourceIp "192.168.56.50" -RuleId "100200"
```

Run recon playbook with a lab firewall block:

```powershell
.\playbooks\Invoke-ReconPlaybook.ps1 -SourceIp "192.168.56.50" -RuleId "100200" -BlockIp
```

## Suggested Wazuh Alert Mapping

| Wazuh Alert Type | Example Rule ID | Playbook |
|---|---:|---|
| Sensitive file created | 100103 | DLP / Sensitive File Playbook |
| PowerShell execution | 100102 | Suspicious PowerShell Triage |
| YARA match | 100302 | YARA Malware Triage |
| Nmap / Kali scan | custom | Recon / Nmap Playbook |

## Screenshots to Add Later

Add screenshots to a future `screenshots/` folder:

- Wazuh alert view
- Rule ID that triggered
- PowerShell playbook output
- Case folder created
- Incident report generated
- Quarantine folder proof

## Resume Bullet Example

Built a PowerShell-based SOAR-lite incident response lab integrated with Wazuh alerts, including playbooks for DLP findings, YARA detections, suspicious PowerShell activity, and network reconnaissance. Automated case folder creation, evidence collection, quarantine actions, and incident report generation.

## Disclaimer

This project is for lab and educational use only. Do not run containment actions such as firewall blocking or file quarantine on production systems without approval.
