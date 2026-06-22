# Wazuh SOAR-Lite Lab Report

## Lab Name

Wazuh SOAR-Lite PowerShell Playbook Automation Lab

## Objective

Demonstrate how Wazuh alerts can be connected to repeatable PowerShell incident response playbooks.

## Environment

| Component | System |
|---|---|
| SIEM | Wazuh |
| Endpoint | Windows lab VM |
| Attack/Test VM | Kali Linux |
| Automation | PowerShell |
| Test Scope | Lab only |

## Playbooks Built

| Playbook | Purpose |
|---|---|
| DLP / Sensitive File | Triage and quarantine sensitive lab files |
| YARA Malware Triage | Collect hash and quarantine suspicious test file |
| PowerShell Triage | Collect recent PowerShell activity |
| Recon / Nmap | Document scan source and optionally block IP |

## Evidence Collected

- Wazuh alert screenshot
- Rule ID screenshot
- PowerShell output screenshot
- Case folder screenshot
- Generated incident report
- Quarantine folder screenshot

## What Worked

Write what worked here.

## What Failed or Needed Fixing

Write what broke, what you changed, and how you fixed it.

## Lessons Learned

Write what this taught you about detection, response, documentation, and control validation.

## GRC / Audit Connection

This lab demonstrates repeatable incident response procedures, evidence collection, and control validation for security monitoring alerts.
