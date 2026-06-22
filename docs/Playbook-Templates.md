# SOAR-Lite Playbook Templates

## Playbook Format

Each playbook should answer the same basic questions:

1. What triggered the alert?
2. What evidence should be collected?
3. What containment action is safe?
4. What recovery or cleanup is needed?
5. What should be documented before closing?

---

## DLP / Sensitive File Playbook

**Trigger:** Wazuh FIM or DLP-style alert for a file that may contain PII, PCI, passwords, payroll data, or confidential keywords.

**Triage Steps:**

- Confirm file path.
- Confirm file name.
- Check file hash.
- Identify whether the finding looks like PII, PCI, Confidential, or Unknown.
- Verify whether this was a lab test file.

**Containment Steps:**

- Copy file to quarantine folder.
- Leave original in place unless this is a safe lab-only test.
- Document the original location.

**Evidence:**

- Wazuh rule ID
- File path
- File hash
- Timestamp
- Hostname
- User context if available

---

## YARA Malware Triage Playbook

**Trigger:** Wazuh alert related to a YARA signature match.

**Triage Steps:**

- Confirm matched file path.
- Collect SHA256 hash.
- Record hostname and timestamp.
- Check whether the file is part of a lab simulation.

**Containment Steps:**

- Copy file to quarantine folder.
- Do not delete unless this is a confirmed lab test and deletion was approved.

**Evidence:**

- Rule ID
- Matched file path
- File hash
- Quarantine path
- Alert timestamp

---

## Suspicious PowerShell Triage Playbook

**Trigger:** Wazuh alert for PowerShell activity.

**Triage Steps:**

- Review recent PowerShell processes.
- Review PowerShell operational log events.
- Check for encoded commands, download commands, suspicious paths, or unusual parent processes.

**Containment Steps:**

- Document activity first.
- Escalate if commands suggest credential theft, persistence, or malicious download behavior.

**Evidence:**

- Running PowerShell processes
- Recent PowerShell log entries
- Current user
- Hostname
- Timestamp

---

## Recon / Nmap Playbook

**Trigger:** Wazuh alert showing scan-like behavior from a Kali or attacker test VM.

**Triage Steps:**

- Identify source IP.
- Identify destination host.
- Confirm whether it was expected lab testing.
- Record open ports if known.

**Containment Steps:**

- Optional lab-only firewall block.
- Document the block rule name.

**Evidence:**

- Source IP
- Hostname
- Rule ID
- Firewall action taken
- Timestamp
