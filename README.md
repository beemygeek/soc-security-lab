# SOC Security Lab

Detection engineering and incident response work for a Windows / Microsoft 365 environment — written the way a SOC actually uses it: **detect → triage → contain → document**.

| | |
|---|---|
| 🔎 **Detections** | 5 Sigma rules (portable to any SIEM) + 5 KQL queries for Microsoft Sentinel / Defender XDR |
| 📘 **Playbooks** | Step-by-step response for phishing, compromised accounts, and endpoint malware |
| 🧪 **Home lab** | VirtualBox build with AD, Sysmon, and a SIEM to generate real telemetry and test every rule |
| 📝 **Templates** | Incident report with timeline, IOCs, and ATT&CK mapping |

## MITRE ATT&CK coverage

| Tactic | Technique | Detection | Playbook |
|---|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment | [office_spawning_shell](detections/sigma/office_spawning_shell.yml) | [Phishing](playbooks/phishing-triage.md) |
| Execution | T1059.001 PowerShell · T1027 Obfuscation | [encoded_powershell_command](detections/sigma/encoded_powershell_command.yml) | [Malware](playbooks/malware-endpoint.md) |
| Execution | T1204.002 Malicious File | [rare_process_from_user_folders](detections/kql/rare_process_from_user_folders.kql) | [Malware](playbooks/malware-endpoint.md) |
| Credential Access | T1110.003 Password Spraying | [password_spray (Sigma)](detections/sigma/password_spray_multiple_accounts.yml) · [password_spray_entra (KQL)](detections/kql/password_spray_entra.kql) | [Compromised account](playbooks/compromised-account.md) |
| Credential Access | T1621 MFA Request Generation | [mfa_fatigue](detections/kql/mfa_fatigue.kql) | [Compromised account](playbooks/compromised-account.md) |
| Initial Access / Persistence | T1078.004 Valid Cloud Accounts | [impossible_travel_signins](detections/kql/impossible_travel_signins.kql) | [Compromised account](playbooks/compromised-account.md) |
| Collection | T1114.003 Email Forwarding Rule | [inbox_rule_forwarding](detections/kql/inbox_rule_forwarding.kql) | [Compromised account](playbooks/compromised-account.md) |
| Persistence / Priv-Esc | T1098 Account Manipulation | [new_local_admin](detections/sigma/new_local_admin.yml) | — |
| Defense Evasion | T1070.001 Clear Windows Event Logs | [security_log_cleared](detections/sigma/security_log_cleared.yml) | [Malware](playbooks/malware-endpoint.md) |

## Repo layout

```
detections/
  sigma/        vendor-neutral rules (convert with sigma-cli to Splunk, Sentinel, Elastic…)
  kql/          Microsoft Sentinel / Defender XDR / Entra ID queries
playbooks/      incident response runbooks
homelab/        lab architecture + build guide + attack/detect exercises
templates/      incident report template
```

## Using the Sigma rules

```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p sysmon detections/sigma/encoded_powershell_command.yml
```

Every rule lists its known false positives — tune against a baseline of your own environment before alerting on it.

## Related

- [powershell-it-toolkit](https://github.com/beemygeek/powershell-it-toolkit) — includes `Get-FailedLogonReport.ps1`, a no-SIEM version of the password-spray detection.
