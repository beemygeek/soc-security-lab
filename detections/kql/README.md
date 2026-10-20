# KQL hunting & detection queries

Queries for **Microsoft Sentinel** and **Microsoft Defender XDR / Entra ID** log tables.
Each file states the table it targets, the ATT&CK technique, and how to tune it.

| File | Table(s) | Technique |
|---|---|---|
| [`impossible_travel_signins.kql`](impossible_travel_signins.kql) | `SigninLogs` | T1078.004 Valid Accounts: Cloud |
| [`mfa_fatigue.kql`](mfa_fatigue.kql) | `SigninLogs` | T1621 MFA Request Generation |
| [`inbox_rule_forwarding.kql`](inbox_rule_forwarding.kql) | `OfficeActivity` | T1114.003 Email Forwarding Rule |
| [`password_spray_entra.kql`](password_spray_entra.kql) | `SigninLogs` | T1110.003 Password Spraying |
| [`rare_process_from_user_folders.kql`](rare_process_from_user_folders.kql) | `DeviceProcessEvents` | T1204.002 Malicious File |
