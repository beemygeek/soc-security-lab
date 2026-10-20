# Home SOC Lab — Build Guide

A small, free lab that recreates a corporate Windows network so I can generate real attack telemetry, write detections against it, and practice the playbooks in this repo. Runs on a single PC with **Oracle VirtualBox**.

## Architecture

```
                    ┌──────────────────────────────┐
                    │      Host PC (VirtualBox)    │
                    └──────────────┬───────────────┘
                                   │  Internal network "labnet" 10.10.10.0/24
     ┌───────────────┬─────────────┼──────────────┬────────────────┐
     │               │             │              │                │
┌────┴────┐   ┌──────┴─────┐ ┌─────┴──────┐ ┌─────┴──────┐  ┌──────┴──────┐
│ pfSense │   │   DC01     │ │  WS01      │ │  SIEM      │  │  Kali       │
│ gateway │   │ WinSrv2022 │ │  Win 11    │ │ Wazuh or   │  │ attacker    │
│ .1      │   │ AD DS, DNS │ │ domain-    │ │ Splunk Free│  │ (isolated)  │
│ NAT out │   │ .10        │ │ joined .20 │ │ .50        │  │ .66         │
└─────────┘   └────────────┘ └────────────┘ └────────────┘  └─────────────┘
```

| VM | Purpose | Resources |
|---|---|---|
| pfSense | Firewall / gateway, NAT to the internet, segmentation | 1 vCPU, 1 GB |
| DC01 | Windows Server 2022 eval — AD DS, DNS, Group Policy | 2 vCPU, 4 GB |
| WS01 | Windows 11 eval, domain-joined, Sysmon installed | 2 vCPU, 4 GB |
| SIEM | Wazuh (free, includes agent + dashboards) or Splunk Free | 2 vCPU, 6 GB |
| Kali | Attack simulation — **internal network only** | 2 vCPU, 2 GB |

## Build steps

1. **Network** — create a VirtualBox *Internal Network* `labnet`; give pfSense a second NIC on NAT for internet.
2. **Domain controller** — install AD DS, promote to `lab.local`, create OUs (Staff, IT, Disabled Users, Servers) and test users. Populate with the onboarding script from [powershell-it-toolkit](https://github.com/beemygeek/powershell-it-toolkit).
3. **Audit policy** — via GPO enable *Advanced Audit Policy*: Logon/Logoff, Account Logon, Account Management, Process Creation (with command line: `Include command line in process creation events`), PowerShell Script Block Logging.
4. **Sysmon** — install on DC01 and WS01 with a community config (SwiftOnSecurity or Olaf Hartong's sysmon-modular).
5. **SIEM** — deploy Wazuh server; install agents on DC01/WS01; forward Security, Sysmon, and PowerShell/Operational logs.
6. **Snapshot everything** before attacking so the lab can be reset in minutes.

## Exercises (attack → detect → respond)

| # | Simulate | Expected telemetry | Detection in this repo |
|---|---|---|---|
| 1 | Password spray against the DC from Kali | 4625 bursts, one source, many users | [`password_spray_multiple_accounts.yml`](../detections/sigma/password_spray_multiple_accounts.yml) |
| 2 | Encoded PowerShell on WS01 | Sysmon EID 1, 4104 script block | [`encoded_powershell_command.yml`](../detections/sigma/encoded_powershell_command.yml) |
| 3 | Macro doc launching `cmd.exe` | Sysmon EID 1, parent `WINWORD.EXE` | [`office_spawning_shell.yml`](../detections/sigma/office_spawning_shell.yml) |
| 4 | Add a user to Domain Admins | 4728 | [`new_local_admin.yml`](../detections/sigma/new_local_admin.yml) |
| 5 | Clear the Security log | 1102 | [`security_log_cleared.yml`](../detections/sigma/security_log_cleared.yml) |

Atomic Red Team (`Invoke-AtomicTest`) is a safe, scripted way to run most of these.

## Safety

- The attacker VM lives only on the internal network — no bridged adapter.
- Use evaluation licenses and lab-only credentials. Never reuse real passwords.
- Never run attack tooling against systems you don't own.
