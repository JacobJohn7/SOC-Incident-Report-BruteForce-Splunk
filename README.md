# Windows Active Directory Brute Force Investigation & SIEM Analytics

---

## Project Overview

This repository contains SIEM log ingestion setups, custom Search Processing Language (SPL) queries, correlation searches, and threat detection rules created during a hands-on SOC investigation of Windows Active Directory brute-force authentication attacks.

The lab simulates dictionary-based authentication attacks against SMB and Remote Desktop Services (RDP) on a target Active Directory Domain Controller (`WIN-DC01`), ingesting raw Security Event Logs into **Splunk Enterprise** via Universal Forwarders.

---

## Infrastructure & Ingestion Setup

### Universal Forwarder Configuration (`inputs.conf`)

Configured on `WIN-DC01` (`192.168.56.106`) to forward Windows Security logs to Splunk:

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1
checkpointInterval = 5
render_xml = false
```

### Attack Simulation Execution

Launched dictionary attacks from Kali (`192.168.56.105`) targeting administrative accounts over SMB:

```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt 192.168.56.106 smb -t 4
```

---

## Splunk SPL Analytics & Investigation Queries

### 1. High-Volume Failed Logon Breakdown (`EventCode 4625`)

Groups authentication failures by target user, origin IP, and NTLM/Kerberos substatus codes:

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625
| stats count by TargetUserName, IpAddress, SubStatus
| sort - count
```

**Output Telemetry:**
```text
TargetUserName   IpAddress       Count  SubStatus     Meaning
administrator    192.168.56.105  87     0xc000006a    User exists, invalid password
admin            192.168.56.105  34     0xc000006a    User exists, invalid password
guest            192.168.56.105  12     0xc0000064    User account does not exist
```

---

### 2. Failure-to-Compromise Correlation Query (`EventCode 4625` -> `4624`)

Tracks whether a high-volume failure sequence culminated in a successful authentication event (`EventCode 4624` with `LogonType 3` Network or `LogonType 10` RDP):

```spl
index=win_logs sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) IpAddress="192.168.56.105"
| eval Action=if(EventCode==4625, "FAILED", "SUCCESS")
| stats count, min(_time) as first_seen, max(_time) as last_seen by TargetUserName, IpAddress, Action, LogonType
| fieldformat first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| fieldformat last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

---

## SIEM Correlation Search & Alert Engineering

Saved as a scheduled Splunk Correlation Rule to generate real-time security alerts when brute-force or password spraying activity crosses baseline thresholds:

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625 IpAddress!="127.0.0.1" IpAddress!="-" TargetUserName!="*$"
| bucket _time span=5m
| stats count, dc(TargetUserName) as unique_users by IpAddress, _time
| where count > 15 OR unique_users > 3
```

### Alert Logic
- **Brute Force Alert:** Triggers if a single source IP generates **> 15 logon failures within 5 minutes**.
- **Password Spray Alert:** Triggers if a single source IP targets **> 3 distinct usernames** within the time window.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Log | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | `WinEventLog:Security` | High count EventCode 4625 (`SubStatus 0xc000006a`) |
| **Credential Access** | Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | `WinEventLog:Security` | Single IP probing multiple `TargetUserName`s |
| **Initial Access** | Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | `WinEventLog:Security` | EventCode 4624 (`LogonType 3` post failure spike) |

---

## Practical SIEM Tuning Gotchas

1. **Filtering Active Directory Machine Account Noise (`*$`)**:
   Domain controllers and computer objects generate automated background authentication events (e.g. `WIN-DC01$`). Filtering `TargetUserName!="*$"` prevents false positive alert triggers.

2. **NTLM `WorkstationName` Field Handling**:
   In NTLM network authentication (`EventCode 4625`), the `WorkstationName` field is often blank or easily spoofed. Reliable IP correlation relies strictly on `IpAddress`.
