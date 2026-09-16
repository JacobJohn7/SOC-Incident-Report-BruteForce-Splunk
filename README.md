# Windows Authentication & Brute Force Analysis in Splunk

**Author:** Jacob John  
**Environment:** Windows Server 2022 (`WIN-DC01`), Kali Linux (`192.168.56.105`), Splunk Enterprise 9.x  

I setup this lab to build and test Splunk correlation searches against real Active Directory authentication logs.

---

### Ingestion Setup (`inputs.conf`)

Configured the Splunk Universal Forwarder on `WIN-DC01` to ingest Windows Security logs:

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1
checkpointInterval = 5
render_xml = false
```

Simulated an SMB/RDP brute force attack from Kali (`192.168.56.105`) using `hydra`:
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt 192.168.56.106 smb -t 4
```

---

### Log Analysis & SPL Queries

#### 1. Grouping Failed Logons (`EventCode 4625`)

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625
| stats count by TargetUserName, IpAddress, SubStatus
| sort - count
```

**Results Breakdown:**
- `administrator` | `192.168.56.105` | 87 attempts | `SubStatus: 0xc000006a` (Bad Password)
- `admin`         | `192.168.56.105` | 34 attempts | `SubStatus: 0xc000006a` (Bad Password)
- `guest`         | `192.168.56.105` | 12 attempts | `SubStatus: 0xc0000064` (User Does Not Exist)

#### 2. Correlating Failures with Successful Login (`EventCode 4624`)

```spl
index=win_logs sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) IpAddress="192.168.56.105"
| eval Action=if(EventCode==4625, "FAILED", "SUCCESS")
| stats count, min(_time) as first_seen, max(_time) as last_seen by TargetUserName, IpAddress, Action, LogonType
| fieldformat first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| fieldformat last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

The search caught 133 failed attempts between `14:02:10` and `14:05:42`, followed by a single successful network login (`EventCode 4624`, `LogonType 3`) for `administrator` at `14:05:50`.

---

### Raw Log Excerpt

```text
EventCode=4625
LogonType=3
TargetUserName=administrator
TargetDomainName=LAB
WorkstationName=KALI-ATTACKER
IpAddress=192.168.56.105
IpPort=49210
Status=0xc000006d
SubStatus=0xc000006a
```

*SubStatus reference:*
- `0xc000006a`: User exists, bad password provided (password guessing)
- `0xc0000064`: User name does not exist (username enumeration)

---

### Correlation Search & Alert Logic

Created a scheduled Splunk correlation alert for threshold detection:

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625 IpAddress!="127.0.0.1" IpAddress!="-"
| bucket _time span=5m
| stats count, dc(TargetUserName) as unique_users by IpAddress, _time
| where count > 15 OR unique_users > 3
```

Alert triggers when a single IP generates **> 15 failed logons in 5 minutes** or probes **> 3 unique usernames**.

---

### Practical SIEM Tuning Gotchas

- **Machine Accounts (`*$`)**: Active Directory computer accounts generate periodic failed logons (e.g. `WIN-DC01$`). Excluded `TargetUserName="*$"` to prevent false alarms.
- **NTLM `WorkstationName` Nulls**: Over NTLM network logons, `WorkstationName` is often blank or untrusted. Correlation rules rely on `IpAddress`.
- **Logon Types**: Differentiated `LogonType 3` (Network SMB/Share) from `LogonType 10` (Remote Desktop / RDP).
