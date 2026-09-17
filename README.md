# Windows Authentication & Brute Force Analysis in Splunk

Splunk search queries and correlation rules written during a lab setup to detect RDP/SMB brute force attacks against a Windows Server 2022 domain controller (`WIN-DC01`).

### Forwarder Configuration (`inputs.conf`)

Configured on the target domain controller to send Security event logs to Splunk:

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1
checkpointInterval = 5
render_xml = false
```

Simulated dictionary attacks from Kali (`192.168.56.105`) using hydra:
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt 192.168.56.106 smb -t 4
```

### SPL Queries

1. Group failed logon attempts (`EventCode 4625`) by target user and substatus code:

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625
| stats count by TargetUserName, IpAddress, SubStatus
| sort - count
```

Sample output:
```text
TargetUserName   IpAddress       Count  SubStatus
administrator    192.168.56.105  87     0xc000006a
admin            192.168.56.105  34     0xc000006a
guest            192.168.56.105  12     0xc0000064
```

2. Correlate failed attempts (`4625`) with successful logons (`4624`):

```spl
index=win_logs sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) IpAddress="192.168.56.105"
| eval Action=if(EventCode==4625, "FAILED", "SUCCESS")
| stats count, min(_time) as first_seen, max(_time) as last_seen by TargetUserName, IpAddress, Action, LogonType
| fieldformat first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| fieldformat last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

### Scheduled Correlation Search

Alert query saved in Splunk to flag source IPs exceeding 15 failures in 5 minutes:

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625 IpAddress!="127.0.0.1" IpAddress!="-" TargetUserName!="*$"
| bucket _time span=5m
| stats count, dc(TargetUserName) as unique_users by IpAddress, _time
| where count > 15 OR unique_users > 3
```

### Log Field Reference

- `SubStatus 0xc000006a`: Valid user, bad password.
- `SubStatus 0xc0000064`: User name does not exist.
- `TargetUserName!="*$"`: Excludes Active Directory computer machine accounts (e.g. `WIN-DC01$`) from alert triggers.
