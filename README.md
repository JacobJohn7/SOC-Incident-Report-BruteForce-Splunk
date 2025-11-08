# 🛡️ SOC Incident Report – Brute Force Attack Detection Using Splunk

**Analyst:** Jacob John  
**Date:** November 2025  
**Company Type:** IT Services Firm  
**Tool:** Splunk Enterprise  
**Framework:** MITRE ATT&CK

---

## 📘 Project Overview
This project demonstrates a real-world **Security Operations Center (SOC) investigation** of a brute-force login attack simulated in a corporate IT environment.  
The objective was to detect, analyze, and report the incident using **Splunk SIEM**, following industry-standard procedures and MITRE ATT&CK mapping.

---

## ⚙️ Tools and Frameworks Used
| Category | Tool / Framework | Purpose |
|-----------|------------------|----------|
| SIEM | Splunk Enterprise | Log ingestion, parsing, and alert correlation |
| Logs | Windows Event Viewer | Source of authentication data |
| Network Analysis | Wireshark | Network traffic inspection |
| Threat Intel | AbuseIPDB, VirusTotal | IP reputation analysis |
| Framework | MITRE ATT&CK | Mapping detected techniques |

---

## 🚨 Incident Summary
**Incident Type:** Brute-force attack on Windows authentication service  
**Detection Method:** Splunk correlation rule (Failed Logon Spike)  
**Source IP:** 45.177.23.61  
**Target System:** WIN-SRV01 (Domain Controller)  
**Account Targeted:** admin01  
**Impact:** Limited — no privilege escalation or data breach detected

---

## 🔍 Investigation Process
1. **Log Collection:**  
   - Ingested Windows Event Logs (Event IDs 4625, 4624) into Splunk via Universal Forwarder.

2. **Detection Query (Splunk):**  
   ```spl
   sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
   | stats count by Account_Name, IPAddress, EventCode
   | where count > 10
