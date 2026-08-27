<p align="center">
  <img width="800" height="533" alt="Azure MySQL honeypot attack diagram" src="https://github.com/user-attachments/assets/bf731ee6-a2a5-4039-8209-beef82c86b7c" />
</p>

<h1 align="center">Azure MySQL Honeypot — Threat Hunt & Incident Investigation</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Azure-VM-0089D6" alt="Azure" />
  <img src="https://img.shields.io/badge/Microsoft-Defender%20for%20Endpoint-0078D4" alt="Microsoft Defender for Endpoint" />
  <img src="https://img.shields.io/badge/Microsoft-Sentinel-0078D4" alt="Microsoft Sentinel" />
  <img src="https://img.shields.io/badge/KQL-Log%20Analytics-informational" alt="KQL / Log Analytics" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/Status-Investigation%20Complete-brightgreen" alt="Status" />
</p>

> **Quick summary:** I exposed a Windows VM with MySQL to the internet as a honeypot, collected Windows and MySQL telemetry, and investigated the activity with Microsoft Defender, Sentinel, Log Analytics, and KQL. The honeypot received brute-force attempts, unauthorized MySQL `root` access, database reconnaissance, table destruction, and an extortion note.

---

## 🧪 What I Built

This project simulates a small SOC investigation from start to finish.

- **Environment:** Azure Windows 11 VM (`corp-dr01-fe123`) with an internet-facing MySQL service.
- **Security stack:** Microsoft Defender for Endpoint, Microsoft Sentinel, Azure Monitor / Log Analytics, KQL, and MySQL logs ingested into `MySQLAudit_CL`.
- **Investigation window:** August 25–27, 2026. (It Took Just 2 Days for the Honeypot to Get Hit by a Ransom Attack)

---

## 🚨 What Happened

After the honeypot was exposed, automated systems began probing it from several public IP addresses. Two types of activity stood out:

1. **Windows/RDP brute-force attempts** targeted accounts such as `administrator`, `admin`, and `guest`.
2. **MySQL was successfully accessed remotely as `root`.** The logs show repeated external root connections, followed by database discovery and destructive SQL activity.

The strongest confirmed attack chain was:

```text
Internet scan
    ↓
Exposed MySQL service (TCP/3306)
    ↓
Remote root access
    ↓
Database / table discovery
    ↓
Privilege discovery
    ↓
Ransom table + extortion message
    ↓
Three world database tables dropped
```

The confirmed compromise stayed at the **database layer** in the telemetry reviewed. I did not find evidence of malicious OS-level persistence, command-and-control activity, or lateral movement.

---

## 🔍 Key Findings

| Finding | What I Observed | Status |
|---|---|---|
| RDP brute force | Repeated public-IP authentication attempts against local Windows accounts | ✅ Confirmed |
| Remote MySQL root access | Multiple external IPs connected as `root` | ✅ Confirmed |
| Database discovery | `SHOW DATABASES`, `SHOW TABLES`, `SHOW CREATE TABLE`, and related queries | ✅ Confirmed |
| Privilege discovery | `SHOW GRANTS FOR CURRENT_USER()` | ✅ Confirmed |
| Data destruction | `DROP TABLE` against three `world` database tables | ✅ Confirmed |
| Extortion activity | `RECOVER_YOUR_DATA_info` table created and populated with a ransom message | ✅ Confirmed |
| Possible dump-tool activity | Repeated `SELECT @@max_allowed_packet` after remote connections | 🟡 Suspected |
| Successful RDP compromise | A visualization showed successes, but they were not reconciled to raw `LogonSuccess` evidence | ❓ Unconfirmed |

---

## 🕒 Timeline

| Time | Event |
|---|---|
| Aug 25 | Sustained RDP brute-force activity begins |
| Aug 25 | External MySQL `root` connections observed |
| Aug 25 | Database/schema reconnaissance |
| Aug 25 | Ransom table and extortion message created |
| Aug 25 | Three `world` database tables dropped |
| Aug 26 | Additional external root sessions and privilege discovery |
| Aug 26 | Ransom-related database artifact accessed again |
| Aug 26 | Honeypot isolated during response |
| Aug 26 | Host released after hardening |

---

## 🧾 Example Evidence

### Remote MySQL access

```kql
let MyDevice = "corp-dr01-fe123";
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| where RawData !has "@localhost"
| project TimeGenerated, RawData
| order by TimeGenerated desc
```
<img width="1946" height="1146" alt="Honeypot1" src="https://github.com/user-attachments/assets/1c3b8334-75f9-43a3-877e-5834047b9cb9" />

### Destructive SQL activity

```kql
let MyDevice = "corp-dr01-fe123";
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has_any ("DROP TABLE", "DROP DATABASE", "FOREIGN_KEY_CHECKS")
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

Observed sequence:

<img width="2208" height="1104" alt="Honeypot2" src="https://github.com/user-attachments/assets/9524cfad-4de0-4e25-9cb2-25d5b1ed32af" />



### Extortion artifact

The attacker created `world.RECOVER_YOUR_DATA_info` and inserted an extortion message containing payment/contact information. This linked the destructive activity to a financially motivated extortion pattern rather than normal administration.

<img width="1992" height="998" alt="ramson" src="https://github.com/user-attachments/assets/9c2837b5-c413-4367-bfec-a04230dc84cf" />



## 🎯 MITRE ATT&CK Mapping

| Behavior | ATT&CK |
|---|---|
| RDP brute force | T1110 — Brute Force |
| Remote access using exposed/default account | T1078.001 — Valid Accounts: Default Accounts |
| Database information collection | T1213 — Data from Information Repositories |
| Privilege discovery | T1069 — Permission Groups Discovery |
| Table deletion | T1485 — Data Destruction |
| Ransom/extortion artifact | T1491.001 — Internal Defacement |
| Suspected automated collection | T1119 — Automated Collection |

---

## 🛡️ Detection & Security Improvements

- Remove MySQL from direct internet exposure; restrict TCP/3306 with an NSG/firewall, VPN, bastion, or allowlist.
- Disable remote `root` access and require strong, unique credentials.
- Alert on successful database authentication from unexpected public IP addresses.
- Alert on high-impact SQL such as `DROP TABLE` and `DROP DATABASE`.
- Detect ransom-style table names such as `RECOVER_YOUR_DATA` and `READ_ME`.
- Correlate repeated `LogonFailed` events with a later `LogonSuccess` from the same IP/account.
- Retain complete MySQL `Connect` events so SQL activity can always be tied back to its source IP.

---

## 🚑 Response

After confirming suspicious activity, I isolated `corp-dr01-fe123` using Microsoft Defender. I reviewed the surrounding endpoint and database telemetry and hardened the environment before releasing the host.

---

## 📚 What I Learned

The biggest lesson was how quickly an internet-facing service can be discovered and attacked without being advertised.

The project also reinforced the importance of **correlating multiple data sources**. The original signal was repeated Windows brute-force activity, but reviewing the MySQL telemetry revealed the more serious issue: successful database access followed by destructive SQL commands and an extortion artifact.

**Skills demonstrated:** Azure security monitoring • Microsoft Defender for Endpoint • Microsoft Sentinel • Log Analytics • KQL • MySQL logging • threat hunting • incident investigation • MITRE ATT&CK • containment

---

## ❓ Open Question

The RDP brute-force campaign may have produced successful Windows logons, but the available evidence is inconsistent. The primary export showed failures while a separate visualization reported several successes. Because those successes were not reconciled to raw `LogonSuccess` events, I left Windows/RDP compromise **unconfirmed**.

**Final scope:** confirmed MySQL/database compromise; Windows host compromise not confirmed.
