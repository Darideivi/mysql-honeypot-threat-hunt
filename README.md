<p align="center">

<img width="1536" height="1024" alt="ChatGPT Image Aug 27, 2026, 06_35_14 PM" src="https://github.com/user-attachments/assets/0fdb71b5-b613-4f00-9347-2238e270e508" />
</p>

<p align="center">
  <em>Reconstructing a full intrusion chain — internet-exposed MySQL to data destruction and extortion — using Microsoft Defender for Endpoint and MySQL audit logs ingested into Microsoft Sentinel</em>
</p>

# Threat Hunt Report: MySQL Honeypot — Unauthorized Access, Data Destruction & Extortion

---

## Incident Brief

| | |
|---|---|
| **Scenario / Trigger** | Recurring custom Microsoft Defender detection — *"Brute Force or Password Spraying Attack Detected"* — fired repeatedly against an internet-facing honeypot VM. Manual review of the paired MySQL audit logs during triage surfaced a separate, more serious finding: successful unauthenticated `root` access to the exposed MySQL service, followed by data destruction and a planted extortion note. |
| **Environment** | Microsoft Defender for Endpoint (Advanced Hunting) + MySQL general log shipped to Azure Monitor / Log Analytics as `MySQLAudit_CL`; investigated via Microsoft Sentinel. |
| **Host(s) Investigated** | `corp-dr01-fe123` (Azure VM, Windows 11, internet-facing honeypot, internal IP `10.2.0.10`) |
| **Data Sources** | `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceProcessEvents_CL`, `MySQLAudit_CL` (Auth Logs + Queries), `MySQLAudit_VM`, MDE Action Center action log |
| **Timeframe** | 2026-08-25 → 2026-08-27 |
| **Analyst** | David Pena |
| **Date Completed** | 08/27/2026 |

> This host is documented elsewhere as an intentional honeypot, and several data points below are still open questions rather than settled facts — most notably, whether the RDP brute-force campaign against `administrator` ever actually succeeded. Where the underlying exports don't fully support a claim, it's marked **unconfirmed** rather than asserted. Timestamps are taken directly from each table's `TimeGenerated` field; the source exports did not specify a timezone, so all times below should be treated as consistent-with-each-other rather than confirmed UTC.

---

## Executive Summary

Between Aug 25 and Aug 26, 2026, the MySQL service on `corp-dr01-fe123` (TCP/3306) accepted repeated `root` logons from at least seven unrelated external IPs with no password supplied — the service was directly exposed to the internet with a default/blank root credential. One session used that access to enumerate the `world` database, plant a table containing an extortion message, and then drop three production-style tables, a pattern consistent with mass-scanned "MySQL ransom" campaigns; a second, unattributed session revisited a similar artifact roughly 25 hours later. A concurrent RDP brute-force campaign against the local `administrator` account ran over the same window — every attempt in the primary logon export failed, but a separately-built attack-map visualization covering a wider time window claims three successful external RDP logons that were never reconciled against source data, so RDP compromise is left as **unconfirmed** rather than ruled out. No evidence of OS-level persistence, malicious process execution, or C2 activity was found in the endpoint telemetry reviewed, indicating the confirmed portion of the intrusion stayed confined to the database layer.

---

## Hunt Objectives

- Determine whether the internet-exposed MySQL service was successfully accessed, and by what method
- Determine the scope and nature of any data impact (confidentiality, integrity, availability)
- Correlate attacker behavior to MITRE ATT&CK techniques across both the database and endpoint layers
- Determine whether the concurrent RDP brute-force campaign against `administrator` ever succeeded
- Document evidence, detection gaps, and response opportunities

---

## Starting Point

Investigation began by scoping the custom detection to the host and pulling the full MySQL authentication history for the surrounding window, to see whether the repeated brute-force alerts were hiding a more serious database-layer compromise.

```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where TimeGenerated between (datetime(2026-08-25) .. datetime(2026-08-27))
| order by TimeGenerated asc
```

---

## Chronological Timeline

| Time (approx.) | Flag | Stage | Action Observed |
|---|---|---|---|
| Aug 25, 17:52–20:40 | 1 | Credential Access | Sustained RDP brute force vs. `administrator`/`admin`/`guest` from 77.83.38.24, then 58.216.163.214. All LogonFailed in the primary export. |
| Aug 25, ~19:00 onward | 2 | Initial Access | First confirmed `root` logon with no password from 94.102.49.155; pattern repeats from 213.209.159.115, 77.90.185.30, 77.90.185.21 through Aug 26. |
| Aug 25, 18:17:55–18:17:56 | 3 | Collection | Reconnaissance on `world.countrylanguage` (SHOW TRIGGERS, SHOW CREATE TABLE, table status) — connection ID 31. |
| Aug 26, 03:19–03:26 | 4 | Discovery | `SHOW GRANTS FOR CURRENT_USER()` issued from 45.186.208.107 after successful root logon. |
| Aug 25, 18:18:02–18:18:03 | 5 | Impact | `FOREIGN_KEY_CHECKS` disabled; `DROP TABLE world.country`, `world.city`, `world.countrylanguage`; re-enabled; committed. |
| Aug 25, 18:17:58–18:18:01 | 6 | Impact | `CREATE TABLE world.RECOVER_YOUR_DATA_info`; extortion note text inserted. |
| Aug 25 19:00 – Aug 26 03:47 | 7 | Collection | Repeated `SELECT @@max_allowed_packet` immediately following successful root logons (77.90.185.30, 213.209.159.115) — dump-tool staging indicator. |
| Aug 26, 19:24:19–19:27:12 | 8 | Discovery | Unattributed session queries `recover_your_data.recover_your_data` directly (SHOW COLUMNS/INDEX, `SELECT *`) — second extortion artifact revisited. |
| Aug 26, 23:31:47 | — | Response | Analyst isolates `corp-dr01-fe123` (`Host-breach-isolation`). |
| Aug 26, 23:50:48 | — | Response | Device released from isolation (`post hardening realese`). |

---

## MITRE ATT&CK Summary

| Flag | Tactic | Technique | ID |
|---|---|---|---|
| 1 | Credential Access | Brute Force | T1110 |
| 2 | Initial Access | Valid Accounts: Default Accounts | T1078.001 |
| 3 | Collection | Data from Information Repositories | T1213 |
| 4 | Discovery | Permission Groups Discovery | T1069 |
| 5 | Impact | Data Destruction | T1485 |
| 6 | Impact | Defacement: Internal Defacement | T1491.001 |
| 7 | Collection | Automated Collection | T1119 |
| 8 | Discovery | Data from Information Repositories (re-access) | T1213 |

---

## Attack Chain

```text
Credential Access                    Initial Access
RDP brute force vs.                  MySQL exposed to internet,
"administrator"                      root / no password accepted
(77.83.38.24, 58.216.163.214)        (94.102.49.155 first confirmed,
success: UNCONFIRMED                 6 more IPs follow)
        │                                    │
        │                                    ▼
        │                             Discovery / Collection
        │                             SHOW DATABASES/TABLES,
        │                             SHOW GRANTS FOR CURRENT_USER(),
        │                             @@max_allowed_packet checks
        │                                    │
        │                                    ▼
        │                             Impact
        │                             DROP TABLE world.country/city/
        │                             countrylanguage
        │                                    │
        │                                    ▼
        │                             Impact
        │                             RECOVER_YOUR_DATA_info planted,
        │                             extortion note inserted
        │                                    │
        └──────────────  (parallel, unconfirmed link)  ──────────────┘
                                     │
                                     ▼
                        Discovery (t+25h, unattributed)
                        recover_your_data artifact re-queried
```

---

## Flag Analysis

### Flag 1 — RDP Brute Force / Password Spraying Against `administrator`
**Tactic / Technique:** Credential Access — Brute Force (T1110)

**Objective:** Determine whether the RDP-facing brute-force campaign flagged by MDE's custom detection ever succeeded in authenticating.

**What to Hunt:** Pull all `DeviceLogonEvents` (and the mirrored `MySQLAudit_VM` export) for the host, filter to `LogonType == "Network"`, and group by `RemoteIP`/`AccountName` to separate sustained failure patterns from any interspersed `LogonSuccess`.

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | Aug 25, 17:52–20:40 (sustained), continuing per attack-map through Aug 26 23:32 |
| Source IPs | 77.83.38.24 (Ukraine, 137 attempts), 58.216.163.214 (China, 18 attempts), 206.189.217.42 (single attempt), 80.66.83.80 (Russia, single attempt — seen only in the wider-window attack map, not in the primary CSV export) |
| Accounts targeted | administrator, admin, guest |
| Result (primary export) | 100% `LogonFailed` |
| Result (attack-map, wider window) | Claims 2 successful logons from 77.83.38.24 and 1 from 206.189.217.42 — **unconfirmed**, not corroborated against a raw `LogonSuccess` row in the exports reviewed |

**Why it Matters:** This is the discrepancy that most needs closing before the incident can be fully scoped. If the attack-map's successful-logon claim is confirmed, RDP becomes a second, independent entry vector alongside the database exposure, and the host-isolation/rebuild scope changes materially. If it isn't confirmed, the brute-force campaign is noise that happened to run in parallel with the real (database-layer) compromise. Treating this as settled in either direction without the underlying `LogonSuccess` row would be a mistake a reviewer should be able to spot immediately from this report.

**KQL Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "corp-dr01-fe123"
| where LogonType == "Network"
| where RemoteIP in ("77.83.38.24", "58.216.163.214", "206.189.217.42", "80.66.83.80")
| summarize Attempts = count(), Successes = countif(ActionType == "LogonSuccess")
    by RemoteIP, AccountName
| order by Attempts desc
```

**Screenshot:**
`![Flag 1 evidence](screenshots/honeypot-attack-map.png)`

**Detection Recommendation:** Alert on any `LogonSuccess` for a local admin account immediately preceded by ≥5 `LogonFailed` events from the same source IP within a 15-minute window — this closes the exact gap this flag ran into, where success and failure counts were tracked in two different places that didn't get reconciled in real time.

---

### Flag 2 — Initial Access via Exposed MySQL with Default/Blank Root Credential
**Tactic / Technique:** Initial Access — Valid Accounts: Default Accounts (T1078.001)

**Objective:** Establish how external actors obtained database access — credential theft, exploit, or misconfiguration.

**What to Hunt:** Query `MySQLAudit_CL` for `ActionType == "LogonSuccess"` where `Username == "root"` and the source is not `localhost`; cross-reference the `RawData` field for adjacent failed attempts against the same account to confirm no password was actually being supplied.

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | First confirmed success ~Aug 25, 19:00:30; recurs from 6+ more IPs through Aug 26, 18:34 |
| Source IPs | 94.102.49.155, 213.209.159.115, 77.90.185.30, 77.90.185.21, 45.186.208.107, 64.89.163.164 |
| Account | root (remote, TCP/IP and SSL/TLS) |
| Evidence pattern | Adjacent failed connections for `admin`/`sa` on the same IPs show `(using password: NO)`; `root` connects successfully immediately after — consistent with a blank/default root password rather than a leaked credential |

**Why it Matters:** This is the confirmed entry point for the entire incident. Unlike the RDP campaign, every step here — failed probe, successful root connect, schema access — is corroborated end-to-end in the same table. It's the finding the rest of the attack chain hangs off of.

**KQL Query Used:**
```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where Username == "root" and ActionType == "LogonSuccess"
| where IpAddress != "localhost" and isnotempty(IpAddress)
| project TimeGenerated, IpAddress, RawData
| order by TimeGenerated asc
```

**Screenshot:**
`![Flag 2 evidence](path/to/screenshot.png)`

**Detection Recommendation:** Alert on any successful MySQL authentication from a non-allowlisted source IP, and separately, on any account (especially `root`) that has ever authenticated with an empty password field in the audit log — that alone should page someone regardless of source.

---

### Flag 3 — Database & Schema Enumeration
**Tactic / Technique:** Collection — Data from Information Repositories (T1213)

**Objective:** Confirm the attacker moved from initial access into active reconnaissance of the database contents before taking destructive action.

**What to Hunt:** Search `MySQLAudit_CL` Queries for `SHOW DATABASES`, `SHOW TABLES`, `SHOW FULL COLUMNS`, and `SHOW CREATE TABLE` issued in temporal proximity to a successful root logon, and tie each back to its connection ID.

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | Aug 25, 18:17:55–18:17:56 (conn ID 31); recurring pattern from other IPs through Aug 26 |
| Databases enumerated | world, sakila, cr_corp_01, recover_your_data, mysql, performance_schema, information_schema, sys |
| Specific target | `world.countrylanguage` — `SHOW TRIGGERS`, `SHOW CREATE TABLE`, `show table status`, `select @@collation_database` |

**Why it Matters:** This is the reconnaissance step directly preceding the data-destruction flag below — the attacker checked table structure and triggers on `countrylanguage` in the same connection, seconds before creating the ransom table and dropping it. It's the clearest evidence that the drop was deliberate rather than accidental or unrelated tooling.

**KQL Query Used:**
```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where Query has_any ("SHOW DATABASES", "SHOW TABLES", "SHOW FULL COLUMNS", "SHOW CREATE TABLE")
| project TimeGenerated, Query, RawData
| order by TimeGenerated asc
```

**Screenshot:**
`![Flag 3 evidence](path/to/screenshot.png)`

**Detection Recommendation:** Baseline normal schema-introspection volume per account/IP and alert when an external, non-application account issues more than a handful of `SHOW`/`INFORMATION_SCHEMA` queries within a single session — legitimate application service accounts rarely browse schema interactively.

---

### Flag 4 — Privilege / Grant Enumeration
**Tactic / Technique:** Discovery — Permission Groups Discovery (T1069)

**Objective:** Determine whether the attacker checked their own privilege level before proceeding — a common gate before deciding whether to escalate, pivot, or act directly.

**What to Hunt:** Search `MySQLAudit_CL` Queries for `SHOW GRANTS FOR CURRENT_USER()` and correlate the connection/source IP with the surrounding successful-logon event.

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | Aug 26, 03:26:19 |
| Source IP | 45.186.208.107 |
| Command | `SHOW GRANTS FOR CURRENT_USER()`, immediately after `SET NAMES utf8mb4` and `SHOW DATABASES` |

**Why it Matters:** Confirms the account being used (`root`) already had full privileges, so no further escalation was needed — it explains why no `GRANT`/`CREATE USER` activity was ever necessary for this actor to reach the destructive stage. MITRE doesn't have a database-specific permission-enumeration technique, so T1069 is used here as the closest analog to the OS/domain-group version of this behavior — worth a caveat if this report is reviewed by someone checking ID precision closely.

**KQL Query Used:**
```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where Query has "SHOW GRANTS"
| project TimeGenerated, IpAddress, Query
```

**Screenshot:**
`![Flag 4 evidence](path/to/screenshot.png)`

**Detection Recommendation:** Flag `SHOW GRANTS FOR CURRENT_USER()` from any non-localhost, non-application source as a discovery indicator worth correlating with what that session does next — on its own it's low severity, but as a leading indicator it's cheap to watch for.

---

### Flag 5 — Data Destruction (DROP TABLE)
**Tactic / Technique:** Impact — Data Destruction (T1485)

**Objective:** Confirm and scope the actual destructive action taken against the database.

**What to Hunt:** Search `MySQLAudit_CL` Queries for `DROP TABLE`, `DROP DATABASE`, and `FOREIGN_KEY_CHECKS` toggling (a common precursor to bulk drops that would otherwise fail on referential integrity).

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | Aug 25, 18:18:02–18:18:03 |
| Connection ID | 28 |
| Commands | `SET FOREIGN_KEY_CHECKS=0` → `DROP TABLE IF EXISTS world.country` → `DROP TABLE IF EXISTS world.city` → `DROP TABLE IF EXISTS world.countrylanguage` → `SET FOREIGN_KEY_CHECKS=1` → `commit` |
| Source IP for connection 28 | Not determined — connection IDs 28/31 do not appear in the Auth Logs export reviewed; the nearest bracketing successful logon is 94.102.49.155 (after, not before) |

**Why it Matters:** This is the confirmed integrity/availability impact of the incident — three tables in a production-style schema were deliberately and irreversibly removed in-session. The unresolved source-IP attribution for this specific connection is a real gap: without it, this action can't be tied to any single one of the seven root-logon source IPs with certainty.

**KQL Query Used:**
```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where Query has_any ("DROP TABLE", "DROP DATABASE", "FOREIGN_KEY_CHECKS")
| project TimeGenerated, Query, RawData
| order by TimeGenerated asc
```

**Screenshot:**
`![Flag 5 evidence](path/to/screenshot.png)`

**Detection Recommendation:** Alert in real time on any `DROP TABLE`/`DROP DATABASE` statement against a production schema issued outside of a change-managed maintenance window, regardless of the authenticating account's privilege level.

---

### Flag 6 — Extortion Note / Internal Defacement
**Tactic / Technique:** Impact — Defacement: Internal Defacement (T1491.001)

**Objective:** Identify the artifact left behind by the attacker and extract IOCs from it (payment demand, contact method, case ID).

**What to Hunt:** Search `MySQLAudit_CL` Queries for `CREATE TABLE` statements with ransom-pattern naming (`RECOVER_YOUR_DATA`, `READ_ME`) and the subsequent `INSERT` carrying the note text.

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | Aug 25, 18:17:58–18:18:01 |
| Connection ID | 28 (same session as Flag 5) |
| Artifact | `CREATE TABLE world.RECOVER_YOUR_DATA_info (READ_ME text) ENGINE=InnoDB DEFAULT CHARSET=utf8`, followed by `INSERT INTO world.RECOVER_YOUR_DATA_info (READ_ME) VALUES ('Saved file name: world.sql...')` |
| IOCs extracted from note | BTC address `bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99`; contact `ak+28t2@onionmail.org`; reference URL `hxxps://2no[.]co/2mysql`; chat link `hxxps://spoo[.]me/akilahelp`; case ID `DATAID: 28T2` |

**Why it Matters:** This single artifact turns an otherwise generic "data destroyed" finding into a clearly financially-motivated extortion attempt, and gives concrete, actionable IOCs (a BTC address and two contact channels) that can be shared with threat intel and used to check for the same campaign hitting other exposed database honeypots or production hosts.

**KQL Query Used:**
```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where Query has_any ("RECOVER_YOUR_DATA", "READ_ME")
| project TimeGenerated, Query, RawData
| order by TimeGenerated asc
```

**Screenshot:**
`![Flag 6 evidence](screenshots/ransom-note-pastesh.png)`

**Detection Recommendation:** Maintain a watchlist of known "MySQL ransom" table/column naming patterns (`RECOVER_YOUR_DATA*`, `READ_ME`, `WARNING`) and alert on `CREATE TABLE` matching them anywhere in the environment — these campaigns reuse the same handful of table names across victims, making this a cheap, high-confidence signature.

---

### Flag 7 — Suspected Bulk-Export / Dump-Tool Staging
**Tactic / Technique:** Collection — Automated Collection (T1119)

**Objective:** Determine whether any of the later sessions attempted to exfiltrate data via a standard dump utility, as opposed to purely destructive or reconnaissance activity.

**What to Hunt:** Search `MySQLAudit_CL` Queries for `SELECT @@max_allowed_packet` — a call issued automatically by `mysqldump` and similar clients to size their transfer buffer before a bulk read — and check whether it's immediately followed by broad `SELECT` activity.

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | Recurring: Aug 25 19:00 PM, 19:19 PM, 19:44 PM, 20:16 PM, 21:18 PM; Aug 26 00:26, 02:01, 02:50, 03:34, 03:47 |
| Source IPs | 77.90.185.30, 213.209.159.115 (both previously confirmed root logons) |
| Command | `SELECT @@max_allowed_packet` immediately after connection establishment, before any further activity captured in this export |

**Why it Matters:** This is a leading indicator, not confirmed proof — the export reviewed does not contain a subsequent bulk `SELECT` against real table data to confirm an actual dump occurred. It's flagged here specifically so it isn't lost: if fuller query logs become available, this is the exact pattern to search for confirmation of data exfiltration, which would upgrade the "suspected" confidentiality impact in the final assessment to "confirmed."

**KQL Query Used:**
```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where Query has "max_allowed_packet"
| project TimeGenerated, IpAddress, Query
| order by TimeGenerated asc
```

**Screenshot:**
`![Flag 7 evidence](path/to/screenshot.png)`

**Detection Recommendation:** Correlate `SELECT @@max_allowed_packet` from a non-application source IP with the row-count/byte-volume of the `SELECT` statements that immediately follow in the same session — that pairing is what actually distinguishes a real dump from an idle client handshake.

---

### Flag 8 — Second-Session Re-Access of Ransom Artifact
**Tactic / Technique:** Discovery — Data from Information Repositories, re-access (T1213)

**Objective:** Determine whether the extortion campaign involved a single actor returning, or a second, independent actor/bot hitting the same exposure.

**What to Hunt:** Search `MySQLAudit_CL` Queries for any reference to `recover_your_data` outside the original Flag 5/6 session window, and check whether its connection ID and source IP tie back to any previously-seen root logon.

**Findings:**

| Field | Value |
|---|---|
| Host | corp-dr01-fe123 |
| Timestamp | Aug 26, 19:24:19–19:27:12 (≈25 hours after the original drop/note event) |
| Connection ID | 79 / 80 |
| Commands | `USE recover_your_data`, `SHOW FULL TABLES/COLUMNS/INDEX`, `SELECT * FROM recover_your_data.recover_your_data` |
| Source IP | Not determined — connection IDs 79/80 do not appear in the Auth Logs export reviewed |

**Why it Matters:** The ~25-hour gap and the different database name (`recover_your_data` vs. the original `world` schema) make single-actor re-visit and independent second-actor/bot both plausible; the missing source IP means this can't be resolved from the current export. Left as an open question rather than assumed either way — see Analyst Notes.

**KQL Query Used:**
```kql
MySQLAudit_CL
| where DeviceName == "corp-dr01-fe123"
| where Query has "recover_your_data"
| project TimeGenerated, IpAddress, Query
| order by TimeGenerated asc
```

**Screenshot:**
`![Flag 8 evidence](path/to/screenshot.png)`

**Detection Recommendation:** Ensure the audit pipeline captures `Connect`/`Connection ID` events for every session without gaps — the two attribution gaps in this hunt (Flags 5 and 8) both trace back to the same root cause: sessions whose `Connect` event fell outside the exported window even though their `Query` events were captured.

---

## Intrusion Narrative

1. **Reconnaissance (parallel, unconfirmed)** — An RDP brute-force campaign against `administrator` runs for hours from Ukraine- and China-geolocated IPs; every logged attempt fails, though a separately-built visualization claims a handful of successes that were never reconciled against source logs.
2. **Initial Access** — Independently, the MySQL service on the same host accepts a `root` connection with no password from 94.102.49.155 — the account had effectively no authentication barrier.
3. **Discovery / Collection** — The successful session (and several that follow from other IPs) browses available databases and tables, eventually focusing on `world.countrylanguage`, and one session checks its own grants, confirming full `root` privilege.
4. **Impact** — Within the same connection, the attacker creates a table named `RECOVER_YOUR_DATA_info`, inserts an extortion message referencing a Bitcoin address and two contact channels, then drops three tables in the `world` database.
5. **Continued exposure** — Over the next day, six more IPs successfully authenticate as `root` with no password; several issue `SELECT @@max_allowed_packet`, a pattern consistent with dump-tool staging, though no confirmed bulk read was captured.
6. **Revisit** — Roughly 25 hours after the original drop, an unattributed session directly queries the `recover_your_data` ransom artifact, leaving open whether this was the original actor or a second opportunistic bot hitting the same exposed service.
7. **Response** — The analyst isolates the host and releases it after hardening; ongoing automated brute-force detections continue to fire in the background throughout.

---

## Detection Gaps & Recommendations

### Gaps Identified
- MySQL was reachable directly from the internet on TCP/3306 with no network-layer restriction, and `root` accepted connections with no password — the single control that would have prevented the entire database-layer portion of this incident.
- The audit export did not capture `Connect` events for at least two connection IDs (28, 31, 79, 80) that *do* appear in the Query log, breaking source-IP attribution for both the destructive action and the second-session revisit.
- No alerting existed on `DROP TABLE`/`DROP DATABASE` against production-style schemas, or on `CREATE TABLE` matching known ransom-note naming patterns.
- The RDP brute-force custom detection fired repeatedly (12+ times over 48 hours) without any workflow to correlate it against the `LogonSuccess` ground truth, which is exactly how the Flag 1 discrepancy went unresolved for as long as it did.

### Recommendations
- Remove MySQL from direct internet exposure; place it behind a VPN/bastion or restrict TCP/3306 to known management IPs via NSG/firewall.
- Disable remote `root` login entirely and enforce unique, strong credentials for every MySQL account.
- Fix the audit log pipeline so every session's `Connect` event is retained for at least as long as its `Query` events — this alone would have closed two of the eight flags' attribution gaps.
- Deploy detection content for `DROP TABLE`/`DATABASE`, `CREATE TABLE` matching ransom-pattern names, and `SELECT @@max_allowed_packet` immediately preceding bulk `SELECT`s.
- Build a lightweight correlation rule that automatically checks for any `LogonSuccess` following a run of `LogonFailed` from the same source/account, and surfaces it alongside the existing brute-force alert rather than as a separate, easy-to-miss data point.

---

## Final Assessment

This was a low-sophistication, opportunistic compromise rather than a targeted intrusion: the attacker(s) did nothing more advanced than connecting to a database that had effectively no authentication barrier, browsing its contents, and running a scripted "drop tables, plant a ransom note" playbook that's common across mass-scanned MySQL exposures. The confirmed impact is contained to the database layer — three tables destroyed and an extortion note planted in the `world` schema — with no evidence of OS-level persistence or lateral movement in the endpoint telemetry reviewed. The most consequential open question is whether the concurrent RDP brute-force campaign against `administrator` ever actually succeeded, as one visualization claims; until that's reconciled against a raw `LogonSuccess` record, the incident should be scoped as "confirmed database compromise, unconfirmed host compromise" rather than closed in either direction. Immediate priorities are removing the MySQL exposure and root credential gap that enabled everything else here, and fixing the audit logging gap that left two of the most important actions in this timeline without a source IP.

---

## Analyst Notes

- This hunt started from a routine automated-detection review (the recurring brute-force alert) and expanded significantly once the paired MySQL audit data revealed a more serious, unrelated finding — a good example of why it's worth glancing at *all* telemetry for a flagged host, not just the log that triggered the alert.
- Two attribution gaps (Flags 5 and 8) were left open rather than guessed at; both trace to the same root cause (missing `Connect` events for specific connection IDs), which is called out explicitly in Detection Gaps above.
- The RDP-success discrepancy in Flag 1 is the single biggest unresolved item in this report — deliberately left as "unconfirmed" rather than adopting either the all-failed CSV or the attack-map's success count, since neither has been directly reconciled against the other yet.
- Evidence reproducible via Microsoft Sentinel Advanced Hunting (`MySQLAudit_CL`) and Microsoft Defender for Endpoint Advanced Hunting (`DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`).
- Every flag mapped to a MITRE ATT&CK technique; two (Flags 4 and 8) use the closest available technique ID where MITRE has no database-specific sub-technique — noted inline where that judgment call was made.
