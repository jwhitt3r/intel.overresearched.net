---
layout: post
title:  "CTI Daily Brief: 2026-06-13 - ShinyHunters posts Council of Europe; Charisma Media adds new victim; Iowa school district insider sentenced"
date:   2026-06-14 20:05:00 +0000
description: "Quiet 24h with no critical CVEs. ShinyHunters added coe.int to its leak site, Charisma Media (securotrop) named Charisma Media as a new victim, and a former Iowa school district IT employee was sentenced to 21 months for credential-abuse attacks. A cluster of Telegram proxy posts continues to dominate low-signal noise."
category: daily
tags: [cti, daily-brief, shinyhunters, charisma-media, ransomware, insider-threat]
classification: TLP:CLEAR
reporting_period: "2026-06-13"
generated: "2026-06-14"
draft: true
severity: high
report_count: 11
sources:
  - RansomLook
  - BleepingComputer
  - Telegram OSINT
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-13 (24h) | TLP:CLEAR | 2026-06-14 |

## 1. Executive Summary

Eleven reports were processed across one correlation batch in the last 24 hours, with no critical-severity items and three rated high. The dominant theme is sustained ransomware leak-site activity: ShinyHunters added the Council of Europe (coe.int) as a victim and Charisma Media (operating under the `securotrop` brand) added a new corporate target via its Tor-based leak site. A separate operationally significant item from BleepingComputer reports the 21-month sentencing of a former Iowa school district IT employee who abused retained credentials for over a year and a half. No CISA KEV additions, exploited CVEs, or in-the-wild zero-day reports surfaced in this period. Background noise was driven by a cluster of Telegram proxy-channel posts (`@Turbotelproxy`) that the correlation engine flagged for possible phishing/anonymisation abuse but which carry low standalone signal.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None |
| 🟠 **HIGH** | 3 | ShinyHunters / coe.int; Charisma Media leak post; Telegram proxy lure cluster |
| 🟡 **MEDIUM** | 4 | Iowa school district insider sentencing; additional Telegram proxy posts |
| 🟢 **LOW** | 1 | Telegram proxy post (low-confidence) |
| 🔵 **INFO** | 3 | Telegram proxy posts (informational tracking) |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters Adds Council of Europe (coe.int) to Leak Site

**Source:** [RansomLook — shinyhunters group page](https://www.ransomlook.io//group/shinyhunters)

ShinyHunters posted `coe.int` — the Council of Europe — as a new entry on its data-leak infrastructure on 2026-06-14 03:45 UTC, per RansomLook's parser. The group is currently operating with a degraded site footprint (2 of 5 .onion mirrors up, average 40% 30-day uptime), but its primary mirror (`shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion`) and a clearnet file server at `91.215.85.22` were observed live during ingest. The post puts ShinyHunters' all-time victim count at 82 with 15 victims added in the last 30 days and 9 in the last 7 — consistent with the group's broader 2026 tempo and aligned to the wider trending entity data (ShinyHunters: 20 pipeline reports across the last 30 days). The summary description does not state what data class was exfiltrated from coe.int; treat the claim as unverified until coe.int issues a statement or sample data appears.

Affected sector: international governmental organisation (legal / human-rights tooling).

#### Indicators of Compromise

```
Mirror (active):   hxxp[:]//shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion/
Mirror (degraded): hxxp[:]//shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd[.]onion/
Mirror (down):     hxxp[:]//toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd[.]onion/
Clearnet domain:   shinyhunte[.]rs
File server:       91[.]215[.]85[.]22
Contact email:     shinygroup@onionmail[.]com
ATT&CK:            T1566 (Phishing)
```

> **SOC Action:** Block egress to the listed clearnet IP and add the `.onion` mirrors to threat-intel proxy block-lists. For organisations with Council of Europe partner relationships (NGOs, judicial bodies, EU member-state CERT contacts), pre-empt phishing pretext lures referencing a "coe.int data leak" — query mail gateways and EDR for inbound mail referencing `coe.int`, ShinyHunters, or `onionmail.com` in the 72 hours after any sample data publication.

### 3.2 Charisma Media Group (securotrop) Names Charisma Media as New Victim

**Source:** [RansomLook — securotrop group page](https://www.ransomlook.io//group/securotrop)

The `securotrop` ransomware brand — a low-volume but consistent operator running a single .onion leak site (`securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid.onion`, 100% 30-day uptime) — added Charisma Media as a victim on 2026-06-14 05:43 UTC with a 26 June 2026 publication deadline. The group's prior victim history (per the RansomLook archive) spans construction, engineering, legal services, and small-business accounting — Kriete Truck Centers, Thompson Builders, Synergy Engineering, Jones Haber Law, and Spartan Carbide are recent named victims. The group uses Tox (ID `BAFBD2AE7FC859F27D49471EF83365DD7E345EB3908B0612BFE83FEF33F79919A6C636A4E543`) for negotiations, has 33 lifetime posts, and is showing a low cadence of 2 victims in the last 30 days. Post text and prior victim listings confirm a standard double-extortion model (data theft + threat to publish).

Affected sector: media / publishing.

#### Indicators of Compromise

```
Leak site: hxxp[:]//securo45z554mw7rgrt7wcgv5eenj2xmxyrsdj3fcjsvindu63s4bsid[.]onion/
Tox ID:    BAFBD2AE7FC859F27D49471EF83365DD7E345EB3908B0612BFE83FEF33F79919A6C636A4E543
ATT&CK:    T1486 (Data Encrypted for Impact), T1496 (Resource Hijacking)
```

> **SOC Action:** For media-sector tenants, hunt EDR telemetry for Tox client artefacts (`qtox.exe`, `utox.exe`) and outbound traffic to Tox DHT bootstrap nodes; these are unusual on corporate endpoints and a useful tripwire for active negotiation. Confirm offline-immutable backups for editorial content management systems and verify mass-file-open / file-rename detections are tuned for the publishing fileshare workload (which produces high baseline file churn).

### 3.3 Iowa School District: Former IT Specialist Sentenced for 21-Month Credential-Abuse Campaign

**Source:** [BleepingComputer — Ex-school district employee jailed for hacks on former employer](https://www.bleepingcomputer.com/news/security/ex-school-district-employee-jailed-for-hacks-on-former-employer/)

Ezekiel Dean Potter, 34, a former senior IT support specialist at the Saydel Community School District (Des Moines, Iowa), was sentenced on 2026-06-11 to 21 months in prison and ordered to pay $59,668.81 in restitution. After leaving the district in April 2023, Potter retained valid administrative credentials and conducted a continuing campaign for the next ~21 months that deleted the district's Facebook page, wiped Apple School Manager records (locking out MacBook/iPad management for roughly a week), deleted nine Gmail accounts of current and former employees including the superintendent and IT director, and disrupted Schoology learning-management access. Investigators traced source IPs to Potter's subsequent employers (Casey's Store Support Center; The Printer Inc.) and recovered a USB drive containing spreadsheets of Saydel credentials. Potter switched to a commercial VPN after receiving Google security alerts mid-campaign. He pleaded guilty in January 2026 under the CFAA without a plea agreement. This is a textbook valid-accounts insider-threat case relevant to any organisation with shared admin tenancy (Google Workspace, Apple School Manager, GoDaddy).

Affected sector: K-12 education; broadly relevant to any SMB/SME with retained-credential exposure.

#### Indicators of Compromise

```
ATT&CK:           T1078 (Valid Accounts)
Behavioural TTP:  Post-employment use of admin credentials across Google Workspace,
                  Apple School Manager, Schoology, GoDaddy
Pivot artefact:   Source IPs traced to subsequent employer networks
Physical artefact: USB drive containing victim credential spreadsheets
```

> **SOC Action:** Within 7 days, audit all Google Workspace and Apple School Manager super-admin / school-admin accounts for active sessions, recovery emails, and app passwords belonging to terminated staff in the last 24 months; force-reset where ambiguity exists. Confirm offboarding runbooks require revocation of recovery codes and 2FA backup devices, not just primary password reset. Hunt for admin-action audit log entries (account deletions, password resets, role changes) sourced from non-corporate IP ranges over the trailing 90 days.

### 3.4 Telegram Proxy Cluster (`@Turbotelproxy`) — Tracking, Not Acting

**Source:** Telegram (channel name redacted)

Seven near-identical posts from a single Telegram MTProto-proxy channel were ingested in the period (IPs `87.248.129.197`–`87.248.129.204`, port 443). The correlation engine flagged the cluster as a possible phishing / anonymisation infrastructure pivot (ATT&CK T1566 shared with the ShinyHunters report), but the standalone signal is low — these channels are routinely used by Iranian and Russian-speaking users to bypass Telegram blocking and the IP range belongs to a UK hosting provider that has been associated with proxy traffic for years. No payload, no lure, no victim is named in any of the seven posts. Included for situational awareness only.

#### Indicators of Compromise

```
MTProto proxy IPs: 87[.]248[.]129[.]197 – 87[.]248[.]129[.]204:443
ATT&CK:            T1566 (Phishing) — correlation engine inference
```

> **SOC Action:** Add the `87.248.129.197/29` range to a watch-list (not a block-list — this is benign-leaning traffic for many users); if your environment has a defensible reason to forbid Telegram MTProto proxies (regulated workloads, classified environments), apply egress controls on TCP/443 to that range and alert on resolution of `t.me` from corporate endpoints.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Ransomware groups targeting critical sectors and using advanced TTPs | Charisma Media By securotrop; coe.int By shinyhunters; Ex-school district employee jailed for hacks on former employer |
| 🟡 **MEDIUM** | Increased use of Telegram for distributing proxy services potentially linked to malicious activities | Four `@Turbotelproxy` MTProto-proxy posts on IPs in `87.248.129.0/24` |

(Yesterday's earlier correlation batches — IDs 171 and 172, run before the daily reporting window — also produced trends on `ShadowByt3$` ransomware activity, `Coinbase Cartel` RaaS targeting, `3AM` double extortion, and the `CVE-2026-11822` SQLite memory-corruption / `CVE-2026-40034` gitoxide command-injection cluster. None of those source reports landed inside the 24-hour reporting window for this brief.)

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (76 reports, last 30 days) — Persistent RaaS operator; not seen in yesterday's window but remains the highest-volume actor pipeline-wide.
- **The Gentlemen** (51 reports) — Second-tier RaaS; no new posts in the reporting window.
- **DragonForce** (41 reports) — Active RaaS, sustained tempo into mid-June.
- **Akira** (33 reports) — RaaS continuing to publish at a steady cadence.
- **TeamPCP** (25 reports) — Mid-tier RaaS.
- **Nightspire** (22 reports) — Mid-tier RaaS.
- **Nova** (22 reports) — Mid-tier RaaS.
- **ShinyHunters** (20 reports) — **Active in the reporting window** — coe.int added.
- **Lockbit5** (20 reports) — Successor-branded LockBit operation, mid-tier volume.
- **Stormous** (19 reports) — Active mid-tier RaaS.

### Malware Families

- **RansomLook** (107 reports) — Aggregator/tracking source rather than a malware family per se; large mention count reflects how much of the pipeline is leak-site monitoring.
- **Tox1** (33 reports) — Tox client artefact, used by leak-site operators for negotiations.
- **Tox** (22 reports) — Same family — **mentioned in yesterday's Charisma Media report**.
- **Other1** (24 reports) — Unclassified leak-site post bucket.
- **Akira ransomware** (17 reports) — Encryptor binary tracking.
- **Shai-Hulud** (12 reports) — Active in recent windows; no posts in this reporting period.
- **Akira** (12 reports) — Family alias.
- **Mini Shai-Hulud** (12 reports) — Smaller variant tracking.
- **RALord** (12 reports) — Less common RaaS lineage.
- **Nova** (11 reports) — Family alias.

(Trending vulnerabilities returned no new CVEs in the reporting window; the pipeline-wide top entries — `CVE-2026-0300`, `CVE-2026-35616`, and several 2012–2013 legacy Android kernel CVEs — relate to earlier ingest batches and are not actionable from this brief.)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Unknown / Telegram OSINT | 8 | — | Single-channel `@Turbotelproxy` MTProto-proxy posts; channel URL withheld per editorial policy. |
| RansomLook | 2 | [link](https://www.ransomlook.io/) | Primary coverage of ShinyHunters and Charisma Media leak-site activity. |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/) | Insider-threat sentencing report (Saydel Community School District). |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** No items — there are no critical CVEs, in-the-wild exploits, or KEV additions in the reporting window that require same-day action. Treat the absence as opportunity to clear backlog from the prior 72 hours (the 2026-06-13 06:54 UTC batch flagged a SQLite FTS5 memory-corruption CVE and a gitoxide command-injection CVE worth verifying patch coverage on).
- 🟠 **SHORT-TERM:** For any organisation with Council of Europe partner relationships, pre-stage phishing detection rules covering inbound mail referencing `coe.int`, ShinyHunters, or the `onionmail.com` contact address before any sample data publication. For media-sector tenants, validate Tox-client / Tox-DHT egress detections in EDR.
- 🟠 **SHORT-TERM:** Audit Google Workspace and Apple School Manager (or analogue SaaS admin consoles) for active sessions, recovery emails, and app passwords belonging to terminated employees over the last 24 months. The Saydel case shows valid-credential abuse continuing 21 months after offboarding — confirm your offboarding runbook revokes recovery codes and 2FA backup devices, not just primary passwords.
- 🟡 **AWARENESS:** Add `87.248.129.197/29` to a watch-list for Telegram MTProto-proxy traffic. Block-list only if regulated workload posture requires it; otherwise treat as low-signal background noise.
- 🟢 **STRATEGIC:** Use the quiet day to test ransomware tabletop scenarios against the four most active leak-site operators (Qilin, The Gentlemen, DragonForce, Akira) and validate offline-immutable backup recovery time objectives. Pipeline-wide entity trending shows these are the actors most likely to drive your next incident.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 11 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
