---
layout: post
title:  "CTI Daily Brief: 2026-06-29 - ShinyHunters Oracle PeopleSoft Zero-Day Breaches Hit Nissan and NAIC; Embargo and Payoutsking Ransomware Active"
date:   2026-06-30 20:05:00 +0000
description: "ShinyHunters exploited an Oracle PeopleSoft zero-day to breach Nissan and the NAIC. Embargo RaaS and Payoutsking ransomware posted new victims. No critical-rated reports for the period; four high-severity items dominate the brief."
category: daily
tags: [cti, daily-brief, shinyhunters, embargo, payoutsking, oracle-peoplesoft]
classification: TLP:CLEAR
reporting_period: "2026-06-29"
generated: "2026-06-30"
severity: high
draft: true
report_count: 8
sources:
  - RansomLock
  - BleepingComputer
  - BellingCat
  - SANS
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-29 (24h) | TLP:CLEAR | 2026-06-30 |

## 1. Executive Summary

Eight reports were ingested across five sources for the 24-hour period ending 2026-06-29. The dominant theme is exploitation of an Oracle PeopleSoft zero-day by the ShinyHunters extortion group, which has now produced confirmed breaches at Nissan (employee data) and the National Association of Insurance Commissioners (publicly available data, outdated logs, and configuration files). Ransomware-as-a-service activity continues unabated, with Embargo RaaS naming a North American trucking victim and Payoutsking posting a new victim via its Tox-based negotiation channel. No CISA KEV additions or confirmed in-the-wild exploitation of new CVEs were reported in the dataset for this period, but the AI correlation engine flagged the Oracle PeopleSoft zero-day exploitation chain as the period's only critical-risk trend.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None this period |
| 🟠 **HIGH** | 4 | ShinyHunters/Oracle PeopleSoft (Nissan, NAIC); Embargo RaaS; Payoutsking ransomware |
| 🟡 **MEDIUM** | 1 | Qilin RaaS new victim (Kunert Fashion) |
| 🟢 **LOW** | 0 | None this period |
| 🔵 **INFO** | 3 | SANS ISC Stormcast; BellingCat Venezuela earthquake imagery; Wired Meta contractor story |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters Exploit Oracle PeopleSoft Zero-Day — Nissan and NAIC Confirm Breaches

**Source:** [BleepingComputer (Nissan)](https://www.bleepingcomputer.com/news/security/nissan-discloses-employee-data-breach-linked-to-oracle-zero-day-attacks/), [BleepingComputer (NAIC)](https://www.bleepingcomputer.com/news/security/naic-says-public-data-stolen-in-shinyhunters-peoplesoft-breach/)

Nissan disclosed a data breach affecting current and former employees after threat actors exploited an Oracle PeopleSoft zero-day vulnerability in a data-theft campaign attributed to the ShinyHunters extortion group. The National Association of Insurance Commissioners (NAIC) separately confirmed that ShinyHunters breached its environment by exploiting the same Oracle PeopleSoft zero-day; NAIC says the stolen content consisted of publicly available data, outdated logs, and configuration files. The CognitiveCTI correlation engine linked the two reports at 0.90 confidence on the shared actor "ShinyHunters" and at 0.70 confidence on shared TTP T1071.001 (Application Layer Protocol: Web Protocols). Affected technology is Oracle PeopleSoft HCM/applications stack; affected sectors include automotive manufacturing and insurance regulation.

MITRE ATT&CK techniques referenced in the entity data: **T1190** (Exploit Public-Facing Application), **T1071.001** (Application Layer Protocol: Web Protocols), **T1566** (Phishing), **T1193** (System Information Discovery).

> **SOC Action:** Inventory all internet-facing Oracle PeopleSoft instances and pull access logs for the past 30 days. Hunt for anomalous outbound HTTP/HTTPS sessions from PeopleSoft application servers to non-Oracle destinations, unexpected admin authentications, and bulk record exports from HCM modules. If your organisation runs PeopleSoft and has not yet applied Oracle's most recent Critical Patch Update, prioritise patching above all other queued work this week. Add ShinyHunters known infrastructure to perimeter blocklists and brief HR/legal on potential employee-data notification obligations.

### 3.2 Embargo RaaS Posts North American Trucking Victim

**Source:** [RansomLook (Embargo)](https://www.ransomlook.io//group/embargo)

Embargo Ransomware-as-a-Service named www.maytrucking.com on its Tor-based leak site. Embargo is a closed-affiliate RaaS first observed in May 2024, operating a double-extortion model using a Rust-based payload that performs AES-256 + RSA-4096 file encryption, deletes volume shadow copies, and disables recovery features (MITRE **T1486** Data Encrypted for Impact, **T1490** Inhibit System Recovery, **T1071.001** Application Layer Protocol: Web Protocols). External analyses cited by RansomLook include SentinelOne, Zscaler, and Trend Micro. Embargo has historically targeted finance, manufacturing, and professional services across North America, Europe, and Asia; the addition of a US logistics firm extends that pattern into transportation.

#### Indicators of Compromise
```
Tor leak site (defanged): hxxp[:]//embargobe3n5okxyzqphpmk3moinoap2snz5k6765mvtkk7hhi544jid[.]onion/
Tor API endpoint (defanged): hxxp[:]//embargobe3n5okxyzqphpmk3moinoap2snz5k6765mvtkk7hhi544jid[.]onion/api/blog/get
Ransom note filenames: HOW_TO_RECOVER_FILES.txt, HOW_TO_RECOVER_FILES_2.txt
Tox ID: 9500B1A73716BCF40745086F7184A33EA0141B7D3F852431C8FDD2E1E8FAF9277E9FDC117B47
```

> **SOC Action:** Query EDR for `vssadmin delete shadows`, `wmic shadowcopy delete`, and `wbadmin delete catalog` execution by non-administrative accounts — these are the recovery-disabling commands characteristic of Embargo payloads. Block the Tor onion domains above at the egress proxy. Logistics and transportation organisations should validate offline, immutable backups for OT/dispatch systems and confirm an out-of-band incident-comms channel exists in case the corporate email tenant is encrypted.

### 3.3 Payoutsking Ransomware — New Victim Posted, Non-RaaS Model

**Source:** [RansomLook (Payoutsking)](https://www.ransomlook.io//group/payoutsking)

The Payoutsking group posted a new (redacted) victim on 2026-06-29, bringing its all-time post count to 111 across two years of observed activity. Payoutsking explicitly states it is not a Ransomware-as-a-Service operation and does not accept affiliates; it communicates exclusively via the Tox messaging protocol and deploys ransom notes named `readme_locker.txt`. Historical victims observed across engineering, food production, technology, and manufacturing in North America and Europe. The CognitiveCTI engine correlated this report with the Wired Meta-contractor story at 0.70 confidence on shared sector (technology).

#### Indicators of Compromise
```
Tor negotiation site (defanged): hxxp[:]//payoutsgn7cy6uliwevdqspncjpfxpmzgirwl2au65la7rfs5x3qnbqd[.]onion/
Ransom note filename: readme_locker.txt
Tox IDs:
  535F403A2EA2DC71A392E18D7DB77FEF70845C0B7E5B9114CD30D301870304379C3547E324E2
  E37F4D443B7FECE0E9775E82D6DC3B304890F80BA03F5101DFD43B2C249AD625CF00EC8B57D4
```

> **SOC Action:** Add `readme_locker.txt` to file-creation telemetry alerts on file servers and end-user workstations. Block the Payoutsking onion address above at the egress proxy. Because Payoutsking favours victims in engineering, food production, and small-to-mid-market technology firms, organisations in those verticals should validate that domain controllers and backup hosts are not directly reachable from general workstation VLANs.

### 3.4 Qilin RaaS — Continued Pressure on Mid-Market Targets

**Source:** [RansomLook (Qilin)](https://www.ransomlook.io//group/qilin)

The Qilin Ransomware-as-a-Service group posted Kunert Fashion as a new victim. Qilin is the second-most-active threat-actor entity in the pipeline over the past 30 days (76 reports, second only to The Gentlemen at 85). The group operates a degraded but persistent Tor leak network, uses Jabber and Tox for affiliate communications, and continues to claim victims across education, healthcare, manufacturing, and consumer goods. No new TTPs were observed for this individual posting.

> **SOC Action:** For mid-market consumer-goods and manufacturing organisations: validate that VPN appliances and external-facing RDP have MFA enforced and that NetScaler/Citrix/Fortinet edge devices are patched to current. Qilin affiliates have repeatedly used unpatched edge appliances as initial-access vectors in prior reporting. Maintain the Qilin known-infrastructure feed inside SIEM watchlists.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in widely used enterprise software | NAIC and Nissan breaches via Oracle PeopleSoft zero-day (ShinyHunters) |
| 🟠 **HIGH** | Increased activity of ransomware-as-a-service groups targeting critical sectors with sophisticated TTPs | Embargo RaaS (maytrucking.com); Payoutsking; correlation batch landscape summary references The Gentlemen RaaS growth |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (85 reports) — RaaS group introducing new ransomware variants targeting large corporations and critical infrastructure globally (per batch landscape summary)
- **Qilin** (76 reports) — High-volume RaaS with degraded but persistent Tor leak infrastructure
- **Deadlock** (55 reports) — Active ransomware operator
- **Lockbit5** (39 reports) — Continued posting activity
- **Akira** (30 reports) — Active ransomware operator
- **DragonForce** (27 reports) — RaaS posting multi-sector victims
- **ShinyHunters** (22 reports) — Extortion group exploiting Oracle PeopleSoft zero-day (this period's headline actor)
- **Nova** (20 reports) — Active operator
- **Nightspire** (18 reports) — Active operator

### Malware Families

- **RansomLook** (140 reports) — Aggregator-tagged entity reflecting RansomLook source ingestion volume, not a malware family in itself
- **Tox1 / Tox** (64 + 44 reports) — Messaging protocol used by Payoutsking and other groups for victim negotiation
- **Akira ransomware** (15 reports)
- **Lockbit5** (14 reports)
- **Qilin** (12 reports)
- **Nova** (10 reports)
- **Deadlock** (10 reports)
- **Anubis ransomware** (9 reports)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 3 | [link](https://www.ransomlook.io/) | Embargo, Payoutsking, Qilin leak-site postings |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/nissan-discloses-employee-data-breach-linked-to-oracle-zero-day-attacks/) | Primary coverage of Oracle PeopleSoft zero-day / ShinyHunters breaches |
| BellingCat | 1 | [link](https://www.bellingcat.com/news/2026/06/29/satellite-imagery-shows-scale-of-venezuela-earthquake-damage/) | OSINT/geospatial, non-cyber |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33112) | Daily ISC Stormcast; threat level green |
| Wired Security | 1 | [link](https://www.wired.com/story/meta-contractors-pretending-to-be-teens-chatbot-testing/) | Meta-contractor chatbot-testing story |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch and inventory Oracle PeopleSoft. Apply Oracle's most recent Critical Patch Update on every internet-facing PeopleSoft instance and pull 30 days of authentication and HTTP egress logs to hunt for ShinyHunters-style data exfiltration (T1190 → T1071.001). This recommendation traces to Items 3.1 and Trend 4 (critical).
- 🟠 **SHORT-TERM:** Block ransomware leak-site and negotiation infrastructure at the egress proxy — specifically the defanged Embargo and Payoutsking onion addresses in Items 3.2 and 3.3. Add `readme_locker.txt` and `HOW_TO_RECOVER_FILES*.txt` to file-creation alerting rules across endpoint and file-server telemetry.
- 🟠 **SHORT-TERM:** EDR hunt for recovery-disabling commands (`vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`) invoked by non-administrative accounts. Triggered by the Embargo TTP profile (T1490) in Item 3.2.
- 🟡 **AWARENESS:** Brief HR, legal, and external-comms teams that ShinyHunters PeopleSoft activity has produced confirmed employee-data exposure at a major OEM (Nissan). Organisations running PeopleSoft for HCM should rehearse a 72-hour notification plan in case they are next in the campaign.
- 🟢 **STRATEGIC:** RaaS pressure on mid-market verticals (transportation, consumer goods, food production, engineering) is the dominant pattern across this period and the prior two correlation batches. Programme-level investment in edge-appliance patch SLA, MFA on all remote access, and offline-immutable backups remains the highest-leverage defensive posture against the Embargo/Payoutsking/Qilin/The Gentlemen cluster.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 8 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
