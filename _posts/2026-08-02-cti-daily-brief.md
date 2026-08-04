---
layout: post
title:  "CTI Daily Brief: 2026-08-02 - Qilin, Coinbase Cartel and Gunra Drive Ransomware Leak-Site Surge; No CISA KEV Additions Observed"
date:   2026-08-03 14:30:00 +0000
description: "23 ransomware leak-site reports from RansomLook: Qilin posts 7 new victims, Coinbase Cartel names four targets with multi-million demands, and Gunra's double-extortion model is flagged as a critical trend. A separate correlation cycle surfaces macOS AMOS stealer activity and MediaWiki RCE CVE-2026-58025."
category: daily
tags: [cti, daily-brief, qilin, coinbase-cartel, gunra]
classification: TLP:CLEAR
reporting_period: "2026-08-02"
generated: "2026-08-03"
draft: false
report_count: 23
severity: high
sources:
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-08-02 (24h) | TLP:CLEAR | 2026-08-03 |

## 1. Executive Summary

Yesterday's collection comprised 23 reports, all sourced from RansomLook leak-site monitoring, making ransomware the sole theme of the reporting period. Qilin was the most active actor with seven newly named victims, while the Coinbase Cartel named four organisations with published demands ranging from $10.5M (MIM Fertility) to $500M (M. B. Kahn Construction Co.). The AI correlation pipeline elevated Gunra's double-extortion campaign to a **critical** trend on the strength of two new manufacturing/hospitality victims and its known Linux variant targeting critical infrastructure. Play (Hive-affiliated, intermittent encryption) and Inc Ransom (which listed quantum-computing firm quantinuum.com) also posted fresh victims. A separate earlier correlation cycle surfaced macOS **AMOS (Atomic) stealer** phishing activity alongside MediaWiki deserialization flaw **CVE-2026-58025** (RCE via malicious log imports). No confirmed in-the-wild exploitation of a named CVE and no CISA KEV additions appeared in this period's pipeline data.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None at report level; Gunra double-extortion flagged as a critical correlation *trend* |
| 🟠 **HIGH** | 21 | Qilin (7), Coinbase Cartel (4), Play (3), Gunra (2), Krybit (3), Inc Ransom, Gammax |
| 🟡 **MEDIUM** | 1 | Krybit listing of countrymotors.com.mx (Mexican dealership) |
| 🟢 **LOW** | 0 | No data available for this period |
| 🔵 **INFO** | 1 | Krybit platform activity note (buzztrading104.co.za) |

## 3. Priority Intelligence Items

### 3.1 Gunra Ransomware — Double-Extortion Campaign Flagged Critical
**Source:** [RansomLook — Gunra](https://www.ransomlook.io//group/gunra)

The correlation pipeline rated Gunra's activity a **critical** trend. Gunra is an emerging group first identified in April 2025 that runs a classic double-extortion model — encrypting data and threatening publication on a Tor-hosted leak site. It has developed a Linux variant and, per external analysis referenced in the report (Trend Micro, CYFIRMA), has targeted critical infrastructure across manufacturing, healthcare, IT, real estate, agriculture and consulting in Brazil, Japan, Canada, Turkey, South Korea, Taiwan, Egypt and the U.S. Two new victims were posted on 2026-08-02: Weilhotel and Siam Stabilizers and Chemicals Co., Ltd. (SSC). Observed techniques: `T1485` (Data Encrypted for Impact), `T1496` (Resource Hijacking), `T1567.002` (Exfiltration Over C2/Web Service).

#### Indicators of Compromise
```
Leak site (active):  hxxp[://]lgiil72vkmdtbc3qv4tyq6wedyjxqr2qd4ze7xl2cxgerdnymxj7soqd[.]onion (70% uptime 30d)
RaaS panel (active): hxxp[://]raas.lgiil72vkmdtbc3qv4tyq6wedyjxqr2qd4ze7xl2cxgerdnymxj7soqd[.]onion (63% uptime 30d)
Ransom notes:        R3ADM3.txt, R3ADM3_2.txt
Contact (Proton):    a00f105546345756@proton[.]me
Contact (Tox):       2507312EC10BB44ED9DAA04E3C5C27E8C13154649B1A02E73ACFAE1681EE0208D05133A8FB22
```

> **SOC Action:** Alert on creation of files named `R3ADM3.txt`/`R3ADM3_2.txt` across file servers and endpoints. For Linux estates, hunt for mass file-modification bursts and unexpected outbound Tor/proxy connections indicative of exfiltration (`T1567.002`); prioritise manufacturing and OT-adjacent hosts given Gunra's critical-infrastructure focus.

### 3.2 Qilin (aka Agenda) — Seven New Victims, Highest Volume
**Source:** [RansomLook — Qilin](https://www.ransomlook.io//group/qilin)

Qilin, a mature Ransomware-as-a-Service operation also tracked as Agenda, was the single most active actor with seven new victims posted on 2026-08-02: The Saturday Evening Post, Commercial Furniture Interiors, Dienst Pack Systems, Ceragres, Pointe Property Group, Schreiner Trockenbau GmbH and Wire Products. Pipeline records show 2,062 all-time posts and 123 in the last 30 days, confirming sustained operational tempo despite most infrastructure showing low uptime. Associated techniques: `T1566` (Phishing), `T1189` (Spearphishing), `T1485` (Data Encrypted for Impact), `T1036` (Masquerading). Affiliate handle "Ben" is referenced in the leak-site data.

#### Indicators of Compromise
```
Contact (Jabber):    qilin@exploit[.]im
Contact (Tox):       7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
Ransom notes:        README-RECOVER-[rand].txt, DtMXQFOCos-RECOVER-README.txt
Exfil FTP servers:   85.209.11[.]49, 188.119.66[.]189, 176.113.115[.]97, 176.113.115[.]209,
                     185.39.17[.]75, 185.196.10[.]52, 185.196.10[.]19, 64.176.162[.]76,
                     208.76.221[.]205, 185.196.8[.]92
Suspicious host:     31.41.244[.]100
Active leak mirror:  hxxp[://]ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion (67% uptime 30d)
```

> **SOC Action:** Block/alert outbound FTP and HTTP to the listed exfiltration IPs at the egress firewall and proxy; these are Qilin `dataShare` staging servers. Hunt EDR for `README-RECOVER-*` note creation and for rclone/WinSCP/FTP client execution spawning from non-standard directories. Treat inbound phishing with attachment lures as the likely initial vector (`T1566`).

### 3.3 Coinbase Cartel — Multi-Sector Expansion, High-Value Demands
**Source:** [RansomLook — Coinbase Cartel](https://www.ransomlook.io//group/coinbase%20cartel)

The Coinbase Cartel RaaS named four new victims on 2026-08-02 with explicit demand figures published on its leak site: M. B. Kahn Construction Co. (Construction — $500M), Xs Cad (Architecture — $26.9M), CEN and Cenelec (Membership Organizations — $21.9M) and MIM Fertility (Healthcare Software — $10.5M). The group spans construction, healthcare, real estate, manufacturing, financial software and architecture, and communicates via Atomic Mail, Tox, Session and SimpleX. Techniques observed across the four reports: `T1566` (Phishing), `T1204` (User Execution), `T1485` (Data Encrypted for Impact), `T1071.001` (Application Layer Protocol: Web Protocols).

#### Indicators of Compromise
```
Contact (Mail):      coinbasecartel@atomicmail[.]io
Contact (Tox):       58041B45371485934F798C77F2F9705DA735F28AC9EBA2A19B4C9DBAF462802B88E33CEF482A
Contact (Session):   056999a0f3681d5deddb6243e9387c9b9a310f1bacc2a4faa1b9085a867887fb22
Contact (SimpleX):   hxxps[://]simplex[.]chat/contact/#/?v=2-7&smp=smp8.simplex.im&a=ie-SNS7kf7I0QN4162sdo7A-X5WpSEoPEtsYueFPtZQ
Primary leak site:   hxxp[://]fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd[.]onion (73% uptime 30d)
```

> **SOC Action:** For construction, healthcare-software and membership-organisation clients, proactively check for unauthorised access and data staging. Alert on SimpleX/Session/Tox client artefacts on corporate endpoints — these encrypted-messenger installs are atypical in enterprise environments and align with this actor's negotiation channels. Reinforce user-execution defences (`T1204`): block execution from user temp/download paths.

### 3.4 Play Ransomware (Hive-Affiliated) — Intermittent Encryption
**Source:** [RansomLook — Play](https://www.ransomlook.io//group/play)

Play posted three victims on 2026-08-02 — The Butcher Brothers, Sigma Plastics Group and Cambridge Management — and the pipeline correlated the latter two at 0.95 confidence on shared actor (Hive-affiliates), malware (Play Ransomware) and TTPs. Play uses intermittent encryption to evade detection tools that inspect encrypted-traffic volume. Techniques: `T1071.001` (Web Protocols), `T1486` (Data Encrypted for Impact). Contact addresses are GMX webmail accounts.

#### Indicators of Compromise
```
Ransom notes:        ReadMe.txt, play.txt, ReadMe2.txt
Contact (Mail):      marinachin@gmx[.]de, Nicolebackserami3@gmx[.]net, reinaldo-jukes092@gmx[.]com
Active file servers: hxxp[://]p2qzf3rfvg4f74v2ambcnr6vniueucitbw6lyupkagsqejtuyak6qrid[.]onion (80% uptime 30d)
                     hxxp[://]x6zdxw6vt3gtpv35yqloydttvfvwyrju3opkmp4xejmlfxto7ahgnpyd[.]onion (77% uptime 30d)
```

> **SOC Action:** Tune ransomware canaries and behavioural EDR to detect *partial*/intermittent file encryption rather than relying on high-entropy full-file signatures. Alert on creation of `play.txt`/`ReadMe.txt` and on outbound connections to GMX from servers that have no business emailing.

### 3.5 macOS AMOS Stealer & MediaWiki CVE-2026-58025 (Earlier Correlation Cycle)
**Source:** RansomLook pipeline correlation batch #264 (2026-08-02 06:16 UTC)

A separate, earlier correlation cycle (batch #264) — distinct from the leak-site collection above — flagged a **high**-risk trend: increased targeting of macOS users via phishing that delivers the **Atomic macOS Stealer (AMOS)** through malicious websites, correlated (0.70) with **CVE-2026-58025**, a MediaWiki deserialization flaw described as enabling remote code execution via malicious log imports. The shared thread is `T1204` (User Execution). Note: underlying primary-source reports and IOCs for these items were not present in this period's report set, so details are limited to the correlation summary. No IOCs available for this item.

> **SOC Action:** For macOS fleets, hunt for AMOS behaviours — `osascript` password-prompt phishing, spawning of unsigned binaries from `~/Downloads`, and credential/keychain access from newly executed apps (`T1204`). For any MediaWiki instances, inventory versions and monitor vendor advisories for CVE-2026-58025 patch availability; restrict access to log-import functionality pending confirmation.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Gunra ransomware's double-extortion model affecting various global sectors | Weilhotel; Siam Stabilizers and Chemicals Co./SSC (batch #265) |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors globally (Qilin) | 7 Qilin victims incl. Dienst Pack Systems, The Saturday Evening Post, Ceragres, Pointe Property Group (batch #265) |
| 🟠 **HIGH** | Coinbase Cartel expansion into multiple sectors with sophisticated TTPs | M. B. Kahn Construction, MIM Fertility, CEN and Cenelec, Xs Cad (batch #265) |
| 🟠 **HIGH** | Increased targeting of macOS users via phishing and software-vuln exploitation | AMOS stealer infection; CVE-2026-58025 MediaWiki (batch #264) |

Two correlation cycles ran in the period: batch #265 (26 reports, 18 correlation entries) and batch #264 (3 reports, 2 entries). Play victims Sigma Plastics Group and Cambridge Management were linked at 0.95 confidence via Hive-affiliation and shared TTPs.

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (118 reports) — Most active RaaS in the pipeline; 7 new victims yesterday. First seen 2026-07-06.
- **The Gentlemen** (115 reports) — High long-run volume; no new posts in this period.
- **DragonForce** (42 reports) — Sustained activity; last seen 2026-07-31.
- **Everest** (21 reports) — Steady leak-site presence.
- **Akira** (21 reports) — Persistent RaaS operator.
- **Inc Ransom** (18 reports) — Listed quantum-computing firm quantinuum.com yesterday.

### Malware Families
- **RansomLook** (160 reports) — Parser/tracking label associated with leak-site scraping; dominant tag artefact, not a payload.
- **DragonForce ransomware** (14 reports) — Active RaaS payload.
- **RALord** (14 reports) — Recurring family.
- **The Gentlemen Ransomware** (12 reports) — Tied to the high-volume actor above.
- **Chaos Ransomware** (12 reports) — Ongoing presence.
- **Play Ransomware** (2 reports this period) — Hive-affiliated, intermittent encryption.

*Note: Vulnerability entity data was sparse — only three CVEs (CVE-2023-2868, CVE-2024-42009, CVE-2025-49113) are indexed pipeline-wide, each with a single mention dated 2026-07-07, and none tie to yesterday's reports. Trend-snapshot data returned empty for this period.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 23 | [link](https://www.ransomlook.io) | Sole source; ransomware leak-site monitoring. All 23 reports are actor victim-postings. No mainstream vendor, government, or news-feed reporting appeared in this period's pipeline. |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Block the ten Qilin `dataShare` exfiltration IPs (85.209.11[.]49, 188.119.66[.]189, 176.113.115[.]97/.209, 185.39.17[.]75, 185.196.10[.]52/.19, 64.176.162[.]76, 208.76.221[.]205, 185.196.8[.]92) at egress and alert on any historical connections — Qilin was the top actor with active infrastructure (§3.2).
- 🟠 **SHORT-TERM:** Deploy detections for the ransom-note filenames across all four active families — `R3ADM3.txt` (Gunra), `README-RECOVER-*` (Qilin), `play.txt`/`ReadMe.txt` (Play) — and prioritise manufacturing/construction/healthcare clients named in the Gunra and Coinbase Cartel trends (§3.1, §3.3).
- 🟠 **SHORT-TERM:** Tune EDR/canaries for intermittent (partial) encryption to catch Play, which specifically uses this technique to evade volume-based detection (§3.4).
- 🟡 **AWARENESS:** Brief macOS users on AMOS phishing lures and inventory any MediaWiki deployments against CVE-2026-58025 pending patch confirmation; treat as watch-items given limited primary-source corroboration (§3.5).
- 🟢 **STRATEGIC:** Source coverage collapsed to a single feed (RansomLook) for this period — validate that Microsoft, SANS, BleepingComputer and other collectors are ingesting correctly, as leak-site-only visibility understates non-ransomware threats.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 23 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
