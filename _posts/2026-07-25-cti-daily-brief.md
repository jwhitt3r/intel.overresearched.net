---
layout: post
title:  "CTI Daily Brief: 2026-07-25 - Exfilsquad Mass Leak Hits Microsoft & Zenith Bank, Global Secret Group Extortion Spree, Qilin RaaS Critical"
date:   2026-07-26 20:36:19 +0000
description: "49 reports across 3 sources, ransomware leak-site activity dominant. Exfilsquad dumps data from Microsoft, Zenith Bank, Frontier Airlines and 11 others with an Aug 5 deadline; Global Secret Group posts 19 fresh victims; Qilin RaaS flagged critical; active scanning for ESAFENET CDG default logins; Steam ClickFix delivers XMRig."
category: daily
tags: [cti, daily-brief, exfilsquad, global-secret-group, qilin]
classification: TLP:CLEAR
reporting_period: "2026-07-25"
generated: "2026-07-26"
draft: true
report_count: 49
severity: high
sources:
  - RansomLook
  - BleepingComputer
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-25 (24h) | TLP:CLEAR | 2026-07-26 |

## 1. Executive Summary

The pipeline processed 49 reports across 3 sources in the last 24 hours, with ransomware leak-site activity accounting for nearly all of it (46 of 49 reports from RansomLook). The dominant story is data-leak extortion: the actor **Exfilsquad** posted 14 fresh victims — including Microsoft (claimed 130 GB / ~8M records), Nigeria's Zenith Bank (claimed 874 GB / ~90M records), Frontier Airlines, Allstate, TaylorMade, the UK Department for Education, and the UK Police National Legal Database — all carrying a 2026-08-05 payment deadline. In parallel, **Global Secret Group** listed 19 victims in a single burst, headlined by Chinese surveillance manufacturer Uniview Technologies (claimed 1.5 TB including employee passport data and alleged government contracts) and US fuel trader Novum Energy. The AI correlation engine again elevated **Qilin's** RaaS operations to a critical-risk trend, and DragonForce, Chaos, Arcus Media, Inc Ransom and M3rx all added postings. On the vulnerability side, SANS ISC reported active internet scanning for default logins on the ESAFENET CDG 3 document-management system, and BleepingComputer detailed a ClickFix campaign on Steam forums delivering XMRig cryptominers. No CISA KEV additions and no confirmed in-the-wild exploitation of a new CVE appeared in this period; the ESAFENET default-credential scanning is the only active exploitation-adjacent activity reported.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None rated critical at report level (Qilin RaaS flagged critical at trend level) |
| 🟠 **HIGH** | 47 | Exfilsquad mass leak; Global Secret Group 19-victim burst; Qilin/DragonForce/Chaos/Arcus Media/M3rx/Inc Ransom postings; ESAFENET default-login scanning |
| 🟡 **MEDIUM** | 1 | Steam forum ClickFix delivering XMRig cryptominers |
| 🟢 **LOW** | 1 | GitHub/PyPI add time-based Dependabot defenses against supply-chain attacks |
| 🔵 **INFO** | 0 | No data available for this period |

## 3. Priority Intelligence Items

### 3.1 Exfilsquad Mass Data-Leak Extortion — Microsoft, Zenith Bank, Frontier Airlines and 11 Others
**Source:** [RansomLook](https://www.ransomlook.io//group/exfilsquad)

The actor tracked as **Exfilsquad** published a large batch of victim listings on its leak site, each with a hard payment deadline of **2026-08-05**. Claimed volumes and record counts (as stated by the actor, unverified) include Microsoft (130 GB / ~8M records, described as PII, password hashes, authentication data, portal identities and internal service tickets), Zenith Bank Plc of Nigeria (874 GB / ~90M records including banking relationships and government identifiers), Frontier Airlines (43 GB / 2.4M records), TaylorMade & Sun Day Red golf (22 GB / 2M records including AI support chat transcripts), Allstate (15.1 GB / 657K records), the UK Department for Education (~600K Help Portal contact records), the UK Police National Legal Database (135K law-enforcement contact records), Newcastle University, District of Columbia Public Schools, City of Houston, City of Atlanta, Analog Devices, Viavi Solutions and Bonava. The correlation engine linked the Exfilsquad postings at 0.90 actor confidence and associated them with phishing (`T1566`) for initial access. Affected sectors span government, education, finance, banking, insurance, aviation and technology across the UK, US and Nigeria.

#### Indicators of Compromise
```
Actor: Exfilsquad
Leak site (100% 30d uptime): hxxp[:]//exfil5gqmbxrg6yky5aeitkdj7kfwxxjh3wxzrtlewjqi2x67o634iyd[.]onion/
Contact mail: exfilsquad[@]onionmail[.]org
Tox ID: 8F4BCBC804C3DB35112D0FCC0E8E02F48BD1F041E8395658A8E9D3E3D2A98C221362B3C3C93F
Extortion deadline: 2026-08-05
```

> **SOC Action:** If your organisation or a key supplier appears on the Exfilsquad list, activate incident response now and assume the claimed data is genuine until proven otherwise — force password resets and rotate any credentials or hashes that could have been exposed, and enforce MFA on all external services. Hunt for phishing-derived initial access (`T1566`) and anomalous bulk data staging/exfiltration in the weeks preceding the posting. Block the listed onion endpoint at egress and monitor for the actor's contact identifiers.

### 3.2 Global Secret Group — 19-Victim Extortion Burst Led by Uniview Technologies and Novum Energy
**Source:** [RansomLook](https://www.ransomlook.io//group/global%20secret%20group)

**Global Secret Group** posted 19 victims in a single burst (0.90 actor correlation confidence), threatening data leaks unless ransoms are paid. The two highest-impact claims are Chinese video-surveillance manufacturer **Uniview Technologies** — where the group alleges it holds 1.5 TB including passwords and passport documents for ~10,000 employees, full financial records, and "top-secret agreements between the company and other countries," plus footage from cameras deployed in prisons and hospitals — and Texas fuel trader **Novum Energy** (842 GB claimed). Other listed victims include OFS (furniture/logistics, Indiana), Portman Finance Group, Cold Front Distribution, Sinop Energia, Al Hayat/Pepsi, Farmers Mutual Fire Insurance and a veterinary hospital. Reported TTP is phishing (`T1566`) leading to data exfiltration. Sectors: energy, electronics/surveillance manufacturing, furniture/logistics, finance and retail across the US and China.

#### Indicators of Compromise
```
Actor: Global Secret Group
Leak site (100% 30d uptime): hxxp[:]//o5lsqyar7ox25z734k6zaxt2vf7bsyi4q5rturi5iyxzqo3ica7bjsad[.]onion/
```

> **SOC Action:** Organisations in the group's target verticals should audit external-facing services and VPN/remote-access exposure and enforce phishing-resistant MFA. Given the surveillance-footage and passport-data claims against Uniview, downstream customers of that vendor should assess exposure of any shared credentials or integration secrets. Monitor egress for the listed onion endpoint and hunt for large outbound transfers to unfamiliar infrastructure. Maps to `T1566` (Phishing).

### 3.3 Qilin RaaS — Critical-Rated Trend, Still the Most-Reported Actor Pipeline-Wide
**Source:** [RansomLook](https://www.ransomlook.io//group/qilin)

The correlation engine flagged **Qilin** (aka Agenda) as a **critical-risk trend**, tied to fresh victim postings including Universitatea de Vest „Vasile Goldiș" din Arad and Contacto Garantido. Qilin remains the single most-reported threat actor pipeline-wide (116 reports, first seen 2026-06-28) and operates a RaaS model using README-RECOVER-[rand].txt ransom notes and Jabber/Tox for negotiation. Its infrastructure is large but heavily degraded — 614 tracked file servers at roughly 1% average 30-day uptime, with only a handful of onion and FTP endpoints currently reachable. Affected sectors this cycle include education and business services.

#### Indicators of Compromise
```
Actor: Qilin (aka Agenda)
Active onion (73% uptime): hxxp[:]//ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
Active file server (83% uptime): hxxp[:]//kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion/
FTP C2: 85.209.11[.]49
FTP C2: 188.119.66[.]189
FTP C2: 176.113.115[.]97
FTP C2: 185.39.17[.]75
Jabber: qilin[@]exploit[.]im
Ransom note: README-RECOVER-[rand].txt
```

> **SOC Action:** Block the listed IPs and onion endpoints at egress and add `README-RECOVER-*.txt` filename patterns to EDR/file-integrity detection. Enforce MFA on remote access and audit VPN exposure. Maps to `T1486` (Data Encrypted for Impact) and `T1071.001` (Web Protocols).

### 3.4 DragonForce and Chaos RaaS Continue Multi-Sector Targeting
**Source:** [RansomLook — DragonForce](https://www.ransomlook.io//group/dragonforce), [RansomLook — Chaos](https://www.ransomlook.io//group/chaos)

**DragonForce** — the cartel-style RaaS previously linked to attacks on UK retailers M&S, Harrods and Co-op — posted Syntron Bioresearch and Deluxe Medical Supply (0.95 actor correlation), continuing its affiliate-driven, double-extortion operations across retail, government, logistics and manufacturing. Separately, **Chaos** (a 2025-era RaaS distinct from the older Chaos Ransomware Builder, known for the 69 GB Optima Tax Relief breach) posted Canadian retail-distribution firm remco.ca and targets Windows, ESXi, Linux and NAS platforms with configurable, partial-file encryption. Both groups use phishing, brokered credentials or vulnerability exploitation for initial access.

#### Indicators of Compromise
```
Actor: DragonForce
Leak blog (83% uptime): hxxp[:]//z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid[.]onion/blog
Active file server (87% uptime): hxxp[:]//dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd[.]onion
Tox ID: 1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856D90A65E99D20
Ransom notes: readme.txt, [rand].README.txt

Actor: Chaos
Leak site (90% uptime): hxxp[:]//hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd[.]onion/
Contact mail: Win88[@]thesecure[.]biz
Ransom note: readme.chaos.txt
```

> **SOC Action:** Block the listed onion endpoints at egress and add the ransom-note filenames to detection content. Given DragonForce's retail track record and Chaos's ESXi/Linux/NAS coverage, prioritise hardening of hypervisor management interfaces and NAS appliances, enforce offline/immutable backups, and validate segmentation. Maps to `T1486` (Data Encrypted for Impact), `T1189` (Drive-by Compromise) and `T1566` (Phishing).

### 3.5 Active Scanning for ESAFENET CDG 3 Default Logins
**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/33184)

SANS Internet Storm Center (handler Johannes Ullrich) reported active internet scanning targeting default credentials on the **ESAFENET CDG 3** (Content Data Guard) document-management and data-leakage-prevention product, which primarily serves the Chinese market. The scans submit the vendor's shipped default password against the `secadmin` account via `POST /CDGServer3/SystemConfig`; the product also has a history of SQL Injection and XSS flaws, with exploit tooling (a 2023 Nuclei template) publicly available. Threat level is rated green, but the activity indicates opportunistic exploitation of exposed instances (`T1190`).

#### Indicators of Compromise
```
Target product: ESAFENET CDG 3 (Content Data Guard)
Scanned endpoint: POST /CDGServer3/SystemConfig
Default account / password: secadmin / Est@Spc820
Weaknesses: default credentials, SQL Injection, XSS
```

> **SOC Action:** Identify any internet-exposed ESAFENET CDG instances, change the `secadmin` default password immediately, and remove management interfaces from public exposure (place behind VPN/allow-listing). Review web logs for `POST /CDGServer3/SystemConfig` requests and for the `secadmin`/`Est@Spc820` login attempt. Maps to `T1190` (Exploit Public-Facing Application).

### 3.6 Steam Forum ClickFix Attacks Deliver XMRig Cryptominers
**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers/)

Steam discussion forums are being abused in **ClickFix** attacks that masquerade as fixes for game and computer problems but instead lead users to download and execute the **XMRig** cryptominer, hijacking system resources for cryptocurrency mining. The lure relies on social engineering (`T1566`) and user execution of the fake "fix." Affected population: gamers and any endpoints where users act on forum-sourced troubleshooting instructions.

> **SOC Action:** Educate users not to paste/run commands or download "fixes" from forum posts. In EDR, hunt for browser or Explorer processes spawning script hosts (powershell.exe, mshta.exe, cmd.exe) followed by high sustained CPU usage indicative of mining, and block known XMRig pool domains at egress. Maps to `T1566` (Phishing), `T1204` (User Execution) and `T1496` (Resource Hijacking).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Qilin's persistent RaaS operations targeting multiple sectors globally with varied TTPs | Plitvička Jezera, Jubilee Jobs, The Myers Y Cooper, Principle Diagnostics, Guntert & Zimmerman, GURR (all "By qilin", batch 2026-07-25) |
| 🟠 **HIGH** | RaaS groups increasingly targeting multiple sectors globally | Deluxe Medical Supply & Syntron Bioresearch (dragonforce); UK Dept for Education & Microsoft (exfilsquad) |
| 🟠 **HIGH** | Phishing remains a prevalent TTP across ransomware campaigns | Universitatea de Vest (qilin); UK Dept for Education (exfilsquad); Al Hayat/Pepsi (global secret group) |
| 🟠 **HIGH** | Arcus Media RaaS using double-extortion across sectors | Brazer Ingenierie & Power Moendas (arcus media) |
| 🟠 **HIGH** | Chromium-based browser vulnerabilities being exploited | CVE-2026-16807, -16806, -16805, -16804 (batch 2026-07-25) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (116 reports) — Most active actor pipeline-wide; critical-rated trend this cycle, last seen 2026-07-26.
- **The Gentlemen** (103 reports) — High-volume RaaS operation, last seen 2026-07-24.
- **DragonForce** (44 reports) — Cartel-style RaaS; posted Syntron Bioresearch and Deluxe Medical Supply this cycle.
- **Akira** (22 reports) — Ongoing multi-sector ransomware campaigns.
- **Global Secret Group** (17 reports) — 19-victim extortion burst this period; all postings dated 2026-07-26.
- **Inc Ransom** (16 reports) — Posted healthlawadvocates.org; active dark-web presence.
- **Chaos** (14 reports) — Multi-platform (Windows/ESXi/Linux/NAS) double-extortion RaaS.

### Malware Families
- **RansomLook** (142 reports) — Parser/feed artifact tag dominating RaaS victim reporting.
- **Tox1 / Tox** (54 / 27 reports) — Tox messaging identifiers used for ransomware negotiation.
- **DragonForce ransomware** (14 reports) — Payload family tied to the DragonForce actor.
- **RALord** (14 reports) — Precursor to the Nova ransomware brand.
- **Chaos Ransomware** (13 reports) — Chaos RaaS payload family, active this cycle.
- **Qilin** (11 reports) — Qilin/Agenda payload family.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 46 | [link](https://www.ransomlook.io/) | Dark-web leak-site monitoring; drove Exfilsquad, Global Secret Group, Qilin, DragonForce, Chaos, Arcus Media, M3rx and Inc Ransom volume |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers/) | Steam ClickFix/XMRig campaign; GitHub/PyPI Dependabot supply-chain defenses |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33184) | Active scanning for ESAFENET CDG 3 default logins |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** If your organisation or a critical supplier appears on the Exfilsquad (§3.1) or Global Secret Group (§3.2) leak lists, treat the claimed data as genuine — invoke IR, rotate exposed credentials and hashes, and enforce MFA ahead of the 2026-08-05 Exfilsquad deadline.
- 🔴 **IMMEDIATE:** Identify internet-exposed ESAFENET CDG 3 instances, change the `secadmin`/`Est@Spc820` default credential, and pull management interfaces behind VPN/allow-listing (§3.5) — active scanning is under way.
- 🟠 **SHORT-TERM:** Block the Qilin, DragonForce and Chaos infrastructure IOCs and deploy ransom-note filename detection (§3.3, §3.4); prioritise hardening of ESXi/NAS management planes and enforce offline/immutable backups given the RaaS surge.
- 🟡 **AWARENESS:** Brief users on the Steam ClickFix/XMRig lure (§3.6) — never run "fixes" pasted from forums — and tune EDR for browser-spawned script hosts and resource-hijacking behaviour.
- 🟢 **STRATEGIC:** Track the broad data-leak-extortion trend across Exfilsquad, Global Secret Group, Qilin, DragonForce, Arcus Media and M3rx; mature ransomware readiness through segmentation, phishing-resistant MFA, and tested incident-response runbooks. Adopt supply-chain hardening such as GitHub/PyPI's new time-based Dependabot defenses (§2).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 49 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
