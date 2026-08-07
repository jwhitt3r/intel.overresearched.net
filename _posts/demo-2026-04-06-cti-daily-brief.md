---
layout: post
title: "CTI Daily Brief: 2026-04-05 — Fortinet EMS Zero-Day Added to CISA KEV; Storm-1175 Chains Medusa Ransomware with Zero-Day Exploits; North Korean Hackers Behind $280M Drift Crypto Theft"
date: 2026-04-06 20:08:00 +0000
description: "Critical 24-hour period dominated by active exploitation of Fortinet FortiClient EMS (CVE-2026-35616) added to CISA KEV, Microsoft attribution of Storm-1175 to Medusa ransomware zero-day campaigns, a $280M North Korean crypto heist via social engineering, and Germany unmasking the leader of REvil/GandCrab. RaaS operations from The Gentlemen, Akira, Brain Cipher, Clop, and Qilin drove 84 ransomware victim disclosures."
category: daily
tags: [cti, daily-brief, storm-1175, medusa, cve-2026-35616, unc4736, revil, the-gentlemen, akira]
severity: critical
classification: TLP:CLEAR
reporting_period: "2026-04-05"
generated: "2026-04-06"
draft: true
report_count: 103
sources:
  - BleepingComputer
  - RecordedFutures
  - CISA
  - Krebs on Security
  - RansomLock
  - SANS
  - Wired Security
  - Schneier
  - Crowdstrike
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-05 (24h) | TLP:CLEAR | 2026-04-06 |

## 1. Executive Summary

The pipeline processed 103 threat reports from 10 sources over the past 24 hours, with 27 rated critical and 55 rated high. The dominant theme is accelerating ransomware operations — 84 reports originated from RansomLock tracking victim disclosures across at least eight active groups. Three items demand immediate SOC attention: CISA added CVE-2026-35616 (Fortinet FortiClient EMS pre-authentication bypass, CVSS 9.1) to the Known Exploited Vulnerabilities catalogue with a Thursday patch deadline; Microsoft attributed Storm-1175 to zero-day exploitation campaigns deploying Medusa ransomware across healthcare, education, and finance sectors; and Drift Protocol confirmed a $280M cryptocurrency theft attributed to North Korean group UNC4736 after a six-month in-person social engineering operation. Separately, German BKA publicly identified Daniil Shchukin as "UNKN," the head of the GandCrab and REvil ransomware operations responsible for over 130 attacks and €35M in damages.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 27 | Fortinet EMS CVE-2026-35616 KEV addition; Storm-1175/Medusa zero-day campaigns; Drift $280M crypto theft; Brain Cipher, Akira, The Gentlemen, Clop victim disclosures |
| 🟠 **HIGH** | 55 | Play, Qilin, LockBit5, Nightspire, Shadowbyt3$ victim claims; breach monitoring analysis |
| 🟡 **MEDIUM** | 17 | Phishing redirect analysis; CrowdStrike exposure evaluation; credential monitoring coverage gaps |
| 🔵 **INFO** | 4 | Industry commentary and security tooling discussions |

## 3. Priority Intelligence Items

### 3.1 Fortinet FortiClient EMS Pre-Auth Bypass Under Active Exploitation (CVE-2026-35616)

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/04/06/cisa-adds-one-known-exploited-vulnerability-catalog), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-fortinet-flaw-exploited-in-attacks-by-friday/), [The Record](https://therecord.media/singapore-us-warn-of-fortinet-bug-exploited)

CISA added CVE-2026-35616 to the KEV catalogue on 6 April, ordering FCEB agencies to patch by 9 April under BOD 22-01. The flaw is a pre-authentication API access bypass in FortiClient EMS stemming from improper access control, allowing unauthenticated remote code execution via crafted requests (CVSS 9.1). Fortinet released emergency hotfixes for versions 7.4.5 and 7.4.6, with version 7.4.7 recommended. Cybersecurity firm Defused first observed in-the-wild exploitation on 31 March, and watchTowr honeypots confirmed exploitation ramping over the Easter weekend. Shadowserver tracks approximately 2,000 exposed FortiClient EMS instances globally, with over 1,400 in the US and Europe. This is the second FortiClient EMS vulnerability disclosed in three weeks, following CVE-2026-21643 patched in February. Singapore's cybersecurity agency issued a parallel advisory.

> **SOC Action:** Immediately inventory all FortiClient EMS instances. Apply Fortinet hotfix for 7.4.5/7.4.6 or upgrade to 7.4.7. Query network logs for anomalous API calls to EMS management endpoints. Review Shadowserver exposure data for your IP ranges. Audit for signs of post-exploitation: new local accounts, unexpected RMM tool installations, or disabled security agents.

### 3.2 Storm-1175 Deploys Medusa Ransomware via Zero-Day and N-Day Exploit Chains

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-links-medusa-ransomware-affiliate-to-zero-day-attacks/)

Microsoft publicly linked Storm-1175, a China-based financially motivated group, to high-velocity Medusa ransomware campaigns exploiting zero-day and n-day vulnerabilities. The group moves from initial access to data exfiltration and ransomware deployment within 24 hours in some cases, heavily targeting healthcare, education, professional services, and finance across Australia, the UK, and the US. Storm-1175 chains multiple exploits to establish persistence — creating user accounts, deploying RMM software, stealing credentials, and disabling security tools before dropping Medusa payloads. Confirmed zero-days include CVE-2026-23760 (SmarterMail authentication bypass). The group has exploited over 16 vulnerabilities across 10 products, including Microsoft Exchange, Papercut, Ivanti Connect Secure, ConnectWise ScreenConnect, JetBrains TeamCity, SimpleHelp, CrushFTP, and BeyondTrust. CISA previously warned in March 2025 that Medusa had impacted over 300 US critical infrastructure organisations.

**Referenced MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)

> **SOC Action:** Query EDR for rapid-succession exploitation patterns: new local account creation followed by RMM software installation (e.g., AnyDesk, Splashtop) within a 24-hour window. Verify patch status for all 10 product families listed. Hunt for CVE-2026-23760 exploitation against any SmarterMail instances. Ensure Medusa ransomware signatures and IOCs from Microsoft's advisory are loaded into detection platforms.

### 3.3 Drift Protocol $280M Crypto Theft Attributed to North Korean UNC4736

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/drift-280m-crypto-theft-linked-to-6-month-in-person-operation/)

Drift Protocol confirmed that the $280M+ hack on 1 April originated from a six-month social engineering operation by UNC4736 (a.k.a. AppleJeus, Labyrinth Chollima), a North Korean threat actor previously linked to the 3CX supply chain attack and the $50M Radiant cryptocurrency theft. Attackers posed as a quantitative trading firm, engaging Drift contributors in person at multiple crypto conferences across several countries. Two contributor compromises are suspected: a malicious code repository exploiting a VSCode/Cursor vulnerability for silent code execution, and a malicious TestFlight application disguised as a wallet product. The attackers hijacked Security Council administrative powers to drain user assets in approximately 12 minutes. Notably, the in-person operatives were non-Korean intermediaries. Blockchain intelligence firms Elliptic and TRM Labs corroborated the DPRK attribution at medium-high confidence.

**Referenced MITRE ATT&CK:** T1566 (Phishing), T1195 (Supply Chain Compromise)

> **SOC Action:** Organisations in the DeFi and cryptocurrency space should review contributor access controls and multisig governance processes. Flag any inbound engagement from unknown quantitative trading firms at recent conferences. Audit developer environments for malicious VSCode/Cursor extensions or unexpected TestFlight app installations. Monitor for wallet-draining transaction patterns.

### 3.4 Germany Identifies REvil/GandCrab Leader "UNKN"

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/04/germany-doxes-unkn-head-of-ru-ransomware-gangs-revil-gandcrab/)

The German Federal Criminal Police (BKA) publicly identified 31-year-old Russian national Daniil Maksimovich Shchukin as "UNKN" (a.k.a. UNKNOWN), the leader of both the GandCrab and REvil ransomware operations. A second suspect, 43-year-old Anatoly Sergeevitsch Kravchuk, was also named. The pair are linked to at least 130 cyberattacks causing €35M in economic damage and extorting nearly €2M across two dozen incidents targeting German organisations between 2019–2021. Shchukin's name appeared in a February 2023 US DOJ filing seeking seizure of cryptocurrency accounts containing $317K in ransomware proceeds. GandCrab claimed to have extorted $2B before shutting down in 2019, and REvil continued the double-extortion model until law enforcement disruptions in 2021.

> **SOC Action:** No immediate defensive action required. Update threat actor profiles for REvil and GandCrab with confirmed attribution. Monitor for potential retaliatory activity from affiliated actors following the public identification.

### 3.5 Ransomware-as-a-Service Operations Surge: Eight Groups Claim Victims in 24 Hours

**Source:** [RansomLock](https://www.ransomlook.io)

RansomLock intelligence tracked 84 victim disclosures across at least eight ransomware groups in a single 24-hour period. The Gentlemen led with 13 new claims spanning education (Thammasat University, Jati Tinggi), energy (PTT Philippines), sports (SATS Sports Club Sweden), logistics (CH Express), and manufacturing (Distritech, AIRCOS). Akira claimed three engineering firms (AKM Consulting, Aqua-Serv, Gauthier Connectique). Brain Cipher posted three victims across insurance, automotive, and e-commerce sectors using LockBit 3.0-based payloads. Clop resumed archival data dumps (ARCHIVE12, ARCHIVE14). Qilin claimed logistics firm Operinter. LockBit5 targeted industrial and automotive domains including gas.mercedes-benz.com[.]eg. Play and Hive affiliates continued operations across professional services.

> **SOC Action:** Review exposure to named victim organisations for supply chain risk. Ensure ransomware playbooks cover double-extortion scenarios. Verify offline backup integrity and test restoration procedures. Monitor dark web leak sites for data associated with your organisation or partners.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased ransomware activity targeting critical infrastructure and government sectors | Germany unmasks REvil suspects; Microsoft links Medusa to zero-day campaigns; CISA Fortinet KEV addition |
| 🔴 **CRITICAL** | Enterprise software vulnerabilities exploited at scale before patch availability | CVE-2026-35616 (FortiClient EMS) in-the-wild since 31 March; second Fortinet EMS flaw in three weeks |
| 🟠 **HIGH** | Ransomware-as-a-Service operations expanding globally with diversified targeting | Play, Qilin, Clop, Brain Cipher, The Gentlemen, Akira, LockBit5 all active simultaneously |
| 🟠 **HIGH** | Nightspire ransomware targeting manufacturing, healthcare, and energy sectors globally | Multiple victim claims across pyrotechnics, confectionery, and industrial firms |
| 🟡 **MEDIUM** | Phishing and social engineering campaigns increasing in sophistication | Drift crypto theft via 6-month in-person operation; phishing redirect techniques evolving |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (43 reports) — Prolific RaaS operation targeting logistics, manufacturing, and professional services globally
- **Nightspire** (35 reports) — Emerging group hitting manufacturing, healthcare, and energy across multiple regions using phishing and exfiltration
- **The Gentlemen** (42 reports combined) — Rapidly expanding operation targeting education, energy, real estate, and sports sectors in APAC and Europe
- **TeamPCP** (29 reports) — Active threat group tracked across multiple campaigns
- **DragonForce** (25 reports) — RaaS group targeting critical sectors including government and holdings firms
- **Akira** (22 reports) — Double-extortion group exploiting unpatched VPNs and ESXi servers; targeting education, manufacturing, healthcare
- **Hive** (16 reports) — Persistent affiliate network linked to Play ransomware operations
- **ShinyHunters** (13 reports) — Data breach and exfiltration group targeting SaaS and business platforms
- **Storm-1175** (new) — China-based group deploying Medusa ransomware via zero-day exploit chains
- **UNC4736** (new) — North Korean actor behind Drift Protocol $280M crypto theft

### Malware Families

- **DragonForce ransomware** (24 reports) — Primary payload for DragonForce RaaS affiliates
- **Akira ransomware** (18 reports) — CryptoAPI-based encryptor with .akira extension; Linux and Windows variants
- **PLAY ransomware** (8 reports) — Deployed by Hive-affiliated operators in professional services targeting
- **CanisterWorm** (7 reports) — Worm observed in prior campaigns, continued tracking
- **Medusa ransomware** (new spotlight) — Storm-1175's primary payload; over 300 US critical infrastructure victims per CISA
- **Clop ransomware** (active) — TA505-linked; resumed archival data dumps with .clop extension and CryptoMix lineage
- **Brain Cipher** (active) — LockBit 3.0-based variant with Salsa20/RSA hybrid encryption; ransom demands up to $8M

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 84 | [link](https://www.ransomlook.io) | Ransomware victim disclosure tracking across 8+ groups |
| BleepingComputer | 5 | [link](https://www.bleepingcomputer.com) | Fortinet KEV, Medusa/Storm-1175, Drift crypto theft, breach monitoring |
| Recorded Future News | 5 | [link](https://therecord.media) | Fortinet exploitation advisory, additional threat reporting |
| SANS | 2 | [link](https://www.sans.org) | Security analysis and advisories |
| Unknown | 2 | — | Unattributed source reports |
| Wired Security | 1 | [link](https://www.wired.com/category/security/) | Security feature reporting |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | Germany doxes REvil/GandCrab leader UNKN |
| Schneier on Security | 1 | [link](https://www.schneier.com) | Security commentary |
| CrowdStrike | 1 | [link](https://www.crowdstrike.com) | Exposure evaluation methodology |
| CISA | 1 | [link](https://www.cisa.gov) | CVE-2026-35616 KEV catalogue addition |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all FortiClient EMS instances against CVE-2026-35616 (hotfix for 7.4.5/7.4.6 or upgrade to 7.4.7). CISA deadline is 9 April. Audit for post-exploitation indicators — new accounts, RMM tools, or disabled security software — on any internet-facing EMS instances.

- 🔴 **IMMEDIATE:** Verify patch status across all products in Storm-1175's target list: Microsoft Exchange, Papercut, Ivanti Connect Secure/Policy Secure, ConnectWise ScreenConnect, JetBrains TeamCity, SimpleHelp, CrushFTP, SmarterMail, and BeyondTrust. Prioritise any unpatched internet-facing instances.

- 🟠 **SHORT-TERM:** Cryptocurrency and DeFi organisations should audit multisig governance and contributor vetting processes in light of the Drift Protocol theft. Review developer toolchains for malicious VSCode/Cursor extensions and unexpected TestFlight installations.

- 🟠 **SHORT-TERM:** Validate ransomware response playbooks against the current eight-group surge. Confirm offline backup integrity, test restoration from backups, and ensure EDR coverage detects Akira (.akira extension), Brain Cipher (LockBit 3.0 variant), and Clop (.clop extension) payloads.

- 🟡 **AWARENESS:** The public identification of REvil/GandCrab leader Shchukin may provoke operational shifts or retaliatory activity among affiliated Russian-speaking cybercrime networks. Maintain elevated monitoring of ransomware infrastructure changes over the next 7–14 days.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 103 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
