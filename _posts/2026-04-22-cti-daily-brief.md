---
layout: post
title:  "CTI Daily Brief: 2026-04-22 — HexagonalRodent DPRK $12M Crypto Heist, RaaS Sophistication Surge, FortiSandbox Path Traversal"
date:   2026-04-23 20:05:51 +0000
description: "DPRK-linked HexagonalRodent siphons $12M from 26,584 crypto wallets via fake job lures; Embargo, Chaos, DragonForce, and Inc Ransom drive a RaaS sophistication trend; FortiSandbox CVE-2026-39813 path-traversal auth bypass disclosed; Apple ships out-of-band iOS fix for notification-retention flaw CVE-2026-28950."
category: daily
tags: [cti, daily-brief, hexagonalrodent, famous-chollima, inc-ransom, dragonforce, chaos-raas, embargo, cve-2026-39813, cve-2026-28950]
classification: TLP:CLEAR
reporting_period: "2026-04-22"
generated: "2026-04-23"
draft: true
severity: high
report_count: 16
sources:
  - RansomLook
  - RecordedFutures
  - BleepingComputer
  - SentinelOne
  - SANS
  - Sekoia
  - Upwind
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-22 (24h) | TLP:CLEAR | 2026-04-23 |

## 1. Executive Summary

The pipeline processed 16 reports across 8 sources for the 24-hour window ending 2026-04-23. The dominant theme is a sustained escalation in Ransomware-as-a-Service sophistication: seven of the nine high-severity items cover active RaaS operations (Inc Ransom, Embargo, Chaos, DragonForce, Kairos, shadowbyt3$) and a correlation trend rated critical specifically flags RaaS maturation across finance, legal, and professional-services victims. The second major story is a DPRK-linked campaign tracked as HexagonalRodent (aligned with Famous Chollima) that stole more than $12 million from 26,584 cryptocurrency wallets by targeting Web3 developers with generative-AI-crafted LinkedIn lures and the BeaverTail, OtterCookie, and InvisibleFerret malware families. On the vulnerability front, Fortinet's FortiSandbox is reportedly affected by CVE-2026-39813, a path-traversal authentication bypass (single TLP:AMBER+STRICT Telegram-sourced disclosure), and Apple issued an out-of-band iOS/iPadOS update patching CVE-2026-28950, a notification-retention flaw reportedly leveraged to recover deleted Signal messages. No new CISA KEV additions appeared in the 24-hour window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No critical-rated reports in the 24-hour window |
| 🟠 **HIGH** | 9 | RaaS activity (Inc Ransom x2, Embargo, Chaos, DragonForce, Kairos, shadowbyt3$); DPRK HexagonalRodent crypto theft; CVE-2026-39813 FortiSandbox |
| 🟡 **MEDIUM** | 4 | Inc Ransom teamster773.org leak post; Apple CVE-2026-28950; LABScon Chinese IoT camera research; Upwind Mythos commentary |
| 🟢 **LOW** | 0 | No low-rated reports |
| 🔵 **INFO** | 3 | Sekoia strategic-autonomy commentary; SANS ISC Stormcast podcast; RansomLook bravox tracking post |

## 3. Priority Intelligence Items

### 3.1 DPRK HexagonalRodent Steals $12M+ from 26,584 Crypto Wallets via Fake-Job Lures

**Source:** [Recorded Future News — The Record](https://therecord.media/north-korean-hackers-siphon-12-million-from-crypto-users)

Expel's Marcus Hutchins attributed a sprawling North Korean operation — tracked internally as **HexagonalRodent** and overlapping with the DPRK cluster known as **Famous Chollima** — to the theft of over $12 million in cryptocurrency during Q1 2026. The operation compromised 2,726 systems and exfiltrated credentials from 26,584 distinct cryptocurrency wallets. Victims were Web3 developers approached on LinkedIn via fake companies (including one registered in Mexico); the lure is a "coding assessment" download that deploys **BeaverTail**, with follow-on stages including **OtterCookie** and **InvisibleFerret**. The operators used generative AI both to refine malware code and to manufacture credible fake recruiter personas. Internal panels recovered by Expel show 31 operators split across six teams, with past members spawning splinter crews. The tradecraft targets credential stores including the macOS Keychain and browser password managers. MITRE references from the entity data: **T1566 (Phishing)** and **T1003 (OS Credential Dumping)**.

#### Indicators of Compromise

```
Malware families: BeaverTail, OtterCookie, InvisibleFerret
Lure vector: LinkedIn DMs from fake companies offering Web3/crypto dev roles
Payload delivery: "coding assessment" / technical-interview download
Credential targets: macOS Keychain, browser password managers, crypto wallet software
Geographic cover: at least one fake company registered in Mexico
```

> **SOC Action:** Hunt for unsigned Node.js/npm package execution originating from Downloads, Desktop, or temp directories on developer endpoints in the last 90 days, and alert on macOS `security` binary reads of the login Keychain by non-Apple signed processes. Block outbound to any newly registered LinkedIn-adjacent recruiter domains, review developer LinkedIn DMs for unsolicited "technical interview" downloads, and rotate any wallet seeds or exchange API keys ever used on a device that ran an interview "test project" since January 2026.

### 3.2 RaaS Sophistication Surge — Embargo, Chaos, DragonForce, and Inc Ransom All Active

**Sources:** [RansomLook — Embargo](https://www.ransomlook.io//group/embargo), [RansomLook — Chaos](https://www.ransomlook.io//group/chaos), [RansomLook — DragonForce](https://www.ransomlook.io//group/dragonforce), [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom)

The pipeline's highest-rated correlation trend for this cycle — rated **critical** — is the continued professionalisation of Ransomware-as-a-Service. Four RaaS groups posted fresh victim claims in the 24-hour window:

- **Embargo** claimed **chipsoft.com** (Dutch healthcare-software vendor). Embargo is a Rust-based RaaS active since May 2024, using AES-256 + RSA-4096, deleting volume shadow copies, and disabling recovery features before exfiltrating to a Tor leak site. Its tracked leak infrastructure shows 25/45 file-server endpoints currently up.
- **Chaos RaaS** (distinct from the 2021 Chaos Builder) claimed **alexandergroup.com**, a Scottsdale-based sales-management consultancy. Chaos supports Windows, ESXi, Linux, and NAS with optional partial-file encryption for stealth. Prior victim Optima Tax Relief had 69 GB exfiltrated.
- **DragonForce** claimed **INCYTE**. The group evolved from hacktivism into a cartel-style RaaS with a captcha-protected affiliate portal; prior victims include M&S, Harrods, and Co-op.
- **Inc Ransom** claimed three victims in the window: **trugreen.com**, **krwlawyers.com**, and **teamster773.org**. Inc Ransom's post cadence remains high (41 posts in the last 30 days; 747 all-time).
- Adjacent: **Kairos** claimed **Gregory Jewellers** and **Nordenta**; **shadowbyt3$** posted a doxx of Eric J Taylor plus additional educational-sector data.

MITRE references across this cluster: **T1078 (Valid Accounts)**, **T1110 (Brute Force)**, **T1486/T1485 (Data Encrypted for Impact)**, **T1490/T1499 (Inhibit System Recovery)**, **T1536.001 (Spearphishing Link)**, **T1071 (Application Layer Protocol)**.

#### Indicators of Compromise

```
Inc Ransom chat server (active): hxxp[:]//incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion/
Inc Ransom blog (active):        hxxp[:]//incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion/blog/disclosures
Embargo leak (active):           hxxp[:]//embargobe3n5okxyzqphpmk3moinoap2snz5k6765mvtkk7hhi544jid[.]onion/
Chaos leak (active):             hxxp[:]//hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd[.]onion/
DragonForce blog (active):       hxxp[:]//z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid[.]onion/blog
DragonForce file server:         hxxp[:]//dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd[.]onion
Ransom notes:
  Inc Ransom:  INC-README.txt / INC-README.html (and -2/-3/-4 variants)
  Embargo:     HOW_TO_RECOVER_FILES.txt / HOW_TO_RECOVER_FILES_2.txt
  Chaos:       readme.chaos.txt
  Kairos:      README_47.txt  (contact: kairossup@onionmail[.]com)
```

> **SOC Action:** Add the Inc Ransom, Embargo, Chaos, DragonForce, and Kairos onion domains listed above to egress deny-lists on Tor-egress monitors and DNS sinkholes. Deploy EDR detections for `vssadmin.exe delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, and `bcdedit /set recoveryenabled no` executed by non-admin or unsigned binaries (T1490). For Windows, ESXi, Linux, and NAS fleets exposed to remote admin, enforce MFA on all privileged accounts and audit for broker-sold credentials against Have-I-Been-Pwned corporate feeds and underground marketplace monitors.

### 3.3 CVE-2026-39813 — Path-Traversal Authentication Bypass in FortiSandbox

**Source:** Telegram (channel name redacted) — TLP:AMBER+STRICT

A Telegram-sourced disclosure describes **CVE-2026-39813**, a path-traversal authentication-bypass vulnerability in **Fortinet FortiSandbox**. According to the post, improper validation of user-supplied input allows directory traversal that bypasses authentication and exposes sensitive data. No vendor advisory, affected-version matrix, or confirmed in-the-wild exploitation was present in the pipeline data; attribution of exploit status should be treated as unconfirmed pending Fortinet's own advisory. MITRE references in the entity data: **T1071.001 (Application Layer Protocol)** and a pipeline-generated **T1095.003 (Path Traversal)** mapping.

> **SOC Action:** Verify whether any FortiSandbox appliance (FSA-VM, FSA-1000F, FSA-2000E, FSA-3000E/3500F/3000F, FSA-500F) is reachable from untrusted networks and, pending Fortinet's advisory, restrict management/API interfaces to a dedicated management VLAN with source-IP allow-listing. Enable web-server logging on the appliance and search for URL patterns containing `../`, `..%2f`, `..%252f`, or absolute filesystem paths in query strings; escalate any hit to IR.

### 3.4 Apple Issues Out-of-Band iOS/iPadOS Fix for CVE-2026-28950 Notification Retention Flaw

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/apple-fixes-ios-bug-that-retained-deleted-notification-data/)

Apple released emergency updates **iOS 26.4.2 / iPadOS 26.4.2** and **iOS 18.7.8 / iPadOS 18.7.8** on 2026-04-22 addressing **CVE-2026-28950**, a Notification Services flaw that caused notifications marked for deletion to be retained in internal storage. Reporting from 404 Media indicates the FBI recovered deleted Signal messages from a suspect's iPhone via this notification store — not from Signal's encrypted message database. Signal publicly thanked Apple for the fix. Apple did not confirm in-the-wild exploitation status, though the out-of-band release cadence is notable. Users can further harden Signal by setting Notifications → Show to "Name Only" or "No Name or Content."

> **SOC Action:** For corporate-managed iOS fleets, push iOS 26.4.2 / iPadOS 26.4.2 (or the 18.7.8 branch for older devices) as a required update via MDM this week. For staff handling sensitive communications (legal, M&A, exec, journalists, IR responders), recommend setting Signal → Notifications → Show = "No Name or Content" and consider enforcing Disappearing Messages defaults.

### 3.5 LABScon25 — Chinese Smart-Home Cameras and IoT Supply-Chain Risk

**Source:** [SentinelOne Labs](https://www.sentinelone.com/labs/labscon25-replay-are-your-chinese-cameras-spying-for-you-or-on-you/)

Marc Rogers and Silas Cutler's LABScon25 replay details how ultra-cheap Chinese video doorbells and security cameras sold under rotating brand names (Eken, Tuck) share identical Allwinner-semiconductor-based hardware, ship with hardcoded root passwords, and route metadata/video through servers in Hong Kong and China. Firmware "fixes" observed by the researchers merely commented out vulnerable services rather than removing them. The researchers trace a shell-company network with non-responsive registered agents designed to frustrate FCC enforcement. No single named CVE, but the collective IoT attack surface is described as remotely controllable via configuration push from overseas. Correlates with the pipeline's **high**-rated trend "Exploitation of vulnerabilities in IoT and network devices," alongside Mirai activity against EoL D-Link routers reported in prior batches.

> **SOC Action:** Inventory IoT doorbells/cameras on guest and corporate-adjacent networks; isolate to a dedicated IoT VLAN with egress restricted to vendor cloud endpoints only. Block outbound connections from IoT segments to residential-grade hosting in HK/CN ASNs. For facilities/exec-protection use-cases, require devices on an approved-vendor list with documented firmware update policies and no hardcoded default credentials.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware-as-a-Service (RaaS) operations becoming more sophisticated | chipsoft.com By embargo; alexandergroup.com By chaos; INCYTE By dragonforce |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors globally | trugreen.com By inc ransom; chipsoft.com By embargo; teamster773.org By inc ransom |
| 🟠 **HIGH** | Exploitation of vulnerabilities in IoT and network devices | LABScon25 Chinese-camera research; prior-batch Mirai/D-Link EoL RCE |
| 🟠 **HIGH** | DPRK actor correlation — HexagonalRodent / Famous Chollima using phishing for crypto theft | Recorded Future HexagonalRodent; shared T1566 Phishing across campaigns |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin / qilin** (96 combined reports; last seen 2026-04-21) — persistent RaaS operator, ongoing multi-sector victimology
- **The Gentlemen / the gentlemen** (79 combined reports; last seen 2026-04-21) — active leak-site operator
- **Coinbase Cartel / coinbase cartel** (53 combined reports; last seen 2026-04-20) — data-extortion cluster
- **DragonForce / dragonforce** (56 combined reports; last seen 2026-04-22) — posted **INCYTE** in this window
- **nightspire** (31 reports; last seen 2026-04-18) — continued tracking
- **shadowbyt3$** (25 reports; last seen 2026-04-22) — posted Eric J Taylor doxx in this window
- **Inc Ransom** (today's data) — 3 new victim posts in the window; 41 victims in last 30 days
- **HexagonalRodent / Famous Chollima** (today's data) — DPRK-linked crypto-theft cluster

### Malware Families

- **RansomLock** (45 reports) — pipeline ingestion tag from the RansomLook feed (not a malware family per se)
- **ransomware / Ransomware** (39 combined reports) — generic tagging
- **dragonforce ransomware / DragonForce ransomware** (35 combined reports) — active leak-site posts
- **RaaS** (19 reports) — category tag reflecting the sustained RaaS trend
- **Tox1 / Tox** (24 combined reports) — chat infrastructure identifier used across multiple RaaS leak sites
- **Akira ransomware** (12 reports) — continued presence
- **BeaverTail / OtterCookie / InvisibleFerret** (today's data) — DPRK HexagonalRodent toolchain
- **embargo / Chaos Ransomware** (today's data) — fresh RaaS victim posts

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 9 | [link](https://www.ransomlook.io) | Primary source for RaaS leak-site activity (Inc Ransom, Embargo, Chaos, DragonForce, Kairos, shadowbyt3$, bravox) |
| RecordedFutures | 1 | [link](https://therecord.media/north-korean-hackers-siphon-12-million-from-crypto-users) | HexagonalRodent DPRK crypto-theft campaign |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/apple-fixes-ios-bug-that-retained-deleted-notification-data/) | Apple CVE-2026-28950 out-of-band patch |
| SentinelOne | 1 | [link](https://www.sentinelone.com/labs/labscon25-replay-are-your-chinese-cameras-spying-for-you-or-on-you/) | LABScon25 Chinese IoT supply-chain research |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/32920) | ISC Stormcast podcast — green threat level |
| Sekoia | 1 | [link](https://blog.sekoia.io/strategic-autonomy-where-you-get-to-choose/) | Strategic-autonomy commentary piece |
| Upwind | 1 | [link](https://www.upwind.io/feed/anthropic-mythos-cloud-security-defense) | Commentary on AI-accelerated zero-day disclosure and Mythos |
| Telegram (channel name redacted) | 1 | — | CVE-2026-39813 FortiSandbox path-traversal disclosure (TLP:AMBER+STRICT) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Push iOS 26.4.2 / iPadOS 26.4.2 (or 18.7.8 for legacy devices) via MDM to all corporate-managed Apple mobile endpoints this week to close CVE-2026-28950. For staff in sensitive roles, enforce Signal → Notifications → "No Name or Content" (Section 3.4).
- 🔴 **IMMEDIATE:** Restrict FortiSandbox management/API interfaces to a dedicated management VLAN with source-IP allow-listing pending a Fortinet advisory on CVE-2026-39813, and search appliance logs for `../` / `..%2f` / `..%252f` traversal patterns in request URIs (Section 3.3).
- 🟠 **SHORT-TERM:** Brief Web3 and engineering teams on the HexagonalRodent/Famous Chollima LinkedIn lure pattern. Block unsigned npm/Node script execution from user Downloads and temp directories, deploy macOS Keychain-access telemetry on developer endpoints, and rotate any wallet seeds or exchange API keys ever used on a device that ran an interview "coding assessment" since January 2026 (Section 3.1).
- 🟠 **SHORT-TERM:** Block and sinkhole the Inc Ransom, Embargo, Chaos, DragonForce, and Kairos onion domains listed in Section 3.2. Validate EDR coverage of shadow-copy deletion (T1490) and data-encryption (T1485/T1486) behaviours against Windows, ESXi, Linux, and NAS fleets.
- 🟡 **AWARENESS:** Inventory IoT doorbells and cameras behind corporate or facilities networks. Isolate to a dedicated IoT VLAN and block egress to residential-grade hosting in HK/CN ASNs pending replacement with vendors that document their firmware update policy (Section 3.5).
- 🟢 **STRATEGIC:** Track the sustained RaaS sophistication trend (Qilin, The Gentlemen, Coinbase Cartel, DragonForce, Inc Ransom) against your sector risk register; update tabletop exercises to assume a RaaS affiliate that brings its own credentials (broker-sourced) and targets ESXi/NAS alongside Windows.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 16 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
