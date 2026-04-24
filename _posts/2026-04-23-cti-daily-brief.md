---
layout: post
title:  "CTI Daily Brief: 2026-04-23 - Breeze Cache WordPress plugin actively exploited; CISA adds four KEVs; ShinyHunters hits ADT and Carnival"
date:   2026-04-24 20:30:00 +0000
description: "Critical Breeze Cache WordPress RCE under active exploitation, CISA adds four new KEV entries, 10K+ Zimbra servers unpatched, ShinyHunters breaches ADT and Carnival, new BlackFile vishing gang, Pack2TheRoot Linux LPE, and Qilin/The Gentlemen RaaS activity dominate the day."
category: daily
tags: [cti, daily-brief, shinyhunters, qilin, the-gentlemen, blackfile, cve-2026-3844, cve-2026-41651, cve-2025-48700]
classification: TLP:CLEAR
reporting_period: "2026-04-23"
generated: "2026-04-24"
draft: true
report_count: 99
severity: critical
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - CISA
  - HaveIBeenPwned
  - SentinelOne
  - Schneier
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-23 (24h) | TLP:CLEAR | 2026-04-24 |

## 1. Executive Summary

The pipeline processed 99 reports over the last 24 hours across 15 sources, dominated by Microsoft Linux-kernel CVE disclosures (44) and RansomLock leak-site monitoring (27). Three critical items and 45 high-severity items stand out. CISA added four new vulnerabilities to its KEV catalogue — Samsung MagicINFO, two SimpleHelp flaws, and a D-Link DIR-823X command-injection bug — while a separate alert flagged CVE-2025-48700 in Zimbra as actively exploited, with more than 10,500 servers still unpatched. Hackers are actively exploiting CVE-2026-3844 in the Breeze Cache WordPress plugin (400K+ installs), with Wordfence logging over 170 attack attempts. ShinyHunters publicly claimed breaches at ADT and Carnival (7.5M records leaked), while a newly named extortion gang "BlackFile" (CL-CRI-1116 / Cordial Spider / UNC6671) is driving a surge of vishing-led intrusions against retail and hospitality. On the espionage track, SentinelLABS disclosed fast16 — a Lua-powered sabotage framework predating Stuxnet — and Qilin remains the most prolific RaaS, posting eight new victims including the City of Napoleon, Ohio.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | Breeze Cache WordPress RCE (CVE-2026-3844); ext4 DoS (CVE-2026-31448); raw socket UAF (CVE-2026-31532) |
| 🟠 **HIGH** | 45 | CISA KEV additions; Zimbra CVE-2025-48700; Pack2TheRoot (CVE-2026-41651); BlackFile vishing; ShinyHunters ADT/Carnival; Qilin / The Gentlemen / Inc Ransom leak-site postings; fast16 sabotage framework |
| 🟡 **MEDIUM** | 20 | Microsoft Linux-kernel hardening CVEs; SMS blaster arrests; Bluetooth tracker in mail |
| 🟢 **LOW** | 5 | Low-severity kernel subsystem patches |
| 🔵 **INFO** | 26 | Telemetry and informational Microsoft advisories |

## 3. Priority Intelligence Items

### 3.1 Active exploitation: CVE-2026-3844 Breeze Cache WordPress unauthenticated RCE

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-file-upload-bug-in-breeze-cache-wordpress-plugin/)

Attackers are actively exploiting CVE-2026-3844 (CVSS 9.8), a missing file-type validation bug in the `fetch_gravatar_from_remote` function of Cloudways' Breeze Cache plugin. Wordfence has already observed more than 170 exploitation attempts. Breeze Cache has 400,000+ active installs; exploitation requires the "Host Files Locally – Gravatars" add-on to be enabled (not default). Successful exploitation yields arbitrary file upload leading to RCE and full site takeover. Cloudways patched the issue in version 2.4.5 earlier this week; versions ≤ 2.4.4 remain vulnerable. Relevant ATT&CK techniques: T1190 (exploit public-facing app), T1071 (application layer protocol).

> **SOC Action:** Inventory WordPress estates for the Breeze Cache plugin and confirm version ≥ 2.4.5; where patching is blocked, disable the "Host Files Locally – Gravatars" add-on immediately. Add WAF signatures blocking POSTs to the Gravatar remote-fetch endpoint with non-image Content-Types, and hunt web logs for unexpected PHP files written under `/wp-content/` in the last 14 days.

### 3.2 CISA KEV: four new actively exploited flaws; Zimbra XSS already in the wild

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/04/24/cisa-adds-four-known-exploited-vulnerabilities-catalog), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-says-zimbra-flaw-now-exploited-over-10k-servers-vulnerable/)

CISA added four vulnerabilities to the KEV catalogue on 2026-04-24, all reflecting active exploitation: CVE-2024-7399 (Samsung MagicINFO 9 Server path traversal), CVE-2024-57726 and CVE-2024-57728 (SimpleHelp authorisation bypass and path traversal), and CVE-2025-29635 (D-Link DIR-823X command injection). Separately, Shadowserver reports more than 10,500 Zimbra Collaboration Suite servers still exposed and vulnerable to CVE-2025-48700, an unauthenticated XSS patched by Synacor in June 2025. The flaw triggers when a user views a malicious email in the Zimbra Classic UI and has been abused by APT28 against Ukrainian government targets in a campaign tracked as Operation GhostMail. CISA previously ordered FCEB agencies to remediate by 23 April. Relevant ATT&CK: T1566 (phishing), T1204.002.

> **SOC Action:** Run an urgent KEV catalogue reconciliation across the asset inventory; prioritise internet-exposed SimpleHelp, Samsung MagicINFO, D-Link DIR-823X, and Zimbra servers. For Zimbra, disable the Classic UI where feasible and upgrade to the latest patched ZCS version; hunt webmail logs for cross-origin script injection patterns and inbound email where HTML body contains inline `<script>` or obfuscated JavaScript.

### 3.3 Pack2TheRoot — 12-year-old PackageKit flaw grants local root on Linux

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-pack2theroot-flaw-gives-hackers-root-linux-access/)

Deutsche Telekom Red Team disclosed CVE-2026-41651 (CVSS 8.8), a flaw in the PackageKit daemon that permits local unprivileged users to run `pkcon install` without authentication and escalate to root. PackageKit 1.0.2 through 1.3.4 are vulnerable; version 1.3.5 contains the fix. Confirmed-vulnerable distributions include Ubuntu Desktop 18.04/24.04/26.04, Ubuntu Server 22.04–24.04, Debian Trixie 13.4, Rocky Linux 10.1, and Fedora 43 (desktop and server). Exploitation reliably produces a PackageKit assertion failure and daemon crash, leaving observable evidence in system logs. No public PoC yet. Relevant ATT&CK: T1068 (exploitation for privilege escalation), T1078 (valid accounts).

> **SOC Action:** Enumerate endpoints with `dpkg -l | grep -i packagekit` or `rpm -qa | grep -i packagekit` and upgrade to 1.3.5. On servers that do not require interactive package management, mask the PackageKit daemon (`systemctl mask packagekit`). Deploy detection for `PackageKit` service crash events in `journalctl` and for anomalous `pkcon install` executions by non-administrative UIDs.

### 3.4 BlackFile extortion gang — vishing-led data theft against retail & hospitality

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-blackfile-extortion-gang-targets-retail-and-hospitality-orgs/)

Unit 42 and RH-ISAC named a new financially-motivated group — BlackFile (also CL-CRI-1116, UNC6671, Cordial Spider) — responsible for a surge of vishing intrusions since February 2026. With moderate confidence, Unit 42 links the crew to "The Com". The attack chain begins with spoofed VoIP calls impersonating IT support, luring staff to phishing portals that harvest credentials and one-time passcodes. Operators then register their own devices to bypass MFA, scrape internal directories to pivot to executive accounts, and exfiltrate data from Salesforce and SharePoint using legitimate API calls while searching for files containing "confidential" and "SSN". Victims have reported swatting attempts during extortion negotiations. TTPs mirror ShinyHunters / SLSH copycats. Relevant ATT&CK: T1566 (phishing), T1556 (MFA bypass via device registration), T1213, T1567.

> **SOC Action:** Enforce multi-factor identity verification on inbound helpdesk calls (call-back on corporate directory numbers only). Alert on new Azure AD / Okta device registrations within 15 minutes of a password reset, and on Salesforce Bulk API exports > 50MB or SharePoint downloads with search terms `confidential`, `SSN`, or `tax`. Run tabletop vishing simulations against frontline support staff.

### 3.5 ShinyHunters: ADT and Carnival added to confirmed victims

**Source:** [Recorded Future](https://therecord.media/ADT-data-breach-cyberattack), [Have I Been Pwned](https://haveibeenpwned.com/Breach/Carnival), RansomLook

ADT (the US home-security provider, $5.1B FY revenue) confirmed a Monday intrusion during which ShinyHunters stole a "limited set" of customer records — names, phone numbers, addresses, DoB, and last-four SSN/tax-ID. ShinyHunters claim 10 million records and are demanding ransom. Separately, HIBP published a Carnival breach of 8.7M records (7.5M unique email addresses) tied to Holland America's Mariner Society loyalty programme; Carnival attributes initial access to a single phishing compromise. These additions follow April claims against Rockstar and McGraw Hill. A British ShinyHunters member pleaded guilty last week; another is serving a 10-year sentence. RansomLook also captured Udemy and ADT leak-site posts. Relevant ATT&CK: T1566 (phishing).

> **SOC Action:** Block and alert on any inbound email or Teams/Slack message referencing internal IT helpdesk URLs that are not on the official allowlist. For tenants with Salesforce, SharePoint, or Snowflake: enable token-binding, shorten session lifetimes, and review API access logs for the "ShinyHunters" pattern of rapid authenticated queries for PII tables.

### 3.6 fast16 — Lua-powered sabotage framework predates Stuxnet by 5 years

**Source:** [SentinelOne Labs](https://www.sentinelone.com/labs/fast16-mystery-shadowbrokers-reference-reveals-high-precision-software-sabotage-5-years-before-stuxnet/), [Wired](https://www.wired.com/story/fast16-malware-stuxnet-precursor-iran-nuclear-attack/)

SentinelLABS decoded the "fast16" reference from the ShadowBrokers Territorial Dispute leak, linking it to a 2005-era sabotage toolkit built around `svcmgmt.exe` and a kernel driver `fast16.sys`. The malware selectively patches high-precision calculation software (e.g., LS-DYNA) in memory to produce systematically inaccurate results, with a self-propagation mechanism designed to infect an entire facility. It uses an embedded customised Lua 5.0 VM for modularity — three years earlier than the earliest Flame sample. Attribution is hedged, but the research highlights a possible early-2000s sabotage operation against Iranian nuclear-research workloads. Relevant ATT&CK: T1014 (rootkit), T1542.003 (bootkit), T1543.003 (Windows service), T1486 (data encrypted for impact).

#### Indicators of Compromise
```
SHA-256: 9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525  (svcmgmt.exe)
SHA-256: 06361562cc53d759fb5a4c2b7aac348e4d23fe59be3b2871b14678365283ca47
SHA-256: 07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529
SHA-256: 09ca719e06a526f70aadf34fb66b136ed20f923776e6b33a33a9059ef674da22
SHA-256: 37414d9ca87a132ec5081f3e7590d04498237746f9a7479c6b443accee17a062
SHA-256: 5966513a12a5601b262c4ee4d3e32091feb05b666951d06431c30a8cece83010
SHA-256: 66fe485f29a6405265756aaf7f822b9ceb56e108afabd414ee222ee9657dd7e2
SHA-256: 7e00030a35504de5c0d16020aa40cbaf5d36561e0716feb8f73235579a7b0909
SHA-256: 8b018452fdd64c346af4d97da420681e2e0b55b8c9ce2b8de75e330993b759a0
SHA-256: 8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9
SHA-256: aeaa389453f04a9e79ff6c8b7b66db7b65d4aaffc6cac0bd7957257a30468e33
SHA-256: bd04715c5c43c862c38a4ad6c2167ad082a352881e04a35117af9bbfad8e5613
SHA-256: c11a210cb98095422d0d33cbd4e9ecc86b95024f956ede812e17c97e79591cfa
SHA-256: da2b170994031477091be89c8835ff9db1a5304f3f2f25344654f44d0430ced1
SHA-256: e775049d1ecf68dee870f1a5c36b2f3542d1182782eb497b8ccfd2309c400b3a
```

> **SOC Action:** For engineering, defence-industrial, and research environments running LS-DYNA / high-precision CAE software: deploy EDR rules for Lua bytecode magic `1B 4C 75 61` in non-game processes, hunt for legacy `svcmgmt.exe`/`svcmgmt.dll` binaries with 2005 PE timestamps, and validate calculation integrity of critical models against known-good baselines.

### 3.7 AI Frame campaign — fake Google Authenticator Chrome extension compromises 260K+

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/69eafa0f9d3e61201eac54d4)

A malicious Chrome extension impersonating Google Authenticator is part of the ongoing "AI Frame / AiFrame" campaign, active since early 2026. The extension abuses excessive permissions and carries dormant infrastructure enabling staged malicious updates without further user interaction. It is linked to at least six companion extensions via a shared developer front, two of which already ship fully operational payloads that inject hidden iframes, display fraudulent paywalls, and maintain bidirectional C2. Reported compromises exceed 260,000 users across 2025–2026. Relevant ATT&CK: T1176, T1027, T1071.001, T1204.002.

#### Indicators of Compromise
```
Domains:
  tapnetic[.]pro
  whitelab[.]studio
  airnetic[.]space
  softnetica[.]com
  onlineapp[.]live
  sidenox[.]stream
  heic-to-jpg[.]pro
  ai-chat-to-pdf[.]com

Hosts (selection):
  authenticator[.]tapnetic[.]pro
  authenticator[.]whitelab[.]studio
  api[.]tapnetic[.]pro
  chatgpt[.]tapnetic[.]pro
  claude[.]tapnetic[.]pro
  gemini[.]tapnetic[.]pro
```

> **SOC Action:** Push a Chrome managed-policy deny-list covering the `tapnetic.pro`, `whitelab.studio`, and `airnetic.space` ecosystems (and sinkhole at DNS). Enumerate installed extensions with Authenticator-branded identities in your browser-management console; block side-loading of unsigned extensions via policy.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software platforms | CVE-2026-3844 Breeze Cache WordPress plugin (active exploitation); CVE-2026-21515 Azure IoT Central EoP |
| 🟠 **HIGH** | Ransomware-as-a-Service groups expanding operations | Udemy and ADT postings by ShinyHunters; Qilin adding eight new victims including City of Napoleon, Ohio |
| 🟠 **HIGH** | Increased targeting of governmental institutions by APT groups | GopherWhisper Mongolian government targeting; CISA report of US agency Cisco-vulnerability breach with FIRESTARTER backdoor |
| 🟠 **HIGH** | Supply-chain vulnerabilities exploited to deliver malware | Checkmarx KICS supply-chain breach; TeamPCP-style CanisterWorm npm packages |
| 🟠 **HIGH** | State-sponsored actors using social media platforms for covert comms | China-linked operators targeting Mongolian government via Slack/Discord; GopherWhisper abuse of Outlook/Slack/Discord |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (57–51 reports across aliases) — most prolific RaaS of the reporting window; added Point Four EPoS, Denso, Progressive Propane, Priests for Life, Flipo Group, Grupo ABC, Marc Cain, and the City of Napoleon, Ohio.
- **The Gentlemen** (58/24 reports) — active across engineering, government, and technology verticals; confirmed victims include EEC Group, Coralina, and Lawson Software; communicates via Tox.
- **Coinbase Cartel** (38/22 reports) — continuing multi-sector ransomware campaign spanning energy (Peru LNG), telecoms, and manufacturing.
- **DragonForce** (29/27 reports) — persistent RaaS presence.
- **ShinyHunters** — confirmed breaches at ADT, Carnival (Mariner Society), and Udemy; linked to recent Rockstar and McGraw Hill claims.
- **BlackFile / CL-CRI-1116 / UNC6671 / Cordial Spider** — newly named vishing extortion crew; possible affiliation with "The Com".
- **nightspire / shadowbyt3$** — ongoing RansomLook visibility.

### Malware Families
- **RansomLook / RansomLock** (45+22 reports) — leak-site infrastructure indexed across Qilin, Inc Ransom, Shinyhunters, Payload, RansomHouse, Insomnia, Beast, AiLock, Payoutsking.
- **DragonForce Ransomware** (26 reports) — continued affiliate-delivered encryption operations.
- **Akira ransomware** (12 reports) — persistent background activity.
- **Beast ransomware** — RaaS evolution of "Monster"; hybrid ECC + ChaCha20 encryption with multithreaded / segmented encryption and ESXi support.
- **AiLock** — ChaCha20 + NTRUEncrypt double-extortion RaaS appending `.AiLock`.
- **uWarrior RAT** — new Italian-origin RAT delivered via RTF exploits (CVE-2012-1856 + CVE-2015-1770 OLE ASLR bypass), borrowing from ctOS; C2 at 63.142.245[.]12, `login.collegefan[.]org`, `login.loginto[.]me`.
- **fast16 / svcmgmt.exe / svcmgmt.dll** — newly disclosed pre-Stuxnet sabotage framework.
- **Tox / Tox1** (28 combined) — continues as preferred comm channel for The Gentlemen and Payoutsking.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 44 | [link](https://msrc.microsoft.com/update-guide) | Linux-kernel and Microsoft product CVE disclosures (majority info/medium) |
| RansomLock | 27 | [link](https://www.ransomlook.io/) | Leak-site monitoring across Qilin, Inc Ransom, The Gentlemen, ShinyHunters, RansomHouse, Payload, Beast, AiLock, Insomnia, Payoutsking |
| BleepingComputer | 7 | [link](https://www.bleepingcomputer.com/news/security/hackers-exploit-file-upload-bug-in-breeze-cache-wordpress-plugin/) | Primary coverage of Breeze Cache RCE, Pack2TheRoot, Zimbra exposure, BlackFile |
| RecordedFutures | 5 | [link](https://therecord.media/ADT-data-breach-cyberattack) | ADT breach, US Cambodia sanctions, SMS blaster arrests |
| AlienVault | 3 | [link](https://otx.alienvault.com/pulse/69eafa0f9d3e61201eac54d4) | uWarrior, AI Frame campaign, fast16 |
| Schneier | 2 | [link](https://www.schneier.com/) | Bluetooth tracker in mail (supply-chain surveillance) |
| Wired Security | 2 | [link](https://www.wired.com/story/fast16-malware-stuxnet-precursor-iran-nuclear-attack/) | fast16 long-read |
| Unknown (Telegram) | 2 | — | Telegram (channel name redacted) — ransomware leaderboards and breach links |
| Sentinel One | 1 | [link](https://www.sentinelone.com/labs/fast16-mystery-shadowbrokers-reference-reveals-high-precision-software-sabotage-5-years-before-stuxnet/) | Primary fast16 disclosure |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/frontier-ai-top-questions-answered/) | Frontier AI and defence (BlackFile attribution context) |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Carnival) | Carnival 7.5M-account breach |
| CISA | 1 | [link](https://www.cisa.gov/news-events/alerts/2026/04/24/cisa-adds-four-known-exploited-vulnerabilities-catalog) | Four KEV additions |
| SANS | 1 | [link](https://isc.sans.edu/) | ISC diary |
| Sysdig | 1 | [link](https://sysdig.com/blog/) | Cloud workload coverage |
| BellingCat | 1 | [link](https://www.bellingcat.com/) | OSINT reporting |

*Trend-snapshot enrichment was unavailable for this period (the snapshot API returned zero entries).*

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all WordPress sites running Breeze Cache to ≥ 2.4.5 or disable the plugin / "Host Files Locally – Gravatars" add-on today. Exploitation is active (ref. §3.1).
- 🔴 **IMMEDIATE:** Complete emergency KEV reconciliation against Samsung MagicINFO, SimpleHelp, D-Link DIR-823X, and Zimbra (CVE-2025-48700). Internet-exposed Zimbra Classic UI should be disabled until patched (ref. §3.2).
- 🟠 **SHORT-TERM:** Deploy PackageKit 1.3.5 across Linux fleets and mask the daemon on non-interactive hosts; bake CVE-2026-41651 detection into build pipelines before new 26.04 LTS images are released (ref. §3.3).
- 🟠 **SHORT-TERM:** Harden helpdesk call-handling against BlackFile/ShinyHunters-style vishing — enforce callback verification, alert on new MFA device registrations, and cap Salesforce/SharePoint bulk-download volumes (refs. §3.4, §3.5).
- 🟡 **AWARENESS:** Brief senior leadership and comms staff on the ShinyHunters resurgence and associated ransom-threat playbook; prepare rapid-response messaging templates in case of leak-site listing (ref. §3.5).
- 🟢 **STRATEGIC:** For organisations in defence, nuclear, and high-precision engineering: treat the fast16 disclosure as a reminder to periodically validate calculation integrity of mission-critical simulation workloads against sealed baselines, and to audit legacy Windows hosts for decade-old driver remnants (ref. §3.6).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 99 reports processed across 4 correlation batches (batch IDs 84–87). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
