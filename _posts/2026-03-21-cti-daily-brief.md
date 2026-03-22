---
layout: post
title: "CTI Daily Brief: 2026-03-21 — Qilin and Nightspire ransomware campaigns surge; VoidStealer debuts novel Chrome ABE bypass"
date: 2026-03-22 21:16:00 +0000
description: "Ransomware dominated the 24-hour reporting window with Qilin claiming six victims and Nightspire adding five. VoidStealer introduced a first-of-its-kind hardware-breakpoint technique to steal Chrome master keys. Correlated trends flagged Citrix CVE-2025-6543 zero-day exploitation and cloud credential phishing as critical and high-risk developments."
category: daily
tags: [cti, daily-brief, qilin, nightspire, voidstealer, everest]
classification: TLP:CLEAR
reporting_period: "2026-03-21"
generated: "2026-03-22"
draft: true
severity: high
report_count: 17
sources:
  - RansomLock
  - BleepingComputer
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-21 (24h) | TLP:CLEAR | 2026-03-22 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 17 reports from 3 sources over the past 24 hours, with 16 rated high and 1 medium. Ransomware-as-a-Service operations dominated the reporting window: Qilin (aka Agenda) claimed six new victims spanning transport, real estate, manufacturing, technology, and entertainment sectors, while Nightspire posted five victims across hospitality, consulting, cannabis, and pharmacy services. BleepingComputer published analysis of VoidStealer, a MaaS infostealer that is the first malware observed in the wild using hardware breakpoints to bypass Chrome's Application-Bound Encryption and extract the v20 master key directly from browser memory. The Everest ransomware group leaked a database from First Priority Group, continuing its shift toward pure data extortion. Correlation analysis identified Citrix CVE-2025-6543 zero-day exploitation targeting government networks as a critical-risk trend and flagged ongoing cloud credential phishing campaigns as high-risk.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | — |
| 🟠 **HIGH** | 16 | Qilin RaaS (6), Nightspire RaaS (5), VoidStealer ABE bypass, Alp-001 (2), Everest data leak, Payload ransomware |
| 🟡 **MEDIUM** | 1 | Nightspire victim (partially redacted) |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 0 | — |

## 3. Priority Intelligence Items

### 3.1 VoidStealer Introduces Hardware-Breakpoint Chrome ABE Bypass

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/voidstealer-malware-steals-chrome-master-key-via-debugger-trick/)

VoidStealer, a MaaS platform advertised on dark web forums since mid-December 2025, introduced a novel Application-Bound Encryption bypass in version 2.0. The technique attaches a debugger to a suspended, hidden browser process, waits for `chrome.dll` or `msedge.dll` to load, scans for a specific string and `LEA` instruction, then sets hardware breakpoints across browser threads. When the breakpoint triggers during startup decryption, VoidStealer reads the register holding a pointer to the plaintext `v20_master_key` and extracts it via `ReadProcessMemory`. Gen Digital researchers confirmed this is the first in-the-wild adoption of this method, likely derived from the open-source ElevationKatz project. The technique requires no privilege escalation or code injection, making it stealthier than prior ABE bypasses.

**Affected:** All Chromium-based browsers (Chrome, Edge) on Windows. Any organisation storing credentials, cookies, or session tokens in browser-managed storage.

**MITRE ATT&CK:** T1555 (Credentials from Password Stores), T1106 (Native API), T1057 (Process Discovery)

> **SOC Action:** Query EDR for processes attaching as debuggers to `chrome.exe` or `msedge.exe` with hardware breakpoint registration (look for `SetThreadContext` calls with `DR0`–`DR3` register modifications). Hunt for suspended browser processes spawned by non-browser parent processes. Review endpoint telemetry for `ReadProcessMemory` calls targeting browser DLLs.

### 3.2 Qilin RaaS Claims Six Victims Across Multiple Sectors

**Source:** [RansomLook — Qilin](https://www.ransomlook.io//group/qilin)

Qilin (also tracked as Agenda) posted six new victims to its leak site within a single 24-hour window: J E Culp Transport (logistics), Southern Commercial Real Estate (property), Southwire (manufacturing/electrical), Marc Dorcel (entertainment), nPower Technologies (energy technology), and Elite Limousine Plus (transport services). The group operates a mature RaaS infrastructure with active Tor onion domains, FTP-based data exfiltration servers, and encrypted communication via Tox and Jabber. Two onion domains and one file server showed 100% uptime over the past 30 days, indicating stable operational infrastructure.

**MITRE ATT&CK:** T1566 (Phishing), T1486 (Data Encrypted for Impact), T1567 (Exfiltration Over Web Service)

> **SOC Action:** Review email gateway logs for phishing lures referencing invoices, shipping documents, or real estate transactions. Ensure network-level blocking of known Qilin FTP exfiltration IPs. Validate offline backup integrity for systems in logistics, manufacturing, and property management verticals.

### 3.3 Nightspire Posts Five Victims; Affiliate Network Expanding

**Source:** [RansomLook — Nightspire](https://www.ransomlook.io//group/nightspire)

Nightspire added five victims in the reporting window: Cannavative Group (cannabis), SAS Cap Estel Hotel (hospitality, France), Semenya Furumele Consulting Engineers (engineering, South Africa), and two partially redacted entities. The group operates through at least six named affiliates (Phantom, Reaper, Volt, Blaze, Shadow, Blade) and maintains communication via ProtonMail, OnionMail, Telegram, and three Tox IDs. Nightspire's operational tempo has accelerated, with 269 total victims tracked on their leak site and consistent daily postings throughout March 2026. Infrastructure shows mixed reliability — one primary onion domain maintains 100% uptime while others are offline.

**MITRE ATT&CK:** T1566 (Phishing), T1059 (Command and Scripting Interpreter)

> **SOC Action:** Monitor for email communications from `nightspireteam@proton[.]me` and `nightspireteam@onionmail[.]org` in spam quarantine. Block Nightspire Tox IDs and Telegram handles at the network policy level where feasible. Assess exposure of hospitality and professional services clients to ransomware pre-positioning.

### 3.4 Everest Leaks First Priority Group Database

**Source:** [RansomLook — Everest](https://www.ransomlook.io//group/everest)

Everest, active since December 2020, published a leaked database from First Priority Group. The group has shifted from traditional file encryption to pure data extortion, threatening to sell or release stolen data without deploying ransomware. Everest targets government, healthcare, manufacturing, and IT services sectors across North America, Europe, and Asia. Initial access vectors include exploitation of public-facing applications (T1190), phishing campaigns (T1566), and credential theft for remote access. The group's Tor-based leak site maintains 97% uptime and has published 431 victim posts to date.

**MITRE ATT&CK:** T1566 (Phishing), T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts)

> **SOC Action:** Search for First Priority Group in your supply chain and third-party vendor registry. If a relationship exists, initiate third-party breach response procedures and credential rotation for any shared integrations. Monitor dark web leak sites for data samples containing your organisation's information.

### 3.5 Alp-001 Claims Hikvision.com and IRCO.com

**Source:** [RansomLook — Alp-001](https://www.ransomlook.io//group/alp-001)

A relatively new ransomware group tracked as Alp-001 claimed two high-profile victims: Hikvision (a major surveillance and IoT equipment manufacturer) and IRCO (a USA-based entity with reported $7.7 billion revenue and 5.9 TB of exfiltrated data). The group's infrastructure is minimal — two onion domains with one maintaining 100% uptime — suggesting an emerging operation. No specific TTPs beyond Tor-based C2 and Tox-based communication have been disclosed.

> **SOC Action:** Organisations using Hikvision equipment should monitor for firmware integrity alerts and review network segmentation of surveillance infrastructure. Assess whether your environment depends on IRCO services and prepare for potential data exposure notifications.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in Citrix products (CVE-2025-6543) | Correlated reports on CVE-2025-6543 in-the-wild exploitation since May 2025; Citrix Netscaler backdoors targeting government networks |
| 🟠 **HIGH** | Qilin ransomware surge across 6 sectors in a single day | 6 victim posts sharing actor and T1566 phishing TTP with 0.90 confidence correlation |
| 🟠 **HIGH** | Phishing campaigns targeting cloud service credentials | AWS console credential phishing campaign; Tycoon2FA PhaaS platform persistence post-takedown |
| 🟠 **HIGH** | Nightspire affiliate network sustaining high operational tempo | 5 victims in 24h, 6 tracked affiliates, multi-channel C2 infrastructure |
| 🟡 **MEDIUM** | Enterprise supply chain and outsourcing risk | Red Hat Consulting breach affecting 5000+ enterprise customers; Trivy supply chain compromise; UK public sector outsourcing concerns |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Nightspire** (5 reports) — RaaS group with expanding affiliate network; accelerating victim posting cadence across hospitality, engineering, and professional services
- **Qilin / Agenda** (5 reports) — Established RaaS operation claiming six cross-sector victims in a single day via phishing-initiated intrusions
- **Handala** (14 reports) — Pro-Palestinian hacktivist group; high report volume across the past two weeks, though no new activity in this 24h window
- **Everest** (1 report) — Data extortion group that leaked First Priority Group database; 431 total victims, shifting away from encryption
- **Alp-001** (2 reports) — Emerging group claiming Hikvision and IRCO; minimal known infrastructure

### Malware Families

- **VoidStealer** (2 reports) — MaaS infostealer with novel Chrome ABE bypass via hardware breakpoints; first in-the-wild observation of this technique
- **Slopoly** (4 reports) — Active across the past two weeks; details pending further analysis
- **DarkSword** (3 reports) — Linked to Aisuru/JackSkid activity clusters
- **NodeSnake** (3 reports) — Node.js-based backdoor observed in recent campaigns
- **Perseus** (3 reports) — Malware family tracked across multiple mid-March reports

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 15 | [link](https://www.ransomlook.io) | Ransomware leak site monitoring; Qilin (6), Nightspire (5), Alp-001 (2), Payload (1), Everest (1) |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com) | VoidStealer malware analysis — Chrome ABE bypass |
| Telegram (channel name redacted) | 1 | — | Anti-India cyber activity callout; TLP:AMBER+STRICT — limited operational value |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Hunt for VoidStealer debugger-based ABE bypass activity — query EDR for `SetThreadContext` calls modifying debug registers (`DR0`–`DR3`) targeting `chrome.exe`/`msedge.exe`, and `ReadProcessMemory` calls against browser DLLs from non-browser parent processes. Consider deploying detection rules for the ElevationKatz toolset signatures.

- 🟠 **SHORT-TERM:** Validate Citrix NetScaler and ADC patch status against CVE-2025-6543. Correlation analysis identified this as a critical trend with confirmed zero-day exploitation against government networks since May 2025. Audit Citrix appliances for indicators of backdoor activity.

- 🟠 **SHORT-TERM:** Review phishing defences for cloud credential harvesting — the Tycoon2FA PhaaS platform persists post-takedown, and a dedicated AWS console credential campaign is active. Enforce phishing-resistant MFA on all cloud management consoles and audit conditional access policies.

- 🟡 **AWARENESS:** Assess supply chain exposure to Qilin, Nightspire, and Everest victim organisations. If any named victims (Southwire, Hikvision, IRCO, First Priority Group) are in your vendor ecosystem, initiate third-party breach response playbooks and prepare for data exposure notifications.

- 🟢 **STRATEGIC:** Evaluate browser credential storage policies enterprise-wide. VoidStealer's ABE bypass demonstrates that browser-stored credentials remain a high-value target despite Google's encryption improvements. Migrate sensitive credentials to dedicated password managers and enforce enterprise browser policies that disable local credential caching where feasible.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 17 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
