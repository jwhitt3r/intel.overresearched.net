---
layout: post
title: "CTI Daily Brief: 2026-04-02 — TeamPCP Supply Chain Campaign Breaches European Commission, Chromium V8 Critical CVEs, Akira Ransomware Surge"
date: 2026-04-03 20:15:00 +0000
description: "Supply chain attacks dominate the threat landscape as TeamPCP's Trivy compromise reaches the European Commission, six critical Chromium CVEs disclosed, Akira and Nightspire ransomware groups claim multiple victims, and DPRK-linked actors target South Korean organisations with LNK-based campaigns."
category: daily
tags: [cti, daily-brief, teampcp, akira, qilin, chromium, vidar, supply-chain]
classification: TLP:CLEAR
reporting_period: "2026-04-02"
generated: "2026-04-03"
draft: true
severity: critical
report_count: 69
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - SANS
  - Cisco Talos
  - Wired Security
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-02 (24h) | TLP:CLEAR | 2026-04-03 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 69 reports from 10 sources over the past 24 hours, with 19 rated critical and 29 rated high — an elevated threat posture driven by two converging themes: supply chain compromise and prolific ransomware operations. The TeamPCP supply chain campaign reached its most significant milestone yet as CERT-EU confirmed a breach of the European Commission's AWS cloud environment via the compromised Trivy scanner (CVE-2026-33634), with 340 GB of data exfiltrated and published by ShinyHunters. Mandiant now quantifies the campaign's reach at over 1,000 SaaS environments. Separately, Microsoft disclosed six critical Chromium vulnerabilities including V8 object corruption (CVE-2026-5279) and multiple use-after-free flaws in Dawn, CSS, and GPU components. Ransomware groups Akira, Nightspire, and Qilin collectively claimed 20+ new victims across manufacturing, insurance, education, and government sectors, while FortiGuard Labs published technical analysis of DPRK-linked campaigns using LNK files with GitHub C2 infrastructure to target South Korean organisations.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 19 | TeamPCP EU Commission breach; Chromium V8/Dawn/ANGLE/CSS/GPU CVEs; Spring AI RCE (CVE-2026-22738); Akira ransomware claims; Axios supply chain RAT |
| 🟠 **HIGH** | 29 | Qilin hits Die Linke; Nightspire 7-victim cluster; DPRK LNK campaigns; Massachusetts emergency comms attack; Ukraine CERT-UA Russian re-intrusion warning |
| 🟡 **MEDIUM** | 19 | Axios npm technical advisory; Hims & Hers Zendesk breach; FCC robocall fine; CBP facility code leak; Exchange Online access issues |
| 🔵 **INFO** | 2 | Microsoft Windows 11 24H2 force upgrades |

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Campaign — European Commission Cloud Breach Confirmed

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/32864), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cert-eu-european-commission-hack-exposes-data-of-30-eu-entities/), [Recorded Future News](https://therecord.media/european-commission-cyberattack-teampcp)

CERT-EU confirmed that TeamPCP breached the European Commission's Europa web hosting platform on AWS through the Trivy supply chain compromise (CVE-2026-33634). Attackers stole AWS API keys via the compromised scanner on 19 March, went undetected for five days until SOC alerts fired on 24 March, and exfiltrated 340 GB of data including approximately 52,000 email-related files. ShinyHunters published the stolen dataset on 28 March. The breach affected 42 internal Commission departments and at least 29 other EU entities. Mandiant now estimates the broader TeamPCP campaign has impacted over 1,000 SaaS environments. Sportradar AG ($4.98B Swiss sports tech company) was also confirmed as a joint TeamPCP/Vect ransomware victim. Cisco Talos published a strategic analysis emphasising the systemic risk posed by supply chain attacks against widely-adopted open-source tooling.

ATT&CK: T1195 (Supply Chain Compromise), T1078 (Valid Accounts), T1537 (Transfer Data to Cloud Account)

> **SOC Action:** Audit all CI/CD pipelines for Trivy versions prior to the patched release. Rotate any AWS credentials that may have been exposed to compromised Trivy scanners. Query CloudTrail logs for `CreateAccessKey` and `AttachUserPolicy` API calls from unrecognised principals between 10–25 March 2026.

### 3.2 Chromium Critical Vulnerability Batch — V8, Dawn, ANGLE, CSS, GPU

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5279)

Microsoft disclosed six critical Chromium vulnerabilities affecting Chrome and Edge: CVE-2026-5279 (object corruption in V8), CVE-2026-5281 and CVE-2026-5286 (use-after-free in Dawn), CVE-2026-5275 (heap buffer overflow in ANGLE), CVE-2026-5273 (use-after-free in CSS), and CVE-2026-5272 (heap buffer overflow in GPU). Three additional high-severity Chromium CVEs were also disclosed (CVE-2026-5291, CVE-2026-5287, CVE-2026-5285). The V8 object corruption flaw is particularly concerning given V8's history as an exploitation target for drive-by and watering-hole attacks.

> **SOC Action:** Prioritise Chrome/Edge patching to the latest stable channel. Verify auto-update is functioning on managed endpoints. Query browser version telemetry and flag any devices running versions prior to this patch batch. Consider temporary mitigation via site isolation enforcement for unpatched systems.

### 3.3 Axios NPM Supply Chain Attack — DPRK State Actor Deploys Cross-Platform RAT

**Source:** [SentinelOne / AlienVault](https://www.sentinelone.com/blog/securing-the-supply-chain-how-sentinelones-ai-edr-stops-the-axios-attack-autonomously/), [Cisco Talos](https://blog.talosintelligence.com/axios-npm-supply-chain-incident/)

A North Korean state actor (tracked as UNC1069/Sapphire Sleet) hijacked the npm credentials of the Axios maintainer and published backdoored versions 1.7.9 and 0.28.1 that deployed the WAVESHAPER.V2 cross-platform RAT on Windows, macOS, and Linux. The malicious packages were live for approximately three hours and accumulated an estimated 600,000 downloads. The attacker bypassed OIDC Trusted Publishing protections by exploiting a coexisting legacy npm access token. The RAT communicated over HTTP to C2 infrastructure and self-deleted post-execution to evade forensics.

#### Indicators of Compromise
```
C2: sfrclak[.]com (142.11.206[.]73)
Domain: callnrwise[.]com
Domain: chickencoinwin[.]website
Domain: focusrecruitment[.]careers
SHA256: 58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668
SHA256: 5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd
```

ATT&CK: T1195.002 (Compromise Software Supply Chain), T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol)

> **SOC Action:** Audit `package-lock.json` and `yarn.lock` files across all repositories for axios versions 1.7.9 or 0.28.1. Query EDR for DNS resolution to `sfrclak[.]com`, `callnrwise[.]com`, `chickencoinwin[.]website`, or `focusrecruitment[.]careers`. Check npm audit logs for any installs of `plain-crypto-js`. Rotate credentials for any npm service accounts that use long-lived tokens alongside OIDC.

### 3.4 DPRK LNK and GitHub C2 Campaigns Targeting South Korea

**Source:** [FortiGuard Labs / AlienVault](https://www.fortinet.com/blog/threat-research/dprk-related-campaigns-with-lnk-and-github-c2)

FortiGuard Labs documented an active DPRK-linked campaign using weaponised LNK files with multi-stage scripting and GitHub-hosted C2 infrastructure targeting South Korean organisations. The campaign deploys XenoRAT and has evolved to embed encoded payloads directly inside LNK files with XOR-based decoding functions. Earlier versions contained metadata linking activity to North Korean groups (Kimsuky, APT37, Lazarus), though recent variants strip this metadata. The attack chain uses decoy PDFs targeting corporate victims while PowerShell scripts execute silently in the background, performing environment checks for analysis tools before establishing persistence.

#### Indicators of Compromise
```
SHA256: 484a16d779d67c7339125ceac10b9abf1aa47f561f40058789bfe2acda548282
SHA256: 9c3f2bd300ad2ef8584cc48adc47aab61bf85fc653d923e106c73fc6ec3ea1dc
SHA256: af0309aa38d067373c54b2a7774a32f68ab72cb2dbf5aed74ac784b079830184
SHA256: c0866bb72c7a12a0288f434e16ba14eeaa35d3c4cff4a86046c553c15679c0b5
SHA256: f20fde3a9381c22034f7ecd4fef2396a85c05bfd54f7db3ad6bcd00c9e09d421
```

ATT&CK: T1566 (Phishing), T1059.001 (PowerShell), T1071 (Application Layer Protocol)

> **SOC Action:** Deploy detection rules for LNK files spawning PowerShell with encoded arguments. Hunt for GitHub API traffic from non-developer endpoints. Block known IOC hashes at the endpoint. Monitor for process lineage patterns of `explorer.exe → cmd.exe → powershell.exe` with `-encodedcommand` flags.

### 3.5 Ransomware Cluster: Akira, Nightspire, Qilin, and DragonForce Multi-Victim Claims

**Source:** [RansomLook](https://www.ransomlook.io), [BleepingComputer](https://www.bleepingcomputer.com/news/security/die-linke-german-political-party-confirms-data-stolen-by-qilin-ransomware/)

Four ransomware groups posted 20+ new victim claims in the past 24 hours. Akira claimed at least five victims across manufacturing (Woodland Trade, American Vintage Home, Briggs Plumbing, Genco Manufacturing), insurance (Charles River Insurance), and telecommunications (Westamerica Communications). Nightspire listed seven victims spanning construction (Siena Construction), defence (TTAF Defense), and religious organisations (Southeastern Conference of Seventh-day Adventists). Qilin confirmed a politically significant attack against Die Linke, a German political party with 64 Bundestag members and 123,000 registered members — the party attributes the attack to Russian-speaking actors and frames it as hybrid warfare. Analysis of Qilin's new EDR-Killer malware capabilities surfaced via Telegram intelligence channels, indicating the group is investing in defence evasion tooling. DragonForce claimed law firm Asmar Schor & McKenna.

ATT&CK: T1486 (Data Encrypted for Impact), T1567 (Exfiltration Over Web Service)

> **SOC Action:** Validate EDR agent health across all endpoints — Qilin's EDR-Killer tool specifically targets security agent processes. Review lateral movement detection rules for credential dumping patterns. Ensure offline backup integrity for critical systems. Political organisations and NGOs should elevate alert posture given Qilin's demonstrated targeting of this sector.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks leveraging compromised credentials and infrastructure | TeamPCP EU Commission breach via Trivy; Cisco Talos supply chain analysis; Axios npm compromise |
| 🔴 **CRITICAL** | Exploitation of software vulnerabilities in widely used technologies | Chromium CVE-2026-5279 V8 object corruption; CVE-2026-5286/5281 Dawn UAF; CVE-2026-22738 Spring AI SpEL RCE |
| 🟠 **HIGH** | Increased ransomware activity with double extortion tactics across multiple sectors | Akira 5-victim cluster; Nightspire 7-victim cluster; Qilin Die Linke attack; DragonForce Asmar Schor & McKenna |
| 🟠 **HIGH** | Phishing remains prevalent TTP across ransomware and data breach incidents | DPRK LNK campaigns; Nightspire phishing-based initial access; Everest credential theft |
| 🟠 **HIGH** | Government and critical infrastructure sector targeting | EU Commission breach; Massachusetts emergency comms attack; CERT-UA Russian re-intrusion warning; Die Linke political party |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (39 reports) — Prolific ransomware operator; confirmed attack on German political party Die Linke; new EDR-Killer malware capability
- **Nightspire** (30 reports) — Rapidly expanding victim list across construction, defence, and religious sectors
- **TeamPCP** (28 reports) — Supply chain threat group; confirmed breach of European Commission via Trivy compromise
- **Akira** (19 reports) — Double-extortion ransomware targeting manufacturing, insurance, and telecom
- **DragonForce** (19 reports) — RaaS operator; joint operation with Vect on Sportradar AG breach
- **ShinyHunters** (12 reports) — Published stolen EU Commission data; involvement in TeamPCP credential distribution chain
- **APT28 / Fancy Bear** (mentioned) — CERT-UA warns of re-intrusion campaigns against Ukrainian military and government

### Malware Families

- **DragonForce Ransomware** (18 reports) — Primary payload for DragonForce operations
- **Akira Ransomware** (15 reports) — VMware ESXi-targeting variant with Bitcoin ransom demands
- **Qilin Ransomware** (15 reports combined) — Deploying new EDR-Killer evasion capabilities
- **WAVESHAPER.V2** (new) — Cross-platform RAT deployed via compromised Axios npm packages
- **Vidar** (5 reports) — Infostealer distributed via fake Claude Code leak repositories on GitHub
- **XenoRAT** (new) — Deployed by DPRK actors via LNK/PowerShell chain with GitHub C2

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 23 | [link](https://www.ransomlook.io) | Ransomware victim claim tracking across Akira, Nightspire, Qilin, DragonForce, Interlock, Payload, INC Ransom, Beast, Ailock, Everest |
| Microsoft | 17 | [link](https://msrc.microsoft.com/update-guide) | Chromium CVE advisories — 6 critical, 3 high |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | EU Commission breach; Die Linke/Qilin; Claude Code malware; ransomware evolution analysis |
| Unknown (Telegram) | 7 | — | CVE-2026-22738 Spring AI PoC; Qilin EDR-Killer analysis; camera credential sales; exploit marketplace |
| RecordedFutures | 4 | [link](https://therecord.media) | EU Commission attribution; Ukraine CERT-UA warning; Massachusetts emergency comms; FCC robocall fine |
| AlienVault | 3 | [link](https://otx.alienvault.com) | DPRK LNK campaigns; Axios supply chain deep-dive; web-delivered malware hunting |
| SANS | 2 | [link](https://isc.sans.edu) | TeamPCP campaign Update 006 — definitive operational summary |
| Cisco Talos | 2 | [link](https://blog.talosintelligence.com) | Supply chain strategic analysis; Axios npm incident advisory |
| Wired Security | 2 | [link](https://www.wired.com) | CBP facility codes leaked via Quizlet flashcards |
| Schneier | 1 | [link](https://www.schneier.com) | Company secretly recording and publishing Zoom meetings |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all CI/CD pipelines for exposure to the Trivy supply chain compromise (CVE-2026-33634). Rotate any AWS credentials that may have transited through compromised Trivy versions. The EU Commission breach confirms that stolen credentials are actively being used against high-value targets with 5-day detection lag.

- 🔴 **IMMEDIATE:** Patch Chrome and Edge browsers to the latest stable channel to address six critical vulnerabilities including V8 object corruption (CVE-2026-5279) and heap buffer overflows in ANGLE and GPU components. Verify auto-update functionality across all managed endpoints.

- 🟠 **SHORT-TERM:** Audit JavaScript dependency chains for compromised Axios versions (1.7.9 and 0.28.1). Revoke any long-lived npm access tokens that coexist with OIDC Trusted Publishing — the Axios attack proved these legacy credentials bypass modern controls. Query EDR for WAVESHAPER.V2 IOCs across all platforms.

- 🟠 **SHORT-TERM:** Validate EDR agent health and implement tamper protection alerting. Qilin's newly documented EDR-Killer malware specifically targets security agent processes before deploying ransomware. Ensure offline backup integrity and test restoration procedures for critical systems.

- 🟡 **AWARENESS:** Organisations using Spring AI SimpleVectorStore should assess exposure to CVE-2026-22738 (SpEL Injection RCE). A proof-of-concept is circulating publicly. Apply vendor patches when available and restrict network access to affected services.

- 🟡 **AWARENESS:** CERT-UA warns that Russian threat actors (APT28, Void Blizzard) are revisiting previously breached infrastructure to check for persistent access. Organisations that experienced security incidents in 2025 should verify complete remediation — including credential rotation, vulnerability patching, and access revocation — not just incident closure.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 69 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
