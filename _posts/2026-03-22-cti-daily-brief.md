---
layout: post
title: "CTI Daily Brief: 2026-03-22 — Trivy Supply-Chain Attack Escalates, CISA Adds DarkSword iOS Exploits to KEV, FBI Warns of Handala Telegram C2"
date: 2026-03-23 21:07:55 +0000
description: "Supply-chain compromises dominated the reporting period as TeamPCP re-compromised Aqua Security's Trivy scanner and deployed the CanisterWorm wiper against Iranian targets. CISA added three DarkSword iOS exploit-chain CVEs to the KEV catalogue, and the FBI issued a flash alert on Iranian MOIS-linked Handala group leveraging Telegram for C2. Akira, Nightspire, and ShinyHunters drove a high volume of ransomware and extortion activity across multiple sectors."
category: daily
tags: [cti, daily-brief, teampcp, handala, darksword, akira, ghostclaw, citrix]
classification: TLP:CLEAR
reporting_period: "2026-03-22"
generated: "2026-03-23"
severity: critical
draft: true
report_count: 88
sources:
  - Microsoft
  - BleepingComputer
  - RansomLock
  - Krebs on Security
  - RecordedFutures
  - Elastic Security Labs
  - Wiz
  - Wired Security
  - Crowdstrike
  - Cisco Talos
  - Sysdig
  - SANS
  - Schneier
  - AppOmni
  - CertEU
  - AlienVault
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-22 (24h) | TLP:CLEAR | 2026-03-23 |

## 1. Executive Summary

The pipeline processed 88 reports from 15+ sources over the past 24 hours, with 16 rated critical and 28 rated high. Supply-chain compromise was the dominant theme: TeamPCP re-established access to Aqua Security's GitHub organisation and Docker Hub, pushing malicious Trivy images and renaming 44 repositories, while simultaneously deploying the CanisterWorm wiper against Iranian targets. CISA added three CVEs from the DarkSword iOS exploit chain to its Known Exploited Vulnerabilities catalogue, ordering federal agencies to patch by 3 April. The FBI published a flash alert warning that Iranian MOIS-linked Handala hackers are using Telegram as command-and-control infrastructure in campaigns targeting journalists and dissidents. Ransomware volume remained elevated, with Akira claiming four victims, Nightspire listing three, and ShinyHunters threatening to leak 200 GB of Ameriprise Financial data. Citrix released patches for two NetScaler vulnerabilities including a CVSS 9.3 out-of-bounds read affecting SAML IdP configurations.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 16 | Trivy supply-chain attack; CanisterWorm wiper; DarkSword iOS KEV additions; Chromium WebRTC/Blink/V8 CVEs; ShinyHunters extortion; Handala Telegram C2 |
| 🟠 **HIGH** | 28 | Citrix NetScaler CVEs; GhostClaw macOS infostealer; Chromium ANGLE/WebRTC CVEs; Akira/Nightspire/Qilin ransomware victims; AI coding agent security risks |
| 🟡 **MEDIUM** | 31 | Cisco Talos annual review; additional Chromium CVEs; data breach claims |
| 🟢 **LOW** | 4 | Regional data breach claims |
| 🔵 **INFO** | 9 | Security tooling advisories; editorial coverage |

## 3. Priority Intelligence Items

### 3.1 Trivy Supply-Chain Attack Escalates — TeamPCP Re-Compromises Aqua Security

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/trivy-supply-chain-attack-spreads-to-docker-github-repos/), [AppOmni](https://appomni.com/ao-labs/trivy-compromise-supply-chain-attack-explained/)

TeamPCP re-established unauthorised access to Aqua Security's GitHub organisations and Docker Hub after an incomplete credential rotation from an earlier March incident. The attackers pushed malicious Docker images tagged `0.69.5` and `0.69.6` to Docker Hub (the last legitimate release is `0.69.3`), injected the TeamPCP Cloud stealer credential-harvesting malware into CI/CD pipelines, and renamed all 44 repositories in the `aquasec-com` GitHub organisation. The compromise exploited a service account (`Argon-DevOps-Mgt`) authenticated via a long-lived Personal Access Token without MFA. Organisations running Trivy in CI/CD should treat any pipeline execution since 22 March as potentially compromised.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain), T1528 (Steal Application Access Token)

> **SOC Action:** Audit all Trivy Docker images and GitHub Actions references. Pin to verified commit SHAs, not mutable tags. Revoke and rotate any credentials exposed in CI/CD runners that executed Trivy between 20–23 March. Search build logs for connections to TeamPCP infrastructure.

### 3.2 CanisterWorm Wiper Targets Iranian Systems via Cloud Infrastructure

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/03/canisterworm-springs-wiper-attack-targeting-iran/)

TeamPCP deployed a new destructive payload — CanisterWorm — that selectively wipes data on systems matching Iran's timezone or with Farsi as the default language. The worm propagates through exposed Docker APIs, Kubernetes clusters, Redis servers, and the React2Shell vulnerability. If the target has Kubernetes cluster access, CanisterWorm destroys data on every node; otherwise it wipes the local machine. The C2 infrastructure uses Internet Computer Protocol (ICP) canisters — blockchain-based smart contracts resistant to takedown. This campaign shares technical infrastructure with the Trivy supply-chain attack (3.1).

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1485 (Data Destruction), T1610 (Deploy Container)

> **SOC Action:** Audit exposed Docker APIs and Kubernetes control planes for unauthorised access. Ensure Redis instances are not publicly reachable. Scan for CanisterWorm indicators tied to ICP canister domains. Organisations with Iran-locale systems should verify data integrity and check for anomalous container deployments.

### 3.3 CISA Adds DarkSword iOS Exploit-Chain CVEs to KEV Catalogue

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-darksword-ios-flaws-exploited-attacks/)

CISA added three vulnerabilities from the DarkSword iOS exploit kit to the KEV catalogue: CVE-2025-31277, CVE-2025-43510, and CVE-2025-43520. The full chain comprises six CVEs enabling sandbox escape, privilege escalation, and remote code execution on iPhones running iOS 18.4 through 18.7. Google Threat Intelligence Group linked DarkSword to UNC6748 (customer of Turkish surveillance vendor PARS Defense) and UNC6353 (suspected Russian espionage). UNC6353 deployed DarkSword in watering-hole attacks against Ukrainian e-commerce and industrial websites, dropping the GhostBlade infostealer, GhostKnife backdoor, and GhostSaber code-execution implant. Federal agencies must patch by 3 April 2026 per BOD 22-01.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution), T1189 (Drive-by Compromise)

> **SOC Action:** Verify all managed iOS devices are updated to iOS 18.8 or later. Query MDM for devices still on iOS 18.4–18.7 and prioritise remediation. Block known DarkSword watering-hole domains at the proxy layer.

### 3.4 FBI Flash Alert: Handala Uses Telegram for C2 in Espionage Campaigns

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-warns-of-handala-hackers-using-telegram-in-malware-attacks/)

The FBI issued a flash alert warning that Iranian MOIS-linked Handala (also tracked as Handala Hack Team, Hatef, Hamsa) and the IRGC-tied Homeland Justice group are using Telegram as C2 infrastructure. Targets include journalists critical of the Iranian government, dissidents, and opposition groups worldwide. The FBI seized four domains used by these groups: `handala-redwanted[.]to`, `handala-hack[.]to`, `justicehomeland[.]org`, and `karmabelow80[.]org`. This follows Handala's attack on U.S. medical device firm Stryker, in which they factory-reset approximately 80,000 devices via the Microsoft Intune wipe command after compromising a domain administrator account.

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols), T1566 (Phishing)

> **SOC Action:** Block the four seized domains at DNS and proxy. Monitor outbound Telegram API traffic from corporate endpoints for anomalous patterns. Review Intune Global Administrator accounts for unauthorized additions. Organisations in media or advocacy sectors should heighten vigilance for social-engineering lures.

### 3.5 Citrix NetScaler Critical Vulnerabilities (CVE-2026-3055, CVE-2026-4368)

**Source:** [CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-003/)

Citrix published security advisory CTX696300 addressing two vulnerabilities in NetScaler ADC and Gateway. CVE-2026-3055 (CVSS 9.3) is an out-of-bounds read that can leak sensitive memory contents from systems configured as SAML Identity Providers. CVE-2026-4368 (CVSS 7.7) is a race condition enabling user session mix-up on Gateway and AAA virtual server configurations. Affected versions include NetScaler ADC and Gateway prior to 14.1-66.59, 13.1-62.23, and 13.1-37.262 (FIPS). No active exploitation confirmed at time of publication, but prior Citrix zero-day exploitation (CVE-2025-6543) by state actors increases urgency.

> **SOC Action:** Identify all internet-facing NetScaler appliances configured as SAML IdP or Gateway. Apply patches immediately, prioritising internet-facing assets. After patching, terminate all active sessions: `kill aaa session -all; kill icaconnection -all; kill rdp connection -all; clear lb persistentSessions`. Snapshot appliances before patching for forensic review.

### 3.6 Chromium Security Update — Multiple Critical and High CVEs

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-4463)

Microsoft ingested a batch of Chromium security fixes affecting Edge and Chrome. Critical-severity CVEs include CVE-2026-4463 (heap buffer overflow in WebRTC), CVE-2026-4449 (use-after-free in Blink), and CVE-2026-4444 (stack buffer overflow in WebRTC). High-severity CVEs include CVE-2026-4456 (UAF in Digital Credentials API), CVE-2026-4452 (integer overflow in ANGLE), CVE-2026-4450 (OOB write in V8), CVE-2026-4448 (heap buffer overflow in ANGLE), CVE-2026-4446 and CVE-2026-4445 (UAFs in WebRTC).

> **SOC Action:** Push Chrome/Edge updates to all managed endpoints. Verify browser auto-update is functioning. Prioritise WebRTC-heavy environments (video conferencing, telehealth) for immediate patching.

### 3.7 GhostClaw Expands to GitHub Repos and AI Workflows

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/69c10792a24c3b8eec93ad9c)

The GhostClaw credential-theft campaign has expanded beyond npm packages to target macOS users through malicious GitHub repositories and AI-assisted development workflows. Attackers impersonate legitimate tools, present fake authentication prompts, and establish persistence via scheduled tasks. All identified repositories communicate with C2 domain `trackpipe[.]dev`.

#### Indicators of Compromise
```
C2: trackpipe[.]dev
SHA256: 189b8419863830f2732324a0e02e71721ec550ffa606f9dc719f935db5d25821
SHA256: 3ab0bcc8ff821bd6ba0e5fdbb992836922a67524f8284d69324f61e651981040
SHA256: 946206d42497ea54a4df3f3fed262a99632672e99b02abcc7a9aff0f677efba8
SHA256: 72bc4f82786e23f067d8731dac2b51c033f49ceceab0a64065a160cdff54f488
```

**MITRE ATT&CK:** T1059.004 (Command and Scripting Interpreter: Unix Shell), T1204.002 (User Execution: Malicious File), T1528 (Steal Application Access Token)

> **SOC Action:** Block `trackpipe[.]dev` at DNS and proxy. Search endpoint telemetry for the listed SHA256 hashes. Audit developer workstations for recently cloned GitHub repositories with suspicious README install instructions. Review AI coding assistant configurations for unrestricted script execution.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply-chain compromises affecting critical software tools | Trivy supply-chain attack (Docker, GitHub); GhostClaw expansion to GitHub repos and AI workflows |
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in Citrix products | CVE-2025-6543 used as zero-day since May 2025; Citrix NetScaler backdoors targeting governments |
| 🟠 **HIGH** | Increased ransomware activity with double extortion tactics | Akira (CONCEPTNET, Schmiede, Dixon Electrical); Nightspire (3 victims); CipherForce (Tuna.uy) |
| 🟠 **HIGH** | Phishing as primary vector for data breaches and ransomware | Lakemonster.com breach (43,773 accounts); Amazon claimed breach; Indonesian government data dumps |
| 🟠 **HIGH** | Phishing campaigns targeting cloud service credentials | AWS console credential phishing campaign; Tycoon2FA PaaS platform persistence after takedown |
| 🟠 **HIGH** | Increased Qilin ransomware activity across multiple sectors | J E Culp Transport, Southern Commercial Real Estate, Southwire, nPower Technologies, Elite Limousine Plus |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala** (15 reports) — Iranian MOIS-linked hacktivist group; FBI flash alert and domain seizures this period
- **Nightspire** (7 reports) — Ransomware group with multiple new victims across European manufacturing and finance
- **TeamPCP** (5 reports) — Cloud-focused cybercrime group behind Trivy supply-chain attack and CanisterWorm wiper
- **UNC6353** (5 reports) — Suspected Russian espionage group deploying DarkSword and Coruna iOS exploit kits
- **Void Manticore** (5 reports) — Iran-nexus destructive threat actor
- **Qilin** (4 reports) — Ransomware operator with sustained multi-sector campaign
- **Akira** (4 reports) — Ransomware group claiming four new victims in education, manufacturing, and electrical contracting
- **APT28** (4 reports) — Russian GRU-linked espionage group

### Malware Families

- **TeamPCP Cloud stealer** (3 reports) — Credential-harvesting malware injected into Trivy supply chain
- **Akira ransomware** (3 reports) — Double-extortion ransomware with active victim claims
- **CanisterWorm** (1 report) — Wiper malware targeting Iranian systems via cloud infrastructure
- **GhostClaw / GhostLoader** (1 report) — macOS infostealer distributed via GitHub and AI workflows
- **DarkSword** (3 reports) — iOS exploit kit used in espionage and crypto-theft campaigns
- **NodeSnake** (3 reports) — Backdoor malware observed in prior reporting periods
- **Slopoly** (4 reports) — Persistent malware family tracked across the pipeline

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 25 | [link](https://msrc.microsoft.com) | Chromium CVE advisories (bulk of volume) |
| RansomLock | 16 | [link](https://www.ransomlook.io) | Ransomware victim monitoring — Akira, Nightspire, ShinyHunters, Qilin |
| Unknown | 12 | — | Telegram-sourced intelligence and unattributed data breach claims |
| BleepingComputer | 7 | [link](https://www.bleepingcomputer.com) | Trivy supply-chain, Handala FBI alert, DarkSword CISA KEV |
| RecordedFutures | 5 | [link](https://therecord.media) | Sentencing, North Korean IT worker schemes |
| Elastic Security Labs | 4 | [link](https://www.elastic.co/security-labs) | Threat research and detection content |
| Wiz | 3 | [link](https://www.wiz.io/blog) | Cloud security analysis |
| Wired Security | 3 | [link](https://www.wired.com/category/security) | Conflict zone reporting |
| Crowdstrike | 2 | [link](https://www.crowdstrike.com/blog) | Threat intelligence |
| Cisco Talos | 2 | [link](https://blog.talosintelligence.com) | 2025 Year in Review |
| Sysdig | 2 | [link](https://sysdig.com/blog) | AI coding agent runtime security |
| CertEU | 1 | [link](https://cert.europa.eu) | Citrix NetScaler advisory SA-2026-003 |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | CanisterWorm wiper deep-dive |
| AppOmni | 1 | [link](https://appomni.com) | Trivy compromise SaaS impact analysis |
| AlienVault | 1 | [link](https://otx.alienvault.com) | GhostClaw IOC pulse |
| SANS | 1 | [link](https://isc.sans.edu) | Security diary |
| Schneier | 1 | [link](https://www.schneier.com) | Security commentary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all Trivy Docker images, GitHub Actions references, and CI/CD pipelines for compromise. Pin dependencies to verified commit SHAs. Rotate any credentials that transited Trivy-integrated runners between 20–23 March. (Ref: §3.1, §3.2)

- 🔴 **IMMEDIATE:** Update all managed iOS devices to iOS 18.8 or later to mitigate the DarkSword exploit chain (CVE-2025-31277, CVE-2025-43510, CVE-2025-43520). Federal agencies: BOD 22-01 deadline is 3 April 2026. (Ref: §3.3)

- 🟠 **SHORT-TERM:** Patch internet-facing Citrix NetScaler ADC and Gateway appliances to address CVE-2026-3055 (CVSS 9.3) and CVE-2026-4368. Terminate all active sessions post-patch and snapshot appliances for forensic analysis. (Ref: §3.5)

- 🟠 **SHORT-TERM:** Block Handala-associated domains (`handala-redwanted[.]to`, `handala-hack[.]to`, `justicehomeland[.]org`, `karmabelow80[.]org`) and `trackpipe[.]dev` at DNS/proxy. Monitor outbound Telegram API traffic for anomalous C2 patterns. (Ref: §3.4, §3.7)

- 🟡 **AWARENESS:** Push Chrome/Edge updates to address 9+ Chromium CVEs including critical heap buffer overflows in WebRTC. Prioritise environments with heavy WebRTC usage. (Ref: §3.6)

- 🟢 **STRATEGIC:** Review CI/CD pipeline security posture — ensure GitHub Actions pin to commit SHAs rather than mutable tags, enforce MFA on all service accounts, and audit PAT usage across automation accounts. The Trivy incident demonstrates that incomplete credential rotation after a breach enables persistent re-compromise. (Ref: §3.1)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 88 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
