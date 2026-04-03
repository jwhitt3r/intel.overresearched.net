---
layout: post
title: "CTI Daily Brief: 2026-03-26 — TeamPCP Attributed to EU Commission Breach; Chromium Patches 6 Critical CVEs; DPRK-Linked $280M Crypto Heist"
date: 2026-03-27 09:00:00 +0000
description: "57 reports processed across 10 sources. TeamPCP formally attributed by CERT-EU to the European Commission AWS breach exposing 30+ EU entities. Google Chromium patched 17 vulnerabilities including 6 critical memory-safety flaws. DPRK-linked actors stole $280M from DeFi platform Drift. Qilin deploys novel EDR killer capable of terminating 300+ security drivers."
category: daily
tags: [cti, daily-brief, teampcp, shinyhunters, dragonforce, qilin, vidar, cve-2026-5279]
classification: TLP:CLEAR
reporting_period: "2026-03-26"
generated: "2026-03-27"
draft: true
severity: critical
report_count: 57
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - Wired Security
  - Cisco Talos
  - SANS
  - BellingCat
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-26 (24h) | TLP:CLEAR | 2026-03-27 |

## 1. Executive Summary

The pipeline processed 57 reports from 10 sources during this reporting period. The dominant theme is a convergence of supply-chain exploitation, mass vulnerability disclosure, and sustained ransomware operations. CERT-EU formally attributed the European Commission AWS breach to TeamPCP, confirming that stolen Trivy supply-chain credentials enabled exfiltration of data affecting 30+ EU entities — with ShinyHunters publishing a 90 GB archive on their leak site. Google released a Chromium security update addressing 17 CVEs, six rated critical, including a V8 object corruption flaw (CVE-2026-5279) and multiple use-after-free vulnerabilities in Dawn and ANGLE. Separately, DPRK-linked actors executed a $280 million theft from DeFi platform Drift using pre-signed transaction manipulation and social engineering. Cisco Talos published analysis of a Qilin ransomware EDR-killer component capable of terminating over 300 security drivers, and DragonForce claimed 13 new victims across multiple sectors.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 28 | Chromium V8, Dawn, ANGLE, CSS, GPU CVEs; EU Commission breach; Drift crypto heist; Spring AI RCE; DragonForce ransomware wave |
| 🟠 **HIGH** | 14 | Qilin EDR killer; BEC democratisation; residential proxy evasion; PhantomJack browser hijacker; Chromium WebGL, PDF UAFs |
| 🟡 **MEDIUM** | 14 | Chromium Compositing, Navigation, WebCodecs, ANGLE, WebUSB CVEs; ShinyHunters/Trivy analysis; geopolitical reporting |
| 🔵 **INFO** | 1 | SANS ISC Stormcast daily podcast |

## 3. Priority Intelligence Items

### 3.1 CERT-EU Attributes European Commission Breach to TeamPCP

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cert-eu-european-commission-hack-exposes-data-of-30-eu-entities/)

CERT-EU attributed the European Commission cloud breach to the TeamPCP threat group. The attackers leveraged a compromised AWS API key — stolen during the earlier Trivy supply-chain attack — to gain management-level access to Commission AWS accounts on March 10. TeamPCP used TruffleHog to scan for additional secrets, created a new access key attached to an existing user for persistence, and exfiltrated approximately 90 GB of data including personal information, usernames, email addresses, and 51,992 email-related files across 42 internal Commission clients and at least 29 other EU entities. The data extortion group ShinyHunters subsequently published the stolen dataset on their dark web leak site on March 28. No lateral movement to other Commission AWS accounts has been detected.

**MITRE ATT&CK:** T1078 (Valid Accounts), T1003 (Credential Dumping), T1012 (Data Exfiltration)

> **SOC Action:** Audit all AWS IAM keys for rotation compliance and revoke any keys generated before the Trivy supply-chain compromise window (March 10–24). Search CloudTrail logs for TruffleHog-consistent secret-scanning patterns and unexpected `CreateAccessKey` API calls. Verify that MFA is enforced on all AWS management accounts.

### 3.2 Chromium Security Update — 6 Critical, 11 Additional CVEs

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5279)

Google released a Chromium security update addressing 17 vulnerabilities spanning the V8 engine, Dawn (WebGPU), ANGLE, CSS, GPU, PDF, WebGL, Compositing, Navigation, WebCodecs, WebUSB, and Codecs components. Six vulnerabilities are rated critical:

- **CVE-2026-5279** — Object corruption in V8
- **CVE-2026-5286** — Use after free in Dawn
- **CVE-2026-5281** — Use after free in Dawn
- **CVE-2026-5275** — Heap buffer overflow in ANGLE
- **CVE-2026-5273** — Use after free in CSS
- **CVE-2026-5272** — Heap buffer overflow in GPU

Three additional CVEs are rated high (CVE-2026-5291 WebGL, CVE-2026-5287 PDF, CVE-2026-5285 WebGL). No in-the-wild exploitation has been reported for this batch, but the V8 object corruption flaw (CVE-2026-5279) is historically the class of vulnerability most commonly weaponised in browser exploit chains.

> **SOC Action:** Prioritise Chromium/Edge patching across all endpoints. Validate that browser auto-update policies are active and confirm deployment via EDR telemetry. Monitor for anomalous renderer process crashes that may indicate exploitation attempts against unpatched systems.

### 3.3 Drift Crypto Platform Confirms $280M Stolen — DPRK Attribution

**Source:** [The Record (Recorded Future)](https://therecord.media/drift-crypto-confirms-280-million-stolen-north-korea)

DeFi platform Drift confirmed the theft of $280 million through a sophisticated attack involving the compromise of administrative approval processes. Attackers set up the operation on March 23 and executed two pre-signed transactions on April 1, exploiting a combination of delayed-execution transaction approvals and social engineering of the security council. Blockchain security firm Elliptic attributed the attack to DPRK-linked actors, noting consistency with laundering methodologies observed in previous North Korean operations including the Bybit hack. If confirmed, this represents the eighteenth DPRK-attributed crypto theft tracked in 2026, with over $300 million stolen year-to-date.

**MITRE ATT&CK:** T1566 (Phishing / Social Engineering)

> **SOC Action:** Organisations with DeFi or blockchain treasury exposure should review multi-signature wallet approval workflows for pre-signed transaction abuse. Implement time-locked transaction review periods and out-of-band verification for any administrative approval changes. Cross-reference wallet addresses against OFAC SDN list updates.

### 3.4 Claude Code Source Leak Weaponised to Distribute Vidar Infostealer

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/claude-code-leak-used-to-push-infostealer-malware-on-github/)

Threat actors exploited the accidental exposure of Anthropic's Claude Code source code to distribute Vidar infostealer malware via malicious GitHub repositories. A repository by user "idbzoomh" advertised "unlocked enterprise features" and was SEO-optimised to appear among top Google results for queries related to the leak. The 7-Zip archive contains a Rust-based executable (ClaudeCode_x64.exe) that deploys Vidar alongside the GhostSocks network traffic proxying tool. The archive is updated frequently, suggesting ongoing delivery iterations by the same operator. A second repository with identical code was also identified.

**MITRE ATT&CK:** T1566 (Phishing), T1204 (User Execution)

> **SOC Action:** Block known malicious repository indicators at the web proxy. Query EDR for any execution of `ClaudeCode_x64.exe` or Rust-compiled binaries from user temp/download directories. Alert on GhostSocks SOCKS5 proxy beaconing patterns. Notify development teams that the legitimate Claude Code tool is distributed only via npm — any standalone executable is malicious.

### 3.5 Qilin Ransomware Deploys EDR-Killer Targeting 300+ Security Drivers

**Source:** [Cisco Talos via AlienVault OTX](https://otx.alienvault.com/pulse/69ce8a077d7ad13478a8e495)

Cisco Talos published analysis of a multi-stage EDR-killer infection chain used by the Qilin ransomware group. The attack deploys a malicious `msimg32.dll` that terminates over 300 EDR drivers from virtually every major security vendor. The DLL side-loading technique allows the malware to neutralise endpoint defences before ransomware deployment, significantly reducing the probability of detection during the encryption phase.

#### Indicators of Compromise
```
SHA256: 12fcde06ddadf1b48a61b12596e6286316fd33e850687fe4153dfd9383f0a4a0
SHA256: 16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0
SHA256: 7787da25451f5538766240f4a8a2846d0a589c59391e15f188aa077e8b888497
SHA256: bd1f381e5a3db22e88776b7873d4d2835e9a1ec620571d2b1da0c58f81c84a56
```

> **SOC Action:** Add the listed SHA256 hashes to EDR blocklists immediately. Monitor for DLL side-loading of `msimg32.dll` from non-standard directories. Deploy kernel-level driver integrity monitoring where available. Alert on mass termination of security service processes.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of software vulnerabilities in widely used technologies, particularly Chromium, posing global user risk | CVE-2026-5279 (V8), CVE-2026-5286 (Dawn), CVE-2026-5281 (Dawn), CVE-2026-5275 (ANGLE) |
| 🔴 **CRITICAL** | Supply chain attacks leveraging popular software packages remain a dominant threat vector | TeamPCP/Trivy → EU Commission breach; axios npm compromise; Claude Code leak exploitation |
| 🟠 **HIGH** | Increased targeting of government and critical infrastructure sectors via phishing and ransomware | EU Commission breach; Faulkner County Sheriff (Qilin); DragonForce multi-sector campaign |
| 🟠 **HIGH** | Ransomware operations expanding with AI-enabled phishing and EDR evasion capabilities | Qilin EDR killer; BEC democratisation via AI; DragonForce RaaS cartel model |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (39 reports) — Most prolific ransomware operator this period; new EDR-killer tooling analysed by Cisco Talos
- **TeamPCP** (26 reports) — Formally attributed to EU Commission breach; linked to Trivy and axios supply-chain attacks
- **Nightspire** (22 reports) — Sustained ransomware operations targeting healthcare and energy sectors
- **DragonForce** (19 reports) — RaaS cartel model with 13 new victim claims this period across retail, government, logistics, and manufacturing
- **Akira** (17 reports) — Continued ransomware activity across multiple sectors
- **ShinyHunters** (10 reports) — Published EU Commission exfiltrated data; linked to Cisco source code breach
- **Coinbase Cartel** (9 reports) — RaaS operation with active data-leak campaigns

### Malware Families

- **DragonForce Ransomware** (18 reports) — Primary payload for DragonForce RaaS operations
- **Akira Ransomware** (13 reports) — Sustained deployment across diverse verticals
- **CanisterWorm** (7 reports) — Active in supply-chain adjacent operations
- **Qilin Ransomware** (5 reports) — Now paired with custom EDR-killer tooling
- **Vidar** (5 reports) — Deployed via Claude Code leak social engineering campaign

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 26 | [link](https://www.ransomlook.io) | DragonForce, Qilin, Akira, Interlock, Crypto24 victim claims |
| Microsoft | 17 | [link](https://msrc.microsoft.com) | Chromium CVE advisories (6 critical, 3 high, 8 medium) |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com) | EU Commission breach, Claude Code malware, residential proxy research |
| RecordedFutures | 2 | [link](https://therecord.media) | Drift crypto $280M heist; French social media legislation |
| AlienVault | 2 | [link](https://otx.alienvault.com) | Qilin EDR killer; PhantomJack browser hijacker via Microsoft Store |
| Wired Security | 2 | [link](https://www.wired.com) | Iran geopolitical and nuclear-site risk analysis |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com) | AI-enabled BEC democratisation analysis |
| SANS | 1 | [link](https://isc.sans.edu) | ISC Stormcast daily podcast |
| BellingCat | 1 | [link](https://www.bellingcat.com) | UAE information control during Iran strikes |
| Unknown (Telegram) | 2 | — | CVE-2026-22738 Spring AI RCE PoC; ShinyHunters/Trivy analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all Chromium-based browsers (Chrome, Edge, Brave, Opera) to address CVE-2026-5279 (V8 object corruption) and five other critical memory-safety vulnerabilities. Validate deployment via EDR or SCCM within 24 hours.

- 🔴 **IMMEDIATE:** Ingest Qilin EDR-killer IOCs (SHA256 hashes in §3.5) into endpoint blocklists. Monitor for `msimg32.dll` side-loading and mass security-service termination events that precede ransomware encryption.

- 🟠 **SHORT-TERM:** Audit AWS IAM key rotation policies and CloudTrail logs in light of the TeamPCP EU Commission breach. Revoke any keys potentially exposed through the Trivy supply-chain compromise and enforce MFA on all cloud management accounts.

- 🟠 **SHORT-TERM:** Alert development teams that Claude Code standalone executables circulating on GitHub are malicious. Block repository-sourced archives containing `ClaudeCode_x64.exe`. Legitimate distribution is via npm only.

- 🟡 **AWARENESS:** GreyNoise research confirms that 78% of residential-proxy-sourced malicious sessions evade IP reputation systems. SOC teams should supplement IP-based detection with behavioural analysis — particularly sequential probing from rotating residential IPs and anomalous SMB traffic from ISP address space.

- 🟡 **AWARENESS:** Cisco Talos warns that AI-enabled BEC attacks now target small organisations with low-value transfers. Reinforce payment-authorisation procedures with out-of-band verification requirements for all fund transfer requests, regardless of apparent sender identity.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 57 reports processed across 13 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
