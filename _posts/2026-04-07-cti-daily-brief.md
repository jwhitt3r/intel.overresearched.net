---
layout: post
title: "CTI Daily Brief: 2026-04-07 — Iran OT Sabotage Campaign, CISA KEV Ivanti EPMM, Coinbase Cartel RaaS Blitz"
date: 2026-04-08 20:10:00 +0000
description: "70 reports processed across 15 sources. Iranian APT groups actively sabotaging US energy and water OT infrastructure. CISA added CVE-2026-1340 (Ivanti EPMM) to the KEV catalogue with an April 11 patching deadline. Coinbase Cartel and Lapsus$ ransomware campaigns claimed multiple high-profile victims. North Korea's Contagious Interview expanded supply chain attacks across five package ecosystems. TeamPCP supply chain campaign compromised Cisco's development environment."
category: daily
tags: [cti, daily-brief, coinbase-cartel, cve-2026-1340, teampcp, contagious-interview, lucidrook]
classification: TLP:CLEAR
reporting_period: "2026-04-07"
generated: "2026-04-08"
severity: critical
draft: true
report_count: 70
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - SANS
  - Wired Security
  - CertEU
  - CISA
  - Schneier
  - RedCanary
  - Sysdig
  - Unit42
  - Cisco Talos
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-07 (24h) | TLP:CLEAR | 2026-04-08 |

## 1. Executive Summary

The pipeline processed **70 reports** from **15 sources** over the past 24 hours, with 14 rated critical and 25 rated high. The dominant theme is active exploitation of critical infrastructure: a joint FBI/NSA/DOE advisory confirmed Iranian-affiliated APT groups are sabotaging US energy and water operational technology through PLC manipulation, causing operational disruptions and financial losses. CISA added CVE-2026-1340 (Ivanti EPMM code injection) to the KEV catalogue with a mandatory federal patching deadline of April 11 after confirmed zero-day exploitation since January. Ransomware-as-a-Service activity surged with the Coinbase Cartel claiming at least seven new victims including JBS Brazil, while Lapsus$ breached AstraZeneca and the French Ministry of Agriculture. Supply chain attacks remain a critical vector, with North Korea's Contagious Interview campaign spreading across five package ecosystems and TeamPCP (now tracked by Google GTIG as UNC6780) compromising Cisco's development environment via the Trivy supply chain exploit.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 14 | Ivanti EPMM KEV, Iran OT sabotage, Coinbase Cartel RaaS, DPRK supply chain, Ninja Forms RCE, AWS AgentCore sandbox escape, Flannel RCE |
| 🟠 **HIGH** | 25 | TeamPCP/Cisco breach, ActiveMQ RCE, ClickFix AtomicStealer, LucidRook Taiwan campaign, Python litellm supply chain, multiple ransomware victims |
| 🟡 **MEDIUM** | 24 | CVE batch (NATS, Gdk-pixbuf, python-ecdsa), Eurail data breach, LAPD file exposure, Lumma Stealer 64-bit variant |
| 🟢 **LOW** | 6 | Miscellaneous ransomware disclosures |
| 🔵 **INFO** | 1 | General threat landscape awareness |

## 3. Priority Intelligence Items

### 3.1 Iran-Linked APT Groups Sabotaging US Energy and Water Infrastructure

**Source:** [Recorded Future News](https://therecord.media/fbi-pentagon-warn-iran-hacking-groups-target-ot), [Wired Security](https://www.wired.com/story/iran-linked-hackers-are-sabotaging-us-energy-and-water-infrastructure/)

A joint advisory from the FBI, NSA, DOE, and CISA confirmed that Iranian-affiliated APT groups — with activity consistent with CyberAv3ngers / Shahid Kaveh Group — are actively targeting internet-facing operational technology devices across US critical infrastructure. Attackers compromised Rockwell Automation and Allen-Bradley PLCs, manipulated HMI/SCADA displays, and caused operational disruptions and financial losses in energy, water/wastewater, and government facility sectors. The advisory links this escalation to the current US–Iran military conflict and notes that since March 2026, at least one Iranian APT group disrupted PLC function at victim organisations. The campaign mirrors the 2023 CyberAv3ngers attacks on Unitronics devices, but with deeper ICS process understanding. CVE-2021-22681 (Rockwell OT products) is specifically highlighted as an exploited vulnerability.

> **SOC Action:** Audit all internet-facing OT/ICS devices for direct exposure, particularly Rockwell Automation PLCs. Query network logs for anomalous connections to PLC management ports. Verify CVE-2021-22681 patches are applied. Review HMI/SCADA display integrity and segment OT networks from IT environments immediately.

### 3.2 CISA KEV: Ivanti EPMM CVE-2026-1340 — Mandatory Patch by April 11

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/04/08/cisa-adds-one-known-exploited-vulnerability-catalog), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-exploited-ivanti-epmm-flaw-by-sunday/)

CISA added CVE-2026-1340 to the Known Exploited Vulnerabilities catalogue on April 8. This critical code injection vulnerability in Ivanti Endpoint Manager Mobile (EPMM) enables unauthenticated remote code execution on internet-exposed appliances. Ivanti disclosed the flaw on January 29, confirming zero-day exploitation at that time. Shadowserver currently tracks approximately 950 exposed EPMM IP addresses — 569 in Europe and 206 in North America. FCEB agencies must patch by April 11 under BOD 22-01. A second related vulnerability, CVE-2026-1281, was also patched in the January update.

> **SOC Action:** Identify all Ivanti EPMM instances via asset inventory. Apply the January 29 security update immediately. If patching is not possible, remove EPMM appliances from internet exposure or discontinue use. Query web server logs for exploitation indicators against EPMM management interfaces.

### 3.3 Coinbase Cartel and Lapsus$ Ransomware Campaigns

**Source:** [RansomLock](https://www.ransomlook.io//group/coinbase%20cartel) (multiple reports)

The Coinbase Cartel RaaS group posted at least seven new victims in a 24-hour period: JBS Brazil, KEB, EasTech, Idera, Balfour Beatty, Scholle IPN, Marlborough Partners, and Correios. The group uses phishing for initial access (T1566), onion services for C2, and encrypted Tox channels for ransom negotiations. In parallel, Lapsus$ claimed breaches of AstraZeneca, the French Ministry of Agriculture, VirtaHealth, and Axcera.io, using SIM swapping, MFA fatigue attacks, and insider access brokers for initial compromise. Other ransomware activity included Worldleaks (Deaconess Health System), Qilin (bnc.com.ve), Payload (El Wastani Petroleum / WASCO), Inc Ransom (rxm.com.au, pacificwestinjury.com), and RansomHouse (Accelerated Services).

> **SOC Action:** Review phishing detection rules and MFA configurations — especially for MFA fatigue resistance. Monitor dark web feeds for organisation mentions. Ensure offline backup integrity and test ransomware recovery playbooks. Alert executive protection teams to social engineering risks from SIM-swap and insider-access campaigns.

### 3.4 North Korea's Contagious Interview: Cross-Ecosystem Supply Chain Attack

**Source:** [Socket.dev via AlienVault](https://socket.dev/blog/contagious-interview-campaign-spreads-across-5-ecosystems)

North Korea's Contagious Interview campaign expanded into a coordinated cross-ecosystem supply chain operation spanning npm, PyPI, Go Modules, crates.io, and Packagist. Threat actors operating under GitHub aliases (including "golangorg") published malicious packages impersonating developer tooling (e.g., `dev-log-core`, `logutilkit`, `fluxhttp`). Loaders retrieve payloads from attacker-controlled infrastructure including Vercel domains and Google Drive, delivering staged RAT payloads for credential theft, browser data exfiltration, and cryptocurrency wallet compromise. The Windows-heavy variant `license-utils-kit` includes a full post-compromise implant with remote shell, keylogging, and encrypted archiving capabilities. MITRE ATT&CK techniques observed: T1195.001, T1059.006, T1059.007, T1071.001, T1555.003, T1036.005.

#### Indicators of Compromise
```
C2: apachelicense[.]vercel[.]app
C2: ngrok-free[.]vercel[.]app
C2: logkit[.]onrender[.]com
C2: logkit-tau[.]vercel[.]app
IP: 66[.]45[.]225[.]94
SHA256: 9a541dffb7fc18dc71dbc8523ec6c3a71c224ffeb518ae3a8d7d16377aebee58
SHA256: bb2a89001410fa5a11dea6477d4f5573130261badc67fe952cfad1174c2f0edd
SHA256: 7c5adef4b5aee7a4aa6e795a86f8b7d601618c3bc003f1326ca57d03ec7d6524
```

> **SOC Action:** Audit developer workstations for the named malicious packages across all five ecosystems. Query DNS logs for the listed C2 domains. Block the identified infrastructure at the proxy/firewall. Review SCA/SBOM tooling coverage for Go Modules, crates.io, and Packagist — not just npm and PyPI.

### 3.5 TeamPCP Supply Chain Campaign: Cisco Development Environment Compromised

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/32880)

The seventh update to the TeamPCP (now designated UNC6780 by Google GTIG) supply chain campaign confirmed that threat actors leveraged stolen Trivy credentials (CVE-2026-33634) to breach Cisco's internal development environment. Over 300 private GitHub repositories containing Cisco source code were exfiltrated, including AI products and customer repositories belonging to banks, BPO firms, and US government agencies. AWS keys were stolen and used for unauthorised cloud activities. ShinyHunters expanded claims to allege access to 3M+ Salesforce records (unverified). The CISA KEV deadline for the underlying Trivy vulnerability arrived without a standalone advisory. MITRE ATT&CK: T1210, T1578.

> **SOC Action:** Organisations using Cisco AI products or with code hosted in Cisco's development infrastructure should contact Cisco to determine exposure. Review CI/CD pipeline dependencies for Trivy-linked components. Rotate any AWS credentials that may have transited through Trivy-integrated build systems.

### 3.6 Additional Critical and High-Severity Items

**Ninja Forms WordPress RCE (CVE-2026-0740)** — [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-flaw-in-ninja-forms-wordpress-plugin/): Critical (CVSS 9.8) unauthenticated RCE via arbitrary file upload in the Ninja Forms File Uploads plugin (versions ≤3.3.26). Wordfence blocked 3,600+ attacks in 24 hours. Patch to version 3.3.27.

**AWS AgentCore Sandbox Escape** — [Unit42](https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/): Researchers bypassed AWS Bedrock AgentCore's sandbox network isolation via DNS tunneling and exploited an MMDS session token enforcement flaw enabling SSRF credential extraction. AWS has remediated the issues. Organisations using AgentCore should verify platform-level controls are applied.

**Apache ActiveMQ RCE (CVE-2026-34197)** — [BleepingComputer](https://www.bleepingcomputer.com/news/security/13-year-old-bug-in-activemq-lets-hackers-remotely-execute-commands/): 13-year-old high-severity (CVSS 8.8) RCE in ActiveMQ Classic via Jolokia API abuse. Versions before 5.19.4 and 6.0.0–6.2.3 affected. Unauthenticated on 6.0.0–6.1.1 due to CVE-2024-32114. Update immediately.

**ClickFix macOS AtomicStealer** — [Jamf via AlienVault](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/): New ClickFix variant uses `applescript://` URL scheme to invoke Script Editor instead of Terminal, bypassing macOS 26.4 paste-scanning protections. Delivers AtomicStealer infostealer via `dryvecar[.]com`. MITRE ATT&CK: T1059, T1566.

**LucidRook Targeting Taiwan** — [Cisco Talos](https://blog.talosintelligence.com/new-lua-based-malware-lucidrook/), [AlienVault](https://otx.alienvault.com/pulse/69d65cbe07a5f680cde16920): New Lua-based malware family targeting Taiwanese NGOs and universities via spear-phishing with compromised authorised mail infrastructure. Related families include LucidKnight and LucidPawn. C2: 59[.]124[.]71[.]242, 1[.]34[.]253[.]131, powerscrews[.]com.

**Python litellm Supply Chain Compromise** — [Schneier](https://www.truesec.com/hub/blog/malicious-pypi-package-litellm-supply-chain-compromise): PyPI package `litellm` version 1.82.8 contained a malicious `.pth` file (`litellm_init.pth`) that executes automatically on Python startup without explicit import. MITRE ATT&CK: T1575.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | RaaS groups (Coinbase Cartel) actively targeting multiple sectors globally via phishing and public-facing application exploitation | JBS Brazil, KEB, EasTech, Idera, Correios, Balfour Beatty breaches |
| 🔴 **CRITICAL** | State-affiliated actors targeting critical infrastructure OT systems | FBI/Pentagon Iran OT advisory; Wired Security Iran ICS reporting |
| 🟠 **HIGH** | Supply chain compromises increasingly used to deliver malware (TeamPCP, DPRK) | TeamPCP/Cisco breach via Trivy; Contagious Interview cross-ecosystem campaign; Axios supply chain attack |
| 🟠 **HIGH** | Phishing remains the dominant initial access vector across campaigns | 16 reports correlated by phishing TTP including ransomware, APT, and commodity malware campaigns |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors (oil/gas, healthcare, legal) | Qilin, RansomHouse, Payload, Inc Ransom, Worldleaks victim disclosures |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (44 reports) — Prolific RaaS operator with sustained global targeting
- **The Gentlemen** (53 reports combined) — Active ransomware group targeting multiple sectors
- **NightSpire** (35 reports) — Evolving RaaS with inconsistent TTPs suggesting multiple affiliates
- **TeamPCP / UNC6780** (31 reports) — Supply chain campaign actor; Cisco breach confirmed
- **DragonForce** (27 reports) — Ransomware group with sustained operational tempo
- **Akira** (22 reports) — Established ransomware operator maintaining high activity
- **Handala** (13 reports) — Pro-Palestinian hacktivist group
- **ShinyHunters** (13 reports) — Data extortion group with claims against Cisco/Salesforce data

### Malware Families
- **DragonForce Ransomware** (25 reports) — Dedicated ransomware tooling
- **Akira Ransomware** (18 reports) — Persistent ransomware family
- **RaaS (generic)** (18 reports combined) — Multiple RaaS platforms active
- **PLAY Ransomware** (15 reports combined) — Active ransomware-as-a-service
- **CanisterWorm** (7 reports) — Worm-type malware observed in recent campaigns
- **AtomicStealer** (new) — macOS infostealer delivered via ClickFix technique
- **LucidRook** (new) — Lua-based stager targeting Taiwanese organisations

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 19 | [link](https://www.ransomlook.io) | Ransomware group victim disclosures; Coinbase Cartel and Lapsus$ primary source |
| Microsoft | 16 | [link](https://msrc.microsoft.com) | CVE disclosures including Flannel RCE, NATS, Gdk-pixbuf |
| BleepingComputer | 6 | [link](https://www.bleepingcomputer.com) | Ivanti EPMM KEV, Ninja Forms RCE, ActiveMQ RCE |
| Recorded Future News | 6 | [link](https://therecord.media) | Iran OT advisory, Minnesota cyberattack, Egyptian journalist targeting, Eurail breach |
| AlienVault | 5 | [link](https://otx.alienvault.com) | Contagious Interview, ClickFix AtomicStealer, LucidRook, NightSpire, Lumma Stealer |
| SANS | 3 | [link](https://isc.sans.edu) | TeamPCP supply chain campaign Update 007 |
| Wired Security | 2 | [link](https://www.wired.com) | Iran ICS sabotage coverage |
| CERT-EU | 2 | [link](https://cert.europa.eu) | 2025 Threat Landscape Report, CTI Framework |
| CISA | 1 | [link](https://www.cisa.gov) | KEV catalogue addition for CVE-2026-1340 |
| Schneier | 1 | [link](https://www.schneier.com) | Python litellm supply chain compromise |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | AWS AgentCore sandbox escape research |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com) | LucidRook malware analysis |
| Red Canary | 1 | [link](https://redcanary.com) | AI in cybersecurity analysis |
| Sysdig | 1 | — | Container security reporting |
| Telegram (channels redacted) | 4 | — | Hacktivist disclosures and ransomware claims |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Ivanti EPMM against CVE-2026-1340 before the April 11 CISA deadline. Identify all exposed instances via asset inventory and remove any unpatched appliances from internet exposure.

- 🔴 **IMMEDIATE:** Audit all internet-facing OT/ICS devices — particularly Rockwell Automation PLCs — for direct exposure. Apply CVE-2021-22681 patches, segment OT from IT networks, and review HMI/SCADA display integrity in response to the FBI/NSA Iran OT advisory.

- 🟠 **SHORT-TERM:** Scan developer workstations and CI/CD pipelines for malicious packages from the Contagious Interview campaign (npm: `dev-log-core`, `logger-base`, `logkitx`; PyPI: `logutilkit`, `fluxhttp`, `license-utils-kit`). Expand SCA tooling coverage to Go Modules, crates.io, and Packagist. Verify `litellm` PyPI package version is not 1.82.8.

- 🟠 **SHORT-TERM:** Update WordPress Ninja Forms File Uploads to version 3.3.27 and Apache ActiveMQ Classic to 5.19.4 or 6.2.3+ to close actively exploited or high-risk RCE vectors.

- 🟡 **AWARENESS:** macOS fleet administrators should monitor for `applescript://` URL scheme abuse and block the domain `dryvecar[.]com`. The ClickFix AtomicStealer variant bypasses Terminal paste-scanning introduced in macOS 26.4.

- 🟢 **STRATEGIC:** Evaluate supply chain security posture across all package ecosystems. The convergence of TeamPCP, Contagious Interview, and litellm compromises in a single 24-hour period underscores the need for SBOM adoption, SLSA attestation, and SigStore verification in build pipelines.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 70 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
