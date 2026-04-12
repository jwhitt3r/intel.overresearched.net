---
layout: post
title: "CTI Daily Brief: 2026-04-11 - Marimo RCE Under Active Exploitation; Krybit and Lamashtu Ransomware Surge"
date: 2026-04-12 20:05:00 +0000
description: "36 reports processed across 5 sources. Two critical vulnerabilities disclosed — CVE-2026-39987 (Marimo pre-auth RCE) confirmed actively exploited within hours of disclosure, and CVE-2026-34757 (LIBPNG use-after-free). Ransomware operations dominated the landscape with Krybit, Lamashtu, Inc Ransom, Blackwater, and The Gentlemen collectively claiming 25 victims across healthcare, education, and industrial sectors."
category: daily
tags: [cti, daily-brief, cve-2026-39987, lamashtu, krybit, inc-ransom]
classification: TLP:CLEAR
reporting_period: "2026-04-11"
generated: "2026-04-12"
severity: critical
draft: true
report_count: 36
sources:
  - BleepingComputer
  - Microsoft
  - RansomLock
  - HaveIBeenPwned
  - Unknown
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-11 (24h) | TLP:CLEAR | 2026-04-12 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 36 reports from 5 sources during the reporting period. The dominant theme is a sustained ransomware surge: six distinct groups — Krybit, Lamashtu, Inc Ransom, Blackwater, The Gentlemen, and shadowbyt3$ — collectively claimed victims across healthcare, education, manufacturing, hospitality, and government sectors. Two critical vulnerabilities were disclosed: CVE-2026-39987, a pre-authentication RCE flaw in the Marimo Python notebook platform, was confirmed actively exploited within 10 hours of disclosure with attackers harvesting credentials from exposed instances; and CVE-2026-34757, a use-after-free in LIBPNG affecting png_set_PLTE, png_set_tRNS, and png_set_hIST functions. Microsoft published five additional high-severity CVEs affecting osslsigncode and Helm Chart tooling. A 1.7-million-account breach at Hallmark via Salesforce was added to HaveIBeenPwned.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | CVE-2026-39987 Marimo RCE (active exploitation); CVE-2026-34757 LIBPNG use-after-free |
| 🟠 **HIGH** | 31 | Krybit (8 victims); Lamashtu (8 victims); osslsigncode CVEs; Blackwater healthcare targeting; Inc Ransom government targeting |
| 🟡 **MEDIUM** | 3 | Hallmark 1.7M account breach; CMS NULL dereference CVEs (CVE-2026-28389, CVE-2026-28390) |

## 3. Priority Intelligence Items

### 3.1 CVE-2026-39987 — Marimo Pre-Auth RCE Under Active Exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-marimo-pre-auth-rce-flaw-now-under-active-exploitation/)

A critical RCE vulnerability (CVSS 9.3) in the Marimo open-source reactive Python notebook platform (versions ≤ 0.20.4) is under active exploitation. The flaw exists in the `/terminal/ws` WebSocket endpoint, which exposes an interactive terminal without authentication checks. Attackers exploited the vulnerability within 10 hours of public disclosure, targeting credential theft.

Sysdig researchers observed 125 IP addresses performing reconnaissance within 12 hours of disclosure. The first confirmed exploitation involved a methodical operator who validated the flaw, performed manual reconnaissance (`pwd`, `whoami`, `ls`), then harvested `.env` files containing cloud credentials and application secrets within three minutes. The attacker also probed for SSH keys. No persistence mechanisms or cryptominers were deployed, suggesting a focused credential-harvesting operation.

Marimo released version 0.23.0 on 2026-04-11 to address the flaw. Users who deploy Marimo in edit mode with `--host 0.0.0.0` are at highest risk.

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1071.001 (Application Layer Protocol: Web Protocols)

> **SOC Action:** Query asset inventories for Marimo instances. Block or disable access to the `/terminal/ws` WebSocket endpoint at the WAF or reverse proxy layer. Rotate all credentials stored in `.env` files on any Marimo host. Upgrade to Marimo 0.23.0 immediately.

### 3.2 CVE-2026-34757 — LIBPNG Use-After-Free Leading to Heap Information Disclosure

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34757)

A critical use-after-free vulnerability in LIBPNG affects the `png_set_PLTE`, `png_set_tRNS`, and `png_set_hIST` functions. Exploitation corrupts PNG chunk data and can lead to heap information disclosure. Given LIBPNG's ubiquity as a dependency across operating systems, browsers, and image-processing libraries, the blast radius is significant.

**MITRE ATT&CK:** T1055 (Process Injection), T1068 (Exploitation for Privilege Escalation)

> **SOC Action:** Identify all systems and applications linking against LIBPNG. Prioritise patching image-processing services and any internet-facing application that handles user-uploaded PNG files. Monitor for unusual memory access patterns in image-rendering processes.

### 3.3 osslsigncode Vulnerability Cluster (CVE-2026-39853, CVE-2026-39855, CVE-2026-39856)

**Source:** [Microsoft MSRC — CVE-2026-39853](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-39853), [CVE-2026-39855](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-39855), [CVE-2026-39856](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-39856)

Three high-severity vulnerabilities in osslsigncode, a tool used for PE binary signing, were disclosed by Microsoft. CVE-2026-39853 is a stack buffer overflow via unbounded digest copy during signature verification that can lead to arbitrary code execution. CVE-2026-39855 is an integer underflow in PE page hash calculation causing out-of-bounds reads. CVE-2026-39856 is an out-of-bounds read via unvalidated section bounds in PE page hash calculation. Together, these flaws enable attackers to craft malicious PE files that trigger code execution or information disclosure when processed by osslsigncode.

> **SOC Action:** Audit CI/CD pipelines and build systems for osslsigncode usage. Update to the latest patched version. Restrict osslsigncode execution to trusted PE files only and sandbox any signing operations that process external inputs.

### 3.4 Ransomware Surge — Krybit, Lamashtu, and Blackwater Target Healthcare and Education

**Source:** [RansomLook — Krybit](https://www.ransomlook.io//group/krybit), [RansomLook — Lamashtu](https://www.ransomlook.io//group/lamashtu), [RansomLook — Blackwater](https://www.ransomlook.io//group/blackwater)

The reporting period saw an intense cluster of ransomware activity across multiple groups:

- **Krybit** claimed 8 victims spanning education (CCCKeito.edu.hk, lkc.ac.bw), ISPs (megasurf.co.za), construction (conrepsa.ro), manufacturing (Gerald Zisser GmbH), and consumer goods (whiskey.co.jp). The group uses Tox protocol for victim communications and maintains multiple .onion domains with 100% uptime over the past 30 days.
- **Lamashtu** also claimed 8 victims across textiles (Gauthier Tissus), engineering (Beaver Engineering), hospitality (The Seacare Hotel), IT services (ClientSolution, EFO Service Srl, Logitech Srl Safety), and aviation/energy (CNAOC, FILAIR). The group uses PGP-encrypted communications via onionmail.org.
- **Blackwater** targeted Medical Park Hastaneler Grubu, Turkey's leading healthcare group operating 36 hospitals across 14 provinces with 14,000 employees.
- **Inc Ransom** targeted Morgan County, Georgia government (morgancountyga.gov) and an Australian technology firm (mastercom.com.au), using T1485 (Data Encrypted for Impact) and Tor-based infrastructure.

> **SOC Action:** Healthcare and education sector organisations should verify offline backup integrity and test restoration procedures. Monitor for Tox protocol traffic and connections to known .onion domains associated with these groups. Review EDR telemetry for T1486 (Data Encrypted for Impact) and T1566 (Phishing) indicators.

### 3.5 Hallmark Data Breach — 1.7 Million Accounts Exposed via Salesforce

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/Hallmark)

In March 2026, attackers compromised Hallmark's Salesforce instance and exfiltrated personal data from approximately 1.7 million accounts spanning both Hallmark and the Hallmark+ streaming service. Exposed data includes email addresses, names, phone numbers, physical addresses, and support tickets. The data was published after an extortion deadline passed.

> **SOC Action:** If your organisation uses Salesforce, review access controls, API token hygiene, and connected app permissions. Organisations with customer overlap with Hallmark should monitor for credential-stuffing attempts using the exposed email corpus.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Vulnerabilities in software development tools and libraries (OpenTelemetry-Go, CUPS) are being actively exploited | CVE-2026-39881 Vim command injection; CVE-2026-29181 OpenTelemetry-Go DoS amplification |
| 🟠 **HIGH** | Global ransomware campaigns targeting multiple sectors with overlapping TTPs and actors | Inc Ransom targeting mastercom.com.au and morgancountyga.gov with shared T1485 TTPs |
| 🟠 **HIGH** | Ransomware groups (The Gentlemen, Nightspire) actively targeting healthcare, biotechnology, and utilities globally | Harlem Stage, BRC Biotechnology, Sahara Air Products campaigns |
| 🟠 **HIGH** | ShinyHunters ransomware attacks targeting diverse sectors using phishing and application layer protocol exploitation | McGraw Hill, Rockstar Games, Abrigo campaigns |
| 🟡 **MEDIUM** | Phishing remains prevalent as an initial access vector across multiple threat actor campaigns | Observed across The Gentlemen, Nightspire, ShinyHunters, and shadowbyt3$ operations |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (66 reports) — Prolific ransomware operator; consistent high-volume activity across the past three weeks
- **The Gentlemen** (63 reports) — Active ransomware group targeting healthcare, biotechnology, performing arts, and manufacturing sectors
- **Nightspire** (37 reports) — Ransomware operator focused on utilities, industrial, and biotechnology sectors
- **TeamPCP** (31 reports) — Persistent threat actor with sustained activity through early April
- **DragonForce** (27 reports) — Ransomware-as-a-Service operator with broad sector targeting
- **Akira** (22 reports) — Established ransomware group maintaining steady operational tempo
- **shadowbyt3$** (16 reports) — Data breach and extortion actor targeting education and financial sectors

### Malware Families

- **RansomLock** (20 reports) — Ransomware variant associated with Lamashtu and Krybit operations; most active family in today's reporting period
- **DragonForce Ransomware** (25 reports) — RaaS payload linked to the DragonForce threat actor
- **Akira Ransomware** (18 reports) — Persistent ransomware family with consistent deployment
- **PLAY Ransomware** (15 reports) — Established ransomware family maintaining operational presence

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 25 | [link](https://www.ransomlook.io) | Ransomware victim tracking; Krybit, Lamashtu, Inc Ransom, Blackwater, The Gentlemen, shadowbyt3$ |
| Microsoft | 8 | [link](https://msrc.microsoft.com/update-guide) | CVE disclosures for LIBPNG, osslsigncode, Helm Chart, CMS NULL derefs |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/critical-marimo-pre-auth-rce-flaw-now-under-active-exploitation/) | Marimo RCE active exploitation coverage |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Hallmark) | Hallmark 1.7M account breach notification |
| Telegram (channel name redacted) | 1 | — | Slipnet malware distribution via phishing |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Upgrade all Marimo instances to version 0.23.0 and rotate any credentials stored in `.env` files on affected hosts. Block access to the `/terminal/ws` WebSocket endpoint at the network perimeter. CVE-2026-39987 is confirmed actively exploited.

- 🔴 **IMMEDIATE:** Inventory all systems linking against LIBPNG and prioritise patching internet-facing services that process user-uploaded PNG files. CVE-2026-34757 is a critical use-after-free with heap disclosure potential.

- 🟠 **SHORT-TERM:** Audit CI/CD pipelines for osslsigncode usage and update to patched versions. Three high-severity vulnerabilities (CVE-2026-39853, CVE-2026-39855, CVE-2026-39856) enable code execution via crafted PE files during signing operations.

- 🟠 **SHORT-TERM:** Healthcare and education organisations should validate offline backup integrity and test restoration procedures given the elevated ransomware targeting by Krybit, Lamashtu, Blackwater, and Inc Ransom across these sectors.

- 🟡 **AWARENESS:** Organisations with customer data overlap with Hallmark should monitor authentication logs for credential-stuffing patterns using the 1.7 million exposed email addresses. Review Salesforce connected app permissions and API token hygiene.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 36 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
