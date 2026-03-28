---
layout: post
title: "CTI Daily Brief: 2026-03-27 — ShinyHunters Claims 350 GB European Commission Breach; TeamPCP Supply Chain Campaign Enters Monetization Phase"
date: 2026-03-28 21:05:00 +0000
description: "29 reports processed across 7 sources. Dominant themes include a claimed ShinyHunters breach of European Commission infrastructure, continued TeamPCP supply chain operations via a backdoored Telnyx PyPI package, five critical Chromium CVEs, a new macOS Infinity Stealer using ClickFix lures, and sustained ransomware activity from Qilin, Nightspire, Coinbase Cartel, and Payload groups."
category: daily
tags: [cti, daily-brief, shinyhunters, teampcp, infinity-stealer, coinbase-cartel, cve-2026-4442]
classification: TLP:CLEAR
reporting_period: "2026-03-27"
generated: "2026-03-28"
draft: true
severity: critical
report_count: 29
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - SANS
  - BellingCat
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-27 (24h) | TLP:CLEAR | 2026-03-28 |

## 1. Executive Summary

The pipeline processed 29 reports from 7 sources over the past 24 hours, with 7 rated critical, 11 high, 9 medium, and 2 informational. The dominant theme is a convergence of supply chain compromise and ransomware escalation. ShinyHunters claimed a breach of the European Commission (*.europa.eu), alleging exfiltration of over 350 GB of data including mail servers, databases, and confidential documents. TeamPCP's supply chain campaign continued with the backdoored Telnyx PyPI package deploying steganography-based credential stealers, though SANS reports no new package compromises in the past 48 hours as the group shifts toward monetization of previously harvested credentials. Microsoft disclosed five critical Chromium vulnerabilities (CVE-2026-4442, CVE-2026-4674, CVE-2026-4675, CVE-2026-4679, and CVE-2026-4673) affecting Chrome and Edge. A new macOS-targeting Infinity Stealer using ClickFix social engineering lures appeared in the wild. Ransomware groups Qilin, Nightspire, Payload, and Coinbase Cartel collectively claimed at least 9 new victims across education, energy, healthcare, and enterprise sectors.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 7 | Chromium CSS/WebGL/Fonts CVEs; ShinyHunters EU Commission breach; Coinbase Cartel RaaS; Telnyx PyPI supply chain attack |
| 🟠 **HIGH** | 11 | Qilin, Nightspire, Payload ransomware victims; Infinity Stealer macOS campaign; TeamPCP campaign update; ransomware landscape tracking |
| 🟡 **MEDIUM** | 9 | Chromium FedCM/WebAudio CVEs; etcd RBAC bypass; Libsoup buffer overread; XPath DoS; INC Ransom; BellingCat OSINT |
| 🔵 **INFO** | 2 | Kali Linux 2026 tool releases; Schneier squid blogging |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters Claims European Commission Data Breach (350 GB+)

**Source:** [RansomLock](https://www.ransomlook.io//group/shinyhunters)

ShinyHunters posted a claim on BreachForums alleging the compromise of European Commission infrastructure under *.europa.eu. The claimed haul exceeds 350 GB and includes mail server dumps, database exports, confidential documents, and contracts. ShinyHunters is a well-established data breach actor with a history of high-profile compromises. The group's .onion infrastructure shows 73% uptime over the past 30 days.

No independent confirmation of the breach scope is available at this time. The European Commission has not publicly acknowledged the incident as of reporting.

> **SOC Action:** Monitor for any europa.eu credential dumps appearing on paste sites and dark web marketplaces. If your organisation interacts with EU Commission systems, preemptively rotate API keys and credentials used for EU portals. Search email logs for any anomalous authentication attempts against europa.eu-adjacent services.

### 3.2 TeamPCP Supply Chain Campaign — Telnyx PyPI Backdoor and Operational Shift

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/backdoored-telnyx-pypi-package-pushes-malware-hidden-in-wav-audio/), [SANS ISC](https://isc.sans.edu/diary/rss/32842)

TeamPCP compromised versions 4.87.1 and 4.87.2 of the Telnyx PyPI package (740,000+ monthly downloads), embedding credential-stealing malware inside WAV audio files using steganography with XOR-based decryption. On Linux/macOS, the payload harvests SSH keys, cloud tokens, cryptocurrency wallets, and environment variables. On Windows, an executable drops into the Startup folder for persistence. If Kubernetes is running, the malware enumerates cluster secrets and deploys privileged pods across nodes.

SANS reports the first 48-hour window without a new package compromise since TeamPCP began operations on March 19. The group appears to have shifted focus to monetizing existing credential harvests, including through a Vect ransomware affiliate partnership. Palo Alto Networks published behavioral detection rules targeting CI/CD pipeline anomalies. The CISA KEV remediation deadline for CVE-2026-33634 is April 8, 2026 (11 days away).

#### Indicators of Compromise
```
Package: telnyx==4.87.1, telnyx==4.87.2 (malicious)
Safe version: telnyx==4.87.0
Malicious file: telnyx/_client.py
Persistence (Windows): %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\msbuild.exe
Staging: ringtone.wav (Linux/macOS), hangup.wav (Windows)
```

MITRE ATT&CK: T1195.002 (Supply Chain Compromise: Software Supply Chain), T1027 (Obfuscated Files or Information), T1059 (Command and Scripting Interpreter), T1003 (Credential Access)

> **SOC Action:** Audit all Python environments for Telnyx versions 4.87.1 and 4.87.2 immediately. Any system that imported these versions should be treated as fully compromised — rotate all secrets, SSH keys, cloud tokens, and Kubernetes service account credentials. Deploy Palo Alto behavioral detection rules for CI/CD anomalies: credential directory enumeration, bulk reads from /proc/\<pid\>/mem, encrypted archive creation (tpcp.tar.gz), and HTTPS to domains registered within the past 30 days.

### 3.3 Chromium Critical Vulnerability Batch (5 CVEs)

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-4442)

Microsoft disclosed five critical and high-severity Chromium vulnerabilities affecting Chrome and Edge:

| CVE | Component | Type | Severity |
|-----|-----------|------|----------|
| CVE-2026-4442 | CSS | Heap buffer overflow | 🔴 Critical |
| CVE-2026-4674 | CSS | Out-of-bounds read | 🔴 Critical |
| CVE-2026-4675 | WebGL | Heap buffer overflow | 🔴 Critical |
| CVE-2026-4679 | Fonts | Integer overflow | 🔴 Critical |
| CVE-2026-4673 | WebAudio | Heap buffer overflow | 🟠 High |

Additional medium-severity issues include CVE-2026-4680 (use-after-free in FedCM) and CVE-2026-4677 (out-of-bounds read in WebAudio). The heap buffer overflow and integer overflow vulnerabilities in CSS, WebGL, and Fonts could enable remote code execution through crafted web content.

> **SOC Action:** Prioritise Chrome/Edge patching to the latest stable channel. Verify enterprise browser management policies are enforcing auto-update. For environments with delayed patching, consider restricting access to untrusted web content via proxy rules or browser isolation. Query EDR for any anomalous renderer process crashes that may indicate exploitation attempts.

### 3.4 Infinity Stealer — New macOS Infostealer via ClickFix Lures

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-infinity-stealer-malware-grabs-macos-data-via-clickfix-lures/)

Malwarebytes documented a new macOS infostealer called Infinity Stealer that uses ClickFix social engineering — a fake Cloudflare CAPTCHA prompting users to paste a base64-obfuscated curl command into Terminal. The payload is compiled with Nuitka (Python → native C binary), producing an 8.6 MB Mach-O binary resistant to static analysis. The stealer harvests Chromium/Firefox credentials, macOS Keychain entries, cryptocurrency wallets, and .env files. Exfiltration occurs via HTTP POST to C2, with Telegram notification to operators.

#### Indicators of Compromise
```
Domain: update-check[.]com (ClickFix lure)
Staging: /tmp/ (Nuitka loader)
Binary: 8.6 MB Mach-O, contains 35 MB zstd archive (UpdateHelper.bin)
Exfiltration: HTTP POST to C2
Notification: Telegram bot callback
```

MITRE ATT&CK: T1204.002 (User Execution: Malicious File), T1059.004 (Unix Shell), T1555 (Credentials from Password Stores), T1041 (Exfiltration Over C2)

> **SOC Action:** Block update-check[.]com at the proxy/DNS layer. Deploy endpoint detection for base64-encoded curl commands executed via Terminal on macOS. Alert on processes spawned from /tmp/ that make outbound HTTP POST connections. Educate users that legitimate CAPTCHAs never require Terminal commands.

### 3.5 Ransomware Surge — Qilin, Nightspire, Payload, and Coinbase Cartel

**Source:** [RansomLock](https://www.ransomlook.io)

Multiple ransomware groups claimed new victims in the past 24 hours:

| Group | Victims | Sectors |
|-------|---------|---------|
| Qilin | IBB Institut für Bildung und Beratung, TR Construya | Education, Construction |
| Nightspire | 2 obfuscated victims | Healthcare, Engineering, Financial Services |
| Payload | Q2 Artificial Lift Services, Don-Nan, A.A. Al Moosa Enterprises (ARENCO) | Energy, Industrial, Real Estate |
| Coinbase Cartel | Genobank | Healthcare/Biotech |

Coinbase Cartel operates a RaaS model with Tor-based C2 and Tox/SimpleX communication channels. The group has claimed 104 victims to date and targets technology, manufacturing, and healthcare sectors. Nightspire maintains multiple .onion domains with mixed uptime (0–97%) and communicates via nightspireteam@proton.me.

> **SOC Action:** Review threat intelligence feeds for IOCs associated with Qilin, Nightspire, Payload, and Coinbase Cartel. Verify offline backup integrity for critical systems. Ensure ransomware playbooks are current and include communications with affected third parties in the named sectors (education, healthcare, energy, construction).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased targeting of critical infrastructure and supply chains | Backdoored Telnyx PyPI package; AI Infrastructure Supply Chain Poisoning Alert |
| 🟠 **HIGH** | Ransomware and extortion-as-a-service operations targeting multiple sectors | CIM By Worldleaks; Sheraton Hotel By Worldleaks; Payoutsking activity |
| 🟠 **HIGH** | Increased ransomware activity with overlapping TTPs across groups | Nightspire, Coinbase Cartel, and Payload victims sharing phishing and C2 techniques |
| 🟡 **MEDIUM** | Exploitation of vulnerabilities in open-source software libraries | CVE-2026-4645 (XPath DoS); CVE-2026-2369 (Libsoup buffer overread); CVE-2026-33343 (etcd RBAC bypass) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (23 reports) — Prolific RaaS operator targeting education, construction, and technology sectors via Tor infrastructure
- **TeamPCP** (17 reports) — Supply chain threat actor responsible for Telnyx, Trivy, LiteLLM, and CanisterWorm compromises; shifting to monetization phase
- **Nightspire** (13 reports) — Ransomware group targeting healthcare, engineering, and financial services with multi-channel communications
- **Akira** (12 reports) — Established ransomware group with sustained campaign activity across multiple verticals
- **Handala** (10 reports) — Threat actor with sustained reporting volume over multiple weeks
- **ShinyHunters** (7 reports) — Data breach actor claiming European Commission compromise; BreachForums operator

### Malware Families

- **Akira ransomware** (9 reports) — Active ransomware deployed across manufacturing, technology, and engineering targets
- **DragonForce ransomware** (5 reports) — Targeting retail, government, logistics, and manufacturing sectors
- **CanisterWorm** (5 reports) — Supply chain worm component associated with TeamPCP campaign
- **Vidar** (4 reports) — Commodity infostealer with persistent presence in the threat landscape
- **Infinity Stealer** (1 report) — Newly documented macOS infostealer using ClickFix and Nuitka compilation

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 11 | [link](https://msrc.microsoft.com/update-guide) | Chromium CVE disclosures and open-source library vulnerabilities |
| RansomLock | 10 | [link](https://www.ransomlook.io) | Ransomware victim tracking for Qilin, Nightspire, Payload, Coinbase Cartel, ShinyHunters |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com) | Telnyx supply chain attack and Infinity Stealer macOS campaign |
| BellingCat | 1 | [link](https://www.bellingcat.com) | OSINT verification of Iran strike footage |
| SANS | 1 | [link](https://isc.sans.edu) | TeamPCP supply chain campaign update 003 |
| Schneier | 1 | [link](https://www.schneier.com) | Non-security content (squid blogging) |
| Telegram OSINT | 2 | — | Ransomware landscape tracking and BreachForums activity (channel names redacted) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all Python environments for Telnyx PyPI versions 4.87.1 and 4.87.2. Treat any system that imported these versions as fully compromised. Rotate all secrets, SSH keys, cloud tokens, and Kubernetes service account credentials. The CISA KEV deadline for CVE-2026-33634 is April 8.

- 🔴 **IMMEDIATE:** Push Chrome and Edge updates to the latest stable channel to address CVE-2026-4442, CVE-2026-4674, CVE-2026-4675, and CVE-2026-4679 (critical heap buffer overflow and integer overflow vulnerabilities). Enable browser isolation for high-risk users pending patch deployment.

- 🟠 **SHORT-TERM:** Block update-check[.]com at the proxy/DNS layer and deploy macOS endpoint detections for base64-encoded curl commands executed via Terminal. The Infinity Stealer ClickFix technique is novel and may be replicated by other threat actors.

- 🟠 **SHORT-TERM:** Monitor dark web and paste sites for europa.eu credential dumps following the ShinyHunters claim. Organisations with EU Commission data-sharing agreements should preemptively rotate integration credentials and API keys.

- 🟡 **AWARENESS:** Deploy Palo Alto Networks behavioral detection rules for CI/CD pipeline attacks. Even without Palo Alto products, evaluate whether CI/CD monitoring can detect credential enumeration, /proc memory reads, encrypted archive creation, and outbound HTTPS to newly registered domains.

- 🟢 **STRATEGIC:** Verify offline backup integrity and ransomware response playbooks given sustained multi-group ransomware activity (Qilin, Nightspire, Payload, Coinbase Cartel, Akira). The convergence of RaaS operators sharing phishing and C2 TTPs suggests a maturing affiliate ecosystem with overlapping infrastructure.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 29 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
