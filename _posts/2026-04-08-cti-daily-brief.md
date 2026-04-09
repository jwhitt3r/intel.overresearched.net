---
layout: post
title: "CTI Daily Brief: 2026-04-08 — Adobe Reader Zero-Day Exploited in Wild; Marimo RCE Weaponised in Under 10 Hours; Qilin Ransomware Surge"
date: 2026-04-09 20:05:00 +0000
description: "89 reports processed across 15 sources. Critical zero-day exploitation of Adobe Reader ongoing since December. Marimo Python notebook RCE exploited within 10 hours of disclosure. CISA ICS advisory for Contemporary Controls BASC 20T PLC (CVE-2025-13926). Multiple OpenPrinting CUPS critical RCEs disclosed. Qilin ransomware group continues high-tempo operations across legal, education, and maritime sectors."
category: daily
tags: [cti, daily-brief, qilin, macsync-stealer, adobe-reader, cups, unc6783]
classification: TLP:CLEAR
severity: critical
reporting_period: "2026-04-08"
generated: "2026-04-09"
draft: true
report_count: 89
sources:
  - Microsoft
  - BleepingComputer
  - RansomLock
  - RecordedFutures
  - AlienVault
  - Cisco Talos
  - CISA
  - SANS
  - Wiz
  - Wired Security
  - Schneier
  - Sysdig
  - Datadog
  - Unit42
  - AppOmni
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-08 (24h) | TLP:CLEAR | 2026-04-09 |

## 1. Executive Summary

The pipeline processed 89 reports from 15 sources over the past 24 hours, with 8 rated critical and 50 rated high. The dominant theme is active zero-day exploitation: an Adobe Reader vulnerability has been exploited in the wild since December using sophisticated PDF-based fingerprinting attacks capable of achieving remote code execution without user interaction beyond opening a file. Separately, a pre-authentication RCE in the Marimo Python notebook was weaponised within 9 hours 41 minutes of advisory publication — no public PoC required. CISA published an ICS advisory for CVE-2025-13926 affecting Contemporary Controls BASC 20T PLCs used in critical infrastructure worldwide (CVSS 9.8). Multiple critical OpenPrinting CUPS vulnerabilities enable unauthenticated remote code execution. On the ransomware front, Qilin maintained high-tempo operations with victims spanning legal services, education, maritime, and automotive sectors, while the Smart Slider 3 Pro plugin supply chain compromise affected up to 900,000 WordPress and Joomla sites.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 8 | Adobe Reader zero-day; CISA ICS advisory CVE-2025-13926; Marimo RCE; OpenPrinting CUPS RCE (CVE-2026-34980); OpenSC stack overflow (CVE-2025-66215); Libinput code execution (CVE-2026-35093); timc ransomware claims |
| 🟠 **HIGH** | 50 | Qilin ransomware (6 victims); Smart Slider supply chain; UNC6783 BPO compromise; MacSync Stealer macOS campaign; CUPS batch CVEs; Bitcoin Depot $3.6M theft; AWS AgentCore "God Mode"; Bitter hack-for-hire |
| 🟡 **MEDIUM** | 15 | M365 Copilot info disclosure; OpenSC additional CVEs; SVG credit card stealer; Kubernetes CVE-2020-8562 analysis |
| 🟢 **LOW** | 1 | Miscellaneous advisory |
| 🔵 **INFO** | 15 | Threat landscape reports; tooling tutorials; industry commentary |

## 3. Priority Intelligence Items

### 3.1 Adobe Reader Zero-Day Exploited Since December

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploiting-acrobat-reader-zero-day-flaw-since-december/)

Attackers have been exploiting an unpatched zero-day in Adobe Reader since at least December 2025 using a "fingerprinting-style PDF exploit" that requires no user interaction beyond opening a malicious PDF. The exploit leverages privileged `util.readFileIntoStream` and `RSS.addFeed` Acrobat APIs to harvest local system information and can chain into subsequent RCE or sandbox escape (SBX) attacks for full system compromise. PDF lures contain Russian-language content referencing the oil and gas industry.

The vulnerability affects the latest version of Adobe Reader. No patch is available at the time of reporting. The researcher (Haifei Li / EXPMON) disclosed the flaw to Adobe and published detection guidance.

**MITRE ATT&CK:** T1204 (User Execution), T1059.003 (JavaScript), T1071.001 (Web Protocols)

> **SOC Action:** Block HTTP/HTTPS traffic containing the `Adobe Synchronizer` User-Agent string at the proxy/NGFW. Deploy detection rules for `util.readFileIntoStream` and `RSS.addFeed` API calls in PDF files. Restrict Adobe Reader JavaScript execution via registry policy (`bEnableJS = 0`). Alert on PDF attachments with Russian-language metadata arriving from external sources.

### 3.2 Marimo Python Notebook Pre-Auth RCE — Exploited in Under 10 Hours

**Source:** [Sysdig](https://webflow.sysdig.com/blog/marimo-oss-python-notebook-rce-from-disclosure-to-exploitation-in-under-10-hours)

A critical pre-authentication RCE vulnerability (GHSA-2679-6mx9-h9xc) in the Marimo open-source Python notebook was disclosed on 8 April and exploited in the wild within 9 hours 41 minutes. Attackers connected to the unauthenticated `/terminal/ws` WebSocket endpoint to obtain an interactive shell, then exfiltrated `.env` files containing credentials within 3 minutes of initial access. No public PoC existed — the attacker built a working exploit directly from the advisory description, suggesting AI-assisted exploit development.

**MITRE ATT&CK:** T1046 (Network Service Scanning), T1078 (Valid Accounts), T1083 (File and Directory Discovery)

#### Indicators of Compromise
```
Attacker IP: 49.207.56[.]74
Endpoint: /terminal/ws (unauthenticated WebSocket)
```

> **SOC Action:** Identify any internet-exposed Marimo instances and take them offline or place behind authentication immediately. Query network logs for connections to `/terminal/ws` endpoints. Scan for `.env` file access from non-standard processes. Update Marimo to the patched version as soon as available.

### 3.3 CISA ICS Advisory: Contemporary Controls BASC 20T (CVE-2025-13926)

**Source:** [CISA](https://www.cisa.gov/news-events/ics-advisories/icsa-26-099-01)

CISA published advisory ICSA-26-099-01 for CVE-2025-13926 (CVSS 9.8) affecting the Contemporary Controls BASC 20T PLC (BASControl20 version 3.1). The vulnerability allows unauthenticated attackers to forge packets using sniffed network traffic to enumerate, reconfigure, rename, delete PLC components, perform file transfers, and execute remote procedure calls. The product is deployed worldwide across Commercial Facilities, Critical Manufacturing, and Energy sectors. The BASC-20T is an obsolete product with no planned patch.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1071.001 (Web Protocols)

> **SOC Action:** Identify any BASC 20T devices on the network and isolate them behind firewalls with strict allowlisting. Ensure no ICS/SCADA devices are directly internet-accessible. If remote access is required, enforce VPN with MFA. Begin planning replacement of this obsolete product.

### 3.4 Smart Slider 3 Pro Supply Chain Compromise — 900K+ Sites at Risk

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/smart-slider-updates-hijacked-to-push-malicious-wordpress-joomla-versions/)

Attackers hijacked the update mechanism for Smart Slider 3 Pro (WordPress/Joomla), distributing malicious version 3.5.1.35 on 7 April. The trojanised update installs multi-layered backdoors: unauthenticated command execution via crafted HTTP headers, authenticated PHP eval and OS command execution, a hidden administrator account (prefix `wpsvc_`), a must-use plugin disguised as a caching component, a theme `functions.php` backdoor, and a standalone PHP backdoor in `wp-includes/` that survives database credential rotation. Over 900,000 sites use Smart Slider for WordPress.

**MITRE ATT&CK:** T1071.001 (Web Protocols), T1068 (Exploitation for Privilege Escalation)

> **SOC Action:** Check all WordPress and Joomla sites for Smart Slider 3 Pro version 3.5.1.35. If found, assume full site compromise: remove the plugin, restore from backups dated 5 April or earlier, reinstall WordPress core from trusted sources, rotate all credentials (WP, DB, FTP/SSH, hosting), regenerate WordPress salts, and scan for hidden admin users with the `wpsvc_` prefix. Check `wp-includes/` for anomalous PHP files and the `mu-plugins/` directory for unexpected entries.

### 3.5 UNC6783 Compromises BPOs to Steal Corporate Zendesk Tickets

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-new-unc6783-hackers-steal-corporate-zendesk-support-tickets/)

Google Threat Intelligence Group disclosed UNC6783, a threat actor linked to the Raccoon persona, which targets business process outsourcing (BPO) providers to gain access to high-value enterprises. The group uses social engineering over live chat, phishing with spoofed Okta login pages (pattern: `<org>[.]zendesk-support<##>[.]com`), clipboard theft to bypass MFA, and fake security updates delivering RATs. After data exfiltration, the actor extorts victims via ProtonMail. The group claimed a breach at Adobe involving 13 million support tickets.

**MITRE ATT&CK:** T1566 (Phishing), T1078 (Valid Accounts)

> **SOC Action:** Deploy FIDO2 security keys for MFA on all support platforms. Block domains matching the pattern `*zendesk-support*[.]com` at the DNS/proxy layer. Monitor helpdesk live chat for social engineering attempts. Audit recent MFA device enrolments for suspicious additions. Review BPO vendor access controls and implement conditional access policies.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Zero-day exploitation of widely used software platforms accelerating | Adobe Reader zero-day active since December; OpenSSL TLS 1.3 key agreement group vulnerability (CVE-2026-2673) |
| 🔴 **CRITICAL** | RaaS groups maintaining aggressive multi-sector targeting globally | Coinbase Cartel targeting 5+ sectors; Qilin sustained operations across legal, education, maritime |
| 🔴 **CRITICAL** | State-affiliated actors targeting critical infrastructure OT/ICS | Iran-linked groups sabotaging US energy and water infrastructure (FBI/Pentagon warnings) |
| 🟠 **HIGH** | Ransomware activity intensifying against healthcare and finance | Nightspire, The Gentlemen, timc targeting healthcare organisations |
| 🟠 **HIGH** | Supply chain compromises as a preferred delivery mechanism | TeamPCP/UNC6780 Cisco source code theft via Trivy-linked breach; Axios supply chain attack; Smart Slider hijack |
| 🟠 **HIGH** | Phishing and credential stuffing prevalent in financial services | MFA bypass techniques; Bitcoin Depot $3.6M theft; accountant-targeting campaigns in Russia |
| 🟠 **HIGH** | E-commerce platforms under exploitation pressure | SVG pixel trick credit card stealer targeting ~100 Magento stores |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (48 reports) — Prolific RaaS operator targeting legal, education, maritime, and enterprise sectors with sustained daily victim claims
- **The Gentlemen** (54 reports combined) — Active ransomware group targeting healthcare and professional services
- **Nightspire** (36 reports) — Ransomware operator with healthcare sector focus
- **TeamPCP / UNC6780** (31 reports) — Supply chain threat actor tracked by Google GTIG; Cisco source code theft via Trivy-linked breach
- **DragonForce** (27 reports) — Ransomware group with cross-sector targeting
- **Akira** (22 reports) — Established RaaS operator maintaining steady activity
- **UNC6783 / Raccoon** (new) — BPO-targeting extortion group disclosed by Google GTIG
- **Bitter** (new) — Hack-for-hire operation targeting MENA journalists and activists

### Malware Families

- **Ransomware (generic)** (39+ reports) — Dominant malware category across all tracked groups
- **DragonForce Ransomware** (25 reports) — Custom ransomware tooling
- **Akira Ransomware** (18 reports) — Established RaaS platform
- **MacSync Stealer** (new) — macOS MaaS infostealer using ClickFix CAPTCHAs, targeting browser credentials, crypto wallets, SSH keys, and Keychain data
- **PLAY Ransomware** (8 reports) — Active RaaS variant
- **ClipBanker** (new) — Cryptocurrency-stealing malware with marathon infection chains

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 31 | [link](https://msrc.microsoft.com/update-guide) | CUPS, OpenSC, ONNX, and Libinput CVE advisories |
| RansomLock | 22 | [link](https://www.ransomlook.io) | Ransomware victim claim tracking (Qilin, timc, Pear, Nightspire, Insomnia, Anubis, Lynx, Beast) |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com) | Adobe Reader zero-day, Smart Slider supply chain, UNC6783, SVG skimmer, Bitcoin Depot |
| RecordedFutures | 5 | [link](https://therecord.media) | Bitcoin Depot theft, Russian accountant targeting |
| AlienVault | 4 | [link](https://otx.alienvault.com) | MacSync Stealer, Bitter hack-for-hire, ClipBanker |
| Cisco Talos | 2 | [link](https://blog.talosintelligence.com) | Threat hunting methodologies |
| CISA | 2 | [link](https://www.cisa.gov) | BASC 20T ICS advisory (ICSA-26-099-01); GPL Odorizers advisory |
| SANS | 2 | [link](https://isc.sans.edu) | TeamPCP supply chain update |
| Wiz | 2 | [link](https://www.wiz.io) | Cloud security research |
| Sysdig | 1 | [link](https://sysdig.com) | Marimo RCE exploitation timeline |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | AWS AgentCore "Agent God Mode" IAM privilege escalation |
| Wired Security | 1 | [link](https://www.wired.com/category/security) | Security reporting |
| Schneier | 1 | [link](https://www.schneier.com) | Security commentary |
| Datadog | 1 | [link](https://www.datadoghq.com) | Kubernetes CVE analysis |
| AppOmni | 1 | [link](https://appomni.com) | EvilToken M365 device code phishing |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Block the `Adobe Synchronizer` User-Agent string at network perimeter and disable JavaScript in Adobe Reader (`bEnableJS = 0`) until Adobe releases a patch for the actively exploited zero-day. Advise users not to open PDF attachments from untrusted sources.

- 🔴 **IMMEDIATE:** Identify and take offline any internet-exposed Marimo notebook instances. The pre-auth RCE on `/terminal/ws` requires no credentials and is being actively exploited. Query firewall logs for connections from 49.207.56[.]74.

- 🟠 **SHORT-TERM:** Audit all WordPress and Joomla sites for Smart Slider 3 Pro version 3.5.1.35. If present, treat as full compromise: restore from pre-April-5 backups, rotate all credentials, regenerate salts, and hunt for hidden admin accounts (prefix `wpsvc_`) and anomalous mu-plugins.

- 🟠 **SHORT-TERM:** Review CUPS deployment across Linux infrastructure and apply patches for CVE-2026-34980 (unauthenticated RCE via PostScript queues), CVE-2026-34978 (path traversal), CVE-2026-39316 (use-after-free), and CVE-2026-34979 (heap overflow). Disable network-shared print queues where not operationally required.

- 🟡 **AWARENESS:** UNC6783 is actively targeting BPO providers to pivot into enterprise environments. Enforce FIDO2 hardware keys for MFA on support platforms, block `*zendesk-support*[.]com` domains, and audit BPO vendor access scopes.

- 🟢 **STRATEGIC:** The Marimo exploitation (9h41m advisory-to-exploit) and Smart Slider supply chain attack reinforce the trend of shrinking vulnerability-to-exploitation windows. Evaluate automated patch management and external attack surface monitoring capabilities to reduce exposure time for both first-party and third-party software.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 89 reports processed across 5 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
