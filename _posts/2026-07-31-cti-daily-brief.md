---
layout: post
title:  "CTI Daily Brief: 2026-07-31 - Iran-linked attacks on 7 states' water systems, critical Rails Active Storage RCE, Gentlemen & Insomnia ransomware"
date:   2026-08-01 20:09:04 +0000
description: "15 reports across 8 sources. Critical Rails Active Storage RCE flaw, FBI-confirmed Iran-linked cyberattacks on water utilities in 7 states, Adform supply-chain crypto theft, Amgen cloud breach, and active Gentlemen/Insomnia ransomware operations."
category: daily
tags: [cti, daily-brief, the-gentlemen, insomnia, rails-active-storage]
classification: TLP:CLEAR
reporting_period: "2026-07-31"
generated: "2026-08-01"
draft: true
report_count: 15
severity: critical
sources:
  - BleepingComputer
  - RansomLook
  - Wired Security
  - SANS
  - HaveIBeenPwned
  - Elastic Security Labs
  - Schneier
  - BellingCat
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-31 (24h) | TLP:CLEAR | 2026-08-01 |

## 1. Executive Summary

The pipeline processed 15 reports from 8 sources over the reporting period, with the threat picture dominated by critical infrastructure targeting and active ransomware operations. The single critical item is a Rails Active Storage flaw that lets an unauthenticated attacker read arbitrary files with potential escalation to remote code execution. The highest-impact operational development is the FBI's confirmation that Iran-linked cyberattacks against industrial control systems have now hit water utilities in seven states — beyond the 30-plus Minnesota utilities previously reported — with CISA noting some incidents disabled digital controls and triggered boil-water notices. Ransomware groups The Gentlemen and Insomnia remained active, posting new victims across financial services, manufacturing, healthcare, and legal sectors. A supply-chain compromise of ad firm Adform's script silently swapped cryptocurrency wallet addresses on visitor clipboards, and pharmaceutical company Amgen disclosed a third-party cloud breach exposing patient health and proprietary data. No confirmed CISA KEV additions appeared in this period's data.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | Rails Active Storage arbitrary file read / RCE |
| 🟠 **HIGH** | 5 | Iran-linked water utility attacks; Gentlemen & Insomnia ransomware; Amgen cloud breach; Adform supply-chain theft |
| 🟡 **MEDIUM** | 5 | Qilin RaaS activity; AI-provider phishing; SplitVPN breach; Arch Linux AUR malware flood |
| 🟢 **LOW** | 0 | None |
| 🔵 **INFO** | 4 | Kinahan cartel OSINT; AI-lab hacking legality; Elastic at Black Hat; Schneier squid blog |

## 3. Priority Intelligence Items

### 3.1 Critical Rails Active Storage flaw enables arbitrary file read and potential RCE

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/rails-patches-critical-active-storage-flaw-with-rce-potential/)

A critical vulnerability in the Ruby on Rails Active Storage framework allows an unauthenticated attacker to read arbitrary files from a Rails application, with potential to escalate to remote code execution. The flaw stems from improper access control within Active Storage; exploitation could expose sensitive data (credentials, configuration, secrets) and, in the worst case, allow attackers to run arbitrary code on the host. Rails has released a patch. No CVE identifier or in-the-wild exploitation was present in the source data. Affected: any web application built on Rails using Active Storage for file handling.

> **SOC Action:** Inventory all internet-facing Rails applications and confirm the Active Storage patch is applied against the current release. Until patched, monitor web logs for anomalous file-path parameters in Active Storage endpoints (e.g., traversal-style requests to `/rails/active_storage/`), and alert on unauthenticated requests returning application source or config files. MITRE: T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts), T1204 (User Execution).

### 3.2 FBI confirms Iran-linked cyberattacks on water utilities across seven states

**Source:** [Wired Security](https://www.wired.com/story/security-news-this-week-7-states-water-systems-hit-by-cyberattacks-likely-tied-to-iran/)

The FBI warned that a hacking campaign against water and wastewater industrial control systems (ICS) has now hit utilities in no fewer than seven states, expanding from the 30-plus Minnesota utilities previously reported. WIRED obtained a memo tying the campaign to Iran — the first official documentation of Iran's likely responsibility for what may be the broadest, most disruptive campaign to target US industrial control systems. CISA's advisory states the attacks in some cases disabled digital controls and "resulted in boil-water notices," suggesting potential water contamination. The FBI, working with the EPA and CISA, urged utilities to remove internet-exposed programmable logic controllers (PLCs), protect them with strong passwords, and enforce device allow-lists. Attribution remains "likely" Iranian-affiliated actors, not confirmed. Affected sector: water/wastewater critical infrastructure.

> **SOC Action:** Immediately enumerate internet-exposed PLCs and HMIs via Shodan/Censys and pull them behind the firewall or a VPN; disable default and shared credentials. Enforce allow-lists so only authorized engineering workstations can reach control devices. Review OT network logs for unauthorized Modbus/web-protocol connections to controllers and for configuration changes. MITRE: T1566 (Phishing), T1071.001 (Application Layer Protocol: Web Protocols), T1489 (Service Stop / disabling controls).

### 3.3 Adform ad-platform script hijacked in supply-chain cryptocurrency theft

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/)

Online advertising firm Adform suffered a supply-chain attack in which its ad-serving script was altered to deliver cryptocurrency-stealing code to any website using its platform. The malicious script replaced legitimate wallet addresses copied to a visitor's clipboard with attacker-controlled addresses, so users pasting a "copied" wallet address unknowingly sent funds to the attacker. This clipboard-hijack technique is difficult for end users to detect. Affected: any site embedding Adform's ad platform, and their visitors performing cryptocurrency transactions.

> **SOC Action:** Audit third-party scripts loaded on your web properties; implement Subresource Integrity (SRI) and a strict Content-Security-Policy to constrain script sources. Advise finance and crypto-handling staff to verify full wallet addresses character-by-character before sending, not just the first/last few. Monitor for unexpected changes in externally loaded ad/marketing scripts. MITRE: T1566 (Phishing), T1204.001 (User Execution: Malicious Link).

### 3.4 Amgen discloses third-party cloud breach exposing patient health and proprietary data

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/amgen-says-cloud-data-breach-exposed-patient-health-proprietary-info/)

Pharmaceutical company Amgen disclosed a data breach in which threat actors stole corporate data and patient information held in multiple cloud systems operated by third-party service providers. The exposed data includes proprietary information and patient health records, underscoring recurring risk in third-party cloud supply chains. No specific threat actor was named in the source data. Affected: healthcare/pharmaceutical sector and Amgen patients.

> **SOC Action:** Review third-party cloud provider access scopes and enforce least privilege on vendor integrations; require MFA and short-lived credentials for all third-party cloud access. Validate that data-loss-detection and cloud audit logging (e.g., API access to storage buckets) are enabled across vendor tenancies. Confirm breach-notification and DPA obligations with affected vendors. MITRE: T1190 (Exploit Public-Facing Application), T1566 (Phishing), T1071.001 (Web Protocols).

### 3.5 Active ransomware operations: The Gentlemen and Insomnia post fresh victims

**Source:** [RansomLook — The Gentlemen](https://www.ransomlook.io//group/the%20gentlemen), [RansomLook — Insomnia](https://www.ransomlook.io//group/insomnia)

Two ransomware groups showed sustained activity on their leak sites during the period. **The Gentlemen** (Tox1/Tox crypter family) listed Philippine Savings Bank alongside recent manufacturing, automotive, and solar-energy victims (World Wide Fittings, Chemco Systems, Total Auto Business Solutions, Ökovolt Solartechnik), with 139 posts in the last 30 days and a 704-post all-time total. **Insomnia** (CryptoLocker/Tox family) posted Merritt Woodwork and Laempe Reich, continuing a pattern of targeting legal services, healthcare, and industrial firms with an 83% 30-day leak-site uptime. Both groups favor Tor hidden services for negotiation. The Gentlemen is currently the most-referenced threat actor pipeline-wide (116 reports).

#### Indicators of Compromise
```
The Gentlemen — leak site (Tor):  hxxp[:]//tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion/
The Gentlemen — chat server (Tor): hxxp[:]//i2ohjeeqe37jre4f2u7pyq73cbm6lecumdxapkvrlryna6rc3it4zsid[.]onion/
Insomnia — leak site (Tor):        hxxp[:]//i62huw7ve22rpyw6lnq3kmfump2dmsg4xpveec3ere73njwatrz74gad[.]onion/
Insomnia — file server (Tor):      hxxp[:]//r3keoxye5mki4fqcvlk4hpfqqzxmakchjpmem7oppynobcieamdbmcyd[.]onion/
```

> **SOC Action:** Block the above Tor onion addresses at egress and alert on any internal host initiating Tor connections (default ports 9001/9030/9050) — a common precursor to ransomware exfiltration/negotiation. Prioritize offline, tested backups and network segmentation for manufacturing, automotive, healthcare, and legal-sector assets matching these groups' targeting. MITRE: T1486 (Data Encrypted for Impact), T1204 (User Execution).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Ransomware-as-a-Service groups expanding operations across sectors | "Index of / By booba team"; "Jani-King By booba team" (batch 261) |
| 🔴 CRITICAL | Exploitation of software vulnerabilities for RCE, particularly in dev tools | "CVE-2026-60004 Gitea RCE (CVSS 9.8) PoC"; "JetBrains warns of critical TeamCity RCE flaw" (batch 260) |
| 🟠 HIGH | Increased targeting of critical infrastructure (water utilities, financial services) | "7 States' Water Systems Hit by Cyberattacks Likely Tied to Iran"; "Philippine Savings Bank By the gentlemen" (batch 263) |
| 🟠 HIGH | Increased ransomware activity across sectors with overlapping TTPs | "Merritt Woodwork By insomnia"; "Laempe Reich By insomnia" (batch 262) |
| 🟠 HIGH | Ransomware activity with data exfiltration and publication threats | "Boyum IT Solutions By genesis"; "AguAseo By gammax" (batch 260) |
| 🟠 HIGH | Phishing as a common initial access vector across diverse campaigns | "Boyum IT Solutions By genesis"; "AguAseo By gammax" (batch 260) |
| 🟡 MEDIUM | Rising phishing across sectors including AI solutions and critical infrastructure | "Phishing Campaigns Targeting AI Solutions Providers"; "This month in security – July 2026" (batch 263) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **The Gentlemen** (116 reports) — most-referenced actor; ransomware group active against finance, manufacturing, automotive, and energy; new victim Philippine Savings Bank this period.
- **Qilin** (115 reports) — ransomware-as-a-service group; new victim Community Management Associates this period.
- **DragonForce** (42 reports) — ransomware group with continued multi-sector victim postings.
- **Everest** (21 reports) — active ransomware/extortion group.
- **Akira** (21 reports) — persistent ransomware operator.
- **Insomnia** (2 reports this period, growing) — CryptoLocker/Tox family; targeting legal, healthcare, and industrial firms.

### Malware Families
- **Tox1 / Tox** (56 / 40 reports) — crypter/protocol family used by The Gentlemen and Insomnia leak-site operations.
- **The Gentlemen ransomware** (15 reports) — encryptor tied to the like-named group.
- **DragonForce ransomware** (14 reports) — encryptor tied to the DragonForce group.
- **RALord** (14 reports) — recurring ransomware family.
- **CryptoLocker** (this period) — family associated with Insomnia operations.

> **Note:** Vulnerability-entity tracking remains sparse this period (only 3 CVEs indexed pipeline-wide, all dated 2026-07-07: CVE-2023-2868, CVE-2024-42009, CVE-2025-49113). The critical Rails Active Storage flaw was not yet assigned a CVE in the source data.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 4 | [link](https://www.ransomlook.io) | Ransomware leak-site tracking (Gentlemen, Insomnia, Qilin) |
| BleepingComputer | 4 | [link](https://www.bleepingcomputer.com) | Critical Rails RCE, Amgen breach, Adform supply-chain, Arch Linux AUR |
| Wired Security | 2 | [link](https://www.wired.com/category/security/) | Iran-linked water utility attacks; AI-lab hacking legality |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com) | SplitVPN breach (865k accounts) |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | Black Hat / DEF CON 2026 product coverage (info) |
| SANS | 1 | [link](https://isc.sans.edu) | Phishing campaign targeting AI solutions providers |
| Schneier | 1 | [link](https://www.schneier.com) | Friday squid blog (info) |
| BellingCat | 1 | [link](https://www.bellingcat.com) | Kinahan cartel Dubai visa OSINT (info) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all internet-facing Rails applications for the Active Storage arbitrary-file-read/RCE flaw and hunt web logs for traversal-style requests to Active Storage endpoints (Item 3.1).
- 🔴 **IMMEDIATE:** For any OT/water-sector environment, pull internet-exposed PLCs/HMIs offline, replace default credentials, and enforce device allow-lists per the FBI/CISA advisory on the Iran-linked ICS campaign (Item 3.2).
- 🟠 **SHORT-TERM:** Block the listed Gentlemen and Insomnia Tor onion addresses at egress, alert on internal Tor usage, and verify offline backups for manufacturing, healthcare, automotive, and legal-sector assets (Item 3.5).
- 🟠 **SHORT-TERM:** Audit third-party web scripts and cloud-vendor access — deploy SRI/CSP against Adform-style script tampering and enforce least-privilege MFA on vendor cloud integrations following the Amgen breach (Items 3.3, 3.4).
- 🟡 **AWARENESS:** Brief finance and end users on clipboard-hijacking crypto theft and end-of-month AI-service phishing lures impersonating ChatGPT/AI providers (Items 3.3, and SANS phishing report).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 15 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
