---
layout: post
title: "CTI Daily Brief: 2026-03-28 — Exitium Ransomware Exfiltrates 278 GB from IKRON; Nightspire Blitzes Healthcare Sector"
date: 2026-03-29 20:05:00 +0000
description: "Ransomware-dominated day with 27 reports across 3 sources. Exitium group claimed two critical-severity victims including IKRON (278 GB exfiltrated) and Ming Hwei Energy (infrastructure encrypted). Nightspire posted four new healthcare and services victims. Qilin, INC Ransom, and Orion groups all posted fresh claims. CVE-2026-3591 disclosed a high-severity ACL bypass via SIG(0) stack use-after-return. WordPress Smart Slider plugin flaw (CVE-2026-3098) exposes 500K+ sites to arbitrary file read."
category: daily
tags: [cti, daily-brief, exitium, nightspire, qilin, cve-2026-3591, cve-2026-3098]
classification: TLP:CLEAR
reporting_period: "2026-03-28"
generated: "2026-03-29"
severity: critical
draft: true
report_count: 27
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-28 (24h) | TLP:CLEAR | 2026-03-29 |

## 1. Executive Summary

The pipeline processed 27 reports from 3 sources over the past 24 hours, with ransomware operations dominating the threat landscape. Two reports reached critical severity: the exitium group claimed Ming Hwei Energy (Taiwanese solar-cell manufacturer, infrastructure encrypted) and IKRON (278 GB of PII, patient records, and CEO emails exfiltrated). Nightspire continued a sustained campaign with four new victim posts targeting healthcare providers and service firms across the United States and Europe. Qilin (Agenda) added Doctor.com to its RaaS leak site, INC Ransom listed Greenology Products, and Orion — with possible links to Babuk-Bjorka — posted two new victims including a Venezuelan food manufacturer. On the vulnerability side, Microsoft published 16 CVE advisories headlined by CVE-2026-3591 (high-severity SIG(0) ACL bypass), and BleepingComputer reported CVE-2026-3098, a file-read flaw in the Smart Slider 3 WordPress plugin affecting over 500,000 sites. No confirmed in-the-wild exploitation or CISA KEV additions were observed in this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | Exitium ransomware: Ming Hwei Energy (encrypted infra), IKRON (278 GB exfil) |
| 🟠 **HIGH** | 9 | Nightspire x4 victims; Qilin Doctor.com; INC Ransom Greenology; Orion x2; CVE-2026-3591 ACL bypass |
| 🟡 **MEDIUM** | 14 | CVE-2026-3098 Smart Slider WP plugin; LIBPNG UAF & OOB read; Picomatch ReDoS; DNSSEC memory leaks; Flannel RCE |
| 🔵 **INFO** | 2 | CVE-2025-67030; CVE-2026-34085 (limited details) |

## 3. Priority Intelligence Items

### 3.1 Exitium Claims IKRON and Ming Hwei Energy — Large-Scale Data Exfiltration and Encrypted Infrastructure

**Source:** [RansomLook](https://www.ransomlook.io//group/exitium)

The exitium ransomware group posted two critical-severity claims within 16 hours. IKRON, a US-based corporation, suffered exfiltration of 278 GB of data including PII (fullz, SSNs, patient records), CEO emails, and corporate documents. Ming Hwei Energy, a Taiwanese solar-cell manufacturer within a fastener conglomerate (11–50 employees, <$5M revenue), had its infrastructure encrypted. Exitium operates via a Tor-hosted leak site with 100% uptime over 30 days and communicates through Proton Mail and Tox. The group has claimed five victims since 12 March 2026, including Fannin CAD (400 GB) and Marborges Agroindustria (Brazil). Phishing is the likely initial access vector given the volume of stolen credentials and email data (T1566).

#### Indicators of Compromise
```
C2: m3ksukzn2glzfdvlusohril7n3iyk4z4fudf6mm22lwhpbpt5aiee5qd[.]onion
Email: blushaimee@proton[.]me
Tox: 0932023CDBDC780B80B4772D22975C9AAD6D1A5921AA4C746C9E4851A307DE1888A6F56FDFBE
```

> **SOC Action:** Search email gateway logs for outbound connections to proton[.]me addresses not in the corporate allow-list. Query DLP alerts for bulk data transfers exceeding 50 GB in the past 30 days. Review DNS logs for .onion resolution attempts via Tor exit nodes.

### 3.2 Nightspire Posts Four New Victims — Healthcare and Services Under Sustained Pressure

**Source:** [RansomLook](https://www.ransomlook.io//group/nightspire)

Nightspire, a prolific ransomware group with 283 posts since early March 2026 and six known affiliates (Phantom, Reaper, Volt, Blaze, Shadow, Blade), listed four new victims in the reporting period: Florida Therapy Services (healthcare, US), OTNet, and two redacted organisations. The group targets healthcare and energy sectors across the United States and Europe using Tor onion services for C2 (primary site at 97% uptime) and phishing (T1566) for initial access. Ransom notes are delivered via Gmail and Proton Mail addresses. AI correlation analysis identified nightspire activity across six reports in this period with 0.90 confidence, linking shared sector targeting (healthcare) and regional focus (United States).

#### Indicators of Compromise
```
C2: nspirep7orjq73k2x2fwh2mxgh74vm2now6cdbnnxjk2f5wn34bmdxad[.]onion
Email: nightspire[.]team@gmail[.]com
Email: nightspireteam[.]receiver@proton[.]me
Tox: 3B61CFD6E12D789A439816E1DE08CFDA58D76EB0B26585AA34CDA617C41D5943CDD15DB0B7E6
```

> **SOC Action:** Alert on email delivery from nightspire-associated addresses. Query EDR for Tor client execution (tor.exe, tor browser artifacts in %APPDATA%). Healthcare-sector organisations should verify backup integrity and segment patient-records databases from internet-facing systems.

### 3.3 Qilin (Agenda) RaaS Adds Doctor.com — Healthcare Targeting Continues

**Source:** [RansomLook](https://www.ransomlook.io//group/qilin)

Qilin, a known ransomware-as-a-service operation also tracked as Agenda, posted Doctor.com as a new victim. The group maintains extensive infrastructure including active .onion leak and file-sharing domains, FTP exfiltration servers, and Jabber/Tox communication channels. Qilin is the top trending threat actor in the pipeline with 24 reports over the past 7 days. Correlation analysis linked Qilin activity with phishing TTPs (T1566) at 0.60 confidence.

#### Indicators of Compromise
```
C2: ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
C2: kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion
Jabber: qilin@exploit[.]im
Tox: 7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
```

> **SOC Action:** Block known Qilin .onion domains at proxy/firewall where Tor traffic inspection is available. Search for ransom note filenames matching `README-RECOVER-*.txt` across file shares. Healthcare organisations should review privileged access to patient data systems.

### 3.4 CVE-2026-3591 — SIG(0) Stack Use-After-Return Enables ACL Bypass

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-3591)

A high-severity stack use-after-return vulnerability in SIG(0) handling code can allow attackers to manipulate memory structures and bypass access control lists. The flaw affects systems relying on DNSSEC SIG(0) for authentication of DNS updates. Exploitation could allow unauthorised zone modifications.

> **SOC Action:** Identify all BIND/named instances using SIG(0) authenticated updates. Apply vendor patches immediately. Monitor DNS update logs for anomalous zone modification attempts from untrusted sources.

### 3.5 CVE-2026-3098 — Smart Slider 3 WordPress Plugin Arbitrary File Read (500K+ Sites)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/file-read-flaw-in-smart-slider-plugin-impacts-500k-wordpress-sites/)

A file-read vulnerability in Smart Slider 3 (all versions through 3.5.1.33) allows subscriber-level authenticated users to read arbitrary server files including `wp-config.php` via the `actionExportAll` AJAX function, which lacks capability checks and file-type validation. Discovered by Dmitrii Ignatyev and validated by Defiant (Wordfence), the flaw was patched in version 3.5.1.34 on 24 March 2026. WordPress.org download stats indicate over 500,000 sites remain on vulnerable versions. Not flagged as actively exploited yet.

> **SOC Action:** Audit all WordPress installations for Smart Slider 3 versions below 3.5.1.34 and update immediately. Review subscriber-level accounts for unusual export or AJAX activity. Check web server logs for requests to `admin-ajax.php` with `action=smartslider` parameters from low-privilege sessions.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased targeting of critical infrastructure and supply chains | Backdoored Telnyx PyPI package (WAV-hidden malware); AI Infrastructure Supply Chain Poisoning Alert |
| 🟠 **HIGH** | Ransomware surge across healthcare, energy, and manufacturing with overlapping TTPs | Nightspire x4, INC Ransom (Greenology), Orion (Pastas Allegri), Exitium (Ming Hwei Energy) |
| 🟡 **MEDIUM** | Phishing (T1566) as common initial access across multiple threat actors | Exitium, Nightspire, INC Ransom, Orion, Qilin — 11 correlated reports |
| 🟡 **MEDIUM** | Multiple vulnerabilities in widely used software libraries | CVE-2026-4833 (Markdown), CVE-2026-33672 & CVE-2026-33671 (Picomatch), CVE-2026-33636 & CVE-2026-33416 (LIBPNG) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (24 reports) — RaaS operation (aka Agenda) targeting healthcare and professional services globally
- **Nightspire** (17 reports) — High-tempo ransomware group with 6 affiliates, focused on healthcare and energy in US/Europe
- **TeamPCP** (17 reports) — Active threat group; last seen 2026-03-28
- **Akira** (12 reports) — Established ransomware operation with consistent victim posting
- **Handala** (10 reports) — Hacktivist/threat actor with geopolitical motivations
- **ShinyHunters** (7 reports) — Data breach specialists; recent European Commission breach reported
- **DragonForce** (5 reports) — Ransomware group active in late March surge
- **INC Ransom** (5 reports) — Long-running RaaS with 715 total victim posts

### Malware Families

- **Akira ransomware** (9 reports) — Persistent ransomware family with double extortion
- **DragonForce ransomware** (5 reports) — Associated with DragonForce threat actor
- **CanisterWorm** (5 reports) — Malware family observed 20–24 March
- **Qilin ransomware** (4 reports) — RaaS payload deployed by Qilin/Agenda group
- **Vidar** (4 reports) — Information-stealing malware, often precursor to ransomware
- **Babuk-Bjorka** (1 report) — Possible links to Orion ransomware operations
- **Orion ransomware** (1 report) — Emerging variant with Babuk-Bjorka connections

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 16 | [link](https://msrc.microsoft.com/update-guide) | CVE advisories: DNSSEC flaws, LIBPNG, Picomatch, Flannel RCE, python-ecdsa DoS |
| RansomLock | 10 | [link](https://www.ransomlook.io) | Ransomware leak-site monitoring: exitium, nightspire, qilin, inc ransom, orion |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com) | Smart Slider 3 WordPress plugin CVE-2026-3098 coverage |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Organisations running BIND/named with SIG(0) authenticated updates should patch CVE-2026-3591 to prevent ACL bypass. Verify DNSSEC configurations are not exposed to untrusted update sources.

- 🔴 **IMMEDIATE:** WordPress administrators should update Smart Slider 3 to version 3.5.1.34 or later. Audit subscriber-level accounts and review `admin-ajax.php` logs for file-export abuse patterns (CVE-2026-3098).

- 🟠 **SHORT-TERM:** Healthcare organisations targeted by nightspire and qilin should validate backup isolation, test restore procedures, and ensure patient-records databases are segmented from internet-facing systems. Block known Tor C2 domains at network perimeter.

- 🟠 **SHORT-TERM:** Review DLP policies for bulk data exfiltration thresholds. Exitium's 278 GB and 400 GB exfiltration events suggest either no DLP alerting or insufficient egress monitoring at victim organisations.

- 🟡 **AWARENESS:** The phishing TTP (T1566) appeared across reports from five separate ransomware groups this period. Reinforce email security controls, enable DMARC enforcement, and update phishing simulation scenarios to reflect current lure themes targeting energy and healthcare sectors.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 27 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
