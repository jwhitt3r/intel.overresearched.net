---
layout: post
title:  "CTI Daily Brief: 2026-07-22 - The Gentlemen leaks 800GB of Disney family-office data; wp2shell WordPress pre-auth RCE exploited in the wild"
date:   2026-07-23 20:07:51 +0000
description: "The Gentlemen exposes 800GB of Disney/Shamrock family-office records; wp2shell WordPress pre-auth RCE sees active PoC exploitation; Qilin and Nova sustain RaaS leak-site activity; Upbound reports $13M in fraudulent Acima leases."
category: daily
tags: [cti, daily-brief, the-gentlemen, qilin, nova]
classification: TLP:CLEAR
reporting_period: "2026-07-22"
generated: "2026-07-23"
draft: true
report_count: 8
severity: critical
sources:
  - RansomLook
  - BleepingComputer
  - Elastic Security Labs
  - RecordedFutures
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-22 (24h) | TLP:CLEAR | 2026-07-23 |

## 1. Executive Summary

The pipeline processed 8 reports across 5 sources for the period, dominated by ransomware/extortion activity and one actively-exploited web application vulnerability. The headline item is a critical breach by The Gentlemen ransomware group, which published over 800 GB of data from Disney Family / Shamrock Holdings — the Disney family's private investment office — including trust instruments, KYC documents, and financial records for named individuals. In parallel, Elastic Security Labs reported active exploitation of wp2shell, a pre-authentication remote code execution chain in WordPress Core (CVE-2026-63030, CVE-2026-60137), with public proof-of-concept tooling already firing against internet-facing hosts. Ransomware-as-a-Service operators Qilin and Nova (a rebrand of RALord) sustained leak-site activity, and fintech firm Upbound Group disclosed that a data breach was leveraged to create $13 million in fraudulent Acima leases. No new CISA KEV additions appeared among the reports in this period, though correlation analysis continued to flag public-facing application exploitation as a critical trend.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | The Gentlemen — 800GB Disney/Shamrock family-office breach |
| 🟠 **HIGH** | 4 | wp2shell WordPress pre-auth RCE; Qilin & Nova RaaS activity; Upbound $13M fraud |
| 🟡 **MEDIUM** | 1 | Kairos leak-site infrastructure (LR Reed) |
| 🔵 **INFO** | 2 | SANS ISC Stormcast; CISA 2015 info-sharing extension (House NDAA) |

## 3. Priority Intelligence Items

### 3.1 The Gentlemen leaks 800GB of Disney family-office data

**Source:** [RansomLook](https://www.ransomlook.io//group/the%20gentlemen)

The Gentlemen ransomware group published a critical data breach targeting Disney Family / Shamrock Holdings — the private investment firm and family office established by Roy E. Disney, distinct from the public Walt Disney Company. The leaked dataset exceeds 800 GB, spans from the 1980s to June 2026, and is organised across 14 categories including family trusts, tax administration, and private-equity fund management. Named individuals in the exposed records include Abigail Disney, Roy P. Disney, and Stanley Gold, with leaked passports, KYC documents, and trust instruments for the Disney Grandchildren Trusts. The group's own listing states the databases are unencrypted and contain embedded ERP credentials, alongside payroll records, bank reconciliations with CNB, and fund subscription agreements (e.g., Shamrock Israel Growth Fund). The Gentlemen's leak infrastructure remains partially active (one onion site at ~90% 30-day uptime) and uses Tox for communication. Affected sector: financial services / family office.

#### Indicators of Compromise
```
Leak site (onion):  hxxp[://]tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion/
Chat server (onion): hxxp[://]i2ohjeeqe37jre4f2u7pyq73cbm6lecumdxapkvrlryna6rc3it4zsid[.]onion/
Tox ID: F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E
```

> **SOC Action:** If your organisation has any financial or legal relationship with Shamrock Holdings / the Disney family office, assume exposure of shared credentials and rotate any ERP or third-party integration secrets. Hunt for The Gentlemen data-exfiltration TTPs (T1071 — Application Layer Protocol) by reviewing large outbound transfers to unrecognised endpoints over the past 90 days, and alert on the Tox client running in your environment.

### 3.2 wp2shell — WordPress pre-auth RCE under active exploitation

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/wp2shell-wordpress-rce-detection-elastic-defend)

Elastic Security Labs published detection guidance for wp2shell, a pre-authentication remote code execution chain in WordPress Core disclosed by Searchlight Cyber on 17 July 2026 (CVE-2026-63030, CVE-2026-60137). The bug is a route-confusion flaw in the REST batch endpoint (`/wp-json/batch/v1`) that lets nested batch sub-requests reach a pre-auth SQL injection primitive, which is then bridged to administrator access and plugin upload — or used to drop a webshell directly to disk via SQL `INTO OUTFILE`. Public PoCs (Icex0, 0xsha, sergiointel, dinosn) appeared within hours of disclosure, and Elastic reports observing the same host footprint in customer telemetry: PHP/web-server runtimes spawning shells and new plugin directories under `wp-content/plugins/`. Affected versions: WordPress 6.9.0–6.9.4 and 7.0.0–7.0.1 (full RCE chain); 6.8.0–6.8.5 (SQLi only). Fixed in 7.0.2, 6.9.5, and 6.8.6. MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell), T1059 (Command and Scripting Interpreter).

> **SOC Action:** Patch internet-facing WordPress to 7.0.2 / 6.9.5 / 6.8.6 immediately and treat any exposed vulnerable instance as potentially compromised. Hunt access logs for POST requests to `/wp-json/batch/v1` or `/?rest_route=/batch/v1`, and query EDR for web-server or PHP processes (`php-fpm`, `apache2`, `nginx`, `www-data`) spawning shell interpreters. Inspect `wp-content/plugins/` and `wp-content/cache/` for newly-written `.php` files. Rely on behavioural detection over static IOCs — public tooling is being renamed and repackaged.

### 3.3 Qilin and Nova sustain Ransomware-as-a-Service leak-site activity

**Source:** [RansomLook — Qilin](https://www.ransomlook.io//group/qilin), [RansomLook — Nova](https://www.ransomlook.io//group/nova)

Two established RaaS operators posted fresh victims. Qilin (aka Agenda) listed Sunway Berhad and shows heavy volume — 2,014 all-time posts, 103 in the last 30 days — operating a large exfiltration back-end (600+ tracked file servers, mostly currently offline) and using Jabber (`qilin@exploit.im`) and Tox for affiliate communications. Nova, a rebrand of RALord, listed VNSO; it runs a captcha-gated leak portal with PGP-encrypted communications and multiple named affiliates. Both groups exemplify the period's dominant RaaS trend and rely on unencrypted/obfuscated non-C2 protocols for data exfiltration (T1574.001) and web-protocol C2 (T1071.001). Nova's phishing tradecraft (T1566) aligns with the wider correlation trend. Affected sectors: mixed (manufacturing, services); victim details per group listings.

#### Indicators of Compromise
```
Qilin Jabber: qilin[@]exploit[.]im
Qilin Tox: 7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
Qilin file server (down): ftp[://]dataShare:...@85.209.11[.]49
Qilin file server (down): 188.119.66[.]189, 176.113.115[.]97, 185.196.10[.]52
Nova Tox: 8E9A6195A769FE7115F087C61D75CF32874C339B3AB0947D07480C9A8A12DA5009151BE6A51F
Nova Session: 054f55ec93aca9bac362b9d91eff36a7ce451e7caba47c0b2e004ba429f9529c79
Nova leak site (onion): hxxp[://]novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd[.]onion/
Nova contact: Telegram (channel name redacted)
```

> **SOC Action:** Block and alert on Tox, Jabber (XMPP to `exploit.im`), and Session client traffic egressing corporate networks — these are non-business messaging channels favoured by both actors. Add the listed file-server IPs to threat-intel watchlists for outbound-connection alerting. For Qilin/Nova defence, prioritise MFA on all remote access and monitor for valid-account abuse and phishing (T1566) precursors.

### 3.4 Upbound breach fuels $13M in fraudulent Acima leases

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/upbound-says-hack-caused-13-million-in-fraudulent-acima-leases/)

Fintech firm Upbound Group disclosed that threat actors who stole data from its systems used it to fraudulently create approximately $13 million in Acima lease-to-own agreements. The incident illustrates downstream monetisation of a data breach, where stolen customer/identity data is weaponised for automated fraudulent account creation rather than direct extortion. Reported TTPs: T1197 (account access / automation) and T1566 (phishing). Affected sector: financial services / fintech.

> **SOC Action:** For lending or account-origination platforms, deploy velocity checks and anomaly detection on new-application volume, and require step-up verification for high-value lease/credit approvals. Review authentication logs for bulk automated account creation and correlate new accounts against known-breached identity data.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely-used software and protocols | Dnsmasq DNS Remote Heap Buffer Overflow (CVE-2026-2291); Rondo Meets Geoserver |
| 🟠 **HIGH** | Increased use of Ransomware-as-a-Service (RaaS) models by various groups | Sunway Berhad By qilin; VNSO By nova |
| 🟠 **HIGH** | Exploitation of public-facing applications and software components | CISA Adds Two Known Exploited Vulnerabilities to Catalog; wp2shell WordPress pre-auth RCE |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors with sophisticated tactics | P & A Construction By qilin; neopharmlabs.com By chaos; Marpatech By nova |
| 🟠 **HIGH** | Phishing remains a prevalent tactic across multiple campaigns | neopharmlabs.com By chaos; St. Francis Xavier Catholic School System By worldleaks |
| 🟡 **MEDIUM** | Phishing as a common TTP across multiple sectors | Phantom Stealer campaign; VNSO By nova; South Korea diplomat data breach |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (98 reports) — high-volume RaaS operator (aka Agenda); listed Sunway Berhad this period.
- **The Gentlemen** (88 reports) — extortion group behind this period's critical Disney/Shamrock breach.
- **DragonForce** (41 reports) — active ransomware brand; no new victim in this period's reports.
- **Akira** (26 reports) — recurring RaaS actor correlated on valid-accounts and phishing TTPs.
- **Nova** (21 reports) — RaaS rebrand of RALord; listed VNSO this period.
- **Chaos** (12 reports) — ransomware actor prominent in prior-batch correlations (healthcare/logistics).

### Malware Families
- **RansomLook** (125 reports) — leak-site tracking/parser tooling attribution; most-mentioned pipeline-wide.
- **Tox** (26 reports) — encrypted messaging client used by The Gentlemen, Qilin, and Nova for comms.
- **RALord** (13 reports) — precursor brand to Nova; retained in correlation attribution.
- **Chaos Ransomware** (13 reports) — payload family tied to the Chaos actor cluster.
- **Nova** (12 reports) — RaaS payload/brand associated with the Nova group.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 4 | [link](https://www.ransomlook.io) | Leak-site tracking: The Gentlemen (critical), Qilin, Nova, Kairos |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/upbound-says-hack-caused-13-million-in-fraudulent-acima-leases/) | Upbound $13M fraudulent-lease breach |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/wp2shell-wordpress-rce-detection-elastic-defend) | wp2shell WordPress pre-auth RCE detection guidance |
| RecordedFutures | 1 | [link](https://therecord.media/cisa-2015-extension-passes-house-ndaa) | CISA 2015 info-sharing extension passes House NDAA |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33178) | ISC Stormcast, 23 Jul 2026 — threat level green |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all internet-facing WordPress to 7.0.2 / 6.9.5 / 6.8.6 and hunt for wp2shell exploitation (`/wp-json/batch/v1` requests, PHP-spawned shells, new plugin/cache `.php` files). Treat exposed vulnerable instances as compromised until verified (ref. §3.2).
- 🟠 **SHORT-TERM:** Rotate ERP and third-party integration credentials for any entity with a business relationship to Shamrock Holdings / the Disney family office, given the leak of embedded credentials in 800GB of unencrypted data (ref. §3.1).
- 🟠 **SHORT-TERM:** Deploy application-velocity and step-up verification controls on lending/origination platforms to counter automated fraudulent account creation of the type used against Upbound/Acima (ref. §3.4).
- 🟡 **AWARENESS:** Alert on Tox, Jabber/XMPP (`exploit.im`), and Session client traffic egressing the network, and watchlist the Qilin file-server IPs — these span The Gentlemen, Qilin, and Nova operations (ref. §3.1, §3.3).
- 🟢 **STRATEGIC:** Reinforce anti-phishing and MFA posture, which correlation analysis repeatedly flags as the common entry vector across RaaS campaigns (Qilin, Nova, Chaos) this period (ref. §4).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 8 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
