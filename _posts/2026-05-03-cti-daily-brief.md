---
layout: post
title:  "CTI Daily Brief: 2026-05-03 - ShinyHunters multi-sector extortion campaign hits Marcus & Millichap and Instructure"
date:   2026-05-04 20:10:00 +0000
description: "ShinyHunters claims back-to-back data theft from Marcus & Millichap (1.8M accounts) and Instructure/Canvas (~9,000 schools). Inc Ransom adds Wilkem Group to its leak site. No critical-severity reports or new CISA KEV additions in the period."
category: daily
tags: [cti, daily-brief, shinyhunters, inc-ransom, instructure]
classification: TLP:CLEAR
reporting_period: "2026-05-03"
generated: "2026-05-04"
draft: true
severity: high
report_count: 5
sources:
  - HaveIBeenPwned
  - BleepingComputer
  - RansomLook
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-03 (24h) | TLP:CLEAR | 2026-05-04 |

## 1. Executive Summary

The pipeline processed five reports across four sources for the reporting period, with no critical-severity items but a clear high-severity theme: the ShinyHunters extortion gang surfaced two large-scale data-theft incidents within 24 hours, claiming responsibility for breaches at commercial real estate brokerage Marcus & Millichap (1,837,078 accounts) and education-tech provider Instructure, the maker of the Canvas LMS. Both intrusions reportedly leveraged exploitation of public-facing applications (T1190), and the cross-report correlation engine flagged shared actor, TTP, and victim-profile signals at 0.70–0.90 confidence. Separately, Inc Ransom added Wilkem Group to its onion leak site, continuing its run against legal, medical, and manufacturing targets. No CISA KEV additions, nation-state activity, or confirmed in-the-wild zero-day exploitation were reported in the period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None reported in this period |
| 🟠 **HIGH** | 2 | ShinyHunters breaches at Marcus & Millichap and Instructure |
| 🟡 **MEDIUM** | 2 | Inc Ransom new victim listing; Reborn Gaming cPanel/WHM breach |
| 🟢 **LOW** | 0 | None reported |
| 🔵 **INFO** | 1 | SANS ISC Stormcast podcast (May 4) |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters claims 1.8M-account breach at Marcus & Millichap

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/MarcusMillichap)

ShinyHunters has been named as the actor behind an April 2026 intrusion at commercial real estate brokerage Marcus & Millichap. Data subsequently released publicly contains 1,837,078 unique email addresses together with names, phone numbers, employers, job titles, and physical company addresses. Marcus & Millichap's disclosure characterised the exposed material as "company forms, templates, marketing materials, and general contact information," but the public dump indicates broader contact-record exposure. The data was added to Have I Been Pwned on 3 May 2026. The pipeline correlates this incident with the Instructure breach (item 3.2) at 0.90 confidence on shared actor and 0.80 on shared TTPs.

Affected products/sectors: commercial real estate; B2B contact data; sales and marketing pipelines that ingest M&M outreach.

> **SOC Action:** Treat the exposed dataset as a high-quality target list for spearphishing and BEC. Stand up additional authentication friction (step-up MFA, phishing-resistant factors) for any internal sales, brokerage, or finance staff likely to receive M&M-themed outreach. Tune email gateways for new look-alike domains spoofing marcusmillichap[.]com and brokerage-themed lures referencing "company forms" or "marketing materials." If your organisation appears in M&M's CRM, force password resets on shared-credential accounts and warn staff that LinkedIn-grade enrichment of these records is now trivial for the attacker.

### 3.2 Instructure (Canvas LMS) confirms breach; ShinyHunters claims ~9,000 schools impacted

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/instructure-confirms-data-breach-shinyhunters-claims-attack/)

Education-tech provider Instructure confirmed on 3 May 2026 that data was stolen from its Canvas LMS environment. Per Instructure, the exposed information involves user-identifying data (names, email addresses, student ID numbers) and inter-user messages; the company states it has found no evidence that passwords, dates of birth, government identifiers, or financial information were involved, and notes that patches have been deployed, monitoring increased, and application keys rotated (customers must re-authorise API access). ShinyHunters listed Instructure on its leak site, claiming nearly 9,000 schools and "275 million individuals" worth of PII were taken via an exploited vulnerability that has since been patched, alongside an alleged compromise of the company's Salesforce instance. BleepingComputer has not independently verified the actor's broader claims. Tagged TTPs include T1190 (Exploit Public-Facing Application) and T1071.001 (Application Layer Protocol: Web Protocols).

Affected products/sectors: Canvas LMS; K–12, higher education, and corporate learning customers across North America, Europe, and Asia-Pacific.

> **SOC Action:** If your organisation uses Canvas or any Instructure product, rotate all OAuth tokens, integration secrets, and API keys, and require users to re-authorise integrations as Instructure has prompted. Audit Salesforce integrations linked to Instructure for unexpected connected-app installs, refresh-token usage, or new API users created in the last 30 days. For school district SOCs, hunt for anomalous logins to staff and student accounts from non-typical ASNs in the period 1 April – 3 May 2026, and brace for downstream credential-stuffing and student-targeted phishing using leaked names and email/student-ID pairs.

### 3.3 Inc Ransom adds Wilkem Group to leak site; campaign cadence remains steady

**Source:** [RansomLook](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom posted Wilkem Group (wilkemgroup[.]com) to its data-leak infrastructure on 4 May 2026. RansomLook tracking shows 763 all-time posts for the group, 34 in the last 30 days and 11 in the last 7 days, with the operator running multiple Tor onion sites — including one disclosure blog at 100% 30-day uptime and a payment chat server also at 100% uptime — alongside several inactive mirrors. Ransom note artefacts include INC-README, INC-README2, INC-README3, INC-README4 (txt) and INC-README.html. Recent victims span legal, medical, manufacturing, real estate, and local government sectors. The pipeline rates this medium-severity but operationally significant given Inc Ransom's sustained tempo.

Affected products/sectors: legal services, healthcare, manufacturing, education, and small-to-mid local government — Inc Ransom's observed targeting band over the last 30 days.

> **SOC Action:** Search EDR for the filenames `INC-README.txt`, `INC-README.html`, `INC-README2.txt`, `INC-README3.txt`, `INC-README4.txt` written to user profile or share root paths in the last 30 days. Block the active disclosure onion `incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion` and chat onion `incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion` at egress (Tor blocking should be policy regardless). Validate that backups for any matched-sector tenants (legal, medical, manufacturing) are immutable and that domain-admin-tier accounts cannot reach backup management planes from user workstations.

#### Indicators of Compromise

```
Inc Ransom — leak/chat infrastructure (active):
Onion (disclosure): hxxp[:]//incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion/blog/disclosures
Onion (mirror):    hxxp[:]//incbacg6bfwtrlzwdbqc55gsfl763s3twdtwhp27dzuik6s6rwdcityd[.]onion
Onion (chat/pay):  hxxp[:]//incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion/

Ransom-note filenames:
INC-README.txt
INC-README2.txt
INC-README3.txt
INC-README4.txt
INC-README.html

Newly listed victim (Wilkem Group):
Domain: wilkemgroup[.]com
```

### 3.4 Reborn Gaming breach via cPanel/WebHost Manager vulnerability

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/RebornGaming)

A small but operationally relevant data breach at gaming community site Reborn Gaming was disclosed via Have I Been Pwned on 4 May 2026, reporting exposure of 126 accounts including email addresses, IP addresses, and Steam IDs. The breach is attributed to a vulnerability in cPanel and WebHost Manager (WHM) — the same product family that featured prominently in the prior day's "Sorry" mass-exploitation reporting. The dataset was self-submitted to HIBP. While the absolute count is modest, the recurrence of cPanel/WHM as the entry vector across the week is worth tracking.

Affected products/sectors: cPanel/WHM-hosted gaming and community sites; small managed-hosting tenants.

> **SOC Action:** If you operate cPanel/WHM (directly or via a hosted provider), confirm WHM is on the latest patched build, audit `/var/cpanel/users/` and `/var/log/cpanel*` for unfamiliar account creation or token issuance since 1 April 2026, and disable WHM API tokens that have not been used in the last 30 days. For managed-services teams: ensure customer-facing cPanel control panels are not exposed to the internet on default ports without IP allow-listing or WAF coverage.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | ShinyHunters is targeting multiple sectors with similar TTPs (T1190, T1071.001) — one continuous extortion campaign rather than two unrelated breaches. | Marcus & Millichap (commercial real estate); Instructure / Canvas LMS (education) |
| 🟡 **MEDIUM** | Ransomware and data-breach extortion remain the dominant pressure across unrelated sectors in the 24-hour window. | Wilkem Group (Inc Ransom); Reborn Gaming (cPanel/WHM); Marcus & Millichap and Instructure (ShinyHunters) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (82 reports) — most-mentioned RaaS operator across the 30-day pipeline window; not active in today's reports but remains the dominant trending actor.
- **The Gentlemen** (63 reports) — sustained leak-site activity over the last month; quiet today.
- **Coinbase Cartel** (31 reports) — extortion brand active across recent batches.
- **DragonForce** (27 reports) — continues to feature in correlation analysis.
- **ShinyHunters** (21 reports, plus 18 under the alternate-case `Shinyhunters` entry) — promoted into today's high-severity items via the Marcus & Millichap and Instructure listings.
- **Inc Ransom** (17 reports) — newly added Wilkem Group on 4 May; consistent multi-sector cadence.

### Malware Families

- **RansomLook / RansomLock** (53 / 44 reports) — leak-site tracker artefacts that dominate ingest volume; treat as source noise rather than malware. Worth excluding from "malware family" trend treatment in future tuning.
- **RaaS** (23 reports) — generic Ransomware-as-a-Service tag attached to multiple operator reports.
- **Tox1 / Tox** (21 / 13 reports) — communications tooling repeatedly attached to The Gentlemen activity.
- **Qilin ransomware** (11 reports) — payload references continue to track Qilin actor activity above.
- **Gentlemen ransomware** (9 reports) — paired with The Gentlemen actor entries.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| HaveIBeenPwned | 2 | [link](https://haveibeenpwned.com/Breach/MarcusMillichap) | Both high-impact breach disclosures (Marcus & Millichap, Reborn Gaming) |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/instructure-confirms-data-breach-shinyhunters-claims-attack/) | Primary coverage of the Instructure / ShinyHunters incident |
| RansomLook | 1 | [link](https://www.ransomlook.io//group/inc%20ransom) | Leak-site monitoring; Inc Ransom victim addition |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/32946) | ISC Stormcast podcast for 4 May 2026 |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** If your organisation is an Instructure / Canvas customer, follow the vendor's instructions to re-authorise integrations and rotate OAuth tokens and API keys. Audit Salesforce connected apps for new install events given ShinyHunters' Salesforce-compromise claim, and treat student/staff records as exposed for downstream phishing planning. (Item 3.2)
- 🔴 **IMMEDIATE:** Treat the Marcus & Millichap dump as a curated spearphishing target list. Pre-position email-gateway rules for look-alike domains, and warn brokerage, finance, and sales staff who deal with M&M directly that highly tailored outreach is likely in the next 14 days. (Item 3.1)
- 🟠 **SHORT-TERM:** Hunt for Inc Ransom indicators across legal, medical, manufacturing, and education tenants — specifically the INC-README* note filenames written to user profile or file-share roots within the last 30 days, and any outbound DNS or proxy records resolving the listed onion services. (Item 3.3)
- 🟠 **SHORT-TERM:** Re-verify cPanel/WHM patch status and review WHM API-token inventory; the Reborn Gaming breach is the second cPanel/WHM-attributed incident this week and reinforces the prior "Sorry" mass-exploitation trend the pipeline flagged on 2026-05-03. (Item 3.4 + correlation batch 102)
- 🟡 **AWARENESS:** Brief leadership that ShinyHunters' two named victims this cycle span unrelated sectors (commercial real estate and education) but share TTPs (T1190 + T1071.001). Expect further sectoral diversification in the coming days; do not assume any one industry is safe from this actor. (Item 3.1, 3.2, Section 4)
- 🟢 **STRATEGIC:** Continue maturing detections around T1190 (Exploit Public-Facing Application) — the dominant initial-access TTP across both ShinyHunters incidents and the Reborn Gaming breach. Internet-facing attack-surface management, WAF rule currency, and patch-window discipline for edge applications all trace back to this technique.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 5 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
