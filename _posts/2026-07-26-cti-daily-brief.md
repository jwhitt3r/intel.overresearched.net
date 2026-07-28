---
layout: post
title:  "CTI Daily Brief: 2026-07-26 - Genesis, Deadlock and DragonForce Drive Multi-Sector Ransomware Extortion; No CVEs or KEV Additions"
date:   2026-07-27 20:08:28 +0000
description: "Fourteen reports across two sources in 24h, overwhelmingly ransomware leak-site activity. Genesis expansion into real estate and healthcare rated critical; Deadlock and DragonForce active across construction, IT and retail. No CVEs, CISA KEV additions, or confirmed in-the-wild exploitation this cycle."
category: daily
tags: [cti, daily-brief, genesis, deadlock, dragonforce]
classification: TLP:CLEAR
reporting_period: "2026-07-26"
generated: "2026-07-27"
report_count: 14
severity: high
draft: true
sources:
  - RansomLook
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-26 (24h) | TLP:CLEAR | 2026-07-27 |

## 1. Executive Summary

The pipeline processed 14 reports across two sources in the last 24 hours, and the picture is almost entirely ransomware leak-site activity: 13 of 14 reports originate from RansomLook dark-web monitoring, with a single SANS ISC informational item making up the remainder. No CVEs, no CISA KEV additions, and no confirmed in-the-wild exploitation appeared in this cycle. The dominant theme is multi-sector double-extortion by four active groups — Genesis, Deadlock, DragonForce, and Inc Ransom — leveraging overlapping TTPs centred on phishing for initial access (T1566) and data encryption for impact (T1485/T1486). The AI correlation engine rated Genesis's continued expansion into real estate and healthcare as a critical-risk trend, driven by six fresh victim listings including Westlake Realty Group and Infinity Pipeline. Deadlock stands out for cross-continental construction and IT-services targeting spanning Thailand, Colombia, Australia, and the UK, while DragonForce added a Thai resort to a leak site tied to earlier attacks on UK retailers M&S, Harrods, and Co-op.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None this period |
| 🟠 **HIGH** | 13 | Genesis (6 victims), Deadlock (4 victims), DragonForce, Inc Ransom leak-site extortion |
| 🟡 **MEDIUM** | 0 | None this period |
| 🟢 **LOW** | 0 | None this period |
| 🔵 **INFO** | 1 | SANS ISC Stormcast daily podcast (no specific threats) |

Note: while no individual report is rated critical severity, the AI correlation engine assigned a **critical risk level** to the Genesis sector-expansion trend (see Section 4).

## 3. Priority Intelligence Items

### 3.1 Genesis Ransomware Expands Across Real Estate, Healthcare, Construction and Finance

**Source:** [RansomLook — Genesis](https://www.ransomlook.io//group/genesis)

Genesis posted six new victims in a single batch (2026-07-27 00:51 UTC): Williams Accounting Professional (CPA firm), JJP Slip Forming Inc., Building Envelope Systems (construction, Plainville MA), Westlake Realty Group (real estate development), Servonix Technologies (IT services), and Infinity Pipeline Inc. (construction). The group operates a financially motivated, no-affiliate model, extracting data and threatening staged publication of a "parsed" folder to dark-web forums and direct notification of victims' customers and suppliers if payment is not made within a set window. Genesis states it hacks charitable, non-profit, and medical institutions only where "reputation gaps" exist, and claims to destroy data after payment and avoid re-attacking the same company. Associated TTPs in the report data include T1566 (Phishing), T1485 (Data Encrypted for Impact), and T1496 (Resource Hijacking). The correlation engine rated this multi-sector expansion a **critical-risk trend**.

#### Indicators of Compromise
```
Leak site (Tor): hxxp[:]//genesis6ixpb5mcy4kudybtw5op2wqlrkocfogbnenz3c647ibqixiad[.]onion/
Contact email:   genesis.info[@]onionmail[.]org
```

> **SOC Action:** Query EDR and mail gateways for phishing-lure delivery to finance, real-estate, and construction business units (T1566). Block and alert on outbound connections to OnionMail infrastructure and Tor exit nodes from corporate endpoints. For any organisation matching the victim profiles, hunt for mass-file modification and staged archive creation (folders named "parsed") consistent with pre-encryption data staging (T1485).

### 3.2 Deadlock Targets Construction and IT Services Across Four Continents

**Source:** [RansomLook — Deadlock](https://www.ransomlook.io//group/deadlock)

Deadlock listed four victims in the reporting window: Tesco Engineer Co. (Thai civil-engineering and pipe manufacturer), Hardware Asesorías Software Ltda (Colombian hardware/software distributor and Apple/Adobe/HP partner), High Class Car Limo (NYC non-emergency medical transport), and West African Resources Ltd (ASX-listed gold miner operating in Burkina Faso). The group's tradecraft, per report data, uses phishing for initial access (T1566, T1204 User Execution) followed by exfiltration and AES-256 (CBC) file encryption with a per-victim key wrapped under an RSA-2048 public key (T1485/T1486). Deadlock maintains both a clearnet and a Tor leak blog with high uptime (2/2 mirrors up, 89% avg 30-day uptime), indicating stable, actively managed infrastructure. Earlier listings show a >150 GB internal-email theft from Italian asset manager WIBEATS S.r.l., underscoring the group's data-exfiltration leverage.

#### Indicators of Compromise
```
Leak blog (clearnet): hxxps[:]//deadlock[.]liveblog365[.]com/
Leak blog (Tor):      hxxp[:]//deadblogdbdu5wprek7wa2o4ce7rnt6u6ntqeud3hzjjcveosgpsqqqd[.]onion/
Session ID:           05b0c8da191a5b3c41105fa034a31784c6d595c49655f232e10e06277ee145c07c
Session ID:           05084f9b14b02f4ffa97795a60ab1fafaf5128e3259c75459aaaeaebc80c14da78
```

> **SOC Action:** Alert on the clearnet leak domain above at the web proxy and DNS layers to catch any employee or IR-team access that could tip attacker awareness. Hunt for AES/RSA key-generation and bulk-encryption behaviour and for large outbound transfers to file-sharing or Tor destinations preceding encryption (T1486). Reinforce phishing controls and user-execution blocking (T1204) for construction, mining, and IT-services staff.

### 3.3 DragonForce RaaS Lists Thai Resort; Cartel-Model Infrastructure Persists

**Source:** [RansomLook — DragonForce](https://www.ransomlook.io//group/dragonforce)

DragonForce added Katathani Phuket Beach Resort to its leak site (2026-07-27 07:46 UTC). DragonForce is a cartel-style RaaS, first identified in late 2023, that pivoted from hacktivism to financially motivated operations by early 2024 and supplies affiliates with customisable payloads, an affiliate portal, and shared leak-site infrastructure under flexible branding. Public reporting links the group to attacks on UK retailers M&S, Harrods, and Co-op, plus government, logistics, and manufacturing targets. Infrastructure health is degraded (3/20 mirrors up, ~13% avg 30-day uptime), but the primary blog and chat/admin servers remain reachable, and the group logged 43 posts in the last 30 days. Attribution to any single affiliate for the Katathani listing is unconfirmed.

#### Indicators of Compromise
```
Leak blog (Tor):   hxxp[:]//z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid[.]onion/blog
File server (Tor): hxxp[:]//dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd[.]onion
Chat server (Tor): hxxp[:]//3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd[.]onion/login
Ransom notes:      readme.txt, [rand].README.txt
```

> **SOC Action:** For retail, hospitality, and logistics organisations, prioritise MFA on remote-access and identity infrastructure — DragonForce affiliates favour help-desk social engineering and valid-account abuse. Block the listed Tor infrastructure at egress and alert on creation of ransom-note filenames (`readme.txt`, `*.README.txt`) across file servers.

### 3.4 Inc Ransom Continues Extortion Despite Degraded Infrastructure

**Source:** [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom listed victim `takethehop[.]com` (2026-07-27 03:48 UTC), continuing a high-volume campaign (853 all-time posts, 31 in the last 30 days) that has recently hit healthcare, legal, government (`.gov`), and manufacturing targets. Group infrastructure is heavily degraded (2/10 mirrors up, ~24% avg 30-day uptime), with several disclosure and payment portals offline, but two Tor blog mirrors remain reachable. No specific TTPs were enumerated in this report beyond the leak-site listing.

#### Indicators of Compromise
```
Leak blog (Tor):    hxxp[:]//incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion/blog/disclosures
Backend (Tor):      hxxp[:]//incbacg6bfwtrlzwdbqc55gsfl763s3twdtwhp27dzuik6s6rwdcityd[.]onion
Ransom notes:       INC-README.html, INC-README.txt, INC-README2/3/4.txt
```

> **SOC Action:** Hunt for the `INC-README` ransom-note family across file shares and endpoints. For healthcare, legal, and public-sector organisations, review external-facing service exposure and validate offline, tested backups given Inc Ransom's sustained targeting of these sectors.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Genesis group's focus on diverse sectors including real estate and healthcare | Westlake Realty Group; Williams Accounting Professional; Infinity Pipeline Inc. |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with overlapping TTPs and actors | Tesco Engineer (Deadlock); Hardware Asesorías Software (Deadlock); Westlake Realty Group (Genesis) |

Batch 252 (2026-07-27 06:25 UTC) processed 14 tier-1 reports and produced five actor/sector correlation entries at 0.80–0.90 confidence. The highest-confidence links (0.90) tie Deadlock victims together via shared actor + T1486, and Genesis victims via shared actor + T1204 (User Execution) and T1485. A sector correlation (0.80) links two Genesis victims through healthcare targeting.

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (116 reports) — highest-volume RaaS in the pipeline; last seen 2026-07-26
- **The Gentlemen** (102 reports) — sustained high-volume leak-site activity
- **DragonForce** (44 reports) — active this cycle; cartel-model RaaS, last seen 2026-07-27
- **Akira** (22 reports) — persistent multi-sector RaaS
- **Deadlock** (16 reports) — active this cycle; construction/IT-services focus, last seen 2026-07-27
- **Genesis** (16 reports) — active this cycle; critical-rated sector expansion, last seen 2026-07-27
- **Inc Ransom** (14 reports) — active this cycle; high-volume, degraded infrastructure

### Malware Families
- **RansomLook** (144 reports) — leak-site monitoring source tag dominating pipeline volume
- **DragonForce ransomware** (15 reports) — active this cycle
- **RALord** (14 reports) — recurring RaaS payload
- **Chaos Ransomware** (13 reports) — sustained activity
- **The Gentlemen ransomware** (12 reports) — recurring payload

*Note: Trending vulnerability data returned only stale entries (all first/last seen 2026-06-30 to 2026-07-07, single mention each) with no linkage to this period's reports. No CVE was material to the last 24 hours. Trend snapshot data was unavailable for this period.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 13 | [link](https://www.ransomlook.io) | All ransomware leak-site listings (Genesis, Deadlock, DragonForce, Inc Ransom) |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33186) | ISC Stormcast daily podcast; informational, no specific threats |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Treat the Genesis critical-rated trend as an active campaign against real-estate, healthcare, construction, and finance organisations. Hunt for phishing-lure delivery (T1566), staged "parsed" data archives, and connections to the listed OnionMail/Tor infrastructure; validate that tested offline backups exist for these business units (Section 3.1).
- 🟠 **SHORT-TERM:** Block the Deadlock and DragonForce leak-site and clearnet domains at proxy/DNS/egress, and alert on the `INC-README`, `readme.txt`, and `*.README.txt` ransom-note families across file shares (Sections 3.2–3.4). Hunt for bulk AES/RSA encryption behaviour preceded by large outbound transfers (T1486).
- 🟠 **SHORT-TERM:** Reinforce anti-phishing and user-execution controls (T1566/T1204) — the shared initial-access vector across Genesis and Deadlock — with emphasis on construction, IT-services, and finance staff.
- 🟡 **AWARENESS:** Retail, hospitality, and logistics teams should prioritise MFA and help-desk social-engineering defences given DragonForce's affiliate tradecraft and its listing of a hospitality target this cycle (Section 3.3).
- 🟢 **STRATEGIC:** The pipeline is dominated by high-volume RaaS leak-site actors (Qilin, The Gentlemen, DragonForce, Akira). Maintain a standing double-extortion playbook — data-exfiltration detection, immutable backups, and a pre-approved breach-notification workflow — rather than treating each listing as an isolated event.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 14 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
