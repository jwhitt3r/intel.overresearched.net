---
layout: post
title:  "CTI Daily Brief: 2026-07-02 - Pegasus targets EU PEGA Committee MEP, SimpleHelp OIDC bypass PoC, Inc Ransom and Anubis expand government and manufacturing hits"
date:   2026-07-03 20:05:00 +0000
description: "Ten reports processed for the 24-hour period ending 2026-07-03. Citizen Lab confirms Pegasus infections of a former PEGA Committee MEP. A Telegram-leaked PoC for CVE-2026-48558 (SimpleHelp OIDC auth bypass) surfaces. Inc Ransom claims a US municipal .gov, Anubis leaks a Swiss manufacturer. Correlation batch flags rising cloud IAM CVE exploitation as the top critical trend."
category: daily
tags: [cti, daily-brief, pegasus, nso-group, inc-ransom, anubis, cve-2026-48558]
classification: TLP:CLEAR
reporting_period: "2026-07-02"
generated: "2026-07-03"
draft: true
severity: high
report_count: 10
sources:
  - Wired Security
  - RecordedFutures
  - BleepingComputer
  - RansomLook
  - Unit42
  - Telegram
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-02 (24h) | TLP:CLEAR | 2026-07-03 |

## 1. Executive Summary

Ten reports were processed across six sources for the 24-hour window ending 2026-07-03, with five items rated High and no Critical-severity reports at ingestion. The dominant operational story is a Citizen Lab disclosure that Pegasus spyware, developed by NSO Group, infected the iPhone of former MEP Stelios Kouloglou during his tenure on the European Parliament's PEGA Committee investigating commercial spyware misuse — an incident Citizen Lab links, via a shared targeting email, to a wider campaign against Russian and Belarusian dissidents. A Telegram channel published a proof-of-concept and write-up for CVE-2026-48558, an OpenID Connect authentication bypass in SimpleHelp remote support software; the vulnerability enables unauthenticated access via improper token validation. Ransomware leak sites continue to churn: Inc Ransom listed the US municipal domain oakparkmi.gov, and Anubis posted Swiss manufacturer Ferrum AG. The pipeline's overnight correlation batch elevates rising exploitation of cloud IAM vulnerabilities (Azure OpenAI, Microsoft Entra) to a critical-risk trend line. No new CISA KEV additions were captured in this window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None ingested in this period |
| 🟠 **HIGH** | 5 | Pegasus/PEGA Committee (x2); CVE-2026-48558 SimpleHelp OIDC PoC; Inc Ransom oakparkmi.gov; Anubis Ferrum AG |
| 🟡 **MEDIUM** | 1 | Ransomhouse evidence post for Prince George County |
| 🟢 **LOW** | 0 | None |
| 🔵 **INFO** | 4 | UK National Cyber Action Plan delay; Unit42 WebAuthn/RDP research; Anthropic Claude Fable 5 subscription updates (x2) |

## 3. Priority Intelligence Items

### 3.1 Pegasus Spyware Infected PEGA Committee MEP While He Investigated Spyware Abuse

**Source:** [Wired Security](https://www.wired.com/story/eu-politicians-investigated-pegasus-spyware-then-it-ended-up-on-one-of-their-phones/), [Recorded Future News](https://therecord.media/pegasus-spyware-european-parliament-pega-committee-member)

Citizen Lab published forensic findings that the iPhone of Stelios Kouloglou — a Greek MEP from 2015 to 2024 and a member of the European Parliament PEGA Committee probing Pegasus abuse — was infected by NSO Group's Pegasus zero-click spyware in October 2022 and again in March 2023, while the committee was drafting its recommendations. Citizen Lab attributes the intrusion to a Pegasus operator whose infrastructure and targeting email overlap with a separately reported May 2024 campaign against Russian and Belarusian journalists and opposition figures between August 2020 and January 2023; the researchers note only a subset of Pegasus customers hold cross-country licensing, narrowing the attribution pool. Citizen Lab has not publicly named the responsible government; Kouloglou personally believes the Greek government is responsible, while Citizen Lab states it has no evidence supporting that claim — attribution remains hedged. Apple issued three threat notifications to Kouloglou which he says he never saw. Affected sector: European legislative institutions and policy staff; affected products: iOS and Android mobile endpoints.

> **SOC Action:** For any principals (executives, legal, government affairs, board members) who could plausibly attract state-adjacent targeting, enrol devices in Apple Lockdown Mode or the Android equivalent, subscribe to Apple/Google threat notifications and monitor for them in mail-flow rules, and run mobile forensic sweeps (MVT, Citizen Lab-published IOCs) on high-risk handsets. Treat unexplained iMessage/SMS with attachments to high-value targets as MITRE T1566 (Phishing) and quarantine.

### 3.2 CVE-2026-48558 — SimpleHelp OpenID Connect Authentication Bypass (PoC Public)

**Source:** Telegram (channel name redacted)

A Telegram channel published a proof-of-concept and write-up for CVE-2026-48558, an authentication bypass in the OpenID Connect flow of SimpleHelp remote-support software. The report describes improper token validation in the OIDC integration that allows an unauthenticated attacker to bypass SSO and obtain access to the affected system, potentially yielding full control. SimpleHelp is deployed as an internet-facing remote-support server across MSPs and IT departments; historical precedent (CVE-2024-57726/57727/57728 exploitation by DragonForce and Medusa affiliates in 2025) shows SimpleHelp CVEs draw rapid ransomware follow-on. The report is TLP:AMBER+STRICT in the pipeline; SOC teams should treat exposure hunts as time-critical. Associated ATT&CK: T1078.004 – Valid Accounts (External Remote Services).

> **SOC Action:** (1) Inventory internet-exposed SimpleHelp servers (default ports 443/8443) and confirm patch level against vendor advisory; if a fixed build is not yet available, restrict management console to VPN-only or an IP allow-list. (2) Search authentication logs for OIDC callback anomalies — successful sign-ins without corresponding IdP audit events, or tokens issued for sub/iss values inconsistent with your tenant. (3) Alert on child processes of the SimpleHelp service account executing PowerShell, cmd, or RMM tooling (T1059).

### 3.3 Inc Ransom Adds US Municipal Domain oakparkmi.gov to Leak Site

**Source:** [RansomLook / Inc Ransom leak site](https://www.ransomlook.io//group/inc%20ransom)

The Inc Ransom leak-site tracker recorded a new post naming oakparkmi.gov — the official domain of Oak Park, Michigan — alongside a running stream of victims across US municipal, healthcare, legal, and manufacturing sectors (including tricountyhs.org, acworth-ga.gov, and Colorado Rehabilitation and Occupational Medicine listed on 2026-07-02). Inc Ransom continues to publish INC-README.html and .txt ransom notes and maintains partial infrastructure (two active .onion sites out of eight tracked; ~29% average 30-day uptime). Data-leak or extortion posts against `.gov` domains typically indicate confirmed access to internal systems rather than opportunistic doxing. ATT&CK: T1486 – Data Encrypted for Impact, T1071 – Application Layer Protocol: Web Protocols.

> **SOC Action:** State/local government teams: verify whether Oak Park, MI has issued a public breach notification; if you share managed IT providers or software supply chain with Michigan municipalities, hunt for known Inc Ransom TTPs — abuse of SimpleHelp/ScreenConnect, Impacket wmiexec, and mass rundll32-based data staging. Ensure offline, immutable backups exist for AD, GIS, and utility billing systems.

### 3.4 Anubis Ransomware Lists Swiss Manufacturer Ferrum AG

**Source:** [RansomLook / Anubis leak site](https://www.ransomlook.io//group/anubis)

The Anubis RaaS leak site posted Ferrum AG — described as one of the largest family-owned manufacturing businesses in Switzerland — on 2026-07-03, part of a recent surge that also lists Northeast Pediatrics & Adolescent Medicine and Quest Healthcare Solutions from earlier in the week. Anubis pairs credential-theft/banking-trojan capability with ransomware and data exfiltration, historically arriving via phishing (T1566), malicious attachments, and unpatched external-facing services. Leak site remains highly available (100% uptime on primary .onion). ATT&CK: T1486, T1566.

> **SOC Action:** European manufacturing SOCs — treat this as a live regional targeting signal. Prioritise phishing-resistant MFA on VPN and ERP portals, block ISO/IMG/LNK payload delivery through mail gateways, and hunt EDR telemetry for wmic shadowcopy delete, vssadmin delete shadows, and mass file-extension change events. Confirm domain controllers and file servers are inventoried with immutable backup.

### 3.5 Ransomhouse Publishes Evidence Post for Prince George County (Medium)

**Source:** [RansomLook / Ransomhouse leak site](https://www.ransomlook.io//group/ransomhouse)

Ransomhouse posted an "evidence" listing for a Prince George County entity — the group's usual precursor step before full data release. Ransomhouse operates a fragmented .onion estate with mixed availability and continues to leverage Telegram for out-of-band updates. This is a monitoring item pending confirmation of jurisdiction and impact.

> **SOC Action:** US local-government CIRT teams should confirm whether the reference is to Prince George's County, Maryland or Prince George County, Virginia and coordinate with MS-ISAC on IOC sharing. No public IOCs in this post.

## 4. AI-Identified Correlation Trends

Correlation batch 208 (2026-07-03 06:20 UTC) ran across 17 tier-1 reports and produced three trends and six correlation entries.

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Rising exploitation of cloud service (IAM) vulnerabilities across multiple platforms | CVE-2026-45499 (Azure OpenAI Elevation of Privilege); CVE-2026-57100 (Microsoft Entra Provisioning Service Elevation of Privilege) |
| 🟠 **HIGH** | Increased targeting of governmental and political sectors with sophisticated spyware and phishing | Pegasus/PEGA Committee reports (Wired, Recorded Future) |
| 🟠 **HIGH** | Persistent ransomware activity across government, healthcare, and manufacturing | Inc Ransom oakparkmi.gov; Anubis Ferrum AG |

The batch also identified a high-confidence (0.90) campaign correlation grouping both Pegasus reports on shared malware, TTPs (T1566), and European government/politics sectors, and a shared-TTP link between Inc Ransom and Anubis on T1486 (Data Encrypted for Impact).

## 5. Trending Entities (Pipeline-Wide)

Rankings reflect pipeline-wide report counts (30-day window), not only the 24-hour reporting window.

### Threat Actors

- **The Gentlemen** (95 reports) — high-volume ransomware/data-leak group; sustained posting cadence through end of June.
- **Qilin** (78 reports) — RaaS operation; continued cross-sector victim listings.
- **Deadlock** (55 reports) — mid-June surge; concentrated activity window.
- **Lockbit5** (39 reports) — successor branding to LockBit tooling; steady presence.
- **Akira** (30 reports) — persistent RaaS against SMB/mid-market.
- **DragonForce** (26 reports) — active affiliate ecosystem, historical SimpleHelp abuse.
- **ShinyHunters** (22 reports, plus 18 under alternate casing) — data-theft-and-extortion collective; recent Medtronic breach coverage.
- **Inc Ransom**, **Anubis**, **Ransomhouse** — all present in today's reporting window (see Section 3).

### Malware Families

- **Anubis ransomware** (11 reports, last seen 2026-07-03) — active in today's window against Ferrum AG.
- **Anubis banking trojan** (10 reports) — same operator lineage, Android/Windows credential theft.
- **Akira ransomware** (14 reports) — sustained SMB targeting.
- **Lockbit5** (14 reports) — post-takedown LockBit rebrand.
- **Qilin** (12 reports) — payload variant tracking.
- **Pegasus** (2 reports in window) — NSO Group commercial spyware; PEGA Committee incident.
- **Deadlock** (10 reports) — mid-June activity.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 3 | [ransomlook.io](https://www.ransomlook.io/) | Inc Ransom, Anubis, Ransomhouse leak-site tracking |
| BleepingComputer | 2 | [bleepingcomputer.com](https://www.bleepingcomputer.com/) | Anthropic Claude Fable 5 subscription coverage (info-tier) |
| RecordedFutures | 2 | [therecord.media](https://therecord.media/) | Pegasus/PEGA disclosure; UK National Cyber Action Plan delay |
| Unit42 | 1 | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/webauthn-added-to-browser-based-rdp/) | Engineering research on WebAuthn for browser-based RDP |
| Wired Security | 1 | [wired.com/story/eu-politicians-investigated-pegasus-spyware-then-it-ended-up-on-one-of-their-phones](https://www.wired.com/story/eu-politicians-investigated-pegasus-spyware-then-it-ended-up-on-one-of-their-phones/) | Primary Pegasus/PEGA Committee reporting |
| Telegram (channel name redacted) | 1 | — | CVE-2026-48558 PoC; TLP:AMBER+STRICT |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Inventory and restrict internet exposure of SimpleHelp servers ahead of imminent CVE-2026-48558 exploitation. Enforce OIDC callback validation logging; if you cannot patch today, place the console behind VPN or IP allow-list.
- 🔴 **IMMEDIATE:** Cloud identity teams — audit Azure OpenAI and Microsoft Entra Provisioning Service role assignments; watch Entra sign-in logs for anomalous privilege escalation events referenced in trend batch 208 (CVE-2026-45499, CVE-2026-57100).
- 🟠 **SHORT-TERM:** For any executive, legal, or government-affairs principals plausibly of interest to state-linked spyware operators, deploy Lockdown Mode, monitor Apple/Google threat notifications, and run scheduled MVT scans against Citizen Lab-published Pegasus IOCs.
- 🟠 **SHORT-TERM:** US state and local government IT — verify Oak Park, MI incident status via MS-ISAC and hunt for Inc Ransom TTPs (SimpleHelp/ScreenConnect abuse, Impacket, mass shadow-copy deletion) across peer municipalities.
- 🟡 **AWARENESS:** Swiss and DACH-region manufacturing SOCs — Anubis is now confirmed active against a large Swiss manufacturer; brief IR retainers and confirm immutable backup posture for OT-adjacent file shares.
- 🟢 **STRATEGIC:** Track the correlation-batch trend line: cloud IAM CVEs are being surfaced in adjacent reporting windows. Fold Azure/Entra privilege paths into the next quarterly purple-team exercise.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 10 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
