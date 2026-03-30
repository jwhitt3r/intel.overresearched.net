---
layout: post
title: "CTI Daily Brief: 2026-03-29 — Active Exploitation of Citrix, F5, and Fortinet Flaws; PLAY and Qilin Ransomware Surge; TeamPCP Supply Chain Campaign Escalates"
date: 2026-03-30 20:05:40 +0000
description: "Three critical network appliance vulnerabilities under active exploitation (CVE-2026-3055, CVE-2025-53521, CVE-2026-21643), PLAY ransomware claims 10 new victims across multiple sectors, Qilin RaaS operations expand, TeamPCP supply chain campaign linked to Databricks investigation, and ShinyHunters breach European Commission cloud infrastructure."
category: daily
tags: [cti, daily-brief, teampcp, play, qilin, shinyhunters, cve-2026-3055, cve-2025-53521, cve-2026-21643, eviltokens, handala, akira]
classification: TLP:CLEAR
reporting_period: "2026-03-29"
generated: "2026-03-30"
draft: true
severity: critical
report_count: 51
sources:
  - BleepingComputer
  - SANS
  - RecordedFutures
  - RansomLock
  - AlienVault
  - Sekoia
  - Wiz
  - BellingCat
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-29 (24h) | TLP:CLEAR | 2026-03-30 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 51 reports from 10 sources over the past 24 hours, with 11 rated critical and 26 rated high — an unusually elevated severity profile driven by concurrent active exploitation of three enterprise network appliance vulnerabilities and a major ransomware surge. The dominant theme is active exploitation of perimeter devices: Citrix NetScaler (CVE-2026-3055), F5 BIG-IP APM (CVE-2025-53521, added to CISA KEV), and Fortinet FortiClient EMS (CVE-2026-21643) all confirmed exploited in the wild with public proof-of-concept activity. PLAY ransomware (Hive-affiliated) claimed 10 new victims in a single day across construction, manufacturing, financial services, and critical infrastructure sectors. The TeamPCP supply chain campaign escalated with dual ransomware operations (CipherForce and Vect) and a suspected Databricks compromise under investigation. ShinyHunters confirmed a 350GB+ breach of European Commission cloud infrastructure via compromised AWS accounts.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 11 | Citrix NetScaler CVE-2026-3055; F5 BIG-IP CVE-2025-53521; Fortinet EMS CVE-2026-21643; Akira, Coinbase Cartel, Morpheus, DragonForce ransomware; Dubai Airport data leak |
| 🟠 **HIGH** | 26 | PLAY ransomware (10 victims); Qilin RaaS (6 victims); TeamPCP supply chain update; EvilTokens PhaaS; EU Commission breach; FBI Director email hack; tax season scam campaigns |
| 🟡 **MEDIUM** | 7 | Apple ClickFix mitigation; CareCloud healthcare breach; Intesa Sanpaolo GDPR fine; Microsoft KB5079391 pulled; Wiz Blue Agent launch |
| 🟢 **LOW** | 2 | Gartner AI SOC evaluation framework; SANS Stormcast |
| 🔵 **INFO** | 5 | DShield honeypot analysis; Bellingcat misinformation guide; Schneier camera indicator discussion |

## 3. Priority Intelligence Items

### 3.1 Three Critical Network Appliance Vulnerabilities Under Active Exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-citrix-netscaler-memory-flaw-actively-exploited-in-attacks/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-now-exploit-critical-f5-big-ip-flaw-in-attacks-patch-now/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-fortinet-forticlient-ems-flaw-now-exploited-in-attacks/)

Three separate critical vulnerabilities in widely deployed enterprise perimeter appliances confirmed active in-the-wild exploitation within the same 24-hour window:

**CVE-2026-3055 — Citrix NetScaler ADC/Gateway Memory Overread.** watchTowr confirmed exploitation from known threat actor IPs since March 27. The flaw affects SAML and WS-Federation authentication endpoints (`/saml/login`, `/wsfed/passive`), enabling extraction of administrative session IDs and potential full appliance takeover. Shadowserver tracks 29,000 NetScaler and 2,250 Gateway instances exposed online. The vulnerability resembles the previously exploited CitrixBleed and CitrixBleed2 flaws from 2023 and 2025. Affected versions: pre-14.1-60.58, pre-13.1-62.23, and pre-13.1-37.262 when configured as SAML IDP.

**CVE-2025-53521 — F5 BIG-IP APM Remote Code Execution.** F5 reclassified this from a DoS flaw to critical RCE after discovering attackers deploying webshells on unpatched devices. CISA added it to the KEV catalogue and mandated federal agency patching by March 30, 2026. Attackers exploit BIG-IP APM systems with access policies configured on virtual servers — no privileges required. Shadowserver tracks over 240,000 BIG-IP instances exposed online.

**CVE-2026-21643 — Fortinet FortiClient EMS SQL Injection.** Defused reported first exploitation four days prior. Attackers smuggle SQL statements through the `Site` header of HTTP requests to achieve unauthenticated RCE. Approximately 1,000 FortiClient EMS instances are publicly exposed via Shodan, with over 1,400 IPs in the US and Europe. Patch: upgrade to FortiClient EMS 7.4.5+.

> **SOC Action:** Immediately audit all Citrix NetScaler, F5 BIG-IP APM, and Fortinet FortiClient EMS appliances for patch status. For NetScaler, check SAML IDP configurations and review access logs for anomalous requests to `/saml/login` and `/wsfed/passive` endpoints. For BIG-IP, inspect disk, logs, and terminal history for webshell artifacts per F5's published IOCs. For FortiClient EMS, examine HTTP access logs for malformed `Site` headers. Prioritise external-facing instances.

### 3.2 PLAY Ransomware Claims 10 Victims in Single-Day Surge

**Source:** [RansomLock](https://www.ransomlook.io//group/play)

The PLAY ransomware group (affiliated with Hive) posted 10 new victims to its leak site in a single day, targeting organisations across construction (Brokk, Colorado Construction), manufacturing (Valley Plating Inc, Ampex Data Systems), financial services (Weber Kracht & Chellew, Witt UK Group), and other sectors (Kivells, Specflue, Dock Pros, Lucky Look). PLAY employs intermittent encryption to evade detection, leverages Tor hidden services for C2 infrastructure, and uses phishing and compromised RDP credentials for initial access (T1566, T1078). This volume of simultaneous postings suggests either a backlog release or an acceleration in operational tempo.

> **SOC Action:** Hunt for PLAY ransomware indicators including `.play` file extensions, `ReadMe*.txt` ransom notes, and connections to known PLAY .onion C2 domains. Query EDR for intermittent file encryption patterns (partial file modification across many files in rapid succession). Review VPN and RDP access logs for credential anomalies.

### 3.3 TeamPCP Supply Chain Campaign Escalates — Databricks Under Investigation

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/32846)

SANS ISC published Update 004 on the TeamPCP supply chain campaign, revealing two significant developments. First, Databricks is investigating a suspected compromise linked to TeamPCP's 300GB credential trove harvested from compromised CI/CD pipelines (Aqua, Checkmarx, BerriAI, Telnyx). Screenshots show AWS artifacts, CloudFormation dumps, and STS tokens matching TeamPCP's playbook. If confirmed, this would be the first major cloud platform identified as a downstream victim. Second, TeamPCP operates dual ransomware tracks: their proprietary CipherForce operation for high-value targets and a mass Vect affiliate program distributed via BreachForums. TeamPCP operates under five confirmed aliases: PCPcat, ShellForce, DeadCatx3, CipherForce, and Persy_PCP. AstraZeneca data was also released, indicating enterprise credential monetisation is accelerating (T1059, T1027, T1566).

> **SOC Action:** Organisations using Databricks or any TeamPCP-compromised component (Aqua, Checkmarx, BerriAI, Telnyx SDK) should treat CI/CD pipeline credentials as compromised and rotate immediately. Add CipherForce and Vect ransomware families to detection watchlists. Monitor for the shared RSA-4096 public key embedded in TeamPCP payloads.

### 3.4 ShinyHunters Breach European Commission — 350GB+ Exfiltrated via AWS

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/european-commission-confirms-data-breach-after-europaeu-hack/), [Recorded Future News](https://therecord.media/european-commission-downplays-shinyhunters-cyber-claim)

The ShinyHunters extortion group claimed responsibility for breaching the European Commission's Europa.eu web platform, stealing over 350GB of data including mail server dumps, databases, confidential documents, and contracts. The Commission confirmed the breach involved at least one AWS account but stated internal systems were not affected. ShinyHunters published a 90GB+ archive on its dark web leak site. The group's recent campaign has used voice phishing (vishing) targeting SSO accounts at Okta, Microsoft, and Google across 100+ organisations (T1566).

> **SOC Action:** Organisations with European Commission data-sharing relationships should monitor for their data appearing in ShinyHunters' leaked archives. Review AWS account security: enforce MFA on all IAM accounts, audit CloudTrail for anomalous API calls, and restrict SSO token lifetimes. Alert on vishing attempts targeting help desks and IT staff.

### 3.5 EvilTokens: Device Code Phishing-as-a-Service Targeting Microsoft 365

**Source:** [Sekoia](https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1/)

Sekoia TDR uncovered EvilTokens, a new PhaaS kit enabling device code phishing attacks against Microsoft 365 accounts. The kit abuses Microsoft's OAuth 2.0 Device Authorisation Grant flow — victims are tricked into entering a device code on the legitimate Microsoft login page, granting attackers persistent access via refresh tokens. EvilTokens provides built-in webmail interfaces, email harvesting, reconnaissance tools, and AI-powered BEC automation. The kit is sold via Telegram bots and plans to expand to Gmail and Okta. Rapid adoption by cybercriminals specialising in Adversary-in-the-Middle phishing and BEC makes this a significant emerging threat (T1566).

> **SOC Action:** Implement conditional access policies that block or limit device code authentication flows where not operationally required. Monitor Azure AD sign-in logs for `devicecode` grant type authentications from unusual locations. Alert on anomalous refresh token usage patterns indicating stolen persistent access.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks becoming a significant threat vector | TeamPCP supply chain campaign (Databricks investigation, dual ransomware ops); Telnyx Python SDK compromise |
| 🔴 **CRITICAL** | Ransomware operations affecting multiple sectors with overlapping TTPs | INC Ransom targeting Conveyors Inc; DragonForce targeting Alliance Select Foods International |
| 🟠 **HIGH** | Increased ransomware activity targeting critical infrastructure and healthcare | PLAY ransomware: Weber Kracht & Chellew, Kivells, Specflue, Dock Pros |
| 🟠 **HIGH** | RaaS operations expanding with multiple actors | Coinbase Cartel (Efficy 43GB, Verimatrix 43GB, PropSpace CRM); Qilin (Summit Tax Advisory) |
| 🟠 **HIGH** | Phishing targeting government sectors across Europe and the United States | EU Commission breach (ShinyHunters); FBI Director Patel email compromise (Handala) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (30 reports) — Prolific RaaS operator with active .onion C2 infrastructure, Tox/Jabber comms, and FTP-based exfiltration; 6 new victims today
- **TeamPCP** (19 reports) — Supply chain threat actor operating dual ransomware tracks (CipherForce + Vect), leveraging compromised CI/CD pipelines
- **Nightspire** (17 reports) — Ransomware group targeting healthcare and energy sectors across US and Europe; no new victims today
- **Hive/PLAY** (13 reports) — PLAY ransomware variant affiliated with Hive; 10 new victims claimed in single-day surge
- **Akira** (13 reports) — Double-extortion ransomware targeting VMware ESXi and corporate networks; 2 new victims today
- **Handala** (11 reports) — Iranian state-sponsored group (MOIS); linked to FBI Director Patel email hack; $10M US reward reissued
- **ShinyHunters** (9 reports) — Data extortion group; confirmed 350GB+ breach of European Commission AWS infrastructure
- **DragonForce** (6 reports) — RaaS cartel evolved from hacktivism; targeting retail, government, logistics, and manufacturing
- **Coinbase Cartel** (2 reports) — RaaS operator posting 43GB+ data leaks from Efficy and Verimatrix; auctioning PropSpace CRM data

### Malware Families

- **Akira ransomware** (10 reports) — Uses Windows CryptoAPI encryption with `.akira` extensions; targets ESXi and Linux environments
- **PLAY ransomware** (10 reports) — Intermittent encryption variant linked to Hive; Tor-based C2 and phishing delivery
- **DragonForce ransomware** (6 reports) — RaaS with customisable payloads, affiliate portals, and PGP-signed ransom notes
- **CipherForce** (1 report) — TeamPCP's proprietary ransomware; newly identified, seeking affiliates
- **Vect** (1 report) — RaaS used by TeamPCP for mass affiliate distribution via BreachForums
- **EvilTokens** (1 report) — PhaaS kit for Microsoft 365 device code phishing with AI-powered BEC automation
- **Winos4.0 / ValleyRAT** (1 report) — Tax-season themed malware campaigns by TA4922

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 28 | [link](https://www.ransomlook.io) | Primary ransomware leak site monitoring; PLAY, Qilin, Akira, Coinbase Cartel, DragonForce, Morpheus, PEAR, Payload, INC Ransom coverage |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Citrix, F5, Fortinet active exploitation; EU Commission breach; Apple ClickFix; Microsoft KB5079391 |
| RecordedFutures | 5 | [link](https://therecord.media) | Iran Handala reward; Flint24 sentencing; EU Commission; Intesa Sanpaolo fine; CareCloud breach |
| SANS | 4 | [link](https://isc.sans.edu) | TeamPCP Update 004; DShield honeypot analysis; ISC Stormcast |
| Sekoia | 1 | [link](https://blog.sekoia.io) | EvilTokens device code PhaaS deep-dive |
| AlienVault | 1 | [link](https://otx.alienvault.com) | Tax season scam campaigns (TA4922, TA2730, Winos4.0, ValleyRAT) |
| Wiz | 1 | [link](https://www.wiz.io) | Blue Agent GA release |
| BellingCat | 1 | [link](https://www.bellingcat.com) | Explosive misinformation guide |
| Schneier | 1 | — | Apple camera indicator light analysis |
| Unknown | 1 | — | Telegram-sourced ransomware statistics (channel name redacted) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Citrix NetScaler ADC/Gateway (CVE-2026-3055), F5 BIG-IP APM (CVE-2025-53521), and Fortinet FortiClient EMS (CVE-2026-21643) on all external-facing instances. Active exploitation confirmed for all three. Review appliance logs for indicators of prior compromise before patching.

- 🔴 **IMMEDIATE:** Organisations with CI/CD pipelines exposed to TeamPCP-compromised components (Aqua, Checkmarx, BerriAI, Telnyx SDK) should rotate all pipeline credentials and secrets, audit Databricks and cloud platform access for anomalous STS token usage, and add CipherForce/Vect ransomware indicators to detection rules.

- 🟠 **SHORT-TERM:** Implement conditional access policies restricting Microsoft device code authentication flows. Monitor Azure AD for `devicecode` grant type sign-ins and anomalous refresh token reuse to counter the EvilTokens PhaaS kit.

- 🟠 **SHORT-TERM:** Hunt for PLAY ransomware activity — intermittent encryption patterns, `.play` extensions, `ReadMe*.txt` ransom notes, and Tor C2 connections. Review VPN/RDP logs for credential anomalies given the group's 10-victim single-day surge.

- 🟡 **AWARENESS:** Tax-season themed phishing campaigns delivering Winos4.0, ValleyRAT, and RMM payloads are targeting US, Canadian, Australian, Swiss, and Japanese taxpayers. Reinforce user awareness training and tune email gateway rules for tax-related lure themes impersonating government agencies.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 51 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
