---
layout: post
title:  "CTI Daily Brief: 2026-07-07 - CISA KEV: Adobe ColdFusion CVE-2026-48282 actively exploited; SCMBANKER banking fraud; Vidar/XMRig malvertising"
date:   2026-07-08 20:15:00 +0000
description: "CISA orders emergency patching of an actively exploited max-severity Adobe ColdFusion RDS flaw (CVE-2026-48282) with a public PoC. Elastic exposes SCMBANKER, an AI-assisted operator-driven banking-fraud toolkit hitting Mexican financial services. Unit 42 details a Vidar stealer / XMRig malvertising campaign. Space Bears and Inc Ransom continue ransomware operations. Accenture confirms 35 GB source-code breach."
category: daily
tags: [cti, daily-brief, space-bears, inc-ransom, scmbanker, vidar-stealer, cve-2026-48282]
classification: TLP:CLEAR
reporting_period: "2026-07-07"
generated: "2026-07-08"
draft: true
severity: critical
report_count: 13
sources:
  - BleepingComputer
  - Elastic Security Labs
  - Unit42
  - RansomLock
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-07 (24h) | TLP:CLEAR | 2026-07-08 |

## 1. Executive Summary

Thirteen reports were processed across the last 24 hours from six sources, dominated by a critical Adobe ColdFusion vulnerability and continued ransomware ecosystem activity. CISA has directed federal agencies to patch a maximum-severity, actively exploited flaw in Adobe ColdFusion by Friday, and a public proof-of-concept for CVE-2026-48282 targeting the ColdFusion Remote Development Service (RDS) has surfaced on Telegram, sharply raising the risk of opportunistic exploitation. Elastic Security Labs disclosed REF6045, an operator-in-the-loop Mexican banking-fraud toolkit called SCMBANKER delivered via ClickFix fake-CAPTCHA lures with AI-assisted script development. Unit 42 detailed a Vidar Stealer and XMRig malvertising campaign abusing code signing and Go-based Factory-v3 loaders to target U.S. and EU victims. Ransomware activity remains steady with Space Bears posting five new victims across manufacturing, real estate, propane, and hospitality management, Inc Ransom continuing weekly disclosures, and Accenture confirming a 35 GB source-code data breach.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | Adobe ColdFusion CVE-2026-48282 (CISA KEV, public PoC) |
| 🟠 **HIGH** | 8 | Space Bears / Inc Ransom postings; SCMBANKER; Vidar/XMRig; multiple RansomLock dataleak posts |
| 🟡 **MEDIUM** | 2 | Accenture breach confirmation; Beacon Insurance dataleak |
| 🔵 **INFO** | 1 | SANS ISC Stormcast (daily podcast) |

## 3. Priority Intelligence Items

### 3.1 CISA KEV: Adobe ColdFusion CVE-2026-48282 actively exploited with public PoC

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-coldfusion-flaw-by-friday/), Telegram (channel name redacted)

CISA has issued an emergency directive requiring federal civilian agencies to patch a maximum-severity Adobe ColdFusion vulnerability by Friday, citing active in-the-wild exploitation. The flaw, tracked as CVE-2026-48282, affects the ColdFusion Remote Development Service (RDS) and enables unauthenticated remote code execution against exposed instances. A working proof-of-concept was published to a Telegram channel within the same 24-hour window, materially lowering the barrier to opportunistic mass exploitation. Affected products: Adobe ColdFusion (all supported RDS-enabled deployments). Affected sectors: federal government (in-scope for the CISA directive), plus any enterprise running internet-exposed ColdFusion — historically finance, healthcare, higher education, and legacy web-application estates.

> **SOC Action:** Immediately inventory all ColdFusion instances (internal and internet-facing) via authenticated scans and CMDB reconciliation. Apply Adobe's out-of-band patch for CVE-2026-48282 today. Where patching cannot occur inside the CISA window, disable the RDS service (`cfusion/lib/neo-rds.xml`) and block inbound TCP to the RDS port at the perimeter. Hunt for post-exploitation: `cfexecute`, unexpected `cfusion` service process trees, new .cfm/.jsp files under webroots (`/wwwroot/`, `/CFIDE/`), and outbound connections from ColdFusion hosts to non-corporate infrastructure over the last 14 days. Map to MITRE T1190 (Exploit Public-Facing Application) and T1505.003 (Web Shell).

### 3.2 SCMBANKER — AI-assisted operator-driven Mexican banking fraud (REF6045)

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/mexican-banking-fraud-scmbanker-ref6045)

Elastic Security Labs is tracking REF6045, an active operator-assisted banking fraud operation targeting customers of Mexican retail and business banks, fintechs, payment processors, cryptocurrency exchanges, investment platforms, the SAT tax authority, and telecoms. Victims are lured via ClickFix fake-CAPTCHA pages (branded "Google Verificación Segura") that copy a `bitsadmin` command to the clipboard and instruct the user to paste it into the Windows Run dialog, staging a PowerShell toolkit dubbed SCMBANKER. Once installed, a live operator can monitor banking sessions, overlay fake bank warnings, drive vishing follow-up, redirect the browser, swap clipboard-copied account numbers, and deploy Remote Utilities for full takeover. Elastic notes the scripts show heavy LLM-generated artefacts, indicating operator use of AI to write most of the tooling. OPSEC failures — open directories, a leaked web-root archive (`zkt.zip`), and an unauthenticated file editor — exposed the operation's infrastructure and targeting logic.

#### Indicators of Compromise

```
C2 host:      68.211.161[.]46
Toolkit path: hxxp[:]//68.211.161[.]46/files/
Validation:   hxxp[:]//68.211.161[.]46/validation.txt
ClickFix:     hxxps[:]//ratonvaquero2026[.]online/
ClickFix:     hxxps[:]//monteviral2026.duckdns[.]org/
Tracking:     hxxps[:]//ww.ssinvestigaciones[.]com/login3.php
C2 (PS1):     hxxps[:]//negratomasa2026[.]online/dashboard2/recData.php
Toolkit:      SCMBANKER (PowerShell), archive zkt.zip
Lure text:    "Google Verificación Segura (Version 2025.5755)"
```

> **SOC Action:** Block the listed C2 hosts and DuckDNS subdomains at the proxy and DNS layers. In EDR, hunt for `bitsadmin.exe /transfer` invocations sourced from `explorer.exe` or Run-dialog parent chains, and for PowerShell child processes of `cmd.exe` executing content piped from `curl`/`bitsadmin`. Alert on process trees where `powershell.exe` spawns `RUtServ.exe` or other Remote Utilities binaries. Educate users — especially in Mexico/LATAM banking customer estates — on the ClickFix "paste into Run" lure. Map to MITRE T1566 (Phishing), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), and T1219 (Remote Access Software).

### 3.3 Vidar Stealer + XMRig malvertising campaign abuses code signing and Go loaders

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)

Unit 42 identified a financially motivated malvertising campaign spiking mid-to-late April 2026 that delivers Vidar Stealer and the XMRig Monero miner to consumer and SMB victims in the U.S. and EU. Loaders are distributed as password-protected `.bin` archives that impersonate cracked commercial software, a design choice to bypass e-mail-gateway scanning and sandbox detonation. Extracted binaries are code-signed under the false subject `CN=justwatch[.]com`, granting an initial appearance of legitimacy. All 43 samples analysed use the Go-based Factory-v3 (aka UpdateFactory) builder framework, with distinctive PDB paths of the form `C:\Users\Administrator\Desktop\UpdateFactory\compiler\1.25.9\go\src\runtime\cgo`. The operator is assessed to be a Vidar MaaS affiliate. Vidar targets browser credentials, cookies, and cryptocurrency wallets; XMRig conducts Monero mining for direct monetisation.

> **SOC Action:** Block downloads of password-protected archives with `.bin` extensions at the web proxy where policy allows. Add detections for the fake signing subject `CN=justwatch[.]com` and for Factory-v3 PDB path artefacts in Sigma/YARA. Search EDR for unsigned or falsely-signed child processes of browsers writing to `%TEMP%` and immediately spawning long-running miner-style workloads (sustained CPU >70%, connections to Monero pools). Remind users that "cracked software" downloads remain a top infostealer vector. Map to MITRE T1566 (Phishing / Malvertising), T1553.002 (Code Signing), T1055 (Process Injection), and T1496 (Resource Hijacking).

### 3.4 Space Bears ransomware — five new victims across five sectors

**Source:** Telegram (channel name redacted) via [RansomLook](https://www.ransomlook.io//group/space%20bears)

The Space Bears ransomware group posted its latest victim, BiesSse (technical adhesive tapes, ~40-year manufacturer with subsidiaries in Austria, Brazil, China, and Mexico), on 2026-07-08, alongside a rolling seven-day list including Fitcrunch (protein food products), Blenheim (UK luxury residential real estate — 500 GB claimed), Salter's Propane (U.S. propane services), and Chebib Control (Brazilian hospitality PMS with >1,000 active clients). Data types advertised include employee and client PII, financial records, CRM databases, and — in Blenheim's case — CAD/BIM architectural drawings and complete buyer/home-layout details. Leak-site uptime is 93% over the last 30 days, indicating a stable operation.

> **SOC Action:** Add BiesSse, Fitcrunch, Blenheim, Salter's Propane, and Chebib Control to third-party risk registers; if any are current suppliers, initiate contact and treat any credentials, contracts, or documents held with those parties as potentially exposed. For SOCs in manufacturing, hospitality PMS, and real-estate/property-development verticals, tune detections for Space Bears TTPs — initial access via phishing and valid accounts, data staging in cloud storage, and long-dwell exfiltration before encryption. Map to MITRE T1486 (Data Encrypted for Impact) and T1567 (Exfiltration Over Web Service).

### 3.5 Inc Ransom continues weekly disclosures; Aesthetic Surgical Images added

**Source:** [RansomLook](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom posted Aesthetic Surgical Images (U.S. cosmetic-surgery imaging) on 2026-07-07 alongside `tecnocurva.com.br` and `samberger24.de`. The group's tracked leak-site infrastructure remains partially degraded (3 of 10 URLs up) but the primary payment/chat onion at `incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion` shows 100% uptime, and the group has now posted 836 total victims with 33 in the last 30 days. Recent victims span healthcare (surgical imaging, ophthalmology, occupational medicine), U.S. municipal government (`oakparkmi.gov`, `acworth-ga.gov`), legal services, and manufacturing — a broad opportunistic targeting pattern consistent with affiliate-driven ransomware.

> **SOC Action:** Healthcare, U.S. local-government, and law-firm SOCs should assume Inc Ransom is actively hunting their sector and revalidate MFA on all remote access, ensure EDR is enforced on all endpoints (including MSP-managed subsets), and confirm offline backup restore tests within the last 90 days. Add the `INC-README*.txt/.html` filename artefacts as file-write detections in EDR. Map to MITRE T1486 (Data Encrypted for Impact) and T1567.002 (Exfiltration to Cloud Storage).

### 3.6 Accenture confirms 35 GB source-code breach

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/accenture-confirms-breach-after-hacker-offers-stolen-data-for-sale/)

Accenture confirmed a security breach after a threat actor advertised 35 GB of stolen data — described as including source code — for sale. The source does not name the threat actor or attribution at this stage; treat as unconfirmed until Accenture publishes further detail.

> **SOC Action:** Organisations with Accenture consulting or managed-services engagements should proactively contact their account team for scope confirmation, rotate any shared credentials, API keys, or SSO federations, and audit privileged access previously granted to Accenture personnel or tooling. Treat any leaked source code as a potential source of hard-coded secrets and internal API knowledge if your organisation is downstream.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software and hardware, posing significant risks to global IT infrastructure | Januscape Linux flaw (VM escape on Intel/AMD); CVE-2026-10536 HTTP/2 stream-dependency UAF (from prior batch, still trending) |
| 🟠 **HIGH** | Increased ransomware activity targeting critical infrastructure and manufacturing sectors | United Infrastructure (Play); RISE Architecture (Akira); Excalibur Rentals (Akira); Siemens SINEC OS and Mendix Studio Pro advisories |
| 🟠 **HIGH** | Growing use of phishing as a primary attack vector across ransomware campaigns | Preneed Funeral Programs (Play); Chisholm Persson & Ball (Akira); Excalibur Rentals (Akira); this cycle's SCMBANKER ClickFix delivery |

The 2026-07-08 correlation batch's landscape summary explicitly ties this cycle's activity to the ColdFusion critical vulnerability, ClickFix-delivered phishing (SCMBANKER), and continued RansomLock-family posting activity across food & beverage, insurance, and manufacturing.

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (98 reports) — high-tempo ransomware operator, active through 2026-07-06.
- **Qilin** (77 reports) — sustained ransomware activity, most recent post 2026-07-07.
- **Deadlock** (55 reports) — active mid-June, no fresh activity this cycle.
- **Lockbit5** (39 reports) — continued postings across the reporting period.
- **Akira** (28 reports) — cited in today's correlation trends (RISE Architecture, Excalibur Rentals).
- **DragonForce** (26 reports) — continued victim postings, most recent 2026-07-07.
- **ShinyHunters / Shinyhunters** (39 combined) — ongoing extortion and data-theft activity.
- **Space Bears** (this cycle) — five new victims across manufacturing, real estate, propane, hospitality.
- **Inc Ransom** (this cycle) — ongoing weekly disclosures, 836 total victims tracked.

### Malware Families

- **RansomLook** (153 reports) — parser/leak-site tracker entity dominating pipeline mentions.
- **Tox1 / Tox** (112 combined) — persistent tooling references across ransomware ecosystem coverage.
- **Lockbit5** (14 reports) — encryptor references in leak-site postings.
- **Akira ransomware** (13 reports) — actively used against manufacturing and architecture verticals.
- **The Gentlemen ransomware** (11 reports) — high-tempo operations.
- **Anubis ransomware / banking trojan** (21 combined) — dual-purpose family, sustained mentions.
- **SCMBANKER** (this cycle, new) — Elastic-named AI-assisted banking-fraud PowerShell toolkit.
- **Vidar Stealer** (this cycle) — MaaS infostealer paired with XMRig in April 2026 malvertising campaign.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 7 | [link](https://www.ransomlook.io/) | Space Bears, Inc Ransom, and dataleak-parser posts across manufacturing, insurance, food & beverage |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-coldfusion-flaw-by-friday/) | Primary coverage of the CISA ColdFusion emergency directive and Accenture breach confirmation |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/) | Vidar Stealer / XMRig malvertising campaign technical analysis |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/mexican-banking-fraud-scmbanker-ref6045) | SCMBANKER / REF6045 Mexican banking-fraud toolkit exposure |
| SANS | 1 | [link](https://isc.sans.edu/) | Daily ISC Stormcast podcast (informational) |
| Unknown (Telegram) | 1 | — | CVE-2026-48282 ColdFusion RDS PoC published on Telegram (channel URL suppressed) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch or fully mitigate Adobe ColdFusion CVE-2026-48282 today. Federal agencies are on a Friday deadline; private sector should treat the same window as binding given the public Telegram PoC and confirmed in-the-wild exploitation. Disable RDS and block inbound to the RDS port as a compensating control if patching is delayed.
- 🔴 **IMMEDIATE:** Push detections for the SCMBANKER ClickFix chain — `bitsadmin` invocations from user-context Run-dialog activity, PowerShell descending from `cmd.exe` with piped remote content, and Remote Utilities (`RUtServ.exe`) executions. Block the IOCs listed in section 3.2 at proxy and DNS.
- 🟠 **SHORT-TERM:** Add YARA/Sigma coverage for Factory-v3/UpdateFactory Go loader PDB paths and the false `CN=justwatch[.]com` signing subject; audit SIEM for `.bin` password-protected archive downloads to catch Vidar/XMRig deliveries.
- 🟠 **SHORT-TERM:** Third-party risk teams — cross-reference today's Space Bears (BiesSse, Fitcrunch, Blenheim, Salter's Propane, Chebib Control) and Inc Ransom (Aesthetic Surgical Images plus healthcare/muni-gov cluster) victims against active supplier and partner lists; assume any shared credentials or documents are exposed.
- 🟡 **AWARENESS:** Brief incident response and privileged-access-management teams on the Accenture 35 GB breach; rotate any credentials, tokens, or federations shared with Accenture consulting engagements and monitor for downstream targeting.
- 🟢 **STRATEGIC:** ClickFix and AI-assisted operator-in-the-loop fraud (SCMBANKER) mark a durable shift in social-engineering — invest in user education specifically covering the "paste this into Run" lure pattern and expand DFIR playbooks to include LLM-generated malware artefact triage.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 13 reports processed across 1 correlation batch (batch 217, 2026-07-08). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
