---
layout: post
title:  "CTI Daily Brief: 2026-04-16 - RedSun Defender Zero-Day Exploited in the Wild; ShinyHunters Dumps 2.1M Amtrak Records"
date:   2026-04-17 20:05:00 +0000
description: "Huntress confirms active exploitation of three leaked Microsoft Defender zero-days (BlueHammer/RedSun/UnDefend); ShinyHunters publishes 2.1M Amtrak Salesforce records; DragonForce and Safepay RaaS activity dominates ransomware volume; Unit 42 detects renewed scanning for CISA KEV entry CVE-2023-33538 on end-of-life TP-Link routers."
category: daily
tags: [cti, daily-brief, redsun, bluehammer, shinyhunters, dragonforce, safepay, cve-2026-33825, cve-2023-33538]
classification: TLP:CLEAR
reporting_period: "2026-04-16"
generated: "2026-04-17"
draft: true
severity: critical
report_count: 27
sources:
  - BleepingComputer
  - RansomLock
  - SANS
  - HaveIBeenPwned
  - Unit42
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-16 (24h) | TLP:CLEAR | 2026-04-17 |

## 1. Executive Summary

The pipeline processed 27 reports across five sources, dominated by a single critical-severity zero-day disclosure and a broad sweep of ransomware victim posts. BleepingComputer's publication of the "RedSun" proof-of-concept against Microsoft Defender — followed within hours by Huntress Labs confirming in-the-wild exploitation of RedSun, BlueHammer (CVE-2026-33825) and UnDefend — is the highest-priority item; two of the three flaws remain unpatched after April Patch Tuesday. A secondary high-impact item is ShinyHunters' public dump of 2.1 million Amtrak records taken from a Salesforce instance, continuing the group's extortion pattern. Ransomware-as-a-Service activity was heavy: Safepay claimed nine fresh victims across legal, education, utility and construction sectors, and DragonForce updated its leak site with a new healthcare victim. Unit 42 reported renewed Mirai-style scanning for CVE-2023-33538 on end-of-life TP-Link routers (CISA KEV since June 2025), and Europol's Operation PowerOFF warned 75,000 DDoS-for-hire users and seized 53 domains.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | RedSun Microsoft Defender LPE zero-day PoC |
| 🟠 **HIGH** | 24 | In-the-wild exploitation of BlueHammer/RedSun/UnDefend; Amtrak (ShinyHunters); DragonForce, Crypto24, Qilin, Safepay, Termite, Inc Ransom, Krybit, Prinz Eugen, ShadowByt3$ ransomware activity; ZionSiphon OT malware; Lumma Stealer/Sectop RAT; CVE-2023-33538 scanning |
| 🟡 **MEDIUM** | 1 | Safepay victim post (cheeky.com.ar) |
| 🔵 **INFO** | 1 | ISC Stormcast daily podcast |

## 3. Priority Intelligence Items

### 3.1 Three Microsoft Defender Zero-Days Now Exploited in the Wild (BlueHammer / RedSun / UnDefend)

**Source:** [BleepingComputer — RedSun PoC](https://www.bleepingcomputer.com/news/microsoft/new-microsoft-defender-redsun-zero-day-poc-grants-system-privileges/), [BleepingComputer — In-the-wild exploitation](https://www.bleepingcomputer.com/news/security/recently-leaked-windows-zero-days-now-exploited-in-attacks/)

A researcher operating as "Chaotic Eclipse" / "Nightmare-Eclipse" has released proof-of-concept code for three Microsoft Defender flaws in protest at how MSRC handled their disclosures. BlueHammer (now tracked as **CVE-2026-33825**) was patched in the April 2026 updates; RedSun and UnDefend remain unpatched. RedSun abuses Windows Defender's Cloud Files API — chaining an EICAR bait file, an oplock-based shadow copy race and a directory junction to overwrite `C:\Windows\system32\TieringEngineService.exe` and execute attacker code as SYSTEM on fully-patched Windows 10, 11 and Server 2019+. UnDefend can be triggered by a standard user to block Defender definition updates. Huntress Labs reports BlueHammer exploitation since 10 April and observed RedSun and UnDefend on a Windows host accessed via a compromised SSLVPN account, with evidence of hands-on-keyboard activity. MITRE mapping from the pipeline: **T1068** (Exploitation for Privilege Escalation), **T1078.002**, **T1137**.

> **SOC Action:** Confirm the April 2026 Patch Tuesday roll-up is deployed to all Windows 10/11/Server endpoints to close BlueHammer (CVE-2026-33825). For the unpatched RedSun and UnDefend flaws, hunt EDR telemetry for unexpected writes to `C:\Windows\system32\TieringEngineService.exe` and for `svchost.exe`/Defender-related processes creating directory junctions or reparse points in user-writable paths; alert on child processes of `MsMpEng.exe` or `TieringEngineService.exe` running outside `%ProgramFiles%\Windows Defender`. Review SSLVPN authentication logs for anomalous geolocations or impossible-travel sessions, rotate any credentials exposed to credential phishing, and enforce MFA on every VPN profile.

### 3.2 ShinyHunters Dumps 2.1M Amtrak Records from Salesforce Compromise

**Source:** [HaveIBeenPwned — Amtrak breach](https://haveibeenpwned.com/Breach/Amtrak)

ShinyHunters claimed a breach of Amtrak's Salesforce instance in April 2026 and, after an unsuccessful ransom demand, published the stolen data. The dump exposed 2,147,679 unique email addresses together with names, physical addresses and support-ticket contents. The group has run a repeated pattern against Salesforce tenants across multiple industries; extortion without technical ransomware is their hallmark. Pipeline MITRE mapping includes **T1566** (Phishing) — consistent with prior ShinyHunters Salesforce intrusions initiated through vishing and OAuth consent abuse rather than exploits.

> **SOC Action:** Audit all connected apps and OAuth grants inside Salesforce; revoke any token not tied to a known enterprise application. Enforce IP allowlisting on Salesforce admin logins, require MFA on every user and service account, and enable Salesforce Shield Event Monitoring to detect bulk record exports. Brief help-desk staff on voice-phishing scripts that impersonate Salesforce support or IT — ShinyHunters has repeatedly used this vector. Proactively notify affected Amtrak Guest Rewards users to rotate reused passwords and watch for targeted phishing referencing support-ticket content.

### 3.3 ZionSiphon — OT Malware Targeting Israeli Water Treatment

**Source:** [BleepingComputer — ZionSiphon](https://www.bleepingcomputer.com/news/security/zionsiphon-malware-designed-to-sabotage-water-treatment-systems/)

Darktrace analysed ZionSiphon, a new operational-technology malware designed to sabotage water treatment and desalination plants. The sample geofences itself to Israeli IP ranges and looks for OT-related files before calling an `IncreaseChlorineLevel()` function that appends `Chlorine_Dose=10`, `Chlorine_Pump=ON`, `Chlorine_Flow=MAX`, `Chlorine_Valve=OPEN` and `RO_Pressure=80` to configuration files. It scans the local subnet for Modbus, DNP3 and S7comm, propagates via USB by copying itself as a hidden `svchost.exe` and placing malicious shortcut files, and attempts self-destruct if its country check fails. The current build's XOR validation is broken, rendering the payload inert — but the intent is a chlorine-dosing physical-safety attack. Pipeline MITRE mapping: **T1036** (Masquerading), **T1091** (USB Replication — inferred from propagation description), **T1205** (Security Software Discovery), **T1067**.

> **SOC Action:** For critical-infrastructure operators, block USB mass-storage on engineering workstations and HMIs by policy; where USB is operationally required, enforce endpoint control and whitelisting of signed vendor tools only. Hunt for new `svchost.exe` binaries in removable-drive root directories and for `.lnk` files that execute hidden binaries. Verify integrity of SCADA configuration files handling chemical dosing against known-good baselines and alert on appended entries matching `Chlorine_*` or `RO_Pressure` keywords. Segment OT networks to deny east-west Modbus/DNP3/S7 scanning from IT assets.

### 3.4 DragonForce and Safepay Dominate Ransomware Victim Posts

**Source:** [RansomLock — DragonForce](https://www.ransomlook.io//group/dragonforce), [RansomLock — Safepay](https://www.ransomlook.io//group/safepay), [RansomLock — Crypto24](https://www.ransomlook.io//group/crypto24), [RansomLock — Qilin (HBX Group)](https://www.ransomlook.io//group/qilin)

DragonForce — the cartel-style RaaS that hit M&S, Harrods and Co-op in 2025 — added German healthcare firm medicalnetworks CJ GmbH & Co. KG to its leak site. Safepay listed nine new victims in a 24-hour burst including a UK primary school (st-bernards.bham.sch.uk), a German waste-management authority, an Australian genealogy non-profit, and law, construction, plumbing and manufacturing firms across multiple continents. Crypto24 (active since early 2025, `.crypto24` extension, double-extortion via RAMP-forum recruitment) leaked data from the Qatar Biomedical Research Institute. Qilin posted HBX Group, Termite posted lanap.com, and Inc Ransom posted bgcsnv.org and treelawoffice.com. The pipeline's top shared TTP across the ransomware set was **T1486** / **T1485** (Data Encrypted for Impact) and **T1566** (Phishing) as an initial vector, with **T1078** (Valid Accounts) correlated with the DraftKings credential-stuffing case (see item 3.5).

> **SOC Action:** Subscribe to RansomLook victim feeds for DragonForce, Safepay, Crypto24 and Qilin so any supply-chain or vendor listing triggers an incident ticket within an hour. Enforce MFA on all remote access, block legacy authentication to email and identity platforms, and verify that offline/immutable backups of domain controllers and SaaS data are tested weekly. For healthcare and education targets specifically, inventory exposed RDP, VPN and Citrix gateways — Crypto24's playbook leans heavily on stolen-credential entry.

### 3.5 Credential Stuffing Sentencing Highlights Continued Risk (DraftKings)

**Source:** [BleepingComputer — DraftKings sentencing](https://www.bleepingcomputer.com/news/security/man-gets-30-months-for-selling-thousands-of-hacked-draftkings-accounts/)

A 23-year-old Memphis man, Kamerin Stokes, received 30 months' prison and was ordered to pay $1,327,061 in restitution for reselling access to hijacked DraftKings accounts. Co-conspirators Nathan Austad and Joseph Garrison ran the November 2022 credential-stuffing attack that compromised ~68,000 DraftKings accounts and enabled roughly $635,000 in fraudulent cash-outs from 1,600 accounts. Stokes reopened his "fraud is fun" shop after his initial arrest, prompting remand. MITRE mapping: **T1078** (Valid Accounts), **T1566** (Phishing). The pipeline correlated this case with Crypto24's ransomware activity through the shared **T1078** pivot.

> **SOC Action:** For any consumer-facing authentication surface, rate-limit login attempts per credential and per source ASN, enforce CAPTCHA after N failures, and enable bot-management rules that score residential-proxy traffic. Integrate a breached-credential feed (HaveIBeenPwned k-anonymity API or equivalent) to force reset on any login using a known-leaked password. Alert on successful authentications followed by rapid payment-method additions and small "verification" deposits — the pattern used in the DraftKings cash-out.

### 3.6 CVE-2023-33538 — Mirai-Style Scanning of End-of-Life TP-Link Routers

**Source:** [Unit 42 — CVE-2023-33538 deep dive](https://unit42.paloaltonetworks.com/exploitation-of-cve-2023-33538/)

Palo Alto Networks Unit 42 reports large-scale automated scanning against the `/userRpm/WlanNetworkRpm` endpoint's `ssid1` parameter on end-of-life TP-Link TL-WR940N (v2/v4), TL-WR740N (v1/v2) and TL-WR841N (v8/v10) routers. The payloads are Mirai-variant binaries. The CVE has been in CISA's KEV catalogue since **June 2025**, and TP-Link confirms the devices are end-of-life with no patch available; it recommends replacement. Unit 42 emulated the TL-WR940N firmware and confirmed the vulnerability is real but requires authentication — realistic given widespread use of default credentials on these devices. MITRE mapping: **T1190** (Exploit Public-Facing Application — inferred), **T1064** (Command and Scripting Interpreter), **T1204** (User Execution).

> **SOC Action:** Inventory any TP-Link WR940N/WR740N/WR841N devices on corporate or home-office networks (via MAC OUI and HTTP banner fingerprinting) and replace them. Until replaced, block inbound access to their admin interfaces, change factory passwords, and place them on an isolated VLAN. Add Unit 42's IOC set and Suricata/Snort rules for the `ssid1` command-injection pattern to perimeter IDS.

### 3.7 Lumma Stealer + Sectop RAT via Cracked-Software SEO Poisoning

**Source:** [SANS ISC Diary 32904](https://isc.sans.edu/diary/rss/32904)

SANS Handler Brad Duncan documented a fresh Lumma Stealer infection chain delivered by SEO-poisoned cracked-software pages (e.g., "Adobe Premiere Pro 2026"). The lure is a password-protected 7-zip archive (`adobe_premiere_pro_(2026)_full_v26.0.2_espanol_[mega].7z`, password `6919`) containing a null-byte-inflated 806 MB EXE that deflates to a 7 MB Lumma Stealer loader. Post-infection, Lumma downloads a 64-bit DLL that runs Sectop RAT (ArechClient2) via `rundll32 ... LoadForm`. MITRE: **T1566** (Phishing), **T1204** (User Execution), **T1027** (Obfuscated Files — null-byte padding).

#### Indicators of Compromise

```
Delivery:
hxxps[:]//incolorand[.]com/how-visual-patch-enhances-ui-consistency-across-releases/
hxxps[:]//mega-nz.goldeneagletransport[.]com/Adobe_Premiere_Pro_%282026%29_Full_v26.0.2_Espa%C3%B1ol_%5BMega%5D.zip
hxxps[:]//arch.primedatahost3[.]cfd/auth/media/JvWcFd5vUoYTrImvtWQAASTh/Adobe_Premiere_Pro_(2026)_Full_v26.0.2_Espa%C3%B1ol_%5BMega%5D.zip

Lumma Stealer C2 domains:
cankgmr[.]cyou
carytui[.]vu
decrnoj[.]club
genugsq[.]best
longmbx[.]click
mushxhb[.]best
pomflgf[.]vu
strikql[.]shop
ulmudhw[.]shop

Sectop RAT C2:
91.92.241[.]102:9000
enotsosun[.]pw (NetGui.dll loader)

SHA256:
c7489e3bf546c5f2d958ac833cc7dbca4368dfba03a792849bc99c48a6b2a14f   (initial 7z)
4849f76dafbef516df91fecfc23a72afffaf77ade51f805eae5ad552bed88923   (inflated Lumma loader)
353ddce78d58aef2083ca0ac271af93659cf0039b0b29d0d169fc015bd3610bc   (deflated loader)
d9b576eb6827f38e33eda037d2cda4261307511303254a8509eeb28048433b2f   (Sectop RAT DLL)
```

> **SOC Action:** Block the C2 domains and the 91.92.241[.]102 IP at DNS/firewall. Deploy EDR detections for `rundll32.exe` loading a DLL from `%TEMP%` with an `LoadForm` export, and for EXE files larger than 500 MB with abnormal entropy profile (null-byte padding). Educate users that searches for cracked software are the single most reliable path to ransomware precursors.

### 3.8 Operation PowerOFF — 75,000 DDoS-for-Hire Users Warned, 53 Domains Seized

**Source:** [BleepingComputer — Operation PowerOFF](https://www.bleepingcomputer.com/news/security/operation-poweroff-identifies-75k-ddos-users-takes-down-53-domains/)

Europol coordinated the latest phase of Operation PowerOFF across 21 countries, warning more than 75,000 booter-service customers by letter and email, arresting four operators, serving 25 search warrants and seizing 53 domains. Prevention measures include SEO ads targeting young people, removing 100+ URLs promoting booters from search results, and on-chain warnings tied to illicit payments.

> **SOC Action:** No direct defensive action, but SOC leadership should note the enforcement tempo. If your organisation operates public-facing services in the named countries, expect a short-term dip in volumetric DDoS volume and use the lull to validate scrubbing-provider failover, anycast capacity, and tarpit rules for L7 attacks.

### 3.9 Prinz Eugen Leaks 1.2 TB from Standard Bank Group

**Source:** [RansomLock — Prinz Eugen](https://www.ransomlook.io//group/prinz%20eugen)

A RansomLook entry attributes a three-week February–March 2026 intrusion at Standard Bank Group and Liberty (financial services, South Africa) to an actor calling itself "Prinz Eugen," with **possible but unconfirmed** ties to DPRK-linked APT37. Approximately 1.2 TB was exfiltrated. Source hedges attribution; treat the APT37 overlap as unverified until corroborated by a primary incident-response report.

> **SOC Action:** South African FSI organisations should verify they have Standard Bank-linked vendor or partner data under their custody and review data-loss-prevention egress logs for large outbound flows to Tor or cloud object storage over the 27 Feb–20 Mar 2026 window. Do not re-share the APT37 attribution externally without primary-source corroboration.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in widely used software platforms | "Recently leaked Windows zero-days now exploited in attacks"; "New Microsoft Defender 'RedSun' zero-day PoC grants SYSTEM privileges" (shared CVE-2026-33825, TTP T1068) |
| 🟠 **HIGH** | Ransomware-as-a-Service groups increasingly targeting diverse sectors globally | DragonForce → medicalnetworks CJ (healthcare, DE); Crypto24 → Qatar Biomedical Research Institute; Termite → lanap.com |
| 🟠 **HIGH** | Malware/actor clustering on Safepay infrastructure | Three victim posts share Safepay malware fingerprint (confidence 0.90); two further posts share Safepay actor attribution (confidence 0.90) |
| 🟡 **MEDIUM** | Credential-stuffing and valid-account abuse as a shared TTP | DraftKings sentencing report and Qatar Biomedical Research Institute (Crypto24) both map to T1078 – Valid Accounts |
| 🟡 **MEDIUM** | Critical-manufacturing vendor exposure (carried forward from prior batches) | AVEVA Pipeline Simulation; Delta Electronics ASDA-Soft; Anviz Multiple Products; Horner Automation Cscape (sector correlation, confidence 0.80) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **qilin** (56 reports) — long-running RaaS, newest victim HBX Group
- **The Gentlemen** (48 reports) — persistent leak-site operator
- **nightspire** (37 reports) — active since late March
- **TeamPCP** (32 reports) — sustained posting cadence
- **DragonForce / dragonforce** (53 combined) — cartel-style RaaS; medicalnetworks CJ listed today
- **Coinbase Cartel** (26 reports) — ongoing double-extortion activity
- **Akira** (22 reports) — still active
- **shadowbyt3$** (21 reports) — Stride Learning / Amplify Technology listed today
- **ShinyHunters** (new in today's set) — Amtrak Salesforce dump
- **prinz eugen** (new in today's set) — Standard Bank Group, possible APT37 alias (unconfirmed)

### Malware Families

- **RansomLock** feed aggregator — 40 references
- **dragonforce ransomware** (26 reports) — continues to lead RaaS volume
- **Akira ransomware** (18 reports)
- **RaaS** label (15 reports) — business-model pattern
- **Tox1** (10 reports) — affiliate messaging infrastructure
- **PLAY ransomware** (8 reports)
- **Gentlemen ransomware** (7 reports)
- **Safepay** — 5 fresh appearances today; highest daily correlation confidence
- **Lumma Stealer** and **Sectop RAT (ArechClient2)** — new SANS-documented infection chain today
- **ZionSiphon** (new) — OT-sabotage malware targeting Israeli water treatment

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 18 | [link](https://www.ransomlook.io/) | Aggregated RaaS leak-site posts; DragonForce, Safepay, Qilin, Crypto24, Termite, Inc Ransom, Krybit, Prinz Eugen, shadowbyt3$ |
| BleepingComputer | 5 | [link](https://www.bleepingcomputer.com) | Primary coverage of RedSun PoC, in-the-wild exploitation of three Defender zero-days, ZionSiphon, DraftKings sentencing, Operation PowerOFF |
| SANS | 2 | [link](https://isc.sans.edu) | Lumma Stealer + Sectop RAT IOC drop; daily Stormcast podcast |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Amtrak) | Amtrak 2.1M-record Salesforce breach (ShinyHunters) |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/exploitation-of-cve-2023-33538/) | CVE-2023-33538 TP-Link exploitation analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Confirm April 2026 Patch Tuesday is fully deployed to close BlueHammer (CVE-2026-33825). Assume RedSun and UnDefend are actively exploited and stand up detections for TieringEngineService.exe overwrites and anomalous directory-junction creation until Microsoft ships a patch. (Traces to item 3.1.)
- 🔴 **IMMEDIATE:** Block the Lumma Stealer / Sectop RAT IOC set at DNS and perimeter (domains, 91.92.241[.]102) and push EDR rules for `rundll32 LoadForm` DLL loads from temp paths. (Traces to item 3.7.)
- 🟠 **SHORT-TERM:** Audit Salesforce OAuth grants, enforce MFA and IP allowlisting on admin logins, and brief help-desk staff on ShinyHunters-style vishing. (Traces to item 3.2.)
- 🟠 **SHORT-TERM:** Inventory and replace end-of-life TP-Link TL-WR940N/WR740N/WR841N routers; block their admin interfaces from untrusted networks until swap-out. (Traces to item 3.6.)
- 🟡 **AWARENESS:** Feed DragonForce, Safepay, Crypto24 and Qilin victim lists into vendor-risk monitoring so listings of third parties trigger supply-chain incident response. (Traces to items 3.4 and Section 5.)
- 🟢 **STRATEGIC:** For ICS/OT operators — particularly water, wastewater and desalination — treat ZionSiphon as a template for future physical-sabotage malware; invest in USB control, OT-IT segmentation and SCADA config-integrity baselining now, not when a working build appears. (Traces to item 3.3.)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 27 reports processed across 1 correlation batch (batch 73, 33 tier-1 reports). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
