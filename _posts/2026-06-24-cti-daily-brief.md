---
layout: post
title:  "CTI Daily Brief: 2026-06-24 — Mandiant Exposes Cisco SD-WAN Zero-Day (CVE-2026-20245), CISA Drops 4 Critical ICS Advisories, North Korea Ships AI-Confusing macOS Malware"
date:   2026-06-25 20:07:51 +0000
description: "65 reports across 15 sources. Mandiant discloses active zero-day exploitation of CVE-2026-20245 in Cisco Catalyst SD-WAN Manager. CISA publishes four critical ICS/ICSMA advisories covering EV charging, Daktronics displays, and pydicom. North Korean-linked 'macOS.Gaslight' embeds prompt injection to defeat LLM-assisted malware analysis. Akira, Stormous, and Anubis ransomware operations remain highly active."
category: daily
tags: [cti, daily-brief, cisco-sd-wan, cve-2026-20245, kimsuky, akira, stormous, cisa-ics]
classification: TLP:CLEAR
reporting_period: "2026-06-24"
generated: "2026-06-25"
draft: true
severity: critical
report_count: 65
sources:
  - AlienVault
  - BleepingComputer
  - CISA
  - Microsoft
  - RecordedFutures
  - Cisco Talos
  - SANS
  - Schneier
  - Wired Security
  - RansomLock
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-24 (24h) | TLP:CLEAR | 2026-06-25 |

## 1. Executive Summary

Over the last 24 hours the pipeline ingested 65 reports across 15 sources, with severity dominated by 37 high-rated items and 5 critical-rated items. The headline event is Mandiant's public disclosure that **CVE-2026-20245**, a privilege-escalation flaw in Cisco Catalyst SD-WAN Manager, was exploited as a zero-day at a service provider to gain root-level access via a malicious CSV upload, chained with prior authentication bypasses (CVE-2026-20127 and CVE-2026-20182). CISA simultaneously released four critical ICS/ICSMA advisories — EVoke EV charging stations (CVSS 9.4), Daktronics display controller firmware (CVSS 9.3), pydicom pynetdicom (CVSS 9.1), and a high-severity Schneider Electric PowerLogic P7 advisory — pushing critical-infrastructure exposure to the front of the queue. On the threat-actor side, SentinelOne attributes the new **macOS.Gaslight** family to a North Korean operator using embedded prompt-injection content to manipulate LLM-assisted analysis pipelines, while Kimsuky's **KimJongRAT** continues evolving via GitHub Releases and Google Drive abuse. Ransomware activity remains dense, with Akira, Stormous, Anubis, Chaos, Qilin, Interlock, Morpheus, ShinyHunters, and a new Go-based **Prinz Eugen** encryptor all posting victims. No new CISA KEV additions were observed in this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 5 | Cisco SD-WAN zero-day (CVE-2026-20245); CISA ICS critical advisories (EVoke, Daktronics, pydicom) |
| 🟠 **HIGH** | 37 | Ransomware victim postings (Akira, Stormous, Anubis, Chaos, Qilin, Interlock, Morpheus); macOS Gaslight; AWS AiTM phishing kit; Bluekit BitM; KimJongRAT; LokiBot; Edgecution Edge extension; Ukrposhta attack; multiple CISA ICS high advisories |
| 🟡 **MEDIUM** | 6 | PirloTV piracy network seizure; Russian dairy cyberattack; SANS IoT botnet diary; DraftKings credential stuffing sentence |
| 🟢 **LOW** | 1 | CVE-2026-46140 Bluetooth btmtk SKB validation |
| 🔵 **INFO** | 16 | Microsoft Win10 ESU extension; Talos AI-enabled CTI; Schneier on AI liability; advisory revisions |

## 3. Priority Intelligence Items

### 3.1 Mandiant — Active Zero-Day Exploitation of Cisco Catalyst SD-WAN Manager (CVE-2026-20245)

**Source:** [Mandiant / Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager), [BleepingComputer](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)

Mandiant identified a threat actor that compromised SD-WAN infrastructure at a service provider in early 2026, ultimately escalating to root by abusing **CVE-2026-20245** — a flaw in SD-WAN Manager's file-upload feature that allows command injection via a crafted CSV file. Initial access was via unauthorised peering connections established between late 2025 and January 2026, possibly through the previously undisclosed authentication-bypass vulnerabilities CVE-2026-20127 and CVE-2026-20182. The actor manipulated default account passwords, created a rogue root account, and executed extensive anti-forensic cleanup — selectively deleting and restoring config files and validation scripts to scrub traces. SD-WAN Manager is heavily deployed at distributed enterprises (banks, retail, healthcare, MSPs), making this a high-impact campaign.

**Affected products:** Cisco Catalyst SD-WAN Manager (vManage).
**MITRE ATT&CK:** T1190, T1078, T1068, T1098, T1136, T1059, T1070, T1070.004, T1070.006, T1133, T1552.001, T1562.001, T1003.008, T1021.004.

#### Indicators of Compromise
```
SHA-256: b82936f37648518425c7d3cf9e09eaffa41d7cdb3840f6a40287e3a108880f7b
IP: 23.245.7[.]178
IP: 45.32.38[.]160
IP: 76.92.245[.]217
IP: 126.51.108[.]152
IP: 153.186.231[.]233
IP: 167.179.79[.]189
IP: 207.190.37[.]94
IP: 209.137.225[.]101
```

> **SOC Action:** Inventory all Cisco Catalyst SD-WAN Manager instances and verify patch level for CVE-2026-20245, CVE-2026-20127 and CVE-2026-20182. Audit `/etc/passwd` and SD-WAN local user accounts for unexpected root-equivalent accounts and recently changed default credentials. Hunt CSV upload events to the vManage GUI/API and correlate with subsequent shell or sudo activity. Block egress to the listed IPs, and submit b82936f3… SHA-256 to EDR custom-IOC lists. Review peering relationships and tear down any unauthorised peer registrations.

### 3.2 CISA Drops Four Critical-Severity ICS / ICSMA Advisories on June 25

**Source:** [CISA ICSA-26-176-02 (EVoke CSMS)](https://www.cisa.gov/news-events/ics-advisories/icsa-26-176-02), [CISA ICSA-26-176-04 (Daktronics)](https://www.cisa.gov/news-events/ics-advisories/icsa-26-176-04), [CISA ICSMA-26-176-01 (pydicom pynetdicom)](https://www.cisa.gov/news-events/ics-advisories/icsma-26-176-01), [CISA ICSA-26-176-07 (Schneider PowerLogic P7)](https://www.cisa.gov/news-events/ics-advisories/icsa-26-176-07)

CISA published a coordinated batch of advisories affecting energy, transportation, healthcare and critical-manufacturing operators. **EVoke Systems EV charging stations (CVE-2026-40702, CVSS 9.4)** expose unauthenticated WebSocket endpoints that allow charger impersonation and privilege escalation across all CSMS versions; EVoke is rolling out OCPP Security Profiles 2/3 and an allow-listed charger-ID inventory as mitigation. **Daktronics Controller Firmware (CVE-2026-28701 / CVE-2026-33560 / hard-coded credentials, CVSS 9.3)** affects VFC-DMP-5000, DMP-5000, and DMP-8000 below firmware versions 8.117.x.x / 9.43.x.x / 10.34.x.x — path traversal plus unrestricted file upload gives unauthenticated root. **pydicom pynetdicom (CVE-2026-56445, CVSS 9.1)** allows unauthenticated arbitrary-path writes via the qrscp C-STORE handler; the maintainer has not engaged with CISA, so users must self-mitigate on version 3.0.4 and below. **Schneider Electric PowerLogic P7 (CVE-2026-9716, CVE-2026-9717, high)** has a NULL pointer dereference and an OS command injection — patches are available.

**Affected sectors:** Energy / Transportation Systems, Commercial Facilities / IT / Emergency Services / Healthcare, Healthcare and Public Health, Energy.

> **SOC Action:** Pull asset inventory for EVoke CSMS, Daktronics VFC-DMP-5000/DMP-5000/DMP-8000, pynetdicom (>=1.0.0,<3.0.4), and Schneider PowerLogic P7 (<=0.2.003.001.000). Patch Daktronics to 8.117.x.x / 9.43.x.x / 10.34.x.x and PowerLogic P7 immediately, and rotate any default Daktronics credentials. Where pynetdicom cannot be updated, block inbound DICOM C-STORE traffic at the firewall and isolate medical-imaging segments. Apply CISA's standard ICS defensive measures: no internet exposure, segment from business networks, VPN with current patching.

### 3.3 North Korea — macOS.Gaslight Embeds Prompt Injection to Defeat LLM Analysis; KimJongRAT Continues to Evolve

**Source:** [BleepingComputer (macOS.Gaslight)](https://www.bleepingcomputer.com/news/security/new-macos-malware-embeds-fake-errors-to-confuse-ai-analysis-tools/), [IIJ SECT (KimJongRAT)](https://sect.iij.ad.jp/blog/2026/06/continuous-evolution-of-kimjongrat-2026/)

SentinelOne attributes with high confidence to a North Korean–linked threat actor a new macOS Rust-based backdoor / infostealer dubbed **macOS.Gaslight**. The binary embeds a 3.5 KB payload of 38 fabricated system messages — fake crash reports, OOM kills, SQL-injection alerts, token-expiration warnings, JSON parse errors — formatted to look like legitimate debugger output. The strings are prompt-injection content designed to make LLM-assisted triage agents abort, truncate, or refuse analysis rather than evade sandboxing. Separately, **Kimsuky (Earth Kumiho)** continues iterating **KimJongRAT**, with a May–June 2026 campaign distributing payloads from GitHub Releases via shortened URLs and pulling subsequent stages from Google Drive using obfuscated VBScript. Kimsuky retrieves C2 addresses dynamically rather than hard-coding them, complicating netflow-based detection.

**MITRE ATT&CK:** T1564.001, T1036, T1059.001, T1204.002, T1218.011, T1027, T1547.001.

> **SOC Action:** For macOS fleets, deploy YARA rules looking for the fake-message strings ("Token Dump", "Worker process killed by OOM killer", "Refresh token logic seems flaky") inside Mach-O binaries, and treat any Rust-compiled Mach-O sample with embedded `{{DATA}}` template placeholders as suspicious. For LLM-assisted analysis pipelines, instrument the agent to treat in-sample strings as untrusted data and never as instructions. For KimJongRAT, hunt for shortened-URL clicks resolving to `github.com/.../releases/download/` followed by `wscript.exe` or `cscript.exe` executing VBScript that pulls from `drive.google.com`.

### 3.4 AWS Console Credential Harvesting — AiTM Phishing Kit Captures MFA

**Source:** [Datadog Security Labs (via AlienVault)](https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/)

Between 16–19 June 2026 Datadog observed three Cloudflare-hosted phishing domains — `loginportal-aws[.]com`, `us-east-prod[.]com`, `us-west-login[.]com` — registered through NICENIC INTERNATIONAL serving cloned AWS console sign-in pages with a server-driven adversary-in-the-middle MFA flow capturing email, SMS, or TOTP second factors in real time. Phishing emails impersonated AWS Support with fabricated bandwidth-throttling support tickets and were sent through legitimate platforms (SendGrid, Nimbu) to pass SPF/DKIM. A VirusTotal-uploaded batch file showed an attacker validation script that called `/api/check` to validate target emails before rendering the cloned page.

**MITRE ATT&CK:** T1566, T1566.001, T1185, T1539, T1056, T1090, T1114.

#### Indicators of Compromise
```
Domain: loginportal-aws[.]com
Hostname: aws.us-west-login[.]com
Hostname: aws-central.us-west-login[.]com
Hostname: aws.us-east-prod[.]com
Registrar: NICENIC INTERNATIONAL GROUP CO., LIMITED
Hosting: Cloudflare
Email delivery: SendGrid, Nimbu
```

> **SOC Action:** Block the three phishing domains and hostnames at egress proxy and DNS. Query AWS CloudTrail for `ConsoleLogin` events from anomalous IPs in the last 10 days and force MFA re-enrolment on any matches. Add the registrar NICENIC and any newly registered Cloudflare-fronted `aws-*` lookalikes to your phishing-domain monitoring. Phish-test users with cloned-console templates and move to FIDO2 / WebAuthn for IAM root and break-glass accounts where credentials cannot be intercepted by AiTM.

### 3.5 Ukraine — IT Army of Russia Claims Attack on Ukrposhta; Mobile App Disrupted

**Source:** [The Record (Recorded Future)](https://therecord.media/ukraine-state-postal-operator-reports-disruption)

Ukraine's state postal operator Ukrposhta confirmed disruption to its mobile application following an overnight cyberattack. The pro-Russian hacktivist group **IT Army of Russia** claimed responsibility and alleged breaching infrastructure weeks earlier, exfiltrating a user database and other internal data; the claim is unverified by Ukrposhta or independent sources. Ukrposhta employs ~32,000 staff across 6,000+ post offices and has faced multiple Russia-linked cyber incidents (Ukrposhta in 2024, Nova Poshta DDoS and phishing in 2025). IT Army of Russia, active since March 2025, uses cybercrime forums and Telegram to publish allegedly stolen data, recruit insiders in Ukrainian critical infrastructure, and solicit military and civilian targeting intelligence.

**MITRE ATT&CK:** T1566.

> **SOC Action:** For organisations operating in or supplying Ukraine, treat IT Army of Russia targeting as ongoing — review phishing controls, harden insider-recruitment risk (privileged-access reviews, USB egress controls), and audit external-facing customer applications for DDoS and credential-stuffing resilience. Allied postal, logistics, and government identity providers should hunt for credential-replay activity using leaked Ukrposhta-style datasets.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in industrial control systems | Yokogawa FAST/TOOLS and CI Server; Horner Automation Cscape |
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities affecting critical infrastructure sectors | ShinyHunters' 0-day attacks: After patching, find out if you were breached; Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access |
| 🟠 **HIGH** | Increased ransomware targeting healthcare and critical manufacturing sectors | Clearview Eye Centre By interlock; Daktronics Controller Firmware |
| 🟠 **HIGH** | Phishing campaigns exploiting global events (FIFA 2026 World Cup) | FIFA 2026 Security Alert (PointWild); AWS AiTM phishing kit (Datadog) |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with data exfiltration + phishing TTPs | ISOPLUS By qilin; Quest Health Solutions By anubis; multiple Stormous victim posts |
| 🟠 **HIGH** | Cybercrime-as-a-service operations being disrupted by law enforcement / private sector | ESET takes part in Operation Endgame (Amadey, Stealc); Three "cybercrime as a service" ops undercut by Microsoft + LE |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **The Gentlemen** (85 reports) — High-volume ransomware/extortion poster active across multiple sectors over the last 30 days
- **Qilin** (65 reports) — RaaS with Jabber/Tox affiliate ops; ISOPLUS posting observed today
- **Akira** (35 reports) — Double-extortion against Windows / Linux / ESXi; Padget Technologies and JMS Southeast posted today
- **ShinyHunters / Shinyhunters** (45 combined) — Active zero-day campaigns and naic.org posting today
- **Deadlock** (55 reports) — Persistent leak-site activity
- **Lockbit5** (39 reports) — Continued ransomware-brand activity
- **DragonForce** (23 reports) — RaaS operations
- **Nova** (20 reports) — Recent victim postings
- **Nightspire** (18 reports) — RaaS activity through mid-June

### Malware Families
- **RansomLook**-tagged ransomware artefacts (138 mentions) — Pipeline-wide ransomware leak-site posts (umbrella)
- **Akira ransomware / Akira / Akira Ransomware** (~36 combined) — Confirmed live victim drops today
- **Tox / Tox1** (~101 combined) — Used by Krybit, Stormous, and others for affiliate / negotiation comms
- **Lockbit5** (14 reports) — Ransomware deployments through mid-June
- **Nova** (11 reports) — Active payload
- **RALord** (10 reports) — Ongoing operations
- **macOS.Gaslight** (new) — Rust-based North Korean macOS backdoor with anti-LLM tradecraft
- **Prinz Eugen** (new) — Go-based encryptor using ChaCha20-Poly1305, no ransom note, recursive most-recent-first encryption

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 18 | [link](https://www.ransomlook.io/) | Ransomware leak-site monitoring across Anubis, Akira, Chaos, Insomnia, Stormous, Morpheus, Qilin, ShinyHunters, Krybit |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com) | macOS.Gaslight; Mandiant Cisco SD-WAN; Bluekit BitM kit; Edgecution malicious Edge extension; DraftKings sentencing |
| CISA | 9 | [link](https://www.cisa.gov/news-events/ics-advisories) | Wave of ICS / ICSMA advisories incl. EVoke, Daktronics, pydicom, Schneider, Yokogawa, Horner, OHIF, Delta, H.VIEW |
| AlienVault | 7 | [link](https://otx.alienvault.com/) | Cisco SD-WAN zero-day; AWS AiTM phishing kit; ClickFix macOS infostealer; FIFA 2026 phishing; Prinz Eugen; LokiBot; KimJongRAT |
| Microsoft | 5 | [link](https://msrc.microsoft.com/update-guide/) | CVE-2026-4367 libxpm DoS; CVE-2026-11816 keras path traversal; DWM Core; Win Admin Center; Bluetooth btmtk |
| RecordedFutures | 3 | [link](https://therecord.media) | Ukrposhta cyberattack; Cellebrite use in Russia; Russian dairy cyberattack |
| Cisco Talos | 2 | [link](https://blog.talosintelligence.com/beyond-iocs-ai-enabled-threat-intelligence/) | AI-enabled threat intelligence; Qakbot COM evasion |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/33104) | Terrabot IoT botnet honeypot diary |
| Schneier | 2 | [link](https://www.schneier.com/) | AI and liability (German court ruling on Google AI summaries) |
| Wired Security | 1 | [link](https://www.wired.com/category/security/) | British police crime-prediction analytics investigation |
| Wiz | 1 | [link](https://www.wiz.io/blog) | Hidden attack paths in cloud environments via runtime signals |
| Sysdig | 1 | [link](https://sysdig.com/blog/) | Cloud-native threat research |
| BellingCat | 1 | [link](https://www.bellingcat.com/) | AI methodology for civilian-harm verification |
| Upwind | 1 | [link](https://www.upwind.io/blog) | Cloud security research |
| Unknown | 2 | — | Telegram (channel name redacted) — Linux Scales eBPF rootkit analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Cisco Catalyst SD-WAN Manager for CVE-2026-20245 (plus the chained CVE-2026-20127 / CVE-2026-20182), audit local accounts for rogue root users, and hunt the eight Mandiant IPs plus SHA-256 `b82936f3…` in EDR / firewall logs. SD-WAN Manager root compromise is a service-provider-scale blast radius.
- 🔴 **IMMEDIATE:** Patch the CISA-disclosed critical ICS issues: Daktronics controller firmware to 8.117.x.x / 9.43.x.x / 10.34.x.x with default-password rotation; Schneider Electric PowerLogic P7 for CVE-2026-9716 / CVE-2026-9717; isolate or filter pynetdicom (< 3.0.4) and EVoke CSMS until OCPP Security Profile 2/3 migration completes.
- 🟠 **SHORT-TERM:** Block the three AWS AiTM phishing domains and move IAM root / break-glass and high-privilege accounts to FIDO2 / WebAuthn; phishing kits with server-driven MFA branching can defeat TOTP and SMS but not phishing-resistant authenticators.
- 🟡 **AWARENESS:** Update macOS detection and any LLM-assisted malware-analysis pipeline to handle the Gaslight prompt-injection class — treat strings extracted from samples as untrusted data, never as instructions to the agent. Brief reverse-engineers that "system messages" inside binaries can be adversarial.
- 🟢 **STRATEGIC:** Healthcare, critical-manufacturing, and energy operators should expect continued ransomware pressure (Interlock, Akira, Anubis, Chaos, Qilin, Stormous, Morpheus) and elevated CISA ICS advisory volume; align quarterly patch programmes with the ICS-CERT cadence and exercise out-of-band restore for OT segments. Allied logistics, postal, and government identity providers should rehearse Russia-aligned hacktivist scenarios (IT Army of Russia, IT-Army-style insider recruitment).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 65 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
