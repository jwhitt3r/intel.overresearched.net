---
layout: post
title: "CTI Daily Brief: 2026-03-16 — CVE-2026-3909 Chromium Skia exploited in the wild; EU sanctions Chinese and Iranian cyber firms; four CISA ICS advisories"
date: 2026-03-17 21:11:00 +0000
description: "High-tempo day with 52 reports across 11 sources. Active exploitation of Chromium Skia CVE-2026-3909, EU cyber sanctions against state-linked entities, four CISA ICS advisories including two at CVSS 9.8, and multiple state-sponsored espionage campaigns targeting critical infrastructure."
category: daily
tags: [cti, daily-brief, cve-2026-3909, boggy-serpens, laundry-bear, leaknet, slopoly, hydra-saiga]
classification: TLP:CLEAR
reporting_period: "2026-03-16"
generated: "2026-03-17"
draft: false
report_count: 52
sources:
  - Microsoft
  - BleepingComputer
  - AlienVault
  - CISA
  - SANS
  - RecordedFutures
  - Unit42
  - Elastic Security Labs
  - Sentinel One
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-16 (24h) | TLP:CLEAR | 2026-03-17 |

## 1. Executive Summary

The pipeline processed 52 reports from 11 sources in the last 24 hours, with 12 rated critical and 12 high. Google confirmed active in-the-wild exploitation of CVE-2026-3909, an out-of-bounds write in Chromium's Skia graphics engine affecting Chrome and Edge. The European Council sanctioned three Chinese and Iranian entities for cyberattacks against EU critical infrastructure, including Integrity Technology Group (linked to Flax Typhoon / Raptor Train) and Emennet Pasargad. CISA published four ICS advisories, two at CVSS 9.8 for Schneider Electric SCADAPack (CVE-2026-0667) and CODESYS in Festo Automation Suite. Separate espionage campaigns from Boggy Serpens (Iran) and a possible Laundry Bear (Russia) operation deploying the novel DRILLAPP backdoor against Ukrainian entities round out a high-tempo day dominated by state-sponsored targeting of critical infrastructure.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 12 | CVE-2026-3909 Chromium Skia (ITW); EU cyber sanctions; CISA ICS advisories (Schneider, Festo); CVE-2026-4105 systemd LPE; CVE-2026-2673 OpenSSL TLS 1.3; Hydra Saiga espionage; DRILLAPP/Laundry Bear; Boggy Serpens |
| 🟠 **HIGH** | 12 | LeakNet ransomware ClickFix/Deno; Slopoly AI-generated malware (Hive0163); Vidar infostealer via WordPress; font-rendering AI bypass; CISA ICS (Siemens SICAM, Schneider EcoStruxure); Coruna iOS exploits |
| 🟡 **MEDIUM** | 17 | Microsoft CVE advisories (Vim, kernel, Perl, libarchive, Erlang SSH); COVERT RAT phishing; ACRStealer infrastructure |
| 🟢 **LOW** | 4 | CISO AI agent guidance; Microsoft 365 Copilot rollback; Samsung PC fix; IPv4-mapped IPv6 analysis |
| ℹ️ **INFO** | 7 | ISC Stormcast; Elastic Security AI agent guide; BreachForums alliance; ransomware pulse snapshot |

## 3. Priority Intelligence Items

### 3.1 CVE-2026-3909: Chromium Skia Out-of-Bounds Write — Exploited in the Wild

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-3909)

Google confirmed that an exploit for CVE-2026-3909 exists in the wild. The vulnerability is an out-of-bounds write in the Skia graphics rendering library used by Chromium. Microsoft Edge (Chromium-based) ingests this component and is also affected. Successful exploitation can lead to arbitrary code execution in the context of the browser renderer process.

> **SOC Action:** Validate that Chrome and Edge are updated to the latest stable release across the fleet. Query EDR for browser crash dumps or unusual child processes spawned from chrome.exe / msedge.exe renderer processes. Prioritise patching within 24 hours given confirmed ITW exploitation.

### 3.2 EU Sanctions Chinese and Iranian Cyber Firms

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/europe-sanctions-chinese-and-iranian-firms-for-cyberattacks/)

The Council of the European Union sanctioned Integrity Technology Group and Anxun Information Technology (i-Soon) — both Chinese — and Iranian firm Emennet Pasargad for cyberattacks against EU critical infrastructure. Integrity Technology Group provided support enabling the compromise of over 65,000 devices across six EU states and is linked to Flax Typhoon and the Raptor Train botnet. Anxun (i-Soon) advertised hacker-for-hire services since at least 2011. Emennet Pasargad conducted influence campaigns including hijacking billboards during the 2024 Paris Olympics and compromising an SMS service in Sweden.

**Entities:** Flax Typhoon, Emennet Pasargad, Holy Souls, Anxun Information Technology (i-Soon), Integrity Technology Group

**ATT&CK:** T1573 (Encrypted Channel), T1001 (Data Obfuscation)

> **SOC Action:** Review network telemetry for connections to known Raptor Train infrastructure. Cross-reference IoT/OT device inventories against Raptor Train target profiles (SOHO routers, IP cameras, NAS devices). Update threat actor profiles for Flax Typhoon and Emennet Pasargad with new EU sanction context.

### 3.3 CISA ICS Advisories: Schneider Electric SCADAPack (CVE-2026-0667, CVSS 9.8) and CODESYS in Festo (CVSS 9.8)

**Source:** [CISA ICSA-26-076-02](https://www.cisa.gov/news-events/ics-advisories/icsa-26-076-02), [CISA ICSA-26-076-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-076-01)

CISA published four ICS advisories on 17 March. Two carry CVSS 9.8 scores:

**CVE-2026-0667** (Schneider Electric SCADAPack/RemoteConnect): CWE-754 improper check for unusual conditions in Modbus TCP enables remote code execution, denial of service, and loss of confidentiality/integrity on SCADAPack 47xi/47x/57x RTUs deployed worldwide in the energy sector. Fixed in firmware 9.12.2 / RemoteConnect R3.4.2.

**CODESYS in Festo Automation Suite** (versions prior to 2.8.0.138): 35+ vulnerabilities including memory corruption, stack/heap buffer overflows, OS command injection, path traversal, deserialization of untrusted data, and weak cryptographic implementations.

Two additional high-severity advisories cover Siemens SICAM SIAPP SDK (ICSA-26-076-04) and Schneider Electric EcoStruxure Data Center Expert (ICSA-26-076-03).

> **SOC Action:** Notify OT/ICS teams immediately. For Schneider SCADAPack, apply firmware 9.12.2 or implement network segmentation and disable the logic debug service. For Festo, upgrade to Automation Suite 2.8.0.138. Verify Modbus TCP exposure with a network scan of OT segments.

### 3.4 DRILLAPP Backdoor Targeting Ukrainian Entities — Possible Laundry Bear (Russia)

**Source:** [LAB52 / S2 Group](https://lab52.io/blog/drillapp-new-backdoor-targeting-ukrainian-entities-with-possible-links-to-laundry-bear/)

LAB52 identified a campaign targeting Ukrainian entities during February 2026 using charity- and judicial-themed phishing lures. The campaign deploys DRILLAPP, a novel JavaScript-based backdoor that executes through the Edge browser in headless mode. DRILLAPP enables file upload/download, microphone recording, and webcam capture by exploiting browser permissions. C2 communication uses WebSockets obtained from URLs hosted on pastefy.app. Attribution to Laundry Bear is assessed with **low confidence** based on shared TTPs with a CERT-UA report from January 2026.

**ATT&CK:** T1566 (Phishing), T1059.007 (JavaScript), T1547.001 (Registry Run Keys), T1113 (Screen Capture), T1071.001 (Web Protocols), T1204.001 (User Execution: Malicious Link)

#### Indicators of Compromise
```
C2: 188.137.228[.]162
C2: 80.89.224[.]13
SHA256: 107b2badfc93fcdd3ffda7d3999477ced3f39f43f458dd0f6a424c9ab52681c3
SHA256: 21fefc3913d3d2dfde7f0dff54800ca7512eb5df9513b1a457a2af25fdd51b26
SHA256: 51e86408904c0ca3778361cde746783a0f2b9fd2a6782aa7e062aa597151876e
SHA256: 6178b1af51057c0bac75a842afff500a8fa3ed957d79a712a6ef089bec7e7a8b
SHA256: 993d55f60414bf2092f421c3d0ac6af1897a21cc4ea260ae8e610a402bf4c81c
```

> **SOC Action:** Hunt for msedge.exe processes launched with `--headless --no-sandbox --disable-web-security` flags. Query proxy/DNS logs for pastefy.app connections. Block the C2 IPs at the perimeter. Search for .lnk files that create .html files in %TEMP% directories.

### 3.5 Boggy Serpens (Iran) Deploys AI-Enhanced Malware Against Energy and Maritime Sectors

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/69b91b4202446dd5143da7c3), [Unit42](https://unit42.paloaltonetworks.com/boggy-serpens-threat-assessment/)

Boggy Serpens, linked to Iran's Ministry of Intelligence and Security, refined its cyberespionage tactics to focus on trusted-relationship compromises and multi-wave targeting. The group combines social engineering with AI-enhanced malware (GhostBackdoor, Lamporat) and Rust-based tools for long-term persistence. A sustained four-wave campaign against a UAE marine and energy company demonstrates the group's focus on regional maritime infrastructure. The group hijacks legitimate accounts to bypass security and uses secondary social-engineering prompts to deliver malware.

**ATT&CK:** T1566 (Phishing), T1078 (Valid Accounts), T1574.002 (DLL Side-Loading), T1055 (Process Injection), T1573.001 (Encrypted Channel), T1027.002 (Software Packing), T1204.002 (Malicious File)

#### Indicators of Compromise
```
Domain: bootcamptg[.]org
Domain: codefusiontech[.]org
Domain: screenai[.]online
Domain: stratioai[.]org
Domain: maxisteq[.]org
Domain: miniquest[.]org
Domain: promoverse[.]org
Hostname: reminders.trahum[.]org
C2: 157.20.182[.]75
C2: 159.198.66[.]153
C2: 159.198.68[.]25
C2: 64.7.198[.]12
```

> **SOC Action:** Query email gateway logs for lures referencing AI/tech bootcamps or fake platform invites from .org domains. Hunt for Rust-compiled binaries in non-standard directories. Add the listed domains and IPs to blocklists. Alert energy-sector and maritime SOC teams to heightened Iranian targeting.

### 3.6 Hydra Saiga: Espionage Campaign Against Central Asian Critical Utilities

**Source:** [VMRay](https://www.vmray.com/hydra-saiga-covert-espionage-and-infiltration-of-critical-utilities/)

Hydra Saiga is a sophisticated espionage campaign targeting energy and water resource sectors in Central Asia (primarily Uzbekistan and Kyrgyzstan). The attackers use custom implants delivered via phishing, with infrastructure mimicking government domains (.uz, .kg TLDs). The campaign employs extensive credential harvesting via LSASS memory access, lateral movement via WMI and PSRemoting, and data exfiltration through encrypted channels.

**ATT&CK:** T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1003.001 (LSASS Memory), T1047 (WMI), T1572 (Protocol Tunneling), T1078 (Valid Accounts), T1021.006 (Windows Remote Management)

#### Indicators of Compromise
```
Domain: adm-govuz[.]com
Domain: allcloudindex[.]com
Domain: docworldme[.]com
Domain: mailboxarea[.]cloud
Domain: 40gov[.]uz
Domain: 40minwater[.]uz
C2: 141.98.82[.]198
C2: 179.60.150[.]151
C2: 195.38.162[.]147
C2: 193.149.129[.]181
C2: 64.7.198[.]46
SHA256: 3da644eec41a32d72d3632b76a524d836f39f3b9854eda5d227cdf7fc4c7b543
SHA256: 8dda063860120a04bf3c7679f6a02a14aee4b5d2c3efc4dbd638dabce8a288a5
```

> **SOC Action:** Block the listed domains and IPs. Hunt for PowerShell scripts performing base64-encoded WMI remote execution. Monitor for LSASS credential dumping (Sysmon Event ID 10). Organisations with Central Asian operations should increase monitoring of government-themed email lures.

### 3.7 LeakNet Ransomware Adopts ClickFix and Deno Runtime for Evasion

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/leaknet-ransomware-uses-clickfix-and-deno-runtime-for-stealthy-attacks/)

LeakNet ransomware now uses the ClickFix social engineering technique for initial access. The attack chain deploys a Deno-based malware loader (a "bring your own runtime" approach) that executes JavaScript payloads directly in system memory, minimising forensic artifacts. Post-exploitation activity includes DLL sideloading (jli.dll loaded via Java in C:\ProgramData\USOShared), C2 beaconing, credential discovery via `klist` enumeration, lateral movement via PsExec, and data exfiltration abusing Amazon S3 buckets.

**ATT&CK:** T1566 (Phishing), T1059 (Command and Scripting Interpreter), T1574.002 (DLL Side-Loading), T1021 (Remote Services), T1071 (Application Layer Protocol)

#### Indicators of Compromise
```
Domain: plurfestivalgalaxy[.]com
C2: 94.156.181[.]89
SHA256: 0884e5590bdf3763f8529453fbd24ee46a3a460bba4c2da5b0141f5ec6a35675
```

> **SOC Action:** Create detection rules for Deno runtime (deno.exe) execution outside developer workstations. Monitor for DLL sideloading via jli.dll in C:\ProgramData\USOShared. Alert on unexpected outbound traffic to Amazon S3 from non-sanctioned processes. Hunt for VBS/PowerShell scripts named Romeo*.ps1 or Juliet*.vbs.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Targeting of critical infrastructure and government sectors by state-sponsored actors | Boggy Serpens threat assessment; Hydra Saiga espionage campaign; IndoHaxSec data leak claims against Israel; China-based espionage against SE Asian military targets; Warlock ransomware attack deploying web shells and tunnels |
| 🟠 **HIGH** | Increased use of phishing as a primary attack vector across multiple campaigns | CVE-2026-24291 RegPwn exploit distribution; Boggy Serpens spear-phishing; COVERT RAT phishing campaign; Iranian cyber threat evolution analysis; BreachForums social engineering activity |
| 🟠 **HIGH** | AI adoption in malware development lowering barriers to entry | Hive0163/Slopoly AI-generated malware in Interlock ransomware attacks; Boggy Serpens AI-enhanced tooling (GhostBackdoor, Lamporat); font-rendering trick bypassing AI security assistants |

**Landscape Summary (Batch 15, 2026-03-17):** The correlation engine processed 17 tier-1 reports across 2 batches. Cross-report analysis identified shared TTPs (T1204.001, T1190, T1059, T1027) linking Coruna iOS exploit kit activity with the Warlock ransomware attack, and connecting Boggy Serpens operations with broader Iranian cyber threat evolution. Sector-level correlation flagged overlapping government-sector targeting across IndoHaxSec, Boggy Serpens, and Warlock operations.

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala** (4 reports) — Pro-Palestinian hacktivist group conducting data leak operations against Israeli targets
- **Void Manticore** (4 reports) — Iranian threat actor linked to destructive wiping operations
- **Laundry Bear** (2 reports) — Russia-linked APT deploying DRILLAPP backdoor against Ukrainian entities
- **Hive0163** (2 reports) — Cybercrime group deploying AI-generated Slopoly malware with Interlock ransomware
- **Storm-2561** (2 reports) — Microsoft-tracked threat actor deploying Hyrax malware
- **COBALT MYSTIQUE** (2 reports) — Iranian cyber espionage group

### Malware Families

- **BeatBanker** (3 reports) — Banking trojan targeting financial institutions
- **Slopoly** (2 reports) — AI-generated malware used by Hive0163 in ransomware operations
- **HijackLoader** (2 reports) — Multi-stage loader used in infostealer campaigns
- **Vidar** (2 reports) — Infostealer distributed via compromised WordPress sites and fake CAPTCHAs
- **Coruna** (2 reports) — iOS web malware exploitation kit
- **Hyrax** (2 reports) — Malware associated with Storm-2561 operations
- **Getpass / MemFun / AppleChris** (2 reports each) — Malware families observed in correlated campaigns

### Vulnerabilities

No trending vulnerability entities returned by the pipeline for this period. Individual CVEs are covered in the Priority Intelligence Items section.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 18 | [link](https://msrc.microsoft.com) | CVE advisories including CVE-2026-3909 (ITW), CVE-2026-4105, CVE-2026-2673 |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | EU sanctions, LeakNet ransomware, font-rendering AI bypass |
| AlienVault | 7 | [link](https://otx.alienvault.com) | Boggy Serpens, Hydra Saiga, Vidar, Slopoly, Coruna IoCs |
| Unknown | 6 | — | Telegram-sourced intelligence (channel names redacted) |
| CISA | 4 | [link](https://www.cisa.gov) | Four ICS advisories: Schneider SCADAPack, Festo CODESYS, Siemens SICAM, Schneider EcoStruxure |
| SANS | 2 | [link](https://isc.sans.edu) | ISC Stormcast daily security podcast; IPv4-mapped IPv6 analysis |
| RecordedFutures | 2 | [link](https://www.recordedfuture.com) | Energy Department cyber strategy; Georgia man charged for crypto theft |
| Unit42 | 2 | [link](https://unit42.paloaltonetworks.com) | Boggy Serpens assessment; LLM prompt fuzzing research |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | AI agent integration guide |
| Sentinel One | 1 | [link](https://www.sentinelone.com/labs) | LABScon25 replay: $9B mobile threat landscape |
| Wired Security | 1 | [link](https://www.wired.com) | Sears AI chatbot data exposure |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Chrome and Edge to address CVE-2026-3909 (Skia OOB write, confirmed in-the-wild exploitation). Validate deployment via EDR software inventory queries within 24 hours.

- 🔴 **IMMEDIATE:** Notify OT/ICS teams of CISA advisories ICSA-26-076-01 and ICSA-26-076-02. Apply Schneider SCADAPack firmware 9.12.2 and Festo Automation Suite 2.8.0.138. Segment Modbus TCP traffic and disable unused debug services on affected RTUs.

- 🟠 **SHORT-TERM:** Ingest IOCs from Boggy Serpens, Hydra Saiga, DRILLAPP/Laundry Bear, and LeakNet campaigns into SIEM and EDR blocklists. Hunt for msedge.exe headless execution with disabled security flags, Rust-compiled binaries in temp directories, PowerShell-driven WMI lateral movement, and Deno runtime execution outside developer workstations.

- 🟠 **SHORT-TERM:** Brief analysts on the ClickFix social engineering technique now adopted by LeakNet and Hive0163. Create detection rules for DLL sideloading via jli.dll in C:\ProgramData\USOShared and for scripts named Romeo*.ps1 or Juliet*.vbs.

- 🟡 **AWARENESS:** The font-rendering attack demonstrated by LayerX bypasses AI security assistants including ChatGPT, Claude, Copilot, and Gemini. Remind teams that AI tools should not be the sole arbiter of whether a command or webpage is safe — manual inspection of source HTML remains essential.

- 🟢 **STRATEGIC:** The emergence of AI-generated malware (Slopoly by Hive0163) and AI-enhanced tooling (Boggy Serpens) signals a shift that will accelerate malware development cycles and complicate attribution. Evaluate detection strategies that focus on behavioural analysis rather than static signatures to stay ahead of increasingly ephemeral, AI-generated payloads.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 52 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
