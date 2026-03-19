---
layout: post
title: "CTI Daily Brief: 2026-03-18 — Handala/Stryker FBI Seizure, Cisco Firewall Zero-Day Added to KEV, SharePoint RCE Exploited in the Wild"
date: 2026-03-19 21:05:00 +0000
description: "67 reports processed across 12 sources. Dominant themes include active exploitation of Cisco FMC (CVE-2026-20131) and SharePoint (CVE-2026-20963) vulnerabilities, FBI seizure of Iran-linked Handala infrastructure after the Stryker wiper attack, and emergence of the Perseus Android banking trojan targeting note-taking apps. CISA added CVE-2026-20131 to the KEV catalogue and issued Intune hardening guidance."
category: daily
tags: [cti, daily-brief, handala, apt28, perseus, interlock, cve-2026-20131, cve-2026-20963]
classification: TLP:CLEAR
reporting_period: "2026-03-18"
generated: "2026-03-19"
draft: true
severity: critical
report_count: 67
sources:
  - Microsoft
  - CISA
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - Elastic Security Labs
  - Cisco Talos
  - SANS
  - Unit42
  - Sentinel One
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-18 (24h) | TLP:CLEAR | 2026-03-19 |

## 1. Executive Summary

The pipeline processed 67 reports from 12 sources over the past 24 hours, with 16 rated critical, 17 high, 25 medium, 3 low, and 6 informational. The dominant theme is active exploitation of enterprise software vulnerabilities: CISA added Cisco Secure Firewall Management Center CVE-2026-20131 to the KEV catalogue after Interlock ransomware exploited it as a zero-day since January, and Microsoft SharePoint CVE-2026-20963 is now confirmed exploited in the wild with a CISA remediation deadline of March 21. The FBI seized clearnet domains belonging to Iranian-linked hacktivist group Handala following the destructive Stryker wiper attack that reset over 200,000 devices via Microsoft Intune, prompting joint FBI/CISA guidance on Intune hardening. APT28 continues targeting Ukrainian government entities via a Zimbra XSS flaw (CVE-2025-66376), and a new Android banking trojan named Perseus is actively targeting note-taking applications to harvest credentials and recovery phrases.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 16 | Cisco FMC zero-day (CVE-2026-20131) in KEV; SharePoint RCE (CVE-2026-20963); Handala/Stryker FBI seizure; Ubiquiti UniFi account takeover; SILENTCONNECT loader; Perseus Android malware; ICS advisories (Schneider Electric, Mitsubishi, CTEK, IGL-Technologies) |
| 🟠 **HIGH** | 17 | APT28 Zimbra exploitation; Lazarus/Bitrefill breach; FBI/CISA Intune advisory; ransomware exfiltration playbook; SILENTCONNECT analysis; Cobra DocGuard malware; ICS advisory (Automated Logic) |
| 🟡 **MEDIUM** | 25 | Microsoft CVE advisories (pyOpenSSL, kernel); Schneider Electric Modicon controllers; AI agent security tradeoffs; AFD.SYS EDR bypass technique |
| 🟢 **LOW** | 3 | Supplementary vulnerability and threat intelligence reports |

## 3. Priority Intelligence Items

### 3.1 Cisco Firewall Zero-Day Exploited by Interlock Ransomware — Added to CISA KEV

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/03/19/cisa-adds-one-known-exploited-vulnerability-catalog), [The Record](https://therecord.media/cisco-ransomware-interlock-firewalls)

CISA added CVE-2026-20131 to the Known Exploited Vulnerabilities catalogue after confirming active exploitation. The vulnerability is a deserialization of untrusted data flaw in Cisco Secure Firewall Management Center (FMC) and Security Cloud Control (SCC). Amazon's CISO disclosed that the Interlock ransomware gang began exploiting this vulnerability as a zero-day on January 26 — over five weeks before Cisco's March 4 public disclosure. Interlock historically targets organisations that cannot tolerate operational downtime, including local governments, schools, and healthcare systems. Amazon discovered the exploitation through a misconfigured Interlock staging server containing custom malware, reconnaissance scripts, and ransom negotiation portals. Interlock has potential links to the Rhysida ransomware operation and typically operates during UTC+3 business hours.

> **SOC Action:** Immediately audit all Cisco FMC and SCC deployments for CVE-2026-20131. Apply the Cisco-released patch. Review FMC authentication logs for anomalous access patterns dating back to late January. Hunt for ConnectWise ScreenConnect and Volatility tool execution in environments where these are not sanctioned.

### 3.2 Microsoft SharePoint RCE Actively Exploited — CISA Deadline March 21

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/critical-microsoft-sharepoint-flaw-now-exploited-in-attacks/)

CVE-2026-20963, a critical deserialization vulnerability in Microsoft SharePoint, is confirmed exploited in the wild. The flaw enables unauthenticated remote code execution against SharePoint Enterprise Server 2016, Server 2019, and Subscription Edition. End-of-life versions (2007, 2010, 2013) are also vulnerable but no longer receive patches. CISA ordered FCEB agencies to remediate by March 21 and strongly urged all organisations to prioritise patching. MITRE ATT&CK: T1210 (Exploitation of Remote Services).

> **SOC Action:** Patch SharePoint servers to the January 2026 cumulative update immediately. For end-of-life SharePoint versions, initiate migration planning and apply network-level segmentation to isolate these servers. Monitor IIS logs on SharePoint servers for unusual POST requests to `/_layouts/` and `/_vti_bin/` endpoints.

### 3.3 FBI Seizes Handala Infrastructure After Stryker Wiper Attack — Joint FBI/CISA Intune Advisory

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-seizes-handala-data-leak-site-after-stryker-cyberattack/), [The Record](https://therecord.media/fbi-cisa-warn-of-microsoft-intune-risks-stryker), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-businesses-to-secure-microsoft-intune-systems-after-stryker-breach/)

The FBI seized two clearnet domains (`handala-redwanted[.]to`, `handala-hack[.]to`) used by the Handala hacktivist group, an Iranian-linked operation with possible ties to Iran's Ministry of Intelligence and Security (MOIS). The seizure follows the destructive attack on medical technology company Stryker, where the group compromised a Windows domain administrator account, created a Global Administrator account in Microsoft Intune, and issued remote wipe commands that factory-reset over 200,000 devices — including employee personal devices enrolled in Intune MDM. No malware was deployed; the attack leveraged legitimate Intune management capabilities. FBI and CISA released a joint advisory urging organisations to harden Intune configurations with role-based access controls, MFA via Entra ID, and dual-approval policies for high-impact actions such as device wiping. Handala has announced plans to rebuild infrastructure via Telegram.

> **SOC Action:** Review Microsoft Intune configurations against the new FBI/CISA guidance. Implement dual-approval requirements for bulk device actions (wipe, retire, reset). Audit Global Administrator account creation events in Entra ID. Verify that personal devices enrolled in MDM have appropriate wipe scope limitations.

### 3.4 APT28 Exploits Zimbra XSS to Harvest Ukrainian Government Credentials

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/russian-apt28-military-hackers-exploit-zimbra-flaw-in-ukrainian-govt-attacks/)

Russia's APT28 (Fancy Bear/Strontium) is exploiting CVE-2025-66376, a stored XSS vulnerability in Zimbra Collaboration Suite, to target Ukrainian government entities including the State Hydrology Agency. The attack — dubbed Operation GhostMail by Seqrite Labs — embeds obfuscated JavaScript directly in the HTML body of phishing emails with no attachments or links. When the email is opened in a vulnerable Zimbra webmail session, the script silently harvests credentials, session tokens, backup 2FA codes, browser-saved passwords, and 90 days of mailbox content, exfiltrating data over both DNS and HTTPS. CISA added CVE-2025-66376 to the KEV catalogue and ordered FCEB agencies to patch within two weeks. MITRE ATT&CK: T1566 (Phishing).

> **SOC Action:** Patch Zimbra Collaboration Suite to the November 2025 update or later. For organisations that cannot immediately patch, implement email gateway rules to strip or quarantine HTML emails with embedded JavaScript targeting Zimbra-specific DOM elements. Monitor DNS query logs for high-entropy subdomain queries indicative of DNS-based exfiltration.

### 3.5 Perseus Android Malware Targets Note-Taking Apps for Credential Theft

**Source:** [The Record](https://therecord.media/malware-streaming-apps-android), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-perseus-android-malware-checks-user-notes-for-secrets/)

A newly discovered Android banking trojan named Perseus is being distributed through fake IPTV streaming apps on unofficial stores, primarily targeting financial institutions in Turkey and Italy. Built on the leaked Cerberus codebase (via the Phoenix fork), Perseus abuses Accessibility Services to perform overlay attacks, keylogging, and full remote device control. Its most distinctive capability is systematically scanning note-taking applications — including Google Keep, Evernote, Samsung Notes, Microsoft OneNote, and Simple Notes — to extract stored passwords, recovery phrases, and financial data. The English-language variant shows indicators of AI-assisted development. The dropper bypasses Android 13+ sideloading restrictions and is shared with the Klopatra and Medusa malware families. MITRE ATT&CK: T1059 (Input Capture), T1008 (Data Exfiltration).

> **SOC Action:** Alert mobile security teams to block known Perseus dropper hashes. Update MDM policies to restrict sideloading on managed Android devices. Advise users against storing credentials, recovery phrases, or financial data in note-taking applications. Monitor for the Perseus dropper shared with Klopatra and Medusa campaigns.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Rise in Android malware leveraging note-taking apps for data exfiltration | Perseus malware across 3 reports; dropper shared with Klopatra/Medusa; targets Google Keep, Evernote, Samsung Notes |
| 🔴 **CRITICAL** | Exploitation of known vulnerabilities in enterprise software | CVE-2026-20131 (Cisco FMC) added to KEV; CVE-2026-20963 (SharePoint) exploited in the wild; Interlock zero-day exploitation since January |
| 🟠 **HIGH** | Increased targeting of healthcare and critical manufacturing sectors | Handala/Stryker wiper attack (200K+ devices); FBI/CISA Intune advisory; 5 ICS advisories for Schneider Electric and Mitsubishi Electric industrial equipment |
| 🟠 **HIGH** | State-sponsored actors leveraging sophisticated phishing and zero-days | APT28 Zimbra exploitation (Operation GhostMail); Lazarus/Bluenoroff Bitrefill breach; DPRK cryptocurrency targeting |
| 🟠 **HIGH** | Increased use of phishing for initial access across campaigns | SILENTCONNECT loader via fake invitations; APT28 HTML-only phishing; MFA bypass via adversary-in-the-middle techniques; 178% surge in fraudulent device registrations |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala** (6 reports) — Iranian-linked hacktivist group; FBI seized clearnet domains after Stryker wiper attack
- **APT28 / Fancy Bear** (4 reports) — Russian GRU-linked group exploiting Zimbra XSS against Ukrainian government
- **UNC6353** (4 reports) — Tracked threat cluster active across multiple campaigns
- **Interlock** (2 reports) — Ransomware gang exploiting Cisco FMC zero-day; linked to St. Paul, DaVita attacks
- **Lazarus / Bluenoroff** (2 reports) — North Korean group attributed to Bitrefill cryptocurrency platform breach
- **ShinyHunters** (2 reports) — Data breach and leak operations
- **LeakNet** (2 reports) — Data leak operations

### Malware Families

- **Perseus** (3 reports) — New Android banking trojan targeting note-taking apps; built on Cerberus/Phoenix codebase
- **SILENTCONNECT** (2 reports) — Multi-stage loader delivering ScreenConnect RMM via phishing; uses VBScript, in-memory PowerShell, PEB masquerading
- **ScreenConnect** (2 reports) — Legitimate RMM tool abused by SILENTCONNECT and Interlock for hands-on-keyboard access
- **Interlock ransomware** (2 reports) — Ransomware deployed via Cisco FMC zero-day exploitation
- **PlugX** (2 reports) — Chinese-attributed RAT observed in ongoing campaigns
- **Cerberus** (2 reports) — Legacy Android banking trojan; source code underpins Perseus

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 26 | [link](https://msrc.microsoft.com) | Bulk CVE advisories including pyOpenSSL, kernel, and romfs vulnerabilities |
| CISA | 9 | [link](https://www.cisa.gov) | KEV additions (CVE-2026-20131, CVE-2025-66376); 5 ICS advisories; Intune hardening guidance |
| BleepingComputer | 9 | [link](https://www.bleepingcomputer.com) | Primary coverage of Handala/Stryker, SharePoint exploitation, Ubiquiti, Perseus, APT28/Zimbra |
| Recorded Future News | 6 | [link](https://therecord.media) | Perseus malware analysis, Interlock/Cisco zero-day, FBI/CISA Intune advisory |
| AlienVault | 3 | [link](https://otx.alienvault.com) | SILENTCONNECT analysis, DTO malware, Cobra DocGuard targeting |
| Elastic Security Labs | 3 | [link](https://www.elastic.co/security-labs) | SILENTCONNECT technical deep-dive with IOCs and YARA rules |
| Cisco Talos | 2 | [link](https://blog.talosintelligence.com) | Identity-based attack trends (Year in Review); ransomware exfiltration playbook |
| SANS | 2 | [link](https://isc.sans.edu) | Supplementary vulnerability and threat analysis |
| Unit 42 | 2 | [link](https://unit42.paloaltonetworks.com) | AI use in malware development; AI agent security tradeoffs |
| Sentinel One | 1 | [link](https://www.sentinelone.com) | Threat intelligence reporting |
| Wired Security | 1 | [link](https://www.wired.com/category/security) | Security feature coverage |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Cisco Secure Firewall Management Center (CVE-2026-20131) and Microsoft SharePoint (CVE-2026-20963). Both are confirmed actively exploited and in the CISA KEV catalogue. SharePoint remediation deadline is March 21.

- 🔴 **IMMEDIATE:** Review and harden Microsoft Intune configurations per the joint FBI/CISA advisory. Implement dual-approval policies for device wipe and retire actions, enforce MFA on all Intune admin accounts via Entra ID, and audit Global Administrator account creation events.

- 🟠 **SHORT-TERM:** Patch Zimbra Collaboration Suite against CVE-2025-66376. Organisations with Zimbra webmail should deploy email gateway controls to detect HTML-embedded JavaScript execution and monitor for DNS-based data exfiltration patterns.

- 🟠 **SHORT-TERM:** Update Ubiquiti UniFi Network Application to version 10.1.89+ to address the maximum-severity path traversal vulnerability (CVE-2026-22557) enabling account takeover. Audit UniFi controller access logs for unauthorised file access attempts.

- 🟡 **AWARENESS:** Brief mobile security teams on the Perseus Android malware campaign. Reinforce user guidance against storing credentials or recovery phrases in note-taking apps, and ensure MDM policies restrict APK sideloading on managed devices.

- 🟢 **STRATEGIC:** Evaluate detection capabilities for living-off-the-land exfiltration techniques as documented in Cisco Talos's Exfiltration Framework. Shift from static IOC-based detection to behavioral baselining of cloud CLI tools, file synchronisation utilities, and managed file transfer platforms.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 67 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
