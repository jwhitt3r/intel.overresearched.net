---
layout: post
title: "CTI Daily Brief: 2026-03-19 — Cisco FMC Zero-Day Exploited by Interlock Ransomware; CISA Adds Five KEVs; FBI Seizes Iran-Linked Handala Infrastructure"
date: 2026-03-20 21:06:00 +0000
description: "Forty-four reports processed across 10 sources. Dominant themes include active exploitation of Cisco FMC CVE-2026-20131 by Interlock ransomware, FBI takedown of Iran MOIS leak sites tied to Stryker healthcare attack, international disruption of four major IoT botnets, Oracle emergency RCE patch for Identity Manager, and CISA adding five actively exploited vulnerabilities to the KEV catalogue."
category: daily
tags: [cti, daily-brief, handala, interlock, beast-ransomware, cve-2026-20131, cve-2026-21992, purelog-stealer]
classification: TLP:CLEAR
reporting_period: "2026-03-19"
generated: "2026-03-20"
draft: true
severity: critical
report_count: 44
sources:
  - Microsoft
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - Wired Security
  - SANS
  - Elastic Security Labs
  - CISA
  - Krebs on Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-19 (24h) | TLP:CLEAR | 2026-03-20 |

## 1. Executive Summary

The pipeline processed 44 reports from 10 sources over the past 24 hours, with 11 rated critical and 10 rated high. The dominant theme is active exploitation of enterprise infrastructure: CISA issued an emergency directive requiring federal agencies to patch CVE-2026-20131 in Cisco Secure Firewall Management Center by Sunday after Amazon confirmed Interlock ransomware exploited it as a zero-day since January 2026. The FBI seized four domains tied to Iran's MOIS operating as "Handala," which disrupted healthcare operations at Stryker by wiping over 200,000 devices via Microsoft Intune. International law enforcement dismantled four IoT botnets (Aisuru, Kimwolf, JackSkid, Mossad) responsible for record-breaking DDoS campaigns. Oracle released an out-of-band patch for CVE-2026-21992 (CVSS 9.8), a pre-authentication RCE in Identity Manager. CISA added five actively exploited vulnerabilities to the KEV catalogue affecting Apple products, Craft CMS, and Laravel Livewire.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 11 | Cisco FMC zero-day (CVE-2026-20131); Oracle Identity Manager RCE (CVE-2026-21992); CISA KEV additions; IoT botnet takedowns; FBI/Iran MOIS domain seizures; AppArmor DFA validation flaw |
| 🟠 **HIGH** | 10 | Beast ransomware toolkit analysis; Tax-season BYOVD malvertising campaign; Police CSAM takedown (Operation Alice); AppArmor privilege escalation (CVE-2026-23268); Azure MCP EoP (CVE-2026-26118); Meta E2EE rollback coverage |
| 🟡 **MEDIUM** | 18 | Linux kernel CVEs (f2fs, dvb-core, io_uring); nghttp2 DoS; Microsoft March update breaking Teams/OneDrive; GSocket backdoor; TeamPCP container attack; data analyst extortion conviction |
| 🟢 **LOW** | 2 | CISO geopolitical guidance; Section 702 reauthorisation commentary |
| 🔵 **INFO** | 3 | ISC Stormcast; SANS diary; general advisories |

## 3. Priority Intelligence Items

### 3.1 Cisco Secure FMC Zero-Day Actively Exploited by Interlock Ransomware (CVE-2026-20131)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-cisco-flaw-by-sunday/)

CISA ordered FCEB agencies to patch CVE-2026-20131 in Cisco Secure Firewall Management Center by 22 March 2026. The vulnerability stems from insecure deserialization of user-supplied Java byte streams in the web management interface, enabling unauthenticated remote code execution as root. No workarounds exist. Amazon threat intelligence confirmed Interlock ransomware exploited this flaw as a zero-day since late January 2026 — more than a month before Cisco published the patch on 4 March. Interlock operators also employ ClickFix for initial access and deploy custom malware families NodeSnake and Slopoly. CISA added CVE-2026-20131 to the KEV catalogue, flagging it as used in ransomware campaigns.

MITRE ATT&CK: T1210 (Exploitation of Remote Services), T1059.001 (PowerShell)

> **SOC Action:** Immediately patch Cisco FMC to the latest release. If patching is not possible within 48 hours, isolate the FMC management interface from untrusted networks. Query SIEM for inbound connections to FMC web management ports (443/tcp) from external IPs since 25 January 2026. Hunt for NodeSnake and Slopoly indicators across endpoints.

### 3.2 FBI Seizes Iran MOIS "Handala" Leak Sites After Stryker Healthcare Attack

**Source:** [Recorded Future News](https://therecord.media/fbi-takes-down-leak-sites-iran-mois)

The FBI seized four domains — Justicehomeland[.]org, Handala-Hack[.]to, Karmabelow80[.]org, and Handala-Redwanted[.]to — linked to Iran's Ministry of Intelligence and Security (MOIS) operating under the moniker "Handala." The group weaponised Microsoft Intune's native device wipe feature to destroy data on over 200,000 Stryker devices across the U.S., Ireland, and India. The attack directly disrupted emergency medical services in Maryland, forcing hospitals to suspend connections to Stryker systems and revert to radio-based clinical communication. Handala also posted stolen data from Israeli government officials and the Sanzer Hasidic community (851 GB). The domains were additionally tied to MOIS operations against Albania dating to 2022.

MITRE ATT&CK: T1489 (Service Stop), T1485 (Data Destruction)

> **SOC Action:** Audit Microsoft Intune device compliance policies and restrict remote wipe permissions to named administrators with MFA. Block the four seized domains at DNS/proxy layers. Review conditional access policies to ensure Intune admin roles require phishing-resistant authentication. Healthcare organisations should verify Stryker system integrity per the vendor's latest customer advisory.

### 3.3 International Takedown of Aisuru, Kimwolf, JackSkid, and Mossad IoT Botnets

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/03/feds-disrupt-iot-botnets-behind-huge-ddos-attacks/), [Wired](https://www.wired.com/story/us-takes-down-botnets-used-in-record-breaking-cyberattacks/)

The DOJ, in coordination with Canadian and German law enforcement, dismantled infrastructure behind four IoT botnets that compromised over three million devices (routers, cameras). Aisuru issued over 200,000 attack commands, JackSkid over 90,000, and Kimwolf over 25,000. Kimwolf introduced a novel propagation mechanism allowing infection of devices behind internal networks, a technique subsequently copied by competing botnets. A 22-year-old Canadian and a 15-year-old German national are identified as suspected operators. The botnets were used for extortion-driven DDoS campaigns causing tens of thousands of dollars in losses per victim.

> **SOC Action:** Review IoT device firmware versions against vendor patch lists. Segment IoT networks from corporate infrastructure. Monitor for anomalous outbound traffic from IoT VLANs. If previously targeted by DDoS extortion from these botnets, coordinate with FBI for victim notification.

### 3.4 Oracle Identity Manager Emergency RCE Patch (CVE-2026-21992, CVSS 9.8)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/oracle-pushes-emergency-fix-for-critical-identity-manager-rce-flaw/)

Oracle released an out-of-band security update for CVE-2026-21992, a pre-authentication RCE vulnerability in Oracle Identity Manager (versions 12.2.1.4.0 and 14.1.2.1.0) and Oracle Web Services Manager (same versions). The flaw is remotely exploitable over HTTP with low complexity, requires no authentication or user interaction, and carries a CVSS v3.1 score of 9.8. Oracle has not confirmed in-the-wild exploitation but issued the patch through its emergency Security Alert programme reserved for critical or actively exploited flaws.

> **SOC Action:** Apply the Oracle Security Alert patch immediately for Identity Manager and Web Services Manager deployments. If patching is delayed, restrict network access to the Identity Manager console to trusted management networks only. Audit Identity Manager logs for anomalous HTTP requests to management endpoints.

### 3.5 PureLog Stealer Campaign Targets Healthcare, Government, and Education via Copyright Lures

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/69bd01b20154ae405e9187fe)

A multi-stage campaign delivers PureLog Stealer to healthcare, government, hospitality, and education sectors using localised copyright violation lures. The infection chain uses a Python-based loader followed by dual .NET loaders executing PureLog entirely in memory (fileless). The malware performs AMSI bypass, establishes registry persistence, captures screenshots, and fingerprints victims before exfiltrating credentials. Communication with PureLog infrastructure is confirmed at multiple C2 domains.

MITRE ATT&CK: T1059.001 (PowerShell), T1055 (Process Injection), T1547.001 (Registry Run Keys), T1027 (Obfuscated Files), T1113 (Screen Capture)

#### Indicators of Compromise
```
C2: 166.0.184[.]127
C2: 64.40.154[.]96
Domain: quickdocshare[.]com
Domain: dq.bestshoppingday[.]com
Domain: logs.bestsaleshoppingday[.]com
Domain: mh.bestshopingday[.]com
Domain: cdn.eideasrl[.]it
SHA256: 35efc4b75a1d70c38513b4dfe549da417aaa476bf7e9ebd00265aaa8c7295870
SHA256: 68c926af0d796a80fcaee24774b1ca0a2c393c3a0e30650c4d2d7965736043ca
SHA256: ac591adea9a2305f9be6ae430996afd9b7432116f381b638014a0886a99c6287
SHA256: e675bc054481bdca6f8cd1d561869e18712dc05a42e5c24b9add7679efc7faf6
```

> **SOC Action:** Block the listed IOCs at DNS, proxy, and EDR layers. Search email logs for copyright-themed lure attachments (ZIP files referencing "Alleged Violation of Intellectual Property Rights"). Hunt for PowerShell spawning .NET assemblies loaded from user temp directories. Monitor for anomalous registry Run key additions.

### 3.6 Beast Ransomware Toolkit Exposed via Open Directory

**Source:** [Team Cymru](https://www.team-cymru.com/post/beast-ransomware-server-toolkit-analysis)

Team Cymru identified an open directory on 5.78.84[.]144 (AS212317) hosting a complete Beast ransomware operator toolkit. Beast, a RaaS platform active since June 2024 and successor to Monster ransomware, resumed operations in January 2026 after pausing in November 2025. The toolkit includes Advanced IP Scanner, Mimikatz, LaZagne for credential theft, and tools for network mapping and data prioritisation. Beast avoids encrypting devices in CIS countries. The operator's toolkit reveals the full attack chain from reconnaissance through credential theft, lateral movement, and encryption.

MITRE ATT&CK: T1003 (OS Credential Dumping), T1021.001 (RDP), T1046 (Network Service Discovery), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)

#### Indicators of Compromise
```
C2: 5.78.84[.]144
SHA256: 2ce62601491549ab91c9517e0accf3286ed29976f6ec359d31ddc060a8d99eb3
SHA256: 479d0947816467d562bf6d24b295bf50512176a2d3d955b8f4d932aea2378227
SHA256: 812df0efea089b956d08352ff0a7e8789d43862dc3764f4441d4e1c1d1fb7957
SHA256: cc0680de960f3e1b727b61a42e59f9c282bd8e41fe20146ed191c7f4bf9283a7
```

> **SOC Action:** Block 5.78.84[.]144 and the listed file hashes. Hunt for Advanced IP Scanner and Mimikatz executions in EDR telemetry. Review RDP authentication logs for brute-force patterns from external sources. Ensure volume shadow copies and backup integrity are verified against ransomware tampering.

### 3.7 Tax-Season Malvertising Campaign with BYOVD EDR Killer

**Source:** [Huntress](https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill)

A large-scale malvertising campaign active since January 2026 targets U.S. taxpayers searching for W-2 and W-9 forms. Attackers abuse Google Ads with dual cloaking services (JustCloakIt, Adspect) to serve rogue ScreenConnect installers. The kill chain deploys a custom crypter ("FatMalloc") using a 2GB memory allocation to evade AV sandboxes, followed by "HwAudKiller" — a previously undocumented BYOVD payload abusing a signed Huawei audio driver to terminate Defender, Kaspersky, and SentinelOne processes from kernel mode. Post-EDR kill, attackers dump LSASS credentials and harvest network credentials via NetExec, consistent with a pre-ransomware or initial access broker playbook. Over 60 rogue ScreenConnect instances were observed across Huntress's customer base.

MITRE ATT&CK: T1204.001 (User Execution: Malicious Link), T1562.001 (Disable or Modify Tools), T1003.001 (LSASS Memory), T1547.006 (Kernel Modules)

#### Indicators of Compromise
```
Domain: anukitax[.]com
Domain: bringetax[.]com
Domain: fioclouder[.]com
Domain: friugrime[.]com
Domain: grinvan[.]com
Domain: gripsmonga[.]sbs
Cloaking: cdn.justcloakit[.]com
Cloaking: rpc.adspect[.]net
SHA256: 033f42102362a8d8d4bdba870599eb5e0c893d8fd8dd4bc2a4b446cbbeb59b99
SHA256: 5abe477517f51d81061d2e69a9adebdcda80d36667d0afabe103fda4802d33db
SHA256: 8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531
```

> **SOC Action:** Block the listed domains and file hashes. Monitor for ScreenConnect trial instances appearing on endpoints that did not request RMM tooling. Implement driver blocklist policies (WDAC/HVCI) to prevent loading of the abused Huawei audio driver. Alert on LSASS access patterns from non-standard parent processes.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased exploitation of vulnerabilities in critical infrastructure and government sectors | Oracle Identity Manager RCE; Cisco FMC zero-day; FBI/Iran MOIS takedown; CISA KEV additions |
| 🟠 **HIGH** | Rise in AI-assisted cyberattacks and evasion techniques | TP-Link Tapo C200 AI-assisted reversing; AI in malware analysis report; unwind metadata manipulation evasion |
| 🟠 **HIGH** | Sophisticated phishing and malware campaigns targeting key industries | Operation Alice CSAM takedown; tax-season malvertising with BYOVD; PureLog Stealer copyright lure campaign |
| 🟠 **HIGH** | Increased focus on vulnerabilities in Microsoft products and services | 19 Microsoft CVEs across kernel, Bing, Copilot, Azure, and Purview; March update breaking Teams/OneDrive |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala / MOIS** (14 reports) — Iran-linked group behind Stryker healthcare wiper attack; FBI seized four associated domains
- **Void Manticore** (5 reports) — Iran-nexus actor linked to destructive operations
- **APT28 / Fancy Bear** (7 reports combined) — Russia-linked espionage group; continued targeting of Ukrainian entities
- **Aisuru** (3 reports) — Botnet operator behind 200,000+ DDoS attack commands; infrastructure seized
- **JackSkid** (3 reports) — Botnet operator; 90,000+ DDoS attacks; internal network propagation
- **KimWolf** (2 reports) — Aisuru variant operator; novel IoT spreading mechanism
- **The Gentlemen** (1 report) — Ransomware group exploiting FortiOS/FortiProxy, leveraging Babuk and LockBit 5.0

### Malware Families

- **Slopoly** (4 reports) — Custom malware linked to Interlock ransomware operations
- **NodeSnake** (3 reports) — Custom RAT used by Interlock alongside Slopoly
- **Perseus** (3 reports) — Android malware targeting note-taking apps for data exfiltration
- **Beast** (2 reports) — RaaS platform (successor to Monster); toolkit exposed via open directory
- **Interlock** (2 reports) — Ransomware gang exploiting Cisco FMC zero-day since January
- **Medusa** (2 reports) — Ransomware family referenced in Gentlemen TTP analysis
- **PureLog Stealer** (1 report) — Info-stealer delivered via copyright lures targeting healthcare and government

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 15 | [link](https://msrc.microsoft.com/update-guide) | Linux kernel CVEs, Azure/Copilot/Bing/Purview vulnerabilities |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Primary coverage of Oracle RCE, Cisco FMC zero-day, botnet takedowns |
| Telegram (channel names redacted) | 6 | — | TP-Link research, metadata evasion, breach forum activity |
| AlienVault | 4 | [link](https://otx.alienvault.com) | PureLog Stealer IOCs, Gentlemen TTPs, Beast toolkit, tax malvertising |
| Recorded Future News | 4 | [link](https://therecord.media) | FBI/Iran MOIS takedown, AI music fraud, botnet disruption |
| Wired Security | 2 | [link](https://www.wired.com/category/security) | Botnet takedown coverage, Meta E2EE rollback analysis |
| SANS | 2 | [link](https://isc.sans.edu) | GSocket backdoor diary, daily stormcast |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | TeamPCP container attack detection engineering |
| CISA | 1 | [link](https://www.cisa.gov) | Five new KEV additions (Apple, Craft CMS, Laravel Livewire) |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | Definitive IoT botnet takedown reporting |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Cisco Secure Firewall Management Center (CVE-2026-20131) before the 22 March CISA deadline. Interlock ransomware has exploited this as a zero-day since January — every day unpatched is a day at risk. Isolate FMC management interfaces from untrusted networks if patching is delayed.

- 🔴 **IMMEDIATE:** Apply the Oracle out-of-band patch for CVE-2026-21992 (CVSS 9.8) on all Identity Manager and Web Services Manager instances. The pre-auth RCE requires no user interaction and is trivially exploitable over HTTP.

- 🟠 **SHORT-TERM:** Audit Microsoft Intune configurations following the Handala/MOIS attack on Stryker. Restrict remote wipe capabilities to named administrators with phishing-resistant MFA. Healthcare organisations should verify Stryker device integrity and segment clinical systems from corporate MDM infrastructure.

- 🟠 **SHORT-TERM:** Deploy IOCs from the PureLog Stealer, Beast ransomware, and tax-season malvertising campaigns across EDR, DNS, and proxy controls. Implement WDAC/HVCI driver blocklists to prevent BYOVD attacks using the Huawei audio driver identified by Huntress.

- 🟡 **AWARENESS:** CISA added five KEVs including Apple and Laravel Livewire vulnerabilities — verify patch status for CVE-2025-31277, CVE-2025-32432, CVE-2025-43510, CVE-2025-43520, and CVE-2025-54068 across the fleet.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 44 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
