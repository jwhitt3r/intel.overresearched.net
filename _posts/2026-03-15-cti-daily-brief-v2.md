---
layout: post
title: "CTI Daily Brief: 2026-03-15 — CISA Adds Wing FTP Server to KEV; Iran-linked Handala Wipes Stryker Devices via Intune"
date: 2026-03-16 21:06:17 +0000
description: "35 reports processed across 10 sources. Dominant theme: Iranian state-aligned actors shifting to identity-based destruction, demonstrated by the Handala/Void Manticore wipe of ~80,000 Stryker devices via Microsoft Intune. CISA added CVE-2025-47813 (Wing FTP Server) to the KEV catalogue amid active exploitation. Multiple espionage campaigns observed from Russia-linked Laundry Bear and a China-nexus actor deploying PlugX in the Persian Gulf."
category: daily
tags: [cti, daily-brief, void-manticore, handala, cve-2025-47813, laundry-bear, storm-2561]
classification: TLP:CLEAR
reporting_period: "2026-03-15"
generated: "2026-03-16"
draft: true
report_count: 35
sources:
  - AlienVault
  - BleepingComputer
  - RecordedFutures
  - SANS
  - Elastic Security Labs
  - Schneier
  - Unit42
  - CISA
  - Wired Security
severity:
  critical: 5
  high: 12
  medium: 11
  low: 1
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-15 (24h) | TLP:CLEAR | 2026-03-16 |

## 1. Executive Summary

The pipeline processed 35 reports from 10 sources over the past 24 hours. The dominant theme is the continued fallout from Iran-linked threat actor Void Manticore (operating as Handala), which wiped approximately 80,000 Stryker corporate devices using Microsoft Intune remote-wipe commands — no malware deployed. CISA added CVE-2025-47813 (Wing FTP Server information disclosure) to its Known Exploited Vulnerabilities catalogue, citing active exploitation that can be chained with a critical RCE flaw (CVE-2025-47812). Russia-linked Laundry Bear (Void Blizzard) launched a new espionage campaign against Ukrainian organisations using the DrillApp backdoor delivered through Starlink-themed phishing lures. A China-nexus actor, possibly Mustang Panda, deployed a PlugX variant against Persian Gulf targets using conflict-themed social engineering. Five reports were rated critical, twelve high, and phishing remained the most prevalent attack technique across all reports (T1566, 13 mentions).

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 5 | CISA KEV addition (CVE-2025-47813); COVERT RAT targeting Argentina judiciary; Void Manticore/Handala TTP exposé; AI-enabled deepfake scam operations |
| 🟠 **HIGH** | 12 | Stryker Intune wipe attack; Iranian cyber evolution (Unit42); Laundry Bear/DrillApp espionage; GoPix banking Trojan; VIP_Keylogger MaaS; ClickFix variant; Operation CamelClone; Storm-2561 fake VPN campaign |
| 🟡 **MEDIUM** | 11 | UK Companies House data exposure; Warlock ransomware TTPs; China-nexus PlugX; Russian parking DDoS; Exchange Online outage; SANS /proxy/ SSRF scans |
| 🟢 **LOW** | 1 | Luxembourg court overturns Amazon GDPR fine |

## 3. Priority Intelligence Items

### 3.1 CISA Adds Wing FTP Server Flaw to KEV — Active Exploitation Confirmed

CISA added CVE-2025-47813 to the Known Exploited Vulnerabilities catalogue on March 16, warning that attackers actively exploit this information disclosure flaw in Wing FTP Server. The vulnerability allows low-privilege users to discover full installation paths via crafted UID cookies. Critically, it chains with CVE-2025-47812 (RCE) and CVE-2025-27889 (credential disclosure) to achieve full remote code execution. Proof-of-concept code has been public since June 2025. The patch has been available since Wing FTP Server v7.4.4 (May 2025). FCEB agencies have a two-week remediation deadline under BOD 22-01.

**MITRE ATT&CK:** T1210 (Exploitation of Remote Services)

> **SOC Action:** Inventory all Wing FTP Server instances. Confirm patching to v7.4.4+. If patching is not immediately possible, restrict network access to the web administration interface and monitor for anomalous UID cookie values exceeding normal length thresholds.

### 3.2 Void Manticore (Handala) Wipes ~80,000 Stryker Devices via Microsoft Intune

Iran-linked Void Manticore, operating under the Handala persona, compromised a Stryker Global Administrator account and created a new Global Admin to push remote-wipe commands through Microsoft Intune between 05:00–08:00 UTC on March 11. Approximately 80,000 devices were wiped. No malware or ransomware was deployed, and investigators found no evidence of data exfiltration. Stryker's medical devices were unaffected, but electronic ordering systems remain offline. The incident is being investigated by Microsoft DART and Palo Alto Unit 42.

Check Point Research published a detailed analysis of Void Manticore's TTPs, confirming MOIS affiliation and documenting the group's use of NetBird for traffic tunneling, AI-assisted PowerShell wiping scripts, and reliance on commercial VPNs and underground services for initial access. Unit42 published a strategic analysis framing this as an evolution from traditional MBR wipers (Shamoon, ZeroCleare) to identity weaponization — abusing MDM platforms as high-leverage attack vectors that bypass EDR telemetry entirely.

**MITRE ATT&CK:** T1078.002 (Valid Accounts: Domain Accounts), T1059.001 (PowerShell), T1485 (Data Destruction), T1561.002 (Disk Wipe), T1572 (Protocol Tunneling)

#### Indicators of Compromise
```
IP: 107.189.19[.]52
IP: 146.185.219[.]235
IP: 31.57.35[.]223
IP: 82.25.35[.]25
SHA256: 08b80ab6a6c4eca08e18096c9468fe0bd2e33fc23142730e59177e6fcd7c902d
SHA256: 1ab1586975779b7d1ce09315b1312b939a194de6df7c5e92aea4f963835f7b08
SHA256: d969ff9fe6099db8f6ef3977a849b1757aa221669387eb29a2c6c0ce4b4abe70
```

> **SOC Action:** Audit Global Administrator and Privileged Role assignments in Entra ID. Enable PIM (Privileged Identity Management) with just-in-time activation. Configure Intune conditional access policies to require phishing-resistant MFA for administrative actions. Alert on creation of new Global Administrator accounts and bulk device wipe commands in Intune audit logs. Hunt for NetBird installations (default service name `netbird`) across endpoints.

### 3.3 Russia-Linked Laundry Bear Deploys DrillApp Backdoor Against Ukraine

Laundry Bear (Void Blizzard), a Russia-linked espionage group active since 2024, launched a new campaign targeting Ukrainian organisations using phishing documents themed around Starlink terminal verification and the Come Back Alive charity. The DrillApp backdoor exploits Microsoft Edge browser permissions to access file systems, capture audio, record screens, and take webcam images. Malicious components are hosted on public text-sharing services. Lab52 researchers note the spyware appears to be in early development, suggesting experimentation with browser-based delivery to evade EDR.

**MITRE ATT&CK:** T1566 (Phishing), T1215 (Browser Extensions)

> **SOC Action:** Monitor for Microsoft Edge spawning child processes that access camera, microphone, or screen recording APIs outside normal browsing patterns. Block known C2 infrastructure at the proxy/firewall layer. Flag inbound emails referencing Starlink verification or Ukrainian charity themes for additional scrutiny.

### 3.4 COVERT RAT Targets Argentina's Judicial Sector

A multi-stage phishing campaign dubbed "Operation Covert Access" targets Argentina's judicial ecosystem with spear-phishing emails containing ZIP archives. The archive includes a weaponised LNK shortcut, BAT loader, and judicial-themed PDF decoy. The final payload is a Rust-based RAT with anti-VM, anti-sandbox, and anti-debugging capabilities that establishes resilient C2 channels and supports modular command execution.

**MITRE ATT&CK:** T1566 (Phishing), T1059 (Command and Scripting Interpreter)

#### Indicators of Compromise
```
C2: 181.231.253[.]69
SHA256: 10bbc5e192c3d01100031634d4e93f0be4becbe0a63f3318dd353e0f318e43de
SHA256: 37e6da4c813557f09fa2336b43c9fbb4633e562952f5113f6a6a8f3c226854eb
SHA256: 4612c90cdfb7e43b4e9afe2a37a82d8b925bab3fd3838b24ec73b0e775afdb75
SHA256: 6ae4222728240a566a1ca8c8873eab3b0659a28437877e4450808264848ab01e
```

> **SOC Action:** Block the C2 IP at the firewall. Add the SHA256 hashes to EDR deny lists. For organisations with presence in Latin American judicial sectors, increase scrutiny on inbound emails containing ZIP attachments with LNK files. Monitor for BAT file execution from user temp directories.

### 3.5 Storm-2561 Distributes Fake VPN Clients via SEO Poisoning

Storm-2561 leverages SEO poisoning to rank malicious domains impersonating enterprise VPN products (FortiClient, Cisco Secure Client, Check Point VPN, Ivanti, SonicWall, Sophos Connect). Victims download trojanised MSI installers that deploy the Hyrax malware, harvesting VPN credentials and exfiltrating data to attacker-controlled infrastructure. The campaign uses stolen code-signing certificates and GitHub repositories for hosting.

**MITRE ATT&CK:** T1566 (Phishing), T1553.002 (Code Signing), T1056.001 (Keylogging), T1574.002 (DLL Side-Loading)

#### Indicators of Compromise
```
C2: 194.76.226[.]93
Domain: checkpoint-vpn[.]com
Domain: cisco-secure-client[.]es
Domain: forticlient-vpn[.]de
Domain: forticlient-vpn[.]fr
Domain: forticlient-vpn[.]it
Domain: ivanti-pulsesecure[.]com
Domain: ivanti-vpn[.]org
Domain: sophos-connect[.]org
Domain: vpn-fortinet[.]com
```

> **SOC Action:** Block the listed domains at DNS/proxy. Alert on MSI installations from user download directories that impersonate VPN clients. Verify internal VPN client distribution is controlled through an approved software repository — not public search engines. Review web proxy logs for connections to the listed domains.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Increased phishing activities via social media platforms | Telegram channels promoting phishing and breach forum activity |
| 🟠 **HIGH** | Increased exploitation of open-source vulnerabilities and tools | React2Shell active compromise; Betterleaks scanner emergence |
| 🟠 **HIGH** | Increased exploitation of critical vulnerabilities in enterprise sectors | Windows 11 RRAS RCE hotpatch; breach forum rank transfers |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Void Manticore / Handala** (7 reports) — Iranian MOIS-affiliated destructive wiper operator; expanded targeting to U.S. enterprises
- **Storm-2561** (2 reports) — SEO poisoning campaign distributing fake VPN clients for credential theft
- **Laundry Bear / Void Blizzard** (1 report) — Russia-linked espionage group targeting Ukraine with DrillApp backdoor
- **Mustang Panda** (possible, 1 report) — China-nexus actor deploying PlugX in Persian Gulf region

### Malware Families

- **Hyrax** (2 reports) — Credential-stealing malware distributed via fake VPN installers by Storm-2561
- **COVERT RAT** (1 report) — Rust-based RAT with advanced anti-analysis targeting Argentina judiciary
- **DrillApp** (1 report) — Browser-based spyware exploiting Edge permissions for espionage
- **GoPix** (1 report) — Banking Trojan targeting Brazilian Pix payment systems via malvertising
- **VIP_Keylogger** (1 report) — MaaS keylogger using steganography and process hollowing
- **ClickFix** (1 report) — New variant using network drive mapping instead of PowerShell/mshta
- **PlugX** (1 report) — China-nexus backdoor variant with HTTPS C2 and DNS-over-HTTPS
- **HOPPINGANT** (1 report) — JavaScript loader used in Operation CamelClone espionage campaign

## 6. Source Distribution

| Source | Reports | Notes |
|--------|---------|-------|
| AlienVault | 10 | OTX pulses covering COVERT RAT, GoPix, VIP_Keylogger, ClickFix, CamelClone, Storm-2561, Handala, PlugX, IPv6 phishing |
| BleepingComputer | 7 | CISA KEV, Stryker attack, Exchange outage, Companies House flaw, Samsung app issue, Shadow AI, ChatGPT ads |
| Unknown | 6 | Telegram channel monitoring (breach forums, dark feed) |
| RecordedFutures | 4 | Stryker impact, Laundry Bear espionage, Russian parking DDoS, Amazon GDPR fine |
| SANS | 2 | /proxy/ SSRF scan analysis, ISC Stormcast podcast |
| Elastic Security Labs | 2 | AI agent skills for security environment provisioning |
| Unit42 | 1 | Iranian cyber threat evolution analysis |
| CISA | 1 | KEV catalogue addition (CVE-2025-47813) |
| Wired Security | 1 | AI face model deepfake scam operations |
| Schneier | 1 | Canadian sovereign AI compute strategy commentary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Wing FTP Server to v7.4.4+ across all environments. If unpatched instances remain, isolate the web administration interface from the internet. CISA's BOD 22-01 deadline is two weeks for FCEB agencies. (Ref: §3.1)

- 🔴 **IMMEDIATE:** Audit all Global Administrator and Privileged Role accounts in Microsoft Entra ID. Enable Privileged Identity Management (PIM) with just-in-time activation. Configure alerts on new Global Admin creation and bulk Intune device wipe commands. Review Conditional Access policies to require phishing-resistant MFA for all administrative actions. (Ref: §3.2)

- 🟠 **SHORT-TERM:** Block Storm-2561 infrastructure (fake VPN domains and C2 IPs listed in §3.5) at DNS and web proxy layers. Ensure enterprise VPN clients are distributed exclusively through approved internal channels, not public search engine downloads.

- 🟠 **SHORT-TERM:** Ingest IOCs from COVERT RAT (§3.4), ClickFix (new variant using network drive mapping via `net use` to WebDAV shares), and VIP_Keylogger campaigns into EDR and SIEM detection rules. Monitor for BAT/CMD execution from user temp directories and `net use` commands mapping external WebDAV shares.

- 🟡 **AWARENESS:** Iranian state-aligned actors are shifting from custom wiper binaries to identity-based destruction via MDM platforms. SOC teams should treat MDM administrative actions (Intune, JAMF, Workspace ONE) as high-fidelity signals and integrate MDM audit logs into SIEM monitoring. (Ref: §3.2, Unit42 analysis)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 35 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
