---
layout: post
title:  "CTI Weekly Brief: 2026-07-13 to 2026-07-19 - Actively-exploited WordPress wp2shell RCE, CISA KEV pressure on SharePoint/Oracle/Fortinet, Windows privesc zero-days, and a sustained RaaS surge"
date:   2026-07-21 22:50:00 +0000
description: "500 reports across 15 sources: WordPress Core wp2shell RCE exploited to plant webshells (CISA KEV), CISA emergency patching of actively-exploited SharePoint, Oracle E-Business Suite and Fortinet FortiSandbox flaws, Windows local-privilege-escalation zero-days (LegacyHive, Narrator Braille, tcpip.sys), a Chromium V8 use-after-free batch, NATS Server auth-bypass trio, Zoom account takeover, a Siemens ROX II OT zero-day chain, and heavy ransomware volume from Qilin, The Gentlemen, Inc Ransom and DragonForce."
category: weekly
tags: [cti, weekly-brief, qilin, the-gentlemen, inc-ransom, wp2shell, cve-2026-63030, cve-2026-58635, chromium-v8]
classification: TLP:CLEAR
reporting_period_start: "2026-07-13"
reporting_period_end: "2026-07-19"
generated: "2026-07-21"
draft: false
severity: critical
report_count: 500
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - CISA
  - SANS
  - Wired Security
  - Schneier
  - Wiz
  - Unit42
  - Cisco Talos
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-13 to 2026-07-19 (7d) | TLP:CLEAR | 2026-07-21 |

## 1. Executive Summary

The pipeline processed 500 reports across 15 sources over the reporting period, with 35 rated critical and 280 rated high. Three storylines dominated the week. First, a run of confirmed in-the-wild exploitation forced multiple CISA advisories in quick succession: WordPress Core's "wp2shell" RCE suite (CVE-2026-63030 and CVE-2026-60137) was exploited to plant webshells and was added to CISA's Known Exploited Vulnerabilities catalogue, while CISA separately ordered federal agencies to patch actively-exploited flaws in on-premises SharePoint, the Oracle E-Business Suite, and Fortinet FortiSandbox. Second, Microsoft's July patch cycle surfaced a cluster of Windows local-privilege-escalation zero-days — LegacyHive (admin access on fully-patched systems), the Narrator Braille bug (CVE-2026-58635, standard user to SYSTEM), and an integer overflow in tcpip.sys (CVE-2026-58532) — alongside a Windows Terminal RCE (CVE-2026-59117) and an RDP information-disclosure flaw (CVE-2026-56171).

Third, ransomware volume remained the largest single driver of report count: RansomLook victim postings and CognitiveCTI correlation batches tracked sustained double-extortion activity from Qilin, The Gentlemen, Inc Ransom, DragonForce, Play, Nova, Safepay and Akira across manufacturing, healthcare, legal and financial-services targets. Additional critical items included a Chromium V8 out-of-bounds read/write (CVE-2026-15903) fronting a wider use-after-free browser batch, a trio of NATS Server authorization-bypass flaws (CVE-2026-58251/58252/58253), a Zoom account-takeover vulnerability, and a Siemens ROX II OT zero-day chain (CVE-2025-40947/40948/40949) enabling persistent root on industrial switches. Correlation analysis also flagged DPRK "Contagious Interview" activity delivered via SVG images and a GST-themed phishing chain dropping Remcos RAT against Indian businesses.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 35 | WordPress wp2shell RCE (exploited, KEV); SharePoint / Oracle EBS / Fortinet FortiSandbox (exploited); Windows privesc zero-days (LegacyHive, Narrator Braille, tcpip.sys); Chromium V8 UAF batch; NATS Server auth-bypass trio; Zoom account takeover; Siemens ROX II OT chain; Squid memory corruption; Windows Terminal RCE; SonicWall SMA1000 / Palo Alto VPN edge exploitation |
| 🟠 **HIGH** | 280 | RansomLook victim postings (Qilin, The Gentlemen, Inc Ransom, DragonForce, Play, Nova, Safepay, Akira); Chromium high-tier CVEs; Linux kernel & BusyBox heap/stack overflow batch (Microsoft feed); DPRK Contagious Interview & GST→Remcos phishing |
| 🟡 **MEDIUM** | 112 | Kernel hardening CVEs; regional advisories; software-development-tool abuse research |
| 🟢 **LOW** | 22 | Minor product bulletins and hardening notices |
| 🔵 **INFO** | 51 | Vendor commentary, retrospectives, and pipeline meta-reports |

_Counts reflect the CognitiveCTI weekly collection (rolling 7-day window aligned to the 2026-07-13 to 2026-07-19 reporting period). Where an item was first indexed at the window boundary, the in-period report is cited as the primary source._

## 3. Priority Intelligence Items

### 3.1 WordPress Core "wp2shell" RCE exploited to plant webshells; added to CISA KEV

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/), [CISA](https://www.cisa.gov/news-events/alerts/2026/07/21/cisa-adds-four-known-exploited-vulnerabilities-catalog)

The "wp2shell" vulnerability suite in WordPress Core — CVE-2026-63030 and CVE-2026-60137 — was exploited in the wild to deploy persistent webshells and install malicious plugins on compromised servers. Public exploit code is available, lowering the bar for opportunistic mass exploitation of internet-exposed sites. CISA added both CVEs to its Known Exploited Vulnerabilities catalogue. Given WordPress's install base, exposure is broad and cross-sector. Observed activity aligns with **T1190** (Exploit Public-Facing Application) and **T1505.003** (Server Software Component: Web Shell).

> **SOC Action:** Confirm all WordPress Core instances are patched to the fixed release. Hunt web roots for recently-created or modified PHP files outside normal deployment paths, and review the `wp-content/plugins` directory for plugins installed outside your change-management window. Query web-access logs for anomalous POST requests to admin/AJAX endpoints followed by requests to newly-created files, and alert on `www-data`/`php-fpm` processes spawning `sh`, `bash`, or `cmd.exe`.

### 3.2 CISA-flagged active exploitation: SharePoint, Oracle E-Business Suite, and Fortinet FortiSandbox

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-admins-to-patch-actively-exploited-sharepoint-flaws/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-oracle-flaw-by-saturday/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-feds-to-patch-exploited-fortinet-fortisandbox-flaws-by-sunday/)

CISA issued three back-to-back directives during the week. Attackers are actively exploiting three vulnerabilities in internet-exposed on-premises SharePoint Server to execute code remotely, escalate privileges, and steal data. CISA separately ordered federal agencies to patch a critical, actively-exploited Oracle E-Business Suite financial-application flaw by Saturday, and to remediate two exploited FortiSandbox vulnerabilities by Sunday — the latter allowing attackers to bypass security controls on the threat-detection platform itself. All three target high-value enterprise infrastructure with strong lateral-movement potential. Techniques align with **T1190** (Exploit Public-Facing Application) and **T1068** (Exploitation for Privilege Escalation).

> **SOC Action:** Treat all three as emergency-priority regardless of federal status. Inventory internet-exposed SharePoint, Oracle EBS, and FortiSandbox instances and validate patch level against the vendor bulletins. For SharePoint, hunt for `w3wp.exe` spawning `cmd.exe`/`powershell.exe` and unexpected `.aspx` files in layouts directories. Restrict management interfaces to VPN/jump-host only and review authentication logs on all three platforms for anomalous access since the start of the reporting period.

### 3.3 Windows local-privilege-escalation zero-days: LegacyHive, Narrator Braille, tcpip.sys

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/), [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59117), [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56171), Telegram (channel name redacted)

Microsoft's July cycle was accompanied by several Windows elevation-of-privilege zero-days. "LegacyHive" grants attackers administrative privileges on up-to-date Windows systems (exact root cause under investigation). CVE-2026-58635, the Windows Narrator Braille bug, escalates a standard user to SYSTEM by abusing the accessibility interface, bypassing traditional privilege-elevation defences. CVE-2026-58532, an integer overflow in tcpip.sys, could enable remote code execution via crafted packets. Two further critical items rounded out the Windows surface: CVE-2026-59117 (Windows Terminal integer-overflow RCE) and CVE-2026-56171 (RDP information disclosure). The Narrator Braille and tcpip.sys write-ups were circulated via Telegram OSINT, increasing exploitation risk. Techniques align with **T1068** (Exploitation for Privilege Escalation) and **T1548** (Abuse Elevation Control Mechanism).

> **SOC Action:** Prioritise the July Windows updates on all endpoints and RDP-exposed hosts. Until patched, monitor for `Narrator.exe` spawning child processes or loading unexpected DLLs, and for unexpected SYSTEM-level token assignments to interactive-session users. Restrict inbound RDP to VPN/gateway only and enforce Network Level Authentication. Watch EDR for anomalous crashes or driver faults in `tcpip.sys` that may indicate exploitation attempts.

### 3.4 Chromium V8 out-of-bounds read/write fronts a wider use-after-free browser batch

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15903)

CVE-2026-15903 is an out-of-bounds read and write in Chromium's V8 JavaScript engine, affecting both Google Chrome and Chromium-based Microsoft Edge, and can lead to arbitrary code execution. CognitiveCTI correlation batch #237 grouped it with a set of sibling use-after-free flaws — CVE-2026-15905 (Aura), CVE-2026-15904 (Ozone), and CVE-2026-15899 (CameraCapture) — under a single "exploitation of Chromium vulnerabilities affecting multiple sectors" trend. V8 memory-corruption bugs are historically favoured for drive-by and one-click exploitation. Techniques align with **T1203** (Exploitation for Client Execution) and **T1068** (Exploitation for Privilege Escalation).

> **SOC Action:** Force-update Chrome and Chromium-based Edge to the fixed builds via managed browser policy and verify rollout with your endpoint inventory rather than trusting auto-update alone. Prioritise workstations used for web browsing and any kiosk/shared systems. Where feasible, enable site isolation and block execution of downloaded content from browser temp directories.

### 3.5 NATS Server authorization-bypass trio (CVE-2026-58251 / 58252 / 58253)

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58251), [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58252), [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58253)

Three critical authorization-bypass vulnerabilities were disclosed in the NATS messaging server. CVE-2026-58251 allows an authorization bypass when subscribing to queues; CVE-2026-58252 bypasses subscription authorization via wildcard overlap; and CVE-2026-58253 is a Route API authentication bypass permitting manipulation of server routing configurations without valid credentials. NATS is widely embedded in cloud-native and microservice architectures, so exploitation could expose sensitive inter-service data or subvert message routing. Technique alignment: **T1190** (Exploit Public-Facing Application) and **T1078** (Valid Accounts, via authz bypass).

> **SOC Action:** Identify NATS deployments (including those bundled inside platform products) and update to the fixed server version. Ensure NATS listeners are not exposed to untrusted networks, enforce mTLS and account/permission scoping, and audit subject/queue subscriptions and route configurations for unexpected wildcard grants.

### 3.6 Zoom critical account-takeover vulnerability

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/zoom-warns-of-critical-account-takeover-vulnerability/)

Zoom disclosed a critical vulnerability in its Windows desktop client and SDK that could allow an unauthenticated party to take over accounts. Given Zoom's ubiquity in enterprise environments, successful account hijacking creates risk of meeting hijacking, social-engineering pivots, and data exposure.

> **SOC Action:** Push the fixed Zoom client version through software distribution and block launch of outdated clients where policy allows. Communicate to staff that updates should be applied immediately and remind users to report unexpected account-activity or session prompts.

### 3.7 Siemens ROX II OT zero-day trilogy enables persistent root on industrial switches

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/)

Unit 42 detailed a three-stage exploit chain against Siemens ROX II OT switches: arbitrary file disclosure (CVE-2025-40948), privilege escalation via command injection (CVE-2025-40947), and persistent root code execution (CVE-2025-40949). Chained together they yield full privilege escalation and durable root access on operational-technology network infrastructure — a high-consequence outcome for industrial and critical-infrastructure environments.

> **SOC Action:** Inventory Siemens ROX II devices and apply Siemens' firmware fixes on the vendor's ICS-CERT timeline. Ensure OT management interfaces are segmented from IT and internet exposure, restrict administrative access to a dedicated OT jump-host, and monitor for unexpected configuration changes or new root-level processes on affected switches.

### 3.8 Ransomware-as-a-Service surge: Qilin, The Gentlemen, Inc Ransom, DragonForce lead volume

**Source:** RansomLook victim-posting feed (via CognitiveCTI correlation batches #229–#237)

Ransomware activity was the single largest contributor to weekly report volume. Correlation analysis tracked sustained double-extortion campaigns: Inc Ransom against healthcare, legal and financial-services targets globally (correlation confidence 0.90); Qilin across insurance, education, manufacturing, healthcare, transportation and government; and further pressure from DragonForce, Play, Nova (the rebranded RALord operation), The Gentlemen, Safepay, Krybit and Akira. Pipeline-wide entity tracking placed The Gentlemen (97 reports), Qilin (89) and DragonForce (42) at the top of active threat actors. Common TTPs across these operations include **T1486** (Data Encrypted for Impact), **T1071** (Application Layer Protocol), and **T1566** (Phishing) for initial access.

> **SOC Action:** Prioritise the initial-access vectors these groups favour: patch internet-facing appliances (see 3.1–3.2, 3.5), enforce phishing-resistant MFA on all external access, and validate that offline, immutable backups exist and are restore-tested. Hunt for the double-extortion precursor pattern — bulk data staging/archiving and large outbound transfers to unfamiliar cloud storage — and ensure EDR is in block (not audit) mode on servers.

### 3.9 DPRK "Contagious Interview" and GST-themed Remcos RAT phishing campaigns

**Source:** CognitiveCTI correlation batch #237

Correlation analysis flagged two sophisticated social-engineering campaigns during the period. The North Korean "Contagious Interview" operation delivered malware hidden in SVG images, targeting developers through fake coding-interview lures to steal credentials. Separately, a multi-stage .NET infection chain used GST (tax) refund phishing to drop Remcos RAT against Indian businesses. Both chains shared **T1140** (Deobfuscate/Decode Files or Information) and **T1083** (File and Directory Discovery), with **T1566** (Phishing) as the entry vector.

> **SOC Action:** Alert developers to fake-recruiter and coding-interview lures, and treat unsolicited "take-home assignment" archives as hostile. Block or sandbox SVG attachments that contain embedded script, and hunt for `.NET` loaders spawning from user temp/Downloads directories and for Remcos-consistent C2 beaconing. Reinforce that finance/tax-refund emails with attachments should be verified out-of-band.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Rising webshell deployments exploiting WordPress vulnerabilities | wp2shell WordPress flaws; CISA Adds Four KEV (batch #241) |
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in VPN/edge appliances to deploy custom malware | SonicWall SMA1000 zero-days; Palo Alto VPN → Qilin (batches #231, #240) |
| 🔴 **CRITICAL** | Exploitation of Chromium vulnerabilities affecting multiple sectors | CVE-2026-15905 (Aura), CVE-2026-15904 (Ozone), CVE-2026-15899 (batch #237) |
| 🔴 **CRITICAL** | Software vulnerabilities exploited for privilege escalation and denial of service | Windows LegacyHive; Narrator Braille (CVE-2026-58635); Cloud Files mini-filter UAF (batch #236) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in critical manufacturing / infrastructure sectors | Siemens ROX II chain; AutomationDirect Productivity Suite (batch #234) |
| 🟠 **HIGH** | Increased exploitation of AI-infrastructure vulnerabilities by sophisticated actors | SANDWORM_MODE AI-toolchain supply-chain worm; AI-infra hacking tool (batch #241) |
| 🟠 **HIGH** | Inc Ransom double-extortion targeting healthcare, legal and financial services globally | reatile.co.za, v-silicon.com, FAST.COM.PH (batch #237) |
| 🟠 **HIGH** | Sophisticated phishing/malware campaigns targeting specific sectors | DPRK Contagious Interview (SVG); GST → Remcos RAT (batch #237) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (97 reports) — most active ransomware operator by volume; military, healthcare and manufacturing victims.
- **Qilin** (89 reports) — high-tempo RaaS across insurance, education, manufacturing, healthcare, transport and government; linked to Palo Alto VPN exploitation.
- **DragonForce** (42 reports) — sustained double-extortion across manufacturing, healthcare and logistics.
- **Akira** (26 reports) — continued cross-sector ransomware activity.
- **Nova** (18 reports) — rebranded RALord RaaS operation.
- **Inc Ransom** (18 reports) — healthcare, legal and financial-services focus (correlation confidence 0.90).
- **Safepay** (12 reports) — active double-extortion postings against European targets.
- **Anubis** (12 reports) — ransomware plus associated Android banking-trojan activity.
- **Krybit** (11 reports) — education and manufacturing sectors.
- **Chaos** (11 reports) — ongoing RaaS victim postings.

### Malware Families

- **RansomLook** (115 reports) — ransomware-tracking feed aggregating victim postings across families.
- **Akira ransomware** (14 reports) — payload behind Akira operations.
- **DragonForce ransomware** (14 reports) — payload behind DragonForce operations.
- **Chaos ransomware** (12 reports) — associated with the Chaos operation.
- **The Gentlemen ransomware** (12 reports) — payload behind the week's highest-volume operator.
- **Anubis** (11 reports) — ransomware and banking-trojan variants.
- **RALord / Nova** (10 reports) — RALord rebranded to Nova.
- **RaaS** (8 reports) — generic ransomware-as-a-service tooling references.

_Note: the vulnerability entity tracker returned only stale, single-count CVEs (CVE-2023/2024/2025 identifiers) for this window and is not representative of the week's activity; the CVEs of record for this period are those cited in Section 3._

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 183 | [link](https://msrc.microsoft.com/update-guide) | MSRC advisory feed; Linux/kernel and product CVEs, Chromium batch |
| RansomLook | 138 | [link](https://www.ransomlook.io/) | Ransomware victim-posting aggregation (Qilin, The Gentlemen, Inc Ransom, DragonForce) |
| BleepingComputer | 48 | [link](https://www.bleepingcomputer.com) | Primary coverage of wp2shell, CISA directives, Zoom, LegacyHive |
| AlienVault | 31 | [link](https://otx.alienvault.com) | OTX community threat intelligence |
| RecordedFutures | 23 | [link](https://www.recordedfuture.com) | Threat-intelligence reporting |
| Unknown | 11 | — | Includes Telegram-origin OSINT (URLs redacted per policy) |
| CISA | 11 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | KEV additions and federal patch directives |
| SANS | 9 | [link](https://isc.sans.edu) | Internet Storm Center diaries (WordPress exploitation, Patch Tuesday) |
| Wired Security | 8 | [link](https://www.wired.com/category/security/) | AI-infrastructure worm; automotive KARR device |
| Schneier | 6 | [link](https://www.schneier.com) | Security commentary and analysis |
| Wiz | 4 | [link](https://www.wiz.io/blog) | Cloud/AI security research (Red Agent business-logic findings) |
| Unit42 | 4 | [link](https://unit42.paloaltonetworks.com) | Siemens ROX II OT zero-day chain |
| HaveIBeenPwned | 4 | [link](https://haveibeenpwned.com) | Breach/credential exposure notifications |
| Upwind | 4 | [link](https://www.upwind.io) | Cloud runtime security research |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com) | Threat research and disclosures |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch WordPress Core against wp2shell (CVE-2026-63030, CVE-2026-60137) and hunt for webshells — both CVEs are in CISA KEV with public exploits (ref. 3.1).
- 🔴 **IMMEDIATE:** Remediate the actively-exploited SharePoint, Oracle E-Business Suite, and Fortinet FortiSandbox flaws under CISA directives; restrict their management interfaces to VPN/jump-host only (ref. 3.2).
- 🔴 **IMMEDIATE:** Deploy the July Windows updates and prioritise RDP-exposed hosts to close the LegacyHive, Narrator Braille (CVE-2026-58635), tcpip.sys (CVE-2026-58532), Windows Terminal (CVE-2026-59117) and RDP (CVE-2026-56171) issues (ref. 3.3).
- 🟠 **SHORT-TERM:** Force-update Chrome and Chromium-based Edge to close the V8 out-of-bounds and sibling use-after-free flaws (CVE-2026-15903 and batch), verified via endpoint inventory (ref. 3.4).
- 🟠 **SHORT-TERM:** Identify and patch NATS Server deployments and confirm listeners are not exposed to untrusted networks; audit wildcard subscription and route grants (ref. 3.5).
- 🟠 **SHORT-TERM:** Push the fixed Zoom Windows client and block outdated versions to prevent account takeover (ref. 3.6).
- 🟡 **AWARENESS:** Brief developers and finance staff on the DPRK "Contagious Interview" SVG lures and GST→Remcos phishing; sandbox script-bearing SVG attachments and hunt for .NET loaders in temp directories (ref. 3.9).
- 🟢 **STRATEGIC:** Harden against the dominant RaaS operators (Qilin, The Gentlemen, Inc Ransom, DragonForce) by closing edge-appliance exposure, enforcing phishing-resistant MFA, and maintaining restore-tested immutable backups; segment OT networks (Siemens ROX II) from IT (ref. 3.7, 3.8).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 500 reports processed across 13 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
