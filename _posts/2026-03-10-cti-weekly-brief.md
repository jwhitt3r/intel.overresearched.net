---
layout: post
title:  "CTI Weekly Brief: 10–16 March 2026 — Iran-Linked Wiper Devastates Stryker, Chrome Zero-Days Actively Exploited, FortiGate Intrusions Escalate"
date:   2026-03-17 00:07:00 +0000
description: "A high-tempo week dominated by Iran-linked Handala/Void Manticore wiper operations against medical technology giant Stryker, two actively exploited Chrome zero-days added to the CISA KEV catalogue, critical Veeam Backup & Replication RCE flaws, and ongoing FortiGate edge-device intrusions enabling deep Active Directory compromise."
category: weekly
tags: [cti, weekly-brief, handala, void-manticore, storm-2561, kadnap, cve-2026-3909, cve-2026-3910]
classification: TLP:CLEAR
reporting_period_start: "2026-03-10"
reporting_period_end: "2026-03-16"
generated: "2026-03-17"
draft: false
severity: "critical"
report_count: 325
sources:
  - Microsoft
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - CISA
  - SANS
  - Wired Security
  - Cisco Talos
  - Unit42
  - Elastic Security Labs
  - Schneier
  - Krebs on Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 10–16 March 2026 (7d) | TLP:CLEAR | 2026-03-17 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 325 reports from 14 sources during the week of 10–16 March 2026. Eighty reports were rated critical and 68 high, producing the most severe weekly distribution observed this quarter. The week was dominated by a single, high-impact event: the Iran-linked Handala group (assessed as a front for Void Manticore / MOIS) executed a destructive wiper attack against medical technology giant Stryker, claiming to have wiped more than 200,000 endpoints across 79 countries and exfiltrated 50 TB of data. The operation leveraged Microsoft Intune remote-wipe capabilities rather than traditional malware deployment, marking a significant evolution in destructive attack tradecraft.

Beyond the Stryker incident, Google released emergency patches for two actively exploited Chrome zero-days (CVE-2026-3909, CVE-2026-3910), both promptly added to the CISA KEV catalogue. CISA also ordered federal agencies to patch an actively exploited n8n workflow automation RCE flaw (CVE-2025-68613) and the Wing FTP Server vulnerability chain (CVE-2025-47813). Veeam disclosed four critical RCE vulnerabilities in Backup & Replication, a product historically targeted by ransomware operators. SentinelOne published a detailed analysis of FortiGate edge intrusions where attackers extracted service account credentials to enroll rogue domain workstations and achieve deep AD compromise. New malware families CastleRAT (abusing the Deno JavaScript runtime) and KadNap (a Kademlia-based botnet hijacking ASUS routers) emerged, while law enforcement disrupted the SocksEscort proxy network powered by AVRecon malware. Storm-2561 launched a credential-theft campaign using fake enterprise VPN sites impersonating Ivanti, Cisco, and Fortinet products.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 80 | Stryker wiper attack; Chrome zero-days (CVE-2026-3909/3910); Veeam RCE; n8n RCE; Wing FTP exploitation; Microsoft Patch Tuesday CVEs; FortiGate intrusions |
| 🟠 **HIGH** | 68 | Notepad++ supply-chain compromise; ICS/SCADA advisories (Siemens, Trane); phishing campaigns; AI-generated malware |
| 🟡 **MEDIUM** | 145 | Microsoft CVE advisories; Go stdlib vulnerabilities; SmartApeSG/Remcos RAT; DevTools and Clipboard policy issues |
| 🟢 **LOW** | 12 | Samsung compatibility issues; informational SANS stormcasts |

## 3. Priority Intelligence Items

### 3.1 Iran-Linked Handala/Void Manticore Wiper Attack on Stryker

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-offline-after-iran-linked-wiper-malware-attack/), [Krebs on Security](https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/), [The Record](https://therecord.media/stryker-cyberattack-iran-hackers)

Handala (Void Manticore, COBALT MYSTIQUE, Storm-1084/Storm-0842), an MOIS-affiliated threat actor, claimed a mass wiper attack against Stryker, a Fortune 500 medical technology company with $25 billion in annual revenue. The attackers claimed to have wiped over 200,000 systems, servers, and mobile devices across 79 countries and exfiltrated 50 TB of data. Employees reported corporate devices were remotely wiped via Microsoft Intune, Entra login pages were defaced with the Handala logo, and staff reverted to pen-and-paper workflows. The attack was framed as retaliation for a U.S. missile strike on an Iranian school.

Check Point Research published a detailed modus operandi analysis confirming Handala as a Void Manticore persona alongside Karma and Homeland Justice. The group relies on manual hands-on operations, off-the-shelf wipers, NetBird for traffic tunnelling, and newly observed AI-assisted PowerShell scripts for wiping activity (T1485, T1561.002, T1059.001, T1078.002).

Unit 42 issued a dedicated advisory on increased wiper risk from this cluster, recommending JIT access models, Microsoft Entra PIM, and multi-administrator approval for destructive Intune actions.

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

> **SOC Action:** Audit Microsoft Intune and Entra ID administrative roles immediately. Implement multi-administrator approval for remote wipe commands. Enable Entra PIM with JIT activation for Global Administrator and Intune Administrator roles. Monitor for mass device-wipe commands and login page modifications. Block the IOCs above at perimeter firewalls and EDR.

### 3.2 Google Chrome Zero-Days Actively Exploited (CVE-2026-3909, CVE-2026-3910)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/google/google-fixes-two-new-chrome-zero-days-exploited-in-attacks/), [CISA](https://www.cisa.gov/news-events/alerts/2026/03/13/cisa-adds-two-known-exploited-vulnerabilities-catalog)

Google released emergency out-of-band updates patching two high-severity Chrome zero-days confirmed exploited in the wild. CVE-2026-3909 is an out-of-bounds write in Skia (the 2D graphics library) that can lead to code execution. CVE-2026-3910 is an inappropriate implementation in the V8 JavaScript/WebAssembly engine. Patches were deployed for Chrome 146.0.7680.75/76 across Windows, macOS, and Linux. CISA added both to the KEV catalogue on 13 March. These are the second and third actively exploited Chrome zero-days of 2026.

> **SOC Action:** Verify all managed Chrome and Chromium-based browsers (including Edge) are updated to version 146.0.7680.75 or later. Query browser version telemetry in your asset management platform to identify unpatched endpoints. Prioritise patching within 48 hours per CISA BOD 22-01 guidance.

### 3.3 CISA Orders Patching of n8n RCE Flaw (CVE-2025-68613)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-n8n-rce-flaw-exploited-in-attacks/)

CISA added CVE-2025-68613 to its KEV catalogue after confirming active exploitation. The vulnerability resides in n8n's workflow expression evaluation system and allows authenticated attackers to execute arbitrary code with the privileges of the n8n process. n8n instances commonly store API keys, database credentials, OAuth tokens, and CI/CD secrets, making exploitation a pathway to full environment compromise. Shadowserver tracks over 40,000 unpatched instances exposed online, with 18,000+ in North America.

> **SOC Action:** Identify all n8n instances in the environment via asset inventory and Shodan/Censys queries. Upgrade to n8n v1.122.0 or later immediately. If patching is delayed, restrict workflow creation/editing permissions to trusted users and limit n8n network exposure to internal-only access.

### 3.4 Veeam Backup & Replication Critical RCE Vulnerabilities

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/veeam-warns-of-critical-flaws-exposing-backup-servers-to-rce-attacks/)

Veeam patched four critical RCE vulnerabilities (CVE-2026-21666, CVE-2026-21667, CVE-2026-21669, CVE-2026-21708) in Backup & Replication. Three allow low-privileged domain users to achieve RCE on backup servers in low-complexity attacks; the fourth allows a Backup Viewer to execute code as the postgres user. VBR servers are high-value ransomware targets — FIN7, Cuba, Akira, and Fog ransomware groups have all exploited previous VBR vulnerabilities. Patched versions: 12.3.2.4465 and 13.0.1.2067.

> **SOC Action:** Patch all Veeam Backup & Replication instances to 12.3.2.4465 or 13.0.1.2067 immediately. Monitor for exploit development by tracking Veeam-related activity on exploit-sharing forums. Review backup server network segmentation to ensure VBR servers are not exposed to general user segments.

### 3.5 FortiGate Edge Intrusions Leading to Deep AD Compromise

**Source:** [SentinelOne via AlienVault](https://www.sentinelone.com/blog/fortigate-edge-intrusions/)

SentinelOne's DFIR team reported multiple incidents throughout early 2026 where FortiGate NGFW appliances were compromised via CVE-2025-59718, CVE-2025-59719, and CVE-2026-24858. Attackers extracted configuration files containing service account credentials, then enrolled rogue workstations into Active Directory to establish deep persistence. Dwell time ranged from near-instantaneous to two months. The investigations highlighted a recurring theme of insufficient logging on perimeter appliances (T1078, T1136.002, T1003.003, T1021.001).

#### Indicators of Compromise
```
IP: 185.242.246[.]127
IP: 193.24.211[.]61
Domain: ndibstersoft[.]com
Domain: neremedysoft[.]com
```

> **SOC Action:** Audit all FortiGate appliances for current firmware versions and verify patches for CVE-2025-59718, CVE-2025-59719, and CVE-2026-24858 are applied. Rotate all service account credentials stored in FortiGate configurations. Enable full logging on perimeter devices and forward to SIEM. Hunt for rogue computer objects in AD that were not provisioned through standard workflows.

### 3.6 Storm-2561 Fake Enterprise VPN Campaign Distributes Hyrax Infostealer

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fake-enterprise-vpn-downloads-used-to-steal-company-credentials/)

Storm-2561 launched an SEO poisoning campaign creating spoofed VPN vendor sites impersonating Ivanti Pulse Secure, Cisco, Fortinet, Sophos, SonicWall, Check Point, and WatchGuard. Victims who search for VPN client downloads are redirected to fake sites hosting a ZIP archive containing a malicious MSI installer. The installer drops a Hyrax infostealer variant that captures VPN credentials, configuration data, and establishes persistence via RunOnce registry keys. The fake client displays an installation error, then redirects to the legitimate vendor site to reduce suspicion (T1566, T1547.001).

> **SOC Action:** Block known Storm-2561 domains at DNS and web proxy. Query EDR for `Pulse.exe` executing from `%CommonFiles%\Pulse Secure` and for `dwmapi.dll` or `inspector.dll` side-loading activity. Alert on RunOnce registry modifications in user temp directories. Remind users to download VPN clients only from authenticated internal portals.

### 3.7 CastleRAT: First Malware to Abuse the Deno JavaScript Runtime

**Source:** [AlienVault](https://otx.alienvault.com/pulse/69b14da6cb1bf921c7ac6d22)

CastleRAT is a newly observed malware family that abuses the Deno JavaScript runtime to execute entirely in memory, evading disk-based detection. The infection chain combines social engineering (ClickFix-style lure), steganography (payload hidden in a JPEG image), and obfuscated JavaScript. CastleRAT capabilities include host fingerprinting, keylogging, clipboard hijacking, digital identity theft, and audio/video surveillance (T1059.007, T1027, T1055, T1056.001, T1115, T1123, T1125).

#### Indicators of Compromise
```
C2: 23.94.145[.]120
Domain: serialmenot[.]com
Domain: dsennbuappec.zhivachkapro[.]com
SHA256: a4787a42070994b7f1222025828faf9b153710bb730e58da710728e148282e28
SHA256: bd8203ab88983bc081545ff325f39e9c5cd5eb6a99d04ae2a6cf862535c9829a
```

> **SOC Action:** Hunt for Deno runtime installations (`deno.exe` / `deno` binary) on endpoints where it is not part of the approved software catalogue. Monitor for JPEG files being read and decoded by scripting interpreters. Block the C2 infrastructure above. Alert on processes spawned by Deno that perform keylogging or clipboard access.

### 3.8 KadNap Botnet and SocksEscort Proxy Network Disruption

**Source:** [BleepingComputer (KadNap)](https://www.bleepingcomputer.com/news/security/new-kadnap-botnet-hijacks-asus-routers-to-fuel-cybercrime-proxy-network/), [BleepingComputer (SocksEscort)](https://www.bleepingcomputer.com/news/security/us-disrupts-socksescort-proxy-network-powered-by-linux-malware/)

Two related proxy-network stories emerged this week. KadNap, a new botnet discovered by Black Lotus Labs, has grown to 14,000 compromised ASUS routers since August 2025 using a custom Kademlia DHT protocol for decentralised C2. The botnet feeds the Doppelganger proxy service. Separately, U.S. and European law enforcement disrupted SocksEscort, a decade-old proxy network powered by AVRecon malware that maintained approximately 20,000 compromised Linux SOHO routers. The operation seized 34 domains, 23 servers, and froze $3.5M in cryptocurrency.

> **SOC Action:** Verify ASUS router firmware is current across all managed sites. Query network logs for connections to `212.104.141[.]140` (KadNap staging). Check for cron jobs running every 55 minutes on Linux-based edge devices. Review outbound proxy traffic patterns for indicators of residential proxy abuse.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased exploitation of vulnerabilities in widely used software platforms | CISA KEV additions for Chrome zero-days; Wing FTP exploitation chain |
| 🔴 **CRITICAL** | Rise in AI-generated malware targeting software vulnerabilities | AI/LLM-generated malware used to exploit React2Shell; VoidLink C2 implant |
| 🔴 **CRITICAL** | Targeting of critical infrastructure and healthcare sectors | Stryker wiper attack; Siemens ICS advisories; medical device disruption |
| 🔴 **CRITICAL** | State-backed actors targeting government and critical infrastructure | Iran-linked Stryker attack; Albania parliament email compromise; APT28 Ukraine espionage |
| 🔴 **CRITICAL** | Persistent cyber espionage in Eastern Europe | APT28 revives advanced malware for Ukraine surveillance; Covenant C2 variant deployment |
| 🟠 **HIGH** | Software supply-chain exploitation accelerating | Nation-state actors exploit Notepad++ supply chain; Chromium V8/WebView vulnerabilities |
| 🟠 **HIGH** | Phishing campaigns targeting enterprise credentials | Storm-2561 fake VPN campaign; Starbucks employee data breach |
| 🟠 **HIGH** | State-sponsored espionage targeting military sectors | China-based espionage against Southeast Asian military targets; FBI data surveillance increase |
| 🟠 **HIGH** | Industrial control systems and critical manufacturing under increased pressure | Siemens RUGGEDCOM, Heliox EV Chargers, SIDIS Prime; Trane Tracer SC; Inductive Automation Ignition |
| 🟠 **HIGH** | Exploitation of open-source vulnerabilities and tools | React2Shell active exploitation; Betterleaks secrets scanner emergence |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala / Void Manticore** (9 reports) — Iranian MOIS-affiliated actor behind Stryker wiper attack and ongoing destructive operations against Israel and U.S. targets
- **Storm-2561** (2 reports) — Threat actor conducting fake enterprise VPN credential-theft campaigns via SEO poisoning
- **APT28 / Fancy Bear / Sednit** (2 reports) — Russian GRU-linked group reviving advanced malware (BeardShell, Covenant variant) for Ukraine espionage
- **COBALT MYSTIQUE** (2 reports) — Alternate tracking name for Iran-linked cluster associated with Handala operations
- **OilRig** (1 report) — Iranian threat actor referenced in Handala modus operandi context
- **ShinyHunters** (1 report) — Financially motivated actor behind Telus Digital 1 PB data breach

### Malware Families

- **BeatBanker** (3 reports) — Banking trojan with multi-report coverage
- **Hyrax** (2 reports) — Infostealer variant distributed via fake VPN installers by Storm-2561
- **AVRecon** (2 reports) — Linux malware powering the disrupted SocksEscort proxy network
- **KadNap** (2 reports) — Kademlia-based botnet targeting ASUS routers for proxy network
- **BeardShell** (2 reports) — Advanced malware revived by APT28 for Ukraine operations
- **Covenant** (2 reports) — Customised open-source C2 framework deployed by APT28
- **COVERT RAT** (1 report) — Rust-based RAT targeting Argentina's judicial sector
- **CastleRAT** (1 report) — Novel RAT abusing Deno runtime for in-memory execution
- **ZeroCleare / Shamoon / Dustman** (1 report each) — Historic Iran-linked wiper families referenced in Handala TTP context

## 6. Source Distribution

| Source | Reports | Notes |
|--------|---------|-------|
| Microsoft | 163 | March Patch Tuesday CVE advisories dominate volume |
| BleepingComputer | 47 | Primary coverage of Stryker, Chrome zero-days, VPN campaign |
| RecordedFutures | 23 | Stryker confirmation and broader geopolitical context |
| AlienVault | 21 | COVERT RAT, CastleRAT, Handala TTP analysis, FortiGate intrusions |
| Unknown | 20 | Includes Telegram-sourced intelligence and unattributed reports |
| CISA | 13 | KEV additions for Chrome, Wing FTP, n8n; ICS advisories |
| SANS | 11 | ISC Stormcasts and guest diary entries |
| Wired Security | 7 | Iran traffic camera hacking, GPS attacks, AI scam coverage |
| Cisco Talos | 5 | Threat analysis and malware research |
| Unit42 | 5 | Handala/Void Manticore wiper risk advisory |
| Elastic Security Labs | 3 | Threat detection research |
| Schneier | 3 | Israel-Iran cyber operations commentary |
| Krebs on Security | 2 | In-depth Stryker/Handala reporting with Intune vector details |
| Upwind | 2 | Cloud security research |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit and harden Microsoft Intune and Entra ID administrative roles. Implement multi-administrator approval for remote-wipe commands and enable Entra PIM with JIT activation for all privileged roles. This directly addresses the Stryker attack vector.

- 🔴 **IMMEDIATE:** Patch all Chrome and Chromium-based browsers to version 146.0.7680.75+ within 48 hours to mitigate actively exploited zero-days CVE-2026-3909 and CVE-2026-3910. Validate patch status across the fleet via endpoint management telemetry.

- 🔴 **IMMEDIATE:** Upgrade Veeam Backup & Replication to version 12.3.2.4465 or 13.0.1.2067 to close four critical RCE vulnerabilities. VBR servers are proven ransomware targets — treat with the same urgency as domain controllers.

- 🟠 **SHORT-TERM:** Identify and patch all n8n instances (CVE-2025-68613) and Wing FTP Server instances (CVE-2025-47813 chain). Both are under active exploitation with CISA KEV deadlines. If immediate patching is infeasible, restrict network access and user permissions.

- 🟠 **SHORT-TERM:** Audit FortiGate NGFW firmware versions and rotate all service account credentials stored in appliance configurations. Enable comprehensive logging on all perimeter devices and hunt for rogue computer objects in Active Directory.

- 🟠 **SHORT-TERM:** Block Storm-2561 infrastructure at DNS and web proxy. Hunt for `Pulse.exe` in `%CommonFiles%\Pulse Secure` and `inspector.dll` side-loading. Remind users to download VPN clients exclusively from internal portals.

- 🟡 **AWARENESS:** Monitor for Deno runtime presence on endpoints as a potential CastleRAT delivery vector. Hunt for JPEG files being decoded by scripting interpreters and unexpected in-memory JavaScript execution.

- 🟢 **STRATEGIC:** Review MDM and endpoint management tool security posture across the organisation. The Stryker incident demonstrates that cloud management platforms (Intune, Workspace ONE, Jamf) can be weaponised for mass destruction if administrative controls are insufficient. Conduct a tabletop exercise simulating a hostile MDM takeover scenario.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 325 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
