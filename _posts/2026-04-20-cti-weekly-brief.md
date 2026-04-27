---
layout: post
title:  "CTI Weekly Brief: 2026-04-20 to 2026-04-26 - Three CISA KEV additions, ArcaneDoor returns to Cisco Firepower, Qilin RaaS dominates the leak-site economy"
date:   2026-04-27 09:00:00 +0000
description: "611 reports processed across 14 correlation batches. UAT-4356 (ArcaneDoor) deploys FIRESTARTER on Cisco Firepower devices; CISA KEV additions for Microsoft Defender BlueHammer, Cisco SD-WAN, and Apache ActiveMQ; Microsoft ships out-of-band ASP.NET Core fix; Qilin, Lockbit5, and Inc Ransom drive a sustained leak-site surge."
category: weekly
tags: [cti, weekly-brief, uat-4356, qilin, shai-hulud, cve-2026-33825, cve-2026-34197]
classification: TLP:CLEAR
reporting_period_start: "2026-04-20"
reporting_period_end: "2026-04-26"
generated: "2026-04-27"
draft: false
severity: critical
report_count: 611
sources:
  - Microsoft
  - BleepingComputer
  - Cisco Talos
  - Unit42
  - AlienVault
  - CISA
  - RecordedFutures
  - SANS
  - Schneier
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-20 to 2026-04-26 (7d) | TLP:CLEAR | 2026-04-27 |

## 1. Executive Summary

The pipeline ingested **611 reports across 14 correlation batches** for the week of 20–26 April 2026, with 32 rated critical and 320 rated high. Three vulnerabilities were added to the CISA Known Exploited Vulnerabilities (KEV) catalogue inside the period: **CVE-2026-33825 ("BlueHammer")** in Microsoft Defender, **CVE-2026-20133** in Cisco Catalyst SD-WAN Manager, and **CVE-2026-34197** in Apache ActiveMQ — the latter exposing roughly 6,400 internet-facing servers. Microsoft also issued an out-of-band fix for a critical ASP.NET Core Data Protection regression (**CVE-2026-40372**) that allows authentication-cookie forgery and SYSTEM-level escalation, and Shadowserver reported more than 1,300 SharePoint servers still unpatched against the actively exploited **CVE-2026-32201** spoofing flaw.

State-sponsored activity returned to perimeter devices: Cisco Talos attributed continued exploitation of **CVE-2025-20333** and **CVE-2025-20362** in Cisco Firepower/ASA appliances to **UAT-4356** (the ArcaneDoor actor), which is implanting the new **FIRESTARTER** backdoor inside the LINA process. Unit 42 published a landscape view of the post-Shai-Hulud npm ecosystem, documenting wormable token theft, CI/CD persistence, and dormant-dependency staging across the **TeamPCP**-attributed @bitwarden/cli compromise. AlienVault detailed a destructive **Lotus Wiper** campaign against Venezuela's energy sector. The ransomware leak-site economy stayed at high volume, with **Qilin** (69 reports), **The Gentlemen** (58), **Coinbase Cartel** (38), **DragonForce** (28), and a freshly active **Lockbit5** branch driving most of the named victim posts. The dominant theme of the week is converging pressure on perimeter, identity, and software-supply-chain trust — multiple unauthenticated RCE/escalation paths are being weaponised within days of disclosure.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 32 | UAT-4356/FIRESTARTER on Cisco Firepower; BlueHammer (CVE-2026-33825); Apache ActiveMQ (CVE-2026-34197); Cisco SD-WAN (CVE-2026-20133); ASP.NET Core (CVE-2026-40372); SharePoint (CVE-2026-32201); Breeze Cache (CVE-2026-3844); Lotus Wiper; npm Shai-Hulud landscape; multiple Microsoft kernel/BPF/ext4 CVEs |
| 🟠 **HIGH** | 320 | Sustained Qilin, Lockbit5, Inc Ransom, M3rx, DragonForce, Medusa, Tridentlocker, PEAR leak-site activity; Udemy ShinyHunters breach (1.4M accounts); ASA/FTD privilege-escalation chain reporting |
| 🟡 **MEDIUM** | 115 | Phishing TTP correlation across leak-site posts; broader OS/library kernel disclosures |
| 🟢 **LOW** | 38 | Lower-confidence parser-derived RansomLook records |
| 🔵 **INFO** | 106 | Telemetry, defender-product policy and product-update notes |

## 3. Priority Intelligence Items

### 3.1 UAT-4356 (ArcaneDoor) deploys FIRESTARTER backdoor on Cisco Firepower devices

**Source:** [Cisco Talos](https://blog.talosintelligence.com/uat-4356-firestarter/)

Cisco Talos reports continued exploitation of **CVE-2025-20333** and **CVE-2025-20362** in Cisco Firepower/ASA/FTD running FXOS by **UAT-4356**, the same state-sponsored actor previously attributed to the 2024 ArcaneDoor campaign targeting network perimeter devices for espionage. The actor implants **FIRESTARTER**, a backdoor that runs arbitrary shellcode inside the LINA process by replacing a hardcoded handler-function offset and parsing WebVPN XML requests for a magic-byte prefix. Persistence is established by manipulating the Cisco Service Platform mount list (`CSP_MOUNT_LIST`) so that the implant copies itself to `/usr/bin/lina_cs` and executes during graceful reboot, then restores the original mount list after re-injection. FIRESTARTER significantly overlaps with RayInitiator's Stage-3 shellcode handler. A hard power cycle is sufficient to remove the transient implant — graceful reboots are not.

Affected: Cisco ASA and FTD appliances on FXOS. MITRE ATT&CK: **T1071** (Application Layer Protocol), **T1105** (Ingress Tool Transfer), **T1543** (Boot/Logon Autostart). Sectors: government, telecommunications, defence — consistent with prior ArcaneDoor targeting.

> **SOC Action:** Patch Cisco ASA/FTD/Firepower to the fixed FXOS train per Cisco's PSIRT advisory for CVE-2025-20333/20362. Hunt for unexpected reboots, modifications to `/opt/cisco/platform/logs/var/log/svc_samcore.log` or `/usr/bin/lina_cs`, and any LINA-process anomalies. Where supported, perform a hard power cycle (not graceful reboot) on suspect devices and re-image from known-good firmware. Capture and inspect `CSP_MOUNT_LIST` and `CSP_MOUNTLIST.tmp` artefacts. Treat any WebVPN endpoint receiving anomalous XML traffic as suspicious.

### 3.2 CISA KEV: Microsoft Defender "BlueHammer" privilege-escalation exploited as zero-day

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-microsoft-defender-flaw-exploited-in-zero-day-attacks/), [AlienVault — RedSun PoC](https://otx.alienvault.com/pulse/69e739ee02f0f88b6f9e017a)

CISA added **CVE-2026-33825** (BlueHammer) to the KEV catalogue and ordered FCEB agencies to patch by **7 May 2026**. The flaw is an insufficient-granularity-of-access-control weakness in Microsoft Defender that allows a low-privileged local user to obtain SYSTEM. Microsoft patched it on 14 April Patch Tuesday after the "Chaotic Eclipse" researcher published proof-of-concept code — alongside companion bugs **RedSun** (a second Defender LPE PoC, `RedSun.exe`) and **UnDefend** (blocks Defender definition updates). Huntress observed hands-on-keyboard exploitation tied to Russian-geolocated infrastructure pivoting through compromised FortiGate SSL VPN access. The RedSun PoC abuses Defender remediation logic for cloud-tagged files combined with filesystem primitives to overwrite protected paths under `C:\Windows\System32`, achieving SYSTEM-level RCE without admin rights or kernel exploits.

#### Indicators of Compromise

```
SHA-256 (RedSun.exe): 57a70c383feb9af60b64ab6768a1ca1b3f7394b8c5ffdbfafc8e988d63935120
TTPs: T1068 (Privilege Escalation), T1222 (File/Directory Permissions Mod), T1574 (Hijack Execution Flow)
```

> **SOC Action:** Apply the April 2026 Patch Tuesday cumulative update to all Windows endpoints. Verify Defender platform/engine versions and force-update where stale. EDR-hunt for unsigned binaries written to `C:\Windows\System32\` by non-installer processes, and for Defender remediation events that are followed by privilege-escalation indicators. Hash-block the published RedSun PoC SHA-256. Review FortiGate SSL VPN access logs for unusual sources, especially Russian-geolocated IPs, and rotate any credentials used over those sessions.

### 3.3 CISA KEV: Cisco Catalyst SD-WAN Manager information disclosure (CVE-2026-20133)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-new-sd-wan-flaw-as-actively-exploited-in-attacks/)

CISA added **CVE-2026-20133** in Cisco Catalyst SD-WAN Manager (formerly vManage) to KEV on 21 April and gave FCEB agencies until 24 April to remediate. The flaw is an unauthenticated information disclosure caused by insufficient file-system access restrictions on the management API; an attacker can read sensitive data from the underlying OS without credentials. Catalyst SD-WAN Manager can administer up to 6,000 SD-WAN devices from a single dashboard, so disclosure of credentials, certificates, or topology data from this plane can enable substantial follow-on access. Cisco patched the bug in February but had not, at the time of CISA's notice, confirmed in-the-wild exploitation; CISA's KEV addition asserts evidence of active abuse. Two related February-patched flaws (CVE-2026-20128 and CVE-2026-20122) are also being exploited.

> **SOC Action:** Apply Cisco's February 2026 Catalyst SD-WAN Manager patches immediately. Restrict management-API exposure to dedicated jump hosts and management VLANs only. Audit recent API access logs for unauthenticated or anomalous reads of configuration files, and rotate any credentials, PSKs, or certificates that were stored or exported through vManage during the exposure window. Apply CISA Emergency Directive 26-03 hunt-and-hardening guidance for Cisco SD-WAN devices.

### 3.4 CISA KEV: Apache ActiveMQ code injection (CVE-2026-34197) — 6,400 exposed servers

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/actively-exploited-apache-activemq-flaw-impacts-6-400-servers/)

Shadowserver identified **6,400+ internet-exposed Apache ActiveMQ servers** vulnerable to **CVE-2026-34197**, a code-injection flaw in the broker that allows authenticated attackers to execute arbitrary code. Distribution skews to Asia (2,925), North America (1,409), and Europe (1,334). The bug — discovered by Horizon3's Naveen Sunkavally with assistance from an AI assistant after sitting undisclosed for 13 years — was patched 30 March 2026 in ActiveMQ Classic 6.2.3 and 5.19.4. CISA added it to KEV with an FCEB remediation deadline of 30 April. ActiveMQ has prior history as a ransomware target (CVE-2023-46604 was used by TellYouThePass), making this a high-probability follow-up vector.

#### Indicators of Compromise

```
Hunt string: brokerConfig=xbean:hxxp://
Internal transport: vm:// connections from unusual sources
TTPs: T1059 (Command/Scripting Interpreter), T1190 (Exploit Public-Facing App)
```

> **SOC Action:** Upgrade ActiveMQ Classic to 6.2.3 or 5.19.4. Search broker logs for connections using the internal `vm://` transport with `brokerConfig=xbean:http://` query parameters, and any anomalous spawning of child processes from the Java broker JVM. Restrict the management/admin port to the management network, enforce authentication, and confirm WAF/IDS signatures for CVE-2026-34197 are deployed.

### 3.5 Microsoft ships out-of-band ASP.NET Core fix (CVE-2026-40372)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-emergency-security-updates-for-critical-aspnet-flaw/)

Microsoft released emergency updates for a critical ASP.NET Core privilege-escalation vulnerability, **CVE-2026-40372**, in the Data Protection cryptographic APIs. A regression introduced in `Microsoft.AspNetCore.DataProtection` packages 10.0.0 through 10.0.6 caused the managed authenticated encryptor to compute the HMAC validation tag over the wrong bytes and discard the result. An unauthenticated attacker can forge payloads that pass DataProtection authenticity checks and decrypt previously protected payloads — including auth cookies, antiforgery tokens, TempData, and OIDC state — and may impersonate privileged users to mint legitimately signed tokens (session refresh, API keys, password-reset links). Tokens minted during the vulnerable window remain valid after upgrade unless the DataProtection key ring is rotated. The fix is in 10.0.7. MITRE ATT&CK: **T1552.001** (Credentials in Files), **T1078** (Valid Accounts).

> **SOC Action:** Update `Microsoft.AspNetCore.DataProtection` to **10.0.7** and redeploy affected applications. **Rotate the DataProtection key ring** to invalidate any forged tokens issued during the exposure window — patching alone is insufficient. Audit issuance logs for password resets, API-key generation, and elevated session refreshes during the period 10.0.0–10.0.6 was deployed. Force re-authentication for all users of affected applications.

### 3.6 1,300+ SharePoint servers unpatched against actively exploited CVE-2026-32201

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-1-300-microsoft-sharepoint-servers-vulnerable-to-ongoing-attacks/)

Shadowserver reports more than **1,300 internet-exposed SharePoint servers** still unpatched against **CVE-2026-32201**, an improper-input-validation spoofing flaw in SharePoint Enterprise Server 2016, SharePoint Server 2019, and SharePoint Server Subscription Edition. Microsoft tagged the bug as a zero-day in the April 2026 Patch Tuesday but has not publicly attributed exploitation to a specific actor. Successful, low-complexity, unauthenticated exploitation lets an attacker view and modify sensitive content. CISA added it to KEV with a 28 April FCEB remediation deadline. Fewer than 200 systems had been patched in the week between disclosure and Shadowserver's scan.

> **SOC Action:** Apply the April 2026 SharePoint security update across all on-prem editions and confirm via Microsoft's documented `Get-SPServerPatchInfo` or build-number checks. For internet-exposed farms, deploy a temporary WAF/IIS rule to require authentication on the affected endpoints until patching is verified. Hunt for unauthorised content modifications and unexpected privilege grants in SharePoint audit logs over the past 14 days.

### 3.7 Breeze Cache WordPress plugin RCE under active exploitation (CVE-2026-3844)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-file-upload-bug-in-breeze-cache-wordpress-plugin/), Telegram (channel name redacted)

Wordfence has logged **170+ exploitation attempts** against **CVE-2026-3844**, a CVSS 9.8 unauthenticated arbitrary-file-upload-to-RCE flaw in the **Breeze Cache** WordPress plugin (Cloudways, 400,000+ active installations). The bug is in the `fetch_gravatar_from_remote` function and is exploitable when the **"Host Files Locally - Gravatars"** add-on is enabled. Patch is in **2.4.5**; affected versions are <= 2.4.4. PoC is circulating through closed Telegram channels. MITRE ATT&CK: **T1190** (Exploit Public-Facing Application), **T1505.003** (Web Shell).

> **SOC Action:** Update Breeze Cache to 2.4.5+. If updating immediately is not possible, disable the "Host Files Locally - Gravatars" add-on or deactivate the plugin. Search WordPress upload directories for newly written PHP files outside expected paths, hunt for HTTP POSTs to `admin-ajax.php` or `breeze_*` endpoints with unusual Content-Type or large request bodies, and review web-server access logs for successful uploads followed by direct file fetches.

### 3.8 Lotus Wiper destructive campaign against Venezuela's energy sector

**Source:** [AlienVault](https://otx.alienvault.com/pulse/69e76908461fbf60038d0105)

A targeted destructive campaign — **Lotus Wiper** — hit **Venezuela's energy and utilities sector** in late 2025/early 2026. Operators used batch scripts coordinated via domain shares to disable security services, lock out users, and stage the wiper. The payload zeroes physical drives, deletes restore points, clears USN journals, and recursively deletes files. There are no ransom notes or financial-extortion artefacts: the campaign is purely destructive. Evidence indicates long-term domain access prior to detonation, with the wiper compiled months before deployment, and reliance on legitimate utilities (`diskpart`, `robocopy`, `fsutil`). Attribution is not provided in the source. MITRE ATT&CK: **T1485** (Data Destruction), **T1561** (Disk Wipe), **T1490** (Inhibit System Recovery), **T1562.001** (Disable Security Tools), **T1059.003** (Windows Command Shell), **T1070** (Indicator Removal).

> **SOC Action:** For OT-adjacent IT and critical-infrastructure tenants, hunt for batch-script execution coming from domain shares, tampering with `vssadmin`/`wbadmin`, mass invocation of `diskpart`/`fsutil usn`/`robocopy /MIR /PURGE`, and disablement of EDR/AV services followed by user-account lockouts. Verify offline, immutable backups exist for SCADA/historian, billing, and AD domain controllers. Tabletop a wiper-specific recovery scenario distinct from ransomware (no decryption path).

### 3.9 Unit 42 — npm post-Shai-Hulud landscape and TeamPCP @bitwarden/cli campaign

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

Unit 42 published a landscape view of the npm registry following the September 2025 Shai-Hulud worm. Three structural shifts now define the threat surface: **wormable propagation** that steals npm tokens and GitHub PATs to auto-republish legitimate packages (e.g., the March 2026 Axios incident); **infrastructure-level persistence** in CI/CD pipelines for long-term access; and **multi-stage payloads with dormant "sleeper" dependencies** that activate only under specific environmental conditions to evade scanners. Unit 42 specifically calls out a malicious **@bitwarden/cli 2026.4.0** package attributed to **TeamPCP**, which impersonates the Bitwarden CLI password manager, steals cloud-provider, CI/CD, and developer-workstation credentials, and self-propagates by backdooring every npm package the victim can publish. Public GitHub repositories tied to the campaign carried the string **"Shai-Hulud: The Third Coming."** The same payload has been observed across Docker Hub images, GitHub Actions, and VS Code extensions.

> **SOC Action:** Block `@bitwarden/cli@2026.4.0` and pin to the verified-legitimate Bitwarden CLI version. Audit npm tokens, GitHub PATs, and CI/CD provider service-account tokens — rotate any that were used in the past 30 days from developer endpoints. Enforce 2FA on npm and GitHub publisher accounts; require provenance/SLSA attestations for production builds. Search source repositories and build artefacts for the marker string "Shai-Hulud" and for unexpected `postinstall` scripts touching credential stores. Scan VS Code extension marketplaces and Docker Hub for organisation-name impersonations.

### 3.10 Ransomware leak-site economy: Qilin, Lockbit5, Inc Ransom, Coinbase Cartel, M3rx

**Source:** [RansomLook (parser feed)](https://www.ransomlook.io)

The week saw sustained ransomware leak-site activity dominated by **Qilin** (RaaS, multi-sector) with at least 12 named victims posted in a single Friday tranche (Chase Cooper, Woodfields, Chelten House, KEMBA Indianapolis CU, SanCor, Mid Florida Dermatology, Buckley Powder, Cahbo, Leistritz, Travel Expert, LA Woodworks, First County FCU, plus Inspira, Longwood Engineering, Muller Technology, A&A Building Material, Exclusive Networks, and Istarpal in subsequent days). **Lockbit5** posted bladex.com, heinrichs-logistic.de, and merlo.de on 26 April, suggesting a logistics/financial-services focus for that branch and continued activity from the LockBitSupp/Wazawaka-affiliated infrastructure. **Inc Ransom** added MTCI and reddycardiology.com (24 April–27 April), the latter creating a healthcare correlation pair. **Coinbase Cartel** continued its energy-and-telecoms campaign with Sanna Web, Peru LNG (Hunt LNG Operating Company), and Aptim. **M3rx** posted dmschweiz.ch, anvilarts.org.uk, primeproperties.com.au, airdriephysio.com, and rainforestclean.com on 26 April, with claims of multi-tens-of-GB exfiltration. **Tridentlocker**, **PEAR**, **Medusa** (RT Software, Mesquite Plumbing, Walman Optical), and **Krybit** (Narteks Tekstil) posted single-digit victim counts each. The AI-correlation engine flagged shared sector exposure across Inc Ransom and Tridentlocker (healthcare) and across Inc Ransom and the "payload" group (legal services / local government).

> **SOC Action:** Treat Qilin, Lockbit5, Inc Ransom, M3rx, Tridentlocker, and Coinbase Cartel as the active threat baseline for the next two weeks. Verify offline backups for legal, healthcare, manufacturing, and energy customers; pre-position incident-response retainers. Monitor MFA-bypass and Microsoft Teams social-engineering vectors (multiple recent Qilin and Lamashtu intrusions started with phishing into Teams). Hunt for `README-RECOVER-*.txt` artefacts, RECOVERY_NOTES.TXT, and Tox/Jabber egress traffic. Cross-reference any tenant matching listed victims to the RansomLook `https://www.ransomlook.io/group/<actor>` feed for ransom-note hashes.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of software vulnerabilities leading to critical security risks | CVE-2026-3844 Breeze Cache PoC actively used (batch 90) |
| 🔴 **CRITICAL** | Application-layer supply-chain attacks | Unit 42 npm landscape; "Firestarter malware survives Cisco firewall updates" (batch 88) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software platforms | CVE-2026-21515 Azure IoT Central EoP; Breeze Cache (batch 86) |
| 🔴 **CRITICAL** | Ransomware attacks against finance and energy sectors | Sanna Web, Peru LNG, Aptim — all by Coinbase Cartel (batch 85) |
| 🔴 **CRITICAL** | Ransomware-as-a-Service operations becoming more sophisticated | Embargo, Chaos, DragonForce victim posts (batch 84) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in cloud-native and enterprise environments | LMDeploy LLM 12-hour exploit; npm self-spreading worm (batch 83) |
| 🔴 **CRITICAL** | Resource hijacking targeting critical infrastructure | K2 Electric, Jiangsu Zenergy — by Genesis and RansomHouse (batch 82) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in critical infrastructure and manufacturing | Siemens RUGGEDCOM CROSSBOW SAC; SenseLive X3050; Apache ActiveMQ (batch 81) |
| 🔴 **CRITICAL** | APT social engineering and remote-services abuse | Iranian APT Seedworm via Microsoft Teams; The Gentlemen + SystemBC (batch 80) |
| 🟠 **HIGH** | Increased Qilin RaaS activity across diverse sectors | 12+ Qilin victims in a single batch (batch 89) |
| 🟠 **HIGH** | Phishing remains a prevalent TTP across ransomware campaigns | Brain Cipher, Lamashtu, Qilin, Nightspire victim posts (batch 89) |
| 🟠 **HIGH** | Privilege-escalation vulnerabilities being exploited at scale | CVE-2026-23339 nfc; CVE-2026-23315 wifi/mt76 (batch 88) |
| 🟠 **HIGH** | RaaS expansion: ShinyHunters double-extortion | Udemy and ADT data leaks (batch 86) |
| 🟠 **HIGH** | APT targeting of governmental institutions | GopherWhisper / Mongolian government; CISA FIRESTARTER notice (batch 86) |
| 🟠 **HIGH** | Supply-chain compromise to deliver malware | Checkmarx KICS analysis tool breach; TeamPCP CanisterWorm (batch 85) |
| 🟠 **HIGH** | State-sponsored use of consumer messaging for C2 | China-linked actor using Slack/Discord vs Mongolia; GopherWhisper Outlook/Slack/Discord (batch 85) |
| 🟠 **HIGH** | Exploitation of IoT and network device vulnerabilities | Chinese-camera firmware analysis; Mirai vs EoL D-Link (batch 84) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (69 reports) — Ransomware-as-a-Service, the dominant leak-site poster of the week across engineering, healthcare, finance, and logistics
- **The Gentlemen** (58 reports) — Active RaaS group; correlated with SystemBC proxy infrastructure
- **Coinbase Cartel** (38 reports) — Targeting energy, telecoms, manufacturing; Peru LNG and Aptim posted this week
- **DragonForce** (28 reports) — Continued multi-sector RaaS activity, post-quantum encryption claims
- **Nightspire** (27 reports) — Recurring victim posts; phishing-led intrusions
- **shadowbyt3$** (25 reports) — Persistent leak-site presence
- **ShinyHunters** (20 reports) — Pay-or-leak extortion against Udemy (1.4M accounts) and ADT
- **TeamPCP** (18 reports) — Attributed to the @bitwarden/cli "Shai-Hulud: The Third Coming" npm campaign
- **Lamashtu** (16 reports) — Phishing-led campaigns observed
- **UAT-4356** (this week, Cisco Talos) — ArcaneDoor actor; FIRESTARTER backdoor on Cisco FXOS

### Malware Families

- **RansomLock / RansomLook** (45 + 37 reports) — Parser-derived ransomware leak-site indexing rather than a single family; reflects the volume of RaaS activity
- **Tox1 / Tox** (18 + 11 reports) — Communications channel used by Qilin, Lockbit5, and others for negotiation
- **Qilin** (9 reports as malware entity) — RaaS payload
- **Gentlemen ransomware** (9 reports)
- **Akira ransomware** (9 reports)
- **DragonForce ransomware** (8 reports)
- **Mirai** (6 reports) — New campaign vs end-of-life D-Link routers
- **FIRESTARTER** (this week) — UAT-4356 implant on Cisco FXOS
- **Lotus Wiper** (this week) — Destructive campaign vs Venezuelan energy sector
- **RedSun.exe / Shai-Hulud / Shai-Hulud 2.0** (this week) — Defender LPE PoC and npm worm variants

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 224 | [link](https://msrc.microsoft.com/update-guide) | MSRC vulnerability disclosures, including kernel/BPF/ext4 CVEs and the ASP.NET Core OOB advisory |
| RansomLock | 161 | [link](https://www.ransomlook.io) | Ransomware leak-site parser feed (Qilin, Lockbit5, Inc Ransom, M3rx, Coinbase Cartel) |
| BleepingComputer | 51 | [link](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-microsoft-defender-flaw-exploited-in-zero-day-attacks/) | Primary coverage of CISA KEV additions, BlueHammer, SD-WAN, ActiveMQ, SharePoint, ASP.NET, Breeze Cache |
| AlienVault | 42 | [link](https://otx.alienvault.com/pulse/69e76908461fbf60038d0105) | OTX pulses incl. Lotus Wiper, RedSun, FudCrypt analyses |
| RecordedFutures | 28 | [link](https://www.recordedfuture.com) | Strategic threat reporting |
| Unknown | 20 | — | Telegram-sourced PoC and leak posts (channel names redacted) |
| CISA | 15 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | ICS advisories incl. SenseLive X3050, Silex Technology, Siemens RUGGEDCOM |
| Wired Security | 9 | [link](https://www.wired.com/category/security/) | Strategic and policy-level security reporting |
| Schneier | 7 | [link](https://www.schneier.com) | Cryptography and policy commentary |
| Unit42 | 7 | [link](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) | npm landscape report; AirSnitch Wi-Fi attacks |
| Cisco Talos | 6 | [link](https://blog.talosintelligence.com/uat-4356-firestarter/) | UAT-4356/FIRESTARTER attribution |
| Wiz | 6 | [link](https://www.wiz.io/blog) | Cloud-native exploitation reporting |
| SANS | 6 | [link](https://isc.sans.edu) | ISC daily diaries |
| Upwind | 5 | [link](https://www.upwind.io/feed) | Cloud workload telemetry |
| ESET Threat Research | 4 | [link](https://www.welivesecurity.com) | Wider regional malware coverage |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch the three CISA KEV additions on every internet-exposed estate within FCEB-equivalent deadlines — **CVE-2026-33825** (Microsoft Defender BlueHammer, by 7 May), **CVE-2026-20133** (Cisco Catalyst SD-WAN Manager, was due 24 April), and **CVE-2026-34197** (Apache ActiveMQ, by 30 April). Confirm SharePoint **CVE-2026-32201** is patched (was due 28 April).
- 🔴 **IMMEDIATE:** For ASP.NET Core applications, upgrade `Microsoft.AspNetCore.DataProtection` to 10.0.7 **and rotate the DataProtection key ring** — patching alone leaves any forged tokens valid (CVE-2026-40372).
- 🔴 **IMMEDIATE:** For Cisco ASA/FTD/Firepower customers, apply the FXOS fixed train and threat-hunt for FIRESTARTER persistence (`/usr/bin/lina_cs`, `CSP_MOUNT_LIST` modifications). Treat any graceful-reboot-only remediation as insufficient.
- 🟠 **SHORT-TERM:** WordPress operators running Breeze Cache should upgrade to 2.4.5 or disable the "Host Files Locally - Gravatars" add-on; review upload directories for unexpected PHP.
- 🟠 **SHORT-TERM:** Treat the Qilin / Lockbit5 / Inc Ransom / Coinbase Cartel / M3rx leak-site wave as the active baseline. Verify offline immutable backups for healthcare, legal, manufacturing, and energy tenants; pre-position IR retainers; rehearse Microsoft-Teams-borne phishing and SystemBC-style proxy eviction.
- 🟠 **SHORT-TERM:** For software-supply-chain risk, audit and rotate npm tokens and GitHub PATs from any developer workstation used in the past 30 days. Block `@bitwarden/cli@2026.4.0` and search repos for the marker string "Shai-Hulud."
- 🟡 **AWARENESS:** Energy-sector and OT-adjacent IT teams should review Lotus Wiper TTPs (batch-script-driven `diskpart`/`fsutil usn`/`robocopy /MIR /PURGE` plus EDR disablement and AD lockouts) and confirm wiper-specific recovery (no-decryption-path) tabletops.
- 🟢 **STRATEGIC:** Reduce internet exposure of management planes (vManage/Catalyst SD-WAN Manager, ActiveMQ admin, SharePoint front-ends) behind dedicated bastions and zero-trust segmentation. The week's pattern — three management-plane CVEs added to KEV in a single week — is the structural lesson, not any individual patch.

---

*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 611 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
