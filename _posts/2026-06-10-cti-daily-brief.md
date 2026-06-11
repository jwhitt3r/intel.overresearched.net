---
layout: post
title:  "CTI Daily Brief: 2026-06-10 - Record Microsoft Patch Tuesday, Ivanti Sentry CVE-2026-10520 (CVSS 10), Exchange & Netlogon Zero-Days Under Active Exploitation"
date:   2026-06-11 00:00:00 +0000
description: "Microsoft ships its largest-ever Patch Tuesday (206 CVEs, six zero-days including actively-exploited CVE-2026-41091 Defender EoP and CVE-2026-42897 Exchange XSS); Ivanti Sentry hit by maximum-severity unauth RCE chain; Windows Netlogon CVE-2026-41089 under attack; China-linked JDY botnet expands against US military; The Gentlemen RaaS operator unmasked."
category: daily
tags: [cti, daily-brief, the-gentlemen, akira, morpheus, nightmare-eclipse, volt-typhoon, cve-2026-45657, cve-2026-41089, cve-2026-10520, cve-2026-42897, cve-2026-41091, mltbackdoor]
classification: TLP:CLEAR
reporting_period: "2026-06-10"
generated: "2026-06-11"
severity: critical
draft: true
report_count: 99
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - AlienVault
  - Wired Security
  - RecordedFutures
  - CertEU
  - SANS
  - Krebs on Security
  - Upwind
  - Schneier
  - Sysdig
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-10 (24h) | TLP:CLEAR | 2026-06-11 |

## 1. Executive Summary

The pipeline processed 99 reports across 13 sources in the last 24 hours, with seven rated critical and 45 rated high. The day was dominated by Microsoft's largest Patch Tuesday on record — 206 CVEs, three publicly disclosed zero-days from researcher "Nightmare Eclipse" (YellowKey, GreenPlasma, MiniPlasma), one CISA KEV-listed Defender EoP (CVE-2026-41091) under active attack, and a 9.8-rated wormable Windows kernel flaw (CVE-2026-45657). Parallel emergency advisories from CERT-EU cover CVE-2026-41089 (Windows Netlogon stack overflow, actively exploited per CCB Belgium) and CVE-2026-10520 / CVE-2026-10523 in Ivanti Sentry (CVSS 10.0 / 9.9 unauth RCE + auth-bypass chain). Ransomware activity remained heavy: Morpheus leaked 680 GB from HDFC Asset Management Company, while The Gentlemen, Akira, WorldLeaks, Krybit, PEAR and Play continued double-extortion campaigns across finance, healthcare and manufacturing. Krebs on Security publicly attributed The Gentlemen's administrator "Hastalamuerte/Zeta88" to Alexander Andreevich Yapaev of Izhevsk, Russia.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 7 | Microsoft Patch Tuesday (CVE-2026-45657 wormable, CVE-2026-41091 KEV); Ivanti Sentry CVE-2026-10520/10523; Windows Netlogon CVE-2026-41089; YellowKey/GreenPlasma/MiniPlasma zero-days; MLTBackdoor analysis; Morpheus leak of HDFC Fund |
| 🟠 **HIGH** | 45 | Ransomware leak-site activity (The Gentlemen, Akira, WorldLeaks, Krybit, PEAR, Play, Embargo, DragonForce, Inc Ransom, Space Bears, Fulcrumsec); Exchange CVE-2026-42897 zero-day; China-linked JDY botnet; M365 voicemail OAuth phishing; SilabRAT MaaS; Linux kernel CVE batch |
| 🟡 **MEDIUM** | 23 | Australian sugar mill cyberattack; Windows update install failures; Telegram proxy advertisements; lower-tier ransomware leak posts |
| 🟢 **LOW** | 9 | Routine RansomLook tracking entries; minor advisories |
| 🔵 **INFO** | 15 | Background OSINT and pipeline enrichment items |

## 3. Priority Intelligence Items

### 3.1 Microsoft June 2026 Patch Tuesday — Largest on Record, Six Zero-Days, KEV Addition

**Source:** [Recorded Future](https://therecord.media/microsoft-ships-largest-patch-tuesday-on-record), [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-yellowkey-greenplasma-miniplasma-zero-days/)

Microsoft shipped 206 CVEs in its June 2026 release — by Trend Micro ZDI's count the largest single Patch Tuesday in program history (prior record 177). The release reflects an AI-driven surge in vulnerability discovery, with Microsoft's internal MDASH system credited for previously identifying multiple flaws. The standout items:

- **CVE-2026-45657** (CVSS 9.8) — wormable RCE deep in the Windows kernel network stack. Microsoft rates exploitation "less likely" but ZDI urges immediate patching; researchers were already reverse-engineering the patch within hours.
- **CVE-2026-41091** (CVSS 7.8) — Microsoft Defender elevation-of-privilege; **on CISA KEV since 20 May 2026** and confirmed exploited in the wild. Attackers trick Defender into writing a malicious file to a protected location for full system control.
- **CVE-2026-45585** ("YellowKey") — backdoor in Windows Recovery Environment enabling BitLocker bypass on Windows 11 and Windows Server 2022/2025 with physical access.
- **CVE-2026-45586** ("GreenPlasma") — CTFMON local privilege escalation to SYSTEM.
- **CVE-2020-17103** ("MiniPlasma") — Cloud Files Mini Filter Driver LPE to SYSTEM.

The three "Plasma" zero-days were disclosed by researcher "Nightmare Eclipse" outside coordinated disclosure; Microsoft notes a follow-on Defender exploit ("RoguePlanet") was published within hours of the patch release. ZDI noted Microsoft's 2026 CVE total has already eclipsed all of 2018.

**Affected:** Windows 10/11, Windows Server 2012–2025, Microsoft Defender, Windows Recovery Environment.
**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1204 (User Execution), T1078.004.

> **SOC Action:** Deploy June 2026 cumulative updates within 24–48 hours, prioritising domain controllers and any host where Defender is the primary AV. Hunt EDR for `MsMpEng.exe` writing to non-standard protected paths (Defender EoP indicator), and for unexpected child processes of CTFMON-related binaries. For YellowKey, audit physical-access exposure of BitLocker-protected endpoints and enable PIN/TPM+PIN where feasible. Block known Nightmare Eclipse PoC hashes at the EDR layer.

### 3.2 Ivanti Sentry — CVE-2026-10520 / CVE-2026-10523 (Max-Severity Unauth RCE + Auth Bypass)

**Source:** [CERT-EU SA 2026-008](https://cert.europa.eu/publications/security-advisories/2026-008/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-max-severity-ivanti-sentry-flaw-allows-code-execution-as-root/)

Ivanti patched two critical flaws in its Sentry secure mobile gateway (formerly MobileIron Sentry). **CVE-2026-10520 (CVSS 10.0)** is an OS command injection allowing unauthenticated remote root code execution. **CVE-2026-10523 (CVSS 9.9)** is an authentication bypass that lets a remote unauthenticated attacker create arbitrary administrative accounts. Fixed in R10.5.2, R10.6.2 and R10.7.1. Ivanti says it is not aware of in-the-wild exploitation at disclosure, but historical pattern strongly suggests rapid weaponisation — watchTowr Labs has already published technical analysis of the command-injection chain.

**Affected:** Ivanti Sentry 10.5.1 and prior, 10.6.1 and prior, 10.7.0 and prior.
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts).

> **SOC Action:** Patch all Sentry appliances to R10.5.2 / R10.6.2 / R10.7.1 immediately; treat as emergency. If patching is delayed, block external access to the Sentry management interface and front the appliance with a reverse proxy enforcing IP allowlists. Hunt web logs for anomalous POST requests to Sentry admin endpoints, new local admin account creation events, and outbound connections from the appliance to non-corporate IPs. Capture forensic images before patching if any indicator of pre-patch compromise exists.

### 3.3 Windows Netlogon CVE-2026-41089 — Actively Exploited Domain-Controller RCE

**Source:** [CERT-EU SA 2026-007](https://cert.europa.eu/publications/security-advisories/2026-007/)

CVE-2026-41089 (CVSS 9.8) is a stack-based buffer overflow in Windows Netlogon allowing unauthenticated attackers to execute arbitrary code with SYSTEM privileges on domain controllers via crafted packets. The Centre for Cybersecurity Belgium (CCB) reports active in-the-wild exploitation. Affects Windows Server 2012 through 2025; patched versions and required build numbers are listed in the CERT-EU advisory.

**MITRE ATT&CK:** T1203 (Exploitation for Privilege Escalation), T1078.003 (Valid Accounts).

> **SOC Action:** Patch all domain controllers to the listed minimum builds (e.g., Server 2022 ≥ 10.0.20348.5074) within 24 hours. Until patched, monitor DC event logs for anomalous Netlogon RPC traffic and unexpected SYSTEM-context process executions. Enable DC-side network captures filtered to TCP/445 and Netlogon RPC for anomaly review. Validate Tier-0 segmentation — assume any unpatched DC reachable from user subnets is at imminent risk.

### 3.4 Microsoft Exchange CVE-2026-42897 — Actively Exploited OWA XSS

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-exchange-server-zero-day-exploited-in-attacks/)

Microsoft patched CVE-2026-42897, a high-severity spoofing/XSS flaw in Exchange Server 2016, 2019 and Subscription Edition that lets a remote unauthenticated attacker execute arbitrary JavaScript in the OWA browser context via a crafted email. CISA added the flaw to the KEV on 15 May 2026 with a federal patch deadline of 29 May. Microsoft had previously rolled out automatic temporary mitigation through Exchange Emergency Mitigation Service (EEMS); the June update is the permanent fix.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1204 (User Execution).

> **SOC Action:** Install June 2026 Exchange security updates and leave EEMS mitigations in place. Hunt OWA/IIS logs for unusual JavaScript-laden inbound mail, anomalous user-agent strings, and post-authentication session-token abuse. Force re-authentication of all OWA sessions and rotate any exposed OAuth tokens. Review CISA's KEV-required attestation if you are a federal entity.

### 3.5 MLTBackdoor — ClickFix → BOF Loader Linked to Ransomware Pre-Cursor Activity

**Source:** [Zscaler ThreatLabz (via AlienVault OTX)](https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor)

Zscaler ThreatLabz detailed MLTBackdoor, a heavily obfuscated implant delivered through ClickFix lures on automotive-themed pages. The kill chain uses `conhost.exe --headless cmd /c` with `curl` to stage a tar archive containing `endpointdlp.dll` and an RC4-encrypted `data.bin`, then sideloads via the legitimate Microsoft Defender `mpextms.exe` binary. The implant supports filesystem commands and a Beacon Object File (BOF) loader for runtime capability expansion, uses a DGA for C2 resilience, and applies LLVM-based MBA + Control Flow Flattening obfuscation. Assessed as a likely foothold for a ransomware-related actor targeting industrial and automotive sectors.

**MITRE ATT&CK:** T1566 (Phishing), T1059.003 (Windows Command Shell), T1027 (Obfuscated Files), T1055.001 (DLL Sideloading), T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer), T1497 (Sandbox Evasion).

#### Indicators of Compromise
```
Staging domains (DGA + hardcoded):
  hxxps[:]//hrs2y15sungu[.]com/d
  hxxp[:]//powwowski[.]com/payloads/update.zip
  carrolc[.]com
  cwrtwright[.]com
  thomphon[.]com

SHA-256 (selected):
  0ca2edf9982f58e63cc49ba69fb9a88762d1f220ed9482810b512d4add0f8f0b
  0f7463aecc3920f9e2b32ab9d77861a9e69a3e8aa28d06b4602195623312331d
  1d09357b6a096fdc35cd5c873eed15665d6b3c879d20c8cf01e6bca0005512cf
  46b2155c1e71b840d4b7a2e94410b89a61e2446523e6f497206d402eb02e0e93
  9c8384f93b9d347a716ea3e55b9a01250473f667b95d467126c048256b0049e9
  a5a5b6257304eefe5212edfd8c0ad27f77357c5046a7acb8eb7ba72ed4bad9e0
  fe8557d454adc7a91162495628d269738b92b4b5d7e5d620fc3f38c27a9a41a7

Sideload pairing:
  Legitimate: mpextms.exe (Microsoft Defender)
  Malicious:  endpointdlp.dll
```

> **SOC Action:** Block listed domains and SHA-256 hashes at proxy/DNS and EDR. Hunt EDR for `conhost.exe --headless` spawning `curl`, for `mpextms.exe` loading `endpointdlp.dll` from non-`Program Files` paths, and for `rundll32` invoking `endpointdlp.dll,#2`. Detect ClickFix lures with a YARA rule on copy-to-clipboard JavaScript containing `cmd /c` and `curl`. Brief automotive and industrial-sector users on ClickFix social engineering.

### 3.6 Voicemail Phishing Kit — Silent OAuth Hijacking of Microsoft 365 Sessions

**Source:** [KnowBe4 ThreatLabs via AlienVault OTX](https://x.com/Kb4Threatlabs/status/2064374959989043207)

A consolidated Phishing-as-a-Service operation is using local-HTML voicemail attachments (spoofing "Business | Masergy") that, when opened during an active M365 browser session, trigger a rogue OAuth 2.0 request with `prompt=none` to silently steal authentication tokens. If no active session exists, victims cascade into credential harvesters mimicking DocuSign/Outlook/Google, device-code phishing flows, and RMM installer downloads. Primary infrastructure resides on a compromised Turkish domain hosting 100+ active campaign directories.

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1528 (Steal Application Access Token), T1539 (Steal Web Session Cookie), T1550.001 (Application Access Token), T1219 (Remote Access Software).

#### Indicators of Compromise
```
Primary phishing:
  guzeldagenerji[.]com[.]tr
  many-potential-customers-hesitate[.]onrender[.]com

M365 credential harvesters:
  office-document-sign[.]tammy-e82[.]workers[.]dev
  office-docusign-net[.]tammy-e82[.]workers[.]dev
  login[.]av7551[.]com
  log[.]evergreenhostingoptions[.]de
  admhr[.]execsuccessmetrics[.]de
  valid[.]boostedengagement[.]de

Google credential harvesters:
  accounts[.]tnfirm[.]icu
  accounts[.]gxcwfe[.]icu
  accounts[.]knuczx[.]icu
  accounts[.]zachnt[.]icu
  accounts[.]odtdrv[.]icu

RMM delivery:
  pmlee[.]com/verify.php
  sparkaxis[.]org/deployment/
  wylderhotels[.]sparkaxis[.]org/personaljflannigan/
```

> **SOC Action:** Block all listed domains at the secure email gateway and DNS. Enforce a Conditional Access policy denying OAuth consent for unverified third-party apps and requiring MFA on every `prompt=none` reauth. Hunt Azure AD sign-in logs for app consent grants from unfamiliar reply URLs and for device-code authentications outside expected user agents. Strip HTML attachments at the mail gateway, or detonate them in a sandbox before delivery. User-awareness brief: any "voicemail" email asking the user to click an embedded player should be reported.

### 3.7 China-Linked JDY Botnet Expands US Military Reconnaissance

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/china-linked-jdy-botnet-expands-targeting-of-us-military-networks/)

Black Lotus Labs (Lumen) reports the JDY botnet — previously linked to Volt Typhoon — has grown from ~650 bots in January 2024 to more than 1,500 compromised SOHO/IoT devices, with a sharp focus on US military networks. JDY is not a DDoS platform; it is a distributed scanning, banner-grabbing and TLS-cert-harvesting reconnaissance grid that rapidly fingerprints internet-facing assets vulnerable to newly disclosed CVEs (e.g., CVE-2026-35616 in FortiClient EMS within hours of disclosure). Compromised devices include Cisco, Araknis, Mimosa, Ubiquiti, DrayTek, Hikvision and Linksys (MIPS/MIPSEL). C2 runs through hidden Tor services, with Platypus reverse-shell framework observed in some cases.

**MITRE ATT&CK:** T1046 (Network Service Scanning), T1189 (Drive-by Compromise), T1090.003 (Multi-hop Proxy), T1595 (Active Scanning).

> **SOC Action:** Audit perimeter firewall logs for SYN scans with fixed source port 19000 and incrementing destination ports (JDY raw-socket fingerprint). Patch internet-facing SOHO routers, FortiClient EMS, and any device on the Black Lotus Labs vendor list. Block known Tor-exit IPs at edge where Tor is not a business requirement. For DoD-adjacent contractors, treat any SOHO router exposing a WMI to the internet as compromised until proven otherwise.

### 3.8 Morpheus Ransomware — 680 GB Leaked From HDFC Asset Management

**Source:** [RansomLook (Morpheus leak site mirror)](https://www.ransomlook.io//group/morpheus)

The Morpheus group claims theft of 680 GB from HDFC Asset Management Company (HDFCAMC, $427.8M revenue), India's largest mutual-fund manager. Data advertised for sale includes portfolio and trading documentation, regulatory/compliance/audit files, SQL databases, HDFCAMC application source code, and senior-executive personal records. Threat actor also offers network access to the buyer. Morpheus leak site uptime over 30 days is 97%, and Morpheus has 20 historical posts including 3i Infotech ($96.8M) on 8 June.

**MITRE ATT&CK:** T1567 (Exfiltration Over Web Service), T1486 (Data Encrypted for Impact — pre-exfil pattern).

> **SOC Action:** Indian financial-services SOCs should hunt outbound transfers >100 GB to commercial cloud-storage endpoints over the past 30 days. Validate that HDFCAMC supply-chain partners rotate any shared credentials and review API keys exposed in source-code repositories. Asia-region CISOs should expect spillover phishing using leaked employee PII.

### 3.9 The Gentlemen RaaS Attribution — Krebs Names Hastalamuerte/Zeta88

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/06/who-runs-the-ransomware-group-the-gentlemen/), [BleepingComputer Gentlemen tracking](https://www.bleepingcomputer.com/) (multiple RansomLook leak posts)

Brian Krebs, leveraging Check Point, Intel 471, Flashpoint and Constella Intelligence data, attributes The Gentlemen ransomware administrator to **Alexander Andreevich Yapaev**, 36, of Izhevsk, Udmurt Republic, Russia, operating under the handles "Hastalamuerte" and "Zeta88". The Gentlemen pays a 90/10 affiliate split (vs. industry-standard 80/20) and is the second most active RaaS by 2026 victim count (332 published victims since mid-2025, 240+ in 2026). Pivot chain runs from the email `hastalamuerte1488@protonmail.com` through a private GitHub account "SantaMuerte", Telegram ID 30907522, and Russian phone +79127650004. Numeric "1488" in the original handle is a known white-supremacist symbol.

Today's leak-site activity for the group includes Scenic Hudson, UiTM Holdings, Silmquinas e Equipamentos, Tokabei Japan, and Allensbach Volunteer Fire Brigade. A parallel Zscaler ThreatLabz pulse tracks the group under "Storm-2697" with 1,570+ compromised organisations and notes Go/C-compiled lockers, WMI/PowerShell lateral movement, Windows Defender tampering, and a CWE-244 key-recovery weakness.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application — VPN/firewall entry), T1059.001 (PowerShell), T1047 (WMI), T1486 (Data Encrypted for Impact), T1562.001 (Disable Security Tools).

> **SOC Action:** Treat any exposed VPN or firewall management interface as a Gentlemen target — patch and put behind MFA-enforced reverse proxy. Hunt for PowerShell remoting against unusual destinations, WMI process creation on file servers, and Windows Defender service-stop events from non-admin accounts. Add the email `hastalamuerte1488@protonmail.com`, Telegram ID `30907522`, and the affiliate-recruitment lures referenced by Check Point to your threat-intel watchlists.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software and systems | YellowKey/GreenPlasma/MiniPlasma zero-days; Patch Tuesday CVE-2026-45657 wormable kernel flaw; CVE-2026-41091 Defender EoP under active attack |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors with sophisticated TTPs | PROBE S.A. de C.V. by Krybit; UiTM Holdings by The Gentlemen; FIZA by Inc Ransom; Morpheus → HDFC Fund; Akira chain (Port Air Express, Midland Theatre, Associated Investor Services); WorldLeaks portfolio (Tata Electronics, First Federal S&L) |
| 🟠 **HIGH** | Phishing campaigns leveraging social media and OAuth flows for credential theft | Voicemail phishing kit silently hijacking M365 OAuth sessions; TikTok / Instagram Reels distributing Vidarstealer; ClickFix delivery of MLTBackdoor and HarborWatch Agent RAT |
| 🟠 **HIGH** | Shared TTPs across BOF-loader and ClickFix-staged implants | MLTBackdoor BOF capability; SilabRAT HVNC + ClickFix; voicemail kit cascading to RMM installers |
| 🟠 **HIGH** | Linux kernel privilege-escalation vulnerability cluster | Microsoft-mirrored advisories for CVE-2026-46275 (Bluetooth hci_uart UAF), CVE-2026-46285 (mtd: docg3 UAF), CVE-2026-46291 (crypto: caam HMAC key leak), CVE-2026-46301 (spi: topcliff-pch UAF), CVE-2026-46303 (isofs Rock Ridge), CVE-2026-46307 (ath5k OOB), CVE-2026-46322 (tun build_skb) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (77 reports, last seen 2026-06-09) — most prolific RaaS by volume; remains dominant despite no fresh leak posts in today's window.
- **The Gentlemen** (61 reports) — second most active; now subject to public attribution to Yapaev / Hastalamuerte.
- **Akira** (41 reports) — sustained double-extortion against corporate VMware ESXi; multiple new victims today.
- **DragonForce** (34 reports) — RaaS cartel offering customisable payloads; Sayre Associates added today.
- **TeamPCP** (30 reports) — continued background activity, no new high-profile victims.
- **Nova** (22 reports) — emerging mid-tier RaaS.
- **ShinyHunters** (22 reports) — data-theft-only extortion.
- **Lockbit5** (20 reports) — Lockbit successor branding continuing.
- **Nightspire** (20 reports) — mid-tier RaaS.
- **Inc Ransom** (18 reports) — FIZA added to leak site today.

### Malware Families

- **RansomLook** (108 reports) — tracker / aggregator entity, not malware itself; indicative of leak-site monitoring volume.
- **Tox1 / Tox / Other1** (38 / 23 / 28 reports) — Tox messenger references tied to The Gentlemen victim communications.
- **Akira ransomware / Akira** (22 / 15 reports) — `.akira` extension, Windows CryptoAPI, ESXi targeting.
- **Mini Shai-Hulud / Shai-Hulud** (14 / 11 reports) — supply-chain campaign tied to compromised npm/Python packages including Microsoft's durabletask Python SDK (per Upwind).
- **The Gentlemen** (12 reports) — RaaS locker family.
- **RALord** (12 reports) — mid-tier RaaS family.
- **MLTBackdoor** (new, this batch) — Zscaler-tracked BOF-loader implant with DGA C2.
- **JDY** (this batch) — China-linked scanning botnet.
- **SilabRAT** (this batch) — MaaS RAT with HVNC, browser-profile cloning, and crypto-wallet password cracking, distributed via phishing and ClickFix.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 34 | [MSRC](https://msrc.microsoft.com/update-guide) | Patch Tuesday + mirrored Linux-kernel CVE advisories |
| RansomLock | 28 | [ransomlook.io](https://www.ransomlook.io) | Leak-site monitoring; The Gentlemen, Akira, WorldLeaks, Morpheus, Inc Ransom, Play, PEAR, Krybit, Embargo, DragonForce, Space Bears, Fulcrumsec |
| Unknown | 12 | — | Includes Telegram-sourced OSINT; channel URLs withheld per policy |
| BleepingComputer | 6 | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-yellowkey-greenplasma-miniplasma-zero-days/) | YellowKey/GreenPlasma/MiniPlasma, Ivanti Sentry max-severity, Exchange CVE-2026-42897, China-linked JDY botnet |
| AlienVault | 5 | [otx.alienvault.com](https://otx.alienvault.com) | MLTBackdoor pulse, voicemail-phishing kit, TikTok/Instagram phishing, SilabRAT, Gentlemen Go-binary analysis |
| Wired Security | 4 | [wired.com/category/security](https://www.wired.com/category/security/) | Background reporting (not detailed in this brief) |
| RecordedFutures | 3 | [therecord.media](https://therecord.media/microsoft-ships-largest-patch-tuesday-on-record) | Microsoft Patch Tuesday lede; Australian sugar-mill cyberattack |
| CertEU | 2 | [cert.europa.eu](https://cert.europa.eu/publications/security-advisories/2026-008/) | SA 2026-007 (Netlogon) and SA 2026-008 (Ivanti Sentry) |
| SANS | 1 | [isc.sans.edu](https://isc.sans.edu) | Routine ISC diary |
| Krebs on Security | 1 | [krebsonsecurity.com](https://krebsonsecurity.com/2026/06/who-runs-the-ransomware-group-the-gentlemen/) | The Gentlemen attribution to Yapaev / Hastalamuerte |
| Upwind | 1 | [upwind.io](https://www.upwind.io/feed/supply-chain-attack-detection-realtime) | Real-time supply-chain attack detection write-up referencing Shai-Hulud and durabletask |
| Schneier | 1 | [schneier.com](https://www.schneier.com) | NSO Group WhatsApp phishing despite court order |
| Sysdig | 1 | [sysdig.com](https://webflow.sysdig.com/blog/vulnerability-management-is-reaching-the-limits-of-human-scale) | Vulnerability management at AI scale |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Microsoft June 2026 cumulative updates (especially the wormable kernel CVE-2026-45657 and KEV-listed Defender CVE-2026-41091), Windows Netlogon CVE-2026-41089 on every domain controller, and Ivanti Sentry to R10.5.2/R10.6.2/R10.7.1 within 24–48 hours. Treat any internet-facing Sentry or unpatched DC as imminently exploitable.
- 🔴 **IMMEDIATE:** Deploy Exchange June 2026 SU on Exchange Server 2016/2019/SE and leave EEMS mitigations enabled. Force OWA re-authentication for all users; rotate any OAuth tokens issued in May/June.
- 🟠 **SHORT-TERM:** Push the MLTBackdoor and voicemail-phishing-kit indicator blocks (Section 3.5 and 3.6) to EDR, proxy, mail gateway and DNS. Strip or detonate inbound HTML attachments at the gateway. Hunt for `mpextms.exe` sideloading `endpointdlp.dll` and for OAuth consent grants to unverified third-party apps.
- 🟠 **SHORT-TERM:** Audit perimeter VPN and firewall management exposure — The Gentlemen, Akira and JDY all weaponise these as entry. Enforce MFA on all admin interfaces; sit them behind reverse proxies with IP allowlists.
- 🟡 **AWARENESS:** Brief Indian financial-services counterparts on the Morpheus HDFCAMC leak and possible spillover phishing using executive PII. Communicate The Gentlemen attribution to relevant counter-extortion and law-enforcement contacts.
- 🟢 **STRATEGIC:** With AI-assisted vulnerability discovery now visibly accelerating Patch Tuesday volume (Microsoft's MDASH, NCSC April warning), restructure patch-management capacity planning for a sustained higher cadence. Pilot automated vulnerability-prioritisation tooling and runtime protection on cloud workloads, per the Sysdig and Upwind observations on the limits of human-scale vulnerability management.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 99 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
