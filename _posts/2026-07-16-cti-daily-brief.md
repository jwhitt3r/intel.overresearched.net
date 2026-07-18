---
layout: post
title:  "CTI Daily Brief: 2026-07-16 - CISA orders emergency Fortinet FortiSandbox patch; DPRK Contagious Interview steganography; Windows LegacyHive zero-day"
date:   2026-07-17 20:15:00 +0000
description: "Five critical items headline yesterday's activity: CISA emergency directive on actively exploited Fortinet FortiSandbox flaws, a Windows LegacyHive privilege-escalation zero-day, a Siemens ROX II OT switch exploit chain, a Firefox WebAssembly RCE, and a Narrator Braille SYSTEM-escalation bug. Ransomware pressure from Qilin, The Gentlemen, and Akira remains elevated across military, healthcare, and manufacturing."
category: daily
tags: [cti, daily-brief, the-gentlemen, qilin, akira, contagious-interview, cve-2025-40949, legacyhive, fortinet-fortisandbox]
classification: TLP:CLEAR
reporting_period: "2026-07-16"
generated: "2026-07-17"
draft: true
report_count: 66
severity: critical
sources:
  - BleepingComputer
  - Unit42
  - Elastic Security Labs
  - AlienVault
  - Microsoft
  - RecordedFutures
  - RansomLook
  - Wired Security
  - SANS
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-16 (24h) | TLP:CLEAR | 2026-07-17 |

## 1. Executive Summary

Sixty-six reports were processed across the last 24 hours from twelve sources, with ransomware operators and privilege-escalation zero-days dominating the picture. CISA issued an emergency directive ordering federal agencies to patch two actively exploited Fortinet FortiSandbox flaws by Sunday, the day's most operationally urgent item. A new Windows LegacyHive zero-day granting admin privileges on fully patched systems was publicly disclosed, alongside a three-CVE Siemens ROX II OT-switch exploit chain (CVE-2025-40947/40948/40949) and a Firefox WebAssembly RCE (CVE-2026-2796). Elastic Security Labs published REF9403, a DPRK-aligned Contagious Interview campaign hiding OTTERCOOKIE-family payloads inside SVG images with zero AV detection. Ransomware-as-a-service pressure remained elevated: Qilin, The Gentlemen, and Akira claimed victims across military, healthcare, and manufacturing, including a disclosed hit on Military Sealift Command.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 5 | Windows LegacyHive zero-day; Siemens ROX II OT trilogy; Windows Narrator Braille SYSTEM EoP; Firefox WebAssembly RCE; CISA-flagged FortiSandbox exploitation |
| 🟠 **HIGH** | 38 | Qilin, The Gentlemen, Akira, Nova, PLAY, Krybit ransomware victim posts; DPRK Contagious Interview (Elastic); ACR Stealer campaigns; ClickLock macOS malware; libsoup CVE cluster |
| 🟡 **MEDIUM** | 16 | Fairlife/Coca-Cola ransomware production halt; Ernst & Young third-party breach; pyasn1/DBI Perl CVE cluster |
| 🔵 **INFO** | 7 | Residential-proxy fraud market analysis; miscellaneous OSINT |

## 3. Priority Intelligence Items

### 3.1 CISA Emergency Directive — Actively Exploited Fortinet FortiSandbox Flaws

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-feds-to-patch-exploited-fortinet-fortisandbox-flaws-by-sunday/)

CISA ordered federal civilian agencies to patch two actively exploited vulnerabilities in Fortinet's FortiSandbox threat-detection platform with a Sunday deadline. The flaws allow attackers to bypass security controls, opening a path to unauthorised access and control of a device whose entire purpose is to detonate and inspect adversary payloads. Compromise of the sandbox platform itself risks silent bypass of downstream detonation-based detections and pivot into the wider Fortinet security fabric.

> **SOC Action:** Inventory FortiSandbox appliances and confirm firmware is on the vendor-fixed version before Sunday's CISA deadline. Pull logs for any anomalous administrative logins, configuration changes, or verdict-modification events on the sandbox in the last 60 days; treat any anomalies as potential in-the-wild exploitation.

### 3.2 Siemens ROX II OT Switch Zero-Day Exploit Chain (CVE-2025-40947 / 40948 / 40949)

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/)

Unit 42, in coordinated disclosure with Siemens, released details of a chained exploit against Siemens Ruggedcom ROX II operational-technology switches: arbitrary file disclosure (CVE-2025-40948, CVSS 6.8) enables reconnaissance and cryptographic-key theft, command injection in the feature-key validation function (CVE-2025-40947, CVSS 7.5) grants root, and web-management task-scheduler injection (CVE-2025-40949, CVSS 9.1) provides persistence surviving reboots. Siemens has published advisories SSA-973901, SSA-078743, and SSA-081142 and released firmware V2.17.1. Attack techniques align with **T1059.001** (command interpreter) and **T1060** (resource hijacking).

> **SOC Action:** For any Siemens ROX II / Ruggedcom deployments in industrial or utility environments, coordinate with OT engineering to schedule firmware V2.17.1 upgrade. Until patched, restrict management-interface reachability to a jump host, monitor `cron` table modifications and web-scheduler activity, and hunt for outbound reads of `/etc/shadow`, private keys, and Siemens configuration files.

#### Indicators of Compromise

```
CVE: CVE-2025-40947 (command injection, CVSS 7.5)
CVE: CVE-2025-40948 (arbitrary file disclosure, CVSS 6.8)
CVE: CVE-2025-40949 (persistent RCE via cron injection, CVSS 9.1)
Advisories: SSA-973901, SSA-078743, SSA-081142
Fixed firmware: ROX II V2.17.1
```

### 3.3 Windows LegacyHive Zero-Day Grants Admin on Fully Patched Systems

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/)

A researcher using the handle "Nightmare Eclipse" publicly released a Windows privilege-escalation exploit dubbed LegacyHive that yields administrator access on up-to-date Windows systems. Full technical details are still being validated, but the exploit is publicly available and maps to **T1068 – Exploitation for Privilege Escalation**. Two additional local-EoP items surfaced the same day — CVE-2026-58635 (Windows Narrator Braille standard-user → SYSTEM) and CVE-2026-58613 (Cloud Files Mini Filter driver use-after-free) — suggesting a wider cluster of Windows local EoP research being weaponised.

> **SOC Action:** Prioritise EDR detections for unexpected token-manipulation, LSASS-adjacent process creation, and integrity-level jumps on user workstations. Query for new administrative accounts, service creations by non-admin users, and scheduled-task creation by unprivileged principals. Track Microsoft's out-of-band or next Patch Tuesday for a LegacyHive fix and stage rollout ahead of predicted commodification.

### 3.4 Firefox WebAssembly RCE — CVE-2026-2796

**Source:** Telegram (channel name redacted)

A public write-up describes reverse engineering of an RCE exploit against Firefox via CVE-2026-2796 in the WebAssembly engine. Crafted WebAssembly modules bypass existing hardening and yield code execution in browser context, aligning with **T1064 – Scripting**. Given the ease of drive-by delivery for browser bugs, this raises the probability of watering-hole and malvertising abuse in the coming days.

> **SOC Action:** Confirm managed-browser fleet is on a Firefox build patched against CVE-2026-2796 (verify via `about:support` or your configuration-management inventory). For unmanaged BYOD, push an announcement to update Firefox and consider temporary blocking of high-risk domains at the proxy. Hunt for `firefox.exe`/`Firefox` spawning `powershell`, `cmd`, or `mshta` in EDR telemetry.

### 3.5 DPRK REF9403 Contagious Interview — SVG Steganography, OTTERCOOKIE-Family Payloads

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography)

Elastic Security Labs detected REF9403, a Contagious Interview cluster targeting developers via fake job offers on public developer Slack workspaces. Actors delivered trojanised Next.js e-commerce repositories containing steganographically hidden payloads inside SVG flag images. Execution deploys a four-stage OTTERCOOKIE-aligned payload: browser credential and crypto-wallet stealer, file stealer, Socket.IO-based RAT, and clipboard stealer. Notable finding: zero antivirus detections at the time of discovery across sample archives (`next-ecommerce-private-main.zip`, `shopping-platform-main.zip`, `ecommerce-platform.zip`, `shop-main.zip`, and variants). MITRE mapping: **T1566 (Phishing)**, **T1078 (Valid Accounts)**, **T1003 (OS Credential Dumping)**.

> **SOC Action:** Brief developer-facing channels on the fake-recruiter lure pattern and remind engineers not to execute unverified `npm install && npm start` from unsolicited coding challenges. Query EDR for `node.exe` / `node` executing from user profile paths and initiating outbound Socket.IO/WebSocket connections. Extract and scan any `.svg` files delivered in ZIP/RAR archives from Slack, Discord, Telegram, or LinkedIn recruiter chats.

#### Indicators of Compromise

```
Archive: next-ecommerce-private-main.zip
Archive: shopping-platform-main.zip
Archive: ecommerce-platform.zip
Archive: ecommerce-platform-main.zip
Archive: shopping-platform.rar
Archive: shop-main.zip
Archive: ecommerce-main.zip
Family: OTTERCOOKIE (multi-stage stealer + Socket.IO RAT)
Cluster: REF9403 (DPRK-aligned Contagious Interview)
```

### 3.6 ACR Stealer — ClickFix + WebDAV + Blockchain C2

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a59832ac2ebd9e525a462b9)

Microsoft's research (published via AlienVault OTX) tracks two distinct ACR Stealer intrusion chains — an Amatera-rebrand malware-as-a-service — using ClickFix social-engineering lures. Chain one uses WebDAV-delivered Python loaders with blockchain dead-drop C2 resolution; chain two is fileless via `mshta` and steganography-concealed payloads inside images. Both harvest browser credentials, auth tokens, and Microsoft 365 / PDF documents. Techniques include **T1055** (Process Injection), **T1218.005** (mshta), **T1027.003** (obfuscation), **T1053.005** (scheduled-task persistence).

> **SOC Action:** Alert on `mshta.exe` launched from user temp directories, `powershell` with base64/obfuscated command lines spawned from Office or browser processes, and outbound connections to blockchain RPC endpoints from workstation zones. Block the domains listed below at the proxy/DNS layer and hunt historical DNS logs for any prior resolution.

#### Indicators of Compromise

```
Domain: apigrokcloud[.]icu
Domain: auramatrixa[.]com
Domain: cpppemwjewjoiwejow[.]sale
Domain: creativecommunityinfo[.]art
Domain: deep-harborio[.]com
Domain: enhanceblabber[.]cc
Domain: looksta[.]icu
Domain: prism-matrixs[.]com
Domain: prism-vertex[.]com
Domain: proton-network[.]com
Domain: zealpraxis[.]com
Hostname: breaksd.wifihot[.]icu
Hostname: contrite.quirksturdy[.]icu
Hostname: fast.raidher[.]icu
Hostname: ux.strainedeasily[.]icu
Hostname: walter.filloco[.]icu
```

### 3.7 Ransomware Pressure — The Gentlemen, Qilin, Akira

**Source:** [RansomLook.io](https://www.ransomlook.io/)

Yesterday's leak-site posts show three RaaS operations dominating volume. **The Gentlemen** disclosed victims including Military Sealift Command, Sunway Scientific, and Advantage Home Health Care — Unit 42 / Elastic correlation pairs this group's phishing + valid-accounts tradecraft (**T1566**, **T1078**) with high confidence. **Qilin** posted Cafar and Acosol; **Akira** posted Westcoast Communication Services and Nesco Bus Maintenance, continuing its documented pattern of exploiting unpatched VPNs, compromised RDP, and phishing against education, manufacturing, and healthcare. Additional posts from Nova (RALord rebrand), PLAY (Hive affiliate), Inc Ransom, Krybit, and M3rx round out an unusually active leak-site day.

> **SOC Action:** For any Fortinet/VPN concentrator, force-verify MFA enrolment on all remote-access accounts and rotate service-account passwords older than 90 days. Enable Windows Defender Attack Surface Reduction rules for LSASS credential theft and block-mode PsExec-style tooling. If your organisation is in defence-adjacent, industrial, or healthcare verticals, treat The Gentlemen / Akira / Qilin TTPs as this week's top hunting focus.

### 3.8 Microsoft July "Patch Wars" — 622 CVEs, 3 Zero-Days, 2 Actively Exploited

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a5947760995db41a09b5025)

An AlienVault OTX write-up flags Microsoft's July Patch Tuesday as the largest ever: 622 vulnerability patches, 62 rated critical, three zero-days including two under active exploitation. The volume is attributed to AI-frontier-model-accelerated vulnerability research and pushes IT patch-test cycles beyond their historical capacity. The pulse also links the Russian-speaking intrusion set **UAT-11795** to observed use of CastleStealer, Starland RAT, Remcos RAT, and WLDR agent delivered via trojanised installers and ClickFix lures. MITRE: **T1566 (Phishing)**, **T1059.001 (PowerShell)**, **T1055 (Process Injection)**, **T1204 (User Execution)**.

> **SOC Action:** Reprioritise patching against the two actively exploited zero-days first, KEV additions next, then CVSS ≥ 9.0 remaining. For hunt teams, layer detections for Remcos RAT C2 patterns, Starland RAT, and CastleStealer file hashes below.

#### Indicators of Compromise

```
SHA256: 90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59
SHA256: 9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f
SHA256: 9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507
SHA256: b8be9a5e0a191050f9099c11c155b436863e9bc43bc904cdb842e249679aa35a
Hostname: w32.b8be9a5e0a-95.sbx[.]tg
Intrusion Set: UAT-11795 (Russian-speaking, financially motivated)
Families: CastleStealer, Starland RAT, Remcos RAT, WLDR agent
```

### 3.9 ClickLock macOS Credential-Theft Malware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-clicklock-macos-malware-traps-users-into-revealing-login-password/)

A new macOS information-stealer named ClickLock forces the user to re-enter their login password by terminating all visible processes on the desktop, then harvests the credentials. Delivery is phishing-driven (**T1566**, **T1204**). ClickLock joins ACR Stealer and OTTERCOOKIE as the third notable credential-stealer disclosure in the same 24-hour window, reinforcing that infostealer volume, not novelty, is the current defensive challenge.

> **SOC Action:** For macOS fleets, alert on unusual `AppleScript` or Automator activity forcing GUI logout events, and confirm your MDM enforces FileVault + Gatekeeper. Rotate credentials for any user whose macOS device shows unexplained forced-logout events in the last 30 days.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Exploitation of software vulnerabilities for privilege escalation and denial of service | Windows LegacyHive zero-day; CVE-2026-58635 (Narrator Braille EoP); CVE-2026-58613 (Cloud Files use-after-free) — shared TTP T1068 across three reports (confidence 0.90) |
| 🟠 HIGH | Increased ransomware activities targeting diverse sectors with sophisticated TTPs | Qilin (Cafar, Acosol); The Gentlemen (Military Sealift Command, Sunway Scientific, Advantage Home Health Care); Akira (Westcoast, Nesco) — shared actor + T1486 encryption (confidence 0.90) |
| 🟠 HIGH | Phishing campaigns leveraging valid accounts and credential theft | Military Sealift Command intrusion + DPRK Contagious Interview — shared TTPs T1566 + T1078 (confidence 0.90) |
| 🟠 HIGH | Resource-hijacking / DoS class exploited across mixed products | HollowByte OpenSSL DDoS + CVE-2026-59885 (pyasn1 quadratic complexity) + CVE-2026-15709 (libsoup permessage-deflate) — shared TTP T1496 (confidence 0.80) |
| 🟡 MEDIUM | Technology-sector concentration | HollowByte OpenSSL, CVE-2026-58613 (Cloud Files), CVE-2026-15713 (libsoup HTTP/2) grouped by sector (confidence 0.70) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (105 reports) — RaaS group; military, healthcare, manufacturing; phishing + double extortion; last seen 2026-07-17
- **Qilin** (84 reports) — Active RaaS operation on Jabber/Tox with multi-onion infrastructure; last seen 2026-07-17
- **DragonForce** (41 reports) — Cross-sector encryption + data-leak operation; last seen 2026-07-16
- **Lockbit5** (36 reports) — Continuing LockBit rebrand; last seen 2026-07-10
- **Akira** (26 reports) — Windows + Linux/ESXi double extortion; VPN/RDP/phishing initial access; last seen 2026-07-17
- **Inc Ransom** (17 reports) — Tor-hosted leak infrastructure; phishing entry vector; last seen 2026-07-17
- **Nova** (15 reports) — RALord rebrand; CAPTCHA-gated leak site; last seen 2026-07-17
- **ShinyHunters** (15 reports) — Credential-theft and extortion; last seen 2026-07-14
- **Stormous** (15 reports) — Sporadic activity; last seen 2026-07-02
- **Cmd Organization** (14 reports) — Phishing-heavy operation; last seen 2026-07-16

### Malware Families

- **Akira ransomware** (13 reports) — CryptoAPI-based Windows encryptor, `.akira` extension
- **DragonForce ransomware** (13 reports) — Cross-sector victims
- **The Gentlemen ransomware** (12 reports) — Tox/onion C2 pairing
- **Chaos Ransomware** (11 reports) — Ongoing commodity family
- **Qilin ransomware** (11 reports) — RaaS payload family
- **OTTERCOOKIE** (new) — DPRK Contagious Interview four-stage stealer + Socket.IO RAT
- **ACR Stealer / Amatera** (new coverage) — MaaS infostealer via ClickFix + WebDAV
- **ClickLock** (new) — macOS credential-theft via forced re-authentication
- **CastleStealer / Starland RAT / Remcos RAT / WLDR agent** — Delivered by UAT-11795

*Note: RansomLook and Tox/Tox1 entries in the pipeline are infrastructure indicators (leak-site tracker and messaging protocol) rather than distinct malware families and have been excluded above.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 26 | [link](https://www.ransomlook.io/) | Ransomware leak-site tracking; The Gentlemen, Qilin, Akira, PLAY, Nova, Krybit posts |
| Microsoft | 15 | [link](https://msrc.microsoft.com/update-guide/) | Perl/libsoup/pyasn1 CVE cluster; MSRC update-guide feed |
| BleepingComputer | 9 | [link](https://www.bleepingcomputer.com/news/security/cisa-warns-feds-to-patch-exploited-fortinet-fortisandbox-flaws-by-sunday/) | Primary coverage of LegacyHive, CISA/Fortinet, ClickLock, HollowByte, Fairlife |
| Unknown / Telegram | 4 | — | CVE-2026-58635, CVE-2026-2796, CVE-2026-58613 EoP write-ups (Telegram-sourced, URLs redacted) |
| RecordedFutures | 3 | [link](https://therecord.media/dairy-company-fairlife-suspends-production-us-cyber-incident) | Fairlife/Coca-Cola incident; Ukraine defence appointments |
| AlienVault | 2 | [link](https://otx.alienvault.com/pulse/6a59832ac2ebd9e525a462b9) | ACR Stealer chains; "Patch Wars" analysis with UAT-11795 IOCs |
| Unit42 | 2 | [link](https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/) | Siemens ROX II trilogy; Global IR Report 2026 |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography) | DPRK REF9403 / Contagious Interview / OTTERCOOKIE |
| Schneier | 1 | [link](https://www.schneier.com/) | Commentary |
| Upwind | 1 | [link](https://www.upwind.io/) | Cloud-security research |
| Wired Security | 1 | [link](https://www.wired.com/story/san-francisco-demands-apple-and-google-delete-ai-nudify-apps-from-app-stores/) | San Francisco cease-and-desist to Apple/Google |
| SANS | 1 | [link](https://isc.sans.edu/) | ISC handler diary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Fortinet FortiSandbox before Sunday's CISA deadline and pull 60 days of admin-plane logs for anomalous activity (traces to §3.1). Confirm Firefox fleet is off the CVE-2026-2796 build (§3.4).
- 🔴 **IMMEDIATE:** For any Siemens Ruggedcom ROX II in industrial or utility environments, schedule firmware V2.17.1 upgrade and restrict management-plane exposure until patched (§3.2).
- 🟠 **SHORT-TERM:** Deploy detections for Windows local privilege-escalation activity (unexpected integrity-level jumps, LSASS token theft, service creation by non-admins) ahead of LegacyHive weaponisation, and stage next Patch Tuesday for out-of-band coverage (§3.3, §3.8).
- 🟠 **SHORT-TERM:** Brief developer-facing communities on the DPRK fake-recruiter / trojanised coding-challenge pattern; block the ACR Stealer domains at proxy/DNS and add EDR alerts for `mshta.exe` from user temp directories (§3.5, §3.6).
- 🟡 **AWARENESS:** Assume elevated ransomware likelihood in defence-adjacent, healthcare, education, and manufacturing verticals; validate MFA on all remote-access accounts and rotate stale service-account credentials for VPN/RDP/ESXi management planes (§3.7).
- 🟢 **STRATEGIC:** The record-volume July Patch Tuesday combined with AI-accelerated vulnerability discovery signals a sustained new operational tempo — review whether patch-testing capacity, KEV-monitoring processes, and change-approval SLAs can absorb this as the steady state, not a one-off spike (§3.8).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 66 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
