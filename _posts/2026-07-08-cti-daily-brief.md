---
layout: post
title:  "CTI Daily Brief: 2026-07-08 - Microsoft patches RoguePlanet Defender zero-day; CISA OpenPLC v3 CVSS 9.9 RCE; Helix vishing crew targets SharePoint"
date:   2026-07-09 20:07:54 +0000
description: "99 reports across 15 sources. 7 critical items dominated by a Microsoft Defender RoguePlanet zero-day patch, a CISA OpenPLC v3 CVSS 9.9 file-write-to-RCE flaw, and an OpenSSL/xorg-server/font-atlas critical batch. New Helix vishing crew and Forg365 AI-driven PhaaS both hit Microsoft 365/SharePoint identity. SentinelOne exposes China- and India-nexus espionage converging on Pakistani law enforcement."
category: daily
tags: [cti, daily-brief, helix, rare-werewolf, qilin, vidar, cve-2026-14480, cve-2026-54891]
classification: TLP:CLEAR
reporting_period: "2026-07-08"
generated: "2026-07-09"
severity: critical
draft: true
report_count: 99
sources:
  - Microsoft
  - BleepingComputer
  - CISA
  - RecordedFutures
  - AlienVault
  - Sentinel One
  - Cisco Talos
  - RansomLock
  - Wiz
  - Permiso
  - SANS
  - Wired Security
  - Schneier
  - Upwind
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-08 (24h) | TLP:CLEAR | 2026-07-09 |

## 1. Executive Summary

The pipeline processed **99 reports across 15 sources** in the last 24 hours, with 7 critical, 49 high, 22 medium, 6 low, and 15 informational items. The dominant theme is a large Microsoft-tracked vulnerability wave — a RoguePlanet Defender zero-day patch, a CISA OpenPLC v3 CVSS 9.9 authenticated file-write-to-RCE (CVE-2026-14480), and a critical batch of TLS/crypto/xorg-server flaws (CVE-2026-54891, CVE-2026-8925, CVE-2026-9545, CVE-2026-55999, CVE-2026-56002). Identity-focused attacks against Microsoft 365 and SharePoint escalated with the emergence of the **Helix** vishing/device-code crew and the **Forg365** AI-driven phishing-as-a-service platform. SentinelOne published a significant nation-state disclosure — suspected **China- and India-nexus** espionage actors converging on Pakistani law enforcement (Balochistan Police) using PlugX, ShadowPad, Cobalt Strike, and Remcos. Ransomware activity remained heavy, with **Qilin** leading same-day leak-site postings and Latvia's state forestry firm LVM still restoring operations weeks after a NATO-adjacent ransomware intrusion. No CISA KEV additions were observed for the period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 7 | OpenPLC v3 file-write-to-RCE (CVSS 9.9); Microsoft Defender RoguePlanet zero-day patch; TLS 1.3 plaintext injection; SASL double-free; HTTP/3 early-data exposure; xorg-server / libXfont2 heap overflows |
| 🟠 **HIGH** | 49 | Helix vishing vs. SharePoint; Forg365 AI PhaaS vs. M365; China/India-nexus espionage on Pakistani LE; Vidar via Steam/Telegram dead drops; Operation Muck and Load (222-repo GitHub lure); Rare Werewolf vs. Russian aerospace; LVM Latvia ransomware; Schneider ICS; OpenSSH pre-10.4 batch; WinRAR CVE-2026-14191 |
| 🟡 **MEDIUM** | 22 | Bulk Microsoft-tracked kernel and library CVEs; ESET H1 2026 threat report |
| 🟢 **LOW** | 6 | Lower-tier CVE disclosures |
| 🔵 **INFO** | 15 | Pipeline context and background items |

## 3. Priority Intelligence Items

### 3.1 CISA ICS Advisory — OpenPLC v3 Authenticated File-Write to RCE (CVE-2026-14480, CVSS 9.9)

**Source:** [CISA ICSA-26-190-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-190-01)

CISA issued a critical advisory for OpenPLC v3, an open-source PLC runtime deployed worldwide in Critical Manufacturing, Energy, Transportation, and Water/Wastewater. CVE-2026-14480 (CVSS 3.1 = 9.9, CWE-73) is an authenticated arbitrary file write in the legacy web UI program-upload workflow. The application stores the attacker-supplied `prog_file` value directly and passes it to `os.path.join()`, which honours absolute paths. An authenticated attacker can drop a malicious `.cpp` into the OpenPLC runtime source directory; the next normal program compilation escalates the write into native code execution as the runtime user. OpenPLC v3 is **end-of-life** — the only vendor remediation is migration to OpenPLC v4. Reported by Grady DeRosa.

> **SOC Action:** Inventory OpenPLC v3 exposure across OT/ICS assets. Where migration to v4 is not immediately possible, ensure the OpenPLC web UI is not internet-reachable, place devices behind a firewalled OT network with jump-host access only, restrict web-UI accounts to named operators, and monitor file writes into the OpenPLC runtime source directory (T1105 / T1059). Segment away from business networks per CISA recommended practices.

### 3.2 Microsoft Patches RoguePlanet Defender Zero-Day

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-rogueplanet-defender-zero-day-vulnerability/)

Microsoft released an out-of-band security update for a Microsoft Defender zero-day tracked internally as "RoguePlanet," disclosed after June 2026 Patch Tuesday. The BleepingComputer report confirms the patch and the zero-day status but does not attribute in-the-wild exploitation to a named actor or provide a public CVE mapping in the summary text.

> **SOC Action:** Confirm the RoguePlanet patch has landed on all Defender-managed endpoints and servers (verify engine and platform version post-update). Prioritise domain controllers, tier-0 assets, and internet-exposed servers. Sweep Defender exclusion policies and tamper-protection state for recent, unexpected changes that could indicate pre-patch exploitation.

### 3.3 Critical Cryptographic & Display Server Batch (Microsoft-Tracked)

**Source:** Microsoft Security Update Guide (multiple advisories, e.g., [CVE-2026-54891](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54891))

Five critical CVEs were ingested from Microsoft's vulnerability feed covering foundational libraries used across Linux, containers, and application stacks:

- **CVE-2026-54891** — TLS 1.3: plaintext `APPLICATION_DATA` injected during the handshake is delivered to client applications after the handshake completes, breaking record-layer isolation.
- **CVE-2026-8925** — SASL library double-free (potential memory corruption / RCE surface for anything using SASL SASL2/GSSAPI, e.g., LDAP, SMTP, IMAP).
- **CVE-2026-9545** — HTTP/3 stack exposes early data (0-RTT) allowing replay/exposure of otherwise protected traffic.
- **CVE-2026-55999 / CVE-2026-56002** — `xorg-server`/`xwayland` glamor font-atlas and `libXfont2` PCF parsing heap buffer overflows (local-to-remote depending on X11 exposure).

Related high-severity items in the same wave: `CVE-2026-55952` (TLS 1.3 pre-shared-key DoS), `CVE-2026-14355` (PHP `openssl_encrypt` AES-WRAP-PAD memory corruption), `CVE-2026-10536` (HTTP/2 UAF), `CVE-2026-58055` (nghttp2 request smuggling), `CVE-2026-56000/56001/56003` (additional xorg/libXfont2 heap issues).

> **SOC Action:** Task vulnerability management to pull vendor SBOMs for `openssl`, `cyrus-sasl`/`gsasl`, `nghttp2`, `xorg-server`/`xwayland`, and `libXfont2` and identify update windows. For TLS-1.3 (CVE-2026-54891) and the HTTP/3 issue (CVE-2026-9545), prioritise reverse proxies, CDN edge nodes, and application gateways. Do NOT assume Windows-only exposure — many of these ship in Linux-based container images across the environment.

### 3.4 New Helix Vishing Crew Targeting SharePoint via Device-Code Phishing & MFA Abuse

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-helix-vishing-group-emerges-in-sharepoint-data-theft-attacks/)

A new data-extortion group, **Helix**, is combining voice phishing (vishing), OAuth device-code phishing, and MFA-fatigue/impersonation to steal data out of SharePoint environments. MITRE mapping in the report: T1566 (Phishing), T1558.002 (Impersonate Trusted Entity — MFA abuse), T1558.003 (Steal or Forge Kerberos Tickets — device-code phishing pathway). No IOCs were published in the ingested description.

> **SOC Action:** Disable end-user device-code flow in Entra ID where not required (Conditional Access → block `deviceCodeFlow`). Alert on device-code sign-ins from atypical geographies and any device-code sign-in that is followed within 15 minutes by SharePoint Online graph downloads over 100 MB. Brief the service desk on vishing pretexts (MFA "test", "help me approve") and require callback verification for MFA resets.

### 3.5 Forg365 — AI-Assisted Phishing-as-a-Service vs. Microsoft 365

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-forg365-phishing-platform-uses-ai-to-target-microsoft-365-accounts/)

A new PhaaS operation, **Forg365**, targets Microsoft 365 accounts by pairing adversary-in-the-middle (AiTM) session capture with device-code phishing and AI-generated lure content. MITRE: T1566. This lowers the technical bar for MFA-bypass phishing against tenants that do not enforce phishing-resistant MFA.

> **SOC Action:** Enforce phishing-resistant MFA (FIDO2 keys, Windows Hello for Business, or certificate-based auth) for privileged and finance/HR users; require session-token binding where available. Hunt for AiTM tell-tales in Entra sign-in logs: unusual user-agent + session ID reuse across geographically distant IPs within a short window (T1078).

### 3.6 China- and India-Nexus Espionage Converge on Pakistani Law Enforcement

**Source:** [SentinelLABS](https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/)

SentinelLABS reports sustained cyberespionage against several Pakistani law-enforcement organisations from **February 2024 to April 2026**, with both a suspected **China-nexus** actor and a suspected **India-nexus** actor converging on **Balochistan Police**. Compromised assets included web applications managing biometric, hotel/tenant, and criminal records. Netflow analysis observed PlugX, ShadowPad, Cobalt Strike, and Remcos C2. A suspected China-nexus actor also planted implants in a citizen-facing police web app disguised as a portal update. Attribution is hedged ("suspected") and should not be upgraded.

> **SOC Action:** For organisations touching Pakistan or CPEC-adjacent supply chains: hunt for PlugX / ShadowPad loader patterns (DLL sideloading with legitimate signed binaries, T1574.002), Cobalt Strike named-pipe patterns, and Remcos C2. Extend web-app monitoring to citizen-facing portals — validate deployment pipelines against unauthorised "update" pushes.

### 3.7 Vidar Infostealer Delivered via Phishing With Steam/Telegram Dead Drops

**Source:** [AlienVault OTX Pulse](https://otx.alienvault.com/pulse/6a4f85b7629d0335b2a22436)

Vidar (MaaS infostealer, active since 2018) is being distributed through Korean-language phishing lures disguised as job applications and copyright-infringement notices, with attachments appearing as Word documents but actually being Go-packed executables. The malware uses a **Dead Drop Resolver** technique — pulling C2 addresses from **Steam profiles and Telegram channels** — plus anti-debug and anti-VM checks. Exfiltrated data includes browser credentials, cookies, history, cryptocurrency wallets, Discord/Steam/Telegram artefacts, Azure credentials, and screenshots. MITRE: T1566.001, T1102.001, T1555.003, T1567.002, T1497.001.

#### Indicators of Compromise
```
SHA256: 340820f7f4c97e3a2477bc99acf746e13b2c92719ebf5c9947a62eef7ec0dddb
SHA256: cff8b04f2c8ed63d37fd393ad23652a8b818e80b03851d7c1bd5842963a03348
SHA256: e8e7faa5e76dc773ffb1a7a6be36a47cc84e3ed45b928859b570332757cdb6cb
Host:   ctl.it-bd[.]com
Host:   frr.ambil-disini.web[.]id
Host:   gor.emiraride[.]com
Host:   gre.syslicense[.]net
Host:   lat.sodstreams[.]com
```

> **SOC Action:** Block the listed hosts and hashes at proxy/EDR. Add Steam Community and Telegram-channel-profile fetches from user endpoints to your egress-anomaly ruleset — legitimate business rarely resolves C2 out of gaming/social-profile bios. Query for `.doc.exe`/double-extension attachments in mail hygiene logs.

### 3.8 Operation "Muck and Load" — 222-Repo GitHub Malware Lure Network

**Source:** [Socket / Kirill Boychenko](https://socket.dev/blog/malicious-go-module-exposes-github-malware-lure-network)

A malicious Go module (`github[.]com/kaleidora/dnsub-scanning-tool`) posing as a DNS/subdomain scanner exposed a broader GitHub-based lure network of **222 confirmed repositories across 190 accounts**, tracked as **Operation Muck and Load**. The chain uses hidden PowerShell execution, public dead-drop resolvers, and password-protected archives to stage Windows RATs and infostealers — confirmed families include **AsyncRAT, Quasar, Remcos, Vidar,** and **XMRig/BitMiner**. Go security team has blocked the module from the proxy. MITRE: T1195.001, T1204.002, T1059.001, T1071.001, T1102.001, T1140, T1543.003, T1608.001.

#### Indicators of Compromise
```
Domain: muckcoding[.]com
Domain: muckdeveloper[.]com
Domain: rlim[.]com
URL:    hxxps[:]//muckcoding[.]com/LG-LW/Api-Certificate
URL:    hxxps[:]//muckdeveloper[.]com/LGTV/MicrosoftCur
URL:    hxxps[:]//rlim[.]com/MicrosoftCur/raw
SHA256: 129de16fe69763f767d8249279a2c4a1a6deafadd1a84563bd84b258ea010bff
SHA256: 235a64e3520b1c2c27763122b303f78aee8d7c083dfd9f1eb936cd5174383609
SHA256: 4ea1c577247b149489506b230e7aa203e1a2fa124109c6056d1986e944f520a4
SHA256: 810614290bdb14d2ddf10f65f8adc988a8272764f2a9e2c378e52fad162da344
SHA256: a628ad47fe93ee7413cca90aeca8f9540bfcd5ccdbeb4d9914670b3ef66247f4
```

> **SOC Action:** Block the three domains at proxy/DNS. Sweep dev workstations and CI runners for `go get` / `go install` events involving `kaleidora/*` or any of the observed hashes over the last 60 days. Enforce commit-signature verification and require review for third-party GitHub dependencies pulled by CI. Alert on `powershell.exe` invocations spawning from Go build artefacts.

### 3.9 Rare Werewolf Spear-Phishing Russian Aerospace With AnyDesk Persistence

**Source:** [Seqrite (via AlienVault)](https://www.seqrite.com/blog/from-invoice-to-anydesk-uncovering-a-phishing-campaign-targeting-russian-aerospace-organizations/)

A spear-phishing campaign impersonating Russian aerospace institute VNIIR (spoofed `vniir-avia.space` and `vniir-info.space` domains) delivers password-protected archives that ultimately configure **AnyDesk for unattended remote access**, exfiltrating AnyDesk config data over SMTP to attacker-controlled email accounts. Seqrite assesses possible attribution to **Rare Werewolf** (a.k.a. Librarian Ghouls), a group historically targeting Russia, Belarus, and Kazakhstan across aerospace, engineering, petrochemical, and industrial verticals. XMRig deployment is a documented post-compromise behaviour but was not observed in this sample. MITRE: T1566.001, T1204.002, T1219 (Remote Access Software), T1053.005, T1547, T1564.003.

#### Indicators of Compromise
```
Domain: vniir-avia[.]space
Domain: vniir-info[.]space
IP:     109.106.178[.]14
IP:     194.87.57[.]81
IP:     198.54.120[.]13
SHA256: 0dc0fa727f900ed5033f46f8ba6cf2d97d20ab95fd334cabc0f216da6e0622b0
SHA256: 12648cd9d425f78db2dbc6e03c14f11e6ac6aadf8b3975c23cce9519e2b58d33
SHA256: 47854deb456cb08c651b7f9ae2f9d87c72d0719de6af233340632efb3c1980f4
SHA256: f57e010541fb4ccbf23aefc4a827f753a6ff3f8792d9c04c3eea83f6963c6bae
```

> **SOC Action:** Alert on any AnyDesk installation followed within one hour by AnyDesk `--set-password` or unattended-access configuration changes (T1219). Query mail hygiene for freshly-registered `.space` lookalike sender domains and undisclosed-recipient invoice lures. Block the three IPs at the egress firewall.

### 3.10 LVM (Latvia) — State Forestry Company Still Restoring Systems

**Source:** [The Record / Recorded Future](https://therecord.media/latvia-state-owned-foresty-company-lvm-ransomware)

Latvia's state-owned forestry company **LVM (Latvijas Valsts Meži)** is still restoring services weeks after a late-June ransomware intrusion that took its mapping platform, hunting application, and contractor/customer systems offline. Attackers dwelled inside the network for over a week before detection and exploited an unpatched vulnerability in a system that had not been updated for two years. **CERT.LV** attributed the intrusion to a foreign, financially motivated ransomware group that has previously targeted NATO/EU organisations; the group has not been publicly named. Approximately 44 GB of internal documents, source code, digital certificates, cryptographic keys, and user credentials were leaked; investigators believe more was exfiltrated than published. CERT.LV also confirmed the same actor compromised Latvian pharma **Olpha (formerly Olainfarm)** — the two intrusions are technically unrelated. Latvia's electronic voter-registration system was **not** compromised (developed in an isolated environment).

> **SOC Action:** Treat this as a vulnerability-hygiene lesson: identify all internet-facing applications with patch levels older than 12 months and force a patch-or-decommission decision this week. Rotate any cryptographic keys or credentials that may have been present in shared repositories; assume leaked source code has been mined for hard-coded secrets.

## 4. AI-Identified Correlation Trends

Batch 219 (2026-07-09 06:16 UTC) surfaced two high-risk trends from a 12-report tier-1 window; batch 218 (2026-07-08 19:14 UTC) added two ransomware-sector trends. All trends carry the AI landscape summary's hedged framing.

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Increased targeting of the **education sector** by various threat actors using different TTPs | "Mount Royal University confirms breach"; "Hackers exploit Roundcube flaw to spy on academic researchers" |
| 🟠 **HIGH** | **Financial services** facing credential theft and regulatory pressure | "Fake Paysafe, Skrill SDKs on NPM and PyPi steal credentials"; "Cash App owner to pay $45 million to settle allegations of lax security" |
| 🟠 **HIGH** | Ransomware wave against **healthcare and dental** sectors, phishing-led | "Creative Smiles Pediatric Dentistry By crpx0"; "SF Smile Doctor By crpx0"; "Bishop Arts Dental PLLC By crpx0"; "Top Notch Dentistry of Dallas By crpx0" |
| 🟠 **HIGH** | RaaS groups (**Chaos, Crpx0**) expanding cross-sector | "corepharma.com By chaos"; "opportune.com By chaos"; "AMHWA Biopharm Co., Ltd. By crpx0" |

No critical-risk correlation trends were identified for the reporting period.

## 5. Trending Entities (Pipeline-Wide)

Trending across the ingestion window (last ~30 days) — provides context on which actors and families the pipeline is currently prioritising.

### Threat Actors

- **The Gentlemen** (98 reports) — active RaaS/data-leak brand; not tied to today's items
- **Qilin** (81 reports) — active in yesterday's leak-site postings (Inter Power Engineering, Sun Dolphin Boats, Bronken's Dist, Alan F Burke, Hum & Jacoby, Peligro Sports)
- **Deadlock** (55 reports) — dormant recently; last seen 2026-06-15
- **Lockbit5** (31 reports) — cluster from 2026-06-18
- **DragonForce** (26 reports) — active this week
- **Akira** (25 reports) — active this week
- **ShinyHunters / Shinyhunters** (20+20 reports) — duplicate entity spellings in feed
- **Inc Ransom** (16 reports); **Stormous** (16 reports)

### Malware Families

- **RansomLook** (158 reports) — leak-site tracker artefact, not itself malware
- **Tox1 / Tox** (67 / 39 reports) — active clustering entity
- **Akira ransomware** (12 reports); **Qilin** (11 reports); **The Gentlemen ransomware** (11 reports)
- **Anubis ransomware / Anubis banking trojan** (11 / 10 reports)
- **Deadlock** (10 reports)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 54 | [MSRC Update Guide](https://msrc.microsoft.com/update-guide) | Dominant driver — vulnerability feed including the critical TLS/xorg/OpenSSH batch |
| RansomLock | 11 | [ransomlook.io](https://www.ransomlook.io) | Leak-site telemetry, mostly Qilin, Brain Cipher, PAYLOAD, Ailock, Chaos |
| BleepingComputer | 9 | [bleepingcomputer.com](https://www.bleepingcomputer.com) | RoguePlanet patch, Helix, Forg365 |
| RecordedFutures | 5 | [therecord.media](https://therecord.media) | LVM Latvia ransomware; EU NIS2 enforcement action |
| CISA | 3 | [cisa.gov ICS Advisories](https://www.cisa.gov/news-events/ics-advisories) | OpenPLC v3 (crit); Schneider PowerChute; Schneider Easergy MiCOM |
| AlienVault | 3 | [otx.alienvault.com](https://otx.alienvault.com) | Vidar; Rare Werewolf; Operation Muck and Load |
| Wired Security | 2 | [wired.com/category/security](https://www.wired.com/category/security) | Coverage |
| SANS | 2 | [isc.sans.edu](https://isc.sans.edu) | Diaries |
| Wiz | 2 | [wiz.io/blog](https://www.wiz.io/blog) | Verizon DBIR commentary |
| Permiso | 2 | [permiso.io/blog](https://permiso.io/blog) | Identity analysis |
| Unknown / Telegram | 2 | — | WebAssembly abuse item; Telegram (channel name redacted) |
| Sentinel One | 1 | [sentinelone.com/labs](https://www.sentinelone.com/labs) | Pakistan LE espionage convergence |
| Cisco Talos | 1 | [blog.talosintelligence.com](https://blog.talosintelligence.com) | "Winning 54% of the time" |
| Schneier | 1 | [schneier.com/blog](https://www.schneier.com/blog) | Commentary |
| Upwind | 1 | [upwind.io/feed](https://www.upwind.io/feed) | Cloud item |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Deploy the Microsoft Defender **RoguePlanet** out-of-band patch to all Defender-managed endpoints today; audit Defender exclusion lists and tamper-protection state for pre-patch tampering (§3.2).
- 🔴 **IMMEDIATE:** For any OpenPLC v3 deployment reachable from an operator workstation, block web-UI access and begin migration to OpenPLC v4 — v3 is EOL and CVE-2026-14480 is CVSS 9.9 authenticated file-write-to-RCE (§3.1).
- 🟠 **SHORT-TERM:** Patch the Microsoft-tracked critical library batch (TLS 1.3, SASL, HTTP/3, xorg-server, libXfont2 — §3.3) with priority to reverse proxies, application gateways, and CDN edge; extend to container base-images.
- 🟠 **SHORT-TERM:** Disable end-user Entra ID **device-code flow** where not required and roll out phishing-resistant MFA for privileged users to blunt both Helix (§3.4) and Forg365 (§3.5).
- 🟠 **SHORT-TERM:** Block the Vidar (§3.7), Muck and Load (§3.8), and Rare Werewolf (§3.9) IOC sets at proxy/EDR/DNS; retro-hunt 60 days.
- 🟡 **AWARENESS:** Brief the service desk on vishing pretexts targeting SharePoint (Helix) — require callback verification for MFA resets and device-code approvals.
- 🟢 **STRATEGIC:** Treat the LVM Latvia incident (§3.10) as a forcing function to enumerate internet-facing applications with patch levels older than 12 months and drive a patch-or-decommission cycle. Assume any leaked source repository will be mined for hard-coded credentials.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 99 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
