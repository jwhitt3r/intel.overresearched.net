---
layout: post
title:  "CTI Daily Brief: 2026-06-22 — SonicWall CVE-2024-40766 escalation by Akira/Fog, Icarus extortion of LastPass via Klue OAuth, FFmpeg PixelSmash RCE, Scattered Spider TfL guilty pleas"
date:   2026-06-23 20:08:58 +0000
description: "61 reports across 14 sources. Critical activity centred on Akira/Fog ransomware exploitation of SonicWall SSLVPN (CVE-2024-40766), Icarus extortion via Klue OAuth supply-chain breach impacting LastPass and Salesforce tenants, and FFmpeg PixelSmash (CVE-2026-8461) heap overflow affecting Jellyfin and other media servers."
category: daily
tags: [cti, daily-brief, akira, icarus, scattered-spider, cve-2024-40766, cve-2026-8461, klue, sonicwall, atomic-macos-stealer]
classification: TLP:CLEAR
reporting_period: "2026-06-22"
generated: "2026-06-23"
draft: true
severity: critical
report_count: 61
sources:
  - SANS
  - BleepingComputer
  - Krebs on Security
  - CISA
  - Unit42
  - AlienVault
  - RecordedFutures
  - Schneier
  - Microsoft
  - Wiz
  - Elastic Security Labs
  - Upwind
  - RansomLook
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-22 (24h) | TLP:CLEAR | 2026-06-23 |

## 1. Executive Summary

The 24-hour window produced 61 reports across 14 sources, dominated by 47 high-severity items and 2 critical entries. The headline event is SANS ISC's deep-dive on CVE-2024-40766 in SonicWall SonicOS, which Akira and Fog ransomware affiliates continue to exploit against SSLVPN appliances — with documented dwell times under four hours and a confirmed compromise of MySonicWall configuration backups exposing encrypted credentials across the entire customer base. In parallel, the Icarus extortion group's Klue OAuth-token supply-chain attack reached LastPass, which confirmed Salesforce CRM data exposure alongside Recorded Future, Tanium, Jamf, Sprout Social, and Insurity. JFrog disclosed FFmpeg "PixelSmash" (CVE-2026-8461), a heap out-of-bounds write in the MagicYUV decoder demonstrated to achieve RCE on Jellyfin via the metadata-scan pipeline. UK NCA secured guilty pleas from two Scattered Spider members (Owen Flowers, Thalha Jubair) for the 2024 Transport for London intrusion. RansomLook leak-site activity remained heavy, with Nova (RALord rebrand), Akira, Icarus, Chaos, Qilin, Brain Cipher, Safepay, Inc Ransom and Aurora all posting new victims. No new CISA KEV additions were observed in the period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | CVE-2024-40766 SonicWall SSLVPN (Akira/Fog ITW); CVE-2026-48909 SP LMS Joomla PHP object injection RCE |
| 🟠 **HIGH** | 47 | Icarus/Klue/LastPass supply chain; Scattered Spider guilty pleas; macOS ClickFix → AMOS; FFmpeg PixelSmash; WhatsApp VBS phishing; 7 CISA ICS advisories (Siemens, ABB, Hubbell, B&R); 25+ ransomware leak-site posts |
| 🟡 **MEDIUM** | 5 | Eraleign/APT73 fabricated-breach claims; Ransomhouse Karl Chevrolet disclosure; Huione cyber-scam infrastructure seizure |
| 🔵 **INFO** | 7 | Trump quantum EO; KIDS Act; CVE-2026-42915 VMSwitch DoS update; SANS Stormcast |

## 3. Priority Intelligence Items

### 3.1 CVE-2024-40766 — SonicWall SSLVPN abuse by Akira and Fog escalates; MySonicWall backup compromise impacts all customers

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/33094)

SANS handler Manuel Humberto Santander Pelaez published a consolidated retrospective on CVE-2024-40766, an improper access-control flaw (CVSS 9.3) in SonicOS management interface and SSLVPN service across Gen 5, Gen 6, and Gen 7 firewalls. Despite the original August 2024 patch, exploitation has not slowed: Akira affiliates have been compromising SSLVPN accounts since September 2024, with Fog ransomware operators accounting for roughly 25% of intrusions and Akira for ~75% during the July-October 2025 surge documented by Arctic Wolf, Huntress, Bitdefender, Rapid7 and Darktrace. By December 2024, Macnica found ~half of Akira/Fog leak-site victims were running SonicWall and at least 48,933 appliances remained publicly exposed and unpatched. Arctic Wolf documented encryption-from-initial-access in under four hours, with the fastest case at 55 minutes.

Two compounding factors keep the vulnerability operational: (1) Gen 6→Gen 7 migrations in which local user passwords were never reset, and (2) SonicWall's September 2025 confirmation that its MySonicWall cloud backup platform was breached and that all firewall configuration backups (containing encrypted credentials) had been compromised. In Feb–Mar 2026, ReliaQuest reported the first in-the-wild exploitation of CVE-2024-12802, a separate MFA-bypass on SonicWall SSLVPN that requires six additional manual LDAP reconfiguration steps on Gen 6 — devices appeared patched by firmware version but remained fully exploitable.

**Affected products:** SonicWall SonicOS Gen 5 ≤ 5.9.2.14-12o; Gen 6 ≤ 6.5.4.14-109n; Gen 7 ≤ 7.0.1-5035. **MITRE ATT&CK:** T1078 (Valid Accounts), T1110 (Brute Force).

> **SOC Action:** Inventory all SonicWall appliances; confirm firmware is above the Gen-specific thresholds AND that local SSLVPN user passwords were rotated post Gen 6→7 migration. Assume MySonicWall configuration backup credentials are compromised — force reset of all firewall-local accounts and shared SSLVPN secrets. For Gen 6, verify CVE-2024-12802 LDAP reconfiguration steps were completed (firmware version alone is insufficient). Query EDR/firewall logs for successful SSLVPN authentication from previously unseen ASNs/geos within the last 60 days and correlate with subsequent RDP/SMB lateral movement; Akira/Fog dwell time is measured in hours, not days.

### 3.2 Icarus extortion group breaches Klue → LastPass and multi-tenant Salesforce data theft

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/), [AlienVault OTX](https://otx.alienvault.com/pulse/6a3999371eb0f2f2e3fb7f08)

On 11 June 2026 the Icarus extortion group compromised Klue, a competitive-intelligence platform that syncs battlecard data with customer Salesforce and Gong tenants, using a dormant credential left over from an abandoned prototype integration. The attackers harvested OAuth tokens for downstream Salesforce and Gong instances and used Python automation to exfiltrate CRM records (contacts, quotes, sales communications). Klue detected anomalous activity on 12 June and revoked OAuth credentials on 13 June; Icarus began extortion on 16 June, demanding contact via Session Messenger within 48 hours.

LastPass confirmed on 23 June that customer names, phone numbers, email addresses, physical addresses, support-case data and Sales/CRM data were exposed via its Salesforce environment. Product, infrastructure and password vaults were not affected. Confirmed downstream victims now include Recorded Future, Tanium, Jamf, Sprout Social, Gong and Insurity. Phishing/social-engineering follow-on activity has been observed from sender domains `baccarat.com[.]au`, `robinskitchen.com[.]au`, and `house[.]com.au`.

**MITRE ATT&CK (per AlienVault):** T1199 (Trusted Relationship), T1078.004 (Valid Cloud Accounts), T1528 (Steal Application Access Token), T1550.001 (Application Access Token), T1071.001 (Web Protocols), T1114.002 (Remote Email Collection — Cloud), T1213/T1213.002 (Data from Information Repositories — SharePoint/Salesforce), T1087.004 (Account Discovery: Cloud), T1020/T1030/T1041/T1567 (Exfiltration).

#### Indicators of Compromise
```
IP (Icarus C2 / source): 138.226.246[.]94
IP (Icarus C2 / source): 212.86.125[.]24
IP (Icarus C2 / source): 94.154.32[.]160
Spoofed sender domain:   baccarat[.]com[.]au
Spoofed sender domain:   robinskitchen[.]com[.]au
Spoofed sender domain:   house[.]com[.]au
Extortion contact:       Session Messenger
```

> **SOC Action:** Pull Salesforce login history for the past 30 days and alert on logins from the three Icarus IPs above; treat any OAuth-grant via Klue as compromised even if revoked. Inventory third-party Salesforce connected apps and rotate any OAuth tokens issued to market-intelligence/CRM-enrichment vendors. Brief executive support desks and sales teams on inbound phishing from the listed `.com.au` domains and Session Messenger contact attempts; route to a managed mailbox for IR triage. Hunt for Python user-agent strings and high-volume `query`/`describeSObject` API calls against Salesforce REST endpoints.

### 3.3 FFmpeg "PixelSmash" — CVE-2026-8461 heap OOB write in MagicYUV decoder; RCE on Jellyfin demonstrated

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/ffmpeg-fixes-pixelsmash-flaw-in-widely-used-video-decoder/)

JFrog disclosed and FFmpeg patched CVE-2026-8461 ("PixelSmash"), CVSS 8.8, a one-row heap out-of-bounds write in the MagicYUV decoder caused by a chroma-plane height mismatch between the frame allocator and the decoder during slice handling. Trigger is any AVI/MKV/MOV file that lands where libavcodec will process it — opening, thumbnailing, or any automated media-ingest workflow. JFrog demonstrated full RCE against Jellyfin 10.11.9 via the normal media-library scan: a crafted MagicYUV AVI dropped into the library triggers `ffprobe` metadata extraction; the OOB write hijacks `AVBuffer.free` to `system()`, executing commands as the `jellyfin` service user. RCE requires ASLR disabled or a chained info-disclosure (e.g., the FFmpeg FlashSV decoder bug) to defeat ASLR; DoS is reliably achievable in all cases.

A torrent-seeding scenario requires zero user interaction against Jellyfin instances whose media library is the torrent download target. Other applications confirmed to bundle vulnerable FFmpeg with MagicYUV enabled: Kodi, OBS Studio, PhotoPrism, Emby, Nextcloud (movie-preview), and GNOME/KDE/XFCE thumbnailers. Slack, Discord, Telegram and WhatsApp use server-side FFmpeg previews but were not tested. Plex uses a custom FFmpeg build that disables MagicYUV.

> **SOC Action:** Patch FFmpeg to a fixed release across all hosts; for self-hosted Jellyfin, Nextcloud, Kodi, Emby, PhotoPrism, OBS, prioritise out-of-band updates. As a compensating control, disable the MagicYUV decoder where the build supports it and verify ASLR is enabled on all media-handling hosts. Audit Jellyfin/Nextcloud library paths against any user-writable or torrent-target directories — segregate them. Hunt EDR for `ffprobe` or `ffmpeg` parent processes spawning `sh`, `bash`, or outbound connections.

### 3.4 macOS ClickFix campaign delivers Atomic macOS Stealer (AMOS) via Terminal-mounted DMG

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/)

Palo Alto Networks Unit 42 identified a new macOS ClickFix campaign delivering Atomic macOS Stealer. A fake CAPTCHA page instructs the visitor to paste a Terminal command which uses `curl -fsSL` to download a DMG from `svs-verificationdate[.]beer` to `/tmp` under a random name, mounts it silently via `hdiutil attach -nobrowse`, walks up to three directory levels for the first `.app`/`.pkg`, and launches it via `open`. The payload observed was `s.01M0td.dmg` mounting a self-signed `NNApp.app`. AMOS targets Chromium browsers (Chrome, Edge, Brave, Opera, Arc, Vivaldi, CocCoc, Yandex) and Firefox derivatives (LibreWolf, SeaMonkey, Tor, Waterfox, Zen) for cookies, logins, autofill, payment cards and profile data; wallets (Exodus, Electrum, Atomic, Wasabi, Bitcoin Core, Litecoin Core, DashCore, Guarda, Binance, Dogecoin, TonKeeper); Telegram Desktop and Discord; Apple Notes, Safari cookies, Keychain databases and `.pdf/.txt/.rtf` documents. A spoofed System Preferences prompt harvests the user password.

**MITRE ATT&CK:** T1566 (Phishing), T1105 (Ingress Tool Transfer), T1204 (User Execution).

#### Indicators of Compromise
```
Distribution domain: svs-verificationdate[.]beer
Payload filename:    s.01M0td.dmg
Mounted bundle:      NNApp.app  (self-signed)
Drop path:           /tmp/<random>
Process chain:       curl -fsSL → hdiutil attach -nobrowse → open <app>
```

> **SOC Action:** Block `svs-verificationdate[.]beer` and any sibling `*.beer` lookalike domains at the DNS/proxy layer. On managed macOS endpoints, alert on `Terminal.app` parent process spawning `curl` followed by `hdiutil attach -nobrowse` within a short window, and on `open` invocations targeting unsigned-or-self-signed application bundles outside `/Applications`. Brief users that legitimate CAPTCHAs never require Terminal commands; consider blocking clipboard-to-Terminal paste via MDM policy where feasible.

### 3.5 Scattered Spider — Flowers and Jubair plead guilty to TfL intrusion; broader 47-entity, $115M conspiracy revealed

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/06/scattered-spider-hackers-plead-guilty-on-day-1-of-trial/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/scattered-spider-members-plead-guilty-to-hacking-transport-for-london/), [Recorded Future News](https://therecord.media/guilty-plea-tfl-cyberattack-scattered-spider-members)

On day one of a planned six-week UK trial, Thalha Jubair (20, East London) and Owen Flowers (18, Walsall) pleaded guilty to unauthorized acts and causing risk of serious damage to human welfare in connection with the August 2024 Transport for London intrusion (which compromised the Oyster refunds system and disrupted customer services). Flowers additionally admitted conspiracy to attack U.S. healthcare providers SSM Health and Sutter Health in September 2024. A separate September 2025 New Jersey indictment alleges Jubair participated in 120 intrusions against 47 U.S. entities (May 2022–September 2025) with at least $115M in ransom payments. Jubair is alleged to have co-run the "Star Chat" Telegram SIM-swap channel and was previously identified as the "Everlynn" handle selling fraudulent emergency-data-request services to major tech companies. The same prosecution links a summer-2022 SMS phishing spree to ≥130 intrusions including LastPass, DoorDash, Mailchimp, Plex and Signal, and to $8M+ in cryptocurrency theft.

**MITRE ATT&CK:** T1566 (Phishing), T1189 (Spearphishing Attachment), T1531 (Account Access Removal — SIM-swap proxy).

> **SOC Action:** Treat the public attribution as a deterrent signal but not an operational change: Scattered Spider TTPs (vishing/smishing of help-desk staff, MFA-fatigue, SIM-swap, EDR/SaaS-admin enrolment) remain in use by ShinyHunters and adjacent crews. Reinforce help-desk identity-verification beyond knowledge-based questions (require manager call-back or in-person check for password and MFA resets), and alert on new MFA-device enrolments outside business hours or from unfamiliar networks.

### 3.6 WhatsApp business-document phishing → ManageEngine Endpoint Central abused for remote admin

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/whatsapp-phishing-attack-uses-fake-business-docs-to-hack-pcs/)

Kaspersky reported an active WhatsApp campaign sending obfuscated VBS files disguised as financial/billing documents from compromised contacts' accounts. Telemetry spans Brazil, India, Mexico, Singapore, UK, Spain, Taiwan, Australia, Russia, Vietnam, and Malaysia, with filenames localized per region. On Windows, the VBS pulls two follow-on scripts that disable UAC via registry edits and download a ZIP containing the legitimate ManageEngine Endpoint Central agent, which is silently installed and pointed at attacker-controlled management servers, granting remote administration. Delivery via WhatsApp Desktop allows direct execution through `wscript.exe`; Web delivery requires manual download. Researchers found Chinese-language artefacts and infrastructure overlap with prior ValleyRAT and Gh0st RAT activity — insufficient for high-confidence attribution.

**MITRE ATT&CK:** T1566 (Phishing), T1070 (Indicator Removal — UAC disable), T1218 (System Binary Proxy Execution — `wscript.exe`).

> **SOC Action:** Block execution of `.vbs` files originating from `WhatsApp.exe` or downloaded by the WhatsApp Desktop process via ASR rule / AppLocker / WDAC. Hunt EDR for `wscript.exe` spawning `reg.exe` or `powershell.exe` with UAC-related registry writes (`EnableLUA`, `ConsentPromptBehaviorAdmin`). Inventory ManageEngine Endpoint Central agent installs against your authorized estate; treat any unmanaged install as an active intrusion and isolate.

### 3.7 Universal cloud bucket-hijacking technique enables data exfiltration across AWS, GCP, Azure

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/cloud-bucket-hijacking-risks/)

Unit 42 disclosed a bucket-hijacking technique exploiting the global-namespace uniqueness of cloud storage bucket names. An attacker who knows (or can guess via leaked IaC, logs or CI output) the name of a deleted-or-deletable destination bucket used by an automated data stream — a Google Cloud logging sink to a GCS bucket, an AWS S3 cross-account replication target, etc. — can recreate that bucket name in their own account. Subsequent writes from the victim's data stream are silently redirected to the attacker. The flaw was shared with Google Cloud, AWS, and Microsoft Azure. No real-world exploitation has been observed, but Unit 42 assesses detection would be very difficult once weaponised.

**MITRE ATT&CK:** T1071.001 (Web Protocols), T1530 (Data from Cloud Storage Object).

> **SOC Action:** Inventory every cloud logging sink, replication destination, and exporter target across your CSP accounts; enforce that destination bucket names embed account-IDs or random suffixes (e.g., `acme-logs-prod-<accountid>-<rand>`) so they cannot be re-registered. Add IaC guardrails (OPA/CFN-guard/Sentinel) blocking destination buckets without organisation-prefix conventions. Monitor data-stream throughput against the actual destination owner — sudden drops in delivered objects, or unexpected `403`/`NoSuchBucket` errors followed by resumed delivery, may indicate hand-off.

### 3.8 CISA ICS advisories — 7 critical-infrastructure bulletins (Siemens, ABB, Hubbell, B&R)

**Source:** [CISA ICS-CERT](https://www.cisa.gov/news-events/ics-advisories)

CISA published seven ICS advisories on 23 June 2026:

- **ICSA-26-174-01 Siemens WinCC Certificate Manager** — CVE-2026-24349, cleartext storage of key material; affects V16–V21 (V21 ≤ 21.0.2).
- **ICSA-26-174-02 Siemens SIPROTEC 5 (DIGSI 5 protocol)** — authenticated arbitrary file upload → permanent DoS. Upgrade to allow-list-enabled versions.
- **ICSA-26-174-03 Siemens products using OpenSSL** — CVE-2025-15467 stack buffer overflow → DoS/RCE; Siemens updates issued, interim countermeasures for unpatched products.
- **ICSA-26-174-04 Siemens SINEC INS** — CVE-2026-46746 (OS command injection), CVE-2026-46747 (path traversal), CVE-2026-46748 (unnecessary privileges); fixed in V1.0 SP2 Update 6.
- **ICSA-26-174-05 ABB Freelance Security Lock** — Security Lock bypass via undocumented keyboard combinations.
- **ICSA-26-174-06 B&R products / Linux kernel** — multiple CWE-822/123/269/787 kernel flaws; public PoC for CVE-2026-31431. No active B&R-specific exploitation observed.
- **ICSA-26-174-07 Hubbell Aclara Metrum Cellular Web Interface** — CVE-2026-1840, missing authentication on the web interface < v2.1.0.105 enabling restart and comms loss.

> **SOC Action:** Distribute ICSA-26-174-01 through 07 to OT/ICS asset owners with the affected device inventory pre-attached; prioritise Siemens SINEC INS (command injection) and Hubbell Aclara Metrum (unauth web interface) for emergency change. For ABB Freelance, restrict physical/keyboard access to engineering workstations until upgrade. For B&R, monitor for CVE-2026-31431 PoC indicators on perimeter-facing Linux hosts.

### 3.9 CVE-2026-48909 — SP LMS PHP object injection RCE (Joomla ≤ 4.1.3)

**Source:** Telegram (channel name redacted)

A Telegram OSINT post describes CVE-2026-48909, a PHP object injection vulnerability in SP LMS (Service Pool Learning Management System) for Joomla CMS ≤ 4.1.3, allowing remote code execution. A PoC was referenced. Source TLP is AMBER+STRICT; no independent confirmation has been published as of the reporting period close.

> **SOC Action:** Inventory Joomla instances with the SP LMS extension installed; upgrade to a version above 4.1.3 (verify with the vendor once an official advisory is published). Where patching is blocked, place the LMS endpoint behind authentication and a WAF rule blocking serialized-PHP-object payloads in POST bodies and query strings.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased targeting of critical-infrastructure and manufacturing sectors by multiple actors | Siemens SINEC INS (ICSA-26-174-04); Impact of Linux kernel vulnerabilities on B&R products (ICSA-26-174-06); Siemens WinCC Certificate Manager (ICSA-26-174-01) |
| 🔴 **CRITICAL** | Exploitation of widely-used software vulnerabilities | CVE-2026-48909 SP LMS for Joomla RCE; FFmpeg PixelSmash CVE-2026-8461 in MagicYUV decoder |
| 🟠 **HIGH** | Rise in ransomware-as-a-service (RaaS) with double-extortion tactics | Reynella East College by Interlock; FTL-Fast Transit Line by Nova (RALord rebrand); Akira posts (Leo International, IH Engineers); Chaos posts (Graymont, Randa) |
| 🟠 **HIGH** | Supply-chain exploitation targeting Salesforce CRM tenants via OAuth | LastPass/Klue breach (BleepingComputer); AlienVault Klue detection pulse; multiple Icarus leak-site posts (Huntress, HDS, Gms-net, Cqcrm, Cbassociations) |
| 🟠 **HIGH** | Phishing as the dominant cross-actor initial access vector | WhatsApp VBS campaign; Klue→Salesforce attack chain; Inc Ransom, Brain Cipher, Ransomhouse, Icarus leak-site posts |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (74 reports) — most prolific RaaS leak-site presence over the trailing 30 days; last seen 2026-06-22.
- **Qilin** (66 reports) — sustained double-extortion across multiple verticals; Schumacher Homes posted 2026-06-22.
- **Deadlock** (55 reports) — concentrated activity in mid-June.
- **Lockbit5** (39 reports) — continued post-rebrand operations.
- **DragonForce** (35 reports) — ongoing leak-site posting.
- **Akira** (31 reports) — actively exploiting SonicWall CVE-2024-40766; Leo International and IH Engineers added 2026-06-23.
- **ShinyHunters / Shinyhunters** (23 + 20 reports) — adjacent to Scattered Spider; identity-driven SaaS intrusion crews.
- **Nightspire** (18 reports).
- **Nova** (16 reports) — RALord rebrand; FTL-Fast Transit Line and cloudquantum posted 2026-06-23.

### Malware Families

- **Akira ransomware** (14 reports) and **Akira Ransomware** alias (9) — `.akira` extension, Windows CryptoAPI encryption, ESXi targeting since March 2023.
- **Lockbit5** (14 reports).
- **Deadlock** (10 reports).
- **RALord** (9 reports) — direct precursor to current Nova activity.
- **Inc Ransom** (9 reports).
- **Atomic macOS Stealer (AMOS)** — first appearance in today's ClickFix campaign with comprehensive browser, wallet, Keychain, and Apple Notes targeting.
- **ManageEngine Endpoint Central** — abused as a remote-admin payload in the WhatsApp VBS campaign.
- **RansomLook** (134 reports) — pipeline parser, not malware; high count reflects leak-site monitoring volume rather than a single family.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 28 | [link](https://www.ransomlook.io) | Ransomware leak-site monitoring (Akira, Icarus, Nova, Chaos, Qilin, Brain Cipher, Inc Ransom, Safepay, Aurora) |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Primary coverage of macOS ClickFix/AMOS, LastPass/Klue, FFmpeg PixelSmash, WhatsApp phishing, Scattered Spider, JaredFromSubway MEV |
| CISA | 7 | [link](https://www.cisa.gov/news-events/ics-advisories) | Seven ICS advisories (Siemens, ABB, Hubbell, B&R) |
| RecordedFutures | 4 | [link](https://therecord.media) | Scattered Spider TfL guilty plea; Huione seizure; quantum EO; KIDS Act |
| Unknown / Telegram | 4 | — | TLP:AMBER+STRICT OSINT posts on CVE-2026-48909, CVE-2026-41096 Windows DNS, CVE-2026-55200 libssh2, BLACKNET-00 builder |
| SANS | 2 | [link](https://isc.sans.edu) | SonicWall CVE-2024-40766 deep-dive; daily Stormcast |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | Scattered Spider guilty pleas |
| Wiz | 1 | [link](https://www.wiz.io) | AI threat readiness — detection/containment |
| AlienVault | 1 | [link](https://otx.alienvault.com) | Klue/Icarus Salesforce detection pulse with IOCs |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | RAG-based CVE advisory automation |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | Universal cloud bucket-hijacking technique |
| Upwind | 1 | [link](https://www.upwind.io) | AI-generated code runtime security |
| Schneier | 1 | [link](https://www.schneier.com) | Anthropic Fable 5 jailbroken within days |
| Microsoft | 1 | [link](https://msrc.microsoft.com) | CVE-2026-42915 VMSwitch DoS acknowledgement update |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** For every SonicWall appliance in scope, validate Gen-specific firmware AND confirm post-migration password rotation; rotate all firewall-local credentials and shared SSLVPN secrets on the assumption MySonicWall configuration backups are compromised. Apply Gen 6 CVE-2024-12802 LDAP reconfiguration. (Section 3.1)
- 🔴 **IMMEDIATE:** Audit all Salesforce connected apps for OAuth grants issued to Klue or other competitive-intelligence/CRM-enrichment vendors; revoke and reissue. Block Icarus IPs `138.226.246[.]94`, `212.86.125[.]24`, `94.154.32[.]160` at perimeter and search the last 30 days of Salesforce login history. (Section 3.2)
- 🟠 **SHORT-TERM:** Patch FFmpeg fleet-wide; for self-hosted Jellyfin/Nextcloud/Kodi/Emby/OBS/PhotoPrism, schedule out-of-band updates this week and disable the MagicYUV decoder where build configuration permits. (Section 3.3)
- 🟠 **SHORT-TERM:** Roll out CISA ICSA-26-174-01 through -07 to OT/ICS asset owners with prioritised remediation for Siemens SINEC INS and Hubbell Aclara Metrum. (Section 3.8)
- 🟡 **AWARENESS:** Brief macOS users that no legitimate CAPTCHA requires pasting Terminal commands; add the `*.beer` C2 domain class and `hdiutil attach -nobrowse` post-`curl` pattern to EDR hunts. (Section 3.4)
- 🟡 **AWARENESS:** Reinforce help-desk identity verification (manager call-back, in-person check) for password and MFA resets in response to the public Scattered Spider attributions and continued ShinyHunters activity. (Section 3.5)
- 🟢 **STRATEGIC:** Enforce account-ID/random-suffix naming on all cloud storage buckets used as data-stream destinations; add IaC guardrails preventing creation of unsuffixed destination buckets across AWS/GCP/Azure. (Section 3.7)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 61 reports processed across 4 correlation batches (IDs 188–191). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
