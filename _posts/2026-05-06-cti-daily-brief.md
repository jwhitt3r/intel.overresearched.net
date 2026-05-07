---
layout: post
title:  "CTI Daily Brief: 2026-05-06 — PAN-OS Captive Portal zero-day exploited in-the-wild by CL-STA-1132; FortiClient EMS pre-auth bypass exploit circulating; APT37 deploys BirdCall Android backdoor"
date:   2026-05-07 20:05:00 +0000
description: "Nine reports across eight sources. One critical (FortiClient EMS pre-auth bypass exploit on Telegram), four high-severity items including limited in-the-wild exploitation of PAN-OS CVE-2026-0300 by CL-STA-1132, North Korean APT37 deploying BirdCall on Android, the TCLBANKER Brazilian banking trojan with WhatsApp/Outlook worm modules, and an AitM Google-ads phishing kit targeting GoDaddy ManageWP."
category: daily
tags: [cti, daily-brief, apt37, cl-sta-1132, tclbanker, birdcall, cve-2026-0300, cve-2026-35616, pan-os, forticlient]
classification: TLP:CLEAR
reporting_period: "2026-05-06"
generated: "2026-05-07"
draft: true
severity: critical
report_count: 9
sources:
  - Unit42
  - Elastic Security Labs
  - RecordedFutures
  - BleepingComputer
  - SANS
  - Wired Security
  - Upwind
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-06 (24h) | TLP:CLEAR | 2026-05-07 |

## 1. Executive Summary

Nine reports were processed across eight sources for the 2026-05-06 reporting window, dominated by network-edge zero-day exploitation and credential-theft tradecraft. The headline item is Unit 42's confirmation of limited in-the-wild exploitation of CVE-2026-0300, an unauthenticated buffer overflow in the PAN-OS User-ID Authentication (Captive) Portal, attributed to a likely state-sponsored cluster tracked as CL-STA-1132 that deploys EarthWorm and ReverseSocks5 tunnellers post-compromise. A separate Telegram-circulated exploit for CVE-2026-35616, a pre-authentication bypass in FortiClient EMS, raises the urgency for any organisation operating internet-exposed Fortinet management consoles. On the cybercrime side, Elastic Security Labs published a deep dive on TCLBANKER, a Brazilian banking trojan with WhatsApp and Outlook worm modules, while BleepingComputer reported an active AitM phishing campaign abusing Google sponsored ads to harvest GoDaddy ManageWP credentials (≈200 confirmed victims, plugin active on >1M sites). Recorded Future / ESET also detailed APT37's Android-port of the BirdCall backdoor targeting ethnic Koreans in China's Yanbian region via a trojanised Sqgame card-game supply chain.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | FortiClient EMS CVE-2026-35616 pre-auth bypass exploit (Telegram) |
| 🟠 **HIGH** | 4 | PAN-OS CVE-2026-0300 in-the-wild (CL-STA-1132); APT37 BirdCall Android; TCLBANKER banking trojan; GoDaddy ManageWP AitM phishing |
| 🔵 **INFO** | 4 | SANS ISC Stormcast; SANS adaptive honeypot UI guest diary; Meta age-verification (Wired); Upwind Kubernetes visibility |

## 3. Priority Intelligence Items

### 3.1 PAN-OS Captive Portal Zero-Day (CVE-2026-0300) Exploited by CL-STA-1132

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/captive-portal-zero-day/)

Palo Alto Networks released an advisory on 6 May 2026 for CVE-2026-0300, a buffer overflow in the User-ID Authentication Portal (Captive Portal) of PAN-OS that permits unauthenticated remote code execution as root on PA-Series and VM-Series firewalls via crafted packets. Prisma Access, Cloud NGFW, and Panorama are not affected. Unit 42 reports limited but confirmed exploitation: unsuccessful attempts began 9 April 2026 and a successful intrusion followed roughly a week later, with shellcode injected into an nginx worker process. Unit 42 attributes the activity to CL-STA-1132, a likely state-sponsored cluster, and observed deployment of the open-source EarthWorm and ReverseSocks5 tunnelling tools, Active Directory enumeration using credentials harvested from the firewall service account, and systematic destruction of crash logs and core dumps to evade detection. Affected products: PAN-OS PA-Series and VM-Series firewalls with Captive Portal exposed. MITRE: T1190 (Exploit Public-Facing Application), T1003 (OS Credential Dumping), T1071.001 (App Layer Protocol).

> **SOC Action:** Apply Palo Alto Networks' patch for CVE-2026-0300 immediately. Restrict User-ID Authentication Portal to trusted internal IPs only and remove any public exposure. Use Cortex Xpanse or equivalent ASM tooling to enumerate exposed Captive Portal instances. Hunt EDR/firewall logs for nginx worker processes spawning child shells, presence of `EarthWorm` or `ReverseSocks5` binaries, and unexplained gaps or wholesale deletion of nginx crash/core artefacts. Rotate any service-account credentials stored on or accessible from PAN-OS devices.

### 3.2 FortiClient EMS Pre-Authentication Bypass Exploit Circulating (CVE-2026-35616)

**Source:** Telegram (channel name redacted) — TLP:AMBER+STRICT

A weaponised exploit for CVE-2026-35616, described as a pre-authentication bypass in FortiClient EMS, was posted to a Russian-language Telegram channel on 7 May 2026 (UTC). According to the post, successful exploitation grants full administrative access to FortiClient EMS without prior credentials, providing a foothold from which to pivot into managed endpoints and internal networks. The pipeline rated this report critical with a confidence of 100, but the underlying CVE detail and patch availability have not yet been corroborated by Fortinet PSIRT or other open-source vendors in our collection. Treat the technical claims as unconfirmed pending vendor confirmation. Affected products: FortiClient EMS (Enterprise Management Server). MITRE: T1190 (Exploit Public-Facing Application).

> **SOC Action:** Confirm the existence and patch status of CVE-2026-35616 directly with Fortinet PSIRT before assuming compromise. In the interim, ensure all FortiClient EMS instances are behind VPN/zero-trust access, audit administrator account creation events on EMS, alert on anomalous endpoint policy or deployment package changes pushed from EMS, and verify EMS hosts are not directly internet-reachable. If exposure exists, segment the host and capture full network/process telemetry for retrospective hunting.

### 3.3 APT37 Deploys Android Variant of BirdCall via Trojanised Sqgame Card-Game Supply Chain

**Source:** [Recorded Future News](https://therecord.media/north-korean-hackers-target-ethnic-koreans-in-china)

ESET researchers, as reported by Recorded Future, attributed an Android malware campaign to North Korea's APT37 (housed within the Ministry of State Security). The threat actor delivered an Android port of the BirdCall backdoor through Sqgame, a Chinese card-game website whose update server appears to have been compromised since at least November 2024. Initial APK downloads were benign; subsequent in-app updates pushed the malicious payload, side-stepping Google Play review entirely. Seven distinct Android versions of BirdCall have been recovered. Capabilities include screenshot capture, microphone audio recording for ambient surveillance, harvesting of contacts, SMS, call logs, media files and private keys, and external-storage scraping for specific file types. Targeting focuses on ethnic Koreans in China's Yanbian Prefecture (the so-called "Third Korea") consistent with APT37's long-running interest in defectors and refugees. ESET says it contacted Sqgame in December 2025 and received no response; the update channel has since been cleaned. MITRE: T1566 (Phishing), T1078 (Valid Accounts), T1003 (OS Credential Dumping).

> **SOC Action:** For organisations supporting at-risk diaspora users (NGOs, media, defector-support orgs): block sideloaded APKs via MDM, enforce Play Protect, and add `Sqgame`-related package names and update servers to mobile threat-defence allow/deny lists once IOCs are published by ESET. Hunt for Android devices exfiltrating to known APT37 infrastructure and any anomalous microphone or contact-list permission prompts on managed mobile fleets.

### 3.4 TCLBANKER: Brazilian Banking Trojan with WhatsApp & Outlook Self-Propagation

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan)

Elastic Security Labs profiled TCLBANKER (campaign reference REF3076), assessed as a major update to the MAVERICK/SORVEPOTEL family. Delivery uses a malicious MSI bundled with the legitimately-signed Logitech `LogiAiPromptBuilder.exe`, which sideloads a malicious `screen_retriever_plugin.dll` masquerading as a Flutter plugin. The loader features environment-gated decryption (sandboxes silently fail to decrypt), ETW patching, anti-debug/anti-instrumentation watchdogs, and string encryption. Two .NET-Reactor protected modules are deployed: a banking trojan that uses UI Automation to monitor the browser address bar against 59 Brazilian banking, fintech, and cryptocurrency domains and triggers a WebSocket C2 plus a WPF full-screen overlay framework for operator-driven social engineering (credential harvest pages, vishing wait screens, fake Windows Update stalls — overlays are hidden from screen-capture tools); and a worm module with a WhatsApp variant that hijacks authenticated browser sessions to message contacts, and an Outlook variant that sends phishing emails via COM automation. All C2 and distribution infrastructure is hosted on Cloudflare Workers under a single account, and developer artefacts (debug logging paths, test process names, an incomplete phishing page) suggest the campaign was caught in an early operational stage. MITRE: T1189 (Drive-by Compromise), T1566 (Phishing), T1574.002 (DLL Side-Loading), T1055 (Process Injection).

> **SOC Action:** Block execution of unsigned `screen_retriever_plugin.dll` loading into `LogiAiPromptBuilder.exe`. Hunt EDR for `LogiAiPromptBuilder.exe` parent processes spawning unexpected children, MSI installations from ZIP archives in user temp/download paths, and outbound WebSocket connections to `*.workers.dev` from user endpoints. Brazil-facing financial institutions should add the 59 monitored banking/fintech domains to fraud-monitoring playbooks. Review WhatsApp-Web and Outlook send-rate anomalies as a worm-spread signal.

### 3.5 AitM Phishing Kit Abuses Google Sponsored Ads for GoDaddy ManageWP Takeover

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-for-godaddy-managewp-login-phishing/)

Guardio Labs identified an active phishing campaign in which a malicious "managewp" Google sponsored search result outranks the legitimate one and steers victims to an adversary-in-the-middle (AitM) login page that proxies traffic to the real ManageWP service. Captured credentials are exfiltrated to an attacker-controlled Telegram channel; the attacker logs in live and triggers a follow-up 2FA prompt that the victim relays, enabling full account takeover. Each ManageWP account typically administers hundreds of WordPress sites, and the platform's plugin is active on more than 1 million sites — making compromise a high-leverage entry point for mass website abuse. Guardio infiltrated the C2 panel (an operator-driven dropdown command system, assessed as a private framework rather than commodity kit) and confirmed approximately 200 unique victims at time of writing. Embedded code includes a Russian-language disclaimer prohibiting use against Russia-based systems, suggesting Russian-speaking operators. MITRE: T1566.002 (Spearphishing Link), T1071.001 (App Layer Protocol: Web Protocols), T1539 (Steal Web Session Cookie / 2FA Bypass via AitM).

> **SOC Action:** Add a detection for any user-initiated authentication session to ManageWP (`managewp.com`) preceded by a click-through from a Google `googleadservices.com` redirect. Force password resets and review session/API tokens for any ManageWP accounts whose users may have searched the platform via Google in the past 30 days. For agencies/MSPs running ManageWP at scale: enforce phishing-resistant MFA (FIDO2/WebAuthn) — TOTP and SMS are bypassed by this AitM flow.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 Critical | Increased exploitation of zero-day vulnerabilities in network security products | CVE-2026-35616 FortiClient EMS pre-auth bypass exploit; PAN-OS Captive Portal CVE-2026-0300 exploited in-the-wild by CL-STA-1132 |
| 🟠 High | Phishing campaigns leveraging popular online platforms | GoDaddy ManageWP Google-Ads AitM kit; FortiClient EMS exploit shared via Telegram (T1566 cross-link) |
| 🟡 Medium | Cybersecurity-sector tooling and visibility advances | SANS adaptive cyber-analytics UI for honeypot logs; Upwind Kubernetes inventory normalisation |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (93 reports) — Most-cited ransomware operation in the pipeline over the trailing 30 days; not active in this 24h window but remains the dominant cybercrime backdrop.
- **The Gentlemen** (52 reports) — Persistent ransomware/extortion operation with active leak-site posts.
- **Coinbase Cartel** (31 reports) — Cryptocurrency-themed extortion brand observed across April.
- **DragonForce** (28 reports) — Ransomware-as-a-Service maintaining steady volume.
- **ShinyHunters** (24 reports) — Data-extortion actor; recent activity through 5 May.
- **APT37** (today) — North Korean state-sponsored group; new BirdCall Android variant detailed by ESET.
- **CL-STA-1132** (today) — Likely state-sponsored cluster tracked by Unit 42 exploiting PAN-OS CVE-2026-0300.

### Malware Families

- **RansomLook** (68 reports) and **RansomLock** (44) — Ransomware-tracking corpus references dominate trending counts.
- **Tox1** / **Tox** (33 / 18) — Ongoing extortion-tooling references.
- **Qilin** (14) — Ransomware payload references.
- **DragonForce ransomware** (7) and **Safepay** (6) — Active RaaS payloads.
- **TCLBANKER / MAVERICK / SORVEPOTEL** (today) — New Brazilian banking trojan family lineage detailed by Elastic.
- **BirdCall** (today) — APT37 Android backdoor (seven Android versions catalogued).
- **EarthWorm**, **ReverseSocks5** (today) — Open-source tunnellers used post-CVE-2026-0300 exploitation.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| SANS ISC | 2 | [link](https://isc.sans.edu/) | Stormcast podcast and adaptive honeypot UI guest diary — informational. |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/captive-portal-zero-day/) | **Primary source** for PAN-OS CVE-2026-0300 in-the-wild exploitation by CL-STA-1132. |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/tclbanker-brazilian-banking-trojan) | TCLBANKER deep-dive (REF3076). |
| RecordedFutures | 1 | [link](https://therecord.media/north-korean-hackers-target-ethnic-koreans-in-china) | APT37 BirdCall Android coverage citing ESET research. |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-for-godaddy-managewp-login-phishing/) | Guardio Labs ManageWP AitM phishing campaign. |
| Wired Security | 1 | [link](https://www.wired.com/story/a-kid-with-a-fake-mustache-tricked-an-online-age-verification-tool/) | Meta AI age-verification bypass research — informational. |
| Upwind | 1 | [link](https://www.upwind.io/feed/inventory-graph-normalization-kubernetes) | Vendor blog on Kubernetes visibility — informational. |
| Telegram (channel name redacted) | 1 | — | Russian-language exploit drop for FortiClient EMS CVE-2026-35616; TLP:AMBER+STRICT. |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch and isolate Palo Alto Networks PA-Series / VM-Series firewalls against CVE-2026-0300 (PAN-OS Captive Portal). Where patching is not yet possible, remove all public exposure of the User-ID Authentication Portal and rotate firewall service-account credentials. CL-STA-1132 is actively exploiting and aggressively wiping crash artefacts to evade detection.
- 🔴 **IMMEDIATE:** Audit FortiClient EMS exposure pending Fortinet PSIRT confirmation of CVE-2026-35616. Treat any internet-reachable EMS as suspect; place behind zero-trust access and capture full telemetry in case retrospective hunting is required.
- 🟠 **SHORT-TERM:** For ManageWP / WordPress hosting agencies and MSPs, enforce phishing-resistant MFA (FIDO2/WebAuthn) — the observed AitM kit defeats TOTP and push-MFA. Block known malicious `googleadservices.com` -> ManageWP-clone redirect chains and review the past 30 days of authentication logs.
- 🟠 **SHORT-TERM:** Brazil-facing financial institutions should activate fraud-monitoring on the 59 banking/fintech domains targeted by TCLBANKER and add detections for `LogiAiPromptBuilder.exe` sideloading `screen_retriever_plugin.dll`.
- 🟡 **AWARENESS:** APT37's pivot to Android via supply-chain update poisoning (Sqgame) reinforces that mobile sideload paths and update channels are valid initial-access vectors for nation-state targeting of diaspora communities. NGOs and at-risk-user organisations should brief mobile users accordingly.
- 🟢 **STRATEGIC:** Re-evaluate exposure of all on-premises management consoles (FortiClient EMS, PAN-OS, similar). The recurring pattern of pre-auth bypass and unauthenticated RCE in network-security middleware argues for treating these systems as crown-jewel assets behind privileged access workstations and zero-trust network access.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 9 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
