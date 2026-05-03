---
layout: post
title:  "CTI Daily Brief: 2026-05-02 — cPanel Zero-Day Mass-Exploited in Sorry Ransomware Campaign; Shinyhunters, M3rx, and Everest All Active"
date:   2026-05-03 20:04:55 +0000
description: "26 reports across 5 sources. CVE-2026-41940 cPanel auth-bypass exploited at scale to deploy Sorry ransomware on 44,000+ hosts. Critical libssh2 and binutils RCEs disclosed. Shinyhunters, M3rx, and Everest post fresh victims."
category: daily
tags: [cti, daily-brief, shinyhunters, m3rx, everest, sorry-ransomware, cve-2026-41940, cve-2026-7598, cve-2026-6846]
classification: TLP:CLEAR
reporting_period: "2026-05-02"
generated: "2026-05-03"
draft: true
severity: critical
report_count: 26
sources:
  - Microsoft
  - BleepingComputer
  - RansomLook
  - SANS
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-02 (24h) | TLP:CLEAR | 2026-05-03 |

## 1. Executive Summary

The pipeline processed 26 reports across 5 sources in the last 24 hours, with 3 critical and 12 high-severity items. The dominant story is confirmed in-the-wild mass-exploitation of cPanel CVE-2026-41940, an authentication-bypass flaw being weaponised to deploy the Go-based Linux "Sorry" ransomware; Shadowserver telemetry indicates at least 44,000 cPanel-running IP addresses have already been compromised. Two additional critical software flaws were disclosed by Microsoft: CVE-2026-7598 (libssh2 integer overflow in `userauth_password`, remote code execution path) and CVE-2026-6846 (binutils arbitrary code execution via malformed XCOFF object files). Ransomware leak-site activity remained heavy, with Shinyhunters posting Instructure Holdings (Canva LMS) and Cushman & Wakefield, the M3rx group posting four new manufacturing/IT/HVAC victims, and Everest naming Fiserv. Microsoft Defender briefly false-positive-flagged legitimate DigiCert root certificates as `Trojan:Win32/Cerdigent.A!dha` before issuing a corrective signature update, an incident plausibly linked to the recent DigiCert code-signing breach.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | cPanel CVE-2026-41940 in-the-wild RCE; libssh2 CVE-2026-7598; binutils CVE-2026-6846 |
| 🟠 **HIGH** | 12 | Shinyhunters (Instructure, Cushman & Wakefield); M3rx (4 victims); Everest (Fiserv); Telegram FEMITBOT scam platform; libpng/Hex/Perl Storable/binutils CVEs |
| 🟡 **MEDIUM** | 4 | Microsoft Defender DigiCert false-positive; nano CVEs (-6842, -6843); vidtv CVE-2026-43058 |
| 🟢 **LOW** | 2 | Wireshark 4.6.5 (43 vulns / 38 CVEs patched); CVE-2026-30656 disclosure |
| 🔵 **INFO** | 5 | Telegram OSINT chatter (Darkfeed pulse, BreachForums council); Photonic listing on mnt6 |

## 3. Priority Intelligence Items

### 3.1 cPanel CVE-2026-41940 Mass-Exploited to Deploy "Sorry" Ransomware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critrical-cpanel-flaw-mass-exploited-in-sorry-ransomware-attacks/)

A critical authentication-bypass flaw in cPanel and WHM tracked as CVE-2026-41940 is being mass-exploited as a zero-day. Shadowserver reports at least 44,000 cPanel-running IP addresses have been compromised since the emergency patch window opened, with exploitation activity dating back to late February. Successful exploitation grants attackers control-panel access; operators are then dropping a Go-based Linux encryptor for the "Sorry" ransomware family, which appends `.sorry` to encrypted files, uses ChaCha20 file encryption with an embedded RSA-2048 public key, and instructs victims to negotiate via a Tox ID in a `README.md` ransom note. Researcher Rivitna assesses decryption is impossible without the corresponding RSA-2048 private key. Affected products: cPanel, WHM (Linux web hosting control panels). Affected sectors: hosting providers, SMB websites, e-commerce. ATT&CK: T1190 (Exploit Public-Facing Application), T1486 (Data Encrypted for Impact), T1203 (Exploitation for Client Execution).

#### Indicators of Compromise
```
Encrypted file extension: .sorry
Ransom note filename: README.md
Tox ID: 3D7889AEC00F2325E1A3FBC0ACA4E521670497F11E47FDE13EADE8FED3144B5EB56D6B198724
Encryption: ChaCha20 + RSA-2048
Family: Sorry (Go-based Linux encryptor — unrelated to 2018 HiddenTear .sorry campaign)
```

> **SOC Action:** Patch all cPanel/WHM instances to the emergency hotfix release immediately. For internet-facing cPanel hosts, hunt for unauthorised process execution under the cPanel service account, the presence of `README.md` ransom notes in web roots, files with `.sorry` extension, and outbound Tor connectivity. Block the published Tox ID at perimeter and EDR. Treat any cPanel host that was internet-exposed since late February 2026 as potentially compromised — review web-server access logs for anomalous authenticated WHM sessions and create a backup-restore plan in case of encryption.

### 3.2 CVE-2026-7598 — libssh2 Integer Overflow in `userauth_password` (Remote Code Execution)

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7598)

Microsoft disclosed a critical integer-overflow vulnerability in libssh2's `userauth.c::userauth_password` routine. Improper handling of large integer values during password authentication allows buffer overflow conditions, creating a remote code-execution path against any application that links the affected libssh2 versions and exposes SSH client functionality to untrusted input. Affected products: any product bundling libssh2 prior to the patched release (commonly used by file-transfer agents, Git clients, monitoring tools, embedded SSH clients). ATT&CK: T1068 (Exploitation for Privilege Escalation), T1078 (Valid Accounts).

> **SOC Action:** Inventory all software dependent on libssh2 (use SBOM data or `ldd`/`grep` sweeps across Linux estate; on Windows, search for bundled `libssh2.dll`). Prioritise patching of any agent that initiates outbound SSH to externally controlled hosts. Until patches are applied, restrict outbound SSH from server estate to a known-good destination allowlist and alert on libssh2-using processes spawning unexpected child processes.

### 3.3 CVE-2026-6846 — Binutils Arbitrary Code Execution via Malformed XCOFF Files (paired with CVE-2026-6845 DoS and CVE-2025-11083 ELF Heap Overflow)

**Source:** [Microsoft MSRC — CVE-2026-6846](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-6846), [CVE-2026-6845](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-6845), [CVE-2025-11083](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-11083)

A trio of GNU Binutils vulnerabilities were disclosed in the same window, correlated by the pipeline (confidence 0.80, infrastructure correlation): CVE-2026-6846 enables arbitrary code execution when binutils processes malformed XCOFF object files; CVE-2026-6845 causes a denial-of-service via crafted ELF; CVE-2025-11083 is a heap-based overflow in `elf_swap_shdr` within `elfcode.h`. The combined risk is meaningful for any CI/CD pipeline, malware reverse-engineering workstation, or build host that processes untrusted object files. ATT&CK: T1059 (Command and Scripting Interpreter), T1203.

> **SOC Action:** Update binutils packages across all developer workstations, build servers, and forensic/malware-analysis hosts. Ensure analyst sandboxes processing third-party binaries are isolated and snapshot-restorable. Audit CI runners for jobs that invoke `objdump`, `readelf`, `nm`, or `ld` against artifacts originating from public registries or pull requests.

### 3.4 Telegram "FEMITBOT" Mini-App Platform Drives Crypto Scams and Android Malware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/telegram-mini-apps-abused-for-crypto-scams-android-malware-delivery/)

CTM360 researchers exposed FEMITBOT, a large-scale fraud platform abusing Telegram's Mini App feature. Threat actors operate a shared backend (signature API response: "Welcome to join the FEMITBOT platform") behind multiple phishing domains and Telegram bots impersonating Apple, Coca-Cola, Disney, eBay, IBM, Moon Pay, NVIDIA, and YouKu. When a victim clicks "Start" on the bot, the embedded Mini App renders a phishing page in Telegram's WebView, displays fake balances and countdown timers, then either solicits deposits/referrals or pushes Android APKs hosted on the same TLS-validated domain as the API. APK names mimic legitimate apps such as BBC, NVIDIA, CineTV, Coreweave, and Claro. Tracking pixels (Meta, TikTok) are embedded for conversion optimisation. ATT&CK: T1566 (Phishing), T1189 (Drive-by Compromise), T1124 (System Information Discovery).

#### Indicators of Compromise
```
Platform identifier (API response): "Welcome to join the FEMITBOT platform"
Delivery vector: Telegram Mini Apps + bot Start button
Payload type: Android APKs sideloaded outside Google Play
Brands abused: Apple, Coca-Cola, Disney, eBay, IBM, Moon Pay, NVIDIA, YouKu, BBC, CineTV, Coreweave, Claro
```

> **SOC Action:** Add a detection in proxy/EDR for the FEMITBOT API string in HTTP responses. For corporate-issued Android devices, enforce MDM policy blocking sideloading and unknown sources. Brief finance and treasury teams on Telegram-hosted "investment" lures. Threat-hunt for Telegram WebView-originated traffic to newly registered domains carrying brand-impersonation TLS certs.

### 3.5 Ransomware Leak-Site Surge — Shinyhunters, M3rx, and Everest

**Source:** [Shinyhunters / RansomLook](https://www.ransomlook.io//group/shinyhunters), [M3rx / RansomLook](https://www.ransomlook.io//group/m3rx), [Everest / RansomLook](https://www.ransomlook.io//group/everest)

Three ransomware groups posted fresh activity in the reporting window, drawing a high-confidence "multi-sector targeting" trend from the AI correlation layer (batch 102, confidence 0.90 actor correlation on M3rx). **Shinyhunters** named **Instructure Holdings, Inc.** (Canva LMS / instructure.com — education sector) and **Cushman & Wakefield Inc.** (commercial real estate); the group continues to operate from `shinyhunte.rs` and rotating onion infrastructure, with phishing as the documented initial-access vector. **M3rx** added four victims in 24 hours: Engineered Machine Tool Inc. (manufacturing — Wichita KS, 180 GB / 698k files claimed stolen), Freitag IT GmbH (IT solutions, Germany), Manatee Air Heating & Cooling Inc. (HVAC, Florida), with prior-week posts including Boxtopia (UK packaging, 166 GB), Optimization Software Technologies LLP (India, 222 GB), DM Schweiz (Switzerland, 120 GB), and Anvil Arts (UK performing arts). **Everest** named **Fiserv** (financial-services technology — payments processing). Everest's broader recent leak-site cadence shows continued double-extortion and pure data-extortion activity, including TSYS, Epiq Global, Symcor, Liberty Mutual, and Frost Bank in late April. ATT&CK: T1566 (Phishing), T1078 (Valid Accounts), T1486 (Data Encrypted for Impact), T1496 (Resource Hijacking).

> **SOC Action:** For organisations in the named verticals (education LMS, commercial real estate, manufacturing, IT services, HVAC, financial-services tech), assume opportunistic targeting and run an immediate phishing-readiness check: validate MFA enforcement on all SSO entry points, confirm M365/Google Workspace mailbox-rule monitoring is on, and verify that domain-controller audit logging plus offline backups are current. For Fiserv-adjacent customers, monitor for fraud-pattern shifts and review any third-party integrations sharing data with Fiserv.

### 3.6 Microsoft Defender False-Positive Flags Legitimate DigiCert Root Certificates

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-defender-wrongly-flags-digicert-certs-as-trojan-win32-cerdigentadha/)

Microsoft Defender signature update (initial release 30 April) flagged two legitimate DigiCert root certificate thumbprints as `Trojan:Win32/Cerdigent.A!dha`, in some cases removing them from the Windows AuthRoot trust store under `HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\`. Affected admins reported broken TLS validation and unnecessary OS reinstalls. Microsoft fixed the detection in Security Intelligence build `1.449.430.0` (current `1.449.431.0`), which also restores the removed entries. The incident appears plausibly linked to the recent DigiCert code-signing breach in which attackers used initialisation codes against approved-but-undelivered EV code-signing certificate orders, leading to revocation of 60 certificates (27 connected to "Zhong Stealer" malware). ATT&CK: T1566 (Phishing — initial DigiCert support staff compromise vector).

#### Indicators of Compromise
```
Detection (false-positive): Trojan:Win32/Cerdigent.A!dha
Affected DigiCert root thumbprints (legitimate, do NOT block):
  0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43
  DDFB16CD4931C973A2037D3FC83A4D7D775D05E4
Fixed in Defender Security Intelligence: 1.449.430.0 (or later)
Registry path affected: HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\
```

> **SOC Action:** Confirm all managed Windows endpoints have Defender signature `1.449.430.0` or later — push via WSUS/Intune and validate. For systems that experienced the false positive, verify the two DigiCert root thumbprints are restored to AuthRoot. Separately, audit code-signing certificate-issuance webhooks and revocation feeds for DigiCert-issued certs since early April; treat any internally observed signed binary with revoked DigiCert EV certs as suspect (Zhong Stealer association).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of critical vulnerabilities in widely used software | CVE-2026-7598 libssh2 RCE; CVE-2026-41940 cPanel "Sorry" ransomware mass-exploitation |
| 🟠 **HIGH** | Multi-sector ransomware targeting using overlapping TTPs | Cushman & Wakefield (Shinyhunters); emtco.com, it-freitag.de, manateeair.com (M3rx); Fiserv (Everest) |
| 🟠 **HIGH** | Increased exploitation of software vulnerabilities across different sectors | CVE-2026-6845 binutils DoS; CVE-2026-32148 Hex lockfile checksum bypass |
| 🟡 **MEDIUM** | Phishing as a prevalent TTP across diverse cyber threats | Defender / DigiCert incident; Telegram FEMITBOT Mini Apps; Shinyhunters Instructure breach; CVE-2026-32148 Hex dependency-substitution risk |

Top correlation entries from batch 102/103: actor correlation on M3rx with confidence 0.90 (manufacturing, IT solutions, HVAC); infrastructure correlation across binutils CVE pair at 0.80; T1059 TTP correlation between nano (-6842) and binutils (-6846) at 0.80; T1486 correlation between Shinyhunters Cushman & Wakefield post and Sorry ransomware campaign at 0.70.

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (82 reports, 30-day) — ransomware-as-a-service operator, last seen 2026-05-02
- **The Gentlemen** (63 reports, 30-day) — sustained leak-site activity through April
- **Coinbase Cartel** (31 reports) — financially motivated, last seen 2026-04-23
- **DragonForce** (27 reports) — ransomware affiliate ecosystem, last seen 2026-04-22
- **shadowbyt3$** (25 reports) — extortion-focused actor on leak markets
- **ShinyHunters / Shinyhunters** (37 reports combined across casing variants) — last seen 2026-05-03 (Instructure Holdings)
- **Inc Ransom** (16 reports) — last seen 2026-05-02
- **M3rx** (3 mentions in this period) — newer multi-sector RaaS posting four victims today
- **Everest** (1 mention this period; 455 leak-site posts all-time) — pivoted toward pure data extortion
- **FEMITBOT** (this period) — Telegram Mini App fraud operator

### Malware Families

- **RansomLook / RansomLock** (97 reports combined) — ransomware leak-site monitoring tag dominant in feed
- **RaaS** (23 reports) — generic RaaS-tagged activity
- **Tox1 / Tox** (34 reports combined) — Tox-based negotiation infrastructure across multiple groups
- **Qilin** (11 reports as malware family)
- **Gentlemen ransomware** (9 reports)
- **Sorry** (1 report this period — new entrant tied to cPanel CVE-2026-41940)
- **Trojan:Win32/Cerdigent.A!dha** (1 report — Defender false-positive label, not a real family)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 11 | [link](https://msrc.microsoft.com/update-guide) | All vulnerability-alert items: 3 CVEs in binutils, libssh2 critical, Hex/libpng/Perl/nano/vidtv mid-tier disclosures |
| RansomLook | 7 | [link](https://www.ransomlook.io) | Leak-site coverage of Shinyhunters (×2), M3rx (×3), Everest (×1), mnt6 (×1) |
| Unknown | 4 | — | All Telegram-origin OSINT (Darkfeed pulse + BreachForums council discussion). Telegram URLs withheld per editorial policy |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com/news/security/critrical-cpanel-flaw-mass-exploited-in-sorry-ransomware-attacks/) | Headline coverage: cPanel Sorry ransomware, Telegram FEMITBOT, Defender DigiCert false-positive |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/32944) | Wireshark 4.6.5 release (43 vulns / 38 CVEs / 35 bugs — high count attributed to AI-assisted vuln reporting) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch cPanel/WHM to the emergency build addressing CVE-2026-41940 and threat-hunt for Sorry ransomware indicators (`.sorry` files, `README.md` ransom notes, the published Tox ID, outbound Tor connectivity from cPanel hosts). Treat any cPanel host internet-exposed since late February 2026 as potentially compromised.
- 🔴 **IMMEDIATE:** Inventory and update libssh2-linked software (CVE-2026-7598). Prioritise outbound-SSH agents and any service that processes attacker-controlled SSH credentials.
- 🟠 **SHORT-TERM:** Roll the binutils trio (CVE-2026-6846 / -6845 / CVE-2025-11083) onto developer workstations, build servers, and malware-analysis sandboxes. Audit CI pipelines for object-file processing of untrusted artifacts.
- 🟠 **SHORT-TERM:** Confirm Microsoft Defender signature 1.449.430.0+ deployed across managed estate and verify the two DigiCert root thumbprints are restored to AuthRoot on previously affected hosts. Separately review any internally observed code-signed binaries against the DigiCert revocation list (Zhong Stealer association).
- 🟡 **AWARENESS:** Brief finance, M&A, and brand-protection teams on the FEMITBOT Telegram Mini-App scam pattern. Education, commercial real estate, manufacturing, IT services, HVAC, and financial-services-technology verticals should treat this week's Shinyhunters / M3rx / Everest leak-site posts as evidence of opportunistic multi-sector pressure and verify MFA, mailbox-rule monitoring, and offline backup status.
- 🟢 **STRATEGIC:** The pipeline's repeated correlation on T1566 (Phishing) across vulnerability disclosures, ransomware leak posts, and OSINT-tracked operations underlines that phishing remains the single most operationally significant initial-access TTP this week. Consider an organisation-wide tabletop on phishing-driven supply-chain and code-signing compromise (the DigiCert support-staff incident is a worked example).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 26 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
