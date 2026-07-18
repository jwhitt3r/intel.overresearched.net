---
layout: post
title:  "CTI Daily Brief: 2026-07-17 - Public wp2shell WordPress exploits, Chromium V8 zero-day, DPRK Contagious Interview, Microsoft ACR Stealer surge"
date:   2026-07-18 20:06:46 +0000
description: "Public exploits released for critical WordPress wp2shell RCE; Chromium V8 out-of-bounds critical patched; DPRK-aligned Contagious Interview hides malware in SVG steganography targeting developers; Microsoft warns of surge in ACR Stealer credential theft; The Gentlemen ransomware targets Ecopetrol and US Military Sealift Command."
category: daily
tags: [cti, daily-brief, qilin, the-gentlemen, inc-ransom, contagious-interview, acr-stealer, ottercookie, cve-2026-15903, cve-2026-50012, wp2shell]
classification: TLP:CLEAR
reporting_period: "2026-07-17"
generated: "2026-07-18"
draft: true
severity: critical
report_count: 43
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - Wired Security
  - Elastic Security Labs
  - Schneier
  - AlienVault
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-17 (24h) | TLP:CLEAR | 2026-07-18 |

## 1. Executive Summary

The pipeline processed 43 reports across 8 sources in the last 24 hours, with four critical items dominating the vulnerability picture. Public exploits are now available for the WordPress Core "wp2shell" RCE flaws, and Microsoft published a batch of six Chromium CVEs (V8 out-of-bounds, plus use-after-free bugs in Aura, Ozone, Network, GPU, and CameraCapture) alongside a critical Squid `cache_digest` memory-corruption bug and an integer-overflow issue in Windows `tcpip.sys`. Ransomware activity remains the loudest ambient signal: Qilin, Inc Ransom, DragonForce, Nova, and The Gentlemen collectively account for 21 leak-site posts, including a $33.1B ransom demand against Ecopetrol and a breach claim against the U.S. Navy's Military Sealift Command. Microsoft warned enterprise customers of a surge in ACR Stealer credential-harvesting attacks, and Elastic Security Labs published tracking of a new DPRK-aligned Contagious Interview campaign (REF9403) that hides an OTTERCOOKIE-like four-stage payload in SVG image steganography. No CISA KEV additions were observed in the collection window; the Chromium V8 and WordPress wp2shell exploitation status warrant close watching over the coming cycle.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | WordPress wp2shell RCE (public exploits); Chromium V8 OOB; Squid `cache_digest` memory corruption; Windows `tcpip.sys` integer overflow |
| 🟠 **HIGH** | 33 | Qilin/Inc Ransom/DragonForce/Nova/The Gentlemen leak-site posts; Chromium UAF batch (Aura, Ozone, Network, GPU, CameraCapture); ACR Stealer surge; DPRK Contagious Interview; Abbott Labs incidents; FSB Poland grid attack |
| 🟡 **MEDIUM** | 4 | Squid FTP gateway memory disclosure; Chromium Cast UAF; Qilin low-tier posts |
| 🔵 **INFO** | 2 | On-device age-verification piece; Schneier squid blog |

## 3. Priority Intelligence Items

### 3.1 WordPress Core "wp2shell" RCE — Public Exploits Released

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/wordpress-core-wp2shell-rce-flaws-get-public-exploits-patch-now/), Telegram (channel name redacted) — CVE-2026-63030

Public proof-of-concept exploits are now circulating for the critical "wp2shell" remote code execution vulnerability in WordPress Core. The flaw permits attackers to execute arbitrary PHP on unpatched sites, either dropping web shells or deploying downstream malware. A Telegram-tracked entry (CVE-2026-63030) mirrors the wp2shell designation and points at the same class of exploitation. Attack chains map to `T1059.001` (PHP command execution), `T1071` (web protocols), and `T1204` (user execution).

**Affected products/sectors:** WordPress Core installations worldwide — hosting providers, e-commerce, publishing, government portals.

> **SOC Action:** Immediately audit WordPress Core versions against the current patch. Block outbound egress from the web tier to unknown IPs, and query WAF/reverse-proxy logs for POST requests to admin endpoints and unusual PHP execution from `wp-content/uploads`. Watch for freshly written `.php` files under `wp-content/` (T1505.003 web shell) and process trees where the PHP-FPM/Apache worker spawns `sh`, `bash`, `wget`, or `curl`.

### 3.2 Chromium Patch Batch — Critical V8 OOB Plus Five Use-After-Free Bugs

**Source:** [Microsoft MSRC — CVE-2026-15903 (V8)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15903), [CVE-2026-15905 (Aura)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15905), [CVE-2026-15904 (Ozone)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15904), [CVE-2026-15901 (Network)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15901), [CVE-2026-15900 (GPU)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15900), [CVE-2026-15899 (CameraCapture)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15899), [CVE-2026-15902 (Cast)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15902)

Microsoft rolled seven Chromium ingest advisories in one cycle, headlined by a **critical** out-of-bounds read/write in the V8 JavaScript engine (CVE-2026-15903) and five **high** use-after-free bugs in the browser's Aura, Ozone, Network, GPU, and CameraCapture subsystems, plus a **medium** Cast UAF. V8 memory-safety issues are the dominant route to drive-by RCE in Chrome and Chromium-based Edge; the correlation batch flagged this as the day's top critical trend. Attack pattern: `T1189` (drive-by compromise) → `T1068` (exploitation for privilege escalation) → sandbox escape.

**Affected products/sectors:** Google Chrome, Chromium-based Microsoft Edge, and any Electron/CEF-embedded apps that track Chromium — all sectors.

> **SOC Action:** Roll the Chrome and Edge Stable updates through your endpoint management tooling this cycle. Verify the effective version on managed endpoints via `chrome://settings/help` inventory or MDM query; block or warn on endpoints stuck below the fixed builds. Enable Chrome site isolation and V8 sandbox flags if not already default. Alert on child processes of `chrome.exe`/`msedge.exe` where the parent renderer spawns `cmd.exe`, `powershell.exe`, or `rundll32.exe` (T1055).

### 3.3 CVE-2026-50012 Squid — `cache_digest` Memory Corruption

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50012)

A critical memory-corruption vulnerability in Squid's `cache_digest` reply handling stems from improper input validation; a maliciously crafted upstream response can corrupt memory and potentially enable arbitrary code execution. A companion **medium** advisory (CVE-2026-47729) covers memory disclosure in Squid's FTP gateway. Together they suggest sustained upstream fuzzing pressure on Squid's parser code.

**Affected products/sectors:** Squid caching proxies — ISPs, universities, enterprise egress gateways, CDN edge points.

> **SOC Action:** Enumerate Squid instances (`squid -v` inventory) and patch to the fixed release. If patching is delayed, disable cache-digest exchange (`cache_peer` options) and restrict FTP gateway usage. Add IDS coverage for anomalous cache_digest reply sizes and Squid worker crashes; monitor `syslog`/`journalctl` for Squid `SIGSEGV`/`abort` events.

### 3.4 CVE-2026-58532 — Windows `tcpip.sys` Integer Overflow

**Source:** Telegram (channel name redacted) — TLP:AMBER+STRICT

An integer-overflow vulnerability in the Windows `tcpip.sys` driver reportedly allows crafted packets to trigger memory corruption and unauthorized code execution against the affected system. The source is a Telegram OSINT channel; attribution and exploit availability are unconfirmed, and no Microsoft advisory has been ingested yet in this collection window. Treat as pre-disclosure intelligence and preserve the hedging on exploitation status.

**Affected products/sectors:** Windows endpoints and servers exposed to untrusted networks (all sectors, particularly perimeter-adjacent hosts).

> **SOC Action:** Watch Microsoft's Update Guide for a formal advisory and out-of-band patch. In the interim, ensure IPv4/IPv6 hosts behind the perimeter have host-based firewall rules restricting inbound TCP/IP to expected ports; enforce network isolation for hosts reachable from the internet. Monitor Windows Event Log for `tcpip` driver bugcheck codes (0x9F, 0xD1) and unexplained blue-screen clusters.

### 3.5 Microsoft — Surge in ACR Stealer Attacks Against Enterprise Customers

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-warns-of-surge-in-acr-stealer-attacks-on-customers/)

Microsoft observed a significant uplift in ACR Stealer deployments targeting its enterprise customer base. The stealer harvests browser-stored passwords, authentication tokens, session cookies, and sensitive documents from compromised endpoints. Reported delivery aligns with `T1566.001` (spearphishing attachment), followed by `T1531` (account discovery) and `T1110` (brute-force credential validation of harvested material).

**Affected products/sectors:** Enterprise Windows fleets across all verticals; SSO/token theft downstream risk to SaaS estates.

> **SOC Action:** Query EDR for browser process (`chrome.exe`, `msedge.exe`, `firefox.exe`) reading from `Local State`, `Login Data`, `Cookies`, and `Web Data` files from unusual parent processes. Rotate cached OAuth refresh tokens for users with recent unmanaged-device sign-ins. Alert on newly enrolled MFA devices where the enrollment session lacks a matching prior authentication (session-token theft indicator). Consider forcing browser password store re-authentication via policy.

### 3.6 DPRK Contagious Interview (REF9403) — OTTERCOOKIE-like Payload Hidden in SVG Steganography

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography), [AlienVault OTX](https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography)

Elastic Security Labs published a new DPRK-aligned Contagious Interview campaign, tracked as REF9403, in which the actors distribute trojanized "coding challenge" repositories (Next.js e-commerce templates cloned from public GitHub projects). Malicious loader stages hide inside SVG flag images using steganography; execution triggers a four-stage payload sharing behavioural characteristics with OTTERCOOKIE — a browser credential and crypto-wallet stealer, a file stealer, a Socket.IO-based RAT, and a clipboard stealer. Elastic reports zero AV coverage across the sample set at the time of publication. Initial access is `T1566` (phishing via Slack #jobs DMs) → `T1204` (user execution of `npm`/`node` build steps) → `T1078` (valid account theft) → `T1003` (credential dumping).

**Affected products/sectors:** Software developers, cryptocurrency platforms, open-source maintainers, and any organisation whose engineers use community Slack/Discord workspaces.

#### Indicators of Compromise

```
Trojanized archives (names):
  next-ecommerce-private-main.zip
  shopping-platform-main.zip
  ecommerce-platform.zip
  ecommerce-platform-main.zip
  shopping-platform.rar
  shop-main.zip
  ecommerce-main.zip

Malware families: OTTERCOOKIE (behavioural overlap)
C2 protocol: Socket.IO (WebSocket transport)
Delivery technique: SVG steganography (T1027.003)
```

> **SOC Action:** Publish an internal advisory to engineering: no `npm install` / `pip install` / `go run` on interview take-home code from an unvetted source. Egress-block Socket.IO-style long-lived WebSocket connections from developer laptops to non-corporate destinations. In EDR, alert on `node.exe`/`npm.exe` reading Chrome/Edge `Login Data`, wallet directories (`AppData\Roaming\Exodus`, `AppData\Roaming\Ledger Live`), and clipboard-hooking APIs. Baseline SVG file execution — if a developer host loads a `.svg` and immediately spawns child processes, escalate.

### 3.7 The Gentlemen Ransomware — Ecopetrol and U.S. Military Sealift Command

**Source:** [RansomLook — The Gentlemen](https://www.ransomlook.io//group/the%20gentlemen)

The Gentlemen leak site posted a $33.1B ransom demand against Colombian state oil company Ecopetrol (2026-07-18) and, one day earlier, claimed a breach at the U.S. Navy's Military Sealift Command (MSC), advertising ITAR documentation, cargo manifests including ESSM shipments, and vessel blueprints. Additional victims listed in the same cycle include Sunway Scientific (Taiwan), Advantage Home Health Care, and Terry P Moosmann CPA. The group operates a Tox1 chat channel and maintains one active .onion leak host at ~93% 30-day uptime. Attribution to The Gentlemen is direct per the leak-site post. Mapped TTPs: `T1071` (application layer C2), `T1485` (data destruction), `T1496` (resource hijacking).

**Affected products/sectors:** Energy (state oil), defence logistics, biotech/laboratory equipment distribution, healthcare, accounting.

> **SOC Action:** For energy and defence-adjacent organisations, hunt for `T1078` valid-account use and unusual privileged-session activity in OT-adjacent IT environments over the past 14 days. Query for large outbound archives (`.7z`, `.rar`, `.zip` >100MB) to cloud storage providers. Review the Trend Micro Unmasking The Gentlemen ransomware writeup for full TTPs and update SIEM detections for the group's known persistence and lateral-movement patterns.

### 3.8 Abbott Laboratories — Two Cyber Incidents Under Investigation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/abbott-laboratories-probes-two-cyber-incidents-amid-extortion-claims/)

Abbott confirmed unauthorized access to internal legacy Exact Sciences systems within its Cancer Diagnostics business, and is separately investigating an extortion claim against its LabCentral portal. Both remain under active investigation; no threat actor attribution has been confirmed. Combined with the Qilin, Inc Ransom, and DragonForce healthcare-adjacent postings tracked in the same cycle, the sector remains a priority target for financially motivated intrusions.

**Affected products/sectors:** Healthcare, medical diagnostics, life-sciences platform providers.

> **SOC Action:** Healthcare and diagnostics organisations should audit legacy portal and vendor-facing web application authentication (MFA enforcement, session lifetimes, dormant admin accounts). Query identity provider logs for anomalous OAuth token issuance to newly registered enterprise applications over the past 30 days. Contain and forensically preserve any systems flagged as legacy — they're the most common ingress path in this cohort.

### 3.9 Russia FSB Sanctioned for Poland Electric Grid Cyberattack

**Source:** [Wired](https://www.wired.com/story/security-news-this-week-your-period-tracker-is-probably-spying-on-you/)

EU and UK sanctions, backed by a joint CISA/FBI/NSA advisory, attribute a cyberattack against Poland's electric grid — which nearly caused electric and water utility outages — to Center 16 of Russia's FSB. Historically Center 16 has focused on cyberespionage, leaving destructive operations to the GRU; the attribution marks a rare public accusation of FSB-executed sabotage against critical infrastructure. The same Wired roundup notes the Mozilla Foundation privacy audit of period-tracker apps (Stardust scored 2/10 for exfiltrating reproductive health data to RudderStack).

**Affected products/sectors:** European critical infrastructure — electricity, water, gas; NATO-adjacent utility operators.

> **SOC Action:** Utility and ICS operators in Europe should review the joint CISA/FBI/NSA advisory when published and align detection to the named FSB Center 16 TTPs. Reinforce network segmentation between corporate IT and OT/SCADA, and re-verify emergency operations procedures assume a potentially compromised IT-side jump host.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in Chromium affecting multiple sectors | CVE-2026-15903 (V8 OOB), CVE-2026-15905 (Aura UAF), CVE-2026-15904 (Ozone UAF) |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors globally by Inc Ransom | reatile.co.za, v-silicon.com, FAST.COM.PH, D.MAG Taiwan, pokka.co, vedan corp, V&P Nurseries |
| 🟠 **HIGH** | Sophisticated phishing and malware campaigns targeting specific sectors | Contagious Interview SVG steganography (DPRK); prior-cycle Remcos RAT via GST phishing |
| 🟠 **HIGH** | Qilin sustained ransomware pressure across insurance, education, healthcare, transport, finance, government | The Nueva School, Armara, Heartland Catfish, KLD Labs, Salina Supply, St Martha Catholic Church, AK Preparedness, Sicc, Droguería Martorani, Powder River HVAC |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (97 reports) — Ransomware; Ecopetrol and Military Sealift Command in this cycle
- **Qilin** (91 reports) — RaaS; 10 leak-site postings today, aliased as Agenda
- **DragonForce** (42 reports) — RaaS with affiliate re-branding; NewNet posting today
- **Akira** (24 reports) — Sustained mid-tier ransomware operator
- **Inc Ransom** (18 reports) — Seven fresh leak-site posts today across healthcare, industry, retail
- **Nova** (16 reports) — Re-brand of RALord, PGP-signed notes
- **Contagious Interview** (2 today, DPRK-aligned) — REF9403 SVG steganography campaign

### Malware Families

- **RansomLook parser artefacts** (117 reports) — Aggregator scraping artefact; treat as tracking metadata, not a family
- **Tox1 / Tox** (84 combined) — Ransomware operator chat channel identifier, not malware per se
- **DragonForce ransomware** (14 reports)
- **Akira ransomware** (13 reports)
- **The Gentlemen ransomware** (12 reports)
- **Chaos ransomware** (11 reports)
- **Qilin (malware entity)** (11 reports)
- **Anubis ransomware** (10 reports)
- **ACR Stealer** (today) — Credential and token harvester surging against Microsoft enterprise customers
- **OTTERCOOKIE** (behavioural family) — Reused technique in DPRK Contagious Interview REF9403

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 21 | [ransomlook.io](https://www.ransomlook.io/) | Ransomware leak-site aggregation (Qilin, Inc Ransom, The Gentlemen, DragonForce, Nova, Krybit) |
| Microsoft | 11 | [msrc.microsoft.com](https://msrc.microsoft.com/update-guide) | Chromium ingest CVEs, Squid, CoreDNS |
| BleepingComputer | 4 | [bleepingcomputer.com](https://www.bleepingcomputer.com) | WordPress wp2shell, ACR Stealer, Abbott Labs, age-verification piece |
| Wired Security | 2 | [wired.com](https://www.wired.com/category/security/) | FSB Poland attribution; period-tracker privacy audit; prompt-injection defence |
| Unknown (Telegram) | 2 | — | CVE-2026-58532 tcpip.sys; CVE-2026-63030 wp2shell (Telegram OSINT, channel redacted) |
| Elastic Security Labs | 1 | [elastic.co/security-labs](https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography) | DPRK Contagious Interview REF9403 |
| Schneier | 1 | [schneier.com](https://www.schneier.com) | Friday squid blog (info) |
| AlienVault | 1 | [otx.alienvault.com](https://otx.alienvault.com) | OTX pulse mirroring Elastic's DPRK report |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch WordPress Core against the wp2shell RCE this cycle — public exploits are already circulating (§3.1). Web shell hunts on any host that was not patched within the first 24h of exploit release.
- 🔴 **IMMEDIATE:** Push Chrome and Chromium-based Edge updates covering CVE-2026-15903 (V8 OOB) and the accompanying UAF batch (§3.2). Verify effective version on managed endpoints, not just policy state.
- 🟠 **SHORT-TERM:** Deploy the ACR Stealer detection package from §3.5 across the enterprise Windows fleet; rotate cached SSO refresh tokens for high-privilege users with recent unmanaged-device sign-ins.
- 🟠 **SHORT-TERM:** Publish an engineering-org advisory on the DPRK Contagious Interview take-home code lure (§3.6). Restrict execution of interview code to disposable, network-isolated VMs; block outbound Socket.IO connections from developer endpoints to unknown destinations.
- 🟡 **AWARENESS:** Healthcare, energy, and defence-logistics teams should treat The Gentlemen, Qilin, and Inc Ransom leak-site activity (§3.7, §3.8) as ongoing recon indicators — hunt for stale valid-account use and large outbound archives to cloud storage over the past 14 days.
- 🟢 **STRATEGIC:** European utility operators should incorporate the FSB Center 16 attribution against Poland's grid (§3.9) into 2026 tabletop exercises assuming compromised IT-side jump hosts adjacent to OT.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 43 reports processed across 2 correlation batches in the reporting window. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
