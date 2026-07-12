---
layout: post
title:  "CTI Daily Brief: 2026-07-11 - Nine critical Chromium/Edge CVEs, M3rx and D1r ransomware surge, RedHook Android malware weaponises Wireless ADB"
date:   2026-07-12 20:15:00 +0000
description: "Microsoft published nine critical Chromium/Edge CVEs across V8, ANGLE, Skia and Safe Browsing; M3rx and D1r ransomware groups exfiltrate multi-terabyte datasets from Eclective, FORECON, WRT World, Bosch, ARM and Synopsys; RedHook Android malware evolves to abuse Wireless ADB for shell access."
category: daily
tags: [cti, daily-brief, m3rx, d1r, chromium, redhook, v8]
classification: TLP:CLEAR
reporting_period: "2026-07-11"
generated: "2026-07-12"
draft: true
severity: critical
report_count: 154
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-11 (24h) | TLP:CLEAR | 2026-07-12 |

## 1. Executive Summary

The pipeline ingested 154 reports across three sources over the last 24 hours, dominated by a large Microsoft Security Response Center (MSRC) advisory batch mirroring Google's Chromium security update. Nine vulnerabilities are rated **critical** — all memory-safety and input-validation flaws in V8, ANGLE, Skia, Safe Browsing, UI and WebView — with a further 75 high-severity Chromium/Edge advisories in the same batch, affecting every Chromium-based browser including Microsoft Edge and Chrome for iOS. On the criminal side, RansomLook surfaced fresh activity from **M3rx** (an ~857 GB theft from Irish hospitality group Eclective plus data from FORECON Inc. and WRT World) and **D1r**, which is weaponising a leaked Synopsys database to publish proprietary Bosch CAN-bus module implementations and an ARM Athena Download Manager tool that bypasses vendor 2FA. BleepingComputer reported that **RedHook Android malware** now abuses Android's Wireless Debugging (Wireless ADB) mechanism to obtain shell-level privileges without a physical connection. No new CISA KEV additions or confirmed in-the-wild exploitation were reported in this window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 9 | Chromium V8 type confusion / UAF (CVE-2026-14431, CVE-2026-14394, CVE-2026-14393, CVE-2026-14430); ANGLE out-of-bounds (CVE-2026-14400, CVE-2026-14386); Skia heap overflow (CVE-2026-14427); Safe Browsing integer overflow (CVE-2026-13974); UI untrusted input (CVE-2026-13927) |
| 🟠 **HIGH** | 75 | ~65 additional Chromium/Edge advisories (WebView, CustomTabs, Autofill, Passwords, Omnibox, DevTools, Chrome for iOS); node-tar DoS (CVE-2026-59873); Python HTMLParser DoS (CVE-2026-15308); M3rx and D1r ransomware ops; RedHook Android malware |
| 🟡 **MEDIUM** | 66 | Lower-tier Chromium implementation issues (Credential Management, ScriptInjections, Clipboard); Titan ransomware activity |
| 🟢 **LOW** | 3 | Residual Chromium policy findings |
| 🔵 **INFO** | 1 | Informational MSRC entry |

## 3. Priority Intelligence Items

### 3.1 Microsoft/Chromium mega-batch: 9 critical + ~65 high CVEs land on Edge

**Source:** [Microsoft Security Response Center (Chromium: CVE-2026-14431 — V8 Type Confusion)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-14431)

Microsoft published 146 Chromium-related advisories in a single 24-hour window, corresponding to a Google Chrome security release ingested into Microsoft Edge. The nine critical items are dominated by memory-corruption bugs in the V8 JavaScript engine (type confusion CVE-2026-14431, use-after-free CVE-2026-14393 and CVE-2026-14394, integer overflow CVE-2026-14430), ANGLE (out-of-bounds write CVE-2026-14400, out-of-bounds read CVE-2026-14386), Skia (heap buffer overflow CVE-2026-14427), Safe Browsing (integer overflow CVE-2026-13974), and UI input validation (CVE-2026-13927). All are described by MSRC as enabling arbitrary code execution via crafted web content; none are listed as exploited in the wild at time of publication. The AI correlation engine flagged an over-arching **critical** trend of "increased focus on memory safety issues such as use-after-free and out-of-bounds vulnerabilities" (batch 225, landscape summary) and a **high** trend of "widespread vulnerabilities in Chromium-based browsers affecting multiple sectors". CVE-2026-58281 (Microsoft Edge remote code execution) was also grouped by the correlator alongside WebView UAF CVE-2026-13827 under shared TTPs T1071.001 (Web Protocols) and T1204 (User Execution). Affected products: Microsoft Edge (Chromium-based), Google Chrome (Windows, macOS, Linux, iOS), all Chromium-derived browsers (Brave, Opera, Vivaldi).

> **SOC Action:** Force-push the Edge/Chrome update to all managed endpoints within 72 hours via WSUS/Intune/JAMF. Use EDR to hunt for anomalous child processes of `msedge.exe` / `chrome.exe` spawning `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe` or `wscript.exe` (MITRE T1059, T1204) since the release date. Verify Edge/Chrome version strings via configuration management and alert on any version older than the July 2026 patch. For fleets that pin to a specific version, request an exception with 24-hour SLA.

### 3.2 M3rx ransomware — 800 GB+ from Irish hospitality group Eclective; FORECON and WRT World also breached

**Source:** [RansomLook — M3rx leak site](https://www.ransomlook.io//group/m3rx)

M3rx published four fresh victim posts on 2026-07-12. The largest is **Eclective (eclective.ie)** — Ireland's largest hospitality group — with 857 GB / 1,683,762 files claimed stolen. Simultaneous posts named **FORECON Inc.** (US forestry services, NY/PA/WV, 860 GB / 437,048 files) and **WRT World Enterprises** (Latin American logistics/purchasing, 377 GB / 267,891 files). The group operates from a `.onion` leak site with 87% 30-day uptime for its primary URL and uses Tox for negotiations. Activity spans hospitality, forestry, logistics and consulting — a broad target profile consistent with an opportunistic double-extortion affiliate rather than a sector-specific campaign. No named initial-access vector, no CVE attribution.

#### Indicators of Compromise
```
Onion (leak):    hxxp[://]4k6plf4h2cm2nco6ae3inrsxnmqgl6lllmwefydhnlcq4tuhwbj4qpad[.]onion/
Onion (chat):    hxxp[://]pippahtohg6qgioqu3ixrsueefuw7thythmmeanyrgwn3eixcuu6jvqd[.]onion/
Tox ID:          9A1217BEDA4AB77052A25D17CB6FFB34AFA2BE462E607F2FD8E1DF1DDD4CA16A64E18B1A0BF2
Ransom notes:    RECOVERY_NOTES.TXT
```

> **SOC Action:** For Eclective, FORECON, WRT World and their downstream partners: assume compromise and initiate IR with a review of external-facing RDP, VPN and email gateway auth logs for the preceding 60 days. Block the two `.onion` addresses at proxy/DNS-over-HTTPS enforcement points and add the Tox ID hash to DLP monitoring for outbound negotiation traffic. Egress-block Tor bootstrap traffic on production segments. Hunt EDR for `RECOVERY_NOTES.TXT` file creation and any process writing multiple `.encrypted`/renamed extensions in rapid succession (T1486 Data Encrypted for Impact).

### 3.3 D1r weaponises leaked Synopsys database against Bosch and ARM

**Source:** [RansomLook — D1r leak site](https://www.ransomlook.io//group/d1r)

New actor **D1r** claims to have used a leaked Synopsys database — cross-referenced with prior "other-group" leaks — to identify high-value targets in the semiconductor and automotive tech supply chain. On 2026-07-12 the group posted (i) the Bosch CAN-bus module implementation, valued by D1r at ~$10,000, published free "for every engineer and car enthusiast", and (ii) an ARM development utility, **Athena Download Manager**, which requires a valid vendor SSL certificate but then bypasses ARM's per-file SMS/email 2FA gates on downloads from `arm.com`. D1r's site is currently offline (0/1 URL up, 0% 30-day uptime) but posts remain viable via RansomLook mirroring. This is a supply-chain style leak amplification (T1195) rather than an intrusion of Bosch or ARM directly — the initial breach is at Synopsys. MITRE mappings from the report: T1048 (Exfiltration Over Alternative Protocol), T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer).

#### Indicators of Compromise
```
Onion (leak):    hxxp[://]dirone3rl3vvq64ckcnrvhe2ogrhjrwu5u7hqzrlotu3rfvmqmmbsuqd[.]onion/
Contact email:   dir10nly[at]onionmail[.]org
Tox ID:          063719AF013AD4EE89B497701BA5916898D70F45543C39E41154C4BCAC3A2F26F57913B31431
Tool named:      Athena Download Manager (bypasses ARM 2FA on downloads)
```

> **SOC Action:** If your organisation received the referenced Synopsys database or has a licensed relationship with Synopsys, ARM or Bosch supplier portals: rotate all SSO/vendor-portal credentials and certificates, revoke and re-issue any SSL client certificates that could be present in the leaked archive, and enable step-up authentication on every arm.com/Bosch supplier session regardless of the Athena Download Manager bypass. Automotive OEMs consuming Bosch CAN module IP should treat the design as public and re-baseline any bus-level authentication assumptions. Threat-hunt web proxy logs for downloads of any file named "Athena" from non-standard hosts and block the associated onion address.

### 3.4 RedHook Android malware pivots to Wireless ADB for shell access

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/redhook-android-malware-now-uses-wireless-adb-for-shell-access/)

BleepingComputer detailed a new RedHook variant that abuses Android's **Wireless Debugging** feature to obtain shell-level access on infected devices without needing a USB connection to a companion PC. Historically, ADB abuse required a physical tether; wireless ADB removes that barrier, so any device that has ever had Developer Options enabled and Wireless Debugging authorised is at heightened risk if RedHook is installed. Reported TTPs: **T1078.001** (Valid Accounts: Application Access Token), **T1105** (Ingress Tool Transfer), **T1546** (Hijack Execution Flow). No specific IOCs (hashes, C2, package names) were surfaced in the pipeline record — treat the technique itself as the primary detection signal.

> **SOC Action:** In MDM (Intune/Workspace ONE/Jamf/AirWatch): disable Developer Options on managed Android fleet where possible, and where not, enforce a policy that turns Wireless Debugging OFF and blocks the ADB TCP port (default 5555) on Wi-Fi networks. On the network side, alert on inbound TCP/5555 traffic to Android device subnets and any TCP/5555 traffic crossing the corporate/BYOD VLAN boundary. Users on personal devices with corporate accounts: mandate a compliance check that reports Developer Options status.

### 3.5 Ecosystem DoS pair: node-tar and Python HTMLParser

**Source:** [MSRC — CVE-2026-59873 (node-tar)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59873), [MSRC — CVE-2026-15308 (Python HTMLParser)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15308)

Two high-severity denial-of-service CVEs against widely used ecosystem components were published in the same batch: **CVE-2026-59873** in `node-tar` (unbounded decompression/parse of tar archives leading to resource exhaustion or potential arbitrary code execution) and **CVE-2026-15308** in Python's incremental `HTMLParser.feed()` (CPU exhaustion via repeated unterminated markup declarations). Both are pre-authentication and remotely reachable in any service that accepts user-supplied archives or HTML. These are the kind of low-glamour supply-chain bugs that frequently ride into production via CI/CD pipelines and log processors.

> **SOC Action:** Query your SBOM/dependency graph (Snyk, Dependabot, Trivy, Grype) for `node-tar` and Python < patched version. Prioritise services that accept user-uploaded archives (build systems, plugin loaders, container registries) and HTML-processing pipelines (scrapers, WYSIWYG previewers, feed importers). Add a size cap and a wall-clock timeout on any `HTMLParser.feed()` call site as a defence-in-depth measure independent of the interpreter patch.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased focus on memory-safety issues such as use-after-free and out-of-bounds vulnerabilities | Chromium CVE-2026-13915 (UAF in Chrome for iOS); Chromium CVE-2026-14385 (heap buffer overflow in ANGLE) |
| 🟠 **HIGH** | Widespread vulnerabilities in Chromium-based browsers affecting multiple sectors | Chromium CVE-2026-13994 (Credential Management); CVE-2026-58281 (Edge RCE) |
| 🟡 **MEDIUM** | Phishing-related TTPs prevalent across multiple browser vulnerabilities (T1566) | Chromium CVE-2026-13924 (WebView untrusted input); CVE-2026-13863 (CustomTabs untrusted input) |

Sector correlation from batch 225 (146 tier-1 reports): technology sector is the primary sink, with confidence 0.85 on the Credential Management / WebView / CustomTabs cluster and 0.82 on the Skia / ANGLE input-validation cluster. Shared TTPs across the browser corpus: T1566 (Phishing), T1105 (Ingress Tool Transfer), T1068 (Exploitation for Privilege Escalation), T1059.001 (PowerShell), T1071.001 (Web Protocols), T1204 (User Execution).

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (109 reports) — dominant leak-site poster over the last 30 days; sector-agnostic double extortion.
- **Qilin** (74 reports) — sustained activity; MSRC/BleepingComputer coverage of agriculture, retail and government hits earlier in the week.
- **Deadlock** (66 reports) — active leak-site operator; RaaS-style victim churn.
- **Lockbit5** (36 reports) — post-LockBit successor; steady posting cadence.
- **Akira** (22 reports) — persistent mid-tier operator.
- **DragonForce** (17 reports) — active this week (linked with Qilin in yesterday's correlation batch 224 as coordinated ransomware activity across sectors).
- **ShinyHunters** (17 reports) — data-broker / extortion activity.
- **M3rx** — new in today's brief (see 3.2); 29 all-time posts, 58% uptime.
- **D1r** — new supply-chain leak actor (see 3.3); 3 posts all time.

### Malware Families

- **RansomLook** (150 reports) — aggregator/telemetry label rather than a discrete family; volume reflects leak-site scraping.
- **Tox1 / Tox** (74 / 45 reports) — Tox-based negotiation channels used by multiple ransomware crews.
- **The Gentlemen Ransomware** (12 reports) — see actor entry above.
- **Deadlock** (12 reports) — family associated with the actor of the same name.
- **Akira ransomware** (11 reports).
- **Anubis ransomware** (11 reports).
- **Qilin** (10 reports).
- **RedHook** — new in today's brief; Android malware, Wireless ADB abuse (see 3.4).

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft (MSRC) | 146 | [msrc.microsoft.com](https://msrc.microsoft.com/update-guide/) | Full ingest of the Chromium/Edge security batch — 9 critical, ~65 high, remainder medium/low policy issues. |
| RansomLook | 7 | [ransomlook.io](https://www.ransomlook.io/) | Leak-site scraper — M3rx (3 posts), D1r (3 posts), Titan (1). |
| BleepingComputer | 1 | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/redhook-android-malware-now-uses-wireless-adb-for-shell-access/) | RedHook Android malware technical write-up. |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Deploy the July 2026 Chromium/Edge security update to all managed browser installs within 72 hours (traces to 9 critical CVEs in §3.1). Prioritise VDI/RDS golden images, kiosk fleets and any workstation used for administrative browsing.
- 🔴 **IMMEDIATE:** Notify Eclective, FORECON Inc. and WRT World supplier-management teams; if any of these are third-party providers to your organisation, invoke the incident-response clause of the contract and rotate any shared credentials or API keys (traces to §3.2 M3rx breach).
- 🟠 **SHORT-TERM:** Automotive, semiconductor and EDA-tool consumers should audit Synopsys, Bosch and ARM supplier-portal credential hygiene, rotate certificates that may appear in the leaked database, and treat the Bosch CAN module implementation as public (traces to §3.3 D1r).
- 🟠 **SHORT-TERM:** Push MDM policy to disable Android Developer Options / Wireless Debugging on the managed mobile fleet and add TCP/5555 alerts to Wi-Fi IDS (traces to §3.4 RedHook).
- 🟡 **AWARENESS:** Patch `node-tar` and Python `HTMLParser` in build systems and any service accepting user-supplied archives or HTML; enforce input-size and timeout guards regardless of patch status (traces to §3.5).
- 🟢 **STRATEGIC:** The concentration of memory-safety CVEs in Chromium (V8, ANGLE, Skia) reinforces the case for enabling every browser hardening flag your fleet supports — Site Isolation, V8 sandbox, and Chrome Enterprise / Edge for Business policies for enhanced Safe Browsing — and for shifting sensitive workflows to memory-safe language runtimes where possible.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 154 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
