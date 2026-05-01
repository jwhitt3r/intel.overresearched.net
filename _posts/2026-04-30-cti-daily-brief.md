---
layout: post
title:  "CTI Daily Brief: 2026-04-30 — Two Critical Chromium CVEs, ShinyHunters Targets Finance Sector, Unit42 Flags 18 Malicious AI Browser Extensions"
date:   2026-05-01 20:30:00 +0000
description: "Two critical Chromium CVEs (Skia heap overflow, ANGLE use-after-free) lead a 21-CVE Microsoft Edge advisory batch; ShinyHunters claims Aman, Towerpoint Wealth and Follett Software in a finance/hospitality extortion campaign; Unit42 publishes 18 malicious AI browser extensions; FBI warns of cargo hijacking via compromised broker accounts."
category: daily
tags: [cti, daily-brief, shinyhunters, chromium, cve-2026-7353]
classification: TLP:CLEAR
reporting_period: "2026-04-30"
generated: "2026-05-01"
draft: true
severity: critical
report_count: 37
sources:
  - Microsoft
  - HaveIBeenPwned
  - Unit42
  - RecordedFutures
  - RansomLook
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-30 (24h) | TLP:CLEAR | 2026-05-01 |

## 1. Executive Summary

Across 37 reports drawn from seven sources, two themes dominate the past 24 hours: a large Microsoft Edge / Chromium advisory batch carrying two critical and eighteen high-severity CVEs, and a coordinated ShinyHunters extortion wave targeting financial services and ultra-luxury hospitality. The Chromium batch is anchored by CVE-2026-7353 (heap buffer overflow in Skia) and CVE-2026-7359 (use-after-free in ANGLE); the AI correlation engine flagged the cluster as `T1068 — Exploitation for Privilege Escalation` with critical risk. ShinyHunters separately claimed the breach of ultra-luxury hotel brand Aman (215,563 records via Salesforce CRM) and posted Towerpoint Wealth, LLC and Follett Software, LLC to its leak site. Unit42 disclosed 18 high-risk Generative AI browser extensions delivering RATs, infostealers, and meddler-in-the-middle attacks, and the FBI warned of a cargo-hijacking campaign in which cybercriminals compromise broker and carrier accounts on freight load boards. No CISA KEV additions were observed in the dataset for this reporting period; no in-the-wild exploitation has been confirmed for the Chromium batch.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | Chromium CVE-2026-7353 (Skia heap overflow); CVE-2026-7359 (ANGLE use-after-free) |
| 🟠 **HIGH** | 23 | 18 Chromium CVEs (V8, WebRTC, Cast, ANGLE, Canvas, GPU, Views, Navigation); ShinyHunters Aman/Towerpoint/Follett; Unit42 malicious AI extensions; FBI cargo hijacking |
| 🟡 **MEDIUM** | 9 | 7 Chromium CVEs (Codecs, Animation, Accessibility, Tint, Feedback, Views, GPU); two Telegram-sourced data-breach posts |
| 🔵 **INFO** | 3 | Telegram April 2026 ransomware summary; ISC Stormcast 1 May; Congress FISA renewal punted to June |

## 3. Priority Intelligence Items

### 3.1 Microsoft Edge / Chromium — 21 CVE batch including two criticals

**Source:** [Microsoft Security Update Guide — CVE-2026-7353](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7353), [CVE-2026-7359](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7359)

Microsoft published 27 Chromium-ingest advisories in the reporting window. Two are rated **critical** and could lead to arbitrary code execution in the renderer or graphics pipeline:

- **CVE-2026-7353** — heap buffer overflow in the Skia graphics library.
- **CVE-2026-7359** — use-after-free in the ANGLE OpenGL ES translation layer.

Eighteen further CVEs are rated **high** and span the V8 JavaScript engine (CVE-2026-7337 — type confusion), WebRTC (CVE-2026-7339 heap overflow, CVE-2026-7341 / 7336 UAF), Cast (CVE-2026-7338 / 7349), Chromoting (CVE-2026-7347), WebMIDI (CVE-2026-7350), MHTML (CVE-2026-7351 — race), ANGLE (CVE-2026-7340 integer overflow, CVE-2026-7354 OOB read/write), Navigation (CVE-2026-7356), Compositing (CVE-2026-7360), GPU (CVE-2026-7333), Views (CVE-2026-7343), Canvas (CVE-2026-7363) and Media (CVE-2026-7355 / 7335). Seven medium CVEs round out the batch (Codecs 7348, Animation 7358, Accessibility 7344, Tint 7346, Feedback 7345, Views 7334, GPU 7357). The Cognitive CTI correlation batch tagged the cluster as `T1068 — Exploitation for Privilege Escalation` at 0.70 confidence with critical risk.

Affected products: Microsoft Edge (Chromium-based), Google Chrome, all downstream Chromium browsers and Electron/CEF embedders.

> **SOC Action:** Trigger an emergency Edge / Chrome update push via Intune / WSUS / SCCM ahead of the scheduled monthly cycle. Force-restart browser sessions on privileged-tier and developer endpoints. Until patched, instrument EDR for renderer-process crashes and child-process spawns from `msedge.exe` / `chrome.exe` indicating exploitation attempts (T1068, T1203). Hunt Chromium browser update telemetry to confirm 100% rollout within 72 hours.

### 3.2 ShinyHunters extortion campaign — Aman, Towerpoint Wealth, Follett Software

**Source:** [HaveIBeenPwned — Aman](https://haveibeenpwned.com/Breach/Aman), [RansomLook — ShinyHunters](https://www.ransomlook.io//group/shinyhunters)

Three separate ShinyHunters disclosures landed within hours of each other:

- **Aman (ultra-luxury hotel brand)** — 215,563 unique email addresses leaked publicly after a "pay or leak" extortion attempt. HIBP attributes the data to a Salesforce CRM compromise. Exposed fields include names, emails, phone numbers, physical addresses, dates of birth, nationalities, language preferences, gender, spouse names and **VIP status flags** — high-value data for follow-on social engineering against the hospitality clientele.
- **Towerpoint Wealth, LLC** — financial advisory firm posted to the ShinyHunters leak site (post 2026-05-01 02:55 UTC).
- **Follett Software, LLC** — education-sector software vendor posted to the same leak site (post 2026-05-01 02:54 UTC).

The actor is operating four leak URLs (three .onion plus the clearnet `shinyhunte[.]rs`) with 60% average 30-day uptime and 59 total leak posts. Cognitive CTI correlated Towerpoint and Follett at 0.90 confidence on shared actor `Shinyhunters`. The Aman incident maps to `T1566 — Phishing` and `T1485 — Data Encrypted/Destroyed for Impact`. ShinyHunters is the third-most-active actor pipeline-wide over the past 30 days (20 reports).

#### Indicators of Compromise

```
Leak (clearnet):  hxxps[:]//shinyhunte[.]rs/
Leak (.onion):    shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion
Leak (.onion):    shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd[.]onion
File server:      hxxp[:]//91.215.85[.]22/
Contact email:    shinygroup[@]onionmail[.]com
PGP key ID:       0x1FC4D0B1DEE914BB05B57FABF1F1B98A51C989B3
```

> **SOC Action:** Block the listed ShinyHunters infrastructure at the proxy and DNS layers and add to threat-intel lookups. For Salesforce-using tenants, audit OAuth-connected applications and external integrations for the past 90 days, rotate API keys and integration-user credentials, and review Event Monitoring logs for anomalous bulk-export patterns. Alert hospitality, wealth-management and EdTech customer-success teams that VIP/HNW personal data may be circulating — pre-emptive customer-comms templates should be staged. Hunt for outbound traffic to `91.215.85.22` and the listed .onion bridges via Tor Browser fingerprinting or residential proxy egress.

### 3.3 Unit42 — 18 malicious AI browser extensions delivering RATs, MitM, infostealers

**Source:** [Unit42 — That AI Extension Helping You Write Emails? It's Reading Them First](https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/)

Palo Alto Unit 42 published research into 18 AI-themed Chrome / Edge browser extensions marketed as productivity tools (email assistants, ChatGPT helpers, summarisers) that deliver remote-access trojans, meddler-in-the-middle attacks and infostealers. Tradecraft observed includes:

- API interception of `fetch` / `XMLHttpRequest` to harvest GenAI prompts.
- Passive DOM observation against Gmail and Notion.
- Browser-proxy reconfiguration to route session traffic via attacker infrastructure.
- HTTPS response decryption via Chrome Debugger Protocol attachment.
- AI-generated malware code, indicating LLM-assisted development pipelines.

Google has either removed the 18 extensions or warned the developers. Mapped TTPs: `T1176 / T1189 — Drive-by Compromise`, `T1530 — Browser History/Data Discovery`, `T1133 — External Remote Services`, `T1566 — Phishing`. Unit42 declined to publish the extension IDs in the public post.

> **SOC Action:** Inventory installed Chromium browser extensions across the fleet via `chrome://extensions` exports or EDR (CrowdStrike `BrowserExtensionInventory`, Defender ASR rule audit). Block the Chrome Debugger Protocol attachment from non-developer endpoints by enforcing the `DeveloperToolsAvailability` policy = `2` (BlockOnAllProfiles). Hunt for browser processes spawning with `--remote-debugging-port` on user endpoints. Communicate to staff that AI-assistant browser extensions are an active malware vector and require IT review before install.

### 3.4 FBI — cybercrime cargo-hijacking via compromised freight load boards

**Source:** [Recorded Future News — Hackers earning millions from hijacked cargo, FBI says](https://therecord.media/hackers-earning-millions-from-hijacked-cargo-fbi)

The FBI issued an advisory describing a two-year campaign in which cybercriminals phish freight brokers and carriers, hijack their load-board accounts, post fraudulent loads, and divert in-transit cargo. Reported losses for 2025 reached USD 725M across the U.S. and Canada — a 60% year-on-year jump — with average per-incident value up 36%. Tradecraft includes account takeover (`T1078 — Valid Accounts`), spoofed broker emails with malicious links (`T1566 — Phishing`), "double-brokering" insertion into delivery chains, and unauthorised changes to FMCSA carrier contact and insurance records. Some incidents include ransom demands for stolen cargo, and overseas phone numbers have been observed in victim contact attempts.

> **SOC Action:** For logistics, automotive, freight-broker and shipping clients, harden load-board account access with phishing-resistant MFA (FIDO2 / passkeys), restrict access to corporate-managed devices, and alert on anomalous bulk-load posting. Cross-reference HR offboarding against load-board admin rosters quarterly. Brief carrier-relations and dispatch staff on the broker-spoofing pattern; treat any shipment-detail change request received via email as suspect until verified out-of-band.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation for Privilege Escalation in Chromium vulnerabilities | CVE-2026-7339 (WebRTC), 7347 (Chromoting), 7350 (WebMIDI), 7351 (MHTML), 7353 (Skia), 7334 (Views), 7359 (ANGLE) — all tagged `T1068` |
| 🟠 **HIGH** | Increased use of phishing techniques across multiple sectors | Aman breach, BEST PRICE Financial Services breach, Follett Software (ShinyHunters), Unit42 AI extensions, FBI cargo hijacking — all tagged `T1566` |
| 🟠 **HIGH** | Targeting of the technology sector with various vulnerabilities | Chromium CVE-2026-7339 (WebRTC), 7348 (Codecs), 7360 (Compositing), 7363 (Canvas) |
| 🟠 **HIGH** | ShinyHunters coordinated multi-victim activity | Towerpoint Wealth and Follett Software posted within minutes of each other (correlation confidence 0.90) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (79 reports, 30-day) — leading ransomware operator pipeline-wide.
- **The Gentlemen** (63 reports) — second-most-active leak-site operator.
- **Coinbase Cartel** (31 reports) — financially-motivated extortion cluster.
- **DragonForce** (28 reports) — ransomware affiliate continuing high-tempo activity.
- **ShinyHunters** (20 reports) — surfaced today with three confirmed leak posts (Aman, Towerpoint Wealth, Follett Software).

### Malware Families

- **RansomLook / RansomLock tooling** (47 / 45 reports) — leak-site infrastructure most-cited in the pipeline.
- **RaaS** (22 reports) — generic Ransomware-as-a-Service tagging.
- **Tox1 / Tox** (21 / 13 reports) — Gentlemen-affiliated tooling.
- **DragonForce ransomware** (20 reports).
- **Qilin** (11 reports) — encryptor activity.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 27 | [link](https://msrc.microsoft.com/update-guide/) | Chromium ingest advisories — 2 critical / 18 high / 7 medium |
| Unknown (Telegram) | 3 | — | Two `baseleeak` breach posts (Best Price Financial, Tokoparts); one `DarkfeedNews` April 2026 ransomware monthly summary |
| RecordedFutures | 2 | [link](https://therecord.media/hackers-earning-millions-from-hijacked-cargo-fbi) | FBI cargo-hijacking advisory; FISA Section 702 renewal extension |
| RansomLook | 2 | [link](https://www.ransomlook.io//group/shinyhunters) | ShinyHunters leak posts: Towerpoint Wealth and Follett Software |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/32940) | ISC Stormcast 1 May 2026 |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/) | 18 high-risk GenAI browser extensions |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Aman) | Aman 215,563 breached accounts |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Force the latest Microsoft Edge / Google Chrome stable channel across the fleet to remediate CVE-2026-7353 (Skia heap overflow) and CVE-2026-7359 (ANGLE use-after-free), plus 18 high-severity Chromium CVEs in the same batch. Confirm rollout via browser version telemetry within 72 hours.
- 🔴 **IMMEDIATE:** For Salesforce-tenanted customers, audit connected OAuth apps and integration-user activity for the last 90 days in light of ShinyHunters' Salesforce-CRM-sourced Aman breach. Rotate API tokens and review Event Monitoring exports.
- 🟠 **SHORT-TERM:** Block the published ShinyHunters infrastructure (`shinyhunte[.]rs`, the three .onion bridges, file server `91.215.85[.]22`, contact `shinygroup[@]onionmail[.]com`) and add to leak-site monitoring for client mentions.
- 🟠 **SHORT-TERM:** Inventory Chromium-browser extensions estate-wide and enforce `DeveloperToolsAvailability=2` and Chrome Debugger Protocol restrictions on non-developer endpoints to mitigate the Unit42 GenAI-extension class of threats.
- 🟡 **AWARENESS:** Brief logistics, freight-broker and dispatch teams on the FBI cargo-hijacking pattern; require phishing-resistant MFA on load-board accounts and out-of-band verification of any in-transit shipment changes.
- 🟢 **STRATEGIC:** Track ShinyHunters tempo — 20 pipeline reports in 30 days and three new victims in a single window suggests a sustained "pay or leak" campaign with Salesforce-CRM as a probable common access vector. Build detections around abnormal Salesforce bulk-export and OAuth-grant events.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 37 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
