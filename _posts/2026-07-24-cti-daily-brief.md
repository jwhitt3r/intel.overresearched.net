---
layout: post
title:  "CTI Daily Brief: 2026-07-24 - Qilin RaaS Surge, Russian Zimbra Zero-Day, Chromium RCE Batch"
date:   2026-07-25 22:52:31 +0000
description: "25 reports across 4 sources. Qilin RaaS operations flagged critical; Russian actor Laundry Bear exploits a Zimbra zero-day against US nuclear scientists; a four-CVE Chromium batch enables arbitrary code execution; in-memory JavaScript malvertising evades AV."
category: daily
tags: [cti, daily-brief, qilin, cve-2026-16805, laundry-bear]
classification: TLP:CLEAR
reporting_period: "2026-07-24"
generated: "2026-07-25"
draft: true
report_count: 25
severity: high
sources:
  - RansomLook
  - Microsoft
  - BleepingComputer
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-24 (24h) | TLP:CLEAR | 2026-07-25 |

## 1. Executive Summary

The pipeline processed 25 reports across 4 sources in the last 24 hours, with ransomware activity dominating the picture. The AI correlation engine elevated Qilin's ransomware-as-a-service operations to a critical-risk trend, tied to at least six fresh victim postings spanning national parks, diagnostics labs, and manufacturing. The most operationally significant intelligence is a previously unknown Zimbra webmail flaw exploited by the Russian state-backed group Laundry Bear (also tracked as Void Blizzard) in a year-long espionage campaign against US nuclear scientists and defense contractors, where merely previewing a malicious email triggers code execution. Microsoft published a batch of four Chromium vulnerabilities (CVE-2026-16804 through -16807), two of which are use-after-free flaws enabling arbitrary code execution in Edge and other Chromium browsers. A separate malvertising campaign is assembling malware directly in browser memory to evade traditional antivirus. No CISA KEV additions and no confirmed in-the-wild exploitation of the Chromium CVEs appeared in this period; the Zimbra flaw is the only confirmed active zero-day exploitation reported.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None rated critical at report level (Qilin RaaS flagged critical at trend level) |
| 🟠 **HIGH** | 21 | Qilin/Nova/Safepay/Blackwater RaaS postings; Zimbra zero-day; Chromium RCE; malvertising; ShinyHunters sextortion |
| 🟡 **MEDIUM** | 2 | Chromium WebMCP use-after-free (CVE-2026-16806); Qilin (Myers Y Cooper) posting |
| 🟢 **LOW** | 0 | No data available for this period |
| 🔵 **INFO** | 2 | Bravox monitoring listing; ChatGPT global outage |

## 3. Priority Intelligence Items

### 3.1 Russian Laundry Bear Exploits Zimbra Zero-Day Against Nuclear and Defense Targets
**Source:** [Wired Security](https://www.wired.com/story/security-news-this-week-the-openai-models-that-hacked-hugging-face-were-active-on-the-internet-for-days/)

US and allied intelligence agencies warned that the Russian state-backed group tracked as **Laundry Bear** (and **Void Blizzard**) exploited a previously unknown flaw in the Zimbra webmail platform during a year-long cyberespionage campaign targeting nuclear scientists, defense contractors, and government employees. Per Proofpoint, simply viewing or previewing a malicious message in a vulnerable Zimbra client causes hidden code embedded in the email to execute — a low-interaction vector requiring no attachment open or link click. Attribution is stated directly by the reporting agencies rather than hedged. Affected sector: government, defense industrial base, energy/nuclear research.

> **SOC Action:** Inventory all Zimbra Collaboration webmail instances and prioritise vendor patching; until patched, disable automatic message preview/rendering and block external HTML email rendering. Hunt for anomalous Zimbra process spawns (mailbox service spawning shells/scripting hosts) and outbound connections from mail servers to unfamiliar infrastructure. Maps to `T1566` (Phishing) and `T1204` (User Execution).

### 3.2 Chromium Four-CVE Batch — Arbitrary Code Execution in Edge and Chromium Browsers
**Source:** [Microsoft (CVE-2026-16805)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-16805)

Microsoft published four Chromium vulnerabilities affecting Microsoft Edge (Chromium-based) and other Chromium browsers, grouped here as a single browser update event:

- **CVE-2026-16807** (🟠 High) — Out-of-bounds write in Codecs; enables arbitrary code execution via improper data-boundary handling.
- **CVE-2026-16805** (🟠 High) — Use-after-free in Blink rendering engine; potential arbitrary code execution.
- **CVE-2026-16804** (🟠 High) — Use-after-free in Input handling; code execution by manipulating freed input objects still referenced in memory.
- **CVE-2026-16806** (🟡 Medium) — Use-after-free in WebMCP.

No confirmed in-the-wild exploitation was reported for any of the four in this period. These are memory-corruption classes historically favoured for browser exploitation chains.

> **SOC Action:** Force-update managed Edge/Chrome fleets to the current Chromium build via GPO/MDM and verify version compliance rather than relying on background updates. Prioritise internet-facing and high-risk-user endpoints. Track for exploitation reporting and CISA KEV escalation. Maps to `T1189` (Drive-by Compromise).

### 3.3 Qilin RaaS — Critical-Rated Surge in Victim Postings
**Source:** [RansomLook](https://www.ransomlook.io//group/qilin)

The correlation engine flagged Qilin (aka Agenda) as a **critical-risk trend**, with an actor correlation confidence of 0.90 linking six fresh victim/infrastructure postings in the last cycle: Jubilee Jobs, Plitvička Jezera National Park, Principle Diagnostics Laboratory, Guntert & Zimmerman, GURR Abdichtungstechnik GmbH, and The Myers Y Cooper. Qilin operates a RaaS model using README-RECOVER-[rand].txt ransom notes, Jabber and Tox for negotiation, and a large but mostly-degraded Tor/FTP infrastructure (614 tracked file servers, ~1% average 30-day uptime). Qilin is the single most-reported threat actor pipeline-wide (114 reports). Affected sectors: manufacturing, healthcare/diagnostics, public sector.

#### Indicators of Compromise
```
Actor: Qilin (aka Agenda)
Active onion (73% uptime): hxxp[:]//ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
Active file server (83% uptime): hxxp[:]//kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion
FTP C2: 85.209.11[.]49
FTP C2: 188.119.66[.]189
FTP C2: 176.113.115[.]97
FTP C2: 185.39.17[.]75
IP: 31.41.244[.]100
Jabber: qilin[@]exploit[.]im
Ransom note: README-RECOVER-[rand].txt
```

> **SOC Action:** Block the listed IPs/onion endpoints at egress and add README-RECOVER-*.txt filename patterns to EDR detection. Given manufacturing/healthcare targeting, audit VPN and remote-access exposure and enforce MFA on external services. Maps to `T1486` (Data Encrypted for Impact) and `T1071.001` (Web Protocols).

### 3.4 In-Memory JavaScript Malware via Fake Trading Platform Malvertising
**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/malicious-sites-use-javascript-to-build-malware-in-browser-memory/)

A large malvertising campaign is serving fake Solana, Luno, and TradingView webpages whose malicious JavaScript instructs the browser to assemble malware directly in memory, never writing the payload to disk. This fileless approach evades signature-based antivirus that inspects files on disk. Affected sector: financial/crypto platform users.

> **SOC Action:** Monitor EDR for browser processes exhibiting anomalous in-memory execution and script-heavy activity; deploy web filtering/ad-blocking on managed endpoints and block newly registered lookalike domains for Solana, Luno, and TradingView. Educate users to reach trading platforms via bookmarks, not search ads. Maps to `T1027` (Obfuscated Files or Information) and `T1566` (Phishing).

### 3.5 ShinyHunters Breach Data Fuels $2,000 Sextortion Scam
**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/shinyhunters-data-leaks-fuel-2-000-sextortion-email-scam/)

Threat actors are weaponising email addresses exposed in breaches leaked by the ShinyHunters extortion group to send sextortion emails demanding $2,000 in Bitcoin, claiming to hold compromising material. This is a bulk, low-sophistication phishing operation trading on breach-derived recipient lists. Affected sector: broad consumer/enterprise inboxes.

> **SOC Action:** Tune secure-email-gateway rules for sextortion lures (Bitcoin demand + compromise threat) and remind users not to engage or pay. Cross-check whether corporate addresses appear in recent ShinyHunters dumps and enforce password resets where exposure is confirmed. Maps to `T1566` (Phishing).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Qilin's persistent RaaS operations targeting multiple sectors globally with varied TTPs | Jubilee Jobs, Plitvička Jezera, Principle Diagnostics, Guntert & Zimmerman, GURR, Myers Y Cooper (all "By qilin") |
| 🟠 **HIGH** | Vulnerabilities in Chromium-based browsers being exploited | CVE-2026-16807, -16806, -16805, -16804 |
| 🟠 **HIGH** | Phishing remains a prevalent TTP across diverse campaigns | Malicious in-memory JavaScript malware; ShinyHunters sextortion scam |
| 🟠 **HIGH** | Ransomware groups increasingly leveraging RaaS models for widespread attacks | Thermalex Inc (kairos); msgas.com.br (blackwater); SistNet (nova) |
| 🟠 **HIGH** | Increased ransomware activity across multiple sectors with overlapping TTPs/malware | Advantage Sintered Metals (securotrop); Center of IT in Finance (nova); GOP (qilin) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (114 reports) — Most active actor pipeline-wide; RaaS "By qilin" postings, critical-rated trend this cycle.
- **The Gentlemen** (103 reports) — High-volume RaaS operation, last seen 2026-07-24.
- **DragonForce** (42 reports) — Sustained RaaS activity across sectors.
- **Akira** (23 reports) — Ongoing multi-sector ransomware campaigns.
- **Nova** (18 reports) — Rebrand of RALord; PGP/captcha-gated ransom notes, active this period.

### Malware Families
- **RansomLook** (133 reports) — Parser/feed artifact tag dominating RaaS victim reporting.
- **Tox1 / Tox** (57 / 28 reports) — Tox messaging identifiers used for ransomware negotiation.
- **RALord** (14 reports) — Precursor to the Nova ransomware brand.
- **DragonForce ransomware** (13 reports) — Payload family tied to the DragonForce actor.
- **Qilin** (11 reports) — Qilin/Agenda payload family, active this cycle.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 17 | [link](https://www.ransomlook.io/) | Dark-web leak-site monitoring; drove the Qilin/Nova/Safepay RaaS volume |
| Microsoft | 4 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-16805) | Chromium CVE batch (-16804 through -16807) |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com/news/security/malicious-sites-use-javascript-to-build-malware-in-browser-memory/) | In-memory malvertising; ShinyHunters sextortion; ChatGPT outage |
| Wired Security | 1 | [link](https://www.wired.com/story/security-news-this-week-the-openai-models-that-hacked-hugging-face-were-active-on-the-internet-for-days/) | Russian Laundry Bear Zimbra zero-day; OpenAI model containment escape |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch and harden Zimbra webmail against the Laundry Bear zero-day (§3.1) — disable message preview/HTML rendering until patched and hunt for mail-server process anomalies. This is the only confirmed active exploitation this period.
- 🟠 **SHORT-TERM:** Force-update Chromium/Edge fleets to remediate CVE-2026-16804/-16805/-16806/-16807 (§3.2) and verify version compliance rather than trusting background updates.
- 🟠 **SHORT-TERM:** Block Qilin infrastructure IOCs and deploy README-RECOVER-*.txt detection (§3.3); audit remote-access exposure for manufacturing and healthcare assets given the critical-rated surge.
- 🟡 **AWARENESS:** Brief users and tune email/web controls against the in-memory malvertising (§3.4) and ShinyHunters sextortion (§3.5) campaigns; verify corporate addresses against ShinyHunters dumps.
- 🟢 **STRATEGIC:** Track the broader RaaS proliferation trend (Qilin, Nova, The Gentlemen, DragonForce, Akira) and mature ransomware readiness — offline backups, segmentation, and tested incident-response runbooks.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 25 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
