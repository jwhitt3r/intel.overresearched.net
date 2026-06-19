---
layout: post
title:  "CTI Daily Brief: 2026-06-17 — ShinyHunters hits Amazon OneMedical and CFGI; Genesis, Safepay, Lynx RaaS surge"
date:   2026-06-18 20:05:56 +0000
description: "Ransomware-dominant 24-hour cycle: ShinyHunters claims OneMedical.com (Amazon) and exposes 248k CFGI records; Genesis, Safepay, Lynx and Inc Ransom drive 16 of 23 reports. SANS flags 20M coordinated SSH brute-force attempts correlated with geopolitical events."
category: daily
tags: [cti, daily-brief, shinyhunters, genesis, safepay, lynx, play, inc-ransom]
classification: TLP:CLEAR
reporting_period: "2026-06-17"
generated: "2026-06-18"
draft: true
severity: high
report_count: 23
sources:
  - RansomLock
  - BleepingComputer
  - SANS
  - HaveIBeenPwned
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-17 (24h) | TLP:CLEAR | 2026-06-18 |

## 1. Executive Summary

The pipeline processed 23 reports across six sources in the last 24 hours, with 17 rated **high** severity and ransomware activity overwhelmingly dominating the cycle. The headline items are a pair of ShinyHunters extortion claims against Amazon-owned OneMedical.com and NAIC.org, paired with HaveIBeenPwned's publication of the CFGI breach (248,235 records) attributed to the same actor. The Genesis, Safepay, Lynx, Inc Ransom, Play, Lamashtu and Ransomhouse RaaS operations together account for 16 RansomLook leak-site posts spanning healthcare, construction, hospitality, and Italian public-utility targets. SANS published a guest diary documenting more than 20 million coordinated SSH brute-force attempts over the last three months, with spikes correlated to CISA Emergency Directive 26-03 (Cisco SD-WAN) and Iran/Israel/US tensions. No critical-severity reports landed in the daily window, but two AI-identified critical trends (obfuscation in malware campaigns and ongoing supply-chain exploitation tied to the Mastra/npm and Shai-Hulud activity) remain live from the prior correlation cycle. No CISA KEV additions or confirmed zero-day exploitation were captured in this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None in window (critical trends carry over from prior batch) |
| 🟠 **HIGH** | 17 | ShinyHunters (OneMedical, NAIC, CFGI), Genesis, Safepay, Lynx, Inc Ransom, Play, Lamashtu, Ransomhouse leak-site posts; SANS SSH brute-force analysis |
| 🟡 **MEDIUM** | 2 | Telegram RDP/VPS reseller advert; Play ransomware victim listing |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 4 | SANS Stormcast; BleepingComputer (ChatGPT for Science leak, Google IP-based ad personalisation); Wired (UK facial age estimation) |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters claims Amazon-owned OneMedical and NAIC; CFGI breach (248k records) confirmed via HIBP

**Source:** [RansomLook — Shinyhunters](https://www.ransomlook.io//group/shinyhunters), [HaveIBeenPwned — CFGI](https://haveibeenpwned.com/Breach/CFGI)

ShinyHunters posted two new victims to its leak site within minutes of each other: **OneMedical.com** (an Amazon-owned primary care provider) and **NAIC.org** (the National Association of Insurance Commissioners). Separately, Have I Been Pwned published a verified breach record for **CFGI**, a US financial consulting and advisory firm, comprising **248,235 unique email addresses** plus names, job titles, employers, phone numbers and physical addresses. HIBP attributes the CFGI exposure to a March 2026 ShinyHunters "pay-or-leak" extortion campaign. RansomLook telemetry shows the ShinyHunters leak site at 39% average 30-day uptime with the primary onion domain (`shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion`) currently up; one file server at `91.215.85.22` is intermittently active (20% uptime, currently down). The group continues to use `shinygroup@onionmail.com` and a published PGP key for victim communication. Reported TTPs: **T1566 — Phishing** for initial access, **T1071.001 — Application Layer Protocol: Web Protocols** for leak-site delivery.

#### Indicators of Compromise

```
Onion (leak):    shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion
Onion (down):    toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd[.]onion
Onion (down):    shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd[.]onion
Clearnet:        hxxps[:]//shinyhunte[.]rs
File server IP:  91.215.85[.]22
Contact email:   shinygroup@onionmail[.]com
```

> **SOC Action:** For organisations doing business with OneMedical, NAIC or CFGI, treat any third-party data exchange from those entities as potentially compromised. Force-reset credentials for any users whose corporate emails appear in CFGI HIBP queries; assume phishing follow-on against named contacts. Block egress to the listed onion domains via Tor-exit IP blocklists where Tor is not business-required, and add `91.215.85[.]22` to threat-feed denylists. Hunt EDR for ShinyHunters-typical phishing artefacts (`T1566`) against finance/insurance staff over the last 90 days.

### 3.2 Genesis RaaS expands healthcare, legal services and construction victim lineup

**Source:** [RansomLook — Genesis](https://www.ransomlook.io//group/genesis)

The Genesis ransomware group added two new victims overnight: **United Personnel** (a division of Masis Staffing Solutions) and **The Associated Builders and Contractors of Indiana/Kentucky**. Genesis's stated operating model published on its leak site reads as financially motivated with no affiliate programme, claims data is destroyed after payment, and stipulates that "charitable, non-profit, and medical institutions are only hacked if they have reputation gaps known from open sources." The group's single onion endpoint (`genesis6ixpb5mcy4kudybtw5op2wqlrkocfogbnenz3c647ibqixiad.onion`) shows 90% 30-day uptime with 89 cumulative leak-site posts; the AI correlation engine assigns 0.90 confidence to Genesis's actor signature across these two victims, with shared TTPs **T1566 — Phishing** and **T1485 — Data Encrypted for Impact**. Recent victim sector spread covers healthcare, legal services, financial services, construction, engineering and business services.

#### Indicators of Compromise

```
Onion (leak):   genesis6ixpb5mcy4kudybtw5op2wqlrkocfogbnenz3c647ibqixiad[.]onion
Contact email:  genesis.info@onionmail[.]org
```

> **SOC Action:** Staffing-services, construction-trade-association, and US Midwest legal firms should review external-facing email gateways for credential-phishing landing pages and enforce phishing-resistant MFA on M365/Workspace tenants. Hunt for `T1485` indicators — rapid mass file modification by single-process trees, ransomware extension renames — in DLP/EDR telemetry. Block the Genesis contact onion domain at egress; confirm offline-immutable backups for HR/payroll datasets.

### 3.3 Safepay RaaS posts four European victims in a single batch

**Source:** [RansomLook — Safepay](https://www.ransomlook.io//group/safepay)

Safepay added four leak-site entries in a tight cluster covering: **harcourts.net** (international real-estate brand), **seinordovest.it** (an Italian public utility), **zaunsysteme.de** (German perimeter-security/construction materials), **brscappuccio.it** (Italian textile manufacturer), and **gut-heckenhof.de** (a German four-star hotel/golf resort). The correlation engine returned a 0.90-confidence actor cluster across the three German/Italian victims, with the brand also tracked as the "Safepay" malware family (mention count 5 in the daily window). Infrastructure includes a network of `.onion` chat and file servers with mixed uptime; multiple sites are intermittently active, suggesting either deliberate rotation or operational pressure. No specific TTPs beyond phishing and file encryption were attributable from the source data.

> **SOC Action:** European real-estate, hospitality, and light-manufacturing operators should validate edge-VPN/RDP exposure (Safepay activity historically follows perimeter-service compromise) and confirm patch state on Fortinet, Citrix, and Cisco edge appliances. Pull logs for unusual after-hours admin RDP from non-corporate ASNs. Block Tor egress for non-research users and run an inventory of unmanaged RMM tools on Windows servers.

### 3.4 Lynx, Inc Ransom, Play, Lamashtu, Ransomhouse continue steady RaaS leak-site cadence

**Source:** [RansomLook — Lynx](https://www.ransomlook.io//group/lynx), [Inc Ransom](https://www.ransomlook.io//group/inc%20ransom), [Play](https://www.ransomlook.io//group/play), [Lamashtu](https://www.ransomlook.io//group/lamashtu), [Ransomhouse](https://www.ransomlook.io//group/ransomhouse)

Seven additional leak-site posts surfaced across five RaaS brands. **Lynx** posted `wolfconstruction.net`; **Inc Ransom** posted `neuwoges.de` (German municipal housing/utilities); **Play** added Integrated Technologies, eurOptimum and Greg Crosslin (Play uses intermittent encryption with `play.txt` / `ReadMe.txt` ransom notes and is historically affiliated with Hive); **Lamashtu** added Great Foods (Lamashtu has 34 leak posts overall with 100% 30-day uptime via `LamashtuSupport@onionmail.org`); **Ransomhouse** posted Prince George County (operates via Telegram channels `RHouseNews`, `DatabaseCartel`, `AgentGlobal` — channel URLs intentionally not linked). The correlation engine clusters the two Play victims at 0.90 confidence with shared TTPs **T1486 — Data Encrypted for Impact** and **T1071.001 — Application Layer Protocol: Web Protocols**.

> **SOC Action:** SOC teams supporting municipal-government, US local-county and German housing-cooperative customers should treat these claims as escalation triggers: validate Volume Shadow Copy retention, confirm AD tier-0 segmentation, and run a fresh check on internet-exposed RDP/SMB. For Play-affected sectors, hunt EDR for processes performing partial file overwrite patterns consistent with intermittent encryption (`T1486` plus high-rate small-block writes).

### 3.5 SANS guest diary: 20M+ SSH brute-force attempts correlate with geopolitical events and CISA advisories

**Source:** [SANS ISC — Guest Diary (Adam Nason)](https://isc.sans.edu/diary/rss/33086)

A DShield honeypot operated by a SANS.edu BACS student logged **20+ million SSH brute-force attempts over 100 days** (17 Feb to 26 May 2026). Volume tracked observable correlation with external events: a ~2,100% surge in late February aligned with **CISA Emergency Directive 26-03 (Cisco SD-WAN)** and rising Iran/Israel/US tensions; March 1–8 peaked at 300,000+ daily events; sustained 50k–100k+ daily probes through to mid-April with a sharp 15 April drop. The author attributes most activity to Chinese botnet infrastructure and opportunistic post-advisory scanning. TTPs documented: **T1110 — Brute Force**, **T1078 — Valid Accounts**, **T1047 — Windows Management Instrumentation** (where successful logins led to follow-on activity).

> **SOC Action:** Confirm SSH is disabled or behind a bastion on all internet-exposed Linux hosts; where SSH must be exposed, enforce key-only auth, fail2ban/CrowdSec rate-limiting, and alert on first-time-seen geolocations. Treat the publication date of any future CISA Emergency Directive as a trigger to pre-emptively raise SSH/RDP log retention and review last-7-day successful logins for tier-0 hosts. Correlate honeypot/Shodan-reflected source IPs against your perimeter-deny ACLs.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Sophisticated use of obfuscation techniques in malware campaigns | ClickFix Campaign Generated Via AI Delivers SmartRAT; 140+ npm Packages Compromised in Coordinated Supply Chain Attack |
| 🔴 CRITICAL | Exploitation of vulnerabilities in widely used software and platforms leading to supply-chain attacks | Mastra Supply Chain Compromise (easy-day-js Dropper / @mastra Installs); GitHub dismissed security reports on flaws now exploited by supply-chain worm |
| 🟠 HIGH | Increased ransomware activity across multiple sectors with shared TTPs and actors | Genesis (United Personnel, ABC Indiana/Kentucky); ShinyHunters (OneMedical, NAIC) |
| 🟠 HIGH | Increased ransomware activity targeting multiple sectors with double-extortion models | Integrated Technologies By play; Greg Crosslin By play; MHE9 Logística Ltda By gunra |
| 🟠 HIGH | Phishing and credential dumping as prevalent tactics | FortiBleed VPN credential leak (73,000 devices); Why Account Takeovers Are Rising |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (65 reports) — sustained RaaS leak-site cadence over 30 days
- **The Gentlemen** (65 reports) — high-volume leak-site presence
- **Deadlock** (55 reports) — concentrated activity in the last week
- **DragonForce** (38 reports) — continuing multi-sector targeting
- **Akira** (30 reports) — recently observed 2026-06-17
- **Nightspire** (24 reports) — steady leak-site posting
- **Shinyhunters / ShinyHunters** (22 + 21 reports) — same actor split across alias casing; today's OneMedical/NAIC/CFGI activity is the headline
- **TeamPCP** (22 reports) — persistent presence
- **Nova** (15 reports) — moderate activity

### Malware Families

- **RansomLook** (132 reports) — parser/source artefact; high frequency is an ingestion-pipeline marker, not a discrete family
- **Tox1 / Tox** (38 + 21 reports) — recurring RaaS-toolkit references
- **Other1** (30 reports) — generic correlation artefact
- **Akira ransomware / Akira** (15 + 11 reports) — active RaaS family
- **Shai-Hulud** (10 reports) — supply-chain worm tied to npm/GitHub
- **Deadlock** (10 reports) — emerging family with rapid growth
- **Mini Shai-Hulud** (10 reports) — variant of the supply-chain worm
- **RALord** (9 reports) — RaaS activity continuing

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 16 | [link](https://www.ransomlook.io/) | Primary feed for RaaS leak-site activity (Shinyhunters, Genesis, Safepay, Play, Lynx, Inc Ransom, Lamashtu, Ransomhouse) |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com) | OpenAI ChatGPT for Science leak; Google EU/UK IP ad-personalisation policy change |
| SANS | 2 | [link](https://isc.sans.edu/) | SSH brute-force guest diary; daily Stormcast podcast |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/CFGI) | CFGI 248k-record breach attributed to ShinyHunters |
| Wired Security | 1 | [link](https://www.wired.com/story/facial-age-estimate-uk-asylum-seekers/) | UK asylum-seeker facial age estimation deployment |
| Telegram (channel name redacted) | 1 | — | RDP/VPS reseller advert — potential criminal marketplace |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Treat any data-sharing relationship with OneMedical, NAIC.org or CFGI as breach-impacted. Force credential resets for any of your users whose corporate addresses appear in HIBP's CFGI dataset; assume targeted phishing follow-on against named contacts in the next 7–14 days. (Section 3.1)
- 🔴 **IMMEDIATE:** Block egress and add detection for the ShinyHunters infrastructure listed in Section 3.1 (onion domains and file-server IP `91.215.85[.]22`). Validate that Tor egress is denied for non-research users.
- 🟠 **SHORT-TERM:** For sectors named by Genesis, Safepay, Play, Inc Ransom and Lynx (healthcare, legal, construction, hospitality, European real-estate and municipal-utility), audit edge-VPN/RDP exposure, confirm offline-immutable backups, and enforce phishing-resistant MFA on identity providers within the next 14 days. (Sections 3.2–3.4)
- 🟠 **SHORT-TERM:** Re-validate exposure to the carry-over critical trends — npm supply-chain compromise (Mastra / Shai-Hulud worm) and obfuscation-heavy droppers (ClickFix → SmartRAT). Inventory developer endpoints for unexpected npm/yarn installs from the last 14 days and pin known-good package versions in CI. (Section 4)
- 🟡 **AWARENESS:** SOC teams should track the SANS finding that CISA Emergency Directives correlate with brute-force surges; pre-stage SSH/RDP log retention and tier-0 successful-login review whenever a new CISA ED is published. (Section 3.5)
- 🟢 **STRATEGIC:** ShinyHunters' continued targeting of healthcare-adjacent and insurance-sector data brokers reinforces the case for tightening third-party-risk programmes on any data-aggregator vendor; the brand's 39% leak-site uptime suggests the operation is well resourced and unlikely to fade in the near term.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 23 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
