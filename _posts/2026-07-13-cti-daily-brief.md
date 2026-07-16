---
layout: post
title:  "CTI Daily Brief: 2026-07-13 - Qilin and Titan RaaS surge, Nihon Kotsu cyberattack shuts Japan's largest taxi operator"
date:   2026-07-14 20:05:00 +0000
description: "Seventeen reports across four sources; the day was dominated by RaaS victim postings from Qilin (9), Titan (3), DragonForce and The Gentlemen, alongside a confirmed cyberattack on Nihon Kotsu, Japan's largest taxi operator. No critical-severity items landed in the period."
category: daily
tags: [cti, daily-brief, qilin, dragonforce, titan, the-gentlemen]
classification: TLP:CLEAR
reporting_period: "2026-07-13"
generated: "2026-07-14"
draft: true
report_count: 17
severity: high
sources:
  - RansomLook
  - BleepingComputer
  - SANS
  - RecordedFutures
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-13 (24h) | TLP:CLEAR | 2026-07-14 |

## 1. Executive Summary

Seventeen reports ingested across four sources in the last 24 hours, with 15 rated high and 2 informational. No critical-severity items landed in the period, but RaaS victim-posting activity dominated: Qilin alone claimed nine fresh victims spanning manufacturing, hospitality, home health and broadcasting, while Titan added three Czech-region victims and DragonForce posted a Chinese autonomous-driving firm (momenta.cn). The most operationally significant non-ransomware item is a confirmed cyberattack on Nihon Kotsu, Japan's largest taxi operator, which forced a partial infrastructure shutdown. No CISA KEV additions or confirmed in-the-wild CVE exploitation were reported in this window; however, the correlation engine flagged critical infrastructure-vulnerability activity carrying over from prior cycles (npm supply-chain and nginx RCE research).

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None in period |
| 🟠 **HIGH** | 15 | Qilin (9), Titan (3), DragonForce, The Gentlemen victim posts; Nihon Kotsu cyberattack |
| 🟡 **MEDIUM** | 0 | None in period |
| 🟢 **LOW** | 0 | None in period |
| 🔵 **INFO** | 2 | SANS ISC Stormcast; EU social-media age-13 policy proposal |

## 3. Priority Intelligence Items

### 3.1 Nihon Kotsu cyberattack forces partial shutdown at Japan's largest taxi operator

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/japans-largest-taxi-operator-shuts-systems-after-cyberattack/)

Nihon Kotsu confirmed a cyberattack that compromised its systems and forced the company to shut down part of its operating infrastructure. Public disclosure at the time of reporting does not attribute the intrusion to a named actor or malware family, and no ransomware group has posted the organisation on a leak site as of this brief. The incident highlights ongoing exposure of dispatch, booking and payment platforms across urban mobility providers, a sector that has seen repeated ransomware and extortion activity throughout 2026. No IOCs published.

> **SOC Action:** Transport and logistics defenders should hunt for anomalous authentication into dispatch, driver-app and payment integration systems; validate segmentation between customer-facing booking platforms and back-office fleet management; and treat any regional taxi-operator supply relationships (payments, telematics, insurance integrations) as monitoring priorities until Nihon Kotsu discloses a root cause.

### 3.2 Qilin RaaS posts nine new victims in 24 hours across manufacturing, hospitality, home health and media

**Source:** [RansomLook — Qilin group page](https://www.ransomlook.io//group/qilin)

Qilin (aka Agenda) posted nine victims to its leak site in the reporting window: Sedemi, Busscar de Colombia, Counts & Dobyns, Centro Científico e Cultural de Macau, Jakub A.S., Cemoi, URH Hoteliers, Hillebrand Home Health and TitanTV, Inc. The group operates under a mature RaaS model with a stable but heavily-degraded onion footprint (RansomLook shows 4 of 640 tracked URLs currently healthy), affiliate coordination via Jabber (`qilin@exploit.im`) and Tox, and ransom notes named `README-RECOVER-[rand].txt` and `DtMXQFOCos-RECOVER-README.txt`. Correlation engine linked the Sedemi and Counts & Dobyns posts (actor confidence 0.90) via shared use of T1071 - Application Layer Protocol, and the Busscar / Cemoi posts via T1071.001.

Affected sectors this cycle: manufacturing (industrial equipment), specialty transport, financial services, cultural / academic institutions, food & beverage, hospitality, home health, and broadcast media. Geographic spread: Colombia, Czech Republic, Macau, Poland, France, Spain and the United States.

#### Indicators of Compromise

```
Ransom note names:
  README-RECOVER-[rand].txt
  README-RECOVER-[rand]_2.txt
  DtMXQFOCos-RECOVER-README.txt

Affiliate contact:
  Jabber: qilin@exploit.im
  Tox:    7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68

Onion (leak, currently up):
  hxxp[:]//ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
  hxxp[:]//kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion

FTP data-share credentials observed in Qilin infrastructure:
  dataShare:nX4aJxu3rYUMiLjCMtuJYTKS@85.209.11[.]49
  dataShare:2bTWYKNn7aK7Rqp9mnv3@188.119.66[.]189
  dataShare:2bTWYKNn7aK7Rqp9mnv3@176.113.115[.]209
  dataShare:2bTWYKNn7aK7Rqp9mnv3@185.39.17[.]75
  datashare:ENqh0jBHKia2L22fxzivbhRL@64.176.162[.]76

TTPs: T1071 - Application Layer Protocol, T1071.001 - Web Protocols,
      T1486 - Data Encrypted for Impact
```

> **SOC Action:** Alert on file-writes matching `README-RECOVER-*.txt` or `*-RECOVER-README.txt` across file servers and endpoints. Block outbound FTP to the IPs above at perimeter and egress-proxy layers, and hunt for FTP `USER dataShare` / `USER datashare` sessions in netflow / firewall logs. Add the Qilin Tox ID to insider-threat / OPSEC monitoring lists for any unmanaged devices.

### 3.3 DragonForce posts Chinese autonomous-driving firm momenta.cn; UK-retail cartel model continues

**Source:** [RansomLook — DragonForce group page](https://www.ransomlook.io//group/dragonforce)

DragonForce added momenta.cn (Chinese autonomous-driving technology developer) to its leak blog. DragonForce operates a cartel-style RaaS: sophisticated affiliate portal, shared leak infrastructure, and strategic branding flexibility that lets affiliates operate under their own labels using DragonForce's backend. External reporting has previously tied DragonForce to the M&S, Harrods and Co-op UK retail intrusions. The momenta.cn posting expands the group's targeting into Asia-Pacific technology. Reported TTPs include T1204 (User Execution), T1486 (Data Encrypted for Impact) and T1499 (Command and Scripting Interpreter). Only one leak URL is currently up (`z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion/blog`) but the login/admin server is stable, suggesting affiliates continue to have working access.

#### Indicators of Compromise

```
Ransom notes:
  readme.xt
  [rand].README.txt

Affiliate contact:
  Tox: 1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856D90A65E99D20

Onion (leak, currently up):
  hxxp[:]//z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid[.]onion/blog

TTPs: T1204 - User Execution, T1486 - Data Encrypted for Impact,
      T1499 - Command and Scripting Interpreter
```

> **SOC Action:** For retail, automotive and mobility organisations, review third-party access controls for suppliers with UK-market exposure (DragonForce's confirmed hunting ground) and Chinese technology partnerships. Hunt for the ransom-note filenames above and stage a tabletop that assumes a DragonForce affiliate has valid credentials via a compromised MSP.

### 3.4 Titan ransomware posts three Czech-Republic victims in one hour

**Source:** [RansomLook — Titan group page](https://www.ransomlook.io//group/titan)

Titan claimed three Czech companies within a single 60-second window: Cooperate consulting CZ s.r.o., Ozmit s.r.o. and DataOstrov s.r.o. The correlation engine linked all three posts (actor confidence 0.90) via shared TTPs T1566 (Phishing) and T1204 (User Execution). Titan's operational summary indicates phishing-led initial access followed by data theft and dark-web leak posting; the burst pattern and shared TTPs strongly suggest a single affiliate working a Czech-region target list, likely from the same phishing cluster.

> **SOC Action:** Czech and central-European MSPs and SMBs should hunt inbound mail for Czech-language phishing (invoice, delivery, corporate-services lures) with attachments requiring user execution (LNK, ISO, ZIP-with-script). Query EDR for user-executed scripts spawning from mail-client child processes over the past 30 days. If any of the three named companies are known suppliers, treat them as potential lateral-movement pivots.

### 3.5 The Gentlemen exfiltrate 400GB from Tangram Interiors

**Source:** [RansomLook — The Gentlemen group page](https://www.ransomlook.io//group/the%20gentlemen)

The Gentlemen (110 reports pipeline-wide, most-active actor in the last 30 days) posted Tangram Interiors — a Southern California commercial-interiors and Steelcase dealer with $245M revenue — claiming 400+ GB of exfiltrated data including client personal data. The group's leak infrastructure is unusually stable (93% uptime on primary onion) and it maintains parser + captcha protections consistent with a mature operation. Group summary references T1566 - Phishing as the primary initial-access vector. Trend Micro external analysis is referenced from the group's own leak page.

> **SOC Action:** Interior-design, architectural, commercial-real-estate and Steelcase-dealer channel partners should assume Tangram client data is in criminal hands and prepare downstream notification for shared clients. Prioritise phishing-simulation refresh cycles and Microsoft 365 conditional-access hardening (block legacy auth, require MFA on all admin roles) — The Gentlemen consistently leverages T1566 for entry.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of infrastructure vulnerabilities by various threat actors (carried from prior cycle) | Hackers backdoor Jscrambler npm package with infostealer malware; Two Bytes to RCE: Chaining Rift + PoolSlip into an ASLR-Independent nginx 1.30.0 Exploit |
| 🟠 **HIGH** | Increased activity of Ransomware-as-a-Service (RaaS) groups targeting multiple sectors globally | Sedemi By qilin; momenta.cn By dragonforce; Counts & Dobyns By qilin |
| 🟠 **HIGH** | Sophisticated phishing campaigns used to facilitate malware deployment (batch 228) | TitanTV, Inc. By qilin; New CrashStealer malware poses as Apple crash reporting tool; VPN service favored by ransomware groups is sanctioned by US |
| 🟠 **HIGH** | Exploitation of infrastructure vulnerabilities in web services (batch 228) | Two Bytes to RCE nginx 1.30.0; CISA warns of actively exploited RCE flaws in Joomla extensions |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (110 reports) — most-active RaaS actor by post volume; commercial and professional-services targeting
- **Qilin** (83 reports) — aka Agenda; RaaS with heavy sector spread and mature affiliate program
- **Deadlock** (66 reports) — persistent leak-site activity
- **Lockbit5** (36 reports) — continued post-relaunch tempo
- **Akira** (24 reports) — active over the last 24h in adjacent cycles
- **DragonForce** (23 reports) — cartel-style RaaS expanding into Asia-Pacific technology this cycle

### Malware Families

- **Qilin** / **Qilin RaaS** / **Qilin Ransomware** (12 reports) — associated payloads and infrastructure
- **Akira ransomware** (12 reports)
- **Deadlock** (12 reports)
- **The Gentlemen Ransomware** (12 reports)
- **Anubis ransomware** (10 reports)

*Note: "RansomLook", "Tox1", "Other1" and "Tox" appear high in the malware entity index as indexing artifacts from the RansomLook parser rather than distinct malware families, and are excluded from the operational list above.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 14 | [link](https://www.ransomlook.io) | Ransomware leak-site tracker; primary source of Qilin, Titan, DragonForce and The Gentlemen victim postings this cycle |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/japans-largest-taxi-operator-shuts-systems-after-cyberattack/) | Sole non-RaaS operational item (Nihon Kotsu cyberattack) |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33152) | ISC Stormcast for 2026-07-14, threat level green |
| RecordedFutures | 1 | [link](https://therecord.media/eu-proposed-social-media-ban-kids-under-13) | Policy: EU proposal for social-media age floor of 13 |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Block the Qilin FTP data-share IPs (`85.209.11[.]49`, `188.119.66[.]189`, `176.113.115[.]209`, `185.39.17[.]75`, `64.176.162[.]76`) at egress; alert on any endpoint writing `README-RECOVER-*.txt`. Rationale: nine fresh victims in 24 hours across multiple sectors and geographies indicates active affiliate operations right now (§3.2).
- 🟠 **SHORT-TERM:** Transport / mobility / logistics defenders — refresh incident-response playbooks for dispatch and payment-platform outages, and review third-party integrations, in light of the Nihon Kotsu shutdown (§3.1). Segment customer-facing booking systems from fleet-management back-office.
- 🟠 **SHORT-TERM:** Central-European MSPs and SMBs should hunt Czech-language phishing with user-executed attachments (LNK, ISO, script-in-ZIP) from the past 30 days; the three near-simultaneous Titan victims suggest an active regional phishing cluster (§3.4).
- 🟡 **AWARENESS:** Commercial interior-design, architecture and Steelcase-channel partners of Tangram Interiors should prepare for downstream client-data exposure notifications and prioritise phishing-simulation and M365 conditional-access hardening (§3.5).
- 🟢 **STRATEGIC:** DragonForce's move against a Chinese autonomous-driving firm expands its geographic footprint beyond UK retail. Automotive, mobility and technology-supplier organisations should treat DragonForce as a credible current-quarter threat and stage a tabletop assuming affiliate access via a compromised MSP (§3.3).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 17 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
