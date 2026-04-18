---
layout: post
title:  "CTI Daily Brief: 2026-04-17 - Critical Protobuf.js RCE PoC; Iran-Linked Cyber Av3ngers Pivot to Rockwell ICS; RaaS Surge from Qilin, Kairos & Coinbase Cartel"
date:   2026-04-18 20:05:00 +0000
description: "PoC released for critical RCE in protobuf.js (GHSA-xq3m-2v4x-88gg); Unit 42 details Iranian Cyber Av3ngers (CL-STA-1128) targeting Rockwell Automation OT/ICS; 19 fresh ransomware leak-site postings spanning Qilin, Kairos, Coinbase Cartel, Blackwater, Nightspire and others; EU age-verification app hacked in under two minutes."
category: daily
tags: [cti, daily-brief, qilin, coinbase-cartel, kairos, cyber-av3ngers, protobuf-rce]
classification: TLP:CLEAR
reporting_period: "2026-04-17"
generated: "2026-04-18"
draft: true
report_count: 28
severity: critical
sources:
  - BleepingComputer
  - Unit42
  - Wired Security
  - Schneier
  - RansomLock
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-17 (24h) | TLP:CLEAR | 2026-04-18 |

## 1. Executive Summary

The pipeline processed 28 reports across six sources in the last 24 hours, dominated by ransomware leak-site activity (22 high-severity items, 19 of them from RansomLook). The single critical-severity item is a public proof-of-concept for an unauthenticated remote code execution flaw in `protobuf.js` (GHSA-xq3m-2v4x-88gg), a Node.js library averaging ~50 million weekly downloads — patched in 8.0.1 and 7.5.5 but not yet observed exploited in the wild. Unit 42 published a major update to its Iran threat brief detailing the Cyber Av3ngers cluster (CL-STA-1128, aka Storm-0784) pivoting from Unitronics PLCs to Rockwell Automation FactoryTalk and Allen-Bradley equipment, with CISA mirroring the findings on 7 April. Ransomware activity remains broad and high-tempo: Qilin, Kairos, Coinbase Cartel, Blackwater, Nightspire, RansomHouse, RansomExx, Payoutsking, Krybit and Inc Ransom all posted fresh victims, with healthcare, logistics and religious organisations heavily represented. No new CISA KEV additions appeared in this 24-hour window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | protobuf.js RCE (GHSA-xq3m-2v4x-88gg) |
| 🟠 **HIGH** | 22 | Qilin/Kairos/Coinbase Cartel/Blackwater/Nightspire leak posts; Unit 42 Iran brief; EU age-verification app vulnerability |
| 🟡 **MEDIUM** | 1 | Telegram-distributed open SOCKS proxy lure |
| 🟢 **LOW** | 1 | Microsoft Teams right-click paste regression from Edge update |
| 🔵 **INFO** | 3 | NAKIVO v11.2 release; Schneier commentary (Anthropic Mythos restrictions, squid blog) |

## 3. Priority Intelligence Items

### 3.1 Critical RCE in protobuf.js — PoC Public, Patches Available

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-flaw-in-protobuf-library-enables-javascript-code-execution/)

Endor Labs published a proof-of-concept for a critical remote code execution flaw in `protobuf.js`, the JavaScript implementation of Google Protocol Buffers, tracked as **GHSA-xq3m-2v4x-88gg** (no CVE assigned at time of writing). The library averages ~50 million npm downloads per week and is widely used for inter-service communication, real-time apps and structured storage. The library builds JavaScript functions from protobuf schemas by string-concatenating them and executing via the `Function()` constructor without validating schema-derived identifiers (e.g., message names). An attacker who can supply a malicious schema can inject arbitrary code that executes during message processing — yielding RCE on the server (or developer workstation) with access to environment variables, credentials, databases and lateral-movement opportunities. The bug was reported by Cristian Staicu on 2 March; maintainers shipped a patch on GitHub on 11 March. npm fixes landed on 4 April (8.x branch) and 15 April (7.x branch). Endor Labs reports exploitation is "straightforward" but no in-the-wild abuse has been observed yet. Affected versions: `protobuf.js ≤ 8.0.0` and `≤ 7.5.4`.

#### Indicators of Compromise
```
Advisory:        GHSA-xq3m-2v4x-88gg
Package:         protobuf.js (npm)
Vulnerable:      <= 8.0.0, <= 7.5.4
Patched:         8.0.1, 7.5.5
Sink:            Function() constructor on schema-derived identifiers
ATT&CK:          T1059.001 (Command and Scripting Interpreter: JavaScript)
```

> **SOC Action:** Inventory `protobuf.js` (and transitive dependencies via `npm ls protobufjs` / SCA tooling) across build pipelines, container images and developer workstations; pin to 8.0.1 or 7.5.5. Treat any `.proto` schema sourced from external systems (object stores, message brokers, partner APIs) as untrusted input — prefer precompiled/static schemas in production. Add Falco/EDR detections for unexpected `node` processes spawning shells or making outbound connections from services that consume external schemas.

### 3.2 Iranian Cyber Av3ngers (CL-STA-1128) Pivot to Rockwell Automation OT/ICS

**Source:** [Unit 42 — Palo Alto Networks](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)

Unit 42's updated Iran threat brief (17 April) reports a new activity cluster, **CL-STA-1128** (overlapping with Cyber Av3ngers / Storm-0784), targeting Rockwell Automation FactoryTalk software and Allen-Bradley PLCs — a shift from the cluster's historic focus on internet-exposed Unitronics PLCs. Unit 42 assesses with moderate confidence that the operator installed FactoryTalk on VPS infrastructure to enable exploitation, based on observed port combinations matching FactoryTalk's static port mappings. Cortex Xpanse identified Rockwell/Allen-Bradley SCADA exposure on **5,600 IP addresses globally** since 1 April. CISA released a corroborating advisory on 7 April. The brief also notes Iran began restoring limited internet access on 17 April after a 47-day outage, with Iranian-IP-space service counts climbing to ~300,000 daily (up from ~20,000 at the end of February). The wider report covers conflict-themed phishing — Unit 42 identified **7,381 phishing URLs across 1,881 hostnames** — impersonating telcos, airlines, law enforcement and energy firms to harvest credentials and run financial fraud, including cryptocurrency donation scams. Tarnished Scorpius is also referenced as an associated cluster.

#### Indicators of Compromise
```
Activity cluster: CL-STA-1128 (aka Cyber Av3ngers, Storm-0784)
Targeted tech:    Rockwell Automation FactoryTalk; Allen-Bradley PLCs
Exposure:         ~5,600 Rockwell/Allen-Bradley IPs globally (Cortex Xpanse, since Apr 1)
Phishing infra:   7,381 URLs / 1,881 hostnames (conflict-themed lures)
ATT&CK:           T1566 (Phishing); T1071.001 (Web C2); T1498 (Network DoS)
```

> **SOC Action:** Run an external attack-surface check for Rockwell FactoryTalk and Allen-Bradley device exposure (common ports include 1330, 1331, 2222, 44818); place any internet-reachable instance behind a VPN or jump host immediately. Hunt EDR for FactoryTalk client binaries running on non-engineering workstations or VPS-class hosts. For OT/IT teams: validate Purdue-model segmentation between Levels 2/3 and the IT enterprise zone. Block/alert on the conflict-themed phishing themes Unit 42 lists (telecom, airline, energy impersonation) and add the `1881` hostname dataset to your URL-filtering deny list when published.

### 3.3 RaaS Posting Wave — Qilin, Kairos, Coinbase Cartel, Blackwater, Nightspire

**Source:** [RansomLook — Qilin](https://www.ransomlook.io//group/qilin), [Kairos](https://www.ransomlook.io//group/kairos), [Coinbase Cartel](https://www.ransomlook.io//group/coinbase%20cartel), [Blackwater](https://www.ransomlook.io//group/blackwater), [Nightspire](https://www.ransomlook.io//group/nightspire), [RansomHouse](https://www.ransomlook.io//group/ransomhouse), [RansomExx](https://www.ransomlook.io//group/ransomexx), [Payoutsking](https://www.ransomlook.io//group/payoutsking), [Krybit](https://www.ransomlook.io//group/krybit), [Inc Ransom](https://www.ransomlook.io//group/inc%20ransom)

Nineteen fresh leak-site postings appeared across ten ransomware brands in 24 hours. **Coinbase Cartel** (4 victims: Altpro, Securitevolfeu, McCuaig and Associates Engineering, "Evict them for me") and **Kairos** (5 victims: Hazel Mercantile, South Florida Injury Centers, Colonial Presbyterian Church, Pullen Moving, FriendlyCare Pharmacy, Strata Republic) dominated by victim count. Both were correlated by the pipeline at 0.90 confidence (shared actor + sectoral spread spanning healthcare, technology, manufacturing, finance, construction, legal, education, logistics and religious organisations). Qilin posted HS Technology Group and remains the most prolific actor in the pipeline-wide window (57 reports in the last ~30 days). Blackwater hit Minidoka Memorial Hospital and Grupo EBD; RansomHouse claimed Winnitex (Americas) Limited; RansomExx claimed SOGO Auction; Payoutsking, Krybit and Inc Ransom each posted single victims. Nightspire posted a victim with a redacted name. Across the set, the dominant TTPs were **T1566 (Phishing)**, **T1486 (Data Encrypted for Impact)**, **T1071.001 (Web C2)** and **T1496 (Resource Hijacking)**. Note: the Coinbase Cartel and Kairos infrastructure overlaps include public Onion services with unstable uptime (consistent with active take-down/relocation cycles).

#### Indicators of Compromise
```
Group:           Qilin (aka Agenda)
Jabber:          qilin@exploit[.]im
Tox:             7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
Ransom notes:    README-RECOVER-[rand].txt
                 README-RECOVER-[rand]_2.txt
                 DtMXQFOCos-RECOVER-README.txt
Active leak:     hxxp[:]//ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion (90% uptime)
                 hxxp[:]//pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd[.]onion (50% uptime)
File server:     hxxp[:]//kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion (100% uptime)

Group:           Kairos
Email:           kairossup@onionmail[.]com
Ransom note:     README_47.txt

Group:           RansomHouse (Winnitex)
File extension:  .White_Rabbit
ATT&CK:          T1566, T1486, T1071.001, T1496
```

> **SOC Action:** For healthcare and logistics constituents in particular, run a fresh tabletop on data-extortion playbooks in the next two weeks and confirm immutable/offline backup posture. In EDR, hunt for ransom-note filenames listed above (`README_47.txt`, `README-RECOVER-*.txt`, `DtMXQFOCos-RECOVER-README.txt`); look for newly-created files with these names across user shares and SMB targets within the last 30 days. Block egress to the listed `.onion` hosts at the proxy/firewall (Tor itself should already be blocked from corporate endpoints). Validate that anti-phishing controls catch credential-harvest themes against the named victim sectors.

### 3.4 EU Age-Verification App Compromised in Under Two Minutes

**Source:** [Wired Security](https://www.wired.com/story/security-news-this-week-it-takes-2-minutes-to-hack-the-eus-new-age-verification-app/)

Security consultant Paul Moore reported on X that the European Commission's newly-released open-source age-verification reference app — pitched by Commission President Ursula von der Leyen as eliminating excuses for platforms to skip age checks — contains a series of issues that allowed full takeover of a user profile in under two minutes. The chain centres on how the app stores a user-created PIN, enabling profile takeover by an attacker. Whitehat researcher Baptiste Robert independently confirmed the vulnerability to *Politico*. No vendor patch or coordinated-disclosure timeline has been published in the source. Risk implication: any platform that integrates this reference app inherits the underlying weakness; bulk profile takeover would expose age-verification claims to repudiation and user impersonation. The Wired round-up also references the Republican-led short-term reauthorisation of US Section 702 surveillance and ongoing nonconsensual deepfake-nude incidents (600+ victims across 28 countries), which sit outside this brief's operational scope.

#### Indicators of Compromise
```
Affected product: EU age-verification reference app (open source)
Root cause:       Insecure local storage of user-created PIN
ATT&CK:           T1555 (Credentials from Password Stores); T1021 (Remote Services)
Patch status:     None disclosed at time of writing
```

> **SOC Action:** If your organisation is piloting the EU age-verification app or any derivative integration, halt rollout until the European Commission publishes a fix and an independent verification. For platforms in scope, do not depend on the reference implementation as a sole identity-assurance control; require a second factor (e.g., bank/eIDAS attestation) for any high-risk decision until patched.

### 3.5 OSINT Note — Post-RAMP Ransomware Ecosystem Dispersion

**Source:** Telegram (channel name redacted)

A Telegram OSINT post (TLP:AMBER+STRICT) flags that the January seizure of the RAMP marketplace continues to disperse ransomware affiliates through Q2 2026, fragmenting communications channels and complicating attribution. No specific actor or campaign is named. Operationally relevant as context for the increased number of small/short-lived RaaS brands (e.g., Coinbase Cartel emerging March 2026, Kairos active across multiple Onion infrastructure swaps).

> **SOC Action:** Brief threat-intel staff that affiliate dispersal is likely to produce more low-volume "rebrand" leak sites in coming weeks; treat overlap of TTPs (rather than brand name) as the primary pivot for attribution and detection engineering.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Vulnerabilities in technology infrastructure leading to potential exploitation | Critical flaw in protobuf.js library (GHSA-xq3m-2v4x-88gg); EU age-verification app hacked in <2 minutes |
| 🔴 **CRITICAL** | Chromium vulnerabilities being actively exploited (carry-over from prior batch) | Chromium CVE-2026-6304 (use-after-free in Graphite); CISA flags Apache ActiveMQ flaw as actively exploited |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors with overlapping TTPs | Coinbase Cartel posts (Altpro, Securitevolfeu, McCuaig, "Evict them for me"); Kairos posts (Pullen Moving, Hazel Mercantile, etc.) |
| 🟠 **HIGH** | Ransomware targeting healthcare and critical infrastructure | Grupo EBD & Minidoka Memorial Hospital (Blackwater); Mag. Fünder Hausverwaltungs (Inc Ransom); Qilin disruption to London healthcare (carry-over) |
| 🟠 **HIGH** | Ransomware with sophisticated evasion techniques | Payouts King QEMU-VM EDR-bypass (carry-over); Winnitex (Americas) Limited (RansomHouse) |
| 🟠 **HIGH** | Targeted cyber campaigns against government and law enforcement, particularly Ukraine | Ukraine APT28 prosecutor/anti-corruption agency targeting (carry-over); US Section 702 reauthorisation debate |
| 🟡 **MEDIUM** | Sophisticated phishing tactics across multiple actors | Conflict-themed lures from Iran (CL-STA-1128); Blackwater operations; Inc Ransom; Telegram-distributed proxy lures |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin / qilin** (57 + 23 reports, RaaS — Agenda alias) — Most prolific brand in the pipeline; Jabber `qilin@exploit.im`, Tox key in IOCs above. Active leak site `ijzn3sicrcy7g…onion` at 90% uptime.
- **The Gentlemen** (48 reports) — Persistent leak-site activity; no posts in the last 24h.
- **Nightspire** (38 reports) — Posted one redacted victim yesterday.
- **TeamPCP** (32 reports) — No posts in this window.
- **Coinbase Cartel** (27 reports) — Four victims posted yesterday; targets span healthcare, finance, construction, legal, education.
- **DragonForce / dragonforce** (26 + 27 reports) — No posts in this 24h window but remains a top-five RaaS by volume.
- **Shadowbyt3$** (22 reports) — Education-sector focus (Ellucian PowerCampus correlation).
- **Akira** (22 reports) — No posts in this window.
- **Kairos** (4 reports yesterday + 4-week trend) — Five victims yesterday across healthcare, religious organisations, logistics.
- **Cyber Av3ngers (CL-STA-1128) / Tarnished Scorpius** (Iran-nexus, named in Unit 42 brief) — OT/ICS targeting against Rockwell Automation; not yet ranked by volume.

### Malware Families

- **RansomLock** (43 reports) — Aggregator label rather than a discrete family; reflects RansomLook ingest volume.
- **Generic "ransomware"** (28 reports) — Untagged ransomware mentions across leak sites.
- **DragonForce ransomware** (26 + 9 reports) — Top branded family by mention volume.
- **Akira ransomware** (18 reports) — Continues steady leak cadence.
- **RaaS** (15 reports) — Service-model tag, broad use across leak posts.
- **Tox1** (10 reports) — Tox messenger references in RaaS infrastructure (used by Qilin, Payoutsking and others for affiliate comms).
- **PLAY ransomware** (8 reports) — No yesterday-window posts.
- **Gentlemen ransomware** (7 reports) — Linked to The Gentlemen actor.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 19 | [link](https://www.ransomlook.io/) | Leak-site aggregation; primary source for RaaS posting wave (Qilin, Kairos, Coinbase Cartel, Blackwater, Nightspire, RansomHouse, RansomExx, Payoutsking, Krybit, Inc Ransom) |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com/news/security/critical-flaw-in-protobuf-library-enables-javascript-code-execution/) | Critical protobuf.js RCE; Microsoft Teams paste regression; NAKIVO v11.2 release |
| Schneier on Security | 2 | [link](https://www.schneier.com/) | Anthropic Mythos restriction commentary; Friday squid blog (no operational content) |
| Unit42 (Palo Alto Networks) | 1 | [link](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/) | Iran threat brief update — CL-STA-1128 / Rockwell Automation targeting |
| Wired Security | 1 | [link](https://www.wired.com/story/security-news-this-week-it-takes-2-minutes-to-hack-the-eus-new-age-verification-app/) | EU age-verification app vulnerability round-up |
| Telegram (channel name redacted) | 2 | — | Post-RAMP affiliate dispersion note (TLP:AMBER+STRICT); SOCKS-proxy lure |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Inventory and patch `protobuf.js` to **8.0.1** or **7.5.5** across all Node.js services, build pipelines, container base images and developer machines. Treat any externally-sourced `.proto` schema as untrusted input until you have audited the upgrade path. (Ties to §3.1.)
- 🔴 **IMMEDIATE:** Audit external attack surface for Rockwell Automation FactoryTalk and Allen-Bradley PLC exposure — Cortex Xpanse counted 5,600 affected IPs globally. Place any internet-reachable instance behind a VPN/jump host today; alert on FactoryTalk client binaries running outside engineering workstations. (Ties to §3.2.)
- 🟠 **SHORT-TERM:** Healthcare, logistics and religious-organisation constituents should rerun ransomware tabletops in the next two weeks given the Kairos/Blackwater/Inc Ransom posting cadence. Verify backup immutability and add the ransom-note filename list (`README_47.txt`, `README-RECOVER-*.txt`, `DtMXQFOCos-RECOVER-README.txt`, `.White_Rabbit` extension) to EDR/XDR file-creation hunts. (Ties to §3.3.)
- 🟠 **SHORT-TERM:** Pause any pilot of the EU age-verification reference app pending an official fix and independent re-test; if already integrated, layer a second identity-assurance factor. (Ties to §3.4.)
- 🟡 **AWARENESS:** Brief detection engineers that post-RAMP affiliate dispersion will continue producing low-volume RaaS rebrands (Coinbase Cartel, Krybit, Payoutsking are recent examples). Prioritise TTP-based detections (T1566, T1486, T1496, T1071.001) over brand-name signatures. (Ties to §3.5 and §4.)
- 🟢 **STRATEGIC:** For OT/ICS-owning constituents, validate Purdue-model segmentation and accelerate any deferred FactoryTalk or RSLogix patch programmes; the Cyber Av3ngers expansion from Unitronics to Rockwell signals broader ICS-vendor coverage going forward. (Ties to §3.2.)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 28 reports processed across 3 correlation batches in the reporting window (4 batches total in the date range). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
