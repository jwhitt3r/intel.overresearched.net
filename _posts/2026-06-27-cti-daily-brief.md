---
layout: post
title:  "CTI Daily Brief: 2026-06-27 - ShinyHunters Sysco extortion, KDDI 14.2M ISP credential breach, Gentlemen ransomware hits TKMS maritime defence"
date:   2026-06-28 20:05:22 +0000
description: "Sixteen reports across the 24-hour window dominated by ransomware leak-site activity and two large credential breaches. Gentlemen ransomware claimed Thyssenkrupp Marine Systems (TKMS) / Atlas Elektronik with 1TB+ alleged exfiltration; ShinyHunters extorted Sysco exposing 2.7M records; KDDI disclosed a third-party vulnerability exploit affecting up to 14.2M email logins across six Japanese ISPs."
category: daily
tags: [cti, daily-brief, the-gentlemen, shinyhunters, krybit, redact, play, safepay]
classification: TLP:CLEAR
reporting_period: "2026-06-27"
generated: "2026-06-28"
draft: true
report_count: 16
severity: high
sources:
  - RansomLook
  - BleepingComputer
  - HaveIBeenPwned
  - SANS
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-27 (24h) | TLP:CLEAR | 2026-06-28 |

## 1. Executive Summary

Sixteen reports were processed across the 24-hour window, drawn from five sources and dominated by ransomware leak-site activity (8 of 16 reports). Three headline incidents anchor the brief: The Gentlemen ransomware group listed Thyssenkrupp Marine Systems (TKMS) / Atlas Elektronik on its leak site with claims of 1TB+ exfiltration, extending pressure on maritime defence supply chains; ShinyHunters' "pay or leak" extortion of Sysco surfaced on HaveIBeenPwned exposing 2,691,852 email addresses plus corporate contact data; KDDI Corporation disclosed a breach involving up to 14.2 million email logins across six Japanese ISPs (STNet, JCOM, Chubu Telecommunications, NIFTY, BIGLOBE) following exploitation of an unnamed third-party software vulnerability. Additional ransomware activity from Krybit (Ford Mexico subsidiary), safepay, Play, and Redact rounded out the period. No critical-severity reports, CISA KEV additions, or confirmed in-the-wild zero-day exploitation were observed in this window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None this period |
| 🟠 **HIGH** | 9 | Gentlemen/TKMS, Sysco/ShinyHunters, KDDI ISP breach, Krybit/Ford MX, Play, Safepay, Redact ransomware activity |
| 🟡 **MEDIUM** | 1 | Suspicious Telegram proxy channel |
| 🟢 **LOW** | 3 | Additional Telegram proxy channel posts |
| 🔵 **INFO** | 3 | YARA-X 1.18/1.19 release, cmd organization leak-site listing, Telegram proxy noise |

## 3. Priority Intelligence Items

### 3.1 The Gentlemen ransomware claims Thyssenkrupp Marine Systems / Atlas Elektronik

**Source:** [RansomLook — The Gentlemen](https://www.ransomlook.io//group/the%20gentlemen)

The Gentlemen ransomware operation added Thyssenkrupp Marine Systems (TKMS) GmbH and Atlas Elektronik to its leak site on 2026-06-28, advertising 1TB+ of allegedly exfiltrated data. TKMS is a major European naval shipbuilder (submarines and surface vessels) and Atlas Elektronik (Bremen, Germany) supplies integrated sonar systems and heavyweight torpedoes — placing this listing squarely in the maritime defence supply chain. The group has produced 545 leak-site posts to date with 106 in the last 30 days, and operates with a 33% average 30-day uptime, indicating active but intermittently disrupted infrastructure. Tox is in use for victim communications; the chat server `i2ohjeeqe37jre4f2u7pyq73cbm6lecumdxapkvrlryna6rc3it4zsid.onion` is currently down while the public-facing leak site remains up. Listing alone does not confirm encryption impact, but the volume claim and target sensitivity warrant urgent verification.

> **SOC Action:** Defence-industrial and maritime suppliers should hunt for The Gentlemen TTPs documented by Trend Micro (Sept 2025 report referenced in the leak-site description). Specifically: query EDR for outbound Tox protocol traffic, isolate any hosts beaconing to `.onion` infrastructure via Tor bridges, and audit privileged-account activity over the past 90 days. Notify defence-sector ISACs (NDISAC, DCSA) of the listing.

#### Indicators of Compromise
```
Tox ID: F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E
Leak site: hxxp[:]//tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion/
Chat server: hxxp[:]//i2ohjeeqe37jre4f2u7pyq73cbm6lecumdxapkvrlryna6rc3it4zsid[.]onion/
```

MITRE ATT&CK: T1071 (Application Layer Protocol), T1189 (Drive-by / Phishing via Service).

### 3.2 ShinyHunters Sysco extortion — 2,691,852 records published

**Source:** [HaveIBeenPwned — Sysco](https://haveibeenpwned.com/Breach/Sysco)

HaveIBeenPwned added the Sysco breach on 2026-06-28 attributing the campaign to ShinyHunters. The actor ran a "pay or leak" extortion play and published 2,691,852 unique email addresses plus names, phone numbers, physical addresses, internal job titles, employer affiliations, usernames, and customer feedback records. The dataset is heavily corporate, exposing Sysco staff and B2B customer contacts — high-value material for business email compromise (BEC) and supply-chain phishing against the food-service distribution sector and its downstream customers. ShinyHunters' "pay or leak" pattern continues a tempo we have observed across June 2026 (20 reports referencing the actor across the pipeline). No specific intrusion vector has been disclosed publicly.

> **SOC Action:** Food-service, hospitality, and B2B suppliers of Sysco customers should pre-stage BEC controls: enable strict DMARC enforcement (`p=reject`) on Sysco-adjacent domains, brief AR/AP teams on payment-redirection lures referencing Sysco invoices, and load the leaked email set into SEG allow-deny logic to flag spoofing. Hunt mailbox rules created in the last 30 days containing redirect/auto-forward to external domains (T1114.003).

MITRE ATT&CK: T1566 (Phishing), T1114 (Email Collection).

### 3.3 KDDI / six-ISP breach exposes up to 14.2M email logins

**Source:** [BleepingComputer — KDDI ISP breach](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)

KDDI Corporation, one of Japan's largest telecoms operators, disclosed on 2026-06-28 that threat actors exploited a vulnerability in an unnamed third-party software product on an email system shared across five additional ISPs: STNet, JCOM, Chubu Telecommunications, NIFTY, and BIGLOBE. The intrusion was detected on 2026-06-17 and the access vector was blocked the same day. Up to 14.22 million customer email addresses and passwords may be exposed, spanning current, former, and inactive accounts. KDDI states some passwords were hashed and/or encrypted but has not disclosed the algorithm or the proportion stored in plaintext. The incident has been reported to Japan's Personal Information Protection Commission and the Ministry of Internal Affairs and Communications.

> **SOC Action:** Treat any Japanese ISP-issued email address appearing in your auth logs as a credential-stuffing risk for the next 90 days. Force password reset and step-up MFA for accounts authenticated from `@kddi`, `@au.com`, `@biglobe.ne.jp`, `@nifty.com`, `@jcom.home.ne.jp`, `@stnet.co.jp`, `@ctc.co.jp` domains. Update IDS rules to alert on credential-spray attempts from Japan-geo source IPs targeting Microsoft 365, Okta, and VPN endpoints (T1110.004).

MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1071 (Application Layer Protocol), T1110.004 (Credential Stuffing).

### 3.4 Krybit ransomware adds Ford Mexico subsidiary

**Source:** [RansomLook — Krybit](https://www.ransomlook.io//group/krybit)

The Krybit ransomware group added `ford.mx` — Ford Motor Company, S.A. de C.V. (Ford de Mexico) — to its leak site on 2026-06-28 alongside recent listings for the Dominican Republic's tourism police (`politur.gob.do`) and San Silvestre School in Peru. Krybit has produced 59 posts since inception with 22 in the last 30 days and runs a high-availability infrastructure (100% average 30-day uptime across three live `.onion` hosts). The group leaves a `README-RECOVER.txt` ransom note and communicates over Tox. Listing predates any public confirmation of encryption impact at the Ford subsidiary.

> **SOC Action:** Automotive manufacturers and Tier-1/Tier-2 suppliers operating in Mexico and LATAM should hunt for Krybit's published indicators: alert on `README-RECOVER.txt` file creations across file shares (T1486 precursor), block the four Krybit `.onion` URLs at egress, and validate that east-west segmentation prevents lateral spread from corporate IT into OT/plant networks.

#### Indicators of Compromise
```
Tox ID: F65E1621B7A5DC0139FE108B9CD48404082951E7E7F421A07A7B88A8E8111C13C552EA2B0C4C
Ransom note filename: README-RECOVER.txt
Leak site: hxxp[:]//krybitxdpxohsmjooeb3gbgpmdddreh6mnflzac6bnezz74b7yje67yd[.]onion/
Leak site: hxxp[:]//krybitx3fh5krdnhegyp2ob3lhizsaiadturtio3ginf7it5gsdgu2yd[.]onion/
Leak site: hxxp[:]//krybitqsdzwmhnitvwuhvsntfgf2wrhxveyxroxpc44c6gkft2cqldyd[.]onion/
```

MITRE ATT&CK: T1486 (Data Encrypted for Impact).

### 3.5 Continued Play and Redact ransomware activity

**Source:** [RansomLook — Play](https://www.ransomlook.io//group/play), [RansomLook — Redact](https://www.ransomlook.io//group/redact)

Play ransomware added J&J Gaming and Kuhnline to its leak site, while Redact added Hologic (medical imaging/diagnostics) and FCCI Insurance Group. Play continues to use intermittent encryption to evade detection per its publicly documented TTPs. Redact's infrastructure averages 32% uptime across 30 days, consistent with a smaller-scale or operationally-constrained group, but the choice of healthcare and insurance targets sustains the broader trend identified by the correlation engine. The previous correlation batch (199) classified the Redact / Play activity cluster as a **critical** risk-level trend on 2026-06-27.

> **SOC Action:** Healthcare, insurance, and gaming/hospitality sectors should run targeted hunts for Play's intermittent-encryption signatures — query EDR for processes that open/close handles to the same file repeatedly within short windows, and alert on volume shadow copy deletion (`vssadmin delete shadows /all`, T1490). For Redact, monitor for anomalous encrypted-traffic patterns to Tor entry nodes.

MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware groups targeting multiple sectors with sophisticated techniques (batch 199, 2026-06-27) | Hologic By redact; FCCI Insurance Group By redact; J&J Gaming By play; Kuhnline By play |
| 🟠 **HIGH** | Increased targeting of critical infrastructure sectors with ransomware and phishing campaigns (batch 200) | ford.mx By krybit; Thyssenkrupp Marine Systems (TKMS) GmbH / Atlas Elektronik By the gentlemen |
| 🟠 **HIGH** | Rising incidents of data breaches involving large-scale account compromises (batch 200) | Sysco - 2,691,852 breached accounts; KDDI 14.2M ISP email logins |
| 🟠 **HIGH** | Increased use of phishing as a common attack vector across various sectors (batch 199) | FCCI Insurance Group By redact; Telegram proxy channel posts; LastPass user-data theft coverage |
| 🟡 **MEDIUM** | Cross-report TTP overlap on T1071 — Application Layer Protocol (Tor/Tox C2) | TKMS by The Gentlemen ↔ KDDI ISP breach (confidence 0.70) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (84 reports) — surged to top trending position; today's TKMS / Atlas Elektronik listing extends recent campaign tempo
- **Qilin** (65 reports) — sustained ransomware presence; no new listing in this window
- **Deadlock** (55 reports) — high recent activity in mid-June, quieter this period
- **Lockbit5** (39 reports) — continued post-rebrand operations
- **Akira** (30 reports) — last seen 2026-06-26
- **DragonForce** (24 reports) — last seen 2026-06-27
- **Nova** (22 reports) — last seen 2026-06-26
- **ShinyHunters** (20 reports) — surfaced today via Sysco extortion confirmation on HIBP
- **Nightspire** (18 reports) — last seen 2026-06-21

### Malware Families

- **RansomLook** (141 reports) — leak-site aggregator referenced across most ransomware reports
- **Tox1 / Tox** (64 / 42 reports) — actor-comms protocol; seen again today with Gentlemen and Krybit Tox IDs
- **Other1** (43 reports) — Gentlemen-linked artifact identifier
- **Akira ransomware** (15 reports) — sustained presence
- **Lockbit5** (14 reports) — continued sightings
- **Nova / RALord / Deadlock** (10 reports each) — mid-tier active families
- **Akira Ransomware** (9 reports) — duplicate-cased entity, same family as above

No vulnerability/CVE entities appeared in today's 24-hour window. The pipeline's trending-vulnerability list reflects items last seen 2026-06-12 / 2026-06-15 (Patch Tuesday residue) and is not actionable for this brief.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 8 | [link](https://www.ransomlook.io) | Primary feed for ransomware leak-site activity (Gentlemen, Krybit, Play, Redact, safepay, cmd organization) |
| Unknown / Telegram | 5 | — | Telegram proxy channel posts; channel URLs withheld per editorial policy |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33106) | YARA-X 1.18/1.19 release notes — defensive tooling update |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/) | KDDI six-ISP breach disclosure |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Sysco) | Sysco / ShinyHunters extortion confirmation |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Defence-industrial / maritime suppliers — initiate inbound-supplier verification with TKMS and Atlas Elektronik contacts; do not rely on email-only confirmation given the leak-site claim. Block The Gentlemen `.onion` infrastructure and Tox ID at egress and EDR (3.1).
- 🟠 **SHORT-TERM:** Treat the Sysco and KDDI exposures as a single elevated-risk credential-stuffing wave. Force resets for any user whose corporate email matches the Sysco dump and rate-limit auth attempts from Japan-geo IPs targeting M365/Okta/VPN for at least 90 days (3.2, 3.3).
- 🟠 **SHORT-TERM:** Healthcare and insurance security teams — Redact's targeting of Hologic and FCCI sustains the critical-risk trend identified by yesterday's batch 199. Run table-top exercises against intermittent-encryption ransomware playbooks and validate immutable-backup integrity (3.5).
- 🟡 **AWARENESS:** Automotive and LATAM operations — Krybit's Ford Mexico listing reinforces the need to enforce segmentation between corporate IT and plant/OT networks. Validate that ransom-note-creation alerts are active across all file shares (3.4).
- 🟢 **STRATEGIC:** Detection engineering — schedule an upgrade window to YARA-X 1.19.0 to pick up the new `--max-cpu-time` CLI option for safer scanning of untrusted samples (SANS ISC, 2026-06-28).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 16 reports processed across 1 correlation batch in the reporting window (3 batches across the 48-hour observation horizon). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
