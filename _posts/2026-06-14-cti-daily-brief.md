---
layout: post
title:  "CTI Daily Brief: 2026-06-14 - ShinyHunters extortion hits Berkadia (305K) and Infinite Campus (137K); Krybit ransomware activity continues"
date:   2026-06-15 20:05:28 +0000
description: "ShinyHunters publishes data from two March 2026 'pay-or-leak' breaches affecting commercial real estate finance (Berkadia, 305k) and education (Infinite Campus, 137k). Krybit ransomware operation remains active with multiple fresh victim listings. AI-powered phishing campaigns and Telegram proxy-driven phishing remain the dominant correlation trends."
category: daily
tags: [cti, daily-brief, shinyhunters, krybit, ransomlook]
classification: TLP:CLEAR
reporting_period: "2026-06-14"
generated: "2026-06-15"
draft: true
severity: high
report_count: 6
sources:
  - HaveIBeenPwned
  - RansomLook
  - SANS
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-14 (24h) | TLP:CLEAR | 2026-06-15 |

## 1. Executive Summary

Six reports were ingested across four sources in the last 24 hours, dominated by ShinyHunters' continuing "pay-or-leak" extortion campaign and ongoing Krybit ransomware-as-a-service activity. ShinyHunters published data allegedly taken from Berkadia (305,216 accounts, commercial real estate finance) and Infinite Campus (137,123 accounts, K-12 student information system), both originally compromised in March 2026 via Salesforce instance access. The Krybit RansomLook listing showed sustained operational tempo with a fresh victim (Frey Brothers, Inc.) and a recent full-data breach disclosure for Tulip Mediworld Hospital. No critical-severity reports landed in the period, no CISA KEV additions were observed, and no confirmed in-the-wild zero-day exploitation was reported. AI-identified correlation trends continue to highlight Telegram proxy-driven phishing infrastructure and AI-powered phishing services (from the prior batch) as the dominant cross-cutting themes.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None this period |
| 🟠 **HIGH** | 3 | ShinyHunters/Berkadia, ShinyHunters/Infinite Campus, Krybit ransomware operation |
| 🟡 **MEDIUM** | 0 | None this period |
| 🟢 **LOW** | 0 | None this period |
| 🔵 **INFO** | 3 | SANS ISC Stormcast, Schneier speaking engagements, RansomLook audit-team listing |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters Publishes Berkadia Breach — 305,216 Accounts Exposed

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/Berkadia)

ShinyHunters published data they allege was exfiltrated from commercial real estate finance firm Berkadia following a March 2026 intrusion. The actor's "pay-or-leak" extortion model targeted Berkadia's Salesforce instance, and the released dataset contains 305,216 unique email addresses along with names, physical addresses, phone numbers, and employer details. The reporting attributes the activity to ShinyHunters with associated TTPs T1566 (Phishing) and T1036 (Masquerading), consistent with the actor's recent Salesforce-focused targeting pattern. Berkadia is a major US commercial mortgage servicer; exposed contact details for real estate professionals create a high-value secondary phishing audience.

**Affected:** Berkadia (commercial real estate finance), Salesforce instance data.

> **SOC Action:** Hunt for ShinyHunters TTPs in Salesforce environments — review Salesforce login audit history for unusual `RestApi` / `Bulk API` usage, OAuth connected-app authorisations from non-corporate IP ranges, and large `Account`/`Contact` export events over the last 90 days. Tighten Salesforce IP login ranges and enforce session-bound MFA for API tokens. Brief real-estate finance teams that highly targeted spear-phishing against listed contacts is plausible.

### 3.2 ShinyHunters Publishes Infinite Campus Breach — 137,123 Accounts Exposed

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/InfiniteCampus)

The same ShinyHunters "pay-or-leak" campaign also targeted student information system vendor Infinite Campus in March 2026, with 137,123 unique email addresses published alongside names, employers, job titles, phone numbers, physical addresses, support tickets, and usernames. Infinite Campus stated the exposed data largely consists of school staff names and contact information already considered directory information. Notwithstanding the vendor's framing, the addition of support tickets to the dataset is operationally significant — ticket bodies can reveal internal infrastructure detail, credentials shared in clear text, and named technical contacts useful for follow-on social engineering against K-12 districts. The correlation pipeline links this report to the Berkadia incident at confidence 0.90 (shared actor: ShinyHunters; shared TTPs: T1566, T1036).

**Affected:** Infinite Campus (US K-12 student information system) and customer school districts.

> **SOC Action:** K-12 district SOC/IT teams should treat any Infinite Campus support-ticket history as potentially exposed: rotate any credentials, API keys, or vendor passwords referenced in tickets, and re-scan ticket archives for inadvertently shared secrets. Enable phishing-resistant MFA on all Infinite Campus admin accounts. Flag inbound emails to staff addresses contained in the breach for enhanced phishing analysis for the next 30 days.

### 3.3 Krybit RaaS Operation — Sustained Victim Disclosure Tempo

**Source:** [RansomLook](https://www.ransomlook.io//group/krybit)

The Krybit ransomware operation remains highly active per RansomLook tracking: 4/4 leak-site mirrors are reporting Up (100% 30-day uptime), 21 posts in the last 30 days, and the most recent listing (2026-06-14) names Frey Brothers, Inc. (US eco-friendly laundry-care products) as a victim. Earlier June listings span manufacturing (Mibet New Energy, China), Bolivian government health infrastructure (AISEM), UAE security solutions (Progress Security), and Philippine insurance (Liberty Insurance Corporation). The actor's late-May listing for Tulip Mediworld Hospital was flagged as a "full data breach." Krybit uses a ransom note named `README-RECOVER.txt` and is reachable via four `.onion` mirrors. No specific intrusion TTPs are described in the source data.

**Affected (recent):** Manufacturing, government/public sector, healthcare, insurance, transport, education — broad cross-sector targeting consistent with opportunistic RaaS.

#### Indicators of Compromise
```
Ransom note filename: README-RECOVER.txt
Leak-site (Tor): hxxp[:]//krybitxdpxohsmjooeb3gbgpmdddreh6mnflzac6bnezz74b7yje67yd[.]onion/
Leak-site (Tor): hxxp[:]//krybitx3fh5krdnhegyp2ob3lhizsaiadturtio3ginf7it5gsdgu2yd[.]onion/
Leak-site (Tor): hxxp[:]//krybitqsdzwmhnitvwuhvsntfgf2wrhxveyxroxpc44c6gkft2cqldyd[.]onion/
Leak-site (Tor): hxxp[:]//krybieodq754vlwufrsuxaswxb5zpxyibaawmed2jaduoz2e5m56hmid[.]onion/
Tox ID (operator): F65E1621B7A5DC0139FE108B9CD48404082951E7E7F421A07A7B88A8E8111C13C552EA2B0C4C
```

> **SOC Action:** Add `README-RECOVER.txt` to filesystem-monitoring detections (EDR file-create events on user profile and shared drives). Block outbound traffic to listed `.onion` infrastructure via egress proxy where Tor is policy-prohibited. Subscribe to RansomLook RSS for the Krybit feed and assess each new listing against your customer/supplier exposure list within 24 hours.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Sophisticated phishing campaigns leveraging AI technologies | FBI disrupts massive AI-powered phishing service using a million URLs (batch 174 carry-over) |
| 🟠 **HIGH** | Targeting of commercial real estate and education sectors by ShinyHunters | Berkadia (305k accounts); Infinite Campus (137k accounts) — shared TTPs T1566, T1036 at 0.90 confidence |
| 🟠 **HIGH** | Increased phishing activity via Telegram proxies | Multiple `@Turbotelproxy`-channel proxy configurations distributing T1566-aligned phishing infrastructure |
| 🟠 **HIGH** | Ransomware-as-a-Service groups targeting multiple sectors | Krybit (ongoing); Anubis, Nightspire, Nova continue from prior batches |
| 🟡 **MEDIUM** | Increased use of Telegram for distributing phishing and proxy services | Repeated `t.me/proxy` infrastructure shared across reports (batch 174) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (72 reports) — Russian-speaking RaaS, sustained operational tempo over the last 30 days
- **The Gentlemen** (51 reports) — emerging extortion brand with significant report volume
- **DragonForce** (39 reports) — RaaS with broad sector targeting; last seen 2026-06-14
- **Akira** (33 reports) — long-running RaaS, continues high posting cadence
- **Nightspire** (26 reports) — government and healthcare-focused listings
- **ShinyHunters** (22 reports) — extortion-only group; today's two HIBP additions confirm continued Salesforce-themed campaign
- **Nova** (23 reports) — active leak-site operator
- **Lockbit5** (20 reports) — successor branding active in the period
- **Stormous** (19 reports) — hacktivist-aligned extortion crew

### Malware Families

- **RansomLook** (105 reports) — pipeline tracker tag for leak-site disclosures; not a malware family per se but dominates volume
- **Tox1 / Tox** (33 / 22 reports) — Tox messenger artefacts surfacing alongside ransom-note pairings
- **Akira ransomware** (17 reports) — paired with Akira threat-actor reporting
- **Shai-Hulud / Mini Shai-Hulud** (12 / 12 reports) — ongoing supply-chain-themed malware reporting
- **Nightspire** (12 reports) — named malware variant tracked alongside the actor
- **RALord** (12 reports) — separate RaaS payload still appearing in recent batches

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| HaveIBeenPwned | 2 | [link](https://haveibeenpwned.com/Breach/Berkadia) | Both ShinyHunters extortion publications driving the day's headline items |
| RansomLook | 2 | [link](https://www.ransomlook.io//group/krybit) | Krybit RaaS listing plus audit-team monitoring entry |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33076) | ISC Stormcast podcast — threat level Green, general security news |
| Schneier | 1 | — | Speaking-engagements administrative post; no threat content |

## 7. Consolidated Recommendations

- 🟠 **SHORT-TERM:** Treat Salesforce as a priority audit surface in light of ShinyHunters' continued targeting. Review connected-app OAuth grants, enforce session-bound MFA on API users, restrict trusted IP ranges for login, and audit large `Account`/`Contact`/`Case` export events over the last 90 days. Traces to PII §3.1 and §3.2.
- 🟠 **SHORT-TERM:** K-12 districts and any organisation using Infinite Campus should assume that historical support-ticket content is exposed: rotate credentials shared in tickets, scan ticket archives for secrets, and brief staff on follow-on phishing risk. Traces to §3.2.
- 🟡 **AWARENESS:** Add Krybit IOCs (ransom-note filename, listed `.onion` mirrors, operator Tox ID) to EDR and egress monitoring. Subscribe to the RansomLook Krybit feed for early sighting of customer/supplier listings. Traces to §3.3.
- 🟡 **AWARENESS:** Continue monitoring `@Turbotelproxy` and similar Telegram-distributed MTProto proxy infrastructure used to mask phishing C2 traffic. Block known `t.me/proxy` URL patterns at perimeter where Telegram is policy-prohibited. Traces to §4 (Telegram-proxy phishing trend).
- 🟢 **STRATEGIC:** With AI-powered phishing services rated critical in the prior correlation batch, accelerate planned investment in phishing-resistant MFA (FIDO2/WebAuthn) for executive, finance, and IT-administrator populations to blunt the highest-value targets of scaled AI phishing. Traces to §4 (critical trend).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 6 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
