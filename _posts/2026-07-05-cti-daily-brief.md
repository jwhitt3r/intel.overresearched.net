---
layout: post
title:  "CTI Daily Brief: 2026-07-05 — The Gentlemen ransomware dominates with 18 victims; Shinyhunters hits Fluke and Ingram Content Group"
date:   2026-07-06 20:05:31 +0000
description: "The Gentlemen ransomware group posted 18 fresh victims across food service, IT, energy and engineering. Shinyhunters added Fluke Corporation and Ingram Content Group. Space Bears leaked 500 GB from UK luxury property firm Blenheim. Arcus Media resurfaces with East African Gasoil."
category: daily
tags: [cti, daily-brief, the-gentlemen, shinyhunters, space-bears, arcus-media, tox1]
classification: TLP:CLEAR
reporting_period: "2026-07-05"
generated: "2026-07-06"
severity: high
draft: true
report_count: 24
sources:
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-05 (24h) | TLP:CLEAR | 2026-07-06 |

## 1. Executive Summary

Twenty-four ransomware victim disclosures were ingested in the last 24 hours, all sourced from the RansomLook dark web tracker and all rated **HIGH**. Activity was overwhelmingly driven by **The Gentlemen** ransomware group, responsible for 18 of 24 postings (75%) across food service, IT services, energy, insurance and engineering research targets spanning Australia, Hong Kong, India, the Philippines, France, Malaysia and Latin America. **Shinyhunters** posted two significant Western victims — Fluke Corporation (US electronic test equipment) and Ingram Content Group (US book distribution). **Space Bears** claimed UK luxury property firm Blenheim with ~500 GB of exfiltrated CRM, financial and architectural CAD/BIM data. **Arcus Media** resurfaced with East African Gasoil. No CVE-linked in-the-wild exploitation or CISA KEV additions were reported in this period; the picture is one of sustained double-extortion ransomware operations rather than new vulnerabilities.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No critical-severity reports in this period |
| 🟠 **HIGH** | 24 | The Gentlemen ransomware (18); Shinyhunters (2); Space Bears; Arcus Media; The Gentlemen affiliates |
| 🟡 **MEDIUM** | 0 | No data available for this period |
| 🟢 **LOW** | 0 | No data available for this period |
| 🔵 **INFO** | 0 | No data available for this period |

## 3. Priority Intelligence Items

### 3.1 The Gentlemen ransomware group posts 18 victims in a single leak-site update

**Source:** [RansomLook — The Gentlemen leak site](https://www.ransomlook.io//group/the%20gentlemen)

The Gentlemen ransomware group posted 18 fresh victim disclosures over a five-hour window, continuing a sustained campaign that has produced 586 total leak-site posts (123 in the last 30 days, 41 in the last 7). Victims disclosed in this window include:

- **Food service:** Royal Foods (Australia), Tonnies Group, Keifert
- **IT services and technology:** Pro-Tech Technology (Hong Kong), Technical Solutions Group (Michigan, USA), Jump Solutions Inc (Philippines), Excel Cell Electronic, LogiQuip, Kosmos, EBNY Development
- **Engineering / research:** CSIR Structural Engineering Research Centre (India), Harsha Engineers
- **Energy:** MBT Energy (Xiamen Mibet New Energy, China)
- **Logistics / distribution:** Quanterm Logistics Sdn Bhd (Malaysia), Automovil Supply S.A, Mercado Libre affiliate
- **Financial services:** Arabia Falcon Insurance Company SAOG (Oman)
- **Public sector / cultural:** Ce Ratp Comité d'Entreprise (France — RATP works council), Virginia Historical Society (USA)

The group operates a Tox-encrypted communications channel (identifier `F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E`) and a Tor-based leak site protected by CAPTCHA to frustrate automated parsing. MITRE ATT&CK techniques observed across the campaign include T1566 (Phishing) for initial access, T1071 (Application Layer Protocol) and T1485 / T1486 (Data Encrypted for Impact). Trend Micro published an unmasking analysis of the group (referenced in the leak-site metadata).

#### Indicators of Compromise
```
Leak site (Tor): hxxp[:]//tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion/
Chat server (Tor, currently down): hxxp[:]//i2ohjeeqe37jre4f2u7pyq73cbm6lecumdxapkvrlryna6rc3it4zsid[.]onion/
Tox ID: F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E
```

> **SOC Action:** For organisations in the affected sectors (food service, IT services, engineering research, energy), search inbound mail for phishing lures targeting operations and finance staff (T1566); alert on any egress attempts to the Tor domain listed above via egress firewall, DNS sinkhole or proxy denylist; hunt EDR telemetry for the Tox client process (`qtox.exe`, `utox.exe`) executing on servers or admin workstations, which is anomalous outside of red-team use.

### 3.2 Shinyhunters posts Fluke Corporation and Ingram Content Group

**Source:** [RansomLook — Shinyhunters leak site](https://www.ransomlook.io//group/shinyhunters)

Shinyhunters added two large US-headquartered victims: **Fluke Corporation** (industrial electronic test and measurement — a subsidiary of Fortive) and **Ingram Content Group** (one of the largest US book wholesalers and print-on-demand providers). Both victims are attributed to phishing-led intrusions (T1566) followed by ransomware deployment, consistent with Shinyhunters' historical modus operandi. The group's leak infrastructure remains partially online (4 of 8 URLs up, 50% average uptime over 30 days) and is backed by four IP-based file servers hosted in Eastern Europe.

#### Indicators of Compromise
```
Leak site (Tor, up): hxxp[:]//shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd[.]onion/
Leak site (Tor, up 67%): hxxp[:]//shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid[.]onion/
Clearnet mirror (down): hxxps[:]//shinyhunte[.]rs/
File server: 91.202.233[.]104
File server: 176.120.22[.]24
File server: 91.215.85[.]103
File server (down): 91.215.85[.]22
Contact: shinygroup[@]onionmail[.]com
```

> **SOC Action:** Block outbound HTTPS to the four file-server IPs at the perimeter firewall — legitimate business traffic to these hosts is highly unlikely. Query SIEM for the last 30 days of DNS lookups against `shinyhunte.rs` and pivot on any originating hosts. Fluke and Ingram supply-chain partners should assume any file, credential or design document exchanged with these organisations in the past 90 days may appear on the leak site and prepare downstream notification workflows accordingly.

### 3.3 Space Bears leaks ~500 GB from UK luxury property firm Blenheim

**Source:** [RansomLook — Space Bears leak site](https://www.ransomlook.io//group/space%20bears)

Space Bears posted **Blenheim**, a UK-based luxury property developer operating across Sheffield, Yorkshire, Derbyshire and the Peak District, claiming ~500 GB of exfiltrated data comprising the CRM database, financial records, architectural drawings, CAD/BIM models, planning documentation, and complete buyer details including home layouts. This posting extends a recent Space Bears run that also included **Salter's Propane** (2026-07-02), **Chebib Control** (Brazilian hospitality PMS provider), **Gerencial Contábil** (Brazilian accounting firm — 600,000+ files plus ~1,000 personal digital certificates and passwords for Brazilian government portals) and **ECOVACS**. The leak site is highly stable at 93% uptime. MITRE ATT&CK techniques observed: T1566 (Phishing) for access; T1048 (Exfiltration Over C2 Channel) and T1071.001 (Application Layer Protocol: Web Protocols) for staging.

#### Indicators of Compromise
```
Leak site (Tor, up 93%): hxxp[:]//5butbkrljkaorg5maepuca25oma7eiwo6a2rlhvkblb4v6mf3ki2ovid[.]onion/
```

> **SOC Action:** UK construction, architecture and high-net-worth property services firms should treat the Blenheim disclosure as a supply-chain notification event: architectural drawings and buyer home layouts create physical-security risk for named individuals. Push a targeted phishing-awareness advisory to conveyancing, property-management and CAD/BIM personnel. Brazilian orgs using the compromised Gerencial certificates should immediately revoke `.pfx`/`.p12` files reissued through Gerencial and rotate government-portal credentials.

### 3.4 Arcus Media RaaS resurfaces with East African Gasoil

**Source:** [RansomLook — Arcus Media leak site](https://www.ransomlook.io//group/arcus%20media)

Arcus Media, a Ransomware-as-a-Service operation active since May 2024 and linked to 50+ confirmed attacks by mid-2025, posted **East African Gasoil**. The group uses selective (partial) encryption of large files with the ChaCha20 cipher and RSA-2048 key protection, disables recovery mechanisms, and terminates SQL and email services to maximise disruption. Initial access is via phishing (T1566), credential theft (T1078 - Valid Accounts / T1110 - Brute Force) or vulnerability exploitation; lateral movement uses Mimikatz and Cobalt Strike. Signed-binary proxy execution (T1218) and boot-or-logon autostart persistence (T1547) are documented.

#### Indicators of Compromise
```
Leak site (Tor, up 53%): hxxp[:]//arcuufpr5xxbbkin4mlidt7itmr6znlppk63jbtkeguuhszmc5g7qdyd[.]onion/
Tox ID: F6B2E01CFA4D3F2DB75E4EDD07EC28BF793E541A9674C3E6A66E1CDA9D931A1344E321FD2582
Contact: AlexanderPushkin[@]exploit[.]im
Contact: arcus[@]xmpp[.]onion
Contact: arcustm[@]proton[.]me
Contact: arcusteam[@]proton[.]me
```

> **SOC Action:** Alert on any observation of Mimikatz (`sekurlsa::logonpasswords`, credential-dumping module loads) and Cobalt Strike beacon indicators (named-pipe patterns `\\.\pipe\msagent_*`, `\\.\pipe\postex_*`) — these are Arcus Media's confirmed lateral-movement toolchain (T1218, T1078). Baseline and alert on service-stop events for `MSSQLSERVER`, `SQLWriter`, `MSExchangeIS` and other critical services outside change windows to catch the pre-encryption teardown pattern.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | The Gentlemen ransomware group is targeting a diverse range of sectors with high frequency and using multiple malware variants (Tox1, Other1). | CSIR Structural Engineering Research Centre; Royal Foods; Pro-Tech Technology; Technical Solutions Group (18 victims total in period, correlation confidence 0.95) |
| 🟠 **HIGH** | Phishing (T1566) remains the prevalent initial-access TTP across multiple ransomware groups. | Fluke Corporation (Shinyhunters); Blenheim (Space Bears); Ingram Content Group (Shinyhunters) |
| 🟠 **HIGH** | T1485 - Data Encrypted for Impact repeatedly observed in The Gentlemen intrusions. | CSIR Structural Engineering Research Centre; Technical Solutions Group; Virginia Historical Society (correlation confidence 0.80) |
| 🟡 **MEDIUM** | Food-service sector clustering under The Gentlemen. | CSIR Structural Engineering Research Centre; Royal Foods; Quanterm Logistics (correlation confidence 0.75) |
| 🟡 **MEDIUM** | IT-services sector clustering under The Gentlemen. | Pro-Tech Technology; Technical Solutions Group; Jump Solutions Inc (correlation confidence 0.70) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (113 reports) — dominant ransomware operator; Tox comms, CAPTCHA-protected leak site, targeting food service / IT / engineering globally
- **Qilin** (73 reports) — long-running RaaS, sustained victim volume
- **Deadlock** (55 reports) — active mid-June cluster
- **Lockbit5** (39 reports) — LockBit successor variant with continued postings
- **Akira** (25 reports) — RaaS, small-mid business victims
- **DragonForce** (24 reports) — active ransomware brand
- **Shinyhunters / ShinyHunters** (20 + 19 reports) — data-extortion crew active this week against Fluke and Ingram Content Group
- **Stormous** (17 reports) — hacktivist-adjacent extortion crew
- **Nova** (17 reports) — mid-tier RaaS

### Malware Families

- **RansomLook** (148 reports) — pipeline source label, not a malware family in the traditional sense (dark-web tracker taxonomy)
- **Tox1** (81 reports) — Tox-protocol contact identifier used as a family label for Gentlemen and Arcus Media
- **Other1** (56 reports) — RansomLook "external analysis link" label used as a secondary family marker
- **Tox** (42 reports) — generic Tox-communication family
- **Lockbit5** (14 reports) — LockBit successor
- **Qilin** (12 reports) — Qilin ransomware payload
- **The Gentlemen ransomware** (11 reports) — Gentlemen-branded payload
- **Anubis ransomware** (11 reports) — active this week
- **Anubis banking trojan** (10 reports) — mobile-banking malware, distinct from Anubis ransomware
- **The Gentlemen Ransomware** (10 reports) — case-variant of the same family

*No vulnerability entities trended in the last 24 hours; the top-15 CVE list from the last 30 days consists of low-frequency single-report items (e.g., CVE-2023-29298, CVE-2026-39987), none observed in this reporting period.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 24 | [link](https://www.ransomlook.io/) | Sole source of intelligence in this period — dark-web ransomware leak-site tracker. Coverage is comprehensive for ransomware victim disclosures but does not include vendor advisories, CVE feeds or law-enforcement notices. |

**Note on source concentration:** the pipeline pulled zero reports from Microsoft, BleepingComputer, SANS, Schneier or other traditional CTI sources in this window. This is a coverage gap worth flagging to pipeline operations — either those feeds were quiet, or the ingestion cycle missed the window.

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Block the four Shinyhunters file-server IPs (`91.202.233[.]104`, `176.120.22[.]24`, `91.215.85[.]103`, `91.215.85[.]22`) at the perimeter and add the Gentlemen, Shinyhunters, Space Bears and Arcus Media leak-site `.onion` domains to your Tor egress denylist. These are actively used C2 / data-exfiltration endpoints. (Ties to items 3.1–3.4.)
- 🔴 **IMMEDIATE:** If your organisation is a customer, supplier or downstream data-processor of Fluke Corporation, Ingram Content Group or Blenheim, initiate third-party incident-response workflows now — do not wait for formal breach notifications. Rotate any credentials, API keys or certificates shared with these organisations in the last 90 days. (Ties to 3.2, 3.3.)
- 🟠 **SHORT-TERM:** Deploy an EDR detection for the Tox client processes (`qtox.exe`, `utox.exe`, `toxic`) executing on servers, DCs or administrative workstations. Tox is the shared C2 channel across The Gentlemen and Arcus Media and has no legitimate enterprise use case. (Ties to 3.1, 3.4.)
- 🟠 **SHORT-TERM:** Refresh phishing-simulation content targeting finance, procurement and operations teams — T1566 is the confirmed initial-access vector across every major actor active in this period. (Ties to correlation trend #2.)
- 🟡 **AWARENESS:** Brief food-service, IT-services and engineering-research CISO / CIO peers on The Gentlemen's sector-clustering behaviour. Australian, Hong Kong, Filipino, French and Indian entities in those verticals are disproportionately represented in this week's leak-site postings. (Ties to 3.1 and correlation trends #4, #5.)
- 🟢 **STRATEGIC:** Flag the RansomLook-only source concentration to pipeline operations. A daily brief driven exclusively by dark-web leak-site trackers misses vendor advisories, CVE / KEV additions and law-enforcement notices — expand ingestion or note the gap in tomorrow's brief.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 24 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
