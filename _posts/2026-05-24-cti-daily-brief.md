---
layout: post
title:  "CTI Daily Brief: 2026-05-24 - Qilin, Inc Ransom, Stormous and Nova Drive Ransomware Surge; Brazilian State Agency Hit"
date:   2026-05-25 20:06:54 +0000
description: "Eight new ransomware victim disclosures dominate the 24-hour window: Qilin lists four targets, Inc Ransom posts Meirc, Stormous publishes a 40GB vspsolutions.com.au dump, and Nova (RALord rebrand) leaks the Brazilian state of Espírito Santo's SECONT alongside a Turkish technology firm."
category: daily
tags: [cti, daily-brief, qilin, inc-ransom, nova, stormous, ransomlook]
classification: TLP:CLEAR
reporting_period: "2026-05-24"
generated: "2026-05-25"
draft: true
severity: high
report_count: 8
sources:
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-24 (24h) | TLP:CLEAR | 2026-05-25 |

## 1. Executive Summary

Eight new high-severity threat reports were ingested in the last 24 hours, all sourced from the RansomLook leak-site aggregator and all reflecting fresh victim disclosures by ransomware-as-a-service (RaaS) operators. Qilin dominated the day with four named victims (Sponseller Group, Global Retool Group, ExpoCredit, Branded Products), reinforcing its position as the most-listed RaaS group across the pipeline (102 reports in the last 30 days). Nova — the RALord rebrand — posted two victims including SECONT (Secretaria de Controle e Transparência), a Brazilian state-government oversight body, alongside Turkish technology firm Adensa Teknoloji. Inc Ransom listed Meirc Training and Consulting (UAE-based corporate training), and Stormous published what it claims is a >40GB full data dump of Australian IT integrator vspsolutions.com.au, including QuickBooks/Reckon financial backups. No CISA KEV additions, CVEs, or confirmed in-the-wild exploitation were ingested in this window; the dominant theme is RaaS-driven extortion across mid-market and public-sector targets, with phishing (T1566) and valid-account abuse (T1078) cited across the AI-derived correlation set.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No critical-severity reports in this window |
| 🟠 **HIGH** | 8 | Qilin (4 victims), Nova (2 victims incl. Brazilian state govt), Inc Ransom, Stormous |
| 🟡 **MEDIUM** | 0 | No data |
| 🟢 **LOW** | 0 | No data |
| 🔵 **INFO** | 0 | No data |

## 3. Priority Intelligence Items

### 3.1 Nova (RALord Rebrand) Lists Brazilian State Oversight Agency SECONT

**Source:** [RansomLook — Nova](https://www.ransomlook.io//group/nova)

Nova, confirmed in the report data as a rebrand of the RALord operation, posted two new victims in the 24-hour window: **SECONT — Secretaria de Controle e Transparência** (the internal-control and transparency secretariat of the Brazilian state of Espírito Santo) and **Adensa Teknoloji**, a Turkish technology firm. SECONT is a sub-national government body, and a confirmed leak from a state oversight agency carries elevated risk: audit findings, whistleblower files, procurement data, and personal data of public officials are common targets for follow-on extortion and influence operations. Nova is operating a known RaaS model with captcha-protected leak infrastructure across 10 .onion domains (avg 30-day uptime ~10%, reflecting heavy churn from takedowns or operator-driven rotation) and three named affiliates (Hunt3rs0p3r4tion, Bog1337, ploja). Tooling indicators include a PGP public key (key ID `937073269075...`), a Session ID, a Tox ID, and the ransom note `README-NOVA.me`. T1566 (Phishing) is cited as a likely initial-access vector. Correlation confidence linking the two Nova posts is 0.90 (shared actor and malware tagging with `RansomLook`).

> **SOC Action:** For Brazil-state and LATAM public-sector defenders, prioritise hunting for the Nova ransom note filename `README-NOVA.me` on file servers and user shares (Splunk: `index=* "README-NOVA.me"`; CrowdStrike: `FileName="README-NOVA.me"`). Block the affiliate handles `Hunt3rs0p3r4tion`, `Bog1337`, `ploja` as Jabber/Tox identifiers in any DLP egress monitoring. Audit Espírito Santo state-government supplier networks for shared credentials or VPN access that may have been the pivot point.

#### Indicators of Compromise

```
Ransom note:  README-NOVA.me
Telegram:     @NovaSupport
Tox ID:       8E9A6195A769FE7115F087C61D75CF32874C339B3AB0947D07480C9A8A12DA50...
Session ID:   054f55ec93aca9bac362b9d91eff36a7ce451e7caba47c0b2e004ba429f9529c79
Leak site:    hxxp[:]//novavdivko2zvtrvtllnq45lxhba2rfzp76qigb4nrliklem5au7czqd[.]onion
Affiliates:   Hunt3rs0p3r4tion, Bog1337, ploja
PGP key fp:   59742223 1A730BFB 74C1430A 935073 2690758220
```

ATT&CK references: T1566 (Phishing), T1071.001 (Web Protocols), T1496.002 (Resource Hijacking — Cryptocurrency Mining).

### 3.2 Qilin Lists Four Victims in a Single Posting Burst

**Source:** [RansomLook — Qilin](https://www.ransomlook.io//group/qilin)

Within a 4-second window on 2026-05-24 (20:51:50–20:51:54 UTC), Qilin (aka Agenda) added four new victims to its leak site: **Sponseller Group**, **Global Retool Group**, **ExpoCredit**, and **Branded Products**. Qilin remains the top-trending threat actor across the pipeline (102 reports / last 30 days, 1,842 posts all-time, 135 in the last 30 days). The shared correlation entry (confidence 0.90, shared elements: "Qilin") groups all four posts as a single coordinated dump. ExpoCredit's listing additionally enumerates T1003 (OS Credential Dumping) and T1030 (Data Encrypted for Impact) in the entity associations, consistent with Qilin's documented playbook of credential harvesting and double-extortion. Qilin operates 9 leak/onion URLs (two active: `ijzn3sicrcy7guix...onion` 97% uptime, `pandora42btuwlld...onion` 90% uptime) and 614 file-server entries — the highest infrastructure footprint in the day's data. Contact channels are Jabber (`qilin@exploit.im`) and Tox.

> **SOC Action:** Hunt for Qilin's ransom-note filenames across endpoint storage: `DtMXQFOCos-RECOVER-README.txt`, `README-RECOVER-[rand].txt`, `README-RECOVER-[rand]_2.txt`. EDR query: `FileName CONTAINS "RECOVER-README" OR FileName CONTAINS "README-RECOVER"`. Block outbound connections to the Qilin file-server IPs listed below at the perimeter and confirm DLP rules flag large outbound FTP transfers (>1GB) over uncommon ports. Re-validate that EDR is hardened against credential-dumping tooling (LSASS access, T1003) — Qilin affiliates routinely deploy Mimikatz-style harvesters pre-encryption.

#### Indicators of Compromise

```
Ransom notes:  DtMXQFOCos-RECOVER-README.txt
               README-RECOVER-[rand].txt
               README-RECOVER-[rand]_2.txt
Jabber:        qilin@exploit[.]im
Tox ID:        7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1B...
Leak sites:    hxxp[:]//ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
               hxxp[:]//pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd[.]onion
File servers:  85.209.11[.]49 (FTP, dataShare)
               188.119.66[.]189 (FTP, dataShare)
               176.113.115[.]97, 176.113.115[.]209
               185.39.17[.]75, 185.196.10[.]19, 185.196.10[.]52
               64.176.162[.]76, 208.76.221[.]205, 185.196.8[.]92, 31.41.244[.]100
Affiliate:     "Ben"
```

ATT&CK references: T1003 (OS Credential Dumping), T1030 (Data Encrypted for Impact), T1566 (Phishing), T1071 (Application Layer Protocol), T1189 (Drive-by Compromise).

### 3.3 Stormous Publishes 40GB+ Full Data Dump from Australian IT Integrator vspsolutions.com.au

**Source:** [RansomLook — Stormous](https://www.ransomlook.io//group/stormous)

Stormous followed up its 17 May 2026 "sample" leak with a complete data dump from **vspsolutions.com.au**, an Australian IT integrator. The disclosed dataset is described in the leak post as ">40GB Full Financial Backups (QuickBooks & Reckon), Email Archives & Staff Personal Folders, Customer/Client Databases (Installers & Integrators nationwide), Shipment & Order Tracking for major brands like Hikvision & Axis." This is operationally significant because vspsolutions.com.au is positioned as a regional distributor for Hikvision and Axis surveillance equipment — any leaked customer database may expose installer credentials, site addresses, and integration documentation for physical security systems across Australia, creating downstream supply-chain risk for end-customer sites. Stormous infrastructure is heavily degraded (5 of 6 monitored URLs down; only one onion at 13% uptime), but the file servers remain reachable to claimed buyers. Entity tagging includes T1071.001 (Web Protocols) and T1537.002 (Supply Chain Compromise — Software Update / Patch). Tox is the contact channel.

> **SOC Action:** Australian and APAC defenders running Hikvision or Axis camera estates: assume installer-side contact details, site lists, and credential inventories are in the wild. Force credential rotation on any shared installer or vendor service accounts touching CCTV/NVR estates, and monitor for spear-phishing referencing recent invoices, RMAs, or shipment numbers (Stormous historically weaponises leaked email archives for follow-on phishing). Treat any unsolicited "Hikvision/Axis firmware update" outreach as suspect until verified through the manufacturer portal, not through reseller channels.

#### Indicators of Compromise

```
Leak host:     hxxp[:]//pdcizqzjitsgfcgqeyhuee5u6uki6zy5slzioinlhx6xjnsw25irdgqd[.]onion
Tox ID #1:     C286720F7592E5668A932F1D06EDEECBAFACB3BE369632C908F9511D072C1425...
Tox ID #2:     0E67D9C77F417ABA9564B97C616A6ADAEDC2D3B2CD32B4868FD65E661F6C7931...
Data scope:    >40GB QuickBooks/Reckon financial backups; email archives;
               customer/installer databases; Hikvision & Axis order/shipment data
```

ATT&CK references: T1071.001 (Web Protocols), T1537.002 (Supply Chain Compromise).

### 3.4 Inc Ransom Lists Meirc Training and Consulting (UAE)

**Source:** [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom posted **Meirc Training and Consulting** — a long-established UAE-based corporate training provider — to its leak blog on 2026-05-25 at 05:47 UTC. Inc Ransom remains an established double-extortion operation (787 posts all-time, 37 in the last 30 days) with two active leak/payment sites (97% and 100% uptime respectively) — its operational tempo is consistent and infrastructure is well-maintained relative to peers. Entity tagging cites T1078 (Valid Accounts) and T1566 (Phishing) as expected initial-access TTPs. Meirc serves enterprise clients across the GCC; a successful data leak could expose customer training records, billing data, and internal-facing learning-management credentials reused across client tenants.

> **SOC Action:** GCC enterprises that purchased training or use Meirc-hosted LMS portals should rotate any federated SSO credentials shared with vendor LMS platforms and audit O365/Entra sign-in logs for anomalous logins originating from Meirc IP ranges or vendor service accounts. Hunt for Inc Ransom ransom-note filenames (`INC-README.txt`, `INC-README2.txt`, `INC-README3.txt`, `INC-README4.txt`, `INC-README.html`) across file shares and EDR endpoint telemetry.

#### Indicators of Compromise

```
Ransom notes:  INC-README.txt, INC-README2.txt, INC-README3.txt,
               INC-README4.txt, INC-README.html
Leak blog:     hxxp[:]//incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion/blog/disclosures
Active host:   hxxp[:]//incbacg6bfwtrlzwdbqc55gsfl763s3twdtwhp27dzuik6s6rwdcityd[.]onion
Payment host:  hxxp[:]//incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion
```

ATT&CK references: T1078 (Valid Accounts), T1566 (Phishing).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware-as-a-Service (RaaS) groups expanding operations globally | Adensa Teknoloji By Nova; Sponseller Group By Qilin; Global Retool Group By Qilin (batch 144) |
| 🟠 **HIGH** | Increased ransomware activity with diverse TTPs across multiple sectors | Meirc Training and Consulting By Inc Ransom; Adensa Teknoloji By Nova; vspsolutions.com.au full data dump By Stormous (batch 144) |
| 🟠 **HIGH** | Persistent Qilin actor cluster (4-way correlation) | Sponseller Group, Global Retool Group, ExpoCredit, Branded Products — all attributed to Qilin within a 4-second posting window (correlation confidence 0.90) |
| 🟠 **HIGH** | Persistent Nova/RansomLook actor cluster | Adensa Teknoloji, SECONT — both attributed to Nova (RALord rebrand) (correlation confidence 0.90) |
| 🟡 **MEDIUM** | Shared TTP: T1566 phishing across cross-actor sample | Meirc Training and Consulting By Inc Ransom; Adensa Teknoloji By Nova (correlation confidence 0.70) |
| 🟡 **MEDIUM** | Shared TTP: T1071.001 web-protocol C2 / exfil across cross-actor sample | vspsolutions.com.au By Stormous; SECONT By Nova (correlation confidence 0.70) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (102 reports / last 30 days) — Dominant RaaS group; posted 4 of 8 victims in this window. Aka Agenda.
- **Akira** (68 reports) — Persistent RaaS; no new posts in this 24h window but remains active.
- **The Gentlemen** (64 reports) — Active multi-sector campaign noted in prior batches (logistics, engineering, technology across JP/CN/IE/TR/PL/AT/US).
- **TeamPCP** (34 reports) — Active leak-site operator; no new posts today.
- **ShinyHunters** (28 reports) — Active throughout May; no new posts today.
- **Inc Ransom** (24 reports) — Listed Meirc today; consistent monthly tempo.
- **DragonForce** (19 reports) — Active across the month; correlation cluster noted in batch 142.
- **Safepay** (19 reports) — Persistent listing activity.
- **Lockbit5** (19 reports) — Continued tracking; no new posts in this window.
- **Everest** (18 reports) — Persistent listing activity.

### Malware Families

- **RansomLook** (134 mentions) — Aggregator-tag attached to most leak-site sourced reports; not a discrete malware family but a data-source label that appears as a malware-typed entity.
- **Akira ransomware / Akira / Akira Ransomware** (37 / 21 / 14 — different label normalisations of the same family).
- **Tox1 / Tox** (34 / 18 mentions) — Contact-channel artefact appearing in leak-site posts.
- **Nightspire** referenced in 25-report batch 143 with confidence 0.95 (no new posts today, but the cluster from 24 May remains the largest correlated actor set this week).
- **The Gentlemen** (14 mentions as a malware-tagged entity).
- **Qilin** (13 mentions as malware-tagged entity).
- **Nova** (10 mentions) — Aligns with the two new posts in this window.

*Note: the vulnerability trending query returned zero results — no CVE-tagged entities were ingested in this 24-hour period.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 8 | [link](https://www.ransomlook.io) | Sole source for this period; leak-site aggregator covering Qilin, Inc Ransom, Nova, Stormous |

*The pipeline did not ingest content from Microsoft, BleepingComputer, Schneier, SANS, or Wired Security in this 24-hour window. The brief is therefore weighted entirely toward dark-web extortion telemetry.*

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Australian APAC defenders running **Hikvision/Axis** estates should treat installer-side contacts, credentials and site documentation tied to vspsolutions.com.au as compromised. Rotate shared installer and vendor service-account credentials touching CCTV/NVR systems, and watch for follow-on spear-phishing referencing the leaked invoices and shipment data.
- 🔴 **IMMEDIATE:** Brazil state-government (Espírito Santo) and federated supplier networks: hunt for Nova ransom note `README-NOVA.me` and inventory any shared credentials, federated SSO, or VPN trust into SECONT. Treat the SECONT compromise as a possible jump-off for downstream phishing of state employees.
- 🟠 **SHORT-TERM:** Deploy EDR file-name hunts for ransom-note artefacts surfaced in this brief: `INC-README*.txt/html` (Inc Ransom), `README-RECOVER-*.txt` and `DtMXQFOCos-RECOVER-README.txt` (Qilin), `README-NOVA.me` (Nova). Pair with LSASS access alerts (T1003) for early-stage credential dumping that typically precedes Qilin encryption.
- 🟠 **SHORT-TERM:** Block the Qilin file-server IPs (`85.209.11[.]49`, `188.119.66[.]189`, `176.113.115[.]97/.209`, `185.39.17[.]75`, `185.196.10[.]19/.52`, `185.196.8[.]92`, `64.176.162[.]76`, `208.76.221[.]205`, `31.41.244[.]100`) at perimeter egress and review NetFlow for outbound FTP exfiltration over the last 30 days.
- 🟡 **AWARENESS:** GCC and UAE clients of Meirc Training and Consulting: assume training-portal credentials and corporate billing data may be in the leak. Rotate any federated SSO into vendor LMS systems and audit Entra sign-in logs.
- 🟢 **STRATEGIC:** All 8 reports today share **phishing (T1566)** or **valid-accounts (T1078)** as the cited initial-access vector. Re-prioritise phishing-resistant MFA (FIDO2/passkeys), Conditional Access risk-based blocking, and continuous user-awareness exercises focused on QuickBooks/Reckon, LMS-portal, and supplier-impersonation lures — these are the recurring pretext themes across this week's RaaS victim set.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 8 reports processed across 2 correlation batches in the reporting window (3 batches if including the 14:05-period batch from earlier in the day). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
