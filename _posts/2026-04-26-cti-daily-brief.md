---
layout: post
title:  "CTI Daily Brief: 2026-04-26 - ShinyHunters Leak 1.4M Udemy Accounts; Qilin, Inc Ransom and Tridentlocker Post New Victims"
date:   2026-04-27 20:15:00 +0000
description: "Eight high-severity reports dominated by ransomware leak-site activity from Qilin, Inc Ransom, Tridentlocker and Payload, alongside a ShinyHunters extortion of Udemy exposing 1.4 million accounts and republished Microsoft advisories for OpenSSL timing-attack CVEs."
category: daily
tags: [cti, daily-brief, qilin, inc-ransom, shinyhunters, ransomlook, tridentlocker, udemy]
classification: TLP:CLEAR
reporting_period: "2026-04-26"
generated: "2026-04-27"
draft: true
severity: high
report_count: 8
sources:
  - RansomLock
  - Microsoft
  - HaveIBeenPwned
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-26 (24h) | TLP:CLEAR | 2026-04-27 |

## 1. Executive Summary

The pipeline ingested 8 high-severity reports from 3 sources in the last 24 hours, with ransomware leak-site activity accounting for five of the eight items. Qilin (Inspira), Inc Ransom (reddycardiology.com, MTCI), Tridentlocker (RT Software) and the "Payload" group (Rural Municipality of Gimli, Manitoba) all posted fresh victims, and the AI correlation layer flagged "increased ransomware activity targeting multiple sectors with overlapping TTPs" as the dominant high-risk trend. The most consequential single incident is a ShinyHunters "pay-or-leak" extortion against online-training platform Udemy that exposed 1,401,259 unique email addresses along with names, phone numbers, employer information and instructor payout details. Microsoft republished two long-standing OpenSSL timing-attack advisories (CVE-2018-0734 DSA, CVE-2018-0735 ECDSA), which are informational in nature rather than evidence of new exploitation. No CISA KEV additions and no confirmed in-the-wild exploitation events were captured in this period; healthcare, legal services and local government remain the most-targeted sectors per the correlation batch.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None in 24h window |
| 🟠 **HIGH** | 8 | Ransomware leak-site posts (Qilin, Inc Ransom, Tridentlocker, Payload), ShinyHunters/Udemy 1.4M breach, Microsoft OpenSSL DSA/ECDSA timing-attack advisories |
| 🟡 **MEDIUM** | 0 | — |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 0 | — |

## 3. Priority Intelligence Items

### 3.1 ShinyHunters "Pay-or-Leak" Extortion Exposes 1.4M Udemy Accounts

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/Udemy)

In April 2026, online-training company Udemy was the victim of a "pay-or-leak" extortion attempt by the ShinyHunters group; after the demand was refused the data was leaked publicly. The dump contains 1,401,259 unique email addresses belonging to customers and instructors, along with names, physical addresses, phone numbers, job titles, employer information and instructor payout methods (PayPal, cheque and bank transfer). HaveIBeenPwned added the breach to its index on 26 April 2026. ShinyHunters is the same actor cluster previously linked to Snowflake-tenant data theft and large-scale third-party SaaS extortion; phishing (T1566) is the primary credential-acquisition pattern attributed in the entity data.

**Affected:** Udemy customers and instructors globally; downstream phishing risk for any organisation listed in the leaked employer field.

#### Indicators of Compromise

```
Threat actor: ShinyHunters
Breach scope: 1,401,259 unique email addresses + names, addresses, phone numbers, employers, payout methods
Date added to HIBP: 2026-04-26
Source URL: hxxps[:]//haveibeenpwned[.]com/Breach/Udemy
```

> **SOC Action:** Pull the HIBP domain-search export for any company-owned domain and force-rotate credentials for matched users; tune email gateway rules to flag inbound mail referencing "Udemy course refund", "instructor payout" or "Udemy account verification" for the next 30 days, as ShinyHunters dumps are routinely weaponised into commodity phishing kits within weeks (T1566).

### 3.2 Qilin RaaS Posts Inspira; Infrastructure Telemetry Refreshed

**Source:** [RansomLook — Qilin](https://www.ransomlook.io//group/qilin)

The RansomLook crawler captured a fresh Qilin (aka Agenda) leak-site post against an organisation listed as "Inspira" on 27 April at 08:55 UTC. The actor profile shows 1,726 lifetime posts, 104 in the last 30 days and 52 in the last 7 days, sustaining Qilin's position as the pipeline's top-trending threat actor (68 reports across the last 30 days). The RansomLook export refreshed the public infrastructure list — multiple onion mirrors plus an HTTPS portal at 31.41.244[.]100 and a wikileaksv2 imitation domain — and confirmed the operator's Tox and Jabber contact identifiers. Qilin's tradecraft per OpenCTI entity links remains valid-account abuse (T1078), RDP lateral movement (T1081) and data-encrypted-for-impact (T1530).

**Affected:** Cross-sector; Qilin has hit healthcare, legal, manufacturing and engineering targets in prior cycles.

#### Indicators of Compromise

```
Onion (active):     ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
Onion (active):     pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd[.]onion
File-server onion:  kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion
Imitation site:     hxxps[:]//wikileaksv2[.]com
Public IP portal:   31.41.244[.]100
File-server IPs:    85.209.11[.]49, 188.119.66[.]189, 176.113.115[.]97,
                    176.113.115[.]209, 185.39.17[.]75, 185.196.10[.]52,
                    185.196.10[.]19, 64.176.162[.]76, 208.76.221[.]205,
                    185.196.8[.]92
Tox ID:             7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
Jabber:             qilin@exploit[.]im
Ransom note:        README-RECOVER-[rand].txt
```

> **SOC Action:** Block egress to the Qilin onion gateways and the listed file-server IPs at the proxy/firewall, then run an EDR sweep for the file pattern `README-RECOVER-*.txt` written to `C:\Users\*\Desktop` or any network share root within the last 14 days (T1486/T1530). Cross-reference any matched host against RDP authentication logs for first-seen external IPs (T1078, T1081).

### 3.3 Inc Ransom Lists reddycardiology.com and MTCI on Leak Site

**Source:** [RansomLook — Inc Ransom (reddycardiology.com)](https://www.ransomlook.io//group/inc%20ransom), [RansomLook — Inc Ransom (MTCI)](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom posted two new victims in the 24-hour window: a US cardiology practice (reddycardiology.com) at 00:56 UTC on 27 April and an organisation tracked as "MTCI" the previous evening. The crawler shows 752 lifetime posts and 9 in the last 7 days, with active leak and chat infrastructure on `incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion` and `incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion`. The correlation engine flagged Inc Ransom's continued bias toward healthcare, legal services and small US municipalities (recent victims include morgancountyga[.]gov, treelawoffice[.]com and multiple US injury-law firms). MITRE techniques recorded on the entity edges: T1485/T1486 data-encrypted-for-impact, T1566 phishing, T1590 command-and-control reconnaissance.

**Affected:** US healthcare (cardiology) and an unnamed organisation tracked as MTCI; secondary risk to law-firm and US local-government supply chains.

#### Indicators of Compromise

```
Leak site (active):  incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion
Chat (active):       incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion
Inactive mirrors:    incblog7vmuq7rktic73r4ha4j757m3ptym37tyvifzp2roedyyzzxid[.]onion,
                     incapt[.]blog, incapt[.]su, incbackend[.]top
Ransom notes:        INC-README.txt / INC-README2.txt / INC-README3.txt /
                     INC-README4.txt / INC-README.html
```

> **SOC Action:** For healthcare and legal-services clients, run a 30-day retro hunt for `INC-README*.txt` or `INC-README*.html` written to file servers and user profile directories, and block the active Inc Ransom onion endpoints at the egress proxy. If a hit is found, treat as a confirmed breach and engage IR — Inc Ransom historically begins exfil 7–14 days before posting (T1486, T1590).

### 3.4 Tridentlocker Adds RT Software; Payload Group Lists Rural Municipality of Gimli (Canada)

**Source:** [RansomLook — Tridentlocker](https://www.ransomlook.io//group/tridentlocker), [RansomLook — Payload](https://www.ransomlook.io//group/payload)

Two lower-volume Russian-speaking ransomware brands added victims in the same window. Tridentlocker (16 lifetime posts, 93% leak-site uptime) listed "RT Software", with a single active onion at `tridentfrdy6jydwywfx4vx422vnto7pktao2gyx2qdcwjanogq454ad[.]onion` serving as both leak portal and chat server. The "Payload" RaaS — 41 lifetime posts and 21 in the last 30 days, tagged russian-speaking-threat-group in OpenCTI — listed the **Rural Municipality of Gimli**, a local government district on the western shore of Lake Winnipeg in Manitoba, Canada. Payload publishes both ESXi and Windows variants and uses recover_payload.txt / RECOVER_payload.txt as ransom notes. The correlation batch grouped these two posts with Inc Ransom's MTCI entry under shared healthcare, legal-services and government sector targeting.

**Affected:** RT Software (sector unspecified); Rural Municipality of Gimli, Manitoba, Canada — Canadian local government / public sector.

#### Indicators of Compromise

```
Tridentlocker leak/chat (active): tridentfrdy6jydwywfx4vx422vnto7pktao2gyx2qdcwjanogq454ad[.]onion
Payload leak (active):            payloadrz5yw227brtbvdqpnlhq3rdcdekdnn3rgucbcdeawq2v6vuyd[.]onion
Payload chat (degraded):          payloadynyvabjacbun4uwhmxc7yvdzorycslzmnleguxjn7glahsvqd[.]onion
Payload ransom notes:             recover_payload.txt, RECOVER_payload.txt
TTPs (Tridentlocker):             T1204 User Execution, T1486 Data Encrypted for Impact,
                                  T1497 Multi-Stage Channels
TTPs (Payload):                   T1071 Application Layer Protocol, T1486 Data Encrypted for Impact
```

> **SOC Action:** Canadian municipal and public-sector SOCs should treat the Gimli posting as a precedent-setting event for the region — run a tabletop walkthrough of ESXi-encryption response (offline credential vault, out-of-band management plane, snapshot integrity) this week. Add the four onion gateways above to proxy block-lists and create EDR detections for the literal filenames `recover_payload.txt` and `RECOVER_payload.txt` in any non-system path (T1486).

### 3.5 Microsoft Republishes OpenSSL Timing-Attack Advisories (CVE-2018-0734, CVE-2018-0735)

**Source:** [Microsoft MSRC — CVE-2018-0734](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0734), [Microsoft MSRC — CVE-2018-0735](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0735)

Microsoft re-published advisories for two long-standing OpenSSL side-channel vulnerabilities. **CVE-2018-0734** is a timing attack against DSA key signing in OpenSSL allowing recovery of the private key through measurement of signing-operation latency; **CVE-2018-0735** is the equivalent timing flaw in ECDSA signature generation. Both are pre-existing OpenSSL issues (originally disclosed 2018) and the description body in the pipeline data is the standard MSRC text "Information published" — there is no indication of new exploitation, no PoC linkage and no CISA KEV addition. The republication most likely reflects an MSRC catalogue update or downstream-package republish rather than a fresh threat. The entity edges record T1114 Code Signing and T1070.004 File Deletion as related techniques.

**Affected:** Any product still shipping unpatched OpenSSL ≤1.1.0i / ≤1.0.2p; primarily relevant to long-tail embedded and appliance vendors.

> **SOC Action:** No emergency action required. Use the republication as a prompt to confirm the inventory of cryptographic libraries on internet-facing appliances and IoT/OT devices is reporting OpenSSL ≥1.1.1 / ≥1.0.2q; flag any device still on a 2018-era OpenSSL build for vendor escalation or replacement.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with overlapping TTPs (T1486 data-encrypted-for-impact dominates) | Inspira (Qilin), Rural Municipality of Gimli (Payload), MTCI (Inc Ransom), RT Software (Tridentlocker) |
| 🟠 **HIGH** | RansomLook malware tag co-occurs across two unrelated leak-site posts in the same batch (correlation confidence 0.90) | Inspira (Qilin), Rural Municipality of Gimli (Payload) |
| 🟡 **MEDIUM** | Phishing as a common TTP in high-profile data breaches | Udemy 1.4M breach (ShinyHunters), reddycardiology.com (Inc Ransom) |
| 🟡 **MEDIUM** | Healthcare and legal-services sectors converging as preferred ransomware targets (T1486) | MTCI (Inc Ransom), RT Software (Tridentlocker), reddycardiology.com (Inc Ransom) |
| 🔴 **CRITICAL** *(carry-over from prior batch)* | Exploitation of software vulnerabilities leading to critical security risks — flagged in batch 90 (2026-04-26 06:10 UTC), referencing CVE-2026-3844 (Breeze Cache <=2.4.4 Unauthenticated Arbitrary File Upload to RCE, PoC public) | Trend pre-dates this 24h window's report set; included for situational awareness |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (68 reports / last 30d) — RaaS leader; aka Agenda; healthcare and legal-sector focus, fresh Inspira posting today
- **The Gentlemen** (58 reports) — Established RaaS, no new activity in this 24h window but remains pipeline-leading
- **qilin** (40 reports) — Lowercase variant in OpenCTI; same operator cluster as Qilin
- **Coinbase Cartel** (38 reports) — Persistent extortion brand; no activity in this window
- **DragonForce** (28 reports) — Active RaaS; no activity in this window
- **shadowbyt3$** (25 reports) — Initial-access broker; no activity in this window
- **nightspire** (25 reports) — RaaS; no activity in this window
- **Inc Ransom** (1 report this window, persistent in pipeline) — Two new victims today
- **ShinyHunters** (1 report this window) — Drove the Udemy 1.4M leak
- **Tridentlocker** / **tridentlocker** (1 each this window) — RT Software listing

### Malware Families

- **RansomLook** (45 reports / last 30d) — Aggregator-tagged ransomware; appeared in two separate operator posts today (correlation confidence 0.90)
- **RansomLook** *(alt spelling, 37 reports)* — Same cluster
- **RaaS** (25 reports) — Generic ransomware-as-a-service tag
- **ransomware** (22 reports) — Catch-all
- **dragonforce ransomware** (21 reports)
- **Tox1** (18 reports) — Tox-protocol payload references in actor profiles
- **Tridentlocker** (1 report this window)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 5 | [link](https://www.ransomlook.io/) | Dark-web leak-site crawler — five RaaS posts (Qilin, Inc Ransom x2, Tridentlocker, Payload) |
| Microsoft | 2 | [link](https://msrc.microsoft.com/update-guide) | Republished OpenSSL timing-attack advisories CVE-2018-0734 / 0735 |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/Udemy) | Headline 1.4M Udemy breach attributed to ShinyHunters |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Pull the HIBP Udemy domain-search export for every owned domain and force credential rotation for matched users; deploy a 30-day inbound mail rule flagging Udemy-themed lures (refunds, instructor payouts, account verification) — the ShinyHunters dataset will enter commodity phishing kits within weeks (Section 3.1, T1566).
- 🟠 **SHORT-TERM:** Add the active Qilin, Inc Ransom, Tridentlocker and Payload onion gateways and the Qilin file-server IP set (Sections 3.2–3.4) to web-proxy and firewall block-lists; deploy EDR file-create detections for `README-RECOVER-*.txt`, `INC-README*.txt`, `recover_payload.txt` and `RECOVER_payload.txt` outside system directories (T1486/T1530).
- 🟠 **SHORT-TERM:** Healthcare, legal-services and Canadian municipal SOCs should treat the Inc Ransom (reddycardiology.com), Tridentlocker (RT Software) and Payload (Rural Municipality of Gimli) postings as sector-relevant precedents — accelerate ESXi/Hyper-V encryption-resilience tabletops, verify offline backup integrity and test out-of-band management-plane access this week.
- 🟡 **AWARENESS:** Brief application owners that Microsoft has republished CVE-2018-0734 / CVE-2018-0735 OpenSSL timing-attack advisories. No emergency action — use as a prompt to confirm cryptographic-library inventory on internet-facing appliances is on OpenSSL ≥1.1.1 / ≥1.0.2q (Section 3.5).
- 🟢 **STRATEGIC:** With T1486 Data Encrypted for Impact recurring across four of the eight reports today and RansomLook tagging two unrelated operator posts, prioritise the Q2 ransomware-resilience programme: immutable backups, segmented backup network, ESXi vCenter MFA enforcement and rehearsed restore-time SLAs against the 2026 wave of cross-RaaS targeting (Section 4).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 8 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
