---
layout: post
title:  "CTI Daily Brief: 2026-07-14 - SonicWall SMA1000 zero-days exploited in the wild; Microsoft ships 622-CVE Patch Tuesday; RaaS surge from Arcus Media, Qilin, Chaos"
date:   2026-07-15 20:05:00 +0000
description: "SonicWall confirms in-the-wild exploitation of two SMA1000 zero-days (CVE-2026-15409, CVE-2026-15410); Microsoft's July Patch Tuesday addresses 622 flaws with two exploited zero-days; 15 fresh RaaS victim postings dominated by Arcus Media, Qilin, Chaos and Coinbase Cartel; 6.6M-record Goose Creek Shopify breach lands on HIBP."
category: daily
tags: [cti, daily-brief, arcus-media, qilin, chaos, coinbase-cartel, sonicwall, cve-2026-15409, cve-2026-15410, patch-tuesday]
classification: TLP:CLEAR
reporting_period: "2026-07-14"
generated: "2026-07-15"
draft: true
severity: critical
report_count: 22
sources:
  - BleepingComputer
  - Cisco Talos
  - HaveIBeenPwned
  - RansomLock
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-14 (24h) | TLP:CLEAR | 2026-07-15 |

## 1. Executive Summary

The pipeline ingested 22 reports across 5 sources in the last 24 hours, dominated by a surge in Ransomware-as-a-Service (RaaS) victim postings and two active-exploitation vulnerability disclosures. SonicWall confirmed in-the-wild abuse of two SMA1000 zero-days (CVE-2026-15409, CVE-2026-15410) and released emergency patches, while Microsoft's July Patch Tuesday addressed 622 vulnerabilities including two already-exploited zero-days (CVE-2026-56155 in AD FS; CVE-2026-56164 in SharePoint Server) and 57 critical entries. RaaS activity was led by Arcus Media (5 fresh victims), Qilin (2), Chaos (2), plus new postings from Coinbase Cartel, Nightspire, Securotrop, Inc Ransom and Black X. Have I Been Pwned added a 6.6M-record Goose Creek Candle Company breach traced to the vendor's Shopify instance, and Spanish police dismantled a €140M investment-fraud/BEC ring. No CISA KEV additions were surfaced by the collection in this reporting window, but the SonicWall and Microsoft zero-days are strong KEV candidates.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | SonicWall SMA1000 zero-day exploitation (CVE-2026-15409, CVE-2026-15410) |
| 🟠 **HIGH** | 17 | Microsoft July Patch Tuesday (622 CVEs, 2 zero-days); 15 RaaS victim posts (Arcus Media, Qilin, Chaos, Coinbase Cartel, Nightspire, Securotrop, Inc Ransom, Black X); Goose Creek 6.6M breach |
| 🟡 **MEDIUM** | 2 | Spanish Police €140M BEC/fraud takedown; Inc Ransom infrastructure activity |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 2 | SANS ISC Stormcast; DShield SIEM update |

## 3. Priority Intelligence Items

### 3.1 SonicWall SMA1000 zero-days actively exploited — patch immediately

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-sma1000-flaws-exploited-in-zero-day-attacks-patch-now/)

SonicWall has confirmed that threat actors are actively exploiting two vulnerabilities in SMA1000 series appliances — **CVE-2026-15409** and **CVE-2026-15410** — in zero-day attacks. The flaws permit unauthorised access and control of affected devices, enabling arbitrary code execution or denial of service. SonicWall SMA1000 is an SSL VPN / remote-access appliance historically favoured by mid-market and enterprise customers, making it a high-value pivot point for initial access brokers and ransomware affiliates. SonicWall has released security updates and is urging customers to install them without delay. No specific threat actor attribution has been published; the source does not name a campaign.

**Affected products/sectors:** SonicWall SMA1000 series appliances; all sectors exposing SMA1000 to the internet — historically concentrated in financial services, healthcare, legal and government.

> **SOC Action:** Inventory all SMA1000 appliances (internal and DMZ), apply SonicWall's emergency patches for CVE-2026-15409/15410 today, and — pending patch application — restrict management-plane access to allow-listed jump hosts only. Hunt authentication and VPN logs for anomalous session creation, unexpected admin logins, and outbound connections from the appliance itself over the last 30 days. Preserve appliance forensic images before patching if exploitation is suspected.

### 3.2 Microsoft July 2026 Patch Tuesday — 622 CVEs, two zero-days already exploited

**Source:** [Cisco Talos](https://blog.talosintelligence.com/microsoft-patch-tuesday-july-2026/)

Microsoft's July 2026 Patch Tuesday addresses **622 vulnerabilities**, 57 rated critical, with two disclosed as exploited in the wild:

- **CVE-2026-56155** — Elevation of privilege in Active Directory Federation Services (AD FS) via insufficient granularity of access control; requires an authorised local attacker.
- **CVE-2026-56164** — Spoofing vulnerability in Microsoft SharePoint Server caused by missing authentication for a critical function; exploitable by an unauthorised attacker over the network.

Talos flags 11 critical RCEs as "more likely to be exploited," including heap overflows in the Windows DHCP Server service (**CVE-2026-50370**, **CVE-2026-50518**), a use-after-free in the Windows DHCP client (**CVE-2026-54128**), heap overflows in Windows Media / Media Foundation (**CVE-2026-50327**, **CVE-2026-50655**), MSMQ (**CVE-2026-54992**), a race condition in the Server Network driver (**CVE-2026-56188**), SharePoint deserialisation (**CVE-2026-50522**, **CVE-2026-58644**), Dynamics NAV / Dynamics 365 Business Central (**CVE-2026-55944**), and the Minecraft Bedrock Dedicated Server (**CVE-2026-55010**). Additional critical entries were noted in RMCAST (**CVE-2026-54982**, **CVE-2026-54995**) and BitLocker (**CVE-2026-50661**). MITRE ATT&CK: **T1210** (Exploitation for Privilege Escalation), **T1071.001** (Application Layer Protocol: Web Protocols), **T1068.003** referenced in the report.

**Affected products/sectors:** Windows, Office (Word, Excel, PowerPoint), SharePoint, SQL Server, AD FS, Dynamics 365 / NAV, Windows Media, DHCP, Print Spooler, Copilot, MSMQ. Cross-sector, with government, IT, financial services and cloud services most exposed per correlation data.

> **SOC Action:** Prioritise this month's Windows Server, AD FS and SharePoint patches — the two exploited zero-days (CVE-2026-56155, CVE-2026-56164) plus the "more likely" DHCP/RMCAST/SharePoint RCEs should be in the first 72-hour patch wave. For AD FS, review sign-in logs and role assignments for anomalous privilege changes; for SharePoint, block anonymous access to admin endpoints until patched and hunt for unauthenticated POSTs to `/_layouts/` and `/_api/` paths. Deploy the Talos-published Snort/ClamAV signatures.

### 3.3 Coinbase Cartel RaaS — new Axiom Global posting, active auction infrastructure

**Source:** [RansomLock](https://www.ransomlook.io//group/coinbase%20cartel)

Coinbase Cartel, a RaaS group tracked at 186 all-time posts, published a new victim listing for **Axiom Global** (business services, ransom pegged at $19.2M) alongside prior high-profile targets including Cambridge Mobile Telematics ($200M), Cognizant ($21.1B) and Panasonic Aero ($2.7B). The group's leak-site infrastructure is largely degraded — 11 of 12 known .onion mirrors are reported down at time of collection — but one primary onion (`fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd[.]onion`) maintains 90% uptime. Operator contact is via `coinbasecartel[@]atomicmail[.]io`, Tox and SimpleX. MITRE ATT&CK: **T1566** (Phishing) for initial access per entity data.

**Affected products/sectors:** Business services, telematics, technology, aerospace, casino/gaming.

#### Indicators of Compromise
```
Actor contact: coinbasecartel[@]atomicmail[.]io
Onion (active): fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd[.]onion
Tox ID: 58041B45371485934F798C77F2F9705DA735F28AC9EBA2A19B4C9DBAF462802B88E33CEF482A
SimpleX: hxxps[:]//simplex.chat/contact/#/?v=2-7&smp=smp8.simplex.im&a=ie-SNS7kf7I0QN4162sdo7A-X5WpSEoPEtsYueFPtZQ
```

> **SOC Action:** Block outbound to atomicmail.io at the mail gateway and web proxy unless an operational exception exists. Add the active onion above to Tor-egress detection rules and correlate any observed Tor-client traffic from enterprise endpoints. Cross-check third-party/vendor lists against Coinbase Cartel's known victims (Cambridge Mobile Telematics, Cognizant, Panasonic Aero) for supply-chain exposure and ask vendors to confirm containment status.

### 3.4 Ransomware-as-a-Service surge — Arcus Media, Qilin and Chaos dominate the 24-hour victim tally

**Source:** [RansomLook — Arcus Media](https://www.ransomlook.io//group/arcus%20media), [RansomLook — Qilin](https://www.ransomlook.io//group/qilin), [RansomLook — Chaos](https://www.ransomlook.io//group/chaos)

Fifteen fresh victim postings landed in the last 24 hours across eight RaaS brands, with **Arcus Media** the most prolific (5 victims: Perpustam, gemese.pt, Distribox, Be Travel, COREBI/NowVertical, I-FITNESS). **Qilin** claimed Levin Furniture and THL; **Chaos** posted sleemanbreweries.ca and spectrumchemical.com; single postings came from **Coinbase Cartel** (Axiom Global), **Securotrop** (ProDirectional Drilling), **Nightspire** (Cedar Crest College), **Inc Ransom** (Golden Glasko & Associates), and **Black X** (sanaa.center). Arcus Media (active since May 2024) uses selective ChaCha20 encryption with RSA-2048 key wrapping, disables recovery services and terminates SQL processes; initial access is via phishing or credential theft; lateral movement uses **Mimikatz** and **Cobalt Strike**. Chaos operates cross-platform (Windows, ESXi, Linux, NAS) and recently breached Optima Tax Relief. MITRE ATT&CK across the cluster: **T1566** (Phishing), **T1078** (Valid Accounts), **T1485** (Data Encrypted for Impact), **T1547.001** (Registry Run Keys), **T1210** (Exploitation for Privilege Escalation), **T1496** (Resource Hijacking: Ransomware).

**Affected products/sectors:** Retail/furniture, education, chemicals, food & beverage, engineering, financial services, professional services, fitness/leisure, oil & gas drilling, travel, media, healthcare — global footprint.

> **SOC Action:** Alert on Mimikatz signatures (`sekurlsa::logonpasswords`, LSASS process access from non-svchost parents) and Cobalt Strike beacon indicators (default named pipe patterns, jitter/sleep anomalies). For any organisation on the victim lists, notify legal/comms leads within one hour and pre-stage IR retainers. Verify ESXi hosts have Secure Boot enabled and SSH management restricted; verify NAS admin interfaces are not exposed to the internet.

### 3.5 Goose Creek Candle Company — 6.6M-record breach via Shopify instance

**Source:** [Have I Been Pwned](https://haveibeenpwned.com/Breach/GooseCreek)

Have I Been Pwned added a **6,574,121-record** breach for Goose Creek Candle Company in June 2026, disclosed after a party claiming access emailed the vendor's customers directly alleging a security flaw. Exposed data includes email addresses, names, phone numbers, physical addresses, order IDs and total spend. The dataset appears to have been sourced from the retailer's Shopify instance. Goose Creek acknowledged the reports but had provided no further detail at time of publication. MITRE ATT&CK: **T1566** (Phishing) — the extortion vector included direct email outreach to affected customers.

**Affected products/sectors:** Retail / e-commerce; Shopify tenants. Downstream phishing risk for the 6.6M exposed customers.

> **SOC Action:** If your organisation uses Shopify for direct-to-consumer sales, audit installed apps and staff-account privileges for least-privilege compliance and rotate all API keys/access tokens. Warn security-awareness distribution lists to expect Goose Creek–themed phishing (order refunds, breach notifications) over the coming weeks. Enrich phishing-detection stacks with the Goose Creek breach dataset from HIBP for exposure scoring on inbound sender domains.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in widely used software | Microsoft July Patch Tuesday (2 exploited zero-days: CVE-2026-56155, CVE-2026-56164); SonicWall SMA1000 (CVE-2026-15409, CVE-2026-15410) |
| 🟠 **HIGH** | Increased activity of Ransomware-as-a-Service (RaaS) groups targeting multiple sectors | Levin Furniture (Qilin); Axiom Global (Coinbase Cartel); sleemanbreweries.ca (Chaos); Perpustam and 4 more (Arcus Media) |
| 🟠 **HIGH** | Exploitation of Microsoft product vulnerabilities, particularly RCE and elevation of privilege | Talos Patch Tuesday analysis; CVE-2026-56155 (AD FS EoP); CVE-2026-50661 (BitLocker bypass); CVE-2026-54128 (DHCP client UAF) |
| 🟠 **HIGH** | Phishing and credential theft as prevalent TTPs across various threat actors | T1566 top-ranked entity (16 mentions); Goose Creek breach follow-on phishing; Arcus Media / Chaos initial-access chains |
| 🟡 **MEDIUM** | Cloud services increasingly targeted for denial of service and other attacks | Azure Active Directory DoS (CVE-2026-50653); SharePoint spoofing zero-day (CVE-2026-56164) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **The Gentlemen** (92 reports) — pipeline-leading actor over the trailing window; last seen 2026-07-14
- **Qilin** (83 reports) — active RaaS; two fresh victim postings today (Levin Furniture, THL)
- **DragonForce** (38 reports) — persistent RaaS operator
- **Lockbit5** (36 reports) — LockBit successor variant tracked pipeline-wide
- **Akira** (25 reports) — sustained RaaS activity
- **Inc Ransom** (15 reports) — new Golden Glasko & Associates posting today
- **ShinyHunters** (15 reports) — OAuth-abuse trend continues per correlation data
- **Arcus Media** (5 mentions today) — dominant single-day contributor, ChaCha20/RSA-2048 with Mimikatz + Cobalt Strike tradecraft

### Malware Families
- **RansomLook** (115 reports) — aggregator source/tag; largest volume driver
- **Tox1 / Tox** (65 / 40 reports) — messaging channel indicator across RaaS operator contact points
- **Akira ransomware** (13 reports) — active family
- **DragonForce ransomware** (11 reports) — active family
- **Chaos Ransomware** (10 reports) — 2 fresh victims today; cross-platform (Windows/ESXi/Linux/NAS)
- **Qilin ransomware** (11+9 reports across name variants) — active RaaS payload
- **Anubis ransomware** (10 reports) — active family

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 16 | [link](https://www.ransomlook.io/) | Aggregated RaaS leak-site postings across Arcus Media, Qilin, Chaos, Coinbase Cartel, Nightspire, Securotrop, Inc Ransom, Black X |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-sma1000-flaws-exploited-in-zero-day-attacks-patch-now/) | Primary coverage of SonicWall zero-day and Spanish police BEC takedown |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/33158) | Daily Stormcast plus DShield SIEM update |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/GooseCreek) | 6.6M-record Goose Creek Candle Co. breach disclosure |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com/microsoft-patch-tuesday-july-2026/) | Authoritative Microsoft July Patch Tuesday analysis with Snort rules |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch SonicWall SMA1000 for **CVE-2026-15409** and **CVE-2026-15410** today. Restrict management access, preserve forensic images before patching where compromise is suspected, and hunt VPN/auth logs for the last 30 days.
- 🔴 **IMMEDIATE:** Apply Microsoft July Patch Tuesday updates for the exploited zero-days **CVE-2026-56155** (AD FS EoP) and **CVE-2026-56164** (SharePoint spoofing) within 72 hours, plus the "more likely to be exploited" DHCP, RMCAST and SharePoint RCEs.
- 🟠 **SHORT-TERM:** Sweep for RaaS tradecraft — Mimikatz (LSASS access), Cobalt Strike beacons, ChaCha20-based encryption utilities and ESXi-targeting scripts — driven by Arcus Media, Qilin and Chaos activity. Add Coinbase Cartel infrastructure IOCs (see §3.3) to blocklists.
- 🟡 **AWARENESS:** Brief customer-service, marketing and security-awareness teams on Goose Creek breach-themed phishing. If your org runs a Shopify storefront, audit installed apps and rotate API keys.
- 🟢 **STRATEGIC:** Review edge-device (VPN/SSL-VPN/remote-access appliance) lifecycle, patch cadence and monitoring depth — SonicWall SMA1000 is the second edge-appliance zero-day cluster this quarter and repeat exposure indicates a strategic control gap. Ensure edge devices log to central SIEM with their own detection use cases.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 22 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
