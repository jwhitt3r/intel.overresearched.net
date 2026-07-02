---
layout: post
title:  "CTI Daily Brief: 2026-07-01 - FortiBleed credentials fuel Lynx ransomware; Ousaban banking Trojan hits Iberia; ChocoPoC RAT hidden in GitHub PoCs"
date:   2026-07-02 20:05:00 +0000
description: "22 reports processed over the last 24 hours. Dominant themes: healthcare-sector ransomware (Anubis, Inc Ransom, Safepay, Stormous), phishing-led banking Trojans (Ousaban) and stolen Fortinet credentials tied to Lynx ransomware operations. Scattered Spider suspect extradited to the U.S."
category: daily
tags: [cti, daily-brief, lynx, inc-ransom, ousaban, chocopoc, anubis, stormous, safepay, scattered-spider, shinyhunters]
classification: TLP:CLEAR
reporting_period: "2026-07-01"
generated: "2026-07-02"
draft: true
severity: high
report_count: 22
sources:
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - SANS
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-01 (24h) | TLP:CLEAR | 2026-07-02 |

## 1. Executive Summary

Twenty-two reports were processed across the last 24-hour cycle, drawn from six sources and dominated by ransomware leak-site activity (RansomLook) and phishing-led credential theft (BleepingComputer, AlienVault). Twelve items carried a high-severity rating, with no confirmed critical or CISA KEV additions in the window. The three headline items are the FortiBleed credential-theft campaign linked to Lynx and INC ransomware operations, an ongoing Ousaban banking-Trojan campaign targeting Spanish and Portuguese banking users with geofenced phishing PDFs, and the ChocoPoC Python RAT being distributed through weaponised proof-of-concept exploits hosted on GitHub. Healthcare remains the most heavily-pressured victim sector, with Anubis, Inc Ransom, Safepay and Stormous all posting new victims during the cycle. On the law-enforcement side, a 19-year-old Scattered Spider suspect was extradited from Finland to Chicago to face charges over an $8M-ransom intrusion at a luxury-jewellery retailer.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No critical-severity items in this cycle |
| 🟠 **HIGH** | 12 | FortiBleed/Lynx credential-theft campaign; Ousaban banking Trojan; ChocoPoC RAT; Anubis, Inc Ransom, Safepay and Stormous leak-site activity |
| 🟡 **MEDIUM** | 6 | Medtronic ShinyHunters breach notification; Kubota month-long intrusion; Scattered Spider extradition; suspected Telegram-proxy phishing infrastructure |
| 🟢 **LOW** | 1 | Additional Telegram-proxy infrastructure indicator |
| 🔵 **INFO** | 3 | ISC Stormcast episode; low-signal Telegram proxy posts |

## 3. Priority Intelligence Items

### 3.1 FortiBleed credential-theft campaign linked to Lynx and INC ransomware

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/)

BleepingComputer reports that the mass credential-theft campaign dubbed FortiBleed — targeting Fortinet edge devices — has been linked to the INC and Lynx ransomware operations. Investigators assess that the stolen Fortinet credentials were intended to enable follow-on network intrusions by these ransomware crews, meaning any organisation whose Fortinet VPN or firewall appliances were exposed during the initial FortiBleed disclosure window should treat credential material from those devices as compromised. Reported TTPs include T1190 (Exploit Public-Facing Application) and T1566 (Phishing).

**Affected products/sectors:** Fortinet edge appliances (FortiGate/FortiOS ecosystem); any downstream enterprise that relies on those devices for remote-access authentication.

> **SOC Action:** Force-rotate all local and privileged credentials configured on Fortinet appliances that were exposed during the FortiBleed window, invalidate active VPN sessions, and hunt for anomalous authentications and ngrok/similar tunnelling from Fortinet-adjacent identities. Add Lynx and INC-associated leak-site domains to your dark-web monitoring watch list.

### 3.2 Ousaban banking Trojan running geofenced campaign against Iberian banks

**Source:** [Fortinet FortiGuard Labs (via AlienVault)](https://www.fortinet.com/blog/threat-research/analysis-of-ongoing-ousaban-attacks-targeting-the-iberian-peninsula)

FortiGuard Labs details an ongoing Ousaban (a Brazilian-origin banking Trojan, related to Casbaneiro/Metamorfo — S0455) campaign targeting banking users in Spain and Portugal. The kill chain begins with a phishing PDF disguised as a corrupted invoice; the "Atualizar" (Update) button and embedded hex-escaped JavaScript direct victims to a webpage that geo-fences delivery to Spanish and Portuguese IPs (with server-side blocking of VPNs and sandbox-like browsers). A VBS downloader extracts an Ousaban payload from a steganographic PDF-icon image and drops it to `C:\SysMain_5874288`, deleting staging artefacts to minimise footprint. Reported ATT&CK techniques include T1566.001/.002, T1204.001/.002, T1027, T1140, T1071.004, T1497.001/.003, T1547.001, T1056.001/.002, T1113, T1115 and T1573.001.

**Affected products/sectors:** Microsoft Windows endpoints; retail banking customers in Spain and Portugal.

#### Indicators of Compromise

```
Domains:
  controlfacturas[.]site
  faturanova[.]xyz
  facture-arsys.duckdns[.]org
  faturanova.duckdns[.]org

IPv4:
  162.33.179[.]46
  213.159.64[.]191
  78.40.209[.]32
  91.92.240[.]140

SHA-256 (selected):
  18fd38988d58dd930f5992d448cc09a9400c1eafba76b820b9a83239ac48cf4e
  1e77992666acbbfa0d01fcefa9cc8fbdac291e0681b35745be27c6dfb159a375
  5837e47198a20877e1b04b270c36d9194206ee38d4f32fe3151b3c3b396c4f0d
  65c1a998bac48e02b52b1c850cd500e9fb87521e21755c3a4a491243f5f9a700
  fadbb8061715128bebecf7bc59132b6bb04fe8cc39b965aa5b8722dffe28d7e7
  ffb9eb47cc0cb2f43e04a10dc84df13d04bca1ebacbe47fad0b669728de2f59c
```

> **SOC Action:** Block the listed domains and IPs at the perimeter and DNS, and add the SHA-256 hashes to EDR file-hash blocklists. In Spanish- and Portuguese-language user pools specifically, hunt for VBS execution spawned from `%TEMP%` writing to `C:\SysMain_*`, PDFs opened followed by `wscript.exe` child-processes, and outbound traffic to `*.duckdns.org` hosts (T1071.004).

### 3.3 ChocoPoC Python RAT distributed via trojanised GitHub proof-of-concept exploits

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/chocopoc-malware-delivered-via-trojanized-exploits-on-github/)

Multiple weaponised proof-of-concept exploits on GitHub were used to deliver ChocoPoC, a Python-based remote-access trojan capable of arbitrary command execution and data exfiltration. The lure exploits the trust security researchers place in public PoC code, meaning junior analysts, red-team apprentices and vulnerability-research teams are the primary at-risk population. Reported techniques include T1566 (Phishing), T1071.001 (Application Layer Protocol: Web Protocols) and T1003 (OS Credential Access).

**Affected products/sectors:** Security-research teams and any endpoint used to pull, build or run PoC code from untrusted GitHub repositories.

> **SOC Action:** Restrict PoC-code execution to isolated, snapshot-reverted VMs on a segregated network; treat researcher endpoints as production-privileged for EDR and DLP purposes. Alert on `python.exe` spawning `cmd.exe`/`powershell.exe` from user-writable directories, and on outbound HTTP/S from Python interpreters to newly-registered domains.

### 3.4 Healthcare-sector ransomware pressure: Anubis, Inc Ransom, Safepay and Stormous all active

**Sources:** [RansomLook — Anubis](https://www.ransomlook.io//group/anubis), [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom), [RansomLook — Safepay](https://www.ransomlook.io//group/safepay), [RansomLook — Stormous](https://www.ransomlook.io//group/stormous)

Four ransomware crews posted new victims during the cycle, with healthcare disproportionately represented. Anubis (a financially-motivated group whose banking-Trojan lineage now runs alongside ransomware operations) named Northeast Pediatrics & Adolescent Medicine. Inc Ransom listed Colorado Rehabilitation and Occupational Medicine and Roundshield. Safepay posted awo-suedost.de, dia179.com and eaglecrestlife.org. Stormous published a "data-leak warning" against Higuchi Inc., claiming exfiltration of 102 GB of Sage-software backups, financial records and customer databases across three Higuchi branches, and simultaneously announced it will terminate operations and erase hosted data in 60 days. Reported TTPs across the four actors include T1566 (Phishing), T1204 (User Execution), T1485/T1486 (Data Encrypted for Impact) and T1003 (OS Credential Dumping). The pipeline's correlation engine assessed the healthcare-sector ransomware cluster as a **critical**-risk trend.

**Affected products/sectors:** Healthcare (paediatrics, rehabilitation, aged-care), Japanese manufacturing, small-to-medium enterprise across multiple regions.

> **SOC Action:** For healthcare tenants, verify offline-immutable backup restore capability within the last 24 hours, review external-facing RDP/VPN exposure and enforce MFA on all remote-access paths. Ingest RansomLook leak-site feeds into your threat-intel platform and alert whenever a victim's domain matches a customer or supplier. If your organisation is a Higuchi Inc. supplier or customer, treat exchanged credentials, invoices and shared drives as potentially compromised.

### 3.5 Scattered Spider extradition and secondary breach disclosures (Medtronic, Kubota)

**Sources:** [The Record / Recorded Future News](https://therecord.media/teen-suspect-in-scattered-spider-hacks-extradited-to-us), [BleepingComputer — Medtronic](https://www.bleepingcomputer.com/news/security/medtronic-notifies-customers-impacted-by-shinyhunters-data-breach/), [BleepingComputer — Kubota](https://www.bleepingcomputer.com/news/security/kubota-says-hackers-had-month-long-access-to-network-systems/)

A 19-year-old dual U.S.–Estonian citizen, Peter Stokes, was extradited from Finland to the U.S. Northern District of Illinois to face conspiracy, cyber-intrusion and fraud charges tied to Scattered Spider. The FBI complaint centres on a May 2025 breach of a luxury-jewellery retailer in which help-desk social engineering (T1566, T1078) was used to reset password and MFA for three user accounts within two to three hours, followed by `ngrok`-based persistent access (T1543.003) to the victim's data centre; the group demanded an $8M ransom, which the victim did not pay. Separately, Medtronic notified customers of a data breach attributed to ShinyHunters, and Kubota North America Corporation confirmed hackers had access to its network systems for over a month.

**Affected products/sectors:** Retail (luxury goods), medical devices/healthcare, agricultural manufacturing; help-desk and identity-provider workflows across the enterprise.

> **SOC Action:** Harden help-desk identity-verification: require callback to a pre-registered number, video verification or manager approval before any MFA-device reset. Hunt for `ngrok.exe`, `ngrok-agent` process names and `*.ngrok.io` / `*.ngrok-free.app` egress from privileged workstations (T1543.003). For medical-device fleets, audit third-party portal access following the Medtronic notice; for month-long intrusion patterns like Kubota, prioritise VPN concentrator and remote-management log retention beyond 90 days.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware attacks targeting healthcare and financial sectors | Northeast Pediatrics & Adolescent Medicine (Anubis); Colorado Rehabilitation and Occupational Medicine (Inc Ransom) |
| 🔴 **CRITICAL** | Exploitation of public-facing applications and infrastructure vulnerabilities | The Gentlemen custom-backdoor activity; 900+ Oracle E-Business instances exposed to ongoing attacks |
| 🟠 **HIGH** | Increased phishing activities across multiple sectors and actors | Ousaban Iberian banking campaign; Medtronic ShinyHunters breach notification |
| 🟠 **HIGH** | Ransomware activity targeting government and healthcare across multiple sectors globally | Brain Cipher activity (digitaldynamics.com, goldenstateortho.com); Worldleaks COMHAR post |
| 🟡 **MEDIUM** | Phishing remains a prevalent TTP across diverse campaigns | Traditional email-security webinar coverage; Worldleaks Starpool post; JADEPUFFER agentic-ransomware analysis |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (104 reports) — Custom-backdoor operator; primary driver of the current "public-facing application exploitation" critical trend
- **Qilin** (82 reports) — Ransomware-as-a-service crew; broad victim base including Rossum Integration, Dennis Waters Rental Properties, Dynamic Laser Solutions
- **Deadlock** (55 reports) — Recent-onset actor active mid-June
- **Lockbit5** (39 reports) — Continued LockBit-branded activity
- **Akira** (33 reports) — Persistent ransomware operator, most recent activity 2026-07-01
- **DragonForce** (27 reports) — Ongoing leak-site activity
- **ShinyHunters** (22 reports) — Attributed to yesterday's Medtronic breach notification
- **Stormous** (18 reports) — 102 GB Higuchi Inc. data-leak warning; announced 60-day shutdown
- **Inc Ransom** (18 reports) — Colorado Rehabilitation and Roundshield victims yesterday

### Malware Families

- **RansomLook** (147 reports) — Aggregated leak-site indicator; volume tracks overall ransomware ecosystem activity
- **Tox1 / Tox** (74 / 45 reports) — Encrypted-messaging identifier used by leak-site operators for negotiation
- **Akira ransomware** (16 reports) — Family associated with the Akira actor cluster
- **Lockbit5** (14 reports) — LockBit v5 payload variant
- **Qilin** (12 reports) — Payload associated with Qilin RaaS
- **Anubis ransomware / Anubis banking trojan** (10 / 9 reports) — Yesterday's Northeast Pediatrics victim tied to this family
- **Deadlock** (10 reports) — Payload for the Deadlock actor cluster

*No vulnerability entities reached a report count above 1 during the pipeline window; CVE-2023-29298, CVE-2023-29300 and CVE-2023-26360 were the most recent to appear.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 8 | [link](https://www.ransomlook.io/) | Primary coverage of Anubis, Inc Ransom, Safepay and Stormous leak-site activity |
| Unknown (Telegram) | 7 | — | Turbotelproxy-channel posts — proxy infrastructure of unclear intent; not linked per Telegram-source policy |
| BleepingComputer | 4 | [link](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/) | Primary coverage of FortiBleed/Lynx, ChocoPoC, Medtronic and Kubota |
| AlienVault | 1 | [link](https://www.fortinet.com/blog/threat-research/analysis-of-ongoing-ousaban-attacks-targeting-the-iberian-peninsula) | Ousaban Iberian banking-Trojan analysis (via Fortinet FortiGuard Labs) |
| RecordedFutures | 1 | [link](https://therecord.media/teen-suspect-in-scattered-spider-hacks-extradited-to-us) | Scattered Spider extradition |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33120) | ISC Stormcast episode 9992 |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Force-rotate all credentials configured on FortiGate/FortiOS appliances exposed during the FortiBleed disclosure window, invalidate live VPN sessions, and hunt for Lynx/INC ransomware pre-cursors on any downstream identity used from those devices (ref. §3.1).
- 🔴 **IMMEDIATE:** For healthcare tenants, verify offline-immutable backup restore within the last 24 hours and confirm MFA is enforced on every remote-access path — Anubis, Inc Ransom, Safepay and Stormous are all actively posting new victims and the pipeline rated the healthcare-ransomware cluster as critical (ref. §3.4).
- 🟠 **SHORT-TERM:** Deploy the Ousaban IOCs (four domains, four IPs, seven+ SHA-256 hashes in §3.2) to perimeter, DNS and EDR blocklists; add Spanish- and Portuguese-language phishing to your user-awareness rotation this week.
- 🟠 **SHORT-TERM:** Harden help-desk identity-verification against Scattered Spider–style social engineering — require callback to pre-registered number or manager approval before MFA-device resets (ref. §3.5); alert on `ngrok` usage from privileged endpoints.
- 🟡 **AWARENESS:** Brief security-research and vulnerability-management staff on the ChocoPoC GitHub-PoC delivery technique; mandate isolated-VM execution for any PoC pulled from a repository whose reputation you cannot independently verify (ref. §3.3).
- 🟢 **STRATEGIC:** Ingest RansomLook feeds into your threat-intel platform and correlate leak-site victim domains against your customer and supplier list — Stormous' Higuchi Inc. dump illustrates the supply-chain blast radius of a single victim.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 22 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
