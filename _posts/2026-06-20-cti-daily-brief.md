---
layout: post
title:  "CTI Daily Brief: 2026-06-20 — Qilin RaaS surge, AryStinger D-Link botnet (CVE-2025-11837), Secure Boot certificate expiry imminent"
date:   2026-06-21 20:30:00 +0000
description: "Qilin ransomware drove 5 of 14 reports as the dominant RaaS operator; AryStinger botnet compromises 4,000+ D-Link routers via CVE-2025-11837 and legacy flaws; Microsoft Secure Boot CA certificates expire 24 June, threatening UEFI trust chain for Windows and Linux."
category: daily
tags: [cti, daily-brief, qilin, inc-ransom, nova, nightspire, arystinger, secure-boot, cve-2025-11837]
classification: TLP:CLEAR
reporting_period: "2026-06-20"
generated: "2026-06-21"
draft: true
report_count: 14
severity: high
sources:
  - RansomLook
  - BleepingComputer
  - Wired Security
  - Telegram (channel name redacted)
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-20 (24h) | TLP:CLEAR | 2026-06-21 |

## 1. Executive Summary

Fourteen reports were processed across three correlation batches in the last 24 hours, dominated by ransomware ecosystem activity (11 of 14 reports). The Qilin RaaS group was the single most active actor with five distinct victim listings spanning Taiwanese manufacturing, Thai telecommunications, US engineering services, and religious institutions, reinforcing its position as the highest-velocity RaaS operation in the pipeline. The non-ransomware standouts are two operationally significant items: BleepingComputer's disclosure of the **AryStinger** botnet, which has compromised more than 4,000 end-of-life D-Link DIR-850L and DIR-818LW routers via CVE-2013-3307, CVE-2016-5681 and CVE-2025-11837 to build a distributed scanning and proxying network; and Wired's reminder that three Microsoft-signed Secure Boot certificates expire on **24 June 2026**, weakening the UEFI trust chain that historically defended against Sednit/APT 28-linked bootkits such as LoJax. A Telegram listing also advertised the **BLACKNET-00** ransomware builder for sale, signalling further commodity ransomware proliferation. No critical-severity items and no CISA KEV additions were observed in the period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None observed in period |
| 🟠 **HIGH** | 11 | Qilin (3), Inc Ransom (2), Nova, Nightspire, Cmd Organization victim postings; AryStinger botnet; Secure Boot certificate expiry; BLACKNET-00 sale |
| 🟡 **MEDIUM** | 3 | Additional Qilin (Belz, Florida Engineering) and Nova (Lockers IT) victim postings with degraded infrastructure |
| 🟢 **LOW** | 0 | None observed in period |
| 🔵 **INFO** | 0 | None observed in period |

## 3. Priority Intelligence Items

### 3.1 AryStinger botnet weaponises 4,000+ end-of-life D-Link routers (CVE-2025-11837)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)

Qianxin's XLab disclosed AryStinger, a previously undocumented botnet that has converted more than 4,000 outdated routers into distributed "executors" for scanning, proxying, tunnelling, command execution and DNS hijacking. AryStinger exploits **CVE-2013-3307**, **CVE-2016-5681** and **CVE-2025-11837** against D-Link DIR-850L and DIR-818LW models — the same families AVrecon targeted before Lumen's 2023 takedown. Two variants were identified: a C-based router strain and a more capable Go-based NAS variant supporting Shell, Go, Java and Python payload execution. Infection telemetry concentrates in South Korea (48.5%), China (31.8%), Sweden (6.4%), Malaysia (3.5%) and Singapore (2.5%). The malware can tamper with DNS settings to hijack browsing and silently monitor inbound/outbound traffic. XLab also notes the distributed DNS-scanning infrastructure could be repurposed for resolver-targeted DDoS, although none has been observed. No attribution to a known cluster has been made. MITRE ATT&CK mappings from the report: **T1021 (Remote Services)**, **T1046 (Network Service Scanning)**, **T1071.001 (Web Protocols C2)**.

> **SOC Action:** Inventory edge devices for D-Link DIR-850L/DIR-818LW and any other EoL CPE; block egress to known XLab AryStinger C2 ranges; alert on outbound TCP from CPE management VLANs to non-RFC1918 destinations; enforce ISP/customer policy to replace EoL routers, apply latest firmware, change default admin credentials, and disable remote-management WAN interfaces (T1133 reduction). Hunt for anomalous DNS query volumes originating from SOHO/branch subnets.

### 3.2 Microsoft Secure Boot certificate expiry on 24 June 2026 — UEFI trust chain at risk

**Source:** [Wired Security](https://www.wired.com/story/a-critical-deadline-is-approaching-for-windows-and-linux-security/)

Three Microsoft-signed certificates that underpin the **Secure Boot** chain of trust for both Windows and Linux systems expire on **24 June 2026**. Secure Boot uses these certificates to cryptographically validate firmware loaded during system startup; their expiry — if not addressed by a vendor-supplied key update — degrades defences against UEFI bootkits that load before the OS and AV stack. The article references the historical UEFI bootkit lineage: LoJax (attributed to Sednit / Fancy Bear / **APT 28**), MosaicRegressor, ESpecter, FinSpy and MoonBounce. Bootkits survive OS reinstallation and remain among the most difficult-to-remediate persistence techniques. This is a strategic/posture item rather than a confirmed in-the-wild campaign, but the timing window is short.

> **SOC Action:** Confirm that the Windows June 2026 cumulative update (containing the updated Microsoft KEK / DB certificates) is deployed to all Secure Boot-enabled estates; for Linux fleets, verify shim/grub package updates and updated DB keys are applied before 24 June; audit firmware update posture for managed servers and workstations; for endpoints unable to receive timely updates (kiosks, OT/IoT), document risk exception and tighten compensating controls (TPM-backed measured boot, BitLocker key rotation). Hunt EDR for known UEFI bootkit indicators (LoJax, MosaicRegressor, ESpecter, MoonBounce) — MITRE **T1542.003 (Bootkit)**.

### 3.3 Qilin RaaS — five fresh victim listings in 24 hours across four countries and sectors

**Source:** [RansomLook — Qilin](https://www.ransomlook.io//group/qilin)

The Qilin (aka Agenda) RaaS operation posted five distinct victims in the period: **Taiwan Sintong Machinery Co., Ltd** (manufacturing, Taiwan), **Sivatel Bangkok** (telecommunications, Thailand), **Tri-tec** (industrial, US), **Belz Institutions** (religious/education, US — rated medium due to degraded infrastructure) and **Florida Engineering Services** (engineering, US — medium). The group operates a parser-enabled RaaS with affiliate "Ben" listed, contacted via Jabber (`qilin@exploit.im`) and Tox, and uses ransom-note families `README-RECOVER-[rand].txt` and `DtMXQFOCos-RECOVER-README.txt`. RansomLook telemetry shows 1,909 lifetime posts, 74 in the last 30 days, 21 in the last 7 days. Onion infrastructure is widely degraded (5/640 servers active) but the data-leak blog at `ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion` remains 100% available. Correlation batch 187 also linked Qilin's TTPs to AryStinger via shared **T1071.001 (Web Protocols)** C2 use.

> **SOC Action:** Hunt for the Qilin ransom-note filenames (`README-RECOVER-*.txt`, `DtMXQFOCos-RECOVER-README.txt`) on file shares; enrich SIEM with the Tox public key `7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BC...` as a brand indicator; for manufacturing, engineering and telecoms customers, validate that internet-exposed RMM, VPN and Citrix appliances are fully patched and MFA-enforced — Qilin affiliates favour exposed remote-access (T1133) and valid-accounts (T1078) entry. Confirm immutable backup posture and 3-2-1 retention.

#### Indicators of Compromise
```
Actor Tox:    7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
Actor Jabber: qilin@exploit.im
Leak site:    ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
Mirror:       pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd[.]onion
File-share:   kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion
Note name:    README-RECOVER-[rand].txt
Note name:    DtMXQFOCos-RECOVER-README.txt
```

### 3.4 Inc Ransom — Newspaper Media Group and jktornel listings; sustained healthcare and legal targeting

**Source:** [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom posted two victims in the window: **Newspaper Media Group** (US media) and **jktornel**. The group has 815 lifetime posts, 30 in the last 30 days and 7 in the last 7 days, with a 29% average 30-day uptime across its ten known onion URLs. Recent monthly victims include healthcare (Horizon Family Medical Group, Blue Nile Medical Center, Champaign-Urbana Public Health District), legal services and manufacturing — consistent with the correlation pipeline's "legal services and healthcare" trend (correlation batch 187, trend 443). Ransom-note families: `INC-README.txt`, `INC-README2.txt`, `INC-README3.txt`, `INC-README4.txt`, `INC-README.html`. Active infrastructure: leak blog `incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion` (93% uptime) and payment portal `incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion` (100%). MITRE: **T1566 (Phishing)** is the documented initial access vector.

> **SOC Action:** For healthcare, legal and media-sector customers, deploy YARA detections for `INC-README*.txt` / `INC-README.html` ransom-note name patterns; tighten phishing controls (DMARC enforcement, attachment sandboxing, link rewriting); query EDR for execution of legitimate admin tooling (PsExec, AnyDesk, RClone, MEGAsync) by interactive user sessions — Inc Ransom affiliates routinely abuse these for lateral movement and exfiltration.

#### Indicators of Compromise
```
Leak site:      incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion
Mirror:         incbacg6bfwtrlzwdbqc55gsfl763s3twdtwhp27dzuik6s6rwdcityd[.]onion
Payment portal: incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion
Note names:     INC-README.txt, INC-README2.txt, INC-README3.txt, INC-README4.txt, INC-README.html
```

### 3.5 BLACKNET-00 ransomware builder offered for sale on Telegram

**Source:** Telegram (channel name redacted)

A Telegram listing classified TLP:AMBER+STRICT advertised the sale of the **BLACKNET-00** ransomware in full, including source/builder. This is a proliferation signal — commodity ransomware sold to unattributed buyers raises the probability of additional opportunistic campaigns over the coming weeks, often targeting under-defended SMB and education sectors. The pipeline tied this listing to Nova's RALord rebrand (correlation batch 186) under the broader trend of ransomware proliferation and rebranding. MITRE entities flagged on the report: **T1566 (Phishing)** and **TA0009 (Command and Control)**.

> **SOC Action:** Add `blacknet-00`, `BLACKNET00` and `BLACKNET-00` as keyword detections in DLP, email gateway and SIEM rule sets; brief the threat-hunt team for the appearance of new commodity ransomware filenames or extensions over the next 2–4 weeks; ensure EDR is configured to alert on first-seen executable spawning encryption-pattern file writes (T1486) on non-developer endpoints.

### 3.6 Nightspire and Nova — sustained RaaS posting velocity

**Source:** [RansomLook — Nightspire](https://www.ransomlook.io//group/nightspire), [RansomLook — Nova](https://www.ransomlook.io//group/nova)

**Nightspire** posted **Artistic Smiles** (US dental) and shows 358 lifetime posts (31 last-30-day, 9 last-7-day) with affiliates `Phantom`, `Reaper`, `Volt`, `Blaze`, `Shadow` and `Blade`. Active leak site: `nspirep7orjq73k2x2fwh2mxgh74vm2now6cdbnnxjk2f5wn34bmdxad[.]onion` (93% uptime). **Nova** (the RALord rebrand) posted **Nhà Thành Phố** (Vietnam) and **Lockers IT** (medium); 151 lifetime posts and CAPTCHA-protected leak infrastructure. Both groups rely heavily on T1566 (Phishing) for initial access per the pipeline tagging.

> **SOC Action:** Monitor for `[NSPIRE_MSG].txt`, `nightspire_readme.txt` and `README-NOVA.me` ransom-note filenames; for dental/healthcare and SMB customers, run a tabletop on the "Nightspire / Nova" extortion-only scenario where decryption may not be feasible; verify offline, immutable backup tested restore RTO/RPO.

#### Indicators of Compromise
```
Nightspire leak:  nspirep7orjq73k2x2fwh2mxgh74vm2now6cdbnnxjk2f5wn34bmdxad[.]onion
Nightspire mail:  night.spire.team@proton.me, nightspireteam.receiver@proton.me
Nightspire note:  [NSPIRE_MSG].txt, nightspire_readme.txt
Nova leak:        novav75eqkjoxct7xuhhwnjw5uaaxvznhtbykq6zal5x7tfevxzjyqyd[.]onion
Nova contact:     Telegram @NovaSupport (channel name redacted in citation)
Nova note:        README-NOVA.me
```

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Qilin RaaS extensive operations across multiple sectors, indicating a robust RaaS model | Taiwan Sintong Machinery; Sivatel Bangkok; Belz Institutions; Tri-tec; Florida Engineering Services (batch 187) |
| 🟠 **HIGH** | Increased ransomware activity across various sectors, with a focus on legal services and healthcare | Wall ISD (cmd organization); jktornel (Inc Ransom) (batch 187) |
| 🟠 **HIGH** | Ransomware proliferation and rebranding activities | Nhà Thành Phố (Nova, ex-RALord); BLACKNET-00 sale; Newspaper Media Group (Inc Ransom) (batch 186) |
| 🟠 **HIGH** | Shared C2 web-protocol abuse linking ransomware affiliates and IoT botnets | Sivatel Bangkok (Qilin); AryStinger D-Link botnet — shared T1071.001 (batch 187) |
| 🟡 **MEDIUM** | Phishing (T1566) remains the prevalent initial-access TTP across ransomware campaigns | Multiple Qilin, Inc Ransom, Nova and Nightspire listings (cross-batch) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **The Gentlemen** (72 reports) — highest-volume actor in the 30-day window; not seen in today's batch but remains pipeline-wide leader
- **Qilin** (67 reports) — most active actor in today's batch with 5 fresh victim posts; RaaS model with affiliate "Ben"
- **Deadlock** (55 reports) — recent emergence (first seen 2026-06-15)
- **Lockbit5** (39 reports) — sustained activity through mid-June
- **DragonForce** (36 reports) — broad sector targeting
- **Nightspire** (27 reports) — active in today's batch (Artistic Smiles)
- **Akira** (27 reports) — sustained mid-June activity
- **ShinyHunters** (23 reports) — data-extortion focus
- **Nova** (16 reports, ex-RALord rebrand) — active in today's batch (Nhà Thành Phố, Lockers IT)

### Malware Families
- **RansomLook** (136 reports) — pipeline tag for RansomLook-sourced postings, not a distinct malware family
- **Tox1 / Tox** (53 / 33 reports) — actor messaging identifier prevalence
- **Lockbit5** (14 reports) — successor strain to LockBit 4
- **Akira ransomware** (13 reports)
- **Nova** (11 reports) and **RALord** (10 reports) — same lineage post-rebrand
- **Nightspire** (11 reports) and **Deadlock** (10 reports)
- **AryStinger** (today, BleepingComputer) — newly disclosed router botnet
- **blacknet-00** (today, Telegram) — commodity ransomware being sold

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 11 | [link](https://www.ransomlook.io/) | Primary coverage of Qilin (5), Inc Ransom (2), Nova (2), Nightspire (1), Cmd Organization (1) victim postings |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/) | AryStinger D-Link router botnet disclosure |
| Wired Security | 1 | [link](https://www.wired.com/story/a-critical-deadline-is-approaching-for-windows-and-linux-security/) | Secure Boot certificate expiry analysis |
| Telegram (channel name redacted) | 1 | — | BLACKNET-00 ransomware sale listing (TLP:AMBER+STRICT) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Verify deployment of the Microsoft June 2026 Secure Boot certificate update across all Secure Boot-enabled Windows and Linux estates **before 24 June 2026**. Inventory devices that cannot receive the update (kiosks, OT, end-of-support) and apply compensating controls; this is a hard deadline traceable to item 3.2.
- 🔴 **IMMEDIATE:** Audit estate for D-Link DIR-850L and DIR-818LW (and other EoL CPE); block management-plane egress, replace devices where feasible, and add detections for AryStinger TTPs (distributed scan jobs, DNS-setting tampering, anomalous DNS query volume from edge devices). Traces to item 3.1.
- 🟠 **SHORT-TERM:** Roll out IOCs and ransom-note YARA detections for Qilin, Inc Ransom, Nightspire and Nova across EDR and file-share monitoring (items 3.3, 3.4, 3.6). Prioritise customers in manufacturing, engineering, telecoms, healthcare, legal services and media — the sectors hit in the 24-hour window.
- 🟠 **SHORT-TERM:** Brief threat-hunt teams on the BLACKNET-00 commodity ransomware sale (item 3.5) and set first-seen executable / mass-encryption (T1486) detections for the next 2–4 weeks while buyers spin up campaigns.
- 🟡 **AWARENESS:** Phishing (T1566) remains the through-line across the majority of today's RaaS activity. Re-confirm DMARC reject posture, link-rewriting, attachment sandboxing and user reporting workflows are active for all tenants.
- 🟢 **STRATEGIC:** Track Nova/RALord-style rebranding and RaaS affiliate churn as a leading indicator; the pipeline is showing repeated rebrand patterns and commodity-builder sales that historically precede broader victim diversification over 60–90 days.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 14 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
