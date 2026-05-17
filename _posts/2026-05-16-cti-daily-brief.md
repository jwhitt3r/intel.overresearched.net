---
layout: post
title:  "CTI Daily Brief: 2026-05-16 - Qilin hits Argentine medical centre; Beast and Lamashtu RaaS expand victim sets"
date:   2026-05-17 20:10:00 +0000
description: "Five reports in 24h dominated by RaaS activity: Qilin posts a healthcare victim, Beast and Lamashtu add new entries, and Microsoft rejects a critical Azure Backup for AKS privilege-escalation report despite an apparent silent patch."
category: daily
tags: [cti, daily-brief, qilin, lamashtu, beast-ransomware, azure]
classification: TLP:CLEAR
reporting_period: "2026-05-16"
generated: "2026-05-17"
draft: true
severity: high
report_count: 5
sources:
  - RansomLook
  - BleepingComputer
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-16 (24h) | TLP:CLEAR | 2026-05-17 |

## 1. Executive Summary

Five reports were processed for the reporting period from two sources (RansomLook and BleepingComputer), with three rated high and two medium. Ransomware-as-a-service activity dominated the day: Qilin posted CLINICA AVELLANEDA Medical Center to its leak site, Lamashtu added Parle Agro (food sector), and Beast added Trivantage. A BleepingComputer report details a public dispute between Microsoft and security researcher Justin O'Leary over an Azure Backup for AKS privilege escalation issue that Microsoft rejected as "expected behavior" — no CVE was issued, despite the researcher observing that the original attack path no longer works. No critical-severity reports landed in the 24-hour window, and no CISA KEV additions or confirmed in-the-wild zero-day exploitation were captured in the pipeline data.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None this period |
| 🟠 **HIGH** | 3 | Qilin healthcare victim; Beast (Trivantage); Lamashtu (Parle Agro) |
| 🟡 **MEDIUM** | 2 | Termite leak-site activity; Azure Backup for AKS CVE dispute |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 0 | — |

## 3. Priority Intelligence Items

### 3.1 Qilin RaaS posts CLINICA AVELLANEDA Medical Center

**Source:** [RansomLook — Qilin group](https://www.ransomlook.io//group/qilin)

Qilin (a.k.a. Agenda) added Argentine healthcare provider CLINICA AVELLANEDA to its leak site on 2026-05-16. The group continues to operate at very high volume — RansomLock tracks 1,813 total posts and 144 in the last 30 days, including 27 in the past week. Qilin's parsed infrastructure shows 6 of 640 indexed URLs currently up (degraded) with multiple onion services rotating; the actor maintains dedicated ransom-note artefacts (`README-RECOVER-[rand]_2.txt`, `README-RECOVER-[rand].txt`) and an affiliate operator handle "Ben". Pipeline-wide, Qilin is the top trending threat actor (115 reports in the last 30 days), underscoring sustained healthcare and multi-sector targeting.

> **SOC Action:** For organisations in healthcare and adjacent supply-chain sectors, hunt EDR telemetry for creation of files matching `README-RECOVER-*.txt` and `*-RECOVER-README.txt` patterns. Block egress to known Qilin onion gateways and Tor entry guards at the perimeter; alert on any outbound Tor handshakes from production servers. Confirm offline, immutable backups for clinical systems and validate restore times against your RTO.

#### Indicators of Compromise

```
Onion (Qilin leak/file servers, currently up):
  hxxp[:]//ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd[.]onion
  hxxp[:]//pandora42btuwlldza4uthk4bssbtsv47y4t5at5mo4ke3h4nqveobyd[.]onion/
  hxxp[:]//kg2pf5nokg5xg2ahzbhzf5kucr5bc4y4ojordiebakopioqkk4vgz6ad[.]onion/
Web mirrors (currently down, defanged for record):
  hxxps[:]//wikileaksv2[.]com
  hxxps[:]//wikileaks2[.]site
IP (Qilin leak mirror — historical, defanged):
  31.41.244[.]100
Contact:
  qilin@exploit[.]im (Jabber)
Tox: 7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68
```

### 3.2 Beast RaaS adds Trivantage; affiliate offering expands

**Source:** [RansomLook — Beast group](https://www.ransomlook.io//group/beast)

Beast ransomware — which evolved from the 2022 Monster family and runs as a Ransomware-as-a-Service — listed US wholesale fabric supplier Trivantage on 2026-05-17 at 00:53 UTC (within the reporting window). Beast's affiliate offering includes hybrid Elliptic-Curve plus ChaCha20 encryption, segmented file encryption, a ZIP-wrapper mode with embedded ransom notes, multithreading, service termination, shadow-copy deletion, hidden-partition usage, and subnet scanning, with offline builders for Windows, Linux, and VMware ESXi. RansomLock tracks 70 total posts, 2 in the last 30 days, and 1 in the past week — modest leak-site volume but rich affiliate tooling. Attributed TTPs include T1078 (Valid Accounts), T1112 (File and Directory Discovery), and T1496 (Resource Hijacking).

> **SOC Action:** ESXi shops should validate that vCenter and ESXi hosts cannot be reached by SMB or RDP scans from user VLANs and that root SSH is disabled or constrained by jump-host. Hunt for unauthorised shadow-copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`) and service termination of backup agents from non-administrative accounts. Validate that ESXi datastore-level snapshots are immutable or air-gapped.

#### Indicators of Compromise

```
Onion (Beast leak/file servers — currently up, defanged):
  hxxp[:]//beast6azu4f7fxjakiayhnssybibsgjnmy77a6duufqw5afjzfjhzuqd[.]onion/
  hxxp[:]//sxsjteplangjoknelabsjdw6lqdq2g7ak5fkmlbhmj7sztrk2ono24yd[.]onion/
  hxxp[:]//gutatzqnumcmlfhq3txzz47gkhf7opozw2potunt2d7d2vne3apfuqqd[.]onion/
  hxxp[:]//iipl7n3txrysjnclu24deu2pbrkse5y5oiwqyvs6mjdxlisilqpssiad[.]onion/
  hxxp[:]//brt2oxyj3pj5lwdyztcnhjuv3ufqisaw4osup4zzzfmvchxm4vya56id[.]onion/
Contact email (Beast — defanged):
  recovery24.email@onionmail[.]com
  blackpool@zohomail[.]eu
  br.fixdata24@proton[.]me
  helpdata24@zohomail[.]eu
Jabber: mnstr@exploit[.]im
Ransom note: readme.txt
```

### 3.3 Lamashtu RaaS lists Parle Agro (food sector)

**Source:** [RansomLook — Lamashtu group](https://www.ransomlook.io//group/lamashtu)

The Lamashtu group, which RansomLock has indexed since April, posted Indian beverage maker Parle Agro to its leak site at 22:52 UTC on 2026-05-16. The actor operates at high tempo — 28 total posts, 14 in the last 30 days, 5 in the past week — and runs both of its tracked onion services at 97% uptime, indicating mature hosting. Communications run through `LamashtuSupport@onionmail[.]org` with a published PGP key. Mapped TTPs include T1566 (Phishing), T1484 (Data Encrypted for Impact, per pipeline tagging), and T1071.001 (Application Layer Protocol: Web Protocols). The food-and-agriculture sector saw correlated activity in the same correlation batch (see §4), linking Beast/Trivantage and Termite/Ramar Foods.

> **SOC Action:** Food-and-beverage manufacturers should review email gateway policy for high-confidence phishing and validate that finance, procurement, and OT engineering inboxes enforce DMARC reject. Verify that ICS/OT segmentation prevents ransomware lateral movement from corporate IT into plant networks; rehearse manufacturing-line recovery playbooks against a 48-hour outage assumption.

#### Indicators of Compromise

```
Onion (Lamashtu leak — defanged):
  hxxp[:]//lamashtux5j74mcm7lwwgn5yrvuwtrpxjoyendif3v3hrztjesfoyayd[.]onion/
Contact: LamashtuSupport@onionmail[.]org
Ransom note: WHAT_HAPPENED.readme.txt
PGP: LamashtuSupport — Keybase OpenPGP v2.0.76 (key fingerprint published in leak portal)
```

### 3.4 Microsoft rejects Azure Backup for AKS privilege-escalation report; no CVE issued

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-rejects-critical-azure-vulnerability-report-no-cve-issued/)

Security researcher Justin O'Leary disclosed a privilege-escalation flaw in Azure Backup for Azure Kubernetes Service (AKS) that allows a user holding only the low-privileged "Backup Contributor" role on a backup vault to gain cluster-admin on a target AKS cluster. The flaw exploits the Trusted Access relationship Azure auto-configures during backup setup — Azure RBAC and Kubernetes RBAC trust boundaries collide, classified by the researcher as a Confused Deputy issue (CWE-441). Microsoft Security Response Center rejected the report as "expected behavior", and a Microsoft CNA representative recommended MITRE against assigning a CVE. CERT/CC independently validated the bug and assigned VU#284781, with planned disclosure on 2026-06-01 that did not occur after Microsoft's CNA-hierarchy objection. O'Leary reports the original attack path no longer works post-disclosure, consistent with a silent patch despite Microsoft's "no product changes" statement. Microsoft's official position remains that this is expected behaviour.

> **SOC Action:** Audit Azure RBAC role assignments on every Backup Vault: enumerate principals holding `Backup Contributor` (or any custom role that grants `Microsoft.DataProtection/backupVaults/backupInstances/write`) and scope them strictly to vaults backing non-sensitive workloads. For AKS clusters with sensitive data, disable AKS Trusted Access integration where backup is not strictly required, and prefer cluster-internal backup tooling (e.g. Velero with an isolated identity) over Azure Backup for AKS. Review Azure activity logs for unexpected `Microsoft.ContainerService/managedClusters/trustedAccessRoleBindings/write` events in the last 90 days. Track CERT/CC VU#284781 for any further disclosure activity.

### 3.5 Termite leak-site activity (Ramar Foods)

**Source:** [RansomLook — Termite group](https://www.ransomlook.io//group/termite)

The Termite group posted ramarfoods.com on 2026-05-16. RansomLock measures a moderate operational tempo with 40% average uptime over 30 days. The actor uses .onion infrastructure and was correlated in the same daily batch as Beast/Trivantage on a shared "Food and Agriculture / food industry" sector signal (confidence 0.60). Termite is rated medium severity rather than high because of the actor's lower observed uptime and limited public TTP profile.

> **SOC Action:** Food-and-agriculture sector defenders should treat the Termite/Lamashtu/Beast cluster as a coordinated sectoral risk this week. Re-validate immutable backup status for ERP, MES, and SCADA systems; rehearse out-of-band communications in case email is unavailable.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Ransomware groups targeting multiple sectors with evolving tactics | Trivantage By beast; Parle Agro By lamashtu (shared TTPs T1496 Resource Hijacking, T1484 Data Encrypted for Impact — correlation confidence 0.70) |
| 🟡 **MEDIUM** | Increased activity of ransomware actors in diverse regions and sectors | ramarfoods.com By termite; Microsoft Azure Backup for AKS CVE dispute |
| 🟠 **HIGH** | Increased ransomware activity targeting healthcare and technology sectors (carried from prior batch 127) | CLINICA AVELLANEDA By qilin; Gastroenterology & Hepatology of CNY By exitium; CVE-2026-6477 (PostgreSQL libpq) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software components (prior batch 127, awareness only — no critical reports landed in the daily window) | CVE-2026-44662 rust-openssl heap buffer overflow; CVE-2026-6477 PostgreSQL libpq lo_* functions |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (115 reports, last 30d) — RaaS, healthcare and multi-sector extortion; today added CLINICA AVELLANEDA
- **The Gentlemen** (59 reports) — Active leak-site operator
- **Akira** (59 reports) — High-volume RaaS affiliate ecosystem
- **ShinyHunters** (29 reports) — Data-theft / extortion brand
- **Inc Ransom** (25 reports) — Ransomware operator
- **Everest** (24 reports) — Data-leak extortion
- **TeamPCP** (23 reports) — Active actor
- **Coinbase Cartel** (18 reports) — Multi-sector RaaS
- **FulcrumSec** (17 reports) — Active leak-site operator
- **Lamashtu** (14 reports, last 30d) — Today added Parle Agro

### Malware Families

- **RansomLook** (119 reports) — Tracking platform tag; not malware itself, surfaces in pipeline parsing of ransomware-watch infrastructure
- **Akira ransomware** (32 reports) — Active RaaS family
- **Tox1** (31 reports) — Contact channel artefact prevalent across leak-site posts
- **Other1** (21 reports) — Generic tag
- **RaaS** (18 reports) — Generic RaaS classifier
- **Akira** (17 reports) — Family/threat-actor crossover tag
- **Tox** (15 reports) — Contact channel artefact
- **Qilin** (14 reports) — Family tag for Qilin operations
- **Akira Ransomware** (12 reports) — Family tag variant
- **The Gentlemen** (10 reports) — Family/threat-actor crossover tag

*Note: vulnerability-entity trending returned no results for this period.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 4 | [link](https://www.ransomlook.io/) | Leak-site monitoring: Qilin, Beast, Lamashtu, Termite posts |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com) | Azure Backup for AKS privilege-escalation dispute |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit Azure RBAC role assignments on Backup Vaults across every subscription. Identify principals holding `Backup Contributor` (or custom roles granting `Microsoft.DataProtection/backupVaults/backupInstances/write`) and restrict to vaults that do not back sensitive AKS clusters. Review activity logs for `Microsoft.ContainerService/managedClusters/trustedAccessRoleBindings/write` in the last 90 days (§3.4).
- 🟠 **SHORT-TERM:** Healthcare and food-and-agriculture defenders should treat Qilin, Lamashtu, Beast, and Termite as the active sectoral risk for this week. Verify offline/immutable backup posture for clinical systems and OT/MES networks; rehearse a 48-hour outage restore (§3.1, §3.2, §3.3, §3.5).
- 🟠 **SHORT-TERM:** Hunt for ransomware staging behaviour across ESXi and Windows estates: shadow-copy deletion (`vssadmin delete shadows`), backup-agent service termination, and creation of `README-RECOVER-*.txt` files. Alert on outbound Tor handshakes from production servers (§3.1, §3.2).
- 🟡 **AWARENESS:** Track CERT/CC VU#284781 (Azure Backup for AKS) for any further disclosure or independent CVE assignment. Note that Microsoft maintains this is "expected behavior" with no product changes (§3.4).
- 🟢 **STRATEGIC:** Re-baseline the assumption that Azure RBAC and Kubernetes RBAC are independently auditable. The Confused Deputy pattern surfaced in §3.4 will likely recur in any cloud-managed K8s backup or DR tooling — extend cloud-posture reviews to cover trust-boundary handoffs between platform RBAC and workload RBAC.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 5 reports processed across 1 correlation batch (batch 128). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
