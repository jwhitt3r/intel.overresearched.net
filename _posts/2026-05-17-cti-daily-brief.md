---
layout: post
title:  "CTI Daily Brief: 2026-05-17 - Unpatched Windows MiniPlasma zero-day grants SYSTEM; Chaos and Qilin RaaS dominate ransomware activity"
date:   2026-05-18 20:10:00 +0000
description: "An unpatched Windows privilege escalation zero-day (MiniPlasma) with a public PoC anchors a high-severity day dominated by Chaos and Qilin Ransomware-as-a-Service activity; Pwn2Own Berlin 2026 closed with 47 fresh zero-days disclosed."
category: daily
tags: [cti, daily-brief, chaos, qilin, inc-ransom, miniplasma, chaotic-eclipse]
classification: TLP:CLEAR
reporting_period: "2026-05-17"
generated: "2026-05-18"
draft: true
severity: critical
report_count: 12
sources:
  - BleepingComputer
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-17 (24h) | TLP:CLEAR | 2026-05-18 |

## 1. Executive Summary

Twelve reports were processed across two sources in the last 24 hours, dominated by ransomware leak-site postings (10 from RansomLook) and bookended by two BleepingComputer items of strategic significance. The headline event is the public release of **MiniPlasma**, a Windows privilege escalation zero-day affecting fully patched Windows 11 systems, with working PoC code distributed on GitHub by researcher Chaotic Eclipse — BleepingComputer independently verified SYSTEM-level escalation on the latest May 2026 Patch Tuesday build. Ransomware activity is concentrated around two RaaS programmes: **Chaos**, which posted four victims in construction, transportation and manufacturing within a 90-minute window, and **Qilin**, which posted four additional victims spanning food production, paper manufacturing, cultural heritage and agriculture. **Inc Ransom** added a single new victim (`bergen1.net`). The contest result from Pwn2Own Berlin 2026 (47 zero-days, $1.29M paid out) signals a pipeline of vendor patches incoming over the next 90 days for Microsoft Exchange, SharePoint, Edge, Windows 11, VMware ESXi, Red Hat Enterprise Linux, and NVIDIA Container Toolkit. No CISA KEV additions were reported in this collection window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | Windows MiniPlasma zero-day with public PoC; SYSTEM access on patched Win11 |
| 🟠 **HIGH** | 9 | Chaos RaaS (4 victims); Qilin RaaS (4 victims); Inc Ransom (1 victim) |
| 🟡 **MEDIUM** | 0 | No medium-severity items in this period |
| 🟢 **LOW** | 0 | No low-severity items in this period |
| 🔵 **INFO** | 2 | Pwn2Own Berlin 2026 results; RansomLook audit-team posting |

## 3. Priority Intelligence Items

### 3.1 MiniPlasma — Unpatched Windows Privilege Escalation Zero-Day with Public PoC

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/)

Researcher Chaotic Eclipse (also known as Nightmare Eclipse) has released both source code and a compiled executable for an exploit dubbed **MiniPlasma**, which grants SYSTEM privileges on fully patched Windows 11 systems including the latest May 2026 Patch Tuesday build. The flaw resides in the `cldflt.sys` Cloud Filter driver's `HsmOsBlockPlaceholderAccess` routine and abuses an undocumented `CfAbortHydration` API to create arbitrary registry keys in the `.DEFAULT` user hive without access checks. The underlying issue was originally reported to Microsoft by Google Project Zero's James Forshaw in September 2020 (CVE-2020-17103) and ostensibly fixed in December 2020 — Chaotic Eclipse asserts the patch was either never effective or silently rolled back. BleepingComputer and independent vulnerability analyst Will Dormann (Tharros) confirmed exploitation works against the current public Windows 11 release; the exploit reportedly fails against the latest Windows 11 Insider Preview Canary build, suggesting Microsoft may already be testing a fix internally. No CVE has been assigned for the regression at time of reporting. MiniPlasma is the sixth Windows zero-day Chaotic Eclipse has published in recent weeks (joining BlueHammer/CVE-2026-33825, RedSun, UnDefend, YellowKey, and GreenPlasma); three of those previously disclosed flaws were observed in active exploitation post-release.

**Affected products:** Windows 11 (all currently supported builds, fully patched May 2026); likely Windows 10 and Windows Server given shared `cldflt.sys` driver. Insider Canary builds appear unaffected.

**MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation; T1082 — System Information Discovery / Impair Defenses.

> **SOC Action:** Treat this as actively weaponisable given prior precedent for this researcher's disclosures being exploited in the wild. Hunt EDR for unusual `cldflt.sys` interactions and for new process creation chains where an unprivileged user context spawns a SYSTEM-integrity `cmd.exe` or `powershell.exe` without a documented service or scheduled-task ancestor. Specifically alert on registry creation under `HKU\.DEFAULT` originating from non-system processes. Restrict execution of unsigned binaries in user-writable directories via AppLocker/WDAC. Monitor Microsoft Security Update Guide for an out-of-band advisory; do not assume the next Patch Tuesday cycle covers this regression.

### 3.2 Chaos RaaS — Coordinated Victim Posting Spree (Construction, Transportation, Manufacturing)

**Source:** [RansomLook (Chaos)](https://www.ransomlook.io//group/chaos)

The Chaos Ransomware-as-a-Service group posted four victims in a single ~90-minute window on 2026-05-17 between 21:50 and 22:51 UTC: **wtitransport.com** (flatbed trucking, US), **cstindustries.com** (manufacturing/construction, founded 1893), **fallprotect.com** (fall-protection equipment), and **challenge-mfg.com** (manufacturing). All four notices carry the identical 72-hour negotiation window before threatened publication on the group's public leak platform. Chaos (first observed early 2025; unaffiliated with the 2021 Chaos Ransomware Builder) operates cross-platform encryptors for Windows, ESXi, Linux and NAS, with optional partial-file encryption for stealth, and is documented to gain initial access via phishing, exploitation of public-facing applications, and brokered credentials. The group's most prominent prior incident is the breach of Optima Tax Relief (69 GB exfiltrated). Six of the group's twelve known leak/admin onion services are currently up (50% uptime), and the AI correlation engine flagged this cluster with 0.90 confidence on shared actor and 0.80 confidence on the construction/transportation sector overlap.

**Affected sectors:** Construction, transportation/logistics, industrial manufacturing, fall-protection / industrial safety.

**MITRE ATT&CK:** T1566 — Phishing; T1078 — Valid Accounts; T1190 — Exploit Public-Facing Application; T1486 — Data Encrypted for Impact; T1203 — Exploitation for Client Execution.

> **SOC Action:** For organisations in construction, transportation and discrete manufacturing: prioritise emergency review of external-facing RDP, VPN and SonicWall/Fortinet edge appliances for unpatched CVEs and exposed management interfaces. Hunt for unusual SSH/RDP authentication from foreign ASNs against industrial control adjacency hosts. Validate that ESXi hosts have `/etc/ssh/sshd_config` locked to ESXiShellTimeOut and that `vpxuser` is monitored, given Chaos's cross-platform encryptor. Confirm offline, immutable backups are no older than 24 hours for critical OT/IT bridge servers. Block known Chaos C2 onion infrastructure egress at the proxy where Tor exits are not legitimately required.

### 3.3 Qilin RaaS — Four New Victims, Diverse Sectors

**Source:** [RansomLook (Qilin)](https://www.ransomlook.io//group/qilin)

Qilin (alias **Agenda**) posted four victims within an eight-minute window on 2026-05-17 starting at 20:49 UTC: **The Taylor Provisions** (food production, US), **Buckeye Paper** (paper manufacturing, US), **Musée du Bas-Saint-Laurent** (cultural heritage, Quebec), and **Fruits Queralt** (agriculture, Spain). Qilin remains the most prolific RaaS actor in the pipeline overall — 123 reports in the past 30 days and 1,822 posts all-time on RansomLook — and is the top trending threat actor pipeline-wide. The group operates two consistently up onion leak sites (`ijzn3sicrcy7guixkzjkib4u…onion` at 97% uptime; `pandora42btuwlldza4u…onion` at 90% uptime) alongside 614 known file-server endpoints (most currently down). Known affiliate "Ben" continues to participate; communications channels remain `qilin@exploit.im` (Jabber) and a published Tox identifier. Qilin's ransom note filenames observed in the wild include `README-RECOVER-[rand]_2.txt` and `DtMXQFOCos-RECOVER-README.txt`. Correlation data flagged Qilin with 0.95 confidence as an active multi-victim cluster spanning healthcare, government, food and cultural sectors over a wider 42-report batch on the same day.

**Affected sectors:** Food production, paper manufacturing, cultural heritage/museums, agriculture, healthcare (correlated), local government (correlated).

**MITRE ATT&CK:** T1566 — Phishing; T1071 — Application Layer Protocol; T1486 — Data Encrypted for Impact.

> **SOC Action:** Detect Qilin precursor activity by hunting for `README-RECOVER-*.txt` file-write events across user shares and DFS namespaces; alert on any process writing this filename pattern. Block egress to the two confirmed-active Qilin leak-site onion addresses where Tor is not business-required. Validate Veeam / immutable backup integrity for SMB-accessible shares — Qilin affiliates have historically deleted volume shadow copies via `vssadmin delete shadows /all /quiet` (T1490). For healthcare and food-sector tenants, raise vigilance on `qilin@exploit.im` Jabber identifier surfacing in any third-party negotiation triage tooling.

### 3.4 Inc Ransom — Continued Victim Posting Cadence

**Source:** [RansomLook (Inc Ransom)](https://www.ransomlook.io//group/inc%20ransom)

Inc Ransom added **bergen1.net** as a new victim on 2026-05-18 03:54 UTC, continuing a steady cadence of 40 posts in the last 30 days and 8 in the last 7. The group operates two consistently up infrastructure endpoints (one disclosures blog and one chat server) against six currently-down endpoints, indicating active operational maintenance. Inc Ransom is the fifth-most prominent threat actor in the pipeline over the trailing 30-day window with 26 reports. Standard tradecraft includes phishing for initial access and the `INC-README.txt` / `.html` family of ransom notes.

**Affected sectors:** Cross-sector (Inc Ransom historically targets legal services, professional services, manufacturing, and education across Inc's broader victim base).

**MITRE ATT&CK:** T1566 — Phishing; T1485 — Data Destruction; T1486 — Data Encrypted for Impact.

> **SOC Action:** Add the `INC-README.txt`, `INC-README.html`, and `INC-README2.txt` filename patterns to file-creation detection rules across endpoint and file-server telemetry. Block / sinkhole the active Inc disclosures blog onion address at the egress proxy where Tor is not approved. For organisations identifying as `bergen1.net` or peers in the same vertical, treat this as an indicator that exfiltration likely preceded posting by 1–4 weeks; initiate retrospective DNS and proxy-log review for unusual large outbound TLS sessions to cloud-storage hostnames.

### 3.5 Pwn2Own Berlin 2026 — 47 Zero-Days Disclosed, 90-Day Patch Window Begins

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-earn-1-298-250-for-47-zero-days-at-pwn2own-berlin-2026/)

Pwn2Own Berlin 2026 (held 14–16 May at OffensiveCon) concluded with $1,298,250 paid for 47 zero-day exploits across web browsers, enterprise applications, local privilege escalation, servers, local inference, cloud-native/container, virtualisation, and LLM categories. DEVCORE won Master of Pwn ($505,000 / 50.5 points); STAR Labs SG took second ($242,500); Out Of Bounds took third ($95,750). Highest single payout was $200,000 to Cheng-Da Tsai (Orange Tsai, DEVCORE) for a three-bug chain achieving RCE-to-SYSTEM on Microsoft Exchange; Orange Tsai also collected $175,000 for a Microsoft Edge sandbox escape chaining four logic bugs. Windows 11 was successfully exploited three times for local privilege escalation; VMware ESXi was compromised via memory corruption; Red Hat Enterprise Linux for Workstations was rooted twice; an NVIDIA Container Toolkit zero-day was demonstrated; and multiple AI coding agents were exploited. Per ZDI policy, vendors have 90 days to ship patches before public technical disclosure — meaning a wave of high-severity Microsoft Exchange, SharePoint, Edge, Windows 11, ESXi, RHEL and NVIDIA advisories should be expected through mid-August 2026.

**Affected products:** Microsoft Exchange, Microsoft SharePoint, Microsoft Edge, Windows 11, VMware ESXi, Red Hat Enterprise Linux for Workstations, NVIDIA Container Toolkit, multiple AI coding agents.

**MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation; T1190 — Exploit Public-Facing Application; T1078 — Valid Accounts.

> **SOC Action:** Stand up a tracker for Pwn2Own Berlin 2026 vendor advisories with a 90-day clock from 2026-05-16 (advisories expected through ~2026-08-14). Pre-stage emergency change windows for Exchange and SharePoint patches given the Orange Tsai RCE-to-SYSTEM chain — these are the highest-likelihood items for active exploitation post-disclosure. For organisations running ESXi, confirm vCenter and ESXi are on supported maintenance branches and that hypervisor management is segmented from corporate identity. Subscribe to ZDI advisory feed (`zerodayinitiative.com/advisories`) and Microsoft Security Update Guide RSS for early notification.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in enterprise technologies, with significant financial incentives at hacking competitions | Pwn2Own Berlin 2026 — 47 zero-days, $1.29M paid |
| 🟠 **HIGH** | Increased use of Ransomware-as-a-Service with double-extortion tactics by the Chaos group targeting multiple sectors globally | `wtitransport.com`, `cstindustries.com`, `fallprotect.com`, `challenge-mfg.com` — all Chaos |
| 🟠 **HIGH** | Qilin and DragonForce RaaS programmes continue to target multiple sectors globally, with a focus on healthcare and government | `Buckeye Paper By qilin`; correlated DragonForce victims `Ingelan`, `Plan` |
| 🟠 **HIGH** | Stormous shifting from ransom demands toward bulk data-exfiltration sales (carryover from prior 24h batch) | `Nipun Consultancy By stormous`; `Important Announcement By stormous` |
| 🟠 **HIGH** | Phishing (T1566) remains the dominant initial-access TTP across multiple RaaS operators | `The Taylor Provisions By qilin`; Tycoon2FA Microsoft 365 device-code phishing (correlated) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (123 reports) — Most prolific RaaS programme in the pipeline; cross-sector, currently posting healthcare, government, food and cultural-heritage victims.
- **The Gentlemen** (59 reports) — Sustained leak-site activity; financially motivated extortion operator.
- **Akira** (59 reports) — Continues to be a top global ransomware threat; recent Windows and VMware ESXi attack patterns.
- **ShinyHunters** (29 reports) — Data-extortion focus; large dump operations.
- **Inc Ransom** (26 reports) — Active this period with one new victim; consistent operational cadence.
- **Everest** (24 reports) — Active data-leak operator.
- **TeamPCP** (23 reports) — Emerging actor; sustained ~3-week presence.
- **Coinbase Cartel** (17 reports) — Crypto-themed extortion / data-leak operator.
- **FulcrumSec** (17 reports) — Recent emergence in pipeline (first seen 2026-04-29).
- **DragonForce** (16 reports) — Active across retail, government, logistics and manufacturing; phishing-led.

### Malware Families

- **Akira ransomware** (32 reports) — Continues to drive a meaningful share of all ransomware reporting.
- **Tox1 / Tox** (31 / 18 reports) — Tox identifiers/protocol references as actor-comms infrastructure across multiple RaaS programmes.
- **RaaS** (18 reports) — Generic RaaS classifier indicating sustained as-a-service operator activity.
- **Qilin ransomware** (14 reports) — Encryptor variant linked to Qilin/Agenda.
- **Akira Ransomware** (12 reports) — Variant entity grouping for Akira encryptor strains.
- **The Gentlemen** (10 reports) — Group-named malware/leak-tool tracking.
- **inc** (1 report this period) — Inc Ransom encryptor family, observed against `bergen1.net`.
- **Chaos Ransomware** (4 mentions this period) — Cross-platform encryptor driving today's Chaos cluster.

*No vulnerability-typed trending entities were returned by the pipeline for this period.*

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 10 | [link](https://www.ransomlook.io/) | Leak-site monitoring: Chaos (4), Qilin (4), Inc Ransom (1), audit-team (1) |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/) | Critical Windows zero-day disclosure and Pwn2Own Berlin 2026 wrap-up |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Treat the MiniPlasma Windows privilege-escalation PoC as live and weaponisable. Deploy detection coverage for SYSTEM-integrity child processes spawned from user-context parents, alert on registry key creation under `HKU\.DEFAULT` from non-system processes, and prepare to act on any out-of-band Microsoft advisory addressing the `cldflt.sys` regression. Block PoC binary delivery via web/email content inspection if hash artefacts surface.
- 🟠 **SHORT-TERM:** For construction, transportation, manufacturing, food production, paper, and cultural-heritage sectors: validate that external-facing edge appliances (VPN, RDP gateways, firewalls) are fully patched and that immutable backup snapshots are no older than 24 hours, given the coordinated Chaos and Qilin posting cadence observed on 2026-05-17.
- 🟠 **SHORT-TERM:** Deploy file-creation detections for the `INC-README.txt`/`README-RECOVER-*.txt` ransom-note filename patterns to provide late-stage tripwire coverage for Inc Ransom and Qilin affiliate intrusions.
- 🟡 **AWARENESS:** Stand up a 90-day vendor-patch tracker for Pwn2Own Berlin 2026 zero-days covering Microsoft Exchange, SharePoint, Edge, Windows 11, VMware ESXi, Red Hat Enterprise Linux, and NVIDIA Container Toolkit. The Orange Tsai Exchange RCE-to-SYSTEM chain is the highest-likelihood follow-on exploitation candidate; pre-stage emergency change windows.
- 🟢 **STRATEGIC:** Phishing (T1566) remains the single highest-confidence initial-access TTP across today's correlations and across the trailing landscape summary. Continue investment in phishing-resistant MFA (FIDO2 / WebAuthn) for high-value identities, enforce conditional-access policies that block device-code authentication flows where not explicitly required (mitigating Tycoon2FA-style Microsoft 365 hijack patterns), and run quarterly assumed-breach exercises against email-borne initial-access scenarios.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 12 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
