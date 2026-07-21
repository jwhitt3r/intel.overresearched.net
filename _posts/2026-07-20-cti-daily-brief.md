---
layout: post
title:  "CTI Daily Brief: 2026-07-20 - wp2shell WordPress webshells hit CISA KEV, Qilin exploits Palo Alto GlobalProtect, JADEPUFFER ransomware targets AI models"
date:   2026-07-21 22:38:00 +0000
description: "87 reports across 14 sources. Four CISA KEV additions including actively exploited wp2shell WordPress flaws; Qilin ransomware weaponises a PAN-OS GlobalProtect auth bypass; a Windows LegacyHive zero-day and a surge in AI-infrastructure attacks dominate the day."
category: daily
tags: [cti, daily-brief, qilin, jadepuffer, mustang-panda, cve-2026-63030, cve-2026-0770]
classification: TLP:CLEAR
reporting_period: "2026-07-20"
generated: "2026-07-21"
draft: true
report_count: 87
severity: critical
sources:
  - Microsoft
  - BleepingComputer
  - CISA
  - Crowdstrike
  - AlienVault
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-20 (24h) | TLP:CLEAR | 2026-07-21 |

## 1. Executive Summary

The pipeline processed 87 reports from 14 sources in the last 24 hours, with 8 rated critical and 32 high. The dominant theme is confirmed in-the-wild exploitation converging on the CISA Known Exploited Vulnerabilities catalogue: CISA added four actively exploited flaws, including the "wp2shell" WordPress Core pair (CVE-2026-63030 and CVE-2026-60137) now used to install persistent webshells, and CVE-2026-0770 in Langflow. Separately, the Qilin ransomware gang is exploiting a critical PAN-OS GlobalProtect authentication bypass to breach networks, and a Windows "LegacyHive" privilege-escalation zero-day received an unofficial community patch. A parallel storyline is the accelerating targeting of AI/ML infrastructure — the agentic actor JADEPUFFER is deploying ENCFORGE ransomware built to destroy AI models via Langflow, while Crowdstrike and Wired document a SANDWORM_MODE supply-chain worm attacking AI toolchains. Iranian-nexus activity and a Mustang Panda backdoor campaign against India round out the nation-state picture.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 8 | wp2shell WordPress webshells (CVE-2026-63030/60137); Qilin exploiting PAN-OS GlobalProtect; Windows LegacyHive zero-day; dxgkrnl double-free CVE-2026-58629; QEMU-KVM CVE-2026-3842; Perl Storable CVE-2026-57433; CMP trust-anchor CVE-2026-42769; netfilter CVE-2026-64076 |
| 🟠 **HIGH** | 32 | CISA KEV additions; JADEPUFFER/ENCFORGE AI ransomware; SANDWORM_MODE AI supply-chain worm; Mustang Panda (India); Iran midyear assessment; KARR car Bluetooth flaw; large Linux kernel CVE batch |
| 🟡 **MEDIUM** | 30 | Spain's €3M 23andMe fine; Kenya presidential website hack; Perl DBI and Linux kernel disclosures |
| 🟢 **LOW** | 6 | Lower-severity kernel/driver disclosures |
| 🔵 **INFO** | 11 | Advisory and analysis content |

## 3. Priority Intelligence Items

### 3.1 wp2shell WordPress Core Flaws Exploited for Webshells — Added to CISA KEV

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-wp2shell-wordpress-flaws-exploited-to-install-webshells/), [CISA](https://www.cisa.gov/news-events/alerts/2026/07/21/cisa-adds-four-known-exploited-vulnerabilities-catalog)

Attackers are actively exploiting the "wp2shell" vulnerability suite in WordPress Core — CVE-2026-63030 (interpretation conflict) and CVE-2026-60137 (SQL injection) — to deploy persistent webshells and install malicious plugins on compromised servers. CISA added both CVEs to the Known Exploited Vulnerabilities catalogue on 21 July, alongside CVE-2021-27137 (DD-WRT stack buffer overflow) and CVE-2026-0770 (Langflow untrusted functionality inclusion), confirming active exploitation. The pipeline correlated the BleepingComputer and CISA reports at 0.90 confidence on the shared CVEs. Affected: WordPress Core web estates and any internet-facing Langflow/DD-WRT assets. Technique: `T1190 - Exploit Public-Facing Application`.

> **SOC Action:** Immediately patch WordPress Core to the fixed release and hunt for unauthorised plugin installs and new PHP files under wp-content (webshell staging). Query web logs for anomalous POST requests to admin/plugin-upload endpoints, and audit for CVE-2026-0770 on any exposed Langflow instances. FCEB agencies are bound by BOD 26-04 remediation timelines for all four KEV entries.

### 3.2 Qilin Ransomware Exploiting Critical Palo Alto GlobalProtect Auth Bypass

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-globalprotect-vpn-bug-now-exploited-in-ransomware-attacks/)

The Qilin ransomware gang is exploiting a critical PAN-OS GlobalProtect authentication bypass flaw to gain unauthorised network access and move laterally, per Arctic Wolf reporting relayed by BleepingComputer. The vulnerability is confirmed exploited in the wild. Qilin is the second most active threat actor pipeline-wide (89 reports in 30 days), making this a high-probability precursor to encryption events. This aligns with a broader AI-identified trend of RaaS groups expanding across sectors.

> **SOC Action:** Apply the Palo Alto PAN-OS/GlobalProtect fix on all internet-facing firewalls without delay and force-rotate GlobalProtect and admin credentials. Review VPN authentication logs for logins from unexpected geographies or impossible-travel patterns, and hunt for post-access lateral movement (new admin accounts, RMM tooling) consistent with Qilin TTPs.

### 3.3 Windows Privilege-Escalation Zero-Days: LegacyHive and dxgkrnl Double-Free

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/windows-legacyhive-zero-day-flaw-gets-free-unofficial-patches/), Telegram (channel name redacted)

A Windows "LegacyHive" zero-day enabling privilege escalation on fully updated systems has received a free, unofficial (community) micropatch ahead of an official Microsoft fix. Separately, a Telegram-sourced technical note details CVE-2026-58629, a double-free in the `dxgkrnl` graphics kernel driver's CreateAllocation rollback path, which may enable arbitrary code execution with elevated privileges (TLP:AMBER+STRICT). Both are local privilege-escalation primitives valuable for post-compromise chaining.

> **SOC Action:** Track Microsoft's advisory channel for the official LegacyHive patch; where an unofficial micropatch is used as a stopgap, validate it in a test ring before deployment. Hunt EDR telemetry for unexpected token-elevation events and anomalous child processes spawning from user-level contexts, and prioritise dxgkrnl/graphics-driver crash telemetry as a possible exploitation signal.

### 3.4 AI Infrastructure Under Sustained Attack: JADEPUFFER/ENCFORGE and SANDWORM_MODE

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a5eb7c2617139caf1fe0f2d), [Crowdstrike](https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/), [Wired](https://www.wired.com/story/a-sneaky-hacking-tool-targeting-ai-infrastructure-is-lurking-in-victims-blind-spots/)

The agentic threat actor JADEPUFFER has evolved to deploy ENCFORGE, a Go-based ransomware that targets ~180 AI/ML file extensions (model checkpoints, vector databases, training datasets) using AES-256-CTR + RSA-2048. Initial access is via CVE-2025-3248 in Langflow, after which the actor autonomously chains reconnaissance, credential harvesting, lateral movement and even real-time container-escape toolkit construction. Encrypted models are effectively unrecoverable — rebuild costs are cited at $75,000–$500,000 per model. In parallel, Crowdstrike (SANDWORM_MODE) and Wired describe a worm targeting AI toolchains and development environments, hunting npm tokens, cryptographic keys and server credentials, with a destructive "death switch." The pipeline correlated the JADEPUFFER and Wired reports at 0.80 confidence (AI-infrastructure sector). Techniques include `T1190`, `T1059`, `T1078`, `T1046`, `T1486`, `T1489`, `T1490` and `T1611`.

#### Indicators of Compromise
```
C2/IPv4: 45.131.66[.]106
SHA256:  8cb0c223b018cecef1d990ec81c67b826eb3c30d54f06193cf69969e9a8baea2
SHA256:  ab9824b61587c77a8d8649545cdbdc63ed2c384e45c9aba534e3f457f96efa7a
SHA256:  ea7822eac6cecef7746c606b862b4d3034856caf754c4cf69533662637905328
```

> **SOC Action:** Patch Langflow against CVE-2025-3248 and CVE-2026-0770, and block/alert on the IOCs above. Isolate AI/ML training infrastructure behind strong network segmentation, enforce immutable/offline backups of model artefacts and vector stores, and audit for exposed npm tokens and cloud keys in CI/CD and developer environments. Monitor containers for escape behaviour (unexpected privileged syscalls, host-mount access).

### 3.5 Mustang Panda Stage-1 Backdoor Targeting India

**Source:** Telegram (channel name redacted)

A Telegram-sourced quick-note attributes a Stage-1 backdoor delivered via a trojanised "SolidPDFCreator" to Mustang Panda, targeting India (TLP:AMBER+STRICT). The backdoor reportedly enables remote command execution and data exfiltration; delivery is assessed as phishing-based (`T1566`). Attribution to Mustang Panda is as stated by the source and should be treated as unconfirmed pending corroboration from a second source.

> **SOC Action:** Block and alert on execution of "SolidPDFCreator"-named binaries from user-writable paths, and hunt for signed-but-anomalous PDF-utility processes making outbound C2 connections. Reinforce phishing controls for staff in India-facing operations and inspect email gateways for lure documents impersonating PDF tooling.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Rising webshell deployments exploiting WordPress vulnerabilities | wp2shell exploitation + CISA KEV addition (shared CVE-2026-63030, CVE-2026-60137; 0.90 confidence) |
| 🔴 CRITICAL | Exploitation of zero-day vulnerabilities in VPN appliances to deploy custom malware | SonicWall SMA1000 zero-days; Qilin exploiting PAN-OS GlobalProtect (batch 240) |
| 🟠 HIGH | Increased exploitation of AI-infrastructure vulnerabilities by sophisticated actors | SANDWORM_MODE AI toolchain worm; AI-infrastructure hacking tool (Wired); JADEPUFFER/ENCFORGE (0.80) |
| 🟠 HIGH | RaaS groups expanding operations across sectors (double extortion) | Qilin and Safepay victim postings across manufacturing/tech/healthcare (batch 240) |
| 🟠 HIGH | Government-sector campaigns using covert application-layer C2 | Middle East government targeting + HOLLOWGRAPH M365-calendar C2 (T1071.001, T1055; 0.85) |

## 5. Trending Entities (Pipeline-Wide)

30-day cumulative counts; not limited to this reporting period.

### Threat Actors
- **The Gentlemen** (97 reports) — most active actor in the dataset; ransomware-linked
- **Qilin** (89 reports) — RaaS gang; today weaponising PAN-OS GlobalProtect auth bypass
- **DragonForce** (42 reports) — active ransomware/extortion operation
- **Akira** (26 reports) — persistent ransomware actor
- **Nova** (18 reports) — ransomware-linked activity
- **Inc Ransom** (18 reports) — double-extortion operation
- **Safepay** (12 reports) — driving the double-extortion trend in batch 240
- **JADEPUFFER** (new this period) — agentic actor deploying ENCFORGE against AI/ML infrastructure

### Malware Families
- **RansomLook** (115 reports) — dominant tracked ransomware-leak indicator source
- **Akira ransomware** (14 reports) — aligned with Akira actor activity
- **DragonForce ransomware** (14 reports)
- **Chaos Ransomware** (12 reports)
- **The Gentlemen ransomware** (12 reports)
- **Anubis ransomware** (11 reports)
- **ENCFORGE** (new this period) — AI/ML-model-destroying ransomware used by JADEPUFFER

> Note: Trending-vulnerability data for this window returned only sparse, older CVE entries (early July / late June) and is not representative of today's activity; the actionable CVEs are those in Sections 3–4.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 62 | [link](https://msrc.microsoft.com/update-guide) | MSRC bulk disclosures — Linux kernel, Perl DBI, USB Type-C, crypto CVEs |
| BleepingComputer | 7 | [link](https://www.bleepingcomputer.com) | wp2shell, Qilin/PAN-OS, LegacyHive zero-day |
| RecordedFuture | 3 | [link](https://therecord.media) | 23andMe fine; Kenya presidential website hack |
| SANS | 2 | [link](https://isc.sans.edu) | Analyst diaries |
| Wired Security | 2 | [link](https://www.wired.com/category/security) | AI-infrastructure worm; KARR car Bluetooth flaw |
| Wiz | 2 | [link](https://www.wiz.io/blog) | Cloud visibility / exploitation detection |
| Unknown (Telegram) | 2 | — | dxgkrnl CVE-2026-58629; Mustang Panda (channel redacted) |
| Sentinel One | 1 | [link](https://www.sentinelone.com/labs) | Iran war cyber midyear assessment |
| Sysdig | 1 | [link](https://sysdig.com/blog) | AI threat-landscape analysis |
| CISA | 1 | [link](https://www.cisa.gov/news-events/alerts/2026/07/21/cisa-adds-four-known-exploited-vulnerabilities-catalog) | Four KEV additions |
| Crowdstrike | 1 | [link](https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/) | SANDWORM_MODE AI supply-chain worm |
| AlienVault | 1 | [link](https://otx.alienvault.com/pulse/6a5eb7c2617139caf1fe0f2d) | JADEPUFFER/ENCFORGE pulse with IOCs |
| Schneier | 1 | [link](https://www.schneier.com) | Commentary |
| RansomLock | 1 | — | Ransomware-leak tracking |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch the four CISA KEV additions on any exposed assets — WordPress Core (CVE-2026-63030, CVE-2026-60137), Langflow (CVE-2026-0770), DD-WRT (CVE-2021-27137) — and hunt WordPress estates for webshells and rogue plugins (Section 3.1).
- 🔴 **IMMEDIATE:** Remediate the PAN-OS GlobalProtect authentication bypass on all internet-facing firewalls and rotate VPN/admin credentials before Qilin converts access into ransomware (Section 3.2).
- 🟠 **SHORT-TERM:** Segment and back up AI/ML infrastructure offline, patch Langflow against CVE-2025-3248, and block the JADEPUFFER/ENCFORGE IOCs; audit developer/CI-CD environments for exposed npm tokens and cloud keys targeted by the SANDWORM_MODE worm (Section 3.4).
- 🟠 **SHORT-TERM:** Deploy interim mitigation for the Windows LegacyHive privilege-escalation zero-day and monitor dxgkrnl crash/elevation telemetry pending official Microsoft patches (Section 3.3).
- 🟡 **AWARENESS:** Brief India-facing operations on the Mustang Panda "SolidPDFCreator" backdoor and reinforce phishing controls; treat the attribution as unconfirmed (Section 3.5).
- 🟢 **STRATEGIC:** Formalise a KEV-driven, risk-based patch SLA (per BOD 26-04) and extend detection engineering to AI-toolchain supply-chain threats, now a recurring correlated trend across multiple vendors.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 87 reports processed across 2 correlation batches (IDs 240–241). A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
