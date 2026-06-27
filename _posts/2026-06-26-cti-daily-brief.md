---
layout: post
title:  "CTI Daily Brief: 2026-06-26 - Chromium 14-CVE batch, FBI warns Russian RIS targets Signal backup keys, novel AI-coding-agent supply chain attack"
date:   2026-06-27 20:10:00 +0000
description: "Microsoft published 14 Chromium CVEs (CVE-2026-13021–13038, 11 high-severity use-after-free); FBI/CISA update warns Russian RIS (UNC5792, UNC4221) is now phishing for Signal backup recovery keys to extract historical messages; researchers demonstrate a GitHub-based attack that weaponises AI coding agents without any malicious repo code; ransomware activity remains broad with Redact, Inc Ransom, Play, 3AM, DragonForce, and Stormous all posting new victims."
category: daily
tags: [cti, daily-brief, russian-intelligence-services, inc-ransom, dragonforce, chromium, signal, lastpass]
classification: TLP:CLEAR
reporting_period: "2026-06-26"
generated: "2026-06-27"
draft: true
severity: high
report_count: 35
sources:
  - Microsoft
  - RansomLook
  - BleepingComputer
  - Wired Security
  - Schneier
  - BellingCat
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-26 (24h) | TLP:CLEAR | 2026-06-27 |

## 1. Executive Summary

The pipeline processed 35 reports across 7 sources in the last 24 hours, dominated by a 14-CVE Chromium security batch from Microsoft (CVE-2026-13021 through CVE-2026-13038, mostly use-after-free) and sustained ransomware leak-site activity. The most operationally significant non-vulnerability item is an FBI/CISA update warning that Russian Intelligence Services (tracked as UNC5792 and UNC4221) have evolved their Signal-targeting phishing campaign to steal Backup Recovery Keys, enabling reconstruction of victims' historical conversations from Signal's cloud backups. Mozilla's 0DIN team disclosed a novel attack chain that weaponises AI coding agents (demonstrated with Claude Code) using a clean GitHub repository plus a DNS-TXT-delivered payload, producing a developer-privileged reverse shell with no malicious code in the repo itself. Ransomware groups Redact, Inc Ransom, Play, 3AM, DragonForce, Safepay, The Gentlemen, and Stormous all posted new victims — Stormous alone claims over 400 GB exfiltrated from multiple targets including jaggroup.com and maglificioliliana.com. No CISA KEV additions and no in-the-wild Chromium exploitation are reported in this window, but the correlation engine has rated the cross-sector ransomware activity at critical risk.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No critical-severity reports this window (correlation engine rated cross-sector ransomware trend at critical) |
| 🟠 **HIGH** | 26 | Chromium CVE-2026-13021–13038 batch; FBI Signal advisory; AI-coding-agent GitHub attack; Redact, Inc Ransom, Play, 3AM, DragonForce, Safepay, The Gentlemen, Stormous leak-site posts |
| 🟡 **MEDIUM** | 5 | Chromium CVE-2026-13027 (FileSystem UAF) and CVE-2026-13033 (Blink>InterestGroups OOB read); LastPass partner-breach via Klue; Telegram proxy phishing infrastructure |
| 🟢 **LOW** | 1 | Chromium CVE-2026-13034 (Passwords inappropriate implementation) |
| 🔵 **INFO** | 3 | BellingCat Kinahan cartel investigation; Schneier squid-fleet geopolitics; Telegram proxy artefact |

## 3. Priority Intelligence Items

### 3.1 FBI/CISA: Russian RIS Phishing Campaign Evolves to Steal Signal Backup Recovery Keys

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/)

The FBI and CISA have updated a March 2026 advisory warning that Russian Intelligence Services (RIS), publicly tracked as **UNC5792** and **UNC4221** and including officers embedded with the FSB Border Guards, have evolved their Signal-targeting phishing campaign. Where the original campaign attempted to steal verification codes, PINs, or trick victims into linking attacker-controlled devices, the new variant impersonates Signal support and walks victims through enabling Signal's Secure Backups feature, then asks them to paste the resulting Backup Recovery Key into chat under the pretext of resolving a "sync issue." Possession of the recovery key lets the attacker restore the victim's encrypted backup on their own device, exposing historical private and group messages. The agencies say the targeting set remains high-value: current and former US and international government officials, military personnel, political figures, journalists, and Ukraine-based officials. Attribution to RIS is explicit in the joint advisory.

Affected products/sectors: Signal Messenger (mobile clients); government, defence, journalism, NGO sectors.

#### Indicators of Compromise

```
Phishing pretext: "mandatory two-factor verification" following alleged
attacks "by hackers from Iran and post-Soviet countries"
Phishing pretext 2: "Your Signal Account data (messages and media) is at
risk of permanent loss due to a sync issue"
Account tracking: UNC5792, UNC4221 (Mandiant clusters)
ATT&CK: T1566 (Phishing), T1193 (Impersonation)
```

> **SOC Action:** Brief executive-protection and high-risk-user populations (especially Ukraine liaisons, journalists, and policy staff) that Signal will never request a Backup Recovery Key in-app. Where MDM is in place, audit whether Signal Secure Backups is enabled on managed devices and consider a temporary "do not enable backups" policy for high-risk users. Hunt mail and chat platforms for the verbatim pretext strings above; treat any inbound message asking a user to copy a recovery key to clipboard as confirmed phishing.

### 3.2 Microsoft Releases 14 Chromium Advisories (CVE-2026-13021 through 13038)

**Source:** [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-13038)

Microsoft published a coordinated batch of 14 Chromium advisories covering CVE-2026-13021 through CVE-2026-13038, ingested into Microsoft Edge (Chromium-based). The bulk are **use-after-free** memory-safety issues — CVE-2026-13026 (Digital Credentials), CVE-2026-13027 (FileSystem), CVE-2026-13029 (Web Authentication), CVE-2026-13031 (Blink), CVE-2026-13035 (Bluetooth), CVE-2026-13036 (Blink), and CVE-2026-13038 (Autofill) — exploitable for arbitrary code execution at the user's privilege level. The batch also includes input-validation flaws in DevTools (CVE-2026-13025) and Navigation (CVE-2026-13024), an inappropriate-implementation issue in DeviceBoundSessionCredentials (CVE-2026-13021) and Autofill (CVE-2026-13022), an uninitialised-use GPU bug (CVE-2026-13023), an out-of-bounds read in Blink>InterestGroups (CVE-2026-13033), and a Passwords implementation flaw (CVE-2026-13034). No in-the-wild exploitation is referenced by the source data, and the items have not appeared on the CISA KEV catalogue in this window. ATT&CK alignment from the entity data points to T1068 (Exploitation for Privilege Escalation) and T1059.001 (Windows Command Shell).

Affected products/sectors: Google Chrome, Microsoft Edge (Chromium-based), and downstream Chromium derivatives; cross-sector.

> **SOC Action:** Force a managed Edge / Chrome update cycle this week — push the channel update via Intune / WSUS / Chrome Enterprise policies and validate version compliance via EDR inventory. Prioritise endpoints used by privileged-account holders, developers, and high-risk-user populations. For unmanaged BYOD, push a user-facing reminder; the multiple UAF bugs in Blink, Bluetooth and Web Authentication are the kind of primitives historically chained into n-day exploit kits.

### 3.3 Clean GitHub Repo Weaponises AI Coding Agents (0DIN / Mozilla research)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/clean-github-repo-tricks-ai-coding-agents-into-running-malware/)

Mozilla's Zero Day Investigative Network (0DIN) demonstrated a supply-chain attack against AI coding agents — proof-of-concept run against Claude Code — that achieves a developer-privileged reverse shell **without placing any malicious code in the cloned repository**. The chain has three benign-looking components: (1) a clean GitHub repo with standard setup instructions; (2) a Python package intentionally designed to error out on first run, telling the user to execute `python3 -m axiom init`; and (3) the `init` invocation calls a shell script that pulls a configuration value from an attacker-controlled DNS TXT record and executes it as a command. Because the agent treats the initial error as a normal setup problem and self-heals by running the suggested command, the human-in-the-loop never sees the malicious step. 0DIN expects threat actors to distribute such repos via fake job postings, tutorials, blog posts, and direct messages. The technique is currently a research disclosure rather than a confirmed in-the-wild campaign, but it is directly applicable to any agentic coding workflow that auto-runs error-recovery commands.

Affected products/sectors: AI coding agents (Claude Code and equivalents); software-development sector.

#### Indicators of Compromise

```
Attack pattern: setup-error-driven command execution
Payload retrieval channel: DNS TXT record (attacker-controlled domain)
Sample setup command in PoC: python3 -m axiom init
ATT&CK: T1074 (Command and Scripting Interpreter), T1078 (Valid Accounts),
        T1205 (Redirect Network Traffic)
```

> **SOC Action:** Update developer-tooling policy to require human confirmation before any AI coding agent executes a command not present in the original prompt — vendor-side disclosure of full execution chains is the medium-term ask. In the short term, sink DNS TXT queries from developer workstations into your DNS telemetry (Umbrella, Quad9 logging, etc.) and alert on TXT lookups followed within 60 seconds by a shell process spawning under a developer's user account. Tighten egress controls on developer subnets so a freshly minted reverse shell cannot reach arbitrary IPs.

### 3.4 Ransomware Surge: Redact, Inc Ransom, Play, 3AM, DragonForce, Stormous

**Sources:** [RansomLook — Redact](https://www.ransomlook.io//group/redact), [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom), [RansomLook — Play](https://www.ransomlook.io//group/play), [RansomLook — 3AM](https://www.ransomlook.io//group/3am), [RansomLook — DragonForce](https://www.ransomlook.io//group/dragonforce), [RansomLook — Stormous](https://www.ransomlook.io//group/stormous), [RansomLook — Safepay](https://www.ransomlook.io//group/safepay), [RansomLook — The Gentlemen](https://www.ransomlook.io//group/the%20gentlemen)

The correlation engine rated cross-sector ransomware activity at **critical** risk based on multi-group posting cadence in the last 24 hours. Notable items: **Redact** named Hologic (medical imaging) and FCCI Insurance Group; **Inc Ransom** posted three US law-firm victims (callhorton.com, johndufourlaw.com, theswansonlawgroup.com), continuing a trend of legal-sector targeting and remains a top-10 trending threat actor pipeline-wide (18 reports); **Play** named J&J Gaming and Kuhnline, reusing intermittent-encryption techniques; **3AM** (Rust-based, `.threeamtime` extension, "0x666" marker) posted acemacon.org — recent 3AM campaigns reportedly use email bombing followed by vishing through Microsoft Quick Assist; **DragonForce** RaaS named Aptora; **Safepay** named hellmold-plank.de; **The Gentlemen** named Ayres Carr & Sullivan, P.C.; **Stormous** posted a "Data Leak Update" claiming over **400 GB** of exfiltrated data from multiple companies including jaggroup.com (corporate email, AD logins, plaintext passwords, Microsoft Dynamics GP databases) and maglificioliliana.com (product designs, customer databases, financial records). The Gentlemen is currently the highest-volume threat actor pipeline-wide (83 reports across the last 30 days).

Affected products/sectors: medical imaging, insurance, legal services, manufacturing, gaming, fashion/retail, education; geography is global.

#### Indicators of Compromise

```
3AM mail:        threeam@onionmail[.]org
3AM leak site:   threeamkelxicjsaf2czjyz2lc4q3ngqkxhhlexyfcp2o6raw4rphyad[.]onion
3AM chat:        threeam7fj33rv5twe5ll7gcrp3kkyyt6ez5stssixnuwh4v3csxdwqd[.]onion
3AM file:        .threeamtime extension; "0x666" marker
3AM TTP:         Microsoft Quick Assist abuse, VM-deployed backdoors
DragonForce:     z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid[.]onion/blog
DragonForce:     dragonforxxbp3awc7mzs5dkswrua3znqyx5roefmi4smjrsdi22xwqd[.]onion
Stormous leak:   pdcizqzjitsgfcgqeyhuee5u6uki6zy5slzioinlhx6xjnsw25irdgqd[.]onion
ATT&CK: T1486 (Data Encrypted for Impact), T1485 (Data Encrypted for Impact),
        T1566 (Phishing), T1078.004 (Valid Accounts: External Remote Services),
        T1496 (Resource Hijacking), T1003 (OS Credential Dumping)
```

> **SOC Action:** Block the listed `.onion` infrastructure at Tor egress points if Tor is not business-required (or alert on access). For 3AM specifically, audit Microsoft Quick Assist usage in EDR — query for `quickassist.exe` invocations preceded by an inbound voice call within 10 minutes, and confirm Quick Assist is disabled by GPO outside of help-desk groups. Customers in the legal, medical-imaging, fashion-manufacturing, and insurance verticals should treat themselves as on-list and re-validate backups, segmentation between corporate email and AD-joined file servers, and incident-response runbooks this week.

### 3.5 LastPass Customer Data Exposed via Partner Breach at Klue

**Source:** [Wired Security](https://www.wired.com/story/security-news-this-week-lastpass-users-had-their-data-stolen-again/)

LastPass notified customers of a data exposure resulting from a breach at AI business-intelligence firm **Klue**. Attackers compromised access tokens belonging to Klue customers (including LastPass) and pivoted into integrated platforms such as Salesforce, extracting customer names, phone numbers, email addresses, physical addresses, support-case data, and sales-related data. LastPass's own core infrastructure and password vaults are **not** reported as affected per the source. The attack pattern — abusing OAuth/access tokens issued to a SaaS analytics vendor to reach downstream platforms — fits a wider 2025–2026 pattern of supply-chain compromise via SaaS integration tokens.

Affected products/sectors: LastPass customer data; broader SaaS integration ecosystem (Salesforce among integrated downstream platforms).

> **SOC Action:** Inventory third-party OAuth and access tokens granted to BI / sales-intelligence vendors (Klue, Gong, ZoomInfo, Clari, etc.) into your Salesforce, HubSpot, and CRM tenants — revoke any unused, scope-minimise the rest, and enable IP allow-listing on the token where the vendor supports it. Warn customer-facing staff that LastPass customers may receive vendor-themed phishing leveraging the exposed contact and support-case data over the next 30–60 days.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware groups targeting multiple sectors with sophisticated techniques | Hologic By redact; FCCI Insurance Group By redact; J&J Gaming By play; Kuhnline By play (batch 199, 2026-06-27) |
| 🟠 **HIGH** | Increased use of phishing as a common attack vector across various sectors | FCCI Insurance Group By redact; Telegram proxy infrastructure; acemacon.org By 3am; LastPass / Klue partner breach (batch 199) |
| 🟠 **HIGH** | Increased targeting of technology sectors with sophisticated exploitation techniques | Chromium CVE-2026-13025 DevTools input-validation; reference to CISA Cisco-flaw exploitation deadline (batch 198, 2026-06-27) |
| 🟠 **HIGH** | Ransomware group Inc Ransom expanding targets across multiple sectors | callhorton.com By inc ransom; johndufourlaw.com By inc ransom; theswansonlawgroup.com By inc ransom (batch 198) |
| 🟡 **MEDIUM** | Phishing remains a prevalent TTP across diverse campaigns | FBI Signal advisory; SMB cyber readiness coverage (batch 198) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (83 reports) — currently the highest-volume actor in the pipeline; reusable parser-with-captcha infrastructure on Tor, 33% avg uptime.
- **Qilin** (65 reports) — sustained ransomware operations through late June.
- **Deadlock** (55 reports) — concentrated activity around mid-June 2026.
- **Lockbit5** (39 reports) — LockBit successor branding active through mid-June.
- **Akira** (32 reports) — continues broad-sector targeting; last seen 2026-06-26.
- **DragonForce** (24 reports) — RaaS cartel with shared affiliate infrastructure; new victim today (Aptora).
- **Nova** (22 reports) — sustained pipeline presence.
- **ShinyHunters / Shinyhunters** (20 + 20 reports; likely entity deduplication issue) — data-leak ecosystem.
- **Inc Ransom** (18 reports) — explicit cross-sector expansion called out in correlation trend; three new victims today.

### Malware Families

- **RansomLook** (143 reports) — pipeline tag attached to RansomLook-sourced leak-site posts (counts inflated by source attribution).
- **Tox1 / Tox** (64 + 41 reports) — Tox identifiers harvested from leak-site infrastructure.
- **Akira ransomware / Akira Ransomware** (15 + 10 reports; deduplication issue).
- **Lockbit5** (14 reports).
- **Nova** (11 reports).
- **RALord** (10 reports).
- **Deadlock** (10 reports).
- **3AM** (1 new report today) — sophistication trend: Quick Assist abuse + vishing + VM-deployed backdoors.
- **PLAYRansomware** (2 new reports today) — intermittent encryption to evade detection.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 14 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-13038) | Coordinated Chromium advisory batch CVE-2026-13021–13038 |
| RansomLook | 12 | [link](https://www.ransomlook.io/) | Leak-site posts from Redact, Inc Ransom, Play, 3AM, DragonForce, Safepay, The Gentlemen, Stormous |
| Unknown | 4 | — | Telegram proxy artefacts — links redacted per editorial policy |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/) | FBI Signal Backup Recovery Key advisory; AI-coding-agent GitHub attack |
| Wired Security | 1 | [link](https://www.wired.com/story/security-news-this-week-lastpass-users-had-their-data-stolen-again/) | LastPass / Klue partner-breach coverage |
| Schneier | 1 | — | Geopolitical / supply-chain context piece (no direct cyber IOCs) |
| BellingCat | 1 | [link](https://www.bellingcat.com/news/2026/06/27/poster-boy-sanctioned-kinahan-cartel-lieutenant-found-playing-padel-in-dubai/) | OSINT investigation; informational |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Push the Chromium-13021/13038 advisory batch through managed-browser update channels for Edge and Chrome this week — prioritise privileged users and developer workstations. (Section 3.2.)
- 🔴 **IMMEDIATE:** Issue a same-day brief to executive-protection, journalist, and Ukraine-liaison user populations that Signal Backup Recovery Keys must never be shared in chat, and audit MDM-managed devices for Signal Secure Backups configuration. (Section 3.1.)
- 🟠 **SHORT-TERM:** Restrict AI-coding-agent autonomous error recovery: require human approval before any agent executes a command not in the original prompt; instrument DNS TXT queries from developer subnets and alert on a TXT lookup followed by a shell-spawn within 60 seconds. (Section 3.3.)
- 🟠 **SHORT-TERM:** Customers in legal, medical-imaging, insurance, and fashion-manufacturing verticals should re-validate backup integrity, AD/email/file-server segmentation, and IR runbooks this week — five distinct groups posted new victims in those sectors in 24 hours. (Section 3.4.)
- 🟡 **AWARENESS:** Inventory and scope-restrict third-party OAuth/access tokens issued to SaaS BI vendors into Salesforce, HubSpot, and other CRM tenants; rotate any tokens issued to Klue specifically. (Section 3.5.)
- 🟢 **STRATEGIC:** Disable Microsoft Quick Assist by GPO outside of designated help-desk groups and add EDR detection for Quick Assist invocations preceded by an inbound voice call — counters the 3AM, Black Basta, and Storm-1811 playbook. (Section 3.4.)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 35 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
