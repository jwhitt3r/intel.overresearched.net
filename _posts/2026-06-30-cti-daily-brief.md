---
layout: post
title:  "CTI Daily Brief: 2026-06-30 - Phantom Squatting, ValleyRAT & Multi-Group Ransomware Sweep"
date:   2026-07-01 20:06:44 +0000
description: "14 reports across five sources: Unit 42 exposes AI-hallucinated domain squatting as a new supply chain vector; ValleyRAT campaigns target Chinese and Japanese users; and Play, Chaos, Aurora, and Payoutsking claim fresh victims across manufacturing, medical devices, and healthcare."
category: daily
tags: [cti, daily-brief, the-gentlemen, play, chaos, aurora, payoutsking, silverfox, valleyrat, phantom-squatting]
classification: TLP:CLEAR
reporting_period: "2026-06-30"
generated: "2026-07-01"
severity: high
draft: true
report_count: 14
sources:
  - BleepingComputer
  - RansomLook
  - SANS
  - AlienVault
  - Unit42
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-30 (24h) | TLP:CLEAR | 2026-07-01 |

## 1. Executive Summary

Fourteen reports were processed across five sources for the 24-hour window ending 2026-07-01, with nine rated **high** severity and no reports flagged critical at the individual report level. The dominant themes are AI-adjacent attack surface expansion and sustained ransomware pressure: Unit 42 disclosed *Phantom Squatting*, a new supply chain vector in which adversaries pre-register the fictional domains that LLMs hallucinate when advising developers, and BleepingComputer reported the *BioShocking* prompt-injection technique that coaxes agentic AI browsers into bypassing safety guardrails. AlienVault's LevelBlue team published fresh IOCs for two ValleyRAT vectors (fake installers plus Chinese/Japanese phishing lures) attributed to SilverFox, using Pool Party Variant 7 injection and BYOVD. RansomLook logged fresh victims for Play, Chaos, Aurora (883 GB exfiltrated from German medical device maker Halberstadt Medizintechnik), Payoutsking (Welldyne), and The Gentlemen (SDEZ). No CISA KEV additions were captured in this window, but AI-identified correlation trends flag ongoing critical-risk exploitation of GNU gzip (CVE-2026-41992) and libxml2 (CVE-2026-11979) from the preceding batch that operators should already be patching.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No individual reports; critical *trend* flag on GNU gzip / libxml2 CVEs |
| 🟠 **HIGH** | 9 | ValleyRAT, Phantom Squatting, BioShocking, PyPI/Pyrogram, Play/Chaos/Aurora/Payoutsking/The Gentlemen victims |
| 🟡 **MEDIUM** | 1 | Metamask secret-phrase phishing (SANS ISC) |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 4 | Anthropic Claude Fable/Sonnet 5 releases; Microsoft quantum-safe roadmap; SANS Stormcast |

## 3. Priority Intelligence Items

### 3.1 Phantom Squatting — LLM-hallucinated domains registered by adversaries as a supply chain vector

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)

Unit 42 researchers published a study of "phantom squatting" — the systematic registration of the fictional web domains that large language models hallucinate when they generate URLs for legitimate brands. Across 913 global brands and 685,339 URL queries against two LLMs, the team observed 2.1 million generated URLs, of which **over 13,229 were confirmed malicious** and approximately **250,000 remain unregistered and available for pre-emptive adversary acquisition**. The report highlights a live case in which an attacker used an AI coding assistant to build a phishing kit named *Montana Empire* targeting a domain the researchers had flagged as a high-risk hallucination candidate 23 days earlier — demonstrating a full LLM-prediction-to-registration lifecycle. Affected surfaces include AI coding assistants, CI/CD pipeline recommendations, and any developer workflow that copies LLM-generated URLs into build telemetry, webhook, or documentation configurations. MITRE mapping: T1566.

> **SOC Action:** Add an outbound URL allowlist policy for CI runners and developer workstations that blocks first-time-seen domains resolved from AI-assistant tool logs. Deploy DNS-layer alerting on newly-registered domains referenced in any build config, terraform manifest, or webhook URL committed in the last 30 days. Audit MCP tool outputs and AI-agent HTTP requests for domains not on the enterprise-approved list.

### 3.2 ValleyRAT — dual-vector campaign against Chinese and Japanese users, attributed to SilverFox

**Source:** [AlienVault (LevelBlue)](https://otx.alienvault.com/pulse/6a446c5df8b0ab9d5af62b64)

LevelBlue tracked two active ValleyRAT delivery vectors: (1) fake installers targeting Chinese-speaking users, deploying Pool Party Variant 7 process injection and BYOVD to disable defences; and (2) ZIP-attached phishing emails against Chinese and Japanese speakers containing EXE+DLL pairs that exploit DLL sideloading. Detection volume has nearly doubled year-on-year since May 2025. Evasion routines include junk-code insertion, memory-size checks, sleep-duration and process-count validation, and fileless execution via Donut-generated shellcode. Persistence is registry-based (T1547.001), followed by C2 payload retrieval. Attribution: intrusion-set **SilverFox**. MITRE mapping: T1027, T1027.002, T1055.012, T1070.004, T1082, T1083, T1105, T1112, T1140, T1204.002, T1218.011, T1497.001, T1497.003, T1547.001, T1566.001, T1566.002, T1574.002.

#### Indicators of Compromise
```
IPv4: 154.92.16[.]22
URL:  hxxp[:]//154.92.16[.]22/xz.bin
Host: frehf.oss-cn-hongkong.aliyuncs[.]com
```

> **SOC Action:** Block egress to 154.92.16[.]22 and the aliyuncs[.]com hostname at the perimeter and DNS layers. Hunt EDR telemetry for the Pool Party Variant 7 thread-injection sequence (NtCreateThreadEx into remote processes with anomalous start addresses) and for Donut-shellcode fileless execution patterns in wscript.exe/mshta.exe/rundll32.exe hosted from user temp directories. Alert on registry writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` originating from processes with sideloaded DLLs in non-standard paths.

### 3.3 BioShocking — prompt-injection framing that jailbreaks agentic AI browsers

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-bioshocking-attack-manipulates-ai-browser-into-data-theft/)

A new prompt-injection technique dubbed *BioShocking* wraps risky real-world actions inside fictional-scenario framings, causing AI-powered browsers to treat the harmful request as narrative content and skip safety checks. The reported outcome is data theft from browser sessions where the agent has authenticated access to user accounts. MITRE mapping: T1566.

> **SOC Action:** Restrict agentic-browser deployments in the enterprise to sandboxed profiles with no access to SSO cookies, corporate mailboxes, or secrets managers. Log every LLM-tool invocation and outbound POST from AI-browser sessions; alert on payloads that contain credentials, session tokens, or API keys. Where possible, pin agentic browsers to read-only tool sets pending vendor guardrail updates.

### 3.4 Malicious PyPI packages — trojanised Pyrogram forks hijack Telegram bot servers

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/)

A campaign active since November 2025 has been publishing trojanised forks of the popular Pyrogram library to PyPI, targeting Python developers building Telegram bots. Once installed, the packages grant attackers arbitrary file read on the compromised bot server, enabling secret and configuration theft plus pivoting into cloud environments. MITRE mapping: T1071.001, T1566.

> **SOC Action:** Query package manifests and lockfiles across bot infrastructure for any Pyrogram fork not published under the official `pyrogram` package name. Enforce hash pinning on Pyrogram installs and rotate Telegram bot tokens, cloud credentials, and any secrets accessible to affected hosts. Add PyPI typosquat detection to the pre-commit pipeline.

### 3.5 Ransomware sweep — five groups claim fresh victims in 24 hours

**Sources:** [Aurora leak site](https://www.ransomlook.io//group/aurora), [Chaos leak site](https://www.ransomlook.io//group/chaos), [Play leak site](https://www.ransomlook.io//group/play), [Payoutsking leak site](https://www.ransomlook.io//group/payoutsking), [The Gentlemen leak site](https://www.ransomlook.io//group/the%20gentlemen)

RansomLook logged fresh listings from five distinct ransomware operations in the reporting window:

- **Aurora — Primed Halberstadt Medizintechnik (Germany, medical devices):** ~2 TB claimed exfiltration across four server volumes including 289 employee home directories, Apollo ERP + VBANK banking with eight account credentials, DATEV accounting with LODAS payroll, and a 100.6 GB database backup dated 2026-06-03. Aurora also lists Corporación Primax S.A. (Peruvian fuel distribution, ~USD 3.4 B revenue) with plaintext SQL credentials, an AD encryption master key, and a full OT network map of 137 fuel stations.
- **Chaos (RaaS) — Universal Plant Services (universalplant.com):** 315 GB claimed, including financial audits, tax filings (ADP), payroll and bank transaction data. Chaos targets Windows, ESXi, Linux, and NAS with configurable fast/partial encryption; access routes are exploited public-facing services (T1190), phishing, or brokered credentials. MITRE mapping: T1071, T1190.
- **Play — Western Construction:** Play continues to use intermittent encryption to reduce detectable I/O patterns. Contact addresses on this listing include `marinachin@gmx[.]de`, `Nicolebackserami3@gmx[.]net`, and `reinaldo-jukes092@gmx[.]com`. MITRE mapping: T1027, T1071.001, T1486.
- **Payoutsking — Welldyne:** Non-RaaS operation, Tox-only communications, direct-to-victim ransom demands. Ransom-note filename observed: `readme_locker.txt`.
- **The Gentlemen — SDEZ:** Continues the group's high-volume tempo (103 tracked reports over the past month); correlation analysis links this actor to a zero-day EDR-disabling exploit reported in the preceding batch.

> **SOC Action:** Rotate any credentials for AD, ERP (Apollo, JD Edwards), payroll (DATEV/LODAS/ADP), and OT/SCADA systems that could plausibly appear in the Aurora or Chaos leak dumps for peer organisations. Block the Tox client protocol at the perimeter unless business-justified, and alert on Tox handshake traffic from workstations. For Play-exposed environments, hunt EDR telemetry for intermittent-encryption patterns (files with alternating encrypted/plaintext blocks) and add ransom-note filename `readme_locker.txt` and Play's `play.txt`/`ReadMe.txt`/`ReadMe2.txt` to file-integrity monitoring watchlists.

### 3.6 Metamask secret-phrase phishing (SANS ISC)

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/33118)

Xavier Mertens published a live phishing lure targeting Metamask users. Rather than attempting credential theft (which would fail against 2FA), the operator impersonates a wallet-risk warning and coerces the victim into surrendering their secret recovery phrase — the wallet's password-recovery secret. The campaign uses `captchasolve[.]help`, registered two days before the campaign appeared. MITRE mapping: T1566, T1189.

> **SOC Action:** Block `captchasolve[.]help` at DNS. Advise Web3-active staff that any request for a Metamask "secret recovery phrase" is a compromise attempt — no legitimate Metamask flow ever asks for the phrase outside the extension UI. Add awareness content specifically to distinguish "credential phishing" from "recovery-phrase phishing" for cryptocurrency-adjacent users.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software and systems | CVE-2026-41992 (GNU gzip buffer overflow); CVE-2026-11979 (libxml2 stack-based buffer overflow) — carried over from batch 204 |
| 🟠 **HIGH** | Increased use of phishing across diverse sectors and campaigns | Metamask secret-phrase phishing; Phantom Squatting; SDEZ (The Gentlemen); Halberstadt (Aurora); BioShocking; Pyrogram/PyPI |
| 🟠 **HIGH** | Ransomware targeting multiple sectors with varied TTPs | Play → Western Construction; Payoutsking → Welldyne; Chaos → Universal Plant Services; Aurora → Halberstadt Medizintechnik |
| 🟠 **HIGH** | Actor overlap: The Gentlemen using zero-day EDR-disabling exploit | Batch-205 correlation entry (confidence 0.90) linking "Not very gentlemanly" analysis with SDEZ leak listing |
| 🟠 **HIGH** | Shared TTPs between ValleyRAT and The Gentlemen EDR-bypass tooling | T1055 (process injection), T1112 (registry modification), T1082 (system information discovery) — confidence 0.75 |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (103 reports) — dominant ransomware actor of the month; live linkage to zero-day EDR-disabling exploit; adds SDEZ this cycle.
- **Qilin** (78 reports) — active RaaS; recent Chamco and Hemmersbach breaches (T1486, T1496.001).
- **Deadlock** (55 reports) — high-tempo mid-June activity.
- **Lockbit5** (39 reports) — sustained volume through mid-June.
- **Akira** (32 reports) — continued targeting into late June.
- **DragonForce** (27 reports) — regular presence through 29 June.
- **ShinyHunters** (22 reports) — tied to the NAIC PeopleSoft and Nissan Oracle zero-day breaches from earlier this week.
- **SilverFox** (this batch) — attributed operator behind ValleyRAT campaigns.

### Malware Families

- **RansomLook** (143 reports) — pipeline aggregator tag; indicator of overall leak-site volume.
- **Tox1 / Tox** (74 + 45 reports) — Tox-protocol infrastructure remains the communication substrate for The Gentlemen, Chaos, Payoutsking, and others.
- **Akira ransomware** (16 reports) — persistent operator toolset.
- **Lockbit5** (14 reports).
- **Qilin / Agenda / Chamco** (12 reports).
- **Anubis ransomware** (9 reports).
- **ValleyRAT** (this batch) — Chinese/Japanese-targeted RAT with BYOVD and Pool Party injection.
- **Pyrogram trojans** (this batch) — malicious Telegram-bot library forks on PyPI.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| BleepingComputer | 5 | [link](https://www.bleepingcomputer.com/) | Primary coverage of BioShocking, PyPI/Pyrogram, and three AI-industry info items |
| RansomLook | 5 | [link](https://www.ransomlook.io/) | Leak-site tracking: Play, Chaos, Aurora, Payoutsking, The Gentlemen |
| SANS | 2 | [link](https://isc.sans.edu/) | Metamask secret-phrase phishing diary + daily Stormcast |
| AlienVault | 1 | [link](https://otx.alienvault.com/) | LevelBlue ValleyRAT / SilverFox analysis with IOCs |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/) | Phantom Squatting supply chain research |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Confirm GNU gzip (CVE-2026-41992) and libxml2 (CVE-2026-11979) patch coverage from the preceding critical-risk trend is fully deployed across build hosts, CI runners, and container base images — these are still the pipeline's top critical-trend items.
- 🔴 **IMMEDIATE:** Block ValleyRAT infrastructure (154.92.16[.]22, `frehf.oss-cn-hongkong.aliyuncs[.]com`) at egress and DNS, and hunt for Pool Party Variant 7 injection sequences and BYOVD driver drops (§3.2).
- 🟠 **SHORT-TERM:** Inventory every AI coding assistant and agentic browser in the environment; disable autonomous outbound HTTP from those tools until a first-time-seen-domain allowlist is in place (§3.1, §3.3). Restrict agentic browsers to sandboxed profiles with no access to SSO or secrets.
- 🟠 **SHORT-TERM:** Audit Python bot repositories and lockfiles for non-canonical Pyrogram forks; rotate Telegram bot tokens and any secrets accessible from bot hosts (§3.4).
- 🟡 **AWARENESS:** Brief helpdesk and Web3-active staff on the Metamask secret-phrase phishing pattern and add `captchasolve[.]help` to the DNS blocklist (§3.6). Remind procurement, HR, and finance staff at manufacturers, medical-device firms, and healthcare providers of the elevated Aurora/Chaos/Play tempo against those sectors (§3.5).
- 🟢 **STRATEGIC:** Formalise a policy that any AI-generated URL, package name, or webhook endpoint referenced in code, IaC, or configuration must be verified against a curated allowlist before commit — LLM hallucination is now a demonstrated pre-registration attack surface (§3.1).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 14 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
