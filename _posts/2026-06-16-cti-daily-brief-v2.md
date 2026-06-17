---
layout: post
title:  "CTI Daily Brief: 2026-06-16 - Malicious JetBrains plugins steal AI API keys; Space Bears ransomware leak hits Brazilian accounting firm"
date:   2026-06-17 20:05:50 +0000
description: "Six reports processed for the 24-hour window. Two high-severity items dominate: a coordinated JetBrains Marketplace plugin campaign exfiltrating AI provider API keys, and a Space Bears ransomware leak exposing Brazilian, Italian, German, and Chinese targets. AI correlation flags a broad uptick in T1566 phishing across diverse sectors."
category: daily
tags: [cti, daily-brief, space-bears, shinyhunters, jetbrains-marketplace]
classification: TLP:CLEAR
reporting_period: "2026-06-16"
generated: "2026-06-17"
draft: true
severity: high
report_count: 6
sources:
  - BleepingComputer
  - RansomLook
  - SANS
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-16 (24h) | TLP:CLEAR | 2026-06-17 |

## 1. Executive Summary

Six reports were processed across the 24-hour window from five distinct sources, with two rated **HIGH** severity. The day's dominant themes are credential theft via a supply-chain channel and continued ransomware data-leak activity. A coordinated campaign on the JetBrains Marketplace placed at least 15 malicious plugins—installed close to 70,000 times—designed to exfiltrate AI provider API keys (OpenAI, DeepSeek, SiliconFlow) over HTTP to `39.107.60[.]51`. Separately, the Space Bears ransomware group posted fresh victims including Brazilian accounting firm Gerencial Contábil (≈1,000 digital certificates plus 600,000+ files), China's ECOVACS (~2 TB), Italy's Cattani S.p.A., and Germany's Lösing Filtertechnik. AI correlation analysis identified a high-confidence trend of T1566 phishing being applied across both IDE-plugin and Android-banking-malware campaigns. No confirmed in-the-wild zero-day exploitation or CISA KEV additions appear in this window.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None this period |
| 🟠 **HIGH** | 2 | JetBrains plugin credential theft; Space Bears multi-victim ransomware leak |
| 🟡 **MEDIUM** | 0 | None this period |
| 🟢 **LOW** | 1 | Telegram proxy-distribution channel (unattributed) |
| 🔵 **INFO** | 3 | ShinyHunters infrastructure notice; SANS Stormcast; Wired Dialog Society leak |

## 3. Priority Intelligence Items

### 3.1 Malicious JetBrains Marketplace Plugins Exfiltrate AI Provider API Keys

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/)

Researchers at Aikido Security disclosed a coordinated campaign of at least 15 malicious JetBrains IDE plugins, published under seven vendor accounts, that have accumulated approximately 70,000 installations since first appearing in October 2025. Fresh plugins were still being published as recently as 10 June 2026. The plugins masquerade as AI coding assistants, code-review tools, and Git utilities powered by OpenAI, DeepSeek, and SiliconFlow. On clicking **Apply** after entering an API key, the plugin transmits the credential in plaintext over HTTP to a hardcoded server. BleepingComputer independently confirmed the credential-theft code is still present in the latest DeepSeek AI Assist build and the plugin remained available on the Marketplace at time of publication. A secondary "paid tier" returns AI API keys to paying users—likely keys harvested from free-tier victims—creating a closed-loop credential-laundering operation. Affected ecosystem: JetBrains IDE users (IntelliJ, PyCharm, GoLand, etc.) and any AI provider whose keys were entered into the affected plugins.

#### Indicators of Compromise

```
C2 (HTTP):    39.107.60[.]51
Endpoint:     hxxp://39.107.60[.]51/api/software/key

Plugin IDs (org/com identifiers):
  org.sm.yms.toolkit              (DeepSeek Junit Test)
  com.json.simple.kit             (DeepSeek Git Commit)
  org.bug.find.tools              (DeepSeek FindBugs)
  org.translate.ai.simple         (DeepSeek AI Chat)
  com.yy.test.ai.simple           (DeepSeek Dev AI)
  com.dev.ai.toolkit              (DeepSeek AI Coding)
  com.json.view.simple            (AI FindBugs)
  com.my.git.ai.kit               (AI Git Commitor)
  org.check.ai.ds                 (AI Coder Review)
  com.review.tool.code            (DeepSeek Coder AI)
  org.code.assist.dev.tool        (AI Coder Assistant)
  com.coder.ai.dpt                (DeepSeek Code Review)
  com.my.code.tools               (CodeGPT AI Assistant)
  ord.cp.code.ai.kit              (DeepSeek AI Assist)
  com.dp.git.ai.tool              (Coding Simple Tool)
```

ATT&CK mapping: **T1566 — Phishing** (social engineering via deceptive plugin branding), **T1048 — Exfiltration Over C2 Channel** (plaintext HTTP POST of stolen credentials).

> **SOC Action:** Inventory JetBrains IDE installations across developer endpoints — query EDR for the plugin IDs listed above (these map to `$USERPROFILE/.config/JetBrains/*/plugins/` on Linux/macOS and `%APPDATA%\JetBrains\<Product>\plugins\` on Windows). Block egress to `39.107.60[.]51` at the proxy and firewall. Force rotation of any OpenAI, DeepSeek, or SiliconFlow API keys held by developers who installed AI-related JetBrains plugins in the last eight months. Audit AI-provider billing dashboards for anomalous usage from unfamiliar source IPs.

### 3.2 Space Bears Ransomware Leak: Brazilian Accounting Firm and Multinational Manufacturers

**Source:** [RansomLook — Space Bears](https://www.ransomlook.io//group/space%20bears)

The Space Bears data-leak site posted Gerencial Contábil (Gerencial PR), a Paraná-based Brazilian accounting and business-advisory firm, listing roughly **1,000 personal digital certificates** (`.pfx`/`.p12` files) with corresponding passwords for Brazilian government portals, client contact details and credentials, and **600,000+ files** of personal information. The digital-certificate exposure is particularly serious: PFX files with known passwords would allow an actor to impersonate the firm and its clients across Brazilian tax, payroll, and government-services platforms. Adjacent victims posted by the same group within the window include China-based robotics manufacturer **ECOVACS** (~2 TB of stolen data), Italian dental-equipment manufacturer **Cattani S.p.A.** (employee/client PII plus 200,000+ files), and German filtration specialist **Lösing Filtertechnik**. The reporting source provides only victim listings and does not detail initial-access TTPs.

> **SOC Action:** Brazilian organisations or service providers with any historical relationship to Gerencial Contábil should treat the 1,000 leaked certificates as compromised: revoke any trust paths, rotate dependent credentials, and watch government-portal access logs for impossible-travel and certificate-presentation anomalies. For manufacturing and robotics sectors, monitor for outbound transfers to unfamiliar tor/onion infrastructure and double-check backup integrity given the data-volume signature (2 TB ECOVACS exfiltration). Pull RansomLook's Space Bears feed daily for additional victim disclosures.

### 3.3 ShinyHunters Posts Infrastructure Maintenance Notice

**Source:** [RansomLook — Shinyhunters](https://www.ransomlook.io//group/shinyhunters)

The ShinyHunters group posted a "Service Notice: Scheduled Maintenance and Infrastructure Upgrades" message on its leak portal. The notice details the uptime of associated onion services—some currently down, others fully operational—and republishes the group's PGP key. Pre-announced infrastructure changes by a high-volume extortion brand frequently precede new victim drops, rebranding, or a shift in TTPs. ShinyHunters is the tenth-most-mentioned threat-actor entity pipeline-wide over the last 30 days (20 reports for the lowercase variant; 22 reports for the capitalised variant).

> **SOC Action:** No immediate defensive action required. Tag this disclosure in threat-actor tracking dashboards as a possible precursor to renewed operational tempo and queue a ShinyHunters TTP refresh (historical T1190 web exploitation and T1078 valid-account use) on the next sprint of detection-engineering reviews.

### 3.4 Telegram Proxy Distribution (Low Severity — Tracking Only)

**Source:** Telegram (channel name redacted)

A Telegram-sourced post advertised a public proxy server (`cdn.ma-rd.co.uk:443`) marked with metadata pointing to a `*.yektanet.com` host. The activity is unattributed, the report carries low confidence as a discrete threat, and it is recorded here only because proxy-channel infrastructure is recurrently abused for circumvention and lightweight C2 relay.

> **SOC Action:** Add `cdn.ma-rd.co.uk` and the parent `yektanet.com` domain to watchlist (alert-only). No block required absent further enrichment.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Increased use of phishing techniques (T1566) across malware campaigns targeting diverse sectors | JetBrains Marketplace plugin theft; New Rokarolla Android malware (217 banking/crypto apps) |
| 🟠 **HIGH** | Targeting of critical-manufacturing sectors with denial-of-service vulnerabilities (carry-over from prior batch) | Rockwell Automation CompactLogix; Rockwell RSLinx; Logix 5370 & 5570 Controllers DoS via CIP |
| 🟠 **HIGH** | Exploitation of cloud-service vulnerabilities and misconfigurations (carry-over) | GCP `serviceData` deprecation analysis; Salesforce threat-hunter mapping |
| 🔴 **CRITICAL** | Ransomware groups leveraging double-extortion tactics and advanced techniques (carry-over) | Multiple Cloak data-leak postings |
| 🟡 **MEDIUM** | Technology and finance sectors under sustained targeting | Space Bears victim listings; Dialog Society leak |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (66 reports) — Highest-volume ransomware brand of the trailing 30-day window
- **The Gentlemen** (65 reports) — Sustained leak-site activity
- **Deadlock** (55 reports) — Recently surged
- **DragonForce** (40 reports) — Active across multiple sectors
- **Akira** (32 reports) — Continued mid-tier extortion volume
- **Nightspire** (29 reports) — Stable cadence
- **Nova** (27 reports) — Active
- **TeamPCP** (24 reports) — Active
- **ShinyHunters / Shinyhunters** (22 + 20 reports) — Posted infrastructure notice this window

### Malware Families

- **RansomLook** (141 reports) — Aggregator-tag, dominant feed signal
- **Tox1 / Tox** (41 + 24 reports) — High volume cluster
- **Other1** (30 reports) — Generic cluster label
- **RALord** (15 reports) — Active
- **Akira ransomware / Akira** (15 + 13 reports) — Aligns with Akira actor trend
- **Nova** (13 reports) — Cross-references Nova threat actor
- **Nightspire** (13 reports) — Cross-references Nightspire actor
- **Mini Shai-Hulud** (12 reports) — Ongoing supply-chain malware lineage

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 2 | [link](https://www.ransomlook.io/) | Space Bears victim leak + ShinyHunters infrastructure notice |
| BleepingComputer | 1 | [link](https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/) | Primary coverage of JetBrains plugin credential-theft campaign |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33082) | Daily ISC Stormcast (routine) |
| Wired Security | 1 | [link](https://www.wired.com/story/leak-exposes-members-of-peter-thiels-secretive-dialog-society/) | Dialog Society membership leak (non-cyber-intrusion data exposure) |
| Unknown | 1 | — | Telegram (channel name redacted) — proxy distribution |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Hunt for the 15 malicious JetBrains plugin IDs across developer endpoints and rotate any OpenAI, DeepSeek, or SiliconFlow API keys that may have been entered into AI-themed JetBrains plugins since October 2025. Block egress to `39.107.60[.]51` and alert on outbound HTTP to that host. Audit AI-provider billing portals for anomalous consumption.
- 🟠 **SHORT-TERM:** For Brazilian organisations or anyone in the Gerencial Contábil client chain, treat the 1,000 leaked digital certificates as compromised — revoke trust paths, rotate dependent credentials, and watch government-portal authentication logs for certificate-impersonation indicators.
- 🟠 **SHORT-TERM:** Audit IDE-plugin and developer-tooling install policies; most enterprises do not enforce code-signing review for JetBrains Marketplace plugins. Consider allowlisting and centralised plugin management via JetBrains Toolbox Enterprise or analogous controls.
- 🟡 **AWARENESS:** Track ShinyHunters' announced infrastructure changes as a potential precursor to renewed extortion campaigns; refresh detection content for the actor's typical T1190 / T1078 chain.
- 🟢 **STRATEGIC:** Phishing (T1566) continues to dominate correlation trends across unrelated campaigns. Re-validate phishing-resistant authentication coverage (FIDO2 / WebAuthn) for developer accounts, API key storage, and admin tooling; review whether sensitive secrets (AI API keys, cloud credentials) are siloed from interactive IDE prompts.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 6 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
