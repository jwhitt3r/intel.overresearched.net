---
layout: post
title: "CTI Daily Brief: 2026-04-03 — DragonForce RaaS Cartel Surges, BQTLock Hits US Hospital, Device Code Phishing Explodes 37x"
date: 2026-04-04 20:05:00 +0000
description: "Ransomware-as-a-service operations dominated the threat landscape with DragonForce claiming five victims across pharma, manufacturing, and retail sectors while BQTLock exfiltrated 5.3TB from a US hospital. Device code phishing attacks surged 37x driven by EvilTokens PhaaS kits, and a six-wave GitHub Actions supply chain campaign compromised npm packages."
category: daily
tags: [cti, daily-brief, dragonforce, inc-ransom, bqtlock, eviltokens, supply-chain]
classification: TLP:CLEAR
reporting_period: "2026-04-03"
generated: "2026-04-04"
draft: true
severity: critical
report_count: 22
sources:
  - RansomLock
  - Wired Security
  - BleepingComputer
  - HaveIBeenPwned
  - Elastic Security Labs
  - Unit42
  - Wiz
  - RecordedFutures
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-03 (24h) | TLP:CLEAR | 2026-04-04 |

## 1. Executive Summary

The pipeline processed 22 reports from 8 sources over the past 24 hours, with 6 rated critical and 10 rated high. Ransomware-as-a-service operations dominated: DragonForce claimed five new victims spanning pharma (AUG Pharma, Kopran), manufacturing (Siam Okamura, G Plants), and tooling (Vietnam Fortress Tools), while BQTLock exfiltrated 5.3TB of patient data from Metro Hospital USA in a double-extortion attack demanding 400 XMR. INC Ransom added four new victims across legal, media, and construction sectors. Beyond ransomware, device code phishing attacks surged 37x year-to-date as the EvilTokens phishing-as-a-service kit and at least ten competing platforms democratised OAuth 2.0 device flow abuse. Wiz disclosed a six-wave GitHub Actions supply chain campaign (prt-scan) that compromised npm packages via `pull_request_target` misconfiguration. Meta paused work with data contractor Mercor after a TeamPCP-linked supply chain breach exposed proprietary AI training data.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 6 | DragonForce RaaS (5 victims); BQTLock hospital breach |
| 🟠 **HIGH** | 10 | INC Ransom (4 victims); device code phishing surge; prt-scan supply chain; Meta/Mercor breach; Anubis; Nightspire |
| 🟡 **MEDIUM** | 5 | Crunchyroll breach (1.2M accounts); Unit42 Bedrock agent research; LinkedIn extension scanning; FCC robocall fine |
| 🟢 **LOW** | 1 | Elastic Security Q1 2026 integrations roundup |

## 3. Priority Intelligence Items

### 3.1 DragonForce RaaS Cartel — Five New Victims in 24 Hours

**Source:** [RansomLock](https://www.ransomlook.io//group/dragonforce)

DragonForce, a ransomware-as-a-service group that pivoted from hacktivism to financially motivated operations in 2024, posted five new victims to its leak site within a single day: Siam Okamura International Co (manufacturing, Thailand), AUG Pharma (pharmaceutical, Egypt), G Plants (UK), Kopran (pharmaceutical, India), and Vietnam Fortress Tools JSC (manufacturing, Vietnam). The group operates a cartel-like affiliate network providing customisable payloads, a shared leak site, and an affiliate portal. DragonForce has previously targeted major UK retailers including M&S, Harrods, and Co-op.

TTPs include phishing for initial access (T1566), credential dumping (T1568), and network sniffing (T1078). The group uses Tor-based C2 infrastructure with PGP-signed ransom notes and encrypted Tox communication channels.

> **SOC Action:** Monitor for outbound connections to `.onion` domains via Tor proxy detection. Hunt for PGP-signed files with `.README.txt` extension patterns in shared drives. Review exposure of any affiliates or partners operating in pharmaceutical, manufacturing, or retail verticals.

### 3.2 BQTLock Ransomware Exfiltrates 5.3TB from US Hospital

**Source:** [RansomLock](https://www.ransomlook.io//group/bqtlock)

BQTLock (aka BaqiyatLock), a RaaS operation active since July 2025, breached Metro Hospital USA and exfiltrated 5.3TB of sensitive medical data including 123,458 patient records (radiology, EKG, MRI, ultrasound, blood work), complete email archives, SonicWall VPN access credentials, and internal backups. The group demands 400 XMR (~$52,000 at current rates) with a tiered payment model that escalates over time. BQTLock uses AES-256 encryption with RSA-4096 key protection, appends `.BQTLOCK` extensions, and drops `READ_ME-NOW_*.txt` ransom notes.

> **SOC Action:** Audit SonicWall VPN appliance firmware versions and enforce MFA on all VPN endpoints. Query EDR for processes writing files with `.BQTLOCK` extension or creating `READ_ME-NOW_*.txt` files. Healthcare organisations should verify backup isolation and test restoration procedures.

### 3.3 Device Code Phishing Surges 37x — EvilTokens and Ten Competing Kits

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/device-code-phishing-attacks-surge-37x-as-new-kits-spread-online/)

Device code phishing attacks exploiting the OAuth 2.0 Device Authorization Grant flow have surged 37x in 2026. The EvilTokens phishing-as-a-service kit is the primary driver, but at least ten competing platforms now offer similar capabilities: VENOM, SHAREFILE, CLURE, LINKID, AUTHOV, DOCUPOLL, FLOW_TOKEN, PAPRIKA, DCSTATUS, and DOLCE. These kits simulate legitimate services (Citrix ShareFile, DocuSign, Microsoft Teams, Adobe) to trick victims into entering device codes on real login pages, granting attackers persistent access via valid OAuth refresh tokens (T1566).

Kits leverage rotating API endpoints, anti-bot gates, Cloudflare Workers, GitHub Pages, and AWS S3 hosting to evade detection.

> **SOC Action:** Implement conditional access policies blocking device code authentication flows where not operationally required. Monitor Azure AD/Entra ID sign-in logs for `deviceCode` grant type authentications from unusual locations. Alert on token refresh patterns from previously unseen device registrations.

### 3.4 prt-scan: Six-Wave GitHub Actions Supply Chain Campaign

**Source:** [Wiz](https://www.wiz.io/blog/six-accounts-one-actor-inside-the-prt-scan-supply-chain-campaign)

Wiz Research disclosed a supply chain campaign exploiting GitHub's `pull_request_target` workflow trigger across six attack waves beginning 11 March 2026 — three weeks before public disclosure. A single actor operating under at least six GitHub accounts (testedbefore, beforetested-boop, 420tb, 69tf420, ezmtebo, and others) opened over 500 malicious pull requests targeting repositories with misconfigured CI/CD pipelines. The attacker exfiltrated `GITHUB_TOKEN` secrets, probed cloud metadata (AWS/Azure/GCP), and successfully compromised at least two npm packages. Payloads evolved from crude bash scripts to AI-generated, language-aware injections across conftest.py, package.json, Makefile, and build.rs files (T1575, T1020).

> **SOC Action:** Audit GitHub Actions workflows for `pull_request_target` triggers that check out PR head code. Rotate any `NPM_TOKEN` or cloud credentials exposed in CI environments. Review npm package integrity for unexpected version bumps in internal dependencies.

### 3.5 Meta/Mercor Breach — TeamPCP Supply Chain Attack Exposes AI Training Data

**Source:** [Wired Security](https://www.wired.com/story/meta-pauses-work-with-mercor-after-data-breach-puts-ai-industry-secrets-at-risk/)

Meta indefinitely paused all work with data contractor Mercor after a supply chain breach linked to TeamPCP compromised the AI API tool LiteLLM, exposing proprietary AI training datasets. A group claiming the Lapsus$ name offered alleged Mercor data for sale, including a 200+ GB database and ~1TB of source code, though researchers assess TeamPCP as the likely actor. OpenAI confirmed it is investigating the incident's impact on its proprietary training data. The breach highlights supply chain risk in the AI training data pipeline where contractors like Mercor, Surge, and Scale AI hold sensitive model-building assets.

> **SOC Action:** Organisations using LiteLLM should audit installed versions for known compromised releases and rotate API keys. Review third-party data contractor access controls and segment AI training infrastructure from production environments.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | RaaS operations accelerating with DragonForce cartel model | 5 DragonForce victims in 24h across pharma, manufacturing, retail |
| 🟠 **HIGH** | Multi-sector ransomware campaigns via INC Ransom and BQTLock | 4 INC Ransom victims (legal, media, IT, construction) + BQTLock hospital breach |
| 🟠 **HIGH** | Supply chain attacks exploiting public-facing CI/CD systems | prt-scan GitHub Actions campaign; Claude Code leak malware distribution |
| 🟠 **HIGH** | Phishing-as-a-service ecosystem expanding rapidly | 37x surge in device code phishing; 11+ active PhaaS kits identified |
| 🟡 **MEDIUM** | Phishing remains the dominant initial access vector across sectors | Phishing observed as shared TTP across ransomware, supply chain, and credential theft campaigns |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (39 reports) — Prolific ransomware operator targeting government and critical infrastructure
- **Nightspire** (31 reports) — Ransomware group with active darknet presence and healthcare targeting
- **TeamPCP** (29 reports) — Supply chain threat actor behind LiteLLM compromise and 1,000+ SaaS environment breaches
- **DragonForce** (24 reports) — RaaS cartel with affiliate model targeting UK retail, pharma, and manufacturing globally
- **Akira** (19 reports) — Ransomware group using double extortion across education, healthcare, and manufacturing
- **INC Ransom** (9 reports) — Ransomware operator using Tor-based infrastructure targeting legal, media, and corporate sectors

### Malware Families

- **DragonForce Ransomware** (23 reports) — Customisable RaaS payload with PGP-signed ransom notes and Tor C2
- **Akira Ransomware** (15 reports) — Double-extortion ransomware with broad sector targeting
- **Qilin Ransomware** (15 reports combined) — Ransomware variant associated with prolific Qilin operations
- **CanisterWorm** (7 reports) — Worm-type malware tracked across late March campaigns
- **Vidar** (5 reports) — Infostealer malware active in credential harvesting campaigns
- **EvilTokens** (1 report) — Device code phishing-as-a-service platform driving 37x attack surge

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 12 | [link](https://www.ransomlook.io) | DragonForce (5), INC Ransom (4), BQTLock, Anubis, Nightspire victim postings |
| Wired Security | 2 | [link](https://www.wired.com/category/security/) | Claude Code malware distribution; Meta/Mercor AI data breach |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com) | Device code phishing 37x surge; LinkedIn extension scanning |
| HaveIBeenPwned | 2 | [link](https://haveibeenpwned.com) | Crunchyroll (1.2M accounts); SongTrivia2 (291K accounts) |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | Q1 2026 security integrations roundup |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | Amazon Bedrock multi-agent prompt injection research |
| Wiz | 1 | [link](https://www.wiz.io/blog) | prt-scan GitHub Actions supply chain campaign (6 waves) |
| RecordedFutures | 1 | [link](https://therecord.media) | FCC $4.5M fine proposal for suspicious foreign call traffic |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Healthcare organisations should verify backup isolation, audit SonicWall VPN firmware, and enforce MFA on all remote access gateways following the BQTLock Metro Hospital breach exfiltrating 5.3TB of patient data.

- 🔴 **IMMEDIATE:** Block OAuth 2.0 device code authentication flows via conditional access policies where not operationally required. Monitor Entra ID sign-in logs for `deviceCode` grant type from unusual locations given the 37x phishing surge.

- 🟠 **SHORT-TERM:** Audit all GitHub Actions workflows for `pull_request_target` triggers and rotate any secrets (NPM_TOKEN, cloud credentials) potentially exposed in CI/CD environments following the prt-scan supply chain campaign.

- 🟠 **SHORT-TERM:** Organisations using LiteLLM or working with AI data contractors should audit installed versions against known compromised releases and rotate all associated API keys following the TeamPCP/Mercor breach.

- 🟡 **AWARENESS:** The DragonForce RaaS cartel posted five victims in a single day across pharmaceutical, manufacturing, and retail sectors. Organisations in these verticals should review ransomware playbooks, test incident response procedures, and validate endpoint detection coverage for `.README.txt` ransom note drops and Tor-based C2 traffic.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 22 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
