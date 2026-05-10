---
layout: post
title:  "CTI Daily Brief: 2026-05-09 - Lynx RaaS surge, Devs Palace ERP critical CVEs, Claude.ai chats abused for Mac infostealer"
date:   2026-05-10 20:15:00 +0000
description: "40 reports across 4 sources: critical Devs Palace ERP and Go/Vim CVEs, Lynx ransomware infrastructure expansion, FulcrumSec sells Avnet 7-12TB breach, and a malvertising campaign weaponising Claude.ai shared chats to deliver MacSync infostealer."
category: daily
tags: [cti, daily-brief, lynx, inc-ransom, fulcrumsec, macsync, cve-2026-45130, cve-2026-8221, devs-palace-erp]
classification: TLP:CLEAR
reporting_period: "2026-05-09"
generated: "2026-05-10"
draft: true
report_count: 40
severity: critical
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - Unknown
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-09 (24h) | TLP:CLEAR | 2026-05-10 |

## 1. Executive Summary

Forty reports were ingested across four sources in the last 24 hours, dominated by Microsoft vulnerability advisories (19) and RansomLook leak-site parsings (15). Four critical-severity items lead the brief: two Microsoft-published Go ecosystem flaws (CVE-2026-39826 html/template XSS bypass and CVE-2026-45130 Vim heap buffer overflow with potential RCE) and two unattributed disclosures for Devs Palace ERP Online up to 4.0.0 (CVE-2026-8221 and CVE-2026-8219), correlated with two earlier medium-severity CVEs in the same product (CVE-2026-8218, CVE-2026-8220) into a single ERP cluster. Ransomware operations remain the dominant high-severity theme: the Lynx RaaS posted eight new victims and continues to operate 28 of 37 onion services, while Inc Ransom and PEAR posted three more victims between them. FulcrumSec announced an exclusive sale of an alleged 7–12TB Avnet breach. No CISA KEV additions or confirmed in-the-wild exploitation were observed in the dataset.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | Devs Palace ERP CVE-2026-8221/8219; Vim heap overflow CVE-2026-45130; html/template XSS CVE-2026-39826 |
| 🟠 **HIGH** | 21 | Lynx RaaS posts (8); Inc Ransom (2); PEAR; FulcrumSec/Avnet; MacSync via Claude.ai chats; Microsoft Go/PgBouncer/Vim CVE batch |
| 🟡 **MEDIUM** | 14 | Go ecosystem hardening CVEs; PgBouncer DoS issues; Devs Palace ERP CVE-2026-8218/8220; Crimenetwork marketplace takedown |
| 🔵 **INFO** | 1 | RansomLook audit-team entry |

## 3. Priority Intelligence Items

### 3.1 Devs Palace ERP Online — four-CVE cluster up to v4.0.0

**Source:** Telegram (channel name redacted)

Four vulnerabilities were disclosed for Devs Palace ERP Online versions up to 4.0.0 within hours of each other: CVE-2026-8218, CVE-2026-8219, CVE-2026-8220 and CVE-2026-8221. CVE-2026-8219 and CVE-2026-8221 are rated critical with CVE-2026-8218 and CVE-2026-8220 rated medium; the AI correlation engine grouped all four into a single high-confidence (0.95) infrastructure cluster targeting the same ERP product. The originating reports carry TLP:AMBER+STRICT, contain no source URL, no public technical detail, no patch reference, and no vendor advisory. Affected sectors are wherever Devs Palace ERP Online is deployed (mid-market ERP customers).

> **SOC Action:** Inventory any Devs Palace ERP Online deployments. Until vendor patches and CVE detail are released, segment ERP application servers from general user networks, restrict outbound egress from those hosts, and prioritise authentication log review for anomalous admin-tier activity. Track NVD for CVE-2026-8218 through CVE-2026-8221 publication.

### 3.2 CVE-2026-45130 — Vim heap buffer overflow in spell file loading

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45130)

A heap buffer overflow in Vim's spell-file loader can be triggered by a maliciously crafted spell file and is reported as exploitable for arbitrary code execution. The companion advisory CVE-2026-44656 (high) covers OS command injection via Vim's `path` completion — both delivered together in the May 10 Microsoft advisory batch. Exploitation pattern aligns with `T1059` Command and Scripting Interpreter and `T1204` User Execution: a victim opens or sources an attacker-supplied file. No public PoC was referenced in the report.

> **SOC Action:** Prioritise Vim package updates across Linux, macOS and developer Windows hosts (WSL, Git Bash, embedded Vim in IDEs). Block ingress of `.spl` and untrusted `.vim` files via mail and file-share gateways. Hunt for Vim spawning unexpected child processes (shell, curl, wget, Python) in EDR.

### 3.3 CVE-2026-39826 — Escaper bypass enables XSS in html/template

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-39826)

A flaw in Go's `html/template` escaper allows attacker-controlled input to bypass auto-escaping and inject script context into rendered pages. A second related advisory, CVE-2026-39823 (medium), covers a meta content URL escaping bypass in the same package. Both flaws would be exposed by any Go web service that renders user input through standard library templating without additional sanitisation.

> **SOC Action:** Identify Go services that use `html/template` and update to the patched runtime/library versions referenced in the MSRC advisory. Audit user-input rendering paths and add WAF rules for typical XSS payloads on affected endpoints. Map Go service inventory via SBOM tooling.

### 3.4 Lynx RaaS — eight new victims, infrastructure largely intact

**Source:** RansomLock — [Lynx group page](https://www.ransomlook.io//group/lynx)

The Lynx ransomware-as-a-service operation posted eight victims in the last 24 hours: bayareaherbs.com, jacksoncountyin.com, st-annes.uk.com, lifelongaccess.org, www.kurita.eu, ossistemes.com, csb-battery.com and funkychunky.com. RansomLook reports 28 of 37 known Lynx services up, with 10 of 14 admin onion portals reporting 97–100% 30-day uptime. The May 10 evening correlation batch (id 115) anchors its landscape summary on Lynx, characterising the activity as a "coordinated effort in ransomware distribution." Mapped TTPs include `T1566` Phishing and `T1071` Application Layer Protocol. Sectors hit span US local government, food/beverage manufacturing, accessibility services and water/industrial chemistry.

> **SOC Action:** Block known Lynx clearnet domains (lynxblog[.]net, lynxchat[.]net, lynxstorage1[.]net) and tier 1 onion exit IPs at egress. In Tor-tolerant environments, alert on outbound TLS to Tor entry guards from servers. Hunt for `T1486` Data Encrypted for Impact precursors: rapid `vssadmin delete shadows`, `bcdedit /set safeboot`, and bulk renames from temp directories.

### 3.5 FulcrumSec offers Avnet data lake (alleged 7–12TB) for exclusive sale

**Source:** RansomLook — [FulcrumSec group page](https://www.ransomlook.io//group/fulcrumsec)

FulcrumSec's leak page advertises an exclusive single-buyer sale of Avnet's EMEA data lake, claiming 1.1TB compressed (7–12TB uncompressed) of `snappy.parquet` partitions covering sales strategies, customer lists, supplier lists, "proprietary AI training data," pricing models and Databricks infrastructure blueprints. The post claims the breach data was processed using Avnet's own OpenAI API keys during exfiltration. Group has 24 posts since first observation; two of four advertised endpoints are up. Contact channels listed are Tuta and proton-style mail, three Telegram handles and two Tox IDs.

> **SOC Action:** If your organisation operates Avnet integrations or shares a supply-chain footprint, monitor for downstream phishing or business-email compromise referencing leaked customer/supplier records. Rotate any shared API keys or Databricks workspace credentials with Avnet exposure. Track FulcrumSec leak page for evidence sample drops to inform breach scope.

### 3.6 Malvertising campaign weaponises Claude.ai shared chats to deliver MacSync infostealer

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-claudeai-chats-to-push-mac-malware/)

Researchers identified an active campaign using Google Ads sponsored results for "claude mac download" that direct victims to a publicly-shared Claude.ai conversation impersonating "Apple Support." The shared chat instructs the user to paste a base64-encoded command into Terminal, which fetches a polymorphic shell loader. The loader checks for Russian/CIS keyboard locales (silently exits with a `cis_blocked` ping if found), profiles external IP, hostname, OS version and locale, then stages a second payload via `osascript`. One observed variant deploys MacSync infostealer, which exfiltrates browser credentials, cookies and macOS Keychain contents. ATT&CK mapping: `T1566` Phishing (malvertising sub-technique), `T1071.001` Application Layer Protocol: Web Protocols, `T1204` User Execution.

#### Indicators of Compromise

```
URL (loader, BleepingComputer variant): hxxps[:]//bernasibutuwqu2[.]com/debug/loader.sh?build=a39427f9d5bfda11277f1a58c89b7c2d
URL (loader, Albayrak variant):         hxxp[:]//customroofingcontractors[.]com/curl/b42a0ed9d1ecb72e42d6034502c304845d98805481d99cea4e259359f9ab206e
Domain (C2, Albayrak variant):          briskinternet[.]com
Malware family:                         MacSync (macOS infostealer)
Loader:                                 loader.sh (polymorphic, gunzip-compressed shell)
Delivery vector:                        Google Ads sponsored search → Claude.ai shared chat
```

> **SOC Action:** Block the listed loader domains at proxy and DNS egress. Hunt EDR for `osascript` invocations spawned from `bash`/`zsh` originating from Terminal sessions in the last 14 days. Push internal guidance: never paste shell commands from search-result-linked chat transcripts; install Claude Code only via Anthropic's documented installer. Add detection for base64-encoded `curl | sh` patterns in user-typed Terminal input where instrumented.

### 3.7 Inc Ransom and PEAR — sustained leak-post cadence

**Source:** RansomLock — [Inc Ransom](https://www.ransomlook.io//group/inc%20ransom), [PEAR](https://www.ransomlook.io//group/pear)

Inc Ransom posted lopezlawfl.com and sibillacapital.com (US legal/financial sectors), continuing its 42-victim 30-day cadence; the AI correlation engine grouped both with 0.85 confidence under `T1566` Phishing → `T1486` Data Encrypted for Impact targeting healthcare and adjacent sectors. PEAR posted Langenberg, Strubberg, Arand & King, LLC (US accounting/tax/advisory) and operates a fully-up infrastructure (8/8 onion services) with 92% 30-day average uptime.

> **SOC Action:** For US legal, accounting and small-financial-services targets, harden externally exposed VPN/RDP/Citrix portals (Inc Ransom historically leverages valid credentials and exposed remote access). Deploy phishing-resistant MFA where missing. Hunt for `T1490` Inhibit System Recovery: shadow copy deletion and recovery partition tampering.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Critical vulnerabilities in Devs Palace ERP Online affecting global infrastructure | CVE-2026-8221, CVE-2026-8219 (and correlated CVE-2026-8218, CVE-2026-8220) |
| 🟠 **HIGH** | Increased ransomware activities targeting multiple sectors with overlapping TTPs | Inc Ransom posts: lopezlawfl.com, sibillacapital.com |
| 🟠 **HIGH** | Phishing as a common TTP across diverse ransomware campaigns | Inc Ransom posts and FulcrumSec/Avnet sale post |
| 🟠 **HIGH** | Lynx RaaS coordinated multi-sector campaign (batch 115 landscape summary) | bayareaherbs.com, jacksoncountyin.com, st-annes.uk.com, lifelongaccess.org, www.kurita.eu, ossistemes.com, csb-battery.com, funkychunky.com |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (100 reports) — sustained leak-site cadence over the last 30 days; no new posts in this 24h window.
- **The Gentlemen** (56 reports) — long-tail RaaS with continuing pipeline presence.
- **Akira** (50 reports) — cross-source coverage indicates sustained mid-cycle activity.
- **DragonForce** (30 reports) — phishing/credential-theft campaigns reported in earlier batches.
- **ShinyHunters** (29 reports) — recent focus on education sector (Canvas-related incidents).
- **Inc Ransom** (22 reports) — actively posted during the reporting window.
- **Lynx** (8 reports in this brief) — dominant theme of the May 10 evening batch.

### Malware Families

- **RansomLook** (90 reports) — leak-site parser metadata, present across most ransomware reports.
- **Tox1 / Tox** (35 / 17 reports) — peer-to-peer messaging used for ransom negotiation.
- **Akira ransomware** (26 reports) — encryption + extortion family with continuing tempo.
- **RaaS** (18 reports) — generic tag for RaaS infrastructure observations.
- **MacSync** (1 report, new) — first appearance of macOS infostealer in this pipeline window.
- **loader.sh polymorphic shell** (1 report, new) — delivery mechanism for the MacSync campaign.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 19 | [MSRC update guide](https://msrc.microsoft.com/update-guide) | Bulk Go ecosystem + Vim + PgBouncer CVE advisory drop |
| RansomLook | 15 | [ransomlook.io](https://www.ransomlook.io/) | Leak-site parsings: Lynx (8), Inc Ransom (2), PEAR (1), FulcrumSec (1), Krybit (1), Leak Bazaar (1), audit (1) |
| Unknown | 4 | — | Devs Palace ERP CVE-2026-8218/8219/8220/8221 (Telegram-origin, channel redacted) |
| BleepingComputer | 2 | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-claudeai-chats-to-push-mac-malware/) | MacSync malvertising story; Crimenetwork takedown |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Inventory and isolate Devs Palace ERP Online deployments (≤ v4.0.0); restrict ERP server egress and review admin authentication logs while awaiting vendor patches for CVE-2026-8218 through CVE-2026-8221.
- 🔴 **IMMEDIATE:** Patch Vim across all Linux, macOS and developer Windows endpoints (CVE-2026-45130 heap overflow + CVE-2026-44656 OS command injection); block untrusted `.spl`/`.vim` file ingress at mail and file-share gateways.
- 🟠 **SHORT-TERM:** Roll out the Microsoft May Go ecosystem advisory: rebuild and redeploy services using `html/template`, `cmd/go`, `golang.org/x/net` and `pgx`; CVEs covered include 39826, 39823, 41889, 42501, 39817, 39825, 33814 and 6664–6667.
- 🟠 **SHORT-TERM:** Push internal communications warning users that sponsored search results for AI-tool downloads (Claude, ChatGPT, etc.) may lead to attacker-controlled instruction sets; block MacSync loader IOCs (bernasibutuwqu2[.]com, customroofingcontractors[.]com, briskinternet[.]com) at DNS and proxy egress.
- 🟡 **AWARENESS:** US legal, accounting, and small-financial firms remain in Inc Ransom and PEAR target sets — verify external-access MFA coverage and shadow-copy/backup integrity.
- 🟢 **STRATEGIC:** If your organisation has an Avnet supplier or customer relationship, brief procurement and security operations on the FulcrumSec sale claim and pre-position incident response should samples or downstream phishing emerge.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 40 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
