---
layout: post
title:  "CTI Daily Brief: 2026-06-05 - Everest Forms Pro RCE (CVE-2026-3300) actively exploited; Coinbase Cartel issues $200M demand"
date:   2026-06-06 20:06:15 +0000
description: "Active in-the-wild exploitation of CVE-2026-3300 (Everest Forms Pro) creating rogue WordPress admins. Coinbase Cartel posts Cambridge Mobile Telematics ($200M) and Demand.io. Krybit, Nova, Inc Ransom, Genesis, Play, and Blackwater continue ransomware churn against healthcare and manufacturing. Polyfill[.]io reactivation triggers credential-collection prompts on Toshiba and Muji."
category: daily
tags: [cti, daily-brief, coinbase-cartel, inc-ransom, nova, cve-2026-3300]
classification: TLP:CLEAR
reporting_period: "2026-06-05"
generated: "2026-06-06"
draft: true
severity: critical
report_count: 16
sources:
  - BleepingComputer
  - RansomLook
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-05 (24h) | TLP:CLEAR | 2026-06-06 |

## 1. Executive Summary

Sixteen reports were processed across two correlation batches in the last 24 hours, with one critical and ten high-severity items. The headline event is confirmed in-the-wild exploitation of **CVE-2026-3300** in the Everest Forms Pro WordPress plugin, where attackers are abusing a `sanitize_text_field()` weakness in the Complex Calculation feature to inject PHP into `eval()` and create rogue administrator accounts (Wordfence has blocked over 29,300 attempts; the recurring rogue username is `diksimarina`). The ransomware ecosystem remained the dominant signal: **Coinbase Cartel** (CoinBreach RaaS) posted two new victims including a $200M demand against **Cambridge Mobile Telematics** and a posting against **Demand.io**, while **Krybit**, **Nova** (RALord rebrand), **Inc Ransom**, **Genesis**, **Play**, and **Blackwater** continued churning leak-site victims across healthcare, manufacturing, education, and legal sectors. Separately, a reactivation of the abandoned **polyfill[.]io** CDN is triggering rogue HTTP 401 login prompts on Toshiba, Muji, Zojirushi, FiNC, Ishiyaku, Hobonichi, and reportedly some Samsung Smart TV pages. No CISA KEV additions were observed in today's data, but the Everest Forms Pro flaw meets the operational bar for emergency patch deployment.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | Everest Forms Pro CVE-2026-3300 actively exploited |
| 🟠 **HIGH** | 10 | Coinbase Cartel, Krybit, Nova, Inc Ransom, Genesis, Play, Blackwater leak-site activity |
| 🟡 **MEDIUM** | 4 | Polyfill[.]io resurrection; Inc Ransom (kelmreuter.com); Chinese peptide labs; Telegram proxy lure |
| 🟢 **LOW** | 0 | — |
| 🔵 **INFO** | 1 | Awesome Breach Intelligence resource listing |

## 3. Priority Intelligence Items

### 3.1 CVE-2026-3300 — Everest Forms Pro WordPress plugin actively exploited for full site takeover

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-everest-forms-pro-flaw-exploited-to-take-over-wordpress-sites/)

CVE-2026-3300 is an unauthenticated PHP code execution vulnerability in the Complex Calculation feature of Everest Forms Pro (versions ≤ 1.9.12). User input passed through `sanitize_text_field()` is not escaped for single quotes, allowing an attacker to close the wrapping PHP string literal, inject arbitrary PHP, and comment out the trailing code so that the injected payload is passed to `eval()`. Wordfence telemetry shows active exploitation since 2026-04-13, with over 29,300 blocked attempts. Observed payloads call `wp_insert_user()` to create a rogue administrator (the recurring username `diksimarina` is a strong post-compromise indicator). Patched in plugin version released 2026-03-18; researcher credit: h0xilo (via Wordfence). Affected products: any WordPress site running Everest Forms Pro ≤ 1.9.12. MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PHP), T1078 (Valid Accounts).

#### Indicators of Compromise
```
Source IP: 202.56.2[.]126
Source IP: 209.146.60[.]26
Indicator: WordPress admin account with username "diksimarina"
Artifact:  Calls to wp_insert_user() originating from Everest Forms Pro form submissions
Vuln:      CVE-2026-3300
```

> **SOC Action:** Inventory all WordPress estates for Everest Forms Pro and upgrade to the patched release (post 2026-03-18) immediately. For unpatched instances, temporarily deactivate the plugin or disable the Complex Calculation feature. Block 202.56.2[.]126 and 209.146.60[.]26 at perimeter and WAF. Run `wp user list --role=administrator` (or DB equivalent) across all sites and quarantine any account matching `diksimarina` or created since 2026-04-13 with no business justification. Search webserver access logs for POSTs to Everest Forms endpoints containing single quotes followed by `wp_insert_user`. Hunt for newly planted PHP webshells under `wp-content/uploads/` and `wp-content/plugins/`.

### 3.2 Coinbase Cartel posts Cambridge Mobile Telematics ($200M) and Demand.io on CoinBreach RaaS leak site

**Source:** [RansomLook — Coinbase Cartel](https://www.ransomlook.io//group/coinbase%20cartel)

The Coinbase Cartel — the RaaS operation behind the **CoinBreach** ransomware — published two fresh victim postings on 2026-06-05: **Cambridge Mobile Telematics** (telematics, $200M demand) and **Demand.io** (advertising, $10.5M). The leak site lists 183 total posts (19 in the last 30 days, 4 in the last 7) and shows a degraded but recovering infrastructure footprint (2 of 12 .onion services up, including a 100%-uptime parser and a 97%-uptime file server). Recent named victims on the same panel include Cognizant ($21.1B), Panasonic Aero ($2.7B), Siveco, Openmind Networks, Pragmatic Solutions, and Engie — a pattern of large-revenue technology, manufacturing, and aerospace targets. Communications channels observed: `coinbasecartel@atomicmail.io`, Tox, Session, and SimpleX. MITRE ATT&CK: T1566 (Phishing), T1486/T1485 (Data Encrypted for Impact).

#### Indicators of Compromise
```
Actor email: coinbasecartel@atomicmail[.]io
Onion (parser, up):       hxxp[:]//fjg4zi4opkxkvdz7mvwp7h6goe4tcby3hhkrz43pht4j3vakhy75znyd[.]onion/
Onion (file server, up):  hxxp[:]//iu6t4jcin7iexrdcgyspal6rsafyu4mw4tkdvugx4nmioxs7mbifdzad[.]onion/
Tox ID:     58041B45371485934F798C77F2F9705DA735F28AC9EBA2A19B4C9DBAF462802B88E33CEF482A
Session ID: 056999a0f3681d5deddb6243e9387c9b9a310f1bacc2a4faa1b9085a867887fb22
Malware family: CoinBreach
```

> **SOC Action:** If your organisation operates in telematics, advertising, or large-revenue tech/manufacturing, increase phishing-response sensitivity and validate inbound-email gateway dwell on Atomic Mail, Tox, and SimpleX domains. Cambridge Mobile Telematics customers should treat the disclosure as a third-party incident — request breach scoping (which datasets, period, customer-data exposure) and rotate any API keys, telematics feed credentials, or shared secrets. Hunt EDR for execution of unsigned binaries writing >100MB across multiple file shares within a 30-minute window (mass-encryption signature) and for outbound Tor traffic to the parser onion above. Block the observed .onion file-server hash where TLS inspection or DNS-over-HTTPS visibility allows.

### 3.3 Sustained ransomware leak-site activity against healthcare, manufacturing, and education (Krybit, Nova, Inc Ransom, Genesis, Play, Blackwater)

**Sources:** [RansomLook — Krybit](https://www.ransomlook.io//group/krybit), [RansomLook — Nova](https://www.ransomlook.io//group/nova), [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom), [RansomLook — Genesis](https://www.ransomlook.io//group/genesis), [RansomLook — Play](https://www.ransomlook.io//group/play), [RansomLook — Blackwater](https://www.ransomlook.io//group/blackwater)

Seven discrete leak-site postings in the 24-hour window form a clear sector-and-TTP correlation cluster (six AI-identified correlation entries, confidence 0.60–0.80). Healthcare appears in three postings — Aspire Hospital (Nova), `kelmreuter.com` (Inc Ransom), and `*B*` (Genesis) — alongside manufacturing (Pearson Ford / Play, `schultz.com.br` / Krybit, `huashan.com.cn` / Krybit, `obrieneng.com` / Inc Ransom) and education (Universitas Nasional / Nova). **Nova** is confirmed as the post-rebrand identity of **RALord** and continues to operate a captcha-protected RaaS panel with PGP and multiple onion services. The common TTP signal across the cluster is T1566 (Phishing) as the initial-access vector, followed by T1485/T1486 (Data Encrypted for Impact); Play continues to use its intermittent-encryption tactic to evade EDR-detected file-write rates. README-RECOVER.txt is a Krybit ransom-note indicator. MITRE ATT&CK: T1566, T1071.001, T1485, T1486.

> **SOC Action:** Healthcare, manufacturing, and education SOCs should re-validate email-gateway phishing controls (DMARC alignment, attachment sandboxing, link-rewrite click-time analysis) and confirm 24-hour offline backup integrity. Hunt EDR for the Play intermittent-encryption pattern: process opening a file, writing a partial buffer, sleeping briefly, and re-opening — a `CreateFile` → partial `WriteFile` → `CloseHandle` loop across thousands of files in <10 minutes. Add `README-RECOVER.txt` to file-creation watchlists and alert on its first appearance anywhere in shared storage. Verify lateral-movement detection on `T1078 - Valid Accounts` and constrain interactive RDP/SMB lateral hops from non-jump-host endpoints.

### 3.4 polyfill[.]io reactivation triggers rogue credential prompts on Toshiba, Muji, and other Japanese sites

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/suspicious-polyfill-login-prompts-pop-up-on-toshiba-muji-websites/)

The abandoned `polyfill[.]io` domain — compromised in 2024 when the original maintainer's domain expired and was acquired by an unrelated entity that injected malicious scripts — became active again in late May 2026 and is now responding with HTTP 401 challenges. Visitor browsers interpret these as authentication requests and surface native browser login prompts on websites that still reference the legacy polyfill CDN in their pages. Confirmed affected: **Toshiba**, **Muji**, **Zojirushi**, **FiNC Technologies**, **Ishiyaku Publishers**, **Hobonichi**, and reportedly some **Samsung Smart TV** pages (per researcher Pasquale Pillitteri). Both Toshiba and Muji have advised users who entered credentials in the prompt to reset their passwords; both have remediated the references. No confirmed credential exfiltration to date, but the prompt is a high-quality phishing primitive on otherwise-trusted domains.

> **SOC Action:** Run a one-time content sweep across all owned web properties for any remaining references to `polyfill[.]io` (grep CDN URLs in HTML, JS bundles, CMS templates, and inherited third-party tags). Replace with `polyfill.top` (the maintainer's current canonical) or remove the polyfill dependency. Add `polyfill[.]io` to corporate proxy block-lists to suppress prompts on user devices. Issue an internal advisory: "If you see an unexpected browser sign-in prompt on a brand-name site, click Cancel and report — do not type credentials." Pull a 30-day query of any user reporting unusual login prompts and triage for credential reuse.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in popular software plugins, indicating a trend toward targeting widely deployed platforms. | Critical Everest Forms Pro flaw exploited to take over WordPress sites |
| 🟠 **HIGH** | Increased ransomware activity targeting healthcare and manufacturing sectors globally. | utourworld.com (Blackwater), kelmreuter.com (Inc Ransom), *B* (Genesis) |
| 🟠 **HIGH** | Coinbase Cartel targeting technology and manufacturing sectors with CoinBreach ransomware. | Demand.io (Coinbase Cartel), Cambridge Mobile Telematics (Coinbase Cartel) |
| 🟠 **HIGH** | Widespread ransomware campaigns targeting multiple sectors with phishing as a common TTP. | huashan.com.cn (Krybit), Aspire Hospital (Nova), schultz.com.br (Krybit) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (79 reports) — Dominant RaaS operator across the 30-day window; not posted in today's set but remains the highest-volume actor in the pipeline.
- **The Gentlemen** (49 reports) — Continued elevated visibility; no postings in today's window.
- **Akira** (36 reports) — Sustained leak-site cadence; no postings in today's window.
- **DragonForce** (35 reports) — Active throughout the past month.
- **TeamPCP** (30 reports) — Persistent activity in the pipeline.
- **ShinyHunters** (28 reports) — Data-theft and extortion postings continuing.
- **Genesis** (22 reports) — Active today (`*B*` posting) targeting healthcare and legal sectors.
- **Nova** (21 reports) — Active today (Aspire Hospital, Universitas Nasional); confirmed RALord rebrand.
- **Inc Ransom** (19 reports) — Active today (`obrieneng.com`, `kelmreuter.com`).
- **Stormous** (17 reports) — Recent activity but no postings in today's window.

### Malware Families

- **RansomLook** (114 reports) — Aggregator/parser entity tag, not a malware family per se; dominates pipeline counts.
- **Tox1 / Tox** (22 / 21 reports) — Tox messaging IDs surfaced as malware-tagged entities across many RaaS profiles.
- **Akira ransomware** (19 reports) — Continued operational presence.
- **RALord** (12 reports) — Now operating as Nova; legacy tag still surfacing on older infrastructure.
- **Mini Shai-Hulud** (11 reports) — npm supply-chain malware wave from the prior month; no fresh activity today.
- **Nova** (11 reports) — Mirrors the actor entity above.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 11 | [link](https://www.ransomlook.io/) | Leak-site aggregation across Coinbase Cartel, Krybit, Nova, Inc Ransom, Genesis, Play, Blackwater |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com) | CVE-2026-3300 Everest Forms Pro exploitation and polyfill[.]io reactivation |
| Telegram (channel names redacted) | 2 | — | Telegram proxy lure and a breach-intelligence resource listing |
| Wired Security | 1 | [link](https://www.wired.com/category/security/) | Crypto-funded Chinese peptide labs and Meta AI account-hack vector |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Everest Forms Pro to the post-2026-03-18 release across all WordPress estates; block 202.56.2[.]126 and 209.146.60[.]26; hunt for and remove any administrator account named `diksimarina` or created since 2026-04-13 without business justification (Section 3.1).
- 🔴 **IMMEDIATE:** Cambridge Mobile Telematics customers — treat as a confirmed third-party data exposure; request scoping from the vendor, rotate any shared API keys/telematics-feed credentials, and pre-position incident-response retainers for downstream notification (Section 3.2).
- 🟠 **SHORT-TERM:** Healthcare, manufacturing, and education SOCs — re-validate email-gateway anti-phishing controls and confirm offline-backup recovery time against the active Krybit/Nova/Inc Ransom/Genesis/Play cluster; add `README-RECOVER.txt` to file-creation watchlists (Section 3.3).
- 🟡 **AWARENESS:** Sweep all owned web properties for legacy `polyfill[.]io` references and replace with `polyfill.top` or remove; block `polyfill[.]io` at the corporate proxy to suppress credential-prompt phishing on user devices (Section 3.4).
- 🟢 **STRATEGIC:** WordPress plugin sprawl continues to drive critical-severity events month over month — establish a managed inventory of all production plugins with a 7-day SLA for security patches and a 24-hour SLA for actively-exploited CVEs.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 16 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
