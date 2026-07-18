---
layout: post
title:  "CTI Daily Brief: 2026-07-15 - Zoom Critical Account Takeover Flaw, GitHub CLI RCE, and TELEPUZ MaaS via ClickFix"
date:   2026-07-16 20:15:00 +0000
description: "Zoom discloses critical unauthenticated account takeover flaw in Windows desktop client/SDK; Microsoft publishes CVE-2026-59831 GitHub CLI RCE; Elastic details TELEPUZ modular MaaS spreading via ClickFix-VIDAR; Operation Fake KickOff harvests corporate credentials via 232 phishing domains; ransomware pressure continues from Qilin, RansomHouse, Space Bears, and Cmd Organization."
category: daily
tags: [cti, daily-brief, zoom, telepuz, cve-2026-59831, shai-hulud, qilin, ransomhouse]
classification: TLP:CLEAR
reporting_period: "2026-07-15"
generated: "2026-07-16"
draft: true
severity: critical
report_count: 13
sources:
  - BleepingComputer
  - RansomLock
  - Microsoft
  - Elastic Security Labs
  - Unit42
  - AlienVault
  - SANS
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-15 (24h) | TLP:CLEAR | 2026-07-16 |

## 1. Executive Summary

Thirteen reports were processed from eight sources over the last 24 hours, dominated by a mix of vendor vulnerability disclosures, supply-chain intelligence, and ongoing ransomware leak-site activity. The single critical item is Zoom's disclosure of an unauthenticated account takeover vulnerability in its Windows desktop client and SDK. Microsoft published CVE-2026-59831, a remote code execution flaw in the GitHub CLI's `gh codespace jupyter` command that expands the ongoing exploitation of developer tooling. Elastic Security Labs disclosed TELEPUZ, a lightweight modular MaaS actively delivered via ClickFix-VIDAR chains, and Unit 42 updated its npm ecosystem threat landscape with a new July "miasma-train-p1" campaign against @asyncapi packages — the latest evolution of the post-Shai-Hulud wormable supply-chain era. On the ransomware side, Qilin, RansomHouse, Space Bears, and Cmd Organization all posted new victims across manufacturing, education, healthcare, and food service. No new CISA KEV additions or confirmed in-the-wild exploitation of the Zoom or GitHub CLI CVEs were reported in the collection.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | Zoom Windows desktop client / SDK account takeover |
| 🟠 **HIGH** | 9 | CVE-2026-59831 GitHub CLI RCE; TELEPUZ MaaS; npm supply chain (Shai-Hulud lineage); Operation Fake KickOff; SpaceX IPO crypto scam; Qilin, RansomHouse, Space Bears, Cmd Organization victims |
| 🟡 **MEDIUM** | 1 | Dutch police dismantle €100M investment fraud ring |
| 🔵 **INFO** | 2 | SANS ISC Stormcast (green); Meta NameTag face recognition analysis |

## 3. Priority Intelligence Items

### 3.1 Zoom Windows Client — Critical Unauthenticated Account Takeover

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/zoom-warns-of-critical-account-takeover-vulnerability/)

Zoom disclosed a critical vulnerability in the Zoom Windows desktop client and Windows SDK that permits an unauthenticated attacker to hijack accounts. The vendor advisory frames the flaw as exploitable without authentication, meaning any successful pathway to a vulnerable client can result in full account compromise — a materially different risk profile from typical Zoom CVEs that require an active meeting session. No confirmed in-the-wild exploitation is cited in the reporting, and no patched build number or CVE identifier appears in the source pulled by the pipeline.

**Affected products:** Zoom Workplace desktop client for Windows, Zoom SDK for Windows.

> **SOC Action:** Enumerate Zoom Windows client versions across the estate via EDR software inventory (or SCCM/Intune) and stage the vendor-released patched build as an emergency deployment. Until patched, block outbound `zoom.us` SDK traffic from non-standard host processes and alert on unexpected `Zoom.exe` or `CptService.exe` child-process chains. Rotate Zoom SSO tokens for any host whose client version cannot be verified.

### 3.2 CVE-2026-59831 — GitHub CLI `gh codespace jupyter` Remote Code Execution

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59831)

Microsoft (as maintainer of the GitHub CLI) published CVE-2026-59831, an RCE flaw in the `gh codespace jupyter` command. An authenticated GitHub CLI user who connects to a malicious Codespace with attacker-controlled Jupyter server settings can be induced to execute arbitrary commands on their own workstation due to improper input validation. Attack requires user execution (T1204) and command interpreter abuse (T1064) — meaning the initial-access vector is social (a lured "please open my Codespace" invite) rather than remote pre-auth. This lands the same day as the Unit 42 npm supply-chain update, and both feed a shared theme of adversaries weaponising developer tooling.

**Affected products:** GitHub CLI (`gh`) with the `codespace jupyter` command.

> **SOC Action:** Push the fixed `gh` CLI build via package managers (Homebrew, winget, apt) to all developer endpoints this cycle. Add a detection for `gh codespace jupyter` invocations followed by anomalous child processes of `gh` or `jupyter`, and educate engineering on the "invite to my Codespace" social-engineering pattern.

### 3.3 TELEPUZ — Modular MaaS Delivered via ClickFix-VIDAR

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix)

Elastic Security Labs published a reverse-engineering analysis of TELEPUZ, a modular, actively developed MaaS payload observed since late April 2026. Infection begins with a ClickFix social-engineering page that instructs the victim to paste and execute a PowerShell one-liner. That fetches a Go-based VIDAR variant (SHA256 `580b441e...`) from `hxxps[:]//memshowblob[.]forum/api/index.php?a=grab`, which in turn pulls the TELEPUZ stager `install.exe` and main DLL `telepuz.dll` from `hurgadatour[.]shop`. The main payload is a hand-written, obfuscated 64-bit DLL loaded via `rundll32`, communicating over WebSockets. Elastic assesses the volume of daily VirusTotal build uploads as consistent with an emerging MaaS.

**Affected sectors:** Broad — any Windows workstation susceptible to ClickFix lures; no specific vertical targeting reported.

#### Indicators of Compromise

```
Delivery domain:  hxxps[:]//memshowblob[.]forum/api/index.php?a=grab
Staging domain:   hurgadatour[.]shop
VIDAR stage 2:    580b441e2961739fd26e54e0a0ea08351cb10a51839519fc722cfa39ecd0c954
TELEPUZ stager:   03fa348b70819296c958c842e7646b3b7efe5fa217ed5098143003c47995a746
TELEPUZ main DLL: 58aec6e3835aaf20f7b4a7e308b36a19e7454673a6f71783871e9bcf6cae8eed
Filename lure:    f322a5fa.exe (dropped to %TEMP%)
```

MITRE ATT&CK: T1566 (Phishing), T1204 (User Execution), T1105 (Ingress Tool Transfer), T1071.001 (Web Protocols).

> **SOC Action:** Block `memshowblob[.]forum` and `hurgadatour[.]shop` at the proxy/DNS layer and add the three SHA256 hashes to EDR block lists. Hunt for PowerShell command lines containing `-NoP -w h -ep bypass` combined with `.'DownloadFile'` string concatenation, and for `rundll32.exe` loading DLLs from user %TEMP% subfolders. Alert on browser processes writing `.exe` files to `%TEMP%` followed by that file being executed within 60 seconds — the ClickFix signature.

### 3.4 npm Supply Chain — Miasma-Train-P1 Targets @asyncapi

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

Unit 42 refreshed its npm threat landscape report with a July 2026 campaign: on 14 July, attackers compromised the release pipelines of four AsyncAPI GitHub repositories and published five trojanised packages (`@asyncapi/generator@3.3.1`, `@asyncapi/specs@6.11.2` and `6.11.2-alpha.1`, `@asyncapi/generator-helpers@1.1.1`, `@asyncapi/generator-components@0.7.1`). The payload is assessed as a descendant of the Miasma RAT and continues the post-Shai-Hulud pattern of stealing npm tokens and GitHub PATs for wormable propagation, embedding in CI/CD for persistence, and using sleeper dependencies to evade scanners. Copycat activity is muddying attribution formerly assigned to TeamPCP.

**Affected products/sectors:** Software development organisations consuming AsyncAPI tooling; CI/CD pipelines with cached npm tokens or GitHub PATs.

> **SOC Action:** Pin `@asyncapi/*` versions below the compromised tags in `package.json` and `package-lock.json`, and audit CI runners for the five malicious versions. Immediately rotate any npm tokens and GitHub PATs that were resident on build agents between 14–15 July, and require repository admins to re-issue least-privileged, expiring PATs. Enable npm's provenance-verification and `--ignore-scripts` in CI where practical.

### 3.5 Operation Fake KickOff — Recruiter-Themed AiTM Credential Harvesting

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a57f26f4f7b83bede7d73d8)

A phishing operation active since April 2025 (tracked internally as O-UNC-038) uses 232 phishing domains and 80 C2 servers to harvest corporate credentials. Attackers impersonate HR consultancies — Robert Half and Aquent together account for ~50% of targeted brands — deliver lures via legitimate SaaS (Salesforce, SendGrid, Zoho), and route victims to fake Calendly pages. The AiTM toolkit uses browser-in-the-box to serve replica Google sign-in pages and can bypass MFA delivered by email, SMS, Google Authenticator, and push. Credentials are exfiltrated to Render-hosted servers and Telegram bots. Personal-email providers are filtered out at the lure — this is explicitly a corporate-credential operation.

**Affected sectors:** Cross-industry corporate targets; Google Workspace tenants over-represented.

#### Indicators of Compromise

```
Lure domains: adidas-hiring[.]com, fifahr-careers[.]com
Actor:        O-UNC-038
Exfil:        Render-hosted C2 + Telegram bots (channel details redacted)
```

MITRE ATT&CK: T1566 (Phishing), T1071.001 (Web Protocols), T1498 (Abuse Elevation Control Mechanism).

> **SOC Action:** Block the listed lure domains and hunt Google Workspace sign-in logs for successful authentications preceded by clicks on Calendly-style short URLs from external HR-branded senders. Enforce phishing-resistant FIDO2/passkeys for all Google Workspace admin accounts. Alert on Salesforce, SendGrid, and Zoho message envelopes whose display-name contains "Robert Half" or "Aquent" but whose Return-Path is external.

### 3.6 SpaceX IPO Cryptocurrency Investment Scam

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a57f270713faa71010c16ad)

Scammers are exploiting public interest in the SpaceX IPO with fraudulent investment portals impersonating SpaceX, Elon Musk, Fidelity, and Robinhood. Victims are walked through a legitimate-looking onboarding flow (W-8BEN forms for non-U.S. investors, tier selection) and directed to deposit BTC, ETH, or USDT to attacker wallets. Techniques mirror TA2730 but the objective is direct crypto theft rather than credential harvesting. One tracked Bitcoin wallet has received ~$8,700 to date.

#### Indicators of Compromise

```
Domains: muskspacexipo[.]com, muskspacexipo[.]vip, spacexshares[.]xyz,
         fidelityspacex[.]site, fidelityspacexipo[.]site, robinhoodspacex[.]com,
         adanispacex[.]com
Randomised: cd7yt860whhm7g7ylj8[.]live, zavpejjyz432d577l2e[.]live,
            hy0zu0fuf7rc2ou5aje[.]live, ogqw9cpz7t7et3j1rur[.]live,
            g8iqelymkc4eya9zs49[.]live, k1rg2oz4zpzw91pdx90[.]live,
            u7aq3ocwrexd70ulpdj[.]live, ddgaoylh4h420fvm7o5[.]live,
            467jtzbkqcfl22t9hxh[.]live, 8fv4dxp7lx035f8ylk7[.]live
Host:    mail.musksapcex[.]space
```

> **SOC Action:** Block the listed domains at the corporate DNS and web proxy, and push a warning through fraud-awareness channels for anyone monitoring SpaceX IPO news. Coordinate with the brand-protection function to submit takedown requests for the SpaceX, Fidelity, and Robinhood look-alike domains.

### 3.7 Ransomware Leak-Site Activity (Qilin, RansomHouse, Space Bears, Cmd Organization)

**Source:** [RansomLook](https://www.ransomlook.io) (aggregated leak-site tracker)

Four separate leak-site postings from the last 24 hours indicate continued RaaS pressure across food service, education, and business services. Qilin listed **Danone (International Delights)**; RansomHouse listed **Fidelity Services Group**; Space Bears listed **FITcrunch** alongside Turbosoft, Techpol-System, Biessse, and Blenheim; and Cmd Organization listed **Saint George's School** with Finance Yorkshire and Medlink Georgia. All four groups continue to rely on TOR-hosted data-leak sites and Jabber/Tox for negotiation. None of the postings confirm ransom payment or successful decryption.

**Affected sectors:** Food and beverage manufacturing (Danone), business services (Fidelity Services Group), fitness/nutrition (FITcrunch), education (Saint George's School).

> **SOC Action:** For each named victim organisation with which you have a supplier, customer, or partner relationship, initiate a third-party risk check today: confirm they have notified you if data was exposed, and review any shared credentials, API keys, or SFTP accounts. Ensure Qilin, RansomHouse, Space Bears, and Cmd Organization detection content is current in EDR and SIEM (TOR beacon signatures, `README-RECOVER-*.txt` file-creation events, and shadow-copy deletion attempts).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Increased phishing activities targeting multiple sectors with sophisticated campaigns | Saint George's School (Cmd Organization); FITcrunch (Space Bears); SpaceX IPO crypto scam; Operation Fake KickOff; Shared Claude Chats Meet ClickFix; June 2026 Infostealer Trend Report |
| 🟠 **HIGH** | Exploitation of software development tools for malicious purposes | CVE-2026-59831 (GitHub CLI `gh codespace jupyter` RCE); Unit 42 npm Threat Landscape (miasma-train-p1 against @asyncapi) |
| 🟠 **HIGH** | Cross-report reuse of T1566 Phishing as initial access | Correlated across 6+ reports in batch 233 including Fidelity Services Group (RansomHouse), Operation Fake KickOff, and Emerging Threat: QuimaRAT |
| 🟠 **HIGH** | Cross-report reuse of T1071.001 Web Protocols for C2 | RansomHouse leak-site activity; Operation Fake KickOff; QuimaRAT |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (92 reports) — Highest-volume actor in the pipeline over the last 30 days; no new activity in yesterday's window.
- **Qilin** (82 reports) — RaaS; new Danone (International Delights) victim posted yesterday.
- **Lockbit5** (36 reports) — Continued leak-site presence; no new posting in yesterday's window.
- **DragonForce** (35 reports) — Cross-sector RaaS; heavy activity in the 15 July correlation batch.
- **Akira** (24 reports) — Ongoing manufacturing/construction targeting.
- **ShinyHunters** (15 reports) — Recent Abbott/Exact Sciences correlation.
- **Cmd Organization** (14 reports) — Posted Saint George's School yesterday; active in education and healthcare.
- **RansomHouse** (indirect: featured in yesterday's batch) — Fidelity Services Group victim posted.

### Malware Families

- **RansomLook** (113 pipeline references) — Aggregator source, not a malware family; reflects the volume of leak-site reporting flowing into the pipeline.
- **Akira ransomware** (13 reports) — Ongoing manufacturing sector activity.
- **DragonForce ransomware** (11 reports) — Multi-victim campaign flagged in the 15 July correlation batch.
- **Qilin** (11 reports) — RaaS toolkit; new deployment against Danone.
- **Chaos Ransomware** (10 reports) — Continued Latin-American and retail targeting.
- **Anubis ransomware / banking trojan** (10 / 9 reports) — Steady mobile and endpoint presence.
- **TELEPUZ** (new this window) — Modular MaaS via ClickFix-VIDAR; Elastic disclosure.
- **Mini Shai-Hulud / Miasma** (new activity this window) — npm supply-chain wormable payload; @asyncapi trojanised packages.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 4 | [link](https://www.ransomlook.io) | Leak-site aggregation across Qilin, RansomHouse, Space Bears, Cmd Organization |
| AlienVault | 2 | [link](https://otx.alienvault.com) | Operation Fake KickOff and SpaceX IPO crypto scam pulses |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/zoom-warns-of-critical-account-takeover-vulnerability/) | Zoom critical vulnerability disclosure; Dutch investment-fraud takedown |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) | Updated npm supply-chain threat landscape |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33160) | ISC Stormcast (green threat level) |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix) | TELEPUZ MaaS reverse-engineering |
| Wired Security | 1 | [link](https://www.wired.com/story/heres-the-truth-about-whether-metas-nametag-face-recognition-exists/) | Meta NameTag face-recognition analysis |
| Microsoft | 1 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59831) | CVE-2026-59831 GitHub CLI RCE |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Deploy the Zoom Windows desktop client and SDK vendor patch as an emergency change; the pre-auth account-takeover primitive is severe enough to warrant out-of-cycle push. Rotate Zoom SSO tokens for any host that cannot be verified as patched (ref. 3.1).
- 🔴 **IMMEDIATE:** Block the TELEPUZ delivery infrastructure (`memshowblob[.]forum`, `hurgadatour[.]shop`) and the SpaceX-IPO crypto-scam domain list at DNS/proxy; add the three TELEPUZ SHA256s to EDR block lists (ref. 3.3, 3.6).
- 🟠 **SHORT-TERM:** Patch `gh` CLI across developer endpoints for CVE-2026-59831 and add detection for `gh codespace jupyter` followed by anomalous child processes. Brief engineering on "open my Codespace" social-engineering patterns (ref. 3.2).
- 🟠 **SHORT-TERM:** Audit CI runners for the five trojanised `@asyncapi/*` versions, rotate npm tokens and GitHub PATs resident on build agents between 14–15 July, and enforce provenance verification (ref. 3.4).
- 🟡 **AWARENESS:** Push a fraud-awareness note covering Operation Fake KickOff (recruiter-themed AiTM) and the SpaceX IPO crypto scam; both actively target end users right now (ref. 3.5, 3.6).
- 🟢 **STRATEGIC:** Stand up phishing-resistant FIDO2/passkey enforcement for Google Workspace admins and high-value corporate accounts — the AiTM toolkits proliferating this quarter defeat every non-FIDO2 MFA method (ref. 3.5).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 13 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
