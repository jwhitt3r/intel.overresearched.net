---
layout: post
title:  "CTI Daily Brief: 2026-04-12 - Adobe Acrobat zero-day CVE-2026-34621 added to CISA KEV; DPRK npm package targets Polymarket; FBI/Indonesia dismantle W3LL PhaaS"
date:   2026-04-13 20:06:19 +0000
description: "66 reports processed. Adobe Acrobat/Reader zero-day (CVE-2026-34621) under active exploitation joined CISA KEV alongside six other CVEs. DPRK Lazarus pushes malicious npm package targeting Polymarket trading bots. FBI and Indonesian authorities seize W3LL phishing-as-a-service and arrest its developer. DragonForce and Coinbase Cartel drive a RaaS surge."
category: daily
tags: [cti, daily-brief, lazarus-group, dragonforce, qilin, cve-2026-34621, phantompulse, storm-stealer]
classification: TLP:CLEAR
reporting_period: "2026-04-12"
generated: "2026-04-13"
draft: true
report_count: 66
severity: critical
sources:
  - BleepingComputer
  - AlienVault
  - CISA
  - Elastic Security Labs
  - RansomLock
  - RecordedFutures
  - SANS
  - Schneier
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-12 (24h) | TLP:CLEAR | 2026-04-13 |

## 1. Executive Summary

Sixty-six reports were processed across ten sources in the last 24 hours, with three critical items and forty high-severity items dominating the feed. The day's headline item is Adobe's emergency patch for **CVE-2026-34621**, an actively exploited Acrobat/Reader zero-day being used to execute arbitrary code via malicious PDFs — CISA added the CVE to the KEV Catalogue on the same day alongside six other exploited vulnerabilities. In parallel, a DPRK-attributed (Lazarus/Famous Chollima) npm package `sleek-pretty@1.0.0` was published to target Polymarket trading-bot developers, exfiltrating CLOB API keys and Ethereum wallet private keys and installing SSH backdoors on Linux hosts. The FBI Atlanta Field Office and Indonesian authorities dismantled the W3LL phishing-as-a-service platform and arrested its developer, a first of its kind joint enforcement action. Ransomware-as-a-Service activity remained the dominant theme with DragonForce, Coinbase Cartel, and Qilin driving the majority of new victim listings on the RansomLock leak-site feed.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 3 | Adobe Acrobat/Reader zero-day (CVE-2026-34621); DPRK npm package (sleek-pretty) targeting Polymarket |
| 🟠 **HIGH** | 40 | CISA KEV additions; FBI W3LL takedown; PhantomPulse RAT via Obsidian; OpenAI macOS cert rotation; Storm infostealer; DragonForce/Qilin/Coinbase Cartel ransomware victim listings |
| 🟡 **MEDIUM** | 6 | Booking.com PIN reset; Basic-Fit breach; Rockstar Games cloud-analytics breach claim; eraleign (apt73) leak-site entries |
| 🟢 **LOW** | 0 | No reports in period |
| 🔵 **INFO** | 17 | Schneier (AI trust, Mythos); Wired (Meta facial recognition); BreachForums channel chatter; SANS ISC Stormcast |

## 3. Priority Intelligence Items

### 3.1 Adobe Acrobat/Reader Zero-Day Under Active Exploitation (CVE-2026-34621)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/adobe-rolls-out-emergency-fix-for-acrobat-reader-zero-day-flaw/), [AlienVault](https://otx.alienvault.com/) (Adobe Reader 0-day)

Adobe released an emergency out-of-band update for Acrobat and Acrobat Reader to patch **CVE-2026-34621**, a prototype-pollution/sandbox-escape flaw that has been exploited in zero-day attacks since at least December 2025. The exploit abuses privileged JavaScript APIs — specifically `util.readFileIntoStream()` to read arbitrary local files and `RSS.addFeed()` to exfiltrate data and fetch additional attacker-controlled code — with no user interaction required beyond opening a malicious PDF. An in-the-wild sample (`yummy_adobe_exploit_uwu.pdf`) was surfaced by EXPMON's Haifei Li; researcher Gi7w0rm reports Russian-language oil-and-gas-themed lures carrying the exploit. Adobe initially rated the flaw CVSS 9.6 (network) before downgrading to 8.6 (local). CISA added the CVE to its KEV Catalogue the same day (see §3.3).

Affected versions:

- Acrobat DC / Acrobat Reader DC ≤ 26.001.21367 → fixed in 26.001.21411
- Acrobat 2024 ≤ 24.001.30356 → fixed in 24.001.30362 (Windows) / 24.001.30360 (macOS)

MITRE techniques: T1203 (Exploitation for Client Execution), T1064 (Scripting), T1071.001 (Web Protocols C2).

> **SOC Action:** Push the Adobe Acrobat/Reader update to all endpoints today via your patch-management platform; prioritise engineering, finance, and any function handling external oil-and-gas-sector PDFs. Until deployment completes, hunt in EDR for `AcroRd32.exe` or `Acrobat.exe` spawning `powershell.exe`, `cmd.exe`, or `mshta.exe`, and for outbound HTTP from Acrobat processes. Quarantine any PDFs matching the filename pattern `*_exploit_*.pdf` or exhibiting RSS.addFeed() abuse. Update EDR PDF-sandbox detection rules to alert on file reads originating inside the Acrobat renderer sandbox.

### 3.2 DPRK Lazarus npm Package Targets Polymarket Traders (sleek-pretty)

**Source:** [Panther / AlienVault](https://panther.com/blog/polymarket-trader-funds-at-risk-dprk-npm-package-steals-wallet-keys)

A new npm package, `sleek-pretty@1.0.0`, was published on 10 April 2026 by account `probull02` (`pro.bull02@outlook.com`) and attributed with high confidence to DPRK's **Lazarus Group / Famous Chollima**. The package masquerades as a logging utility but executes malicious code at `require()` time (no install hook), running four attack chains: system fingerprinting, SSH-key persistence on Linux hosts (`authorized_keys` write), filesystem exfiltration of developer secrets, and targeted theft of **Polymarket CLOB API credentials and L1 Ethereum/Polygon wallet private keys**. The payload specifically hunts SDK files `createClobClient.ts` and `clob.ts` rather than scanning generically — indicating prior research on Polymarket bot-developer workflows. Polymarket carries roughly $477M in open interest and $9.7B monthly trading volume, so one compromised bot developer can expose multiple third-party traders. This campaign extends a 2024–2025 StepSecurity-documented effort with added SDK-specific targeting and persistent SSH access.

MITRE techniques: T1204 (User Execution), T1059.001 (Bash), T1071.002 (Web Protocols), T1003 (OS Credential Dumping).

#### Indicators of Compromise

```
npm package: sleek-pretty@1.0.0 (publisher: probull02, pro.bull02@outlook.com)
Domain:      mywalletsss[.]store
Hostname:    api.mywalletsss[.]store
URL:         hxxp[://]api.mywalletsss[.]store/api/validate/system-info
URL:         hxxps[://]api.mywalletsss[.]store/api/validate/files
URL:         hxxps[://]api.mywalletsss[.]store/api/validate/project-env
URL:         hxxps[://]api.mywalletsss[.]store/api/validate/system-info
Persistence: ~/.ssh/authorized_keys write (Linux hosts)
```

> **SOC Action:** Block `mywalletsss[.]store` and `*.mywalletsss[.]store` at web proxy, DNS, and firewall. Query package registries (internal Verdaccio, Artifactory, npm audit logs) for any install of `sleek-pretty` and remediate any host that imported it. For Linux developer workstations, diff `~/.ssh/authorized_keys` against a known-good baseline and rotate any SSH keys on suspect hosts. For teams building on `@polymarket/clob-client`, enforce Polymarket CLOB API key rotation and sweep `.env` files from repositories. Add a CI/CD guardrail that blocks newly published npm packages (<30 days old) from low-reputation publishers.

### 3.3 CISA Adds Seven Vulnerabilities to KEV Catalogue

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/04/13/cisa-adds-seven-known-exploited-vulnerabilities-catalog)

CISA added seven CVEs to the Known Exploited Vulnerabilities Catalogue on 13 April 2026, all with evidence of active exploitation. FCEB agencies must remediate by the BOD 22-01 due date; CISA urges all organisations to prioritise these:

- **CVE-2026-34621** — Adobe Acrobat & Reader prototype-pollution (see §3.1)
- **CVE-2026-21643** — Fortinet SQL Injection
- **CVE-2025-60710** — Microsoft Windows link-following
- **CVE-2023-36424** — Microsoft Windows out-of-bounds read
- **CVE-2023-21529** — Microsoft Exchange Server deserialization of untrusted data
- **CVE-2020-9715** — Adobe Acrobat use-after-free
- **CVE-2012-1854** — Microsoft Visual Basic for Applications insecure library loading

> **SOC Action:** Run an authenticated vulnerability scan with a KEV-aware profile, triaging to patch all seven CVEs within 21 days (sooner for CVE-2026-34621, CVE-2026-21643, and CVE-2023-21529 given recency of exploitation). For legacy Exchange Server, confirm November 2023 cumulative updates are applied or deprecate the server. For the VBA CVE (CVE-2012-1854), audit for any Office installation older than 2013 still in production and retire.

### 3.4 FBI and Indonesia Dismantle W3LL Phishing-as-a-Service Platform

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-takedown-of-w3ll-phishing-service-leads-to-developer-arrest/), [RecordedFuture](https://therecord.media/)

The FBI Atlanta Field Office and Indonesian authorities seized the **W3LL Store** phishing-as-a-service marketplace and arrested its alleged developer — the first joint U.S.–Indonesia enforcement action targeting a phishing-kit developer. W3LL Store operated between 2019 and 2023, selling a $500 phishing kit capable of building adversary-in-the-middle (AiTM) replicas of Microsoft 365 login portals to harvest credentials and authentication session tokens, defeating MFA. Investigators link the platform to more than 17,000 victims targeted 2023–2024 and ≥25,000 compromised accounts sold through the W3LLSTORE marketplace, facilitating over $20M in attempted fraud (primarily BEC). After the original shutdown, the kit was rebranded and continued selling via encrypted messaging platforms.

MITRE techniques: T1566 (Phishing), T1071.001 (Web Protocols).

> **SOC Action:** The takedown disrupts one PhaaS operation but AiTM kits remain prevalent. Confirm Conditional Access policies enforce token-binding, sign-in-frequency re-auth, and unfamiliar-sign-in blocking for all Microsoft 365 tenants. Hunt Entra ID sign-in logs for token-replay patterns: the same session ID from mismatched IPs/countries within a short window. Prioritise rule to alert on inbox rules created shortly after sign-in from a new ASN (BEC precursor).

### 3.5 PhantomPulse RAT Delivered via Obsidian Plugin Abuse (REF6598)

**Source:** [Elastic Security Labs](https://www.elastic.co/security-labs/phantom-in-the-vault)

Elastic Security Labs detailed a novel campaign tracked as **REF6598** in which threat actors posing as a venture-capital firm on LinkedIn and Telegram pivot targets in the financial and cryptocurrency sectors into opening a shared Obsidian cloud vault. The vault abuses Obsidian's legitimate community plugin ecosystem — specifically the **Shell Commands** and **Hider** plugins — to silently execute code once the victim enables community plugin sync. The cross-platform chain delivers a previously undocumented, heavily AI-generated Windows RAT named **PHANTOMPULSE** (loaded in-memory via AES-256-CBC decryption, timer queue callbacks, and module stomping, with C2 resolution via Ethereum transaction data) and an obfuscated macOS AppleScript dropper with Telegram-based fallback C2. Elastic notes a weakness in PHANTOMPULSE's C2 resolution allows defenders to take over implants.

MITRE techniques: T1566 (Phishing), T1204.002 (User Execution: Legitimate Software), T1137 (External Remote Services), T1218 (Signed Binary Proxy Execution), T1070.004 (File Deletion).

> **SOC Action:** Audit developer and research-staff endpoints for Obsidian installations and block or alert on the `Shell Commands` and `Hider` community plugins via MDM/EDR allow-listing. On Windows, hunt for PowerShell or cmd child processes whose parent is `Obsidian.exe`. On macOS, alert on `osascript` spawned from `Obsidian.app`. Block outbound connections from Obsidian processes to non-sync domains, and review LinkedIn/Telegram-originated "VC" outreach in security awareness programmes.

### 3.6 OpenAI Rotates macOS Code-Signing Certificates after Axios Supply-Chain Compromise

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/openai-rotates-macos-certs-after-axios-attack-hit-code-signing-workflow/)

OpenAI is rotating macOS code-signing certificates used for ChatGPT Desktop, Codex, Codex CLI, and Atlas after a GitHub Actions workflow executed the compromised **Axios 1.14.1** npm package on 31 March 2026. The Axios supply-chain attack is attributed to North Korean threat actor **UNC1069**, who social-engineered a maintainer via fake web-conference calls, gained account access, and published malicious versions to npm. OpenAI reports no evidence its signing certificate was used to distribute malicious binaries but is rotating out of caution. The previous certificate will be fully revoked on **8 May 2026**; older macOS client builds will stop working at that point.

> **SOC Action:** Audit CI/CD pipelines (GitHub Actions, GitLab Runners, Jenkins) for dependencies pinned to `axios@1.14.1` and remove. Enforce `package-lock.json` / `npm-shrinkwrap.json` pinning and mandatory SBOM generation for release artefacts. For endpoints running OpenAI macOS apps (ChatGPT Desktop, Codex, Atlas), push update to the newly signed versions before 8 May 2026 to avoid business disruption.

### 3.7 "Storm" Infostealer Shifts Browser Credential Decryption Server-Side

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/the-silent-storm-new-infostealer-hijacks-sessions-decrypts-server-side/)

A new subscription infostealer branded **Storm** emerged on underground cybercrime networks in early 2026 and sells for under $1,000/month. Storm harvests browser credentials, session cookies, autofill, Google account tokens, credit cards, and crypto-wallet data from both Chromium- and Gecko-based browsers, then **ships encrypted blobs to operator infrastructure for server-side decryption** — bypassing Chrome's App-Bound Encryption and sidestepping endpoint telemetry that relies on local SQLite/credential-store access. The operator panel also supports automated session restore: by pasting a Google Refresh Token and a geo-matched SOCKS5 proxy, the panel rebuilds the victim's authenticated session silently. Storm also pulls data from Telegram, Signal, Discord, and crypto wallet extensions; everything runs in memory.

MITRE techniques: T1078 (Valid Accounts), T1102 (Web Protocols), T1566 (Phishing delivery).

> **SOC Action:** Because Storm avoids local decryption, standard detections based on process access to `Login Data` / `Cookies` SQLite files may miss it. Add EDR rules that flag non-browser processes reading Chrome's `User Data\Local State` DPAPI blob, and large outbound POSTs (>200 KB) from user processes to newly registered domains. Enforce token-binding on identity providers and reduce session lifetime for privileged SaaS applications. Hunt Google Workspace audit logs for sign-ins with mismatched device fingerprints and new SOCKS5 egress IPs.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🟠 **HIGH** | Increased activity of Ransomware-as-a-Service (RaaS) groups targeting multiple sectors globally (Correlation Batch 65, 13 Apr) | Affordable Oil by DragonForce; Helzberg, Ralph Lauren, Carters by Coinbase Cartel — shared malware RansomLock; TTPs T1566 (Phishing), T1485 (Data Encrypted for Impact) |
| 🟠 **HIGH** | Global ransomware campaigns with overlapping TTPs and actors (Correlation Batch 64, 12 Apr) | mastercom.com.au, morgancountyga.gov by Inc Ransom; Tor-based darknet C2; T1485 |
| 🟡 **MEDIUM** | BreachForums continues to act as a significant coordination hub for threat actors (Correlation Batch 65) | Multiple Telegram-sourced posts referencing BreachForums (channel redacted) |
| 🟡 **MEDIUM** | Healthcare and government sectors under persistent pressure from Everest and Inc Ransom | K Subsea Group by Everest; bdac.com.au by Inc Ransom — shared sector (healthcare), shared region (global) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (53 reports, case-variant totals 73) — RaaS group, most active listings in period (multiple new victims including J Brand, Herth+Buss, PGDIS.PAPETIQUE PRO)
- **The Gentlemen** (43 reports, 63 with case variants) — persistent leak-site operator
- **Nightspire** (37 reports) — continues to post new victims
- **TeamPCP** (31 reports) — ongoing leak-site activity
- **DragonForce** (27 reports) — driving day's RaaS correlation; multiple new victims (Affordable Oil, edtg.com, Travel of America, Lift, rudolf-med.com, sistemigestioneintegrata.eu)
- **Akira** (22 reports) — continuing victim postings
- **Coinbase Cartel** — new actor cluster correlated (Helzberg, Ralph Lauren, Carters) using RansomLock malware
- **Lazarus Group / Famous Chollima (DPRK)** — sleek-pretty npm campaign (§3.2)
- **UNC1069 (DPRK)** — Axios npm supply-chain (§3.6)

### Malware Families

- **Ransomware (generic)** — 28 reports
- **DragonForce ransomware** — 26 reports
- **RansomLock** — 23 reports (shared payload tag across multiple victim listings)
- **Akira ransomware** — 18 reports
- **RaaS (generic)** — 13 reports
- **PLAY ransomware** — 8 reports
- **Qilin** — 7 reports (as malware family)
- **PHANTOMPULSE** — novel AI-generated Windows RAT (§3.5)
- **Storm** — subscription infostealer with server-side decryption (§3.7)
- **sleek-pretty** — DPRK npm package (§3.2)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 26 | [ransomlock feed](https://ransomlock.com) | Leak-site victim postings — DragonForce, Qilin, Coinbase Cartel, Inc Ransom, Everest, Medusa, RansomHouse, eraleign (apt73), securotrop, krybit |
| AlienVault | 13 | [otx.alienvault.com](https://otx.alienvault.com) | DPRK npm package; ASO RAT; GIFTEDCROOK; MiniDionis/CozyCar; Claude Code leak lure; CPU-Z watering hole; Arabian Gulf PlugX |
| Unknown / Telegram | 11 | — | Telegram OSINT chatter including BreachForums channel posts (channel redacted) and weekly ransomware stats post |
| BleepingComputer | 5 | [bleepingcomputer.com](https://www.bleepingcomputer.com) | Adobe zero-day; W3LL takedown; OpenAI cert rotation; Storm infostealer; Booking.com PIN reset |
| RecordedFutures | 3 | [therecord.media](https://therecord.media) | W3LL takedown; Rockstar Games breach claim; Basic-Fit EU data exposure |
| Schneier | 2 | [schneier.com](https://www.schneier.com) | Anthropic Mythos/Project Glasswing commentary; AI chatbots and trust |
| Wired Security | 2 | [wired.com/category/security](https://www.wired.com/category/security) | Meta facial-recognition glasses warning; "dumbest hack of the year" |
| SANS | 2 | [isc.sans.edu](https://isc.sans.edu) | EncystPHP webshell scans; ISC Stormcast podcast |
| Elastic Security Labs | 1 | [elastic.co/security-labs](https://www.elastic.co/security-labs) | PhantomPulse RAT / Obsidian abuse |
| CISA | 1 | [cisa.gov](https://www.cisa.gov) | Seven new KEV entries |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Adobe Acrobat/Reader to 26.001.21411 / 24.001.30362 (Windows) / 24.001.30360 (macOS) across all endpoints to close CVE-2026-34621 (active in-the-wild exploitation since December 2025). Concurrently hunt EDR for Acrobat processes spawning scripting interpreters or making outbound HTTP.
- 🔴 **IMMEDIATE:** Block `mywalletsss[.]store` (and sub-domains) at proxy/DNS/firewall, remove `sleek-pretty` from package registries, diff `authorized_keys` on Linux developer hosts, and rotate Polymarket CLOB API keys and Ethereum private keys for any team that may have installed the package.
- 🟠 **SHORT-TERM:** Remediate the six remaining CISA KEV additions within 21 days, with priority on CVE-2026-21643 (Fortinet SQLi), CVE-2023-21529 (Exchange deserialisation), and CVE-2025-60710 (Windows link-following). Verify Exchange servers are at November 2023 CU or later.
- 🟠 **SHORT-TERM:** Audit CI/CD dependencies for `axios@1.14.1` and update OpenAI macOS apps (ChatGPT Desktop, Codex, Codex CLI, Atlas) ahead of 8 May 2026 certificate revocation. Enforce dependency-pinning and SBOM generation in release pipelines.
- 🟡 **AWARENESS:** Brief developer and research staff on the Obsidian/PhantomPulse social-engineering pattern (LinkedIn → Telegram → shared vault → plugin sync). Block Obsidian community plugins `Shell Commands` and `Hider` via MDM; alert on `osascript` / `powershell.exe` children of `Obsidian`.
- 🟢 **STRATEGIC:** Storm infostealer's server-side decryption defeats detections that rely on local browser-credential access. Invest in token-binding, reduced session lifetimes for privileged SaaS, and behavioural detection for large outbound transfers from user processes to newly registered domains. Pair with enterprise-wide MFA phishing-resistance (FIDO2) to blunt AiTM kits that replaced W3LL.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 66 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
