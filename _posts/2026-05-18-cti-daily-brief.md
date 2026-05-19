---
layout: post
title:  "CTI Daily Brief: 2026-05-18 - Suspected npm/PyPI Supply Chain Wave, CISA GovCloud Credential Leak, SHub Reaper macOS Infostealer"
date:   2026-05-19 20:10:00 +0000
description: "Suspected large-scale npm/PyPI supply chain campaign tracked by Upwind alongside TeamPCP Mini Shai-Hulud activity; CISA contractor exposes AWS GovCloud credentials on public GitHub; SHub 'Reaper' macOS infostealer spoofs Apple security updates; Safepay and Nightspire ransomware dominate victim listings."
category: daily
tags: [cti, daily-brief, safepay, nightspire, teampcp, shinyhunters, shub, supply-chain]
classification: TLP:CLEAR
reporting_period: "2026-05-18"
generated: "2026-05-19"
draft: true
severity: high
report_count: 22
sources:
  - Upwind
  - SANS
  - Krebs on Security
  - BleepingComputer
  - HaveIBeenPwned
  - RecordedFutures
  - RansomLock
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-18 (24h) | TLP:CLEAR | 2026-05-19 |

## 1. Executive Summary

The pipeline processed 22 reports across seven sources for 2026-05-18, with 16 rated high and the dominant theme split between a suspected large-scale npm/PyPI supply chain wave and sustained ransomware extortion across Europe. Upwind disclosed an active, ongoing supply chain campaign affecting widely-used packages including `timeago.js`, `echarts-for-react`, and multiple `@antv/*` libraries, while SANS ISC confirmed escalation of the TeamPCP campaign with a Checkmarx Jenkins plugin trojanization and a self-spreading "Mini Shai-Hulud" worm that hit roughly 170 npm/PyPI packages. Krebs on Security reported that a CISA contractor's public GitHub repository exposed plaintext AWS GovCloud administrator credentials and internal CISA system passwords. BleepingComputer detailed a new SHub macOS infostealer variant ("Reaper") that abuses the `applescript://` URL scheme to bypass macOS Tahoe Terminal mitigations. HaveIBeenPwned added 34.5M Addi (Colombian fintech) accounts attributed to ShinyHunters' "pay or leak" extortion. Safepay (six victims) and Nightspire (five victims) dominated the ransomware victim listings; no CISA KEV additions were reported in this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No critical-rated reports in period |
| 🟠 **HIGH** | 16 | Safepay/Nightspire ransomware leak-site activity; npm/PyPI supply chain; TeamPCP campaign; CISA GovCloud credential leak; SHub "Reaper" macOS infostealer; Addi 34.5M breach |
| 🟡 **MEDIUM** | 4 | INTERPOL Operation Ramz takedown; CTT Portugal 468k breach; one additional Safepay victim |
| 🔵 **INFO** | 2 | Bavacai leak-site listing; SANS Stormcast podcast |

## 3. Priority Intelligence Items

### 3.1 Suspected Large-Scale npm/PyPI Supply Chain Campaign

**Source:** [Upwind](https://www.upwind.io/feed/large-scale-npm-pypi-supply-chain-campaign-suspected-across-multiple-popular-packages), [SANS ISC](https://isc.sans.edu/diary/rss/32994)

Upwind researchers are tracking what they assess as a coordinated, still-active software supply chain campaign across npm and PyPI ecosystems. Confirmed malicious package versions include `timeago.js@4.2.2`, `echarts-for-react@3.2.7`, `@antv/g-math@3.3.0`, `@antv/scale@0.7.2`, `@antv/path-util@3.2.1`, `@antv/g-canvas@2.4.0`, `jest-date-mock@1.2.11`, `jest-canvas-mock@2.7.3`, and `@antv/matrix-util@3.2.4`. Observed behaviours include `preinstall` lifecycle execution, `bun run index.js` install-time execution, heavily obfuscated payloads, credential and token harvesting, AWS / GitHub / npm / Kubernetes / Vault secret access, CI/CD workflow manipulation, package publishing abuse, and GitHub-based optional dependency injection (`@antv/setup`). SANS ISC separately reports that the TeamPCP campaign escalated with Checkmarx's official confirmation that its Jenkins AST scanner plugin was trojanized (malicious version 2026.5.09, exposure window 2026-05-09 01:25 UTC to 2026-05-10 08:47 UTC) and a self-spreading "Mini Shai-Hulud" worm that poisoned roughly 170 npm/PyPI packages including 42 `@tanstack/*` packages (combined cumulative downloads above 500M) shipped with valid SLSA Build Level 3 provenance and carrying a 1-in-6 disk-wipe payload triggered on Israeli and Iranian locale hosts. SANS attributes a tracking identifier of CVE-2026-45321 (CVSS 9.6 per The Hacker News; advisory GHSA-g7cv-rxg3-hmpx). Attribution between the Upwind cluster and TeamPCP is not confirmed in the source reporting.

**Affected sectors:** Software development, DevOps, CI/CD pipelines, cloud-native and Kubernetes environments.

**MITRE ATT&CK:** T1196 (Supply Chain Compromise), T1071 (Application Layer Protocol), T1083 (File and Directory Discovery), T1064 (Scripting), T1490 (Inhibit System Recovery).

#### Indicators of Compromise

```
Malicious npm versions (Upwind cluster):
  timeago.js@4.2.2
  echarts-for-react@3.2.7
  @antv/g-math@3.3.0
  @antv/scale@0.7.2
  @antv/path-util@3.2.1
  @antv/g-canvas@2.4.0
  jest-date-mock@1.2.11
  jest-canvas-mock@2.7.3
  @antv/matrix-util@3.2.4
Optional dependency reference: @antv/setup (GitHub-hosted)
Lifecycle abuse: preinstall + bun run index.js
Checkmarx Jenkins AST plugin (TeamPCP):
  Malicious build: 2026.5.09
  Last known-good: 2.0.13-829.vc72453fa_1c16 (2025-12-17)
  Remediated: 2.0.13-848.v76e89de8a_053 / 2.0.13-847.v08c0072b_2fd5
Mini Shai-Hulud worm: CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx
```

> **SOC Action:** Block install of the listed malicious package versions in internal registry mirrors and CI runners. Quarantine any build host that resolved them since 2026-05-09 and rotate every credential exposed to those builds (AWS, GitHub, npm publish tokens, Kubernetes service accounts, Vault tokens). Disable `preinstall` script execution where feasible (`npm install --ignore-scripts` in CI) and enforce lockfile + integrity-hash verification rather than relying on SLSA provenance alone. For Jenkins controllers running the Checkmarx AST plugin, downgrade or upgrade off the 2026.5.09 build and audit job logs from 2026-05-09 01:25 UTC to 2026-05-10 08:47 UTC for anomalous outbound HTTP from the Jenkins JVM.

### 3.2 CISA Contractor Exposed AWS GovCloud Admin Credentials on Public GitHub

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)

A CISA contractor maintained a public GitHub repository ("Private-CISA") that exposed administrative credentials to three AWS GovCloud accounts, plaintext usernames and passwords for internal CISA systems (including the Landing Zone DevSecOps environment, "LZ-DSO"), tokens, and a CSV titled `AWS-Workspace-Firefox-Passwords.csv`. GitGuardian researcher Guillaume Valadon flagged the repo on 2026-05-15 after the owner failed to respond to automated alerts; commit history shows the repository owner explicitly disabled GitHub's default secrets-detection feature. Independent researcher Philippe Caturegli (Seralys) validated the AWS keys authenticated at administrator privilege and noted the archive included plaintext credentials to CISA's internal artifactory — a viable foothold for supply chain backdooring of CISA-built software.

**Affected sectors:** US federal government (CISA / DHS).

**MITRE ATT&CK:** T1098 (Account Manipulation), T1078 (Valid Accounts).

> **SOC Action:** For US federal agencies and contractors with shared infrastructure dependencies, treat any inbound CISA-built or CISA-distributed tooling delivered since the exposure window as untrusted pending CISA confirmation of credential rotation. Audit your own GitHub organisations for the GitGuardian / TruffleHog indicators of disabled secret-scanning push protection and add a CI-side gate that blocks pushes containing AWS access key IDs (`AKIA[0-9A-Z]{16}`) and IAM long-lived credentials. Enforce SCP-level deny on long-lived `iam:CreateAccessKey` for human principals in GovCloud equivalents.

### 3.3 SHub macOS Infostealer "Reaper" Variant Bypasses Tahoe Terminal Mitigation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/shub-macos-infostealer-variant-spoofs-apple-security-updates/)

SentinelOne researchers identified a new SHub variant dubbed "Reaper" that uses the `applescript://` URL scheme to launch the macOS Script Editor pre-loaded with a malicious AppleScript, bypassing the Terminal-paste mitigations Apple introduced in macOS Tahoe 26.4. Lure sites impersonate WeChat, Miro, and Microsoft installers on look-alike domains. The script displays a fake XProtectRemediator-themed security update prompt, downloads a shell script via `curl`, and executes it via `zsh`. The malware exits if the host uses a Russian keyboard layout (reporting `cis_blocked` to C2). Targets include Chrome, Firefox, Brave, Edge, Opera, Vivaldi, Arc and Orion browser data; MetaMask and Phantom wallet extensions; 1Password, Bitwarden and LastPass extensions; Exodus, Atomic Wallet, Ledger Live, Electrum and Trezor Suite desktop wallets; iCloud and Telegram session data; and a "Filegrabber" module that exfiltrates files under 2MB (6MB for PNGs) from Desktop and Documents up to 150MB. Wallet hijack replaces the legitimate `app.asar` with a malicious copy. C2 telemetry is routed via a Telegram bot.

**Affected sectors:** macOS users, cryptocurrency holders, knowledge workers.

**MITRE ATT&CK:** T1566 (Phishing), T1078 (Valid Accounts), T1082 (System Information Discovery), T1204 (User Execution).

#### Indicators of Compromise

```
Lure domains:
  qq-0732gwh22[.]com
  mlcrosoft[.]co[.]com
  mlroweb[.]com
Execution mechanism: applescript:// URL scheme -> Script Editor -> osascript
Payload delivery: curl + zsh shell-script execution
Wallet hijack artefact: app.asar replacement
C2 exfil channel: Telegram bot (channel not published)
Geofence: skip if Russian keyboard input source detected
```

> **SOC Action:** On managed macOS fleets, deploy a Configuration Profile that disables the `applescript` URL scheme handler or remaps it to a no-op via `LSHandlers`. Hunt EDR telemetry for `osascript` invocations spawned by `Script Editor.app` with a parent process of a browser, and for `app.asar` writes inside `/Applications/Exodus.app/`, `/Applications/Atomic Wallet.app/`, `/Applications/Ledger Live.app/`, `/Applications/Electrum.app/`, and `/Applications/Trezor Suite.app/`. Block the three listed lookalike domains at the proxy and warn users that legitimate Apple security updates never prompt for the macOS password inside a browser-launched workflow.

### 3.4 Addi (Colombia) — 34.5M Account Breach Claimed by ShinyHunters

**Source:** [HaveIBeenPwned](https://haveibeenpwned.com/Breach/ADDI)

Colombian fintech Addi confirmed unauthorised activity on its platform in March 2026; the ShinyHunters "pay or leak" extortion group subsequently published a dataset covering 34,532,941 records including email addresses, names, phone numbers, physical addresses, Colombian government IDs (Cédula de Ciudadanía), credit scores, estimated income, socioeconomic levels, purchase data, IP addresses, device information, and latitude/longitude pairs. HaveIBeenPwned added the breach on 2026-05-18.

**Affected sectors:** Financial services, consumer credit, Colombia.

**MITRE ATT&CK:** T1566 (Phishing) — initial vector not disclosed in the source.

> **SOC Action:** Organisations operating in Colombia or with Colombian customer overlap should pre-position fraud-monitoring rules for Cédula-based identity-takeover attempts and account-recovery flows referencing Addi-linked email addresses. For SOCs supporting global identity providers, sweep authentication logs for password-spray and credential-stuffing patterns originating from the released dataset, particularly against banking, telco and crypto-exchange portals where Latin American customers have linked accounts.

### 3.5 Safepay and Nightspire Ransomware Victim Surge

**Source:** [RansomLook (Safepay)](https://www.ransomlook.io//group/safepay), [RansomLook (Nightspire)](https://www.ransomlook.io//group/nightspire)

Two ransomware leak-site clusters dominated yesterday's victim listings. Safepay posted six new victims across European sectors (German transportation `berlinmobil.de`, German clinic `hautarzt-budihardja.de`, French media `mediafrance.de`, UK timber `ashleytimber.co.uk`, UK print `printroom.co.uk`, and `adlan.com`) plus one additional medium-rated listing (`harrisoncountywv.com` — US county government). Nightspire posted five new victims including Vantage Energy LLC (US energy) and TAKOSAN OTOMOBIL (Turkish automotive), with sectoral exposure across energy, healthcare, transportation, construction, and financial services. RansomLook records both groups maintaining `.onion` infrastructure for negotiation, file servers, and chat, with several mirrors degraded but at least one primary up. Nightspire continues to operate Telegram and Tox communication channels alongside affiliate handles (Phantom, Reaper, Volt, Blaze, Shadow, Blade).

**Affected sectors:** German municipal transport, German healthcare, UK SMB manufacturing, US energy, Turkish automotive, US local government.

**MITRE ATT&CK:** T1071 (Application Layer Protocol), T1071.001 (Web Protocols), T1486 (Data Encrypted for Impact), T1566 (Phishing).

> **SOC Action:** Query EDR for the Nightspire ransom-note filenames `nightspire_readme.txt`, `readme_2.txt`, and `readme.txt` written outside development directories, and alert on creation across more than five hosts within a 30-minute window. For Safepay, monitor for outbound DNS / TLS SNI to recently-registered `.onion`-bridged domains from finance and HR workstations and block known Tor exit nodes at the egress proxy where business policy permits. Energy and transportation operators in the named geographies should brief incident commanders on the Nightspire affiliate handle list so threat-intel feeds can correlate Telegram chatter against ongoing intrusions.

### 3.6 INTERPOL Operation Ramz — 200+ Arrests, 53 Servers Seized

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/interpol-operation-ramz-seizes-53-malware-phishing-servers/), [Recorded Future News](https://therecord.media/more-than-200-arrested-interpol-middle-east-scams)

INTERPOL announced Operation Ramz, a Middle East / North Africa-focused crackdown that arrested 200+ individuals, identified 382 additional suspects across 13 countries (Algeria, Bahrain, Egypt, Iraq, Jordan, Lebanon, Libya, Morocco, Oman, Palestine, Qatar, Tunisia, UAE), and seized 53 servers used for phishing, malware distribution and online fraud affecting 3,867 confirmed victims. The operation also dismantled a Jordan-based investment-scam compound where 15 trafficked Asian workers were forced to run fraud schemes, shut down a phishing-as-a-service platform in Algeria, and secured compromised devices unknowingly relaying malware in Qatar. Private-sector partners included Kaspersky, Group-IB, Shadowserver, Team Cymru, and TrendAI.

**Affected sectors:** Banking, retail, consumer fraud targets across MENA; downstream impact on global victims of MENA-based phishing infrastructure.

**MITRE ATT&CK:** T1566 (Phishing).

> **SOC Action:** Expect short-term infrastructure churn from operators displaced by the Ramz takedown; raise the sensitivity of newly-registered domain detection rules and re-baseline blocklists drawn from MENA-attributed phishing kits over the next 14 days. If your threat-intel feeds include named indicators from Kaspersky, Group-IB, Shadowserver or Team Cymru, prioritise ingestion of any Ramz IOC release.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks involving popular package managers (npm and PyPI) | Upwind npm/PyPI campaign disclosure; SANS TeamPCP / Mini Shai-Hulud / Checkmarx Jenkins confirmation |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with sophisticated TTPs | Safepay (`mediafrance.de`); Nightspire (Vantage Energy LLC) |
| 🟠 **HIGH** | Continued double-extortion ransomware across energy, healthcare, transportation, finance | Nightspire campaign (Vantage Energy LLC, TAKOSAN OTOMOBIL, Huse Incorporated, and two redacted victims) |
| 🟠 **HIGH** | Ransomware-as-a-Service (RaaS) model proliferation | Qilin (Gartengestaltung Muller eU, RCR Industrial Flooring); ailock (Design Engineering & Consulting) |
| 🟡 **MEDIUM** | Phishing campaigns remain a persistent threat across regions and sectors | INTERPOL Operation Ramz seizures; SHub Reaper macOS lure infrastructure |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (123 reports, 30-day) — RaaS group with sustained victim volume across construction, retail and SMB sectors.
- **Akira** (61 reports) — Continuing high-tempo ransomware operations with phishing and external-remote-services initial access.
- **The Gentlemen** (59 reports) — Active across engineering, retail, education, healthcare and electronics-engineering sectors.
- **ShinyHunters** (30 reports) — "Pay or leak" extortion; claimed the 34.5M Addi breach in this period.
- **Inc Ransom** (26 reports) — Continued leak-site posting cadence.
- **TeamPCP** (25 reports) — Supply chain campaign actor confirmed behind Checkmarx Jenkins plugin trojanization and Mini Shai-Hulud worm.
- **Everest** (24 reports) — Active leak-site operations.
- **Safepay** (18 reports) — Six new victims in this period; concentrated on European SMB and municipal targets.
- **FulcrumSec** (17 reports) — Active extortion actor.
- **DragonForce** (16 reports) — Active leak-site operations.

### Malware Families

- **Akira ransomware** (34 reports) — Sustained deployment volume tied to Akira actor.
- **Qilin** (15 reports as malware label) — Payload tracking alongside the actor.
- **Mini Shai-Hulud** (1 report) — Self-spreading npm/PyPI worm with disk-wipe payload (TeamPCP).
- **Safepay ransomware** (2 reports) — Encrypts for impact (T1486); leak-site driven extortion.
- **PCPJack** (1 report) — Rival npm worm that evicts TeamPCP before stealing credentials (per SANS ISC).
- **SHub / Reaper** (1 report) — macOS infostealer; AppleScript URL-scheme abuse; Telegram-bot C2.

> Vulnerability trending returned zero entries from the pipeline in this period.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 13 | [link](https://www.ransomlook.io) | Safepay and Nightspire leak-site listings dominate the day. |
| HaveIBeenPwned | 2 | [link](https://haveibeenpwned.com/Breach/ADDI) | Addi (34.5M, ShinyHunters) and CTT Portugal (468k) breach notifications. |
| BleepingComputer | 2 | [link](https://www.bleepingcomputer.com/news/security/shub-macos-infostealer-variant-spoofs-apple-security-updates/) | SHub Reaper macOS infostealer; INTERPOL Operation Ramz. |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/32994) | TeamPCP supply chain campaign weekly update; Stormcast podcast. |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/) | CISA contractor GovCloud credential exposure. |
| RecordedFutures | 1 | [link](https://therecord.media/more-than-200-arrested-interpol-middle-east-scams) | Operation Ramz coverage corroborating BleepingComputer. |
| Upwind | 1 | [link](https://www.upwind.io/feed/large-scale-npm-pypi-supply-chain-campaign-suspected-across-multiple-popular-packages) | Primary disclosure of suspected npm/PyPI supply chain wave. |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Quarantine build hosts and rotate AWS / GitHub / npm / Kubernetes / Vault credentials exposed to any of the listed malicious npm/PyPI versions or to Checkmarx Jenkins AST plugin build 2026.5.09 in the 2026-05-09 to 2026-05-10 window. Enforce `--ignore-scripts` in CI and do not trust SLSA provenance as a sole signal until the Mini Shai-Hulud signing chain is fully analysed.
- 🟠 **SHORT-TERM:** macOS fleets should disable or remap the `applescript://` URL scheme handler and add EDR detections for `osascript` spawned from `Script Editor.app` under a browser parent, plus `app.asar` overwrites in wallet application bundles, to counter the SHub "Reaper" lure chain.
- 🟠 **SHORT-TERM:** Audit corporate GitHub organisations for users who have disabled push protection / secret-scanning and add a blocking pre-receive hook for AWS access-key patterns; treat the CISA exposure as a templated wake-up call for federal contractors handling government cloud credentials.
- 🟡 **AWARENESS:** Brief incident commanders supporting European SMB, US energy, Turkish automotive and German municipal transport on Safepay and Nightspire negotiation infrastructure and ransom-note artefacts; prepare for a possible Nightspire affiliate handle (Phantom / Reaper / Volt / Blaze / Shadow / Blade) appearing in chat-channel collections.
- 🟢 **STRATEGIC:** Expect a 7–14 day churn of MENA-attributed phishing infrastructure following Operation Ramz; raise sensitivity on newly-registered-domain feeds and prioritise ingestion of Ramz-released IOCs from Kaspersky, Group-IB, Shadowserver and Team Cymru.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 22 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
