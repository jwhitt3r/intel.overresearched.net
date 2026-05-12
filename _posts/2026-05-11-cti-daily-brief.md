---
layout: post
title:  "CTI Daily Brief: 2026-05-11 - Shai-Hulud TanStack supply-chain attack, Copy.Fail Linux LPE, SAP critical patches, Iran's Seedworm campaign"
date:   2026-05-12 21:00:00 +0000
description: "TeamPCP escalates the Shai-Hulud npm/PyPI supply-chain campaign to TanStack, Mistral and UiPath packages while SAP patches critical Commerce Cloud and S/4HANA flaws. Theori discloses Copy.Fail, a working Linux kernel LPE. Iran-linked Seedworm breaches a Korean electronics maker, and ShinyHunters extorts Instructure as Congress opens an investigation."
category: daily
tags: [cti, daily-brief, teampcp, shinyhunters, seedworm, the-gentlemen, akira, shai-hulud, copy-fail]
classification: TLP:CLEAR
reporting_period: "2026-05-11"
generated: "2026-05-12"
draft: true
severity: critical
report_count: 89
sources:
  - BleepingComputer
  - Wiz
  - Schneier
  - Microsoft
  - AlienVault
  - RecordedFutures
  - Cisco Talos
  - SANS
  - HaveIBeenPwned
  - RansomLock
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-11 (24h) | TLP:CLEAR | 2026-05-12 |

## 1. Executive Summary

The pipeline processed 89 reports from 15 sources across the last 24 hours, dominated by a record day for software supply-chain compromise and high-volume ransomware leak-site activity. TeamPCP's "Mini Shai-Hulud" campaign weaponised GitHub Actions cache poisoning and OIDC token theft to publish 84 malicious versions across 42 TanStack packages, plus packages in the @uipath, @mistralai and guardrails-ai namespaces — all carrying valid SLSA Build Level 3 provenance attestations, making them indistinguishable from legitimate releases. SAP shipped May Patch Tuesday with two critical flaws in Commerce Cloud (CVE-2026-34263, unauthenticated RCE) and S/4HANA (CVE-2026-34260, SQL injection), and security researcher Theori disclosed Copy.Fail, a working PoC Linux kernel local privilege escalation that bypasses file-integrity monitoring across every major distribution. Iran-linked Seedworm (MuddyWater) compromised a South Korean electronics manufacturer as part of a nine-organisation espionage sweep, and ShinyHunters extorted education vendor Instructure for the Canvas LMS breach, prompting a House Homeland Security Committee investigation. No new CISA KEV additions were observed in the reporting window, but Copy.Fail and the SAP CVEs are strong candidates pending CISA review.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | Mini Shai-Hulud npm/PyPI compromise; SAP Commerce Cloud + S/4HANA RCE/SQLi; Copy.Fail Linux kernel LPE; Aurora data dump of NorthWest Handling Systems |
| 🟠 **HIGH** | 66 | Heavy The Gentlemen / Akira / Qilin / Genesis / Inc Ransom / Lamashtu leak-site activity; ShinyHunters at Instructure & Cushman & Wakefield; Seedworm Korean breach; Vibe Hacking AI-augmented campaigns |
| 🟡 **MEDIUM** | 6 | Linux kernel CVE backlog; ancillary advisories |
| 🟢 **LOW** | 4 | Lower-confidence leak-site reposts |
| 🔵 **INFO** | 9 | Vendor write-ups, blog summaries, contextual reporting |

## 3. Priority Intelligence Items

### 3.1 Mini Shai-Hulud: TanStack, Mistral, UiPath and Guardrails-AI npm/PyPI Packages Compromised by TeamPCP

**Source:** [Wiz](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised), [BleepingComputer](https://www.bleepingcomputer.com/news/security/shai-hulud-attack-ships-signed-malicious-tanstack-mistral-npm-packages/), [AlienVault / Socket](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)

On 11 May 2026 TeamPCP launched a coordinated supply-chain attack against npm and PyPI, hitting @tanstack (including `@tanstack/react-router`, ~12M weekly downloads), @uipath, @mistralai and `guardrails-ai`. The attacker forked the TanStack/router repo, renamed it `zblgg/configuration` to evade fork enumeration, and opened a pull request that triggered a `pull_request_target` workflow. Attacker code poisoned the GitHub Actions cache; when maintainers later merged legitimate PRs to main, the release workflow restored the poisoned cache and attacker binaries extracted OIDC tokens directly from the runner's process memory (`/proc/<pid>/mem`). Those tokens were used to publish 84 malicious versions across 42 TanStack packages — every one carrying valid SLSA Build Level 3 provenance and Sigstore attestations tied to the legitimate TanStack release workflow. Endor Labs, Aikido and Socket recorded between 160 and 416 compromised package artifacts in total. The payload steals GitHub Actions OIDC tokens, PATs, npm publish tokens, AWS IMDSv2 / IAM / ESC credentials, Kubernetes service-account tokens, HashiCorp Vault tokens, SSH keys, Claude Code configs and `.env` files; it writes itself into Claude Code hooks and VS Code auto-run tasks so removing the malicious package does not remove it. Exfiltration runs over three redundant channels: a typosquat domain, the Session P2P messenger network, and GitHub API dead-drops using stolen tokens. A persistent `gh-token-monitor` daemon (LaunchAgent on macOS, systemd on Linux) polls GitHub every 60 seconds and attempts `rm -rf ~/` on receiving a 40X response that indicates token revocation. The malware terminates if the host is configured for Russian.

**Affected products/sectors:** Software development, AI/ML platforms (Mistral AI, Guardrails AI), enterprise automation (UiPath), CI/CD pipelines, any downstream consumer of compromised package versions.

**MITRE ATT&CK:** T1566 (Phishing — supply-chain delivery), T1059.001 (PowerShell), T1071.001 (Web Protocols C2), T1195.002 (Compromise Software Supply Chain), T1552.001 (Credentials in Files).

#### Indicators of Compromise
```
Domain (typosquat): git-tanstack[.]com
Exfil channel: Session P2P messenger network
Exfil channel: GitHub API dead-drops via stolen tokens
Persistence: ~/.config/gh-token-monitor (Linux systemd)
Persistence: ~/Library/LaunchAgents/gh-token-monitor.plist (macOS)
Persistence: Claude Code hooks + VS Code tasks.json auto-run
Malicious commit ref: github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c
Affected namespaces: @tanstack, @uipath, @mistralai, guardrails-ai
```

> **SOC Action:** (1) Pin lockfiles to pre-2026-05-11 versions of `@tanstack/*`, `@uipath/*`, `@mistralai/mistralai` and `guardrails-ai`, then rebuild from clean caches. (2) Rotate every GitHub Actions OIDC token, npm token, AWS IAM key, GCP/Azure key, Kubernetes service-account token, HashiCorp Vault token and SSH key that was reachable from any pipeline that installed these packages since 1 May 2026. (3) Hunt for `gh-token-monitor` LaunchAgents/systemd units and remove them before rotating; revoking tokens with the daemon still resident triggers the `rm -rf ~/` handler. (4) Block `git-tanstack[.]com` and Session-protocol traffic at egress. (5) Search VS Code `tasks.json` and Claude Code hook configs for unknown auto-run entries.

---

### 3.2 SAP May 2026 Patch Day: Critical RCE in Commerce Cloud and SQL Injection in S/4HANA

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/sap-fixes-critical-vulnerabilities-in-commerce-cloud-and-s-4hana/)

SAP's May 2026 advisory addresses 15 vulnerabilities including two critical flaws. **CVE-2026-34263** is a missing authentication check in SAP Commerce Cloud caused by improper Spring Security configuration, allowing an unauthenticated attacker to upload malicious configuration and inject server-side code — full confidentiality, integrity and availability impact. **CVE-2026-34260** is a low-complexity SQL injection in S/4HANA exploitable by an authenticated user with basic privileges, leading to data exposure and potential application crash. SAP reports no in-the-wild exploitation yet, but CISA has historically added 14 SAP flaws to the KEV catalogue, including two abused in ransomware attacks. SAP customers should also note that several official SAP npm packages were compromised in a recent TeamPCP supply-chain wave — the May patch advisory does not address that ecosystem-side risk.

**Affected products/sectors:** SAP Commerce Cloud (large retail / e-commerce), SAP S/4HANA (enterprise ERP), broad cross-industry exposure given SAP's footprint among 99 of the Fortune 100.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1068 (Exploitation for Privilege Escalation).

> **SOC Action:** Apply SAP May 2026 security notes immediately for Commerce Cloud and S/4HANA; the Commerce Cloud flaw is unauthenticated and internet-exposed deployments should be considered pre-compromised until proven otherwise. Audit WAF / reverse-proxy logs for anomalous POSTs to Commerce Cloud configuration endpoints and SQL error patterns from low-privilege S/4HANA accounts. Confirm no SAP-namespaced npm packages from the prior compromise window remain pinned in any frontend build.

---

### 3.3 Copy.Fail — Working PoC Linux Kernel Local Privilege Escalation

**Source:** [Schneier on Security](https://www.schneier.com/) (write-up referencing Theori disclosure of CVE-2026-31431)

Theori disclosed Copy.Fail on 29 April 2026 with a working proof-of-concept. The exploit abuses the kernel crypto API (AF_ALG sockets) together with `splice()` to write four bytes at a time directly into the page cache of files the attacker does not own. The exploit runs unmodified across Ubuntu, RHEL, Debian, SUSE, Amazon Linux and Fedora — no race condition and no per-distribution offsets required. Crucially, the on-disk file is never modified, so AIDE, Tripwire, OSSEC and any checksum/file-integrity monitoring solution see nothing. A local attacker can therefore escalate to root by stealthily editing the in-memory contents of trusted binaries or configuration files (e.g., `/etc/sudoers`, setuid binaries) without triggering FIM alerts.

**Affected products/sectors:** Every major Linux distribution; particularly acute risk for multi-tenant systems (CI runners, shared dev hosts, hosting providers, Kubernetes nodes with pod-to-host escape vectors).

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation), T1078.004 (Valid Accounts: Local Accounts), T1547.001 (Registry Run Keys / Startup Folder — analogous persistence post-LPE).

> **SOC Action:** Track distro vendor advisories for the Copy.Fail kernel patch and prioritise rollout to any host that accepts untrusted local users (CI/CD runners, shared dev VMs, multi-tenant container hosts). Until patched, supplement FIM with memory-resident integrity attestation (IMA/EVM appraisal in `appraise` mode) where possible. Hunt for unexpected `AF_ALG` socket creation by non-crypto workloads in eBPF/auditd logs.

---

### 3.4 Iran-Linked Seedworm (MuddyWater) Breaches South Korean Electronics Maker in Nine-Country Espionage Sweep

**Source:** [Symantec / AlienVault](https://www.security.com/threat-intelligence/iran-seedworm-electronics)

Symantec attributes a Q1 2026 espionage campaign affecting at least nine organisations across four continents to Seedworm (aka MuddyWater, Temp Zagros, Static Kitten), widely assessed as linked to Iran's Ministry of Intelligence and Security (MOIS). Targets span industrial and electronics manufacturing, education, public-sector bodies, financial services and professional services — including a major South Korean electronics manufacturer where the actor maintained a week of access in February 2026, plus government agencies and an international airport in the Middle East. Tradecraft relies on DLL sideloading using legitimately signed binaries: Fortemedia's `fmapp.exe` paired with malicious `fmapp.dll`, and SentinelOne's `sentinelmemoryscanner.exe` paired with malicious `sentinelagentcore.dll`. Both malicious DLLs deliver ChromElevator for browser credential and cookie theft. Loader chain runs through `node.exe` orchestrating PowerShell stages for reconnaissance, screenshot capture, SAM hive theft, privilege escalation and SOCKS5 reverse-proxy tunnelling.

**Affected products/sectors:** Industrial manufacturing, semiconductors / electronics, government, aviation, education, financial services, professional services.

**MITRE ATT&CK:** T1574.002 (DLL Sideloading), T1003.001/T1003.002 (LSASS / SAM dumping), T1059.001 (PowerShell), T1090.001 (Multi-hop Proxy), T1078 (Valid Accounts), T1567.002 (Exfiltration to Cloud Storage).

#### Indicators of Compromise
```
Domain: timetrakr[.]cloud
Hostname: svc.wompworthy[.]com
URL: hxxps[:]//svc.wompworthy[.]com
URL: hxxps[:]//timetrakr[.]cloud/sp.ps1
SHA256: 0c9b911935a3705b0ad569446804d80026feb6db3884aeb240b6c76e9b8cf139
SHA256: 128b58a2a2f1df66c474094aacb7e50189025fbf45d7cd8e0834e93a8fbed667
SHA256: 3ee7dab4ae4f6d4f16dfabb6f38faef370411a9fc00ff035844e54703b99600a
SHA256: 74ab3838ebed7054b2254bf7d334c80c8b2cfec4a97d1706723f8ea55f11061f
SHA256: b21c802775df0c0d82c8cfde299084abc624898b10258db641b820172a0ba29a
SHA256: bee79c3302b1a7afc0952842d14eff83a604ef00bfdae525176c16c80b2045f7
SHA256: c6182fd01b14d84723e3c9d11bc0e16b34de6607ccb8334fc9bb97c1b44f0cde
SHA256: d587959841a763669279ad831b8f0379f6a7b037dffc19deab5d41f37f8b5ffc
SHA256: e25892603c42e34bd7ba0d8ea73be600d898cadc290e3417a82c04d6281b743b
Sideloaded binaries: fmapp.exe + fmapp.dll; sentinelmemoryscanner.exe + sentinelagentcore.dll
Implant: ChromElevator (browser cred/cookie theft)
```

> **SOC Action:** EDR-hunt for `node.exe` as the parent process of `fmapp.exe` or `sentinelmemoryscanner.exe`, and for `powershell.exe` spawned by `node.exe`. Block the listed domains and hashes at proxy and EDR. Query AV/EDR telemetry for any execution of legitimate Fortemedia or SentinelOne binaries from non-standard directories. Validate SentinelOne installer integrity on hosts where `sentinelmemoryscanner.exe` runs outside the agent install path.

---

### 3.5 ShinyHunters Extort Instructure (Canvas LMS) — Congress Opens Investigation

**Source:** [The Record / Recorded Future News](https://therecord.media/instructure-pays-ransom-canvas-incident-congress-investigation), [BleepingComputer](https://www.bleepingcomputer.com/news/security/instructure-reaches-agreement-with-shinyhunters-to-stop-data-leak/), [HaveIBeenPwned (related Cushman & Wakefield breach)](https://haveibeenpwned.com/Breach/CushmanWakefield)

Education-technology vendor Instructure paid a ransom to ShinyHunters after the group breached the Canvas LMS twice in two weeks. The first intrusion on 1 May 2026 lifted data tied to 9,000 customer institutions — names, email addresses, student IDs and student/professor messages. A second intrusion on 7 May 2026 defaced login portals with a ransom note ahead of finals exams; ShinyHunters used cross-site scripting in the Free-for-Teacher environment to obtain admin sessions. The House Homeland Security Committee notified Instructure on 11 May that it will investigate the recurrence of intrusions days apart and the gap between Instructure's "contained" public messaging on 2 May and the actual scope. In parallel, ShinyHunters' "pay or leak" campaign netted 310,431 business contact records from Cushman & Wakefield (disclosed via HaveIBeenPwned on the same day).

**Affected products/sectors:** EdTech (Canvas customers — universities and K-12 globally), commercial real estate.

**MITRE ATT&CK:** T1566 (Phishing), T1190 (Exploit Public-Facing Application — XSS), T1485 (Data Encrypted for Impact / Destruction), T1496 (Resource Hijacking).

> **SOC Action:** Canvas-using institutions should rotate all admin session tokens, force admin password reset, and audit Canvas application logs for unfamiliar admin sessions originating from non-corporate IP space since 25 April 2026. Review Free-for-Teacher accounts and disable until Instructure confirms remediation of the XSS class. Treat Instructure's "data destruction" attestation as best-effort; assume the data may resurface and prepare student/staff comms accordingly.

---

### 3.6 Vibe Hacking — Two AI-Augmented Campaigns Target LatAm Government and Banks

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a02ea171e7005022d5c8a6f)

Two distinct campaigns, SHADOW-AETHER-040 (Spanish-speaking, six Mexican government entities compromised Dec 2025–Jan 2026) and SHADOW-AETHER-064 (Portuguese-speaking, Brazilian financial institutions targeted from April 2026), are operating agentic AI assistants directly inside victim networks via SOCKS5 tunnels (Chisel, Neo-reGeorg) layered on ProxyChains/SSH. The AI agents generate hacking tools and scripts on demand, producing one-off binaries that defeat signature-based detection. Tooling overlap (Chisel, Neo-reGeorg, CrackMapExec, Impacket) is consistent but the operators are linguistically distinct.

**Affected products/sectors:** Government (Mexico), financial services (Brazil); LatAm focus but the TTP pattern is portable.

**MITRE ATT&CK:** T1071.001 (Web Protocols), T1071.002 (File Transfer Protocols), T1090 (Proxy), T1505.003 (Web Shell).

#### Indicators of Compromise
```
IPv4: 167.148.195[.]53
IPv4: 209.99.185[.]221
IPv4: 209.99.185[.]223
Domain: cloudservbr[.]com
Domain: infra-telemetry[.]com
SHA256: 1c37a58df996dd62449a76e49dd700d9d5fc70739179a92f3a86b6bdf4e1d87e
SHA256: 2dbf48e7da928f88d37d5f3560838987a277eafed85612ad841b4edfa59944f3
SHA256: 3b72ef13049bea56198134de13ee54bfb3b327a19dcec20e2d70719bd4379e63
SHA256: 5209edb0076bbb0d08bfeb24fcd1eed714aa1038fe4c30921059bd3c95f83b72
SHA256: 97f7a1a84d3d1aca5048f433d5689e3af1289597acae7e432fac2fc5f2c64341
Tools: Chisel, Neo-reGeorg, CrackMapExec, Impacket
Implants: implante_http, SOCKTZ
```

> **SOC Action:** Block listed IPs and domains at perimeter. Hunt for `chisel`, `neo-regeorg` and `impacket-*` binary names in EDR process telemetry; even when renamed they retain distinctive command-line shapes (`chisel client`, `proxychains ssh -D`). Alert on SSH dynamic-port-forward (`-D`) flags from non-admin user shells. Note that AI-generated payloads will not match yara/IOC sets — focus detection on behaviour (lateral-tooling families, proxy chains, unexpected SOCKS endpoints) rather than file hashes.

---

### 3.7 Ransomware Leak-Site Surge: The Gentlemen, Akira, Qilin, Genesis, Inc Ransom, Aurora, Lamashtu

**Source:** RansomLook leak-site aggregation (57 posts across the reporting window)

Six ransomware operators dominated leak-site activity in the 24-hour window: **The Gentlemen** (9 posts including Qatar National Broadband, Dodson & Horrell, Amstel Securities — sectors: telecoms, retail, transportation), **Akira** (4 posts including Manhattan Broadcasting, Vision 3 Architects, Kaplan Companies, Taylor Clay Products — sectors: broadcasting, architecture, manufacturing, healthcare), **Genesis** (6+ posts including Pequod Associates, Casino Gaming Commission, HostBooks — sectors: legal, gaming, fintech), **Qilin** (4 posts including AppDirect, Mediapost Spain, Keller Williams Real Estate Exton — RaaS model on Tor onions), **Inc Ransom** (3 posts including rbh aerospace, lalsgroup.com — sectors: aerospace, conglomerates), **Aurora** (3 posts including NorthWest Handling Systems, Avanti Windows & Doors, Startec Group — dumped plaintext SQL SA credentials, employee SSNs and TLS private keys) and **Lamashtu / Worldleaks / Space Bears / Interlock / Kairos / Money Message / Nitrogen** rounding out the high-severity ransomware coverage. Aurora's Startec dump is notable for including wildcard TLS private keys and CPA-reviewed financials going back two decades.

**Affected products/sectors:** Telecommunications, retail, transportation, broadcasting, architecture, manufacturing, healthcare, aerospace, legal services, gaming, real estate, education, libraries, religious institutions.

**MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1190, T1078 (Valid Accounts via compromised VPN/RDP), T1566 (Phishing initial access), T1048 (Exfiltration over Alternative Protocol).

> **SOC Action:** For organisations in Aurora's named victim list, treat all SA-equivalent SQL credentials, wildcard TLS certs, AD service-account passwords and W-4/I-9 PII as exposed — rotate and re-issue immediately. For Akira-exposed sectors, audit VPN appliances for missing patches and confirm MFA enforcement on every external RDP and VPN entry point (Akira's documented initial-access vector). Pre-position dark-web monitoring for the specific victim domains named in the brief data.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply-chain attacks against npm and PyPI are accelerating, with TeamPCP compromising multiple package namespaces simultaneously (Mini Shai-Hulud variant) | TanStack npm packages compromised; Mini Shai-Hulud Strikes Again (Wiz); Shai Hulud ships signed malicious TanStack/Mistral npm packages (BleepingComputer) |
| 🔴 **CRITICAL** | Supply-chain attacks broadening from package registries into AI/ML ecosystems (Hugging Face, OpenClaw) and developer-trust signals (SLSA, Sigstore) | Shai-Hulud TanStack worm; Poisoning the well — AI supply chain attacks on Hugging Face and OpenClaw (prior batch) |
| 🟠 **HIGH** | Ransomware operators The Gentlemen and Akira running broad multi-sector campaigns across telecoms, retail, transportation, education, manufacturing and healthcare | 13 RansomLook posts attributing to The Gentlemen and Akira (Oriental Diamond, Qatar National Broadband, SETCAR, Kaplan Companies, Taylor Clay, Manhattan Broadcasting, Vision 3 Architects, etc.) |
| 🟠 **HIGH** | State-sponsored actors leveraging legitimate signed binaries and stolen credentials to operate inside trust boundaries | Seedworm DLL sideloading via Fortemedia/SentinelOne binaries; Cisco Talos "State-sponsored actors, better known as the friends you don't want"; Vibe Hacking AI-agent intrusions in LatAm |
| 🟠 **HIGH** | RaaS-driven targeting of healthcare and legal sectors | Space Bears at SmilePoint Dental; Inc Ransom at rbh aerospace; Genesis at Casino Gaming Commission, Pequod Associates; Qilin recurrent on Tor RaaS infrastructure |
| 🟠 **HIGH** | EdTech under sustained pressure — XSS-driven account takeover and extortion | Instructure / Canvas LMS twice-breached by ShinyHunters; Congressional investigation announced |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (102 reports) — Russian-speaking RaaS, Tor onion infrastructure, Jabber/Tox affiliate coordination
- **The Gentlemen** (60 reports) — Active multi-sector ransomware operator using Tox1 malware
- **Akira** (57 reports) — Double-extortion ransomware targeting Windows + Linux/ESXi via unpatched VPN and RDP
- **ShinyHunters** (33 reports) — Data-theft / extortion group; this week's Instructure and Cushman & Wakefield breaches
- **DragonForce** (30 reports) — Continuing leak-site activity
- **Coinbase Cartel** (29 reports) — Sustained financial-sector targeting
- **Inc Ransom** (23 reports) — Aerospace and conglomerate targeting
- **Everest** (22 reports) — Ongoing leak-site presence
- **TeamPCP** (21 reports) — Operators behind the Shai-Hulud npm/PyPI supply-chain worm
- **Lamashtu** (18 reports) — Custom encryption + PGP-based negotiation infrastructure

### Malware Families

- **RansomLook** (98 reports) — Tracking/parsing infrastructure across leak sites
- **Tox1** (37 reports) — Used by The Gentlemen and several adjacent operators
- **Akira ransomware** (30 reports) — `.akira` extension, Windows CryptoAPI + Linux/ESXi variants
- **Other1** (22 reports) — Aggregator category for unclassified Tor-distributed payloads
- **RaaS** (19 reports) — Generic Ransomware-as-a-Service references
- **Tox / Tox1 variants** (18 reports)
- **Qilin** (14 reports) — RaaS-distributed payload tracked separately from the actor entity
- **Mini Shai-Hulud** — TeamPCP's npm/PyPI worm variant (new entity this batch)
- **ChromElevator** — Seedworm's browser credential / cookie theft tool

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 57 | [link](https://www.ransomlook.io) | Leak-site aggregation — primary visibility into The Gentlemen, Akira, Qilin, Genesis, Inc Ransom, Aurora, Lamashtu activity |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com/news/security/sap-fixes-critical-vulnerabilities-in-commerce-cloud-and-s-4hana/) | SAP critical patch coverage; Shai-Hulud signed-package campaign; Instructure / ShinyHunters update |
| Microsoft | 3 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-6965) | Linux kernel CVE batch (SQLite integer truncation, i3c DMA race, rxrpc DATA/RESPONSE) |
| AlienVault | 3 | [link](https://otx.alienvault.com/pulse/6a02ea171e7005022d5c8a6f) | Seedworm Korean breach; Vibe Hacking LatAm AI-augmented campaigns |
| RecordedFutures | 2 | [link](https://therecord.media/instructure-pays-ransom-canvas-incident-congress-investigation) | Instructure ransom payment + Congressional investigation |
| SANS | 2 | [link](https://isc.sans.edu) | Internet Storm Center analysis |
| Wiz | 2 | [link](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised) | Authoritative Mini Shai-Hulud technical write-up |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com/state-sponsored-actors-better-known-as-the-friends-you-dont-want/) | State-sponsored actor tradecraft analysis |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | Threat research |
| CISA | 1 | [link](https://www.cisa.gov) | Advisory coverage |
| Sysdig | 1 | [link](https://sysdig.com/blog) | Cloud-native threat research |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | Endpoint research |
| BellingCat | 1 | [link](https://www.bellingcat.com) | OSINT / surveillance reporting |
| Upwind | 1 | [link](https://www.upwind.io/feed/blog) | Cloud security analysis |
| Schneier | 1 | — | Copy.Fail Linux LPE analysis (source URL not captured by pipeline) |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com/Breach/CushmanWakefield) | Cushman & Wakefield breach disclosure |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Pin lockfiles to pre-2026-05-11 versions of `@tanstack/*`, `@uipath/*`, `@mistralai/mistralai` and `guardrails-ai`; rotate every CI/CD-reachable secret (GitHub OIDC, npm tokens, AWS/GCP/Azure keys, Kubernetes service accounts, Vault tokens, SSH keys) and hunt for the `gh-token-monitor` daemon BEFORE rotating to avoid triggering the destructive token-revocation handler (ref: 3.1).
- 🔴 **IMMEDIATE:** Apply the SAP May 2026 security notes for Commerce Cloud (CVE-2026-34263, unauthenticated RCE) and S/4HANA (CVE-2026-34260, SQLi). Treat internet-exposed Commerce Cloud instances as pre-compromise until verified (ref: 3.2).
- 🟠 **SHORT-TERM:** Stage Copy.Fail (Linux kernel LPE) patches for every multi-tenant Linux host — CI runners, dev VMs, container hosts. Until patched, enable IMA/EVM appraisal where supported; file-checksum FIM tools will not see this exploit (ref: 3.3).
- 🟠 **SHORT-TERM:** EDR-hunt for Seedworm tradecraft — `node.exe` parent of `fmapp.exe` or `sentinelmemoryscanner.exe`, `powershell.exe` spawned from `node.exe`, execution of legitimate Fortemedia / SentinelOne binaries from non-standard paths. Block listed Seedworm domains and hashes (ref: 3.4).
- 🟠 **SHORT-TERM:** Canvas / Instructure customers: rotate admin sessions, force admin password reset, audit Canvas admin-session logs back to 25 April 2026 from non-corporate IPs, disable Free-for-Teacher accounts until XSS class is remediated (ref: 3.5).
- 🟡 **AWARENESS:** AI-augmented intrusions (Vibe Hacking, SHADOW-AETHER-040/064) generate one-off tools on demand — file-hash detection will lag. Shift detection emphasis to behavioural signatures (Chisel/Neo-reGeorg/Impacket behaviour, dynamic SSH port forwards, unexpected SOCKS5 endpoints) (ref: 3.6).
- 🟢 **STRATEGIC:** The Shai-Hulud campaign demonstrates that SLSA / Sigstore provenance attestations alone do not prove a package is uncompromised — they only prove it was published through the legitimate pipeline. Add registry-side anomaly detection (new optionalDependencies, sudden release cadence, embedded binary blobs), and require human review for major-version bumps of foundation packages in CI/CD policy. Re-evaluate sole reliance on signed-package trust signals.

---

*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 89 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
