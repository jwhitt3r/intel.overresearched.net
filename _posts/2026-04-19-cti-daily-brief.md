---
layout: post
title:  "CTI Daily Brief: 2026-04-19 — CISA Axios npm Supply Chain Alert; North Korean Lazarus $290M Kelp Heist; Microsoft Teams Helpdesk Impersonation"
date:   2026-04-20 20:06:21 +0000
description: "53 reports across 13 sources. CISA issued an emergency alert on a compromised Axios npm package delivering a RAT; Lazarus sub-group TraderTraitor stole $290M from LayerZero/Kelp; Microsoft warned of Teams-based helpdesk impersonation; Vercel disclosed a double OAuth supply chain compromise via Context.ai; The Gentlemen RaaS paired with SystemBC in a 1,570-victim botnet."
category: daily
categories: [cti, daily-brief]
tags: [cti, daily-brief, the-gentlemen, qilin, everest, lazarus, scattered-spider, axios-npm, context-ai]
classification: TLP:CLEAR
reporting_period: "2026-04-19"
generated: "2026-04-20"
draft: true
severity: high
report_count: 53
sources:
  - CISA
  - BleepingComputer
  - RecordedFutures
  - Wiz
  - AlienVault
  - RansomLock
  - Unit42
  - Crowdstrike
  - SANS
  - Wired Security
  - Schneier
  - BellingCat
---
| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-19 (24h) | TLP:CLEAR | 2026-04-20 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 53 reports across 13 sources during the 24-hour window, with 36 items rated high severity and no reports reaching critical — though the correlation engine flagged one critical-risk trend around sophisticated APT use of social engineering and remote services. The day's standout item is a CISA alert on a software supply chain compromise of the Axios npm package (versions 1.14.1 and 0.30.4), which injected the malicious `plain-crypto-js@4.2.1` dependency to deliver a remote access trojan. A separate, concurrent supply chain incident saw Vercel disclose that attackers abused a compromised Context.ai OAuth application to pivot into its Google Workspace. Nation-state activity was also prominent: LayerZero attributed a $290 million theft from crypto platform Kelp to North Korea's TraderTraitor (Lazarus sub-group), and a British leader of the Scattered Spider collective pleaded guilty to an $8M SMS-phishing scheme. Ransomware pressure remained high, with RansomLook surfacing 23 new victim posts attributed to Qilin, The Gentlemen, Everest, Payload, Krybit, Lamashtu, PEAR, and Payoutsking. No CISA KEV additions were recorded in the period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | None in period |
| 🟠 **HIGH** | 36 | CISA Axios npm alert; Vercel/Context.ai OAuth compromise; Lazarus/TraderTraitor $290M Kelp theft; Microsoft Teams helpdesk impersonation; Gentlemen/SystemBC ransomware; Qilin + Everest leak-site posts; Windows Server OOB updates |
| 🟡 **MEDIUM** | 5 | French ANTS passport-agency breach; Italy Poste €15M GDPR fine; Bluesky DDoS; Musk/X French probe; SEL (qilin) |
| 🟢 **LOW** | 1 | Microsoft Teams launch failure (reverted service update) |
| 🔵 **INFO** | 11 | Wiz/Databricks integration; CrowdStrike + Unit42 AI-exploit commentary; Bellingcat OSINT guide; SANS Stormcast/EPSS |

## 3. Priority Intelligence Items

### 3.1 CISA: Supply Chain Compromise of Axios npm Package
**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager)

CISA issued a formal alert after Axios npm versions **1.14.1** and **0.30.4** were published (30 March 2026) with a malicious dependency, `plain-crypto-js@4.2.1`, that stages multi-stage payloads from threat-actor infrastructure and drops a remote access trojan. Any CI/CD pipeline, developer workstation, or production build that ran `npm install` or `npm update` against the affected versions should be considered potentially compromised. CISA's remediation guidance includes downgrading to `axios@1.14.0` or `axios@0.30.3`, deleting `node_modules/plain-crypto-js/`, rotating VCS tokens, CI/CD secrets, cloud keys, npm tokens, and SSH keys, and blocking outbound connections to `Sfrclak[.]com`. MITRE mappings: T1195.002 (Supply Chain Compromise), T1190 (Exploit Public-Facing Application), T1566.002 (Spearphishing Link), T1078 (Valid Accounts).

#### Indicators of Compromise
```
Malicious package: plain-crypto-js@4.2.1
Affected: axios@1.14.1, axios@0.30.4
Safe: axios@1.14.0, axios@0.30.3
C2 domain: Sfrclak[.]com
```

> **SOC Action:** Inventory all Axios versions across SBOMs, artifact repositories, and live runtimes; hunt for the exact npm tarball hashes of `axios@1.14.1` / `axios@0.30.4` and `plain-crypto-js@4.2.1` in Nexus/Artifactory caches. Block egress to `Sfrclak[.]com` at the proxy. In developer and CI/CD environments, set `ignore-scripts=true` and `min-release-age=7` in `.npmrc`. Rotate any secret that was ever injected into a build where the compromised Axios build ran, and hunt EDR for unexpected child processes of `node` and anomalous egress during `npm install`.

### 3.2 Vercel Discloses Double Supply Chain Compromise via Context.ai OAuth
**Source:** [Wiz](https://www.wiz.io/blog/contextai-oauth-token-compromise)

Vercel disclosed that an attacker compromised an employee's Google Workspace via OAuth tokens issued to the third-party AI office-suite vendor **Context.ai**. A Vercel employee had authorised the Context.ai app with "Allow All" scopes, giving the attacker broad delegated access into the Workspace tenant and, by extension, into Vercel's downstream SaaS estate. Hudson Rock reporting suggests an infostealer infection of a Context.ai employee was the initial foothold into Context.ai itself; claims of responsibility by an actor purporting to be "ShinyHunters" are unverified. Wiz links this tradecraft to the Salesloft Drift → Salesforce incidents and Midnight Blizzard's OAuth-abuse campaign against Microsoft — a pattern of trusted-third-party OAuth becoming the initial-access vector of choice for stealthy SaaS compromise. MITRE: T1078 (Valid Accounts), T1528 (Steal Application Access Token), T1204 (User Execution).

#### Indicators of Compromise
```
OAuth Client ID: 110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com
```

> **SOC Action:** In Google Workspace, navigate to Admin Console → Security → API Controls → Manage Third-Party App Access and search for "Context" or the listed OAuth Client ID; revoke if present. Pull `admin.googleapis.com` activity logs for `authorize`, `update_application_setting`, and token_authorization events across all users in the last 90 days. For every tenant that authorises Context.ai, rotate credentials for users whose tokens were issued, and review Drive/Mail/Calendar access logs for anomalous API-driven reads. Enforce OAuth allow-lists for high-privilege scopes and require admin consent for any "Allow All" request going forward.

### 3.3 Microsoft: Teams Increasingly Abused for IT Helpdesk Impersonation
**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-teams-increasingly-abused-in-helpdesk-impersonation-attacks/)

Microsoft reported a surge in threat actors abusing **external Teams chats** to impersonate IT or helpdesk staff, convincing users to initiate a remote-support session via **Quick Assist**. The observed nine-stage chain: external Teams contact → Quick Assist remote control → reconnaissance via `cmd.exe` / PowerShell → payload drop to `ProgramData` → DLL side-loading via signed binaries (Autodesk, Adobe Reader, Windows Error Reporting, DLP agents) → HTTPS C2 blending into outbound traffic → registry-based persistence → lateral movement via **WinRM** to domain controllers → exfiltration via **Rclone** to external cloud storage with filters to reduce volume. MITRE: T1566 (Phishing), T1219 (Remote Access Software), T1021.006 (WinRM), T1574.002 (DLL Side-Loading), T1567.002 (Exfil to Cloud Storage).

> **SOC Action:** Treat external Teams messages as untrusted by default — enforce the Teams external-communication warning banner and, where tenable, block cross-tenant chat for non-partner domains. Hunt EDR for `QuickAssist.exe` / `quickassist.exe` execution lineage followed within 30 minutes by `powershell.exe` or `cmd.exe` spawning from `C:\ProgramData\`. Alert on any new outbound HTTPS connection sourced from signed-application processes (Autodesk, Adobe Acrobat, `WerFault.exe`) that lack prior baseline. Restrict WinRM to a controlled admin-jump-host subnet and alert on `winrs`/`Enter-PSSession` from user workstations. Inventory and block `rclone.exe` unless explicitly whitelisted, and monitor `rclone` command-line patterns regardless of binary name.

### 3.4 The Gentlemen Ransomware Paired With SystemBC Proxy (1,570-victim botnet)
**Sources:** [AlienVault](https://otx.alienvault.com/pulse/69e63f93a0ddbd53fcab3f51), [RansomLook (The Gentlemen group)](https://www.ransomlook.io//group/the%20gentlemen)

AlienVault OTX published an incident-response write-up of The Gentlemen RaaS, which has claimed 320+ victims since mid-2025 (240 in early 2026) and ships multi-platform lockers for Windows, Linux, NAS, BSD, and ESXi. The observed intrusion used **SystemBC** as a covert SOCKS5 proxy for tunnelling and payload staging; analysis of the SystemBC C2 revealed a botnet of **1,570 corporate victims**. The kill chain progressed from AnyDesk remote access → domain-controller compromise → credential harvesting with Mimikatz → lateral movement via PsExec and administrative shares → Cobalt Strike payload delivery → defence-evasion (security-tool tampering, log clearing) → scheduled tasks and services for persistence → **Group Policy-driven ransomware deployment** including ESXi encryption. MITRE (from report): T1021.001/.002/.006, T1003, T1486, T1490, T1489, T1543.003, T1562.001, T1562.004, T1570, T1573.002, T1059.001/.003. RansomLook surfaced three additional Gentlemen victim posts in the period (Champion Homes, Euro Creations, SmartSystems).

#### Indicators of Compromise (selection)
```
SHA256: 025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a
SHA256: 1eece1e1ba4b96e6c784729f0608ad2939cfb67bc4236dfababbe1d09268960c
SHA256: 22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67
SHA256: 3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235
SHA256: 860a6177b055a2f5aa61470d17ec3c69da24f1cdf0a782237055cba431158923
SHA256: 992c951f4af57ca7cd8396f5ed69c2199fd6fd4ae5e93726da3e198e78bec0a5
SHA256: f736be55193c77af346dbe905e25f6a1dee3ec1aedca8989ad2088e4f6576b12
Leak site: tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion
```

> **SOC Action:** Block the listed SHA-256s at AV/EDR and hunt back 30 days. Restrict AnyDesk and other RMM to documented administrators with conditional-access + MFA; alert on AnyDesk/TeamViewer/ScreenConnect processes on domain controllers and ESXi management interfaces. On ESXi, require MFA for vCenter/SSO and block SSH from non-management networks. For SystemBC indicators, inspect egress for long-lived TCP sessions to uncommon high ports from servers that should not initiate outbound connections. Audit GPO changes over the last 14 days for unknown startup/logon scripts or software-installation entries — the Group Policy deployment vector is specifically called out in the report.

### 3.5 North Korea's TraderTraitor (Lazarus) Blamed for $290M Theft From Kelp via LayerZero
**Source:** [RecordedFutures](https://therecord.media/crypto-north-korea-theft-kelp)

LayerZero published a post-mortem attributing the $290M Kelp heist to **TraderTraitor**, a Pyongyang crypto-theft sub-cluster of **Lazarus**. Kelp relied on LayerZero as its sole Decentralized Verifier Network (DVN) for the `rsETH` token; the attackers compromised the single DVN and minted large volumes of `rsETH` without any real Ether collateral, then used the synthetic tokens as collateral on other platforms to borrow real ETH and USD-pegged stablecoins. A simultaneous DDoS against backup systems was used to inhibit defender response, and the tools were built to self-destruct on completion. LayerZero has not disclosed the precise compromise vector; comparable past Lazarus crypto heists have traced back to malware-laden laptops. Attribution is LayerZero's, not independently corroborated; Kelp disputes the framing. MITRE: T1498 (Network DoS), T1485 (Data Destruction), T1190 (Exploit Public-Facing Application), T1566 (Phishing).

> **SOC Action:** Crypto infra operators running LayerZero DVNs should audit their configurations for single-DVN dependencies and move to multi-DVN redundancy per LayerZero guidance. More broadly, Web3 engineering teams should treat developer laptops as Tier 0 assets — require EDR, FIDO2 for code-signing and deployer-key access, hardware-wallet custody for operational funds, and network segmentation between development and production signer hosts. Threat-hunt for TraderTraitor/Lazarus TTPs: fake recruiter contact on LinkedIn, trojanised npm/PyPI packages aimed at crypto engineers, and `javascript`-delivered post-exploit tooling in CI runners.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Sophisticated APT groups leveraging social engineering and remote services | Iranian APT Seedworm targeting global orgs via Microsoft Teams; The Gentlemen & SystemBC (batch 80) |
| 🟠 **HIGH** | Increased phishing and credential-access techniques across sectors | Seiko USA defacement; Lazarus/Kelp $290M; Qilin victim posts; Teams helpdesk impersonation; FlowerStorm phishing kit |
| 🟠 **HIGH** | Ransomware-as-a-Service operations targeting multiple sectors | Qilin: SEL, City'Pro, The Go Solution, COHAN Hospitals; plus The Gentlemen and Everest double-extortion activity |
| 🟠 **HIGH** | Everest ransomware group consistently running double-extortion without encryption | Everest leak-site posts: Umiles, Tokoparts, Straight Line Logistics, PT Brantas Abipraya, Nutrabio, Citizens Bank, Complete Aircraft, Frost Bank |
| 🟡 **MEDIUM** | Trusted-third-party OAuth integrations as initial access into SaaS estates | Context.ai → Vercel; Salesloft Drift → Salesforce parallel; Midnight Blizzard pattern |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **qilin / Qilin** (62 + 26 reports, pipeline-wide) — RaaS; four new victim posts today including COHAN (Colombian hospitals cooperative) and a French legal firm
- **The Gentlemen / the gentlemen** (54 + 24 reports) — RaaS; AlienVault incident-response report plus three fresh leak-site posts
- **Everest** (6 today; 3rd-tier pipeline-wide) — eight fresh double-extortion posts across banking, aerospace, logistics, and manufacturing
- **Scattered Spider** — leader Tyler Robert Buchanan pleaded guilty; SMS-phishing/SIM-swap/MFA-fatigue playbook confirmed in court filings
- **TraderTraitor / Lazarus** — named by LayerZero for the $290M Kelp theft
- **ShinyHunters** (unverified) — claimed Vercel/Context.ai OAuth incident; copycat impersonation possible
- **nightspire, TeamPCP, Coinbase Cartel, DragonForce, shadowbyt3$** — remain in the pipeline-wide top 10 without fresh activity today

### Malware Families
- **Gentlemen ransomware** (9 pipeline reports; 3 today) — multi-OS lockers including ESXi
- **SystemBC** — SOCKS5 proxy used alongside Gentlemen; 1,570-victim botnet observed
- **Cobalt Strike + Mimikatz** — post-exploit staples in The Gentlemen intrusion
- **FakeWallet / SparkKitty** — 20+ trojan iOS App Store apps masquerading as MetaMask, Ledger, Trust Wallet, Coinbase, TokenPocket, imToken, and Bitpie; primarily targets China
- **FlowerStorm** — Microsoft-credential phishing kit using Cloudflare-fronted `continuousperformance.de` hosts
- **remote access trojan** (unnamed) — payload dropped by the Axios `plain-crypto-js` supply-chain compromise

Vulnerability trending data showed no fresh CVEs in the 24-hour window (the top trending entries — CVE-2024-27198/27199 and others — are carry-over from prior periods).

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 23 | [link](https://www.ransomlook.io/) | Leak-site aggregation: Qilin (5), Everest (8), The Gentlemen (3), Payload (2), PEAR (1), Payoutsking (1), Krybit (1), Lamashtu (1), plus one Qilin medium-severity infra post |
| BleepingComputer | 7 | [link](https://www.bleepingcomputer.com/news/security/microsoft-teams-increasingly-abused-in-helpdesk-impersonation-attacks/) | Teams helpdesk impersonation, Scattered Spider plea, Windows Server OOB, Seiko defacement, backup-strategy commentary |
| RecordedFutures | 6 | [link](https://therecord.media/crypto-north-korea-theft-kelp) | Lazarus/Kelp $290M; Scattered Spider plea; Italy Poste GDPR fine; French ANTS breach; Bluesky DDoS; Musk/X probe |
| AlienVault (OTX) | 4 | [link](https://otx.alienvault.com/pulse/69e63f93a0ddbd53fcab3f51) | The Gentlemen/SystemBC IR write-up; FakeWallet (x2); FlowerStorm phishing kit |
| Wiz | 3 | [link](https://www.wiz.io/blog/contextai-oauth-token-compromise) | Context.ai OAuth compromise; Wiz Code CI/CD; Wiz/Databricks integration |
| SANS ISC | 2 | [link](https://isc.sans.edu/diary/rss/32914) | EPSS-driven CVE prioritisation; Stormcast podcast |
| Unknown (Telegram) | 2 | — | VIP-exploit-channel advert; Darkfeed weekly ransomware stats (channel names redacted) |
| CISA | 1 | [link](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager) | Axios npm supply chain compromise alert |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/ai-software-security-risks/) | Frontier AI models accelerating zero-day / N-day discovery |
| Crowdstrike | 1 | [link](https://www.crowdstrike.com/en-us/blog/frontier-ai-collapses-exploit-window-how-defenders-must-respond/) | Frontier AI collapsing the exploit window (defender guidance) |
| Wired Security | 1 | [link](https://www.wired.com/story/the-weird-twisting-tale-of-how-china-spied-on-alysa-liu-and-her-dad/) | Alleged PRC transnational repression case |
| Schneier | 1 | — | Commentary on NYT speculation about Satoshi Nakamoto's identity |
| BellingCat | 1 | [link](https://www.bellingcat.com/resources/2026/04/20/xiaohongshu-rednote-open-source-guide/) | OSINT guide to Xiaohongshu/RedNote |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Run a full inventory of Axios npm usage across CI pipelines, container images, and developer machines; downgrade `axios@1.14.1` → `1.14.0` and `axios@0.30.4` → `0.30.3`; delete `node_modules/plain-crypto-js/`; rotate any secret that was ever accessible during a build of an affected version; block egress to `Sfrclak[.]com`. See §3.1.

- 🔴 **IMMEDIATE:** Audit Google Workspace (and any SaaS tenant with equivalent OAuth controls) for the Context.ai application — OAuth Client ID `110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com`. Revoke, rotate affected user credentials, and pull 90 days of OAuth authorisation and API-usage logs. See §3.2.

- 🟠 **SHORT-TERM:** Roll out (or verify) Teams external-chat warning banners, block cross-tenant chat for non-partner domains where feasible, and deploy a Quick Assist / RMM watchlist in EDR correlated with PowerShell and Rclone execution. Pair with a short user-awareness note about helpdesk-impersonation lures. See §3.3.

- 🟠 **SHORT-TERM:** Harden against The Gentlemen tradecraft: enforce MFA on vCenter/ESXi, restrict GPO authoring to a tightly-scoped admin tier with change alerting, and hunt for the published Gentlemen/SystemBC SHA-256s. See §3.4.

- 🟡 **AWARENESS:** For Web3 / crypto-infra customers, flag LayerZero's recommendation to run multi-DVN redundancy and the broader Lazarus/TraderTraitor developer-laptop targeting pattern. See §3.5.

- 🟢 **STRATEGIC:** Treat trusted-third-party OAuth as a first-class supply-chain vector. Stand up an OAuth app-governance programme (admin-consent workflow, scope restrictions, quarterly app reviews) and wire OAuth token-grant telemetry into SIEM. Correlates with the Context.ai, Salesloft Drift, and Midnight Blizzard pattern highlighted in §4.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 53 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
