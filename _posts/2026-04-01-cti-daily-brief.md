---
layout: post
title: "CTI Daily Brief: 2026-04-01 — DPRK-Linked $280M Drift Crypto Heist, Qilin EDR Killer Analysis, F5 BIG-IP APM Actively Exploited"
date: 2026-04-02 20:10:00 +0000
description: "High-tempo day dominated by a $280M cryptocurrency theft attributed to North Korea, Cisco Talos analysis of Qilin's EDR-killing infection chain, active exploitation of F5 BIG-IP APM and Apple DarkSword iOS flaws, a Chinese-nexus TrueConf zero-day campaign, and a massive ransomware wave led by DragonForce and Netrunner across healthcare, manufacturing, and telecoms."
category: daily
tags: [cti, daily-brief, dragonforce, qilin, north-korean-hackers, darksword, handala, cve-2025-53521]
classification: TLP:CLEAR
reporting_period: "2026-04-01"
generated: "2026-04-02"
draft: true
severity: critical
report_count: 117
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - Cisco Talos
  - RecordedFutures
  - CISA
  - SANS
  - Wired Security
  - Sysdig
  - AlienVault
  - Schneier
  - Elastic Security Labs
  - BellingCat
  - Permiso
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-01 (24h) | TLP:CLEAR | 2026-04-02 |

## 1. Executive Summary

The pipeline processed 117 reports from 15 sources over the last 24 hours, with 42 rated critical and 33 high — an exceptionally elevated threat tempo. The dominant theme is a ransomware surge led by DragonForce (12+ victims), Netrunner (6 victims spanning healthcare and telecoms), and Qilin, whose EDR-killing toolchain received detailed technical analysis from Cisco Talos. Outside ransomware, the headline item is a $280 million theft from DeFi platform Drift, attributed by Elliptic and independent researchers to DPRK-linked operators using social engineering and pre-signed transaction abuse. Active exploitation continues against F5 BIG-IP APM (CVE-2025-53521, 14,000+ instances exposed) and Apple iOS devices via the DarkSword exploit kit, for which Apple released iOS 18.7.7. CISA published an ICS advisory for a CVSS 9.8 deserialization flaw in Hitachi Energy Ellipse affecting critical manufacturing worldwide. A Chinese-nexus campaign dubbed TrueChaos exploited a TrueConf zero-day (CVE-2026-3502) to deliver Havoc C2 implants to Southeast Asian government targets.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 42 | Drift $280M crypto heist; Qilin EDR killer; F5 BIG-IP APM RCE; Cisco IMC auth bypass; DarkSword iOS exploit kit; DragonForce/Netrunner/Akira ransomware wave; CVE batch (LIBPNG, Libarchive, NATS, bn.js, brace-expansion) |
| 🟠 **HIGH** | 33 | ShareFile pre-auth RCE chain; Stryker/Handala recovery; BEC democratisation; AdTech browser hijacking; residential proxy abuse; Coinbase Cartel / WorldLeaks / Beast ransomware |
| 🟡 **MEDIUM** | 38 | Microsoft CVE advisories; open-source library vulnerabilities; DevTools policy updates |
| 🟢 **LOW** | 2 | Samsung compatibility advisory; minor tooling update |
| 🔵 **INFO** | 2 | SandyClaw AI agent sandbox research |

## 3. Priority Intelligence Items

### 3.1 DPRK-Attributed $280M Drift Cryptocurrency Theft

**Source:** [Recorded Future News](https://therecord.media/drift-crypto-confirms-280-million-stolen-north-korea)

Decentralised finance platform Drift confirmed that $280 million was withdrawn during a security incident on 1 April 2026. Attackers conducted a multi-week preparation campaign, compromising Drift's security council administrative powers through sophisticated social engineering to obtain pre-signed transaction approvals. Two pre-signed transactions executed on 1 April bypassed withdrawal limits. Blockchain security firm Elliptic identified on-chain laundering methodologies and network-level indicators consistent with previous DPRK-attributed operations. If confirmed, this represents the eighteenth DPRK cryptocurrency theft Elliptic has tracked in 2026, totalling over $300 million. The tactics resemble those deployed in the $1.5 billion Bybit hack. North Korean operators were separately confirmed responsible for the recent Axios npm supply chain compromise.

> **SOC Action:** Monitor for outbound connections to known DPRK-linked cryptocurrency laundering infrastructure. Review any organisational exposure to Drift Protocol DeFi services and assess whether API keys or wallet integrations require rotation.

### 3.2 Qilin Ransomware EDR Killer — Technical Deep-Dive

**Source:** [Cisco Talos](https://blog.talosintelligence.com/qilin-edr-killer/)

Cisco Talos published a detailed analysis of the malicious `msimg32.dll` deployed in Qilin ransomware attacks. The DLL initiates a multi-stage infection chain that disables over 300 EDR drivers across virtually every vendor. The loader uses SEH/VEH-based obfuscation to conceal API invocation, suppresses ETW event generation at runtime, and decrypts/executes the EDR killer payload entirely in memory. Once active, the killer loads two helper drivers: `rwdrv.sys` for physical memory access and `hlpdrv.sys` for EDR process termination. Before terminating EDR processes, the malware unregisters monitoring callbacks to prevent interference. The DLL is side-loaded by a legitimate application importing from `msimg32.dll`. ATT&CK techniques: T1574 (DLL Side-Loading), T1562 (Impair Defenses).

> **SOC Action:** Hunt for unsigned `msimg32.dll` files outside `C:\Windows\System32`. Alert on any loading of `rwdrv.sys` or `hlpdrv.sys` kernel drivers. Monitor for ETW provider registration changes and EDR callback deregistration events. Verify EDR tamper-protection is enabled across all endpoints.

### 3.3 UAT-10608 Large-Scale Credential Harvesting via React2Shell

**Source:** [Cisco Talos](https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/)

Cisco Talos disclosed a large-scale automated credential harvesting campaign by threat cluster UAT-10608. The operation exploits CVE-2025-55182 (React2Shell), a pre-authentication RCE in React Server Components, to compromise Next.js applications. As of disclosure, 766 hosts have been compromised, yielding database credentials (91.5%), SSH private keys (78.2%), AWS credentials (25.6%), live Stripe API keys (11.4%), and GitHub tokens (8.6%) — over 10,120 files exfiltrated. The C2 infrastructure hosts a GUI called "NEXUS Listener" for operator analytics. Scanning appears automated via Shodan/Censys enumeration of public Next.js deployments. ATT&CK techniques: T1190 (Exploit Public-Facing Application), T1041 (Exfiltration Over C2).

> **SOC Action:** Audit all public-facing Next.js deployments for CVE-2025-55182 exposure. Rotate any AWS credentials, SSH keys, GitHub tokens, and Stripe API keys on servers running vulnerable React Server Components. Query network logs for connections to known NEXUS Listener C2 infrastructure.

### 3.4 Apple iOS 18.7.7 — DarkSword Exploit Kit Actively Exploited

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/apple-expands-ios-18-updates-to-more-iphones-to-block-darksword-attacks/)

Apple expanded iOS 18.7.7 availability to address the actively exploited DarkSword exploit kit, which targets iOS 18.4 through 18.7 using six CVEs (CVE-2025-31277, CVE-2025-43529, CVE-2026-20700, CVE-2025-14174, CVE-2025-43510, CVE-2025-43520). DarkSword has been used by Turkish commercial surveillance vendor PARS Defense, UNC6748, and suspected Russian espionage group UNC6353. Three malware families are deployed: GhostBlade (JavaScript infostealer), GhostKnife (backdoor), and GhostSaber (code execution/data theft). The exploit kit source code was released on GitHub last month, broadening the threat beyond state-sponsored use.

> **SOC Action:** Enforce iOS 18.7.7 or iOS 26 on all managed Apple devices via MDM. Block known DarkSword C2 domains at the proxy/firewall layer. Prioritise patching for devices unable to upgrade to iOS 26.

### 3.5 TrueConf Zero-Day (CVE-2026-3502) — Chinese-Nexus Campaign "TrueChaos"

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-trueconf-zero-day-to-push-malicious-software-updates/)

Check Point researchers disclosed "TrueChaos," a campaign exploiting CVE-2026-3502 in TrueConf video conferencing servers (versions 8.1.0–8.5.2) to distribute malicious software updates. The missing integrity check in the update mechanism allows attackers controlling the server to replace updates with arbitrary executables pushed to all connected clients. Check Point attributes TrueChaos with moderate confidence to a Chinese-nexus threat actor based on TTPs, Alibaba Cloud/Tencent C2 hosting, and victimology targeting Southeast Asian government entities. The infection chain includes DLL sideloading, reconnaissance (tasklist, tracert), UAC bypass via `iscicpl.exe`, and likely deployment of the Havoc C2 framework. Patched in version 8.5.3. ATT&CK: T1195 (Supply Chain Compromise), T1574 (DLL Side-Loading), T1548 (Abuse Elevation Control Mechanism).

#### Indicators of Compromise
```
Files: poweriso.exe, 7z-x64.dll, iscsiexe.dll
Path: %AppData%\Roaming\Adobe\update.7z
C2: Alibaba Cloud / Tencent hosted infrastructure (specific IPs in Check Point report)
```

> **SOC Action:** Identify any TrueConf Server deployments and upgrade to 8.5.3 immediately. Hunt for `poweriso.exe`, `7z-x64.dll`, or `iscsiexe.dll` on endpoints. Monitor for update.7z artifacts under `%AppData%\Roaming\Adobe\`.

### 3.6 F5 BIG-IP APM RCE — 14,000+ Instances Exposed, Actively Exploited

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-14-000-f5-big-ip-apm-instances-still-exposed-to-rce-attacks/)

CVE-2025-53521, originally disclosed as a DoS flaw in October 2025, was reclassified as a critical RCE vulnerability in F5 BIG-IP APM after evidence of active exploitation emerged. Shadowserver tracks over 17,100 IPs with BIG-IP APM fingerprints, of which 14,000+ remain unpatched. CISA added the flaw to its Known Exploited Vulnerabilities catalogue and ordered federal agencies to patch by 31 March — a deadline that has passed. F5 advises checking disks, logs, and terminal history for compromise indicators and rebuilding affected systems from scratch if compromise is confirmed.

> **SOC Action:** Verify all BIG-IP APM instances are patched against CVE-2025-53521. If running vulnerable versions with access policies on virtual servers, assume compromise and initiate forensic review per F5 guidance. Rebuild from known-good configurations if compromise indicators are found.

### 3.7 Cisco IMC Authentication Bypass (CVE-2026-20093) and SSM On-Prem RCE (CVE-2026-20160)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-cisco-imc-auth-bypass-gives-attackers-admin-access/)

Cisco released patches for CVE-2026-20093, a critical authentication bypass in the Integrated Management Controller (IMC) password change functionality affecting UCS C-Series and E-Series servers. Unauthenticated attackers can send crafted HTTP requests to alter any user password, including Admin accounts. No workarounds exist. Separately, CVE-2026-20160 enables unauthenticated RCE on Smart Software Manager On-Prem via crafted API requests, granting root-level command execution. No active exploitation reported yet for either flaw.

> **SOC Action:** Patch all Cisco IMC and SSM On-Prem instances immediately. Audit IMC access logs for unexpected password change requests. Restrict IMC management interfaces to trusted networks.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks leveraging popular software packages | Axios npm compromise (STARDUST CHOLLIMA / UNC1069); TeamPCP multi-stage supply chain attacks; Mercor/LiteLLM supply chain incident |
| 🟠 **HIGH** | Ransomware surge targeting healthcare, telecoms, manufacturing with sophisticated TTPs | Qilin (3+ victims + EDR killer); DragonForce (12+ victims); Netrunner (6 victims incl. hospitals); Payoutsking (4 victims) |
| 🟠 **HIGH** | Phishing campaigns exploiting software vulnerabilities and social engineering | WhatsApp fake app spyware distribution; EvilTokens device code phishing; TrueConf zero-day malicious updates; DarkSword iOS exploit kit |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (38 reports) — Prolific RaaS operator; EDR killer toolchain detailed by Cisco Talos; targeting healthcare, legal, media
- **TeamPCP** (25 reports) — Supply chain attack group targeting security infrastructure
- **Nightspire** (22 reports) — Active ransomware operator across multiple sectors
- **DragonForce** (18 reports) — High-volume ransomware campaign hitting retail, government, logistics, manufacturing
- **Akira** (17 reports) — Established RaaS group; Bitcoin ransoms ranging $200K–$4M
- **Handala** (12 reports) — Iranian-linked hacktivist group; Stryker wiper attack recovery ongoing
- **ShinyHunters** (10 reports) — Data theft and extortion operations
- **Coinbase Cartel** (9 reports) — Emerging RaaS operator with double-extortion model
- **Netrunner** (6 reports, today) — New entrant targeting healthcare (Japanese hospitals), telecoms, fitness, manufacturing

### Malware Families

- **DragonForce Ransomware** (17 reports) — Primary payload for DragonForce operations
- **Akira Ransomware** (13 reports) — Encrypts via Windows CryptoAPI with .akira extension; Tor-based exfiltration
- **Qilin Ransomware** (10 reports) — RaaS model with advanced EDR evasion capabilities
- **CanisterWorm** (7 reports) — Worm-based propagation malware tracked across multiple campaigns
- **PLAY Ransomware** (5 reports) — Established RaaS family with ongoing operations

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 44 | — | Ransomware leak site monitoring; DragonForce, Netrunner, Qilin, Akira victim disclosures |
| Microsoft | 32 | [link](https://msrc.microsoft.com) | CVE advisories for open-source libraries (LIBPNG, Libarchive, NATS, bn.js, brace-expansion, OpenSC) |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com) | F5 BIG-IP, Cisco IMC, DarkSword, TrueConf, ShareFile, Stryker coverage |
| Cisco Talos | 6 | [link](https://blog.talosintelligence.com) | Qilin EDR killer analysis; UAT-10608 credential harvesting; BEC democratisation |
| RecordedFutures | 4 | [link](https://therecord.media) | Drift $280M crypto heist DPRK attribution |
| CISA | 3 | [link](https://www.cisa.gov) | ICS advisory for Hitachi Energy Ellipse (CVSS 9.8) |
| SANS | 3 | [link](https://isc.sans.edu) | Threat monitoring and analysis |
| Wired Security | 2 | [link](https://www.wired.com/category/security/) | Coruna iOS exploit kit disclosure |
| AlienVault | 2 | [link](https://otx.alienvault.com) | Qilin EDR killer; AdTech browser hijacking |
| Sysdig | 2 | [link](https://sysdig.com) | Cloud-native security research |
| Schneier | 1 | [link](https://www.schneier.com) | Coruna iOS hacking toolkit leak commentary |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | Threat detection research |
| BellingCat | 1 | [link](https://www.bellingcat.com) | OSINT investigation |
| Permiso | 1 | [link](https://permiso.io) | SandyClaw AI agent sandbox research |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch all F5 BIG-IP APM instances against CVE-2025-53521 — active exploitation confirmed, CISA KEV deadline has passed, and 14,000+ instances remain exposed. Assume compromise on unpatched systems and initiate forensic review per F5 guidance.

- 🔴 **IMMEDIATE:** Enforce iOS 18.7.7 or iOS 26 on all managed Apple devices to mitigate the DarkSword exploit kit (6 CVEs, actively exploited by state-sponsored and commercial surveillance actors). The public release of the exploit kit source code significantly increases the threat surface.

- 🔴 **IMMEDIATE:** Audit all public-facing Next.js applications for CVE-2025-55182 (React2Shell) exposure. UAT-10608 has already compromised 766 hosts and exfiltrated AWS credentials, SSH keys, and GitHub tokens at scale. Rotate all secrets on any server running vulnerable React Server Components.

- 🟠 **SHORT-TERM:** Deploy detection rules for Qilin's EDR-killing infection chain — hunt for unsigned `msimg32.dll` outside System32, `rwdrv.sys`/`hlpdrv.sys` kernel driver loads, and ETW provider tampering. Verify EDR tamper-protection is active and test EDR resilience against known bypass techniques.

- 🟠 **SHORT-TERM:** Patch Cisco IMC (CVE-2026-20093) and SSM On-Prem (CVE-2026-20160) and restrict management interfaces to trusted networks. Identify any TrueConf Server deployments and upgrade to 8.5.3 to close the zero-day exploited in the TrueChaos campaign.

- 🟡 **AWARENESS:** The DPRK-attributed $280M Drift cryptocurrency theft underscores the continued targeting of DeFi platforms through social engineering of administrative approval processes. Organisations managing multi-signature wallets or governance councils should review approval workflows for pre-signed transaction abuse vectors.

- 🟢 **STRATEGIC:** The convergence of supply chain attacks (Axios npm, TeamPCP, LiteLLM) and RaaS-model ransomware (Qilin, DragonForce, Netrunner) across healthcare, manufacturing, and telecoms highlights the need for software composition analysis in CI/CD pipelines and sector-specific tabletop exercises for ransomware response.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 117 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
