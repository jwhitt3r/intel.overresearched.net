---
layout: post
title:  "CTI Daily Brief: 2026-04-21 - CISA KEV SharePoint CVE-2026-32201 with 1,300+ unpatched; Microsoft OOB patch for ASP.NET CVE-2026-40372; Harvester APT deploys Linux GoGra; Lazarus macOS campaign"
date:   2026-04-22 20:06:38 +0000
description: "51 reports processed across 3 correlation batches. Microsoft issues out-of-band patch for critical ASP.NET Core flaw CVE-2026-40372; Shadowserver warns 1,300+ SharePoint servers remain unpatched against CISA KEV-listed CVE-2026-32201; Unit 42 discloses AirSnitch WPA2/WPA3-Enterprise attacks; FudCrypt cryptor-as-a-service infrastructure dissected; DPRK HexagonalRodent uses AI to steal $12M in crypto; self-propagating npm worm hits Namastex Labs packages; Harvester APT expands to Linux with GoGra Microsoft Graph API backdoor; Lockbit5 posts 10 new victims across healthcare and industrial sectors."
category: daily
tags: [cti, daily-brief, harvester, lazarus-group, hexagonalrodent, lockbit5, dragonforce, cve-2026-40372, cve-2026-32201, cve-2026-33626, fudcrypt, gogra, airsnitch]
classification: TLP:CLEAR
reporting_period: "2026-04-21"
generated: "2026-04-22"
draft: true
severity: critical
report_count: 51
sources:
  - RansomLock
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - SANS
  - Unit42
  - Sysdig
  - Cisco Talos
  - Wiz
  - Wired Security
  - Schneier
  - Upwind
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-21 (24h) | TLP:CLEAR | 2026-04-22 |

## 1. Executive Summary

The pipeline processed 51 reports from 13 distinct sources in the last 24 hours, with four items rated critical and 33 high. Microsoft released out-of-band patches for a critical ASP.NET Core Data Protection flaw (CVE-2026-40372) allowing unauthenticated attackers to forge authentication cookies and escalate to SYSTEM, while Shadowserver confirmed that 1,300+ SharePoint servers remain unpatched against CISA KEV-listed CVE-2026-32201, still being abused in the wild. Unit 42 publicly disclosed "AirSnitch," a set of novel Wi-Fi attacks (Port Stealing, Gateway Bouncing) that bypass WPA2 and WPA3-Enterprise encryption industry-wide. AlienVault dissected the FudCrypt cryptor-as-a-service platform ($800–$2,000/month) backed by abuse of four Azure Trusted Signing accounts. Nation-state activity included Harvester's new Linux GoGra backdoor using Microsoft Graph API for C2, a Lazarus "Mach-O Man" macOS campaign leveraging ClickFix lures, DPRK-linked HexagonalRodent "vibe-coding" AI-generated malware to steal $12M in cryptocurrency, and the UK NCSC reporting four major nation-state incidents per week. Sysdig observed CVE-2026-33626 (LMDeploy SSRF) exploited within 12 hours of GHSA publication, and a self-propagating npm supply-chain worm hit 16 Namastex Labs packages.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 4 | FudCrypt CaaS analysis; AirSnitch WPA2/WPA3 bypass; ASP.NET CVE-2026-40372 OOB patch; SharePoint CVE-2026-32201 KEV (1,300+ unpatched) |
| 🟠 **HIGH** | 33 | Lockbit5 / DragonForce / AiLock / Worldleaks / Pear / Ransomhouse / Genesis victim postings; Harvester GoGra Linux; Lazarus Mach-O Man; HexagonalRodent DPRK AI ops; npm CanisterWorm-style supply-chain attack; LMDeploy CVE-2026-33626 exploitation; Kyber ESXi/Windows ransomware; TwizAdmin MaaS; LOTUSLITE India banking; FormBook phishing; China/UK nation-state intel |
| 🟡 **MEDIUM** | 5 | French HexDex arrest; Telegram tdata credential harvesting (SANS honeypot); Caller-as-a-Service fraud; Telegram leak-site chatter |
| 🟢 **LOW** | 1 | Microsoft Universal Print / Graph API regression |
| 🔵 **INFO** | 8 | DoD cyber strategy; ICE Graphite spyware use; Wiz at Google Next; Teams efficiency mode; Spain manga piracy takedown; ISC Stormcast |

## 3. Priority Intelligence Items

### 3.1 Microsoft OOB Patches Critical ASP.NET Core Flaw (CVE-2026-40372)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-emergency-security-updates-for-critical-aspnet-flaw/)

Microsoft released out-of-band security updates for CVE-2026-40372, a privilege-escalation vulnerability in the ASP.NET Core Data Protection cryptographic APIs (`Microsoft.AspNetCore.DataProtection` packages 10.0.0–10.0.6). A regression causes the managed authenticated encryptor to compute the HMAC validation tag over the wrong bytes and discard the result, allowing unauthenticated attackers to forge payloads that pass DataProtection authenticity checks. Forged payloads can decrypt authentication cookies, antiforgery tokens, TempData, and OIDC state — and tokens issued during the vulnerable window remain valid after the 10.0.7 upgrade unless the DataProtection key ring is rotated. Affected products: all ASP.NET Core apps using the DataProtection package in the 10.0.0–10.0.6 range. MITRE: T1078.004 (Valid Accounts), T1552.001 (Modify Authentication Process).

> **SOC Action:** Immediately update `Microsoft.AspNetCore.DataProtection` to 10.0.7 and redeploy. Rotate the DataProtection key ring on every affected application to invalidate any forged cookies or session/refresh/API-key tokens issued during the vulnerable window. Audit authentication logs for anomalous privileged sessions dating back to the first 10.0.0–10.0.6 deployment.

### 3.2 SharePoint CVE-2026-32201 on CISA KEV — 1,300+ Servers Still Unpatched

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-1-300-microsoft-sharepoint-servers-vulnerable-to-ongoing-attacks/)

Shadowserver reports that 1,300+ internet-exposed Microsoft SharePoint servers remain unpatched against CVE-2026-32201, a zero-day spoofing/improper-input-validation flaw affecting SharePoint Enterprise Server 2016, 2019, and Subscription Edition. Fewer than 200 systems have been patched since Microsoft's April 2026 Patch Tuesday release. CISA added the CVE to the Known Exploited Vulnerabilities catalogue and, under Binding Operational Directive 22-01, ordered FCEB agencies to remediate by **28 April 2026**. Exploitation requires no user interaction or privileges and allows threat actors to view or modify sensitive information. Affected sectors: federal government, enterprise SharePoint tenants. MITRE: T1071 (Application Layer Protocol), T1530 (data access).

> **SOC Action:** Apply the April 2026 Patch Tuesday SharePoint updates today. For any remaining exposed on-prem SharePoint servers, restrict inbound access to trusted networks at the edge, and query web-server logs for anomalous authenticated requests without matching sign-in events. Confirm BOD 22-01 compliance before the 28 April deadline.

### 3.3 Unit 42 Discloses AirSnitch: WPA2/WPA3-Enterprise Bypass

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/air-snitch-enterprise-wireless-attacks/)

Unit 42 and academic collaborators (research presented at NDSS Symposium 2026) disclosed AirSnitch — a set of novel attacks that exploit protocol-infrastructure interactions to break client isolation on WPA2 and WPA3-Enterprise networks. Techniques include **Port Stealing** (manipulating the MAC address table to hijack Layer-2 frames) and **Gateway Bouncing** (redirecting traffic via organization-specific network quirks), enabling cleartext interception and packet injection on Layer-2, regardless of upper-layer encryption. Research is being released publicly because some flaws (Port Stealing) are rooted in Wi-Fi design and cannot be patched within existing protocol standards. Affected: Android, macOS, iOS, Windows, Ubuntu Linux, and Wi-Fi equipment from multiple major vendors. AirSnitch serves as a foundation for higher-layer attacks (DNS spoofing, credential theft).

> **SOC Action:** Segment wireless guest/BYOD networks from corporate VLANs and enforce VPN or mTLS for all sensitive traffic on Wi-Fi. Enable DHCP snooping, dynamic ARP inspection, and port security on access-layer switches connected to APs. Disable legacy 802.11 features where possible and schedule a Wi-Fi architecture review against AirSnitch guidance. Treat WPA2/WPA3-Enterprise as a low-assurance control going forward.

### 3.4 FudCrypt Cryptor-as-a-Service Dissected — Azure Trusted Signing Abuse

**Source:** [AlienVault](https://otx.alienvault.com/pulse/69e8c2ea19756cc9d2899dea)

AlienVault published a deep analysis of FudCrypt, a subscription-based cryptor-as-a-service ($800–$2,000/month) with 200 registered users and 334 recorded builds. Recovered server infrastructure showed 32 enrolled agents and fleet C2 history. Technical capabilities include: 20 undocumented DLL-sideload carrier profiles, per-build polymorphic encryption (layered XOR-32, RC4-16, custom S-box), AMSI bypass, ETW patching, CMSTPLUA silent UAC elevation, Windows Defender tampering via Group Policy, and indirect syscalls / module stomping / fiber execution / Ekko sleep obfuscation in the dev branch. The operator maintains separate **four Azure Trusted Signing accounts** to sign fleet agents, native loaders, and ScreenConnect installers. MITRE: T1218 (signed binary proxy), T1055 (process injection), T1562 (defense evasion), T1574 (DLL sideloading).

#### Indicators of Compromise
```
Domain: fudcrypt[.]net
Domain: mstelemetrycloud[.]com
Domain: hijacklibs[.]net
SHA256: 00d31d04e092ce1f73839aeafaaf695fd1b68e92bf030c92543dd74a979a8a7d
SHA256: 056e17a0478ce166200140dbe0165140d8f7c851f0acc0cca6d1f267df1eaeec
SHA256: 14f17d7c548ddf02bbe3479d133ad2241b625fde26ce5ae641b297434c23956b
SHA256: 16cbe40fb24ce2d422afddb5a90a5801ced32ef52c22c2fc77b25a90837f28ad
SHA256: 8649b4dc2e8093550c8887ae88bcfb31c034046ecbb9d5318f8f0b6d90382ea6
SHA256: 91dd099c3cfeffe1ea23d864a796c301c80544231a7988cd656030ffd1805fc5
(80+ additional SHA256 hashes in source report)
```

> **SOC Action:** Hunt for outbound DNS/HTTP to `fudcrypt[.]net`, `mstelemetrycloud[.]com`, and `hijacklibs[.]net`. In EDR, flag signed binaries from Azure Trusted Signing where the certificate subject is newly observed in the environment and correlate with ScreenConnect installer activity spawning from user temp directories. Tune AMSI/ETW bypass detections (suspicious module loads into `amsi.dll`/`ntdll.dll`) and alert on CMSTPLUA elevation from non-admin processes.

### 3.5 Harvester APT Expands to Linux with GoGra Microsoft Graph API Backdoor

**Source:** [Symantec via AlienVault](https://www.security.com/blog-post/harvester-new-linux-backdoor-gogra), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-gogra-malware-for-linux-uses-microsoft-graph-api-for-comms/)

Symantec and Carbon Black Threat Hunter linked a new Linux GoGra variant to the Harvester nation-state group, based on code similarities with the earlier Windows espionage campaign. GoGra uses hardcoded Azure AD tenant/client credentials to poll an Outlook mailbox folder ("Zomato Pizza") at two-second intervals via Microsoft Graph API OData queries, filtering for subject lines starting with `Input`. Commands are AES-CBC decrypted and executed via `/bin/bash -c`; output is AES-encrypted and emailed back with subject `Output`; tasking emails are then deleted via HTTP DELETE to reduce forensic visibility. Lures masquerade ELF files as PDFs (filename-trailing space trick, e.g. `umrah .pdf`, `TheExternalAffairesMinister .pdf`). Persistence uses systemd user units and XDG autostart entries masquerading as Conky. VirusTotal submissions originated from India and Afghanistan; Harvester has historically targeted South Asia. MITRE: T1566 (Phishing), T1204 (User Execution), T1543 (Create/Modify Process), T1102 (Web Service), T1041 (Exfiltration over C2), T1027 (Obfuscated Files), T1036 (Masquerading).

#### Indicators of Compromise
```
SHA256: 2d0177a00bed31f72b48965bee34cec04cb5be8eeea66ae0bb144f77e4d439b1
SHA256: 57cd5721bae65c29e58121b5a9b00487a83b6c37dded56052cab2a67f90ea943
SHA256: 74ac41406ce7a7aa992f68b4b3042f980027526f33ec6c8d84cb26f20495c9dc
SHA256: 9c23c65a8a392a3fd885496a5ff2004252f1ad4388814b20e5459695280b0b82
SHA256: d8d84eaba9b902045ae4fe044e9761ad0ce9051b85feea3f1cf9c80b59b2b123
Path: ~/.config/systemd/user/userservice
```

> **SOC Action:** Audit Azure AD app registrations and conditional-access logs for service principals polling `/me/messages` or `/users/{id}/mailFolders/{folder}/messages` at sub-minute intervals; hunt for non-interactive OAuth token issuance to unfamiliar tenants/clients. On Linux endpoints, alert on new `~/.config/systemd/user/` unit files and XDG autostart entries referencing Conky, and hash-match the SHA256 IOCs across fileshares and email gateways.

### 3.6 Lazarus "Mach-O Man" macOS Campaign Targets Fintech

**Source:** [ANY.RUN via AlienVault](https://any.run/cybersecurity-blog/lazarus-macos-malware-mach-o-man/)

Lazarus Group is running an active ClickFix campaign aimed at macOS users in fintech, crypto, and other high-value sectors. Attackers contact targets over Telegram (often from compromised colleague accounts), redirect them to spoofed Zoom/Teams/Meet pages, and instruct the victim to paste and run a "fix" command that installs the Mach-O Man kit. The malware harvests browser credentials and macOS Keychain data, with Telegram used as the exfiltration channel. Related tooling observed in the same campaign includes PyLangGhostRAT, a Python port of an earlier Go RAT. MITRE: T1566 (Phishing), T1204 (User Execution), T1555 (Credentials from Password Stores), T1059.004 (Bash), T1071.001 (HTTP), T1567 (Alternative Protocol exfil).

#### Indicators of Compromise
```
IP (C2): 172.86.113[.]102
URL: hxxp[:]//172.86.113[.]102/localencode
URL: hxxp[:]//livemicrosft[.]com/meet/89035563931?p=9jXK14VFM8fObdKxfkake8tD7rPhzs.1
URL: hxxp[:]//update-teams[.]live/teams
Domain: livemicrosft[.]com
Domain: update-teams[.]live
SHA256: 0f41fd82cac71e27c36eb90c0bf305d6006b4f3d59e8ba55faeacbe62aadef90
SHA256: 4b08a9e221a20b8024cf778d113732b3e12d363250231e78bae13b1f1dc1495b
SHA256: 85bed283ba95d40d99e79437e6a3161336c94ec0acbc0cd38599d0fc9b2e393c
SHA256: 89616a503ffee8fc70f13c82c4a5e4fa4efafa61410971f4327ed38328af2938
SHA256: a73ce18952b40fd621789e43c56b2af08d1497ce3560b2481fa973d8265ce491
SHA256: dfee6ea9cafc674b93a8460b9e6beea7f0eb0c28e28d1190309347fd1514dbb6
SHA256: eb3eae776d175f7fb2fb9986c89154102ba8eabfde10a155af4dfb18f28be1b5
```

> **SOC Action:** Block `livemicrosft[.]com`, `update-teams[.]live`, and `172.86.113[.]102` at DNS and perimeter egress. Query macOS MDM / EDR telemetry for `osascript` or Terminal-launched curl/wget chains following a Telegram-sourced URL click; alert on any process reading `~/Library/Keychains/login.keychain-db` from non-Apple signed binaries. Reinforce user guidance that no legitimate meeting platform ever requires pasting a shell command.

### 3.7 Self-Propagating npm Supply-Chain Worm Hits Namastex Labs (CanisterWorm-style)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-npm-supply-chain-attack-self-spreads-to-steal-auth-tokens/)

Socket and StepSecurity identified a worm-like npm supply-chain attack targeting developer credentials across 16 compromised Namastex Labs packages (AI-agent and database tooling), with techniques similar to — but not confidently attributed to — TeamPCP's CanisterWorm. On install, the malicious payload harvests npm publish tokens, API keys, SSH keys, CI/CD credentials, cloud/registry credentials, LLM platform keys, Kubernetes/Docker configs, browser-stored crypto-wallet data (MetaMask, Exodus, Atomic, Phantom), then republishes any package the stolen token can publish with an incremented version, cascading the compromise. PyPI credentials trigger a parallel `.pth`-based payload. First malicious release observed 21 April 2026 22:14 UTC.

**Affected packages (remove/quarantine):**
`@automagik/genie` 4.260421.33–4.260421.39, `pgserve` 1.1.11–1.1.13, `@fairwords/websocket` 1.0.38–1.0.39, `@fairwords/loopback-connector-es` 1.4.3–1.4.4, `@openwebconcept/theme-owc` 1.0.3, `@openwebconcept/design-tokens` 1.0.3.

MITRE: T1078 (Valid Accounts), T1552.001 (Unsecured Credentials), T1195.002 (Supply Chain Compromise), T1059.007 (JavaScript).

> **SOC Action:** Search internal artifact registries and developer machines for the listed package@version pairs and quarantine immediately. Rotate every npm publish token, PyPI token, SSH key, cloud-provider access key, and CI/CD secret present on any affected build host. Audit the last 48 hours of npm package publications from your organisation for unexplained patch-level bumps. Pin dependencies via lockfiles and enable npm provenance/attestation checks.

### 3.8 LMDeploy SSRF (CVE-2026-33626) Weaponised Within 12 Hours

**Source:** [Sysdig](https://webflow.sysdig.com/blog/cve-2026-33626-how-attackers-exploited-lmdeploy-llm-inference-engines-in-12-hours)

Sysdig's honeypot observed the first exploitation attempt against CVE-2026-33626 — a Server-Side Request Forgery in LMDeploy's vision-language image loader — just 12 hours 31 minutes after the GHSA was published on the main GitHub advisory page. No public PoC existed at the time. The attacker used the `image_url` parameter to port-scan internal services (AWS IMDS `169.254.169.254`, Redis on 6379, MySQL on 3306, a secondary admin HTTP interface) and exfiltrated DNS OOB data in a single eight-minute session from `103.116.72[.]119`. LMDeploy is a Shanghai AI Laboratory toolkit serving InternVL2, internlm-xcomposer2, and Qwen2-VL over an OpenAI-compatible API. Affected: any LMDeploy instance before the fixed release. MITRE: T1133 (External Remote Services), T1048 (Exfiltration over Alternative Protocol), T1190 (Public-Facing Application).

#### Indicators of Compromise
```
Source IP: 103.116.72[.]119
SSRF target: hxxp[:]//169.254.169.254/ (AWS IMDS)
SSRF target: hxxp[:]//127.0.0.1:3306 (MySQL)
SSRF target: hxxp[:]//127.0.0.1:6379 (Redis)
```

> **SOC Action:** Inventory all internal and external LMDeploy deployments; patch to the fixed release or front the service with an egress filter that blocks RFC 1918, link-local, and metadata-service destinations. Enforce IMDSv2 on AWS. Review LMDeploy access logs for `image_url` values pointing to private IPs or 169.254.169.254 and block source IP `103.116.72[.]119` at perimeter. Alert on outbound DNS from LLM-inference hosts to uncontrolled resolvers.

### 3.9 DPRK HexagonalRodent Uses AI to Steal $12M in Crypto

**Source:** [WIRED Security](https://www.wired.com/story/ai-tools-are-helping-mediocre-north-korean-hackers-steal-millions/)

Expel disclosed a North Korean state-sponsored operation, tracked as HexagonalRodent, that compromised 2,000+ developer machines working on small crypto launches, NFTs, and Web3 projects, stealing up to $12M in three months. The crew "vibe-coded" nearly every component (phishing sites, malware, infrastructure) using OpenAI, Cursor, and Anima — evidenced by AI-typical inline comments in the code and leaked prompts on unsecured infrastructure. Initial access relied on fraudulent tech-firm recruiter lures leading to a "coding assignment" laced with credential-stealing malware. Attribution is hedged: code infrastructure ties the activity to known DPRK operators, but the attack crew appears unsophisticated. MITRE: T1566 (Phishing), T1204 (User Execution), T1555 (Credentials), T1583.001 (Acquire Domains).

> **SOC Action:** Train engineering and DevRel staff on fraudulent recruiter lures — particularly those that ask candidates to run a "coding assignment" or install a non-standard toolchain. Flag new developer hires' first 30 days of downloads from unfamiliar GitHub organisations. Query EDR for unsigned binaries or Node.js scripts executing from user Downloads or Desktop within 2 hours of a job-application site visit.

### 3.10 Kyber Ransomware Dual-Platform (Windows + ESXi)

**Source:** [AlienVault](https://otx.alienvault.com/pulse/69e8c18ece091934fe2136f5)

Kyber ransomware operates two variants: a C++ build targeting VMware ESXi (datastore encryption, VM termination, management-interface defacement) and a Rust build for Windows with experimental Hyper-V targeting. Both share campaign identifiers and Tor-based negotiation infrastructure. MITRE: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery). Shared TTP correlation observed with TwizAdmin multi-stage MaaS (crypto clipper + infostealer + Fernet-encrypted ransomware 'crpx0').

> **SOC Action:** On ESXi, disable SSH and the vSphere Web Client on management VLANs, enforce vCenter MFA, and snapshot-replicate critical VMs to an offline target. On Windows endpoints, flag attempts to disable Hyper-V services or enumerate checkpoints from non-admin sessions. Hunt for new encryption-related file extensions on datastores and unexpected logins to ESXi/vCenter in the last 14 days.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in cloud-native and enterprise environments | CVE-2026-33626 LMDeploy SSRF weaponised in 12h; npm self-spreading supply-chain worm hits Namastex Labs |
| 🔴 **CRITICAL** | Resource hijacking targeting critical infrastructure sectors | Genesis ransomware posting K2 Electric, Inc.; Ransomhouse posting Jiangsu Zenergy Battery Technologies |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in critical infrastructure and manufacturing sectors (carryover from prior batch) | Siemens RUGGEDCOM CROSSBOW SAC; SenseLive X3050; Apache ActiveMQ exploitation (6,400 servers) |
| 🟠 **HIGH** | Increased ransomware activity across multiple sectors with overlapping TTPs | Millennium (Leak Bazaar); HexagonalRodent AI-assisted campaigns; Kyber ESXi/Windows dual-platform |
| 🟠 **HIGH** | Rise in phishing as the primary vector for initial access across campaigns | Telegram "Breached" retirement announcement; Caller-as-a-Service fraud economy; FormBook phishing in EU/LATAM |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **qilin** (58 reports) — RaaS collective dominant across RansomLook victim postings, industrial/real estate/energy targets
- **The Gentlemen** (55 reports) — High-volume ransomware crew active since early April
- **Qilin** (40 reports) — Case-duplicate of qilin; continued broad targeting
- **Coinbase Cartel** (32 reports) — Financially motivated crew active across March–April
- **nightspire** (31 reports) — Ransomware group with steady leak-site cadence
- **DragonForce** (29 reports) — RaaS pivoting from hacktivism; two new legal-sector victims posted today (Galliher Law Firm, Primius Law Firm)
- **TeamPCP** (27 reports) — Supply-chain-focused crew associated with CanisterWorm techniques
- **dragonforce** (27 reports) — Case-duplicate of DragonForce
- **shadowbyt3$** (24 reports) — Telegram-/leak-site-affiliated actor
- **Harvester** (today) — Nation-state group (South Asia focus); new Linux GoGra backdoor disclosed
- **Lazarus Group** (today) — DPRK; active macOS "Mach-O Man" ClickFix campaign against fintech
- **HexagonalRodent** (today) — DPRK sub-cluster using AI tooling for crypto-developer targeting

### Malware Families

- **RansomLock** (45 reports) — Aggregator/feed tag dominating the pipeline
- **ransomware** (27 reports) — Generic category
- **dragonforce ransomware** (26 reports)
- **RaaS** (19 reports) — Generic RaaS tag
- **Akira ransomware** (15 reports)
- **Tox1** (14 reports) — Crypto/ransom-note payment channel referenced by Lockbit5
- **RansomLook** (12 reports) — Pipeline aggregator
- **Tox** (10 reports)
- **DragonForce ransomware** (10 reports)
- **GoGra** (today) — Harvester APT backdoor (Linux/Windows)
- **Mach-O Man** (today) — Lazarus macOS credential stealer
- **FudCrypt** (today) — Cryptor-as-a-Service platform
- **CanisterWorm**-style (today) — Self-propagating npm supply-chain worm
- **Kyber ransomware** (today) — Dual-platform Windows/ESXi
- **TwizAdmin** (today) — Multi-stage MaaS (clipper + infostealer + Fernet ransomware)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 18 | [link](https://www.ransomlook.io/) | Lockbit5 (10), DragonForce (2), AiLock, Pear, Worldleaks, Ransomhouse, Genesis victim listings |
| BleepingComputer | 9 | [link](https://www.bleepingcomputer.com/news/security/over-1-300-microsoft-sharepoint-servers-vulnerable-to-ongoing-attacks/) | Primary coverage of SharePoint KEV, ASP.NET OOB patch, npm worm, GoGra Linux, French ANTS breach, Universal Print |
| AlienVault | 8 | [link](https://otx.alienvault.com/pulse/69e8c2ea19756cc9d2899dea) | FudCrypt, FormBook, TwizAdmin, Kyber, GoGra, Mach-O Man, LOTUSLITE, March phishing trends |
| RecordedFutures | 4 | [link](https://therecord.media/china-cyber-capabilities-match-us-dutch-intel-says) | Dutch MIVD on China parity; NCSC 4 major incidents/week; HexDex arrest; DoD cyber strategy |
| Unknown (Telegram) | 3 | — | Redacted — `t.me` channel chatter (Breached retirement, KittyKatKrew) |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/32888) | Telegram tdata credential-harvest diary; ISC Stormcast |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com/air-snitch-enterprise-wireless-attacks/) | AirSnitch WPA2/WPA3-Enterprise disclosure |
| Sysdig | 1 | [link](https://webflow.sysdig.com/blog/cve-2026-33626-how-attackers-exploited-lmdeploy-llm-inference-engines-in-12-hours) | CVE-2026-33626 LMDeploy 12-hour exploitation |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com/ir-trends-q1-2026/) | Q1 2026 IR trends; phishing reemerges as top initial access |
| Wired Security | 1 | [link](https://www.wired.com/story/ai-tools-are-helping-mediocre-north-korean-hackers-steal-millions/) | HexagonalRodent DPRK AI-assisted crypto theft |
| Schneier | 1 | [link](https://www.schneier.com/) | ICE Graphite spyware usage |
| Wiz | 1 | [link](https://www.wiz.io/blog/wiz-at-google-cloud-next) | Cloud-native security product update |
| Upwind | 1 | [link](https://www.upwind.io/feed/ai-security-repeating-1990s-mistakes) | AI security commentary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch SharePoint (CVE-2026-32201, FCEB deadline 28 April) and ASP.NET Core DataProtection (CVE-2026-40372) — and **rotate the DataProtection key ring** to invalidate cookies or tokens forged during the vulnerable window.
- 🔴 **IMMEDIATE:** Remove and quarantine the 16 malicious Namastex Labs npm package versions from developer machines, CI runners, and internal mirrors; rotate every npm/PyPI publish token, cloud credential, and CI secret exposed on affected hosts.
- 🟠 **SHORT-TERM:** Block Mach-O Man C2 (`172.86.113[.]102`, `livemicrosft[.]com`, `update-teams[.]live`) and Harvester GoGra SHA256 hashes at EDR/proxy. Audit Azure AD app registrations polling Outlook mailbox folders at sub-minute intervals — GoGra's signature C2 pattern.
- 🟠 **SHORT-TERM:** Patch LMDeploy; where LMDeploy cannot be retired, front it with an egress allow-list blocking RFC 1918 and `169.254.169.254`, and force IMDSv2 on cloud hosts.
- 🟡 **AWARENESS:** Brief engineering staff on DPRK recruiter lures and ClickFix "paste-a-command" tactics (HexagonalRodent, Lazarus). Reinforce that legitimate meeting platforms never ask users to run shell commands.
- 🟢 **STRATEGIC:** Treat WPA2/WPA3-Enterprise as a low-assurance control post-AirSnitch — enforce VPN/mTLS for sensitive intranet traffic on Wi-Fi and schedule a wireless architecture review including Port Stealing and Gateway Bouncing mitigations.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 51 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
