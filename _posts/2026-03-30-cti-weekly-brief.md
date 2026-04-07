---
layout: post
title: "CTI Weekly Brief: 30 Mar – 05 Apr 2026 — TeamPCP Supply Chain Escalation, Axios npm Compromise, and Ransomware Surge Across Critical Sectors"
date: 2026-04-07 09:00:00 +0000
description: "523 reports processed across 14 correlation batches. The week was dominated by the TeamPCP supply chain campaign reaching the European Commission, the North Korean-attributed Axios npm compromise, a critical FortiClient EMS zero-day under active exploitation, and sustained ransomware operations by DragonForce, Akira, Qilin, and Nightspire across healthcare, manufacturing, and government sectors."
category: weekly
severity: critical
tags: [cti, weekly-brief, teampcp, dragonforce, akira, qilin, axios, cve-2026-35616]
classification: TLP:CLEAR
reporting_period_start: "2026-03-30"
reporting_period_end: "2026-04-05"
generated: "2026-04-07"
draft: false
report_count: 523
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - SANS
  - Wired Security
  - Cisco Talos
  - CISA
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 30 Mar – 05 Apr 2026 (7d) | TLP:CLEAR | 2026-04-07 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 523 reports from 15 sources during the week of 30 March – 5 April 2026. The reporting period was defined by three converging themes: a sustained escalation of the TeamPCP supply chain campaign, a surge in ransomware-as-a-service (RaaS) operations by multiple groups, and the active exploitation of critical vulnerabilities in enterprise infrastructure.

The TeamPCP supply chain campaign reached its most consequential milestone to date when CERT-EU confirmed that the European Commission's AWS cloud environment was breached via the Trivy supply chain compromise (CVE-2026-33634), resulting in the exfiltration of 340 GB of data affecting 30 EU entities. Separately, North Korean threat actor UNC1069 compromised the Axios npm package — downloaded 100 million times weekly — by socially engineering a maintainer into installing a fake Microsoft Teams update. Fortinet issued an emergency weekend patch for CVE-2026-35616, a FortiClient EMS zero-day under active exploitation enabling unauthenticated remote code execution against over 2,000 exposed instances. Ransomware operations remained intense, with DragonForce (25 reports), Qilin (39 reports), Akira (19 reports), and Nightspire (34 reports) collectively targeting healthcare, manufacturing, legal, and government sectors. Google researchers disclosed "Coruna," a state-sponsored iPhone hacking toolkit exploiting 23 iOS vulnerabilities, and the Drift cryptocurrency platform confirmed a $280 million theft attributed to DPRK-linked actors. German authorities publicly identified Daniil Maksimovich Shchukin as the leader of the GandCrab and REvil ransomware operations.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 152 | TeamPCP/EU Commission breach; Axios npm supply chain; FortiClient EMS CVE-2026-35616; Chromium V8/Dawn/ANGLE CVEs; DragonForce, Akira multi-sector ransomware; Drift $280M crypto theft |
| 🟠 **HIGH** | 178 | Nightspire multi-sector campaign; Qilin EDR killer; Inc Ransom operations; device code phishing surge; React2Shell exploitation |
| 🟡 **MEDIUM** | 156 | Chromium DevTools/WebGL issues; Spring AI SpEL injection PoC; EvilTokens phishing kit |
| 🟢 **LOW** | 12 | SmartApeSG/Remcos RAT; Samsung compatibility issues |
| 🔵 **INFO** | 25 | Vendor advisories; Defend4Container; general awareness reporting |

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Campaign Breaches European Commission Cloud

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/32864), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cert-eu-european-commission-hack-exposes-data-of-30-eu-entities/), [Cisco Talos](https://blog.talosintelligence.com/protecting-supply-chain-2026/)

CERT-EU confirmed that the European Commission's Europa web hosting platform on AWS was breached through the Trivy supply chain compromise (CVE-2026-33634). TeamPCP used a compromised AWS API key with management rights — stolen via the poisoned Trivy scanner on 19 March — to access the Commission's cloud environment. Using TruffleHog to scan for additional secrets, they exfiltrated 340 GB of data (91.7 GB compressed) including approximately 52,000 email-related files from 71 clients: 42 internal European Commission departments and 29 other EU entities. ShinyHunters published the stolen dataset on their dark web leak site on 28 March. Separately, Mandiant quantified the campaign's impact at over 1,000 SaaS environments, and the Sportradar AG breach was confirmed as a joint TeamPCP/Vect ransomware operation. Cisco Talos noted that nearly 25% of the top 100 targeted vulnerabilities in 2025 affected widely used frameworks and libraries, underscoring the systemic risk. ATT&CK techniques: T1195 (Supply Chain Compromise), T1078 (Valid Accounts), T1003 (Credential Dumping).

> **SOC Action:** Audit all CI/CD pipeline dependencies for Trivy versions prior to the patched release. Rotate any AWS API keys that may have been exposed through the Trivy scanner. Query cloud audit logs for TruffleHog execution patterns and unexpected IAM key creation events. Review CERT-EU advisory for specific exposure indicators.

### 3.2 Axios npm Supply Chain Compromise Attributed to North Korean UNC1069

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/)

North Korean threat actor UNC1069 socially engineered the lead maintainer of the Axios npm package — which receives 100 million weekly downloads — by impersonating a legitimate company through a fabricated Slack workspace with realistic channels and fake employee profiles. During a staged Microsoft Teams call, the maintainer was prompted to install a fake Teams update that deployed a RAT, granting the attackers access to npm credentials. Two malicious versions (1.14.1 and 0.30.4) were published, injecting a dependency (`plain-crypto-js`) that installed a cross-platform RAT on macOS, Windows, and Linux systems. The malicious versions were live for approximately three hours before removal. Google Threat Intelligence Group attributed the attack to UNC1069 based on the use of WAVESHAPER.V2 malware and overlapping infrastructure. ATT&CK techniques: T1566 (Phishing), T1195 (Supply Chain Compromise), T1059 (Command and Scripting Interpreter).

> **SOC Action:** Query package management systems for Axios versions 1.14.1 and 0.30.4. If found, treat the host as compromised — rotate all credentials and authentication tokens. Search for the `plain-crypto-js` npm package in dependency trees. Monitor for WAVESHAPER.V2 indicators in EDR telemetry.

### 3.3 FortiClient EMS Zero-Day Under Active Exploitation (CVE-2026-35616)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-fortinet-forticlient-ems-flaw-cve-2026-35616-exploited-in-attacks/)

Fortinet released an emergency weekend patch on 5 April for CVE-2026-35616, a critical improper access control vulnerability in FortiClient Enterprise Management Server (EMS) versions 7.4.5 and 7.4.6. The flaw enables unauthenticated attackers to execute arbitrary code via specially crafted requests. Discovered by cybersecurity firm Defused, the vulnerability was observed being exploited as a zero-day before responsible disclosure. Shadowserver identified over 2,000 exposed FortiClient EMS instances online, concentrated in the US and Germany. This follows a separate critical FortiClient EMS flaw (CVE-2026-21643) reported the previous week that was also actively exploited.

> **SOC Action:** Apply FortiClient EMS hotfixes for versions 7.4.5 and 7.4.6 immediately. If patching is not feasible, restrict network access to EMS management interfaces. Query firewall logs for anomalous requests targeting FortiClient EMS endpoints. Upgrade to version 7.4.7 when available. FortiClient EMS 7.2 is not affected.

### 3.4 Drift Cryptocurrency Platform — $280 Million Stolen, DPRK Attribution

**Source:** [Recorded Future](https://therecord.media/drift-crypto-confirms-280-million-stolen-north-korea)

Decentralized finance platform Drift confirmed that $280 million was withdrawn during a security incident on 1 April. Attackers staged the operation over multiple weeks beginning 23 March, compromising the platform's security council administrative powers through sophisticated social engineering to obtain pre-signed transaction approvals. Two pre-signed transactions were executed on 1 April, bypassing withdrawal limits. Blockchain security firm Elliptic identified multiple indicators linking the attack to DPRK-affiliated actors, consistent with techniques observed in the $1.5 billion Bybit hack. If confirmed, this represents the eighteenth DPRK-attributed crypto theft tracked by Elliptic in 2026, totalling over $300 million.

> **SOC Action:** DeFi operators should audit multi-signature approval workflows for social engineering vectors. Implement time-locked transaction delays and out-of-band verification for high-value operations. Monitor Elliptic and Chainalysis feeds for laundering indicators associated with this theft.

### 3.5 "Coruna" State-Sponsored iPhone Hacking Toolkit Disclosed

**Source:** [Schneier on Security](https://www.schneier.com) (via Google Threat Intelligence)

Google researchers disclosed "Coruna," a highly sophisticated iPhone hacking toolkit exploiting 23 distinct iOS vulnerabilities across five complete exploitation chains. The toolkit silently installs malware on devices that visit websites containing the exploitation code, requiring no user interaction. The scale and complexity of Coruna — encompassing 23 vulnerabilities — suggests development by a well-resourced, likely state-sponsored group. No specific threat actor attribution was provided. Apple had previously issued emergency iOS 18 backported patches for the related DarkSword exploitation technique, which was found active in the wild in March.

> **SOC Action:** Enforce iOS updates to the latest available version across all managed devices. Monitor Apple security advisories for patches specifically addressing the 23 CVEs associated with Coruna. Review MDM policies to ensure web content filtering is active on managed iPhones.

### 3.6 Germany Identifies GandCrab/REvil Ransomware Leader

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/04/germany-doxes-unkn-head-of-ru-ransomware-gangs-revil-gandcrab/)

The German Federal Criminal Police (BKA) publicly identified 31-year-old Russian national Daniil Maksimovich Shchukin as UNKN (a.k.a. UNKNOWN), the leader of both the GandCrab and REvil ransomware operations. Shchukin and co-conspirator Anatoly Sergeevitsch Kravchuk are linked to at least 130 acts of computer sabotage and extortion causing over €35 million in economic damage across Germany between 2019 and 2021. A 2023 US DOJ filing linked Shchukin to a cryptocurrency wallet containing over $317,000 in ransomware proceeds. GandCrab and REvil collectively extorted over $2 billion from victims and pioneered double extortion tactics.

> **SOC Action:** Update threat intelligence platforms with the named individuals for attribution tracking. Review historical GandCrab/REvil IOCs against current telemetry — successor operations may reuse infrastructure components. Monitor for potential retaliatory activity from affiliated actors.

### 3.7 Claude Code Source Leak Weaponised to Distribute Vidar Infostealer

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/claude-code-leak-used-to-push-infostealer-malware-on-github/), [Wired Security](https://www.wired.com/story/security-news-this-week-hackers-are-posting-the-claude-code-leak-with-bonus-malware/)

Following the accidental exposure of Anthropic's Claude Code source code via a published npm package on 31 March, threat actors created malicious GitHub repositories advertising "unlocked enterprise features" to distribute the Vidar information-stealing malware and the GhostSocks network traffic proxying tool. The malicious repositories are SEO-optimised and appear among the first Google Search results for "leaked Claude Code." Victims download a 7-Zip archive containing a Rust-based dropper (`ClaudeCode_x64.exe`). Zscaler observed the archive being updated frequently with varying payloads. Anthropic issued copyright takedown notices against approximately 96 repositories.

#### Indicators of Compromise
```
Dropper: ClaudeCode_x64.exe (Rust-based)
Malware: Vidar infostealer, GhostSocks proxy
Delivery: Malicious GitHub repositories (SEO-optimised)
```

> **SOC Action:** Block download of executables from untrusted GitHub repositories via web proxy policies. Query EDR for execution of `ClaudeCode_x64.exe` or child processes associated with Vidar. Alert users that no legitimate "Claude Code download" requires a standalone executable — the official tool is installed via npm.

### 3.8 Qilin Ransomware Deploys EDR Killer Targeting 300+ Drivers

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/69ce8a077d7ad13478a8e495) (via Cisco Talos)

Cisco Talos published analysis of a multi-stage infection chain used by the Qilin ransomware group that deploys a malicious `msimg32.dll` to terminate over 300 EDR drivers from nearly every major vendor. The EDR killer enables Qilin operators to neutralise endpoint defences before deploying their ransomware payload, significantly increasing the success rate of encryption operations.

#### Indicators of Compromise
```
SHA256: 12fcde06ddadf1b48a61b12596e6286316fd33e850687fe4153dfd9383f0a4a0
SHA256: 16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0
SHA256: 7787da25451f5538766240f4a8a2846d0a589c59391e15f188aa077e8b888497
SHA256: bd1f381e5a3db22e88776b7873d4d2835e9a1ec620571d2b1da0c58f81c84a56
Filename: msimg32.dll (DLL side-loading)
```

> **SOC Action:** Hunt for `msimg32.dll` side-loading in non-standard directories. Add the above SHA256 hashes to EDR blocklists. Monitor for bulk termination of security-related services and drivers. Ensure tamper protection is enabled on all EDR agents.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks targeting developer tooling and cloud infrastructure are accelerating, with TeamPCP and UNC1069 demonstrating operational maturity | TeamPCP/Trivy → EU Commission breach; Axios npm compromise; LiteLLM PyPI compromise; 1,000+ SaaS environments impacted |
| 🔴 **CRITICAL** | Enterprise infrastructure appliances remain high-value targets with rapid zero-day exploitation | FortiClient EMS CVE-2026-35616 exploited as zero-day; CVE-2026-21643 exploited the prior week; 2,000+ exposed instances |
| 🔴 **CRITICAL** | RaaS operations continue expanding victim counts through double extortion across multiple sectors | DragonForce (25 reports), Qilin (39), Akira (19), Nightspire (34) — healthcare, manufacturing, government, legal |
| 🟠 **HIGH** | DPRK-linked actors are conducting parallel campaigns across cryptocurrency theft and software supply chain compromise | Drift $280M theft; Axios npm compromise via UNC1069; WAVESHAPER.V2 deployment |
| 🟠 **HIGH** | Phishing-as-a-service kits are driving a surge in device code phishing attacks | 37x increase in device code phishing; EvilTokens kit enabling phishing-as-a-service; WhatsApp spyware distribution |
| 🟠 **HIGH** | State-sponsored actors are stockpiling iOS zero-day chains for surveillance operations | Coruna toolkit (23 iOS vulnerabilities); DarkSword exploitation technique; Apple emergency backports to iOS 18 |
| 🟡 **MEDIUM** | Leaked source code is being rapidly weaponised as malware delivery vehicles | Claude Code leak → Vidar/GhostSocks distribution; SEO-optimised malicious GitHub repositories |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (47 reports) — Prolific RaaS operator targeting healthcare, telecom, legal, and government sectors with EDR-killing capabilities
- **Nightspire** (34 reports) — Actively targeting manufacturing, healthcare, and energy sectors globally using phishing and data exfiltration
- **TeamPCP** (38 reports) — "Chaos-as-a-service" group behind the Trivy, LiteLLM, and GitHub supply chain campaigns; linked to EU Commission breach
- **DragonForce** (25 reports) — RaaS group targeting retail, government, logistics, and manufacturing across multiple regions
- **Akira** (27 reports) — Sustained double-extortion ransomware operations against education, healthcare, manufacturing, and insurance sectors
- **Hive** (14 reports) — Associated with PLAY ransomware operations targeting legal services and critical infrastructure
- **ShinyHunters** (13 reports) — Data extortion group that published the EU Commission stolen dataset; involvement in credential distribution chain
- **Inc Ransom** (9 reports) — Targeting legal, healthcare, and IT sectors with double extortion
- **Coinbase Cartel** (9 reports) — RaaS operation actively leaking data from finance, healthcare, and government sectors

### Malware Families

- **DragonForce ransomware** (24 reports) — Primary payload for DragonForce RaaS operations
- **Akira ransomware** (15 reports) — Double-extortion ransomware with persistent operational cadence
- **Qilin ransomware** (15 reports) — Includes new EDR killer module targeting 300+ security drivers
- **PLAY ransomware** (15 reports) — Hive-affiliated ransomware targeting legal services and critical infrastructure
- **CanisterWorm** (7 reports) — Worm-like propagation observed across compromised environments
- **Vidar** (5 reports) — Commodity infostealer distributed via Claude Code leak and other social engineering campaigns
- **EvilTokens** (4 reports) — Device code phishing-as-a-service kit fuelling the 37x increase in device code phishing attacks

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 185 | [link](https://ransomlock.com) | Ransomware victim claim monitoring across multiple groups |
| Microsoft | 136 | [link](https://msrc.microsoft.com) | Chromium CVEs (V8, Dawn, ANGLE, CSS, GPU) and Azure/Bing advisories |
| BleepingComputer | 49 | [link](https://www.bleepingcomputer.com) | Primary coverage of FortiClient EMS, Axios compromise, Claude Code leak |
| AlienVault | 24 | [link](https://otx.alienvault.com) | Qilin EDR killer analysis; SentinelOne AI EDR reporting |
| RecordedFutures | 23 | [link](https://therecord.media) | Drift crypto theft; DPRK attribution intelligence |
| SANS | 14 | [link](https://isc.sans.edu) | TeamPCP campaign updates (Update 006); supply chain tracking |
| Wired Security | 11 | [link](https://www.wired.com/category/security/) | Claude Code malware roundup; Iran-US cyber conflict reporting |
| Cisco Talos | 9 | [link](https://blog.talosintelligence.com) | Supply chain defence analysis; Qilin EDR killer coverage |
| CISA | 7 | [link](https://www.cisa.gov) | Federal patching directives; Citrix NetScaler and Langflow advisories |
| BellingCat | 5 | [link](https://www.bellingcat.com) | OSINT and geopolitical intelligence |
| Schneier | 4 | [link](https://www.schneier.com) | Coruna iPhone toolkit disclosure; US government hacking tool analysis |
| HaveIBeenPwned | 4 | [link](https://haveibeenpwned.com) | Breach notification data |
| Wiz | 4 | [link](https://www.wiz.io) | Cloud post-compromise enumeration findings related to TeamPCP |
| Unit42 | 4 | [link](https://unit42.paloaltonetworks.com) | Threat actor and malware research |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | REvil/GandCrab leadership identification |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Apply the FortiClient EMS hotfix for versions 7.4.5 and 7.4.6 to address CVE-2026-35616. If immediate patching is not possible, restrict network access to EMS management interfaces and monitor for exploitation indicators.

- 🔴 **IMMEDIATE:** Audit all CI/CD pipelines for Trivy and LiteLLM dependencies. Rotate AWS credentials that may have been exposed through the Trivy supply chain compromise (CVE-2026-33634). Check for unauthorized IAM key creation in CloudTrail logs.

- 🔴 **IMMEDIATE:** Query package management systems for Axios npm versions 1.14.1 and 0.30.4 and the `plain-crypto-js` dependency. Treat any system that installed these versions as fully compromised — rotate all credentials, API keys, and session tokens.

- 🟠 **SHORT-TERM:** Deploy the Qilin EDR killer IOCs (SHA256 hashes listed in Section 3.8) to EDR blocklists. Hunt for `msimg32.dll` side-loading in non-standard paths. Enable tamper protection on all endpoint agents and monitor for bulk termination of security services.

- 🟠 **SHORT-TERM:** Enforce iOS updates across the fleet to the latest available version in response to the Coruna exploitation toolkit (23 iOS vulnerabilities) and the DarkSword technique. Review MDM web content filtering policies.

- 🟡 **AWARENESS:** Alert development teams that malicious GitHub repositories are impersonating the Claude Code source leak with SEO-optimised pages. Block download and execution of `ClaudeCode_x64.exe` via endpoint policies. Reinforce that Claude Code is installed only via npm, not standalone executables.

- 🟡 **AWARENESS:** The 37x increase in device code phishing powered by the EvilTokens kit warrants review of conditional access policies. Implement device code flow restrictions in Entra ID where feasible.

- 🟢 **STRATEGIC:** The convergence of TeamPCP, UNC1069, and other supply chain campaigns demonstrates that software supply chain integrity requires dedicated investment. Evaluate SBOM generation, dependency pinning, and artifact signing across the development lifecycle.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 523 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
