---
layout: post
title: "CTI Weekly Brief: 23 Mar to 29 Mar 2026 - TeamPCP Supply Chain Campaign Escalates Across PyPI Ecosystem, Ransomware Surge, and Government Sector Breaches"
date: 2026-03-30 08:10:00 +0000
description: "A week dominated by TeamPCP's multi-stage supply chain campaign compromising Trivy, Checkmarx, LiteLLM, and Telnyx on PyPI, alongside elevated ransomware operations from Qilin, Nightspire, Akira, and DragonForce. ShinyHunters breached the European Commission's AWS infrastructure and Handala hackers compromised the FBI Director's personal email."
category: weekly
tags: [cti, weekly-brief, teampcp, qilin, shinyhunters, handala, canisterworm, polyshell]
classification: TLP:CLEAR
severity: critical
reporting_period_start: "2026-03-23"
reporting_period_end: "2026-03-29"
generated: "2026-03-30"
draft: false
report_count: 569
sources:
  - Microsoft
  - BleepingComputer
  - SANS
  - AlienVault
  - RecordedFutures
  - RansomLock
  - Wired Security
  - Schneier
  - CISA
  - Wiz
  - Elastic Security Labs
  - Cisco Talos
  - Unit42
---
| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 23 Mar to 29 Mar 2026 (7d) | TLP:CLEAR | 2026-03-30 |

## 1. Executive Summary

The pipeline processed 569 threat reports from 15+ sources during the reporting period, marking a high-tempo week driven by two dominant themes: a sustained software supply chain campaign by TeamPCP and a surge in ransomware operations across multiple sectors.

TeamPCP's supply chain campaign was the defining story of the week. Building on the initial Trivy vulnerability scanner compromise on 19 March, the group expanded to compromise all 91 tags of Checkmarx's ast-github-action, backdoor the LiteLLM PyPI package (3.4 million daily downloads), and inject steganographic malware into the Telnyx PyPI SDK. CISA added CVE-2026-33634 to the Known Exploited Vulnerabilities catalogue with a remediation deadline of 8 April. The group's CanisterWorm malware introduced a geopolitically targeted Kubernetes wiper payload aimed at Iranian systems. By week's end, SANS assessed that TeamPCP shifted operational focus from new compromises to monetization of harvested credentials, partnering with the Vect ransomware affiliate program.

Ransomware groups Qilin (24 reports), Nightspire (17 reports), Akira (12 reports), and DragonForce (6 reports) collectively drove the majority of the 126 critical-severity reports, targeting healthcare, energy, manufacturing, and retail sectors. ShinyHunters breached the European Commission's AWS infrastructure, exfiltrating over 350 GB of data. Iran-linked Handala hackers compromised FBI Director Kash Patel's personal email, publishing historical documents and correspondence. PolyShell mass exploitation hit 56.7% of vulnerable Magento/Adobe Commerce stores with a novel WebRTC-based card skimmer.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 126 | TeamPCP supply chain (LiteLLM, Telnyx, Checkmarx, Trivy); PolyShell Magento exploitation; Qilin, DragonForce, Akira ransomware campaigns; Nasir Security UAE energy targeting |
| 🟠 **HIGH** | 152 | European Commission breach; FBI Director email hack; GhostClaw macOS infostealer; Fake VS Code GitHub campaign; Nightspire healthcare ransomware |
| 🟡 **MEDIUM** | 237 | Smart Slider WordPress plugin CVE-2026-3098; TikTok for Business phishing; Bubble AI credential theft; ICS advisories (PTC Windchill, WAGO switches) |
| 🟢 **LOW** | 19 | Minor configuration advisories; Samsung compatibility issues |
| 🔵 **INFO** | 35 | Threat landscape context; defender tooling releases |

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Campaign — Multi-Ecosystem Compromise and Kubernetes Wiper

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/32842), [BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/backdoored-telnyx-pypi-package-pushes-malware-hidden-in-wav-audio/), [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/), [AlienVault](https://otx.alienvault.com/pulse/69c26c92be4a06388a97f328)

TeamPCP conducted the most significant open-source supply chain campaign of 2026 to date, compromising five distinct ecosystems in rapid succession: Aqua Security's Trivy vulnerability scanner (19 Mar), Checkmarx ast-github-action and KICS (23 Mar, all 91 tags), BerriAI's LiteLLM on PyPI (24 Mar, versions 1.82.7–1.82.8), and the Telnyx PyPI SDK (27 Mar, versions 4.87.1–4.87.2).

The LiteLLM compromise was particularly impactful given the package's 3.4 million daily downloads. Malicious code injected into `litellm/proxy/proxy_server.py` deployed the "TeamPCP Cloud Stealer," harvesting SSH keys, cloud credentials (AWS, GCP, Azure), Kubernetes secrets, and cryptocurrency wallet data. Version 1.82.8 installed a `.pth` file that executes on every Python interpreter startup regardless of whether LiteLLM is imported. Sources report approximately 500,000 data exfiltration events, though many are believed to be duplicates.

The Telnyx compromise introduced WAV steganography — malware payloads embedded in audio files using XOR-based decryption, extracted and executed in memory. On Windows, the malware drops a persistent executable (`msbuild.exe`) in the Startup folder.

TeamPCP's CanisterWorm malware targets Kubernetes clusters with a geopolitically selective wiper: systems configured with Farsi language/timezone settings are wiped and force-rebooted, while non-Iranian nodes receive the CanisterWorm backdoor. The malware deploys privileged DaemonSets across all cluster nodes and spreads laterally via exposed Docker APIs and SSH.

CISA added CVE-2026-33634 (CVSS 9.4) to the KEV catalogue. Federal agencies must remediate by 8 April 2026. By 28 March, SANS assessed TeamPCP shifted to monetization, partnering with the Vect ransomware affiliate program on BreachForums. No new package compromises were observed in the final 48 hours of the reporting period.

#### Indicators of Compromise
```
C2: checkmarx[.]zone
C2: aquasecurtiy[.]org (typosquat)
C2: scan[.]aquasecurtiy[.]org
C2: tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io
C2: souls-entire-defined-routes[.]trycloudflare[.]com
C2: championships-peoples-point-cassette[.]trycloudflare[.]com
C2: plug-tab-protective-relay[.]trycloudflare[.]com
IP: 45[.]148[.]10[.]122
IP: 45[.]148[.]10[.]212
Malicious packages: litellm 1.82.7, litellm 1.82.8, telnyx 4.87.1, telnyx 4.87.2
Safe versions: Trivy >= v0.69.2, trivy-action v0.35.0, LiteLLM < 1.82.7, Telnyx 4.87.0
CVE: CVE-2026-33634 (CVSS 9.4), CVE-2025-68613
```

> **SOC Action:** Search CI/CD workflow logs for any execution of `checkmarx/ast-github-action` between 12:58–19:16 UTC on 23 March 2026. Query package managers for litellm 1.82.7/1.82.8 and telnyx 4.87.1/4.87.2. Rotate all secrets accessible to compromised workflows. Hunt for `litellm_init.pth` files in Python environments. Monitor for DaemonSet deployments from non-standard service accounts in Kubernetes clusters. Block IOCs at network perimeter. (T1195.002, T1059, T1078, T1552)

### 3.2 PolyShell Mass Exploitation — 56.7% of Vulnerable Magento Stores Compromised

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/polyshell-attacks-target-56-percent-of-all-vulnerable-magento-stores/)

Mass exploitation of the PolyShell vulnerability in Magento Open Source and Adobe Commerce began on 19 March, two days after public disclosure. By 25 March, Sansec confirmed 56.7% of all vulnerable stores had been targeted. The flaw resides in Magento's REST API file upload feature, which accepts polyglot files capable of achieving remote code execution or stored XSS.

Attackers deployed a novel WebRTC-based payment card skimmer that exfiltrates data over DTLS-encrypted UDP rather than HTTP, bypassing Content Security Policy (CSP) controls including `connect-src` directives. The skimmer connects to a hardcoded C2 via WebRTC with a forged SDP exchange, receives second-stage payloads, and executes by reusing existing script nonces. Sansec detected this skimmer on the e-commerce site of a car maker valued at over $100 billion.

Adobe released a partial fix in version 2.4.9-beta1 on 10 March but no stable branch patch is available.

> **SOC Action:** Audit all Magento/Adobe Commerce instances for PolyShell exploitation. Review REST API file upload logs for polyglot file indicators. Deploy Sansec-published IOCs. Monitor for anomalous WebRTC DTLS-UDP traffic from e-commerce frontends. Escalate to Adobe for stable patch timeline if running affected versions. (T1059, T1020)

### 3.3 European Commission Data Breach — ShinyHunters Exfiltrate 350 GB via AWS

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/european-commission-confirms-data-breach-after-europaeu-hack/)

The European Commission confirmed a data breach after the ShinyHunters extortion group compromised AWS accounts associated with the Europa.eu platform. The group claimed to have exfiltrated over 350 GB of data including mail server dumps, databases, confidential documents, and contracts before access was blocked. ShinyHunters published a 90+ GB archive on their dark web leak site.

The Commission stated internal systems were not affected and websites remained operational. The breach is part of a broader ShinyHunters campaign that recently targeted Infinite Campus, CarGurus, Canada Goose, Panera Bread, and Match Group, leveraging voice phishing (vishing) attacks against SSO accounts at Okta, Microsoft, and Google.

> **SOC Action:** Organizations using AWS-hosted infrastructure should review IAM access logs for anomalous credential usage patterns consistent with vishing-acquired SSO tokens. Enforce hardware MFA on all cloud administration accounts. Review data-loss prevention controls on S3 buckets and RDS instances. (T1566, T1078)

### 3.4 FBI Director Patel Personal Email Compromise — Handala/Iran-Linked

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-confirms-hack-of-director-patels-personal-email-inbox/)

Iran-linked hacktivist group Handala (also tracked as Handala Hack, Hatef, Hamsa) breached FBI Director Kash Patel's personal Gmail account and published historical emails, photos, and documents. The FBI confirmed the compromise, stating the stolen data was historical and contained no government information. Handala framed the action as retaliation for FBI domain seizures and a $10 million Rewards for Justice bounty on the group's members.

Handala operates as a hacktivist persona for Iran's Ministry of Intelligence and Security (MOIS) and previously breached medical technology giant Stryker, wiping nearly 80,000 devices.

> **SOC Action:** Review executive and VIP personal email security posture. Enforce phishing-resistant MFA (FIDO2) on personal accounts used by senior staff. Brief leadership on targeted credential theft risks from state-affiliated groups. (T1566)

### 3.5 Ransomware Surge — Qilin, Nightspire, Akira, and DragonForce

**Source:** Multiple RansomLock reports, correlation batches 25–38

Ransomware operations drove the bulk of this week's report volume with overlapping TTPs across groups:

**Qilin** led with 24 reports, targeting healthcare (Aroostook Mental Health Services, Louise Medical Center), retail (Bedrosians Tile & Stone), government (Washoe Tribe), and manufacturing sectors. **Nightspire** (17 reports) focused heavily on U.S. healthcare including Florida Therapy Services and multiple redacted medical organizations, operating via Tor onion services for C2. **Akira** (12 reports) employed double extortion against education, manufacturing, and technology targets (GeoMechanics Technologies, Axiomatic Technologies, Sheladia Associates, BHS Bau, Frontier Technologies). **DragonForce** (6 reports) hit food manufacturing (Alliance Select Foods International), retail (Edward Beiner), travel (STS Travel), and automotive (Groupe Courtois Automobiles).

Additionally, **Black Nevas** emerged as a notable new entrant with 7 victims in a single batch including insurance, legal, and manufacturing sectors across India, the UK, and China.

> **SOC Action:** Verify offline backup integrity for critical systems. Hunt for Akira-associated VMware ESXi targeting patterns. Monitor for Tor exit node connections from internal hosts. Review EDR alerts for credential dumping (T1003) and lateral movement via RDP/SMB. Ensure healthcare-sector specific incident response playbooks are current.

### 3.6 GhostClaw Expands to GitHub and AI Workflows — macOS Infostealer

**Source:** [AlienVault](https://otx.alienvault.com/pulse/69c10792a24c3b8eec93ad9c)

The GhostClaw credential-theft group expanded distribution beyond npm packages to GitHub repositories and AI-assisted development workflows. The campaign targets macOS users with multi-stage payloads delivered through compromised GitHub projects disguised as legitimate tools. Infection chains involve shell command execution, fake authentication prompts, and persistence via scheduled tasks and modified system configurations. All identified repositories communicate with C2 infrastructure at trackpipe[.]dev.

#### Indicators of Compromise
```
C2: trackpipe[.]dev
SHA256: 189b8419863830f2732324a0e02e71721ec550ffa606f9dc719f935db5d25821
SHA256: 3ab0bcc8ff821bd6ba0e5fdbb992836922a67524f8284d69324f61e651981040
SHA256: 946206d42497ea54a4df3f3fed262a99632672e99b02abcc7a9aff0f677efba8
SHA256: 43dc96bde2d5214ea3e93c1d9f62da54c260587e0b5bd366bb55ab615262384e
```

> **SOC Action:** Block trackpipe[.]dev at DNS and proxy layers. Scan macOS developer endpoints for GhostClaw IOC hashes. Review AI-assisted coding tool configurations for unauthorised repository sources. Alert developers to verify GitHub project legitimacy before installation. (T1059.004, T1027, T1204.002)

### 3.7 Fake VS Code Security Alerts — Large-Scale GitHub Notification Abuse

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/fake-vs-code-alerts-on-github-spread-malware-to-developers/)

A coordinated campaign posted thousands of fake VS Code security advisories in GitHub Discussions across multiple repositories, triggering email notifications to developers. Posts used realistic titles with fabricated CVE IDs and impersonated maintainers. Links directed victims to Google Drive-hosted files, redirecting through drnatashachinn[.]com which runs JavaScript reconnaissance to profile targets before delivering second-stage payloads.

> **SOC Action:** Alert development teams about fake GitHub security advisories. Block drnatashachinn[.]com at proxy/DNS. Instruct developers to verify CVE IDs against NVD or MITRE before acting on GitHub Discussion alerts. (T1566)

### 3.8 Nasir Security — Pro-Iranian Campaign Targeting UAE Energy Infrastructure

**Source:** RansomLock monitoring

Pro-Iranian threat group Nasir Security, claiming Hezbollah affiliation, announced large-scale cyber operations against UAE energy infrastructure during the reporting period. The group claimed breaches of the UAE Federal Customs Authority and multiple oil companies across the UAE and Oman. While specific technical details and independent verification are limited, the campaign represents a claimed escalation in Middle Eastern cyber conflict targeting critical energy infrastructure.

> **SOC Action:** Energy sector organisations with Middle Eastern operations should review network segmentation between IT and OT environments. Heighten monitoring for reconnaissance activity targeting SCADA/ICS systems. Coordinate with sector ISACs for shared indicators.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks targeting AI and cloud ecosystems at scale | LiteLLM, Trivy, Checkmarx, Telnyx PyPI compromises; CISA KEV entry for CVE-2026-33634; CanisterWorm Kubernetes wiper |
| 🔴 **CRITICAL** | Increased exploitation of vulnerabilities in widely deployed platforms | PolyShell Magento mass exploitation; CVE-2026-24291 Windows LPE; n8n CVE-2025-68613 |
| 🔴 **CRITICAL** | Ransomware operations with overlapping TTPs across multiple sectors | Qilin, Nightspire, Akira, DragonForce, Black Nevas, INC Ransom all active simultaneously |
| 🟠 **HIGH** | Phishing campaigns targeting government sectors (EU and US) | European Commission AWS breach; FBI Director email compromise |
| 🟠 **HIGH** | Ransomware targeting healthcare and energy sectors specifically | Nightspire healthcare focus; Payload energy targeting; Nasir Security UAE claims |
| 🟠 **HIGH** | Developer supply chain targeting expanding to new vectors | GhostClaw GitHub/AI workflows; Fake VS Code GitHub alerts; TeamPCP WAV steganography |
| 🟡 **MEDIUM** | Phishing prevalent across financial and technology sectors | TikTok for Business phishing; Bubble AI credential theft; GitHub social engineering |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (24 reports) — Most active ransomware operator; multi-sector targeting including healthcare, retail, government
- **Nightspire** (17 reports) — Heavy healthcare focus in the US; Tor-based C2 infrastructure
- **TeamPCP** (17 reports) — Supply chain specialist; compromised 5 open-source ecosystems in 10 days
- **Akira** (12 reports) — Double extortion against education, manufacturing, technology; VMware ESXi targeting
- **Handala** (10 reports) — Iran/MOIS-linked hacktivist; FBI Director email breach, prior Stryker wiper attack
- **ShinyHunters** (8 reports) — Data extortion; European Commission 350 GB breach via vishing-acquired SSO tokens
- **DragonForce** (6 reports) — Food manufacturing, retail, automotive, government targeting
- **INC Ransom** (5 reports) — Active across manufacturing and services sectors
- **Agenda** (4 reports) — Ransomware operations observed mid-week
- **Shellforce** (4 reports) — Linked to TeamPCP ecosystem activity

### Malware Families
- **Akira ransomware** (9 reports) — Double extortion; Windows CryptoAPI; Linux/ESXi variants
- **DragonForce ransomware** (6 reports) — Multi-sector deployment
- **CanisterWorm** (5 reports) — TeamPCP's Kubernetes wiper/backdoor with geopolitical targeting
- **TeamPCP Cloud Stealer** (4 reports) — Credential harvester deployed via supply chain compromises
- **BlackNevas** (4 reports) — Emerging ransomware variant
- **Trigona** (4 reports) — Ransomware operations observed in parallel
- **Vidar** (4 reports) — Infostealer activity
- **Remcos RAT** (4 reports) — Remote access trojan distribution
- **PLAY ransomware** (4 reports) — Hive-affiliated operations
- **GhostClaw/GhostLoader** — macOS infostealer expanding to GitHub and AI workflow vectors

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 209 | [link](https://www.microsoft.com/en-us/security/blog/) | Trivy compromise detection guidance; Defender intelligence feeds |
| RansomLock | 135 | [link](https://www.ransomlook.io/) | Primary ransomware victim tracking; Nasir Security, ShinyHunters |
| BleepingComputer | 49 | [link](https://www.bleepingcomputer.com) | Lead coverage: TeamPCP campaign, PolyShell, EU Commission, FBI hack |
| RecordedFutures | 34 | [link](https://www.recordedfuture.com) | Threat actor tracking and attribution |
| AlienVault | 22 | [link](https://otx.alienvault.com) | CanisterWorm analysis; GhostClaw IOCs; Trivy supply chain pulse |
| SANS | 15 | [link](https://isc.sans.edu) | TeamPCP campaign updates 001–003; operational tempo analysis |
| Wired Security | 13 | [link](https://www.wired.com/category/security/) | Long-form threat landscape reporting |
| CISA | 9 | [link](https://www.cisa.gov) | KEV additions; ICS advisories (PTC Windchill, WAGO) |
| Schneier | 8 | [link](https://www.schneier.com) | Security analysis and commentary |
| Wiz | 7 | [link](https://www.wiz.io/blog) | Cloud security analysis; Checkmarx scope assessment |
| Elastic Security Labs | 6 | [link](https://www.elastic.co/security-labs) | Detection rule development |
| Cisco Talos | 5 | [link](https://blog.talosintelligence.com) | Threat intelligence reporting |
| Unit42 | 5 | [link](https://unit42.paloaltonetworks.com) | Behavioral detection rules for CI/CD attacks |
| HaveIBeenPwned | 4 | [link](https://haveibeenpwned.com) | Breach notification tracking |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all CI/CD pipelines for TeamPCP compromise indicators. Search for `checkmarx/ast-github-action` executions between 12:58–19:16 UTC 23 March. Verify litellm and telnyx package versions. Rotate all secrets exposed to compromised workflows. CISA KEV deadline for CVE-2026-33634 is 8 April 2026.

- 🔴 **IMMEDIATE:** Patch or mitigate PolyShell in all Magento Open Source and Adobe Commerce instances. Monitor for WebRTC DTLS-UDP exfiltration from storefront servers. Deploy Sansec IOCs. Contact Adobe for stable-branch patch timeline.

- 🔴 **IMMEDIATE:** Hunt for CanisterWorm DaemonSet deployments in Kubernetes clusters. Audit for privileged pod creation by non-standard service accounts. Block TeamPCP C2 domains (checkmarx[.]zone, aquasecurtiy[.]org) at network perimeter.

- 🟠 **SHORT-TERM:** Enforce phishing-resistant MFA (FIDO2/WebAuthn) on all cloud administration and SSO accounts. The ShinyHunters vishing campaign compromised AWS accounts via stolen SSO tokens — password-based MFA is insufficient.

- 🟠 **SHORT-TERM:** Brief executive leadership and VIP staff on personal account security following the Handala breach of FBI Director Patel's Gmail. Personal accounts are increasingly targeted as entry points.

- 🟠 **SHORT-TERM:** Verify offline backup integrity and test restoration procedures. The simultaneous activity of Qilin, Nightspire, Akira, DragonForce, and Black Nevas across healthcare, energy, and manufacturing increases ransomware risk for those sectors.

- 🟡 **AWARENESS:** Alert development teams about the fake VS Code security advisory campaign on GitHub and GhostClaw distribution via GitHub repositories and AI workflows. Developers should verify CVEs against NVD before acting on advisories and audit AI coding tool repository sources.

- 🟢 **STRATEGIC:** Evaluate CI/CD pipeline hardening against supply chain attacks — pin GitHub Actions to immutable SHA commits rather than mutable tags, implement package integrity verification, and deploy behavioral monitoring for anomalous workflow execution patterns as recommended by Palo Alto Networks.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 569 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
