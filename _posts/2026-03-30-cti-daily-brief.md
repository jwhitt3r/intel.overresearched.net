---
layout: post
title: "CTI Daily Brief: 2026-03-30 - Axios npm Supply Chain Compromise Delivers Cross-Platform RAT; CISA Orders Citrix NetScaler Patch; TeamPCP Post-Compromise Activity Escalates"
date: 2026-03-31 20:05:00 +0000
description: "High-volume day with 133 reports across 15 sources dominated by the Axios npm supply chain compromise delivering cross-platform RATs, CISA emergency directive for CVE-2026-3055 in Citrix NetScaler, TeamPCP post-compromise lateral movement in cloud environments, and Operation TrueChaos zero-day exploitation targeting Southeast Asian governments."
category: daily
tags: [cti, daily-brief, teampcp, axios, akira, cve-2026-3055, eviltokens, crysome-rat]
classification: TLP:CLEAR
reporting_period: "2026-03-30"
generated: "2026-03-31"
draft: true
severity: critical
report_count: 133
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - SANS
  - Wiz
  - CISA
  - Wired Security
  - Unit42
  - BellingCat
  - Datadog
  - HaveIBeenPwned
  - Cisco Talos
  - Elastic Security Labs
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-30 (24h) | TLP:CLEAR | 2026-03-31 |

## 1. Executive Summary

The pipeline processed 133 reports from 15 sources in the past 24 hours, marking one of the highest-volume collection days this month. The dominant theme is **supply chain compromise at scale**: the Axios npm package was backdoored to deliver cross-platform RATs affecting an estimated 80% of cloud environments, while TeamPCP's broader campaign against Trivy, LiteLLM, and Checkmarx continued to generate post-compromise activity in victim AWS and GitHub environments. CISA added CVE-2026-3055 (Citrix NetScaler ADC memory disclosure, CVSS 9.3) to its Known Exploited Vulnerabilities catalogue and ordered federal agencies to patch by Thursday after confirmed in-the-wild exploitation. A Chinese-nexus actor exploited a TrueConf zero-day (CVE-2026-3502) to target Southeast Asian government entities in Operation TrueChaos. Ransomware operations remain elevated, with Akira, Genesis, Coinbase Cartel, and Qilin collectively accounting for the majority of RansomLock-sourced victim disclosures.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 37 | Axios supply chain RAT; Cisco/Trivy breach; CISA Citrix NetScaler KEV; ICS advisories (Anritsu, PX4); Handlebars.js injection CVEs; Coinbase Cartel & Akira ransomware disclosures |
| 🟠 **HIGH** | 54 | Operation TrueChaos 0-day; GhostSocks malware; EvilTokens PhaaS; Genesis & Qilin ransomware victims; Leak Bazaar criminal service |
| 🟡 **MEDIUM** | 38 | Microsoft CVE advisories (LIBPNG, Requests, Forge); LinkedIn phishing campaign; GCP Vertex AI research |
| 🟢 **LOW** | 2 | Miscellaneous advisories |
| 🔵 **INFO** | 2 | Background reporting |

## 3. Priority Intelligence Items

### 3.1 Axios npm Supply Chain Compromise — Cross-Platform RAT Delivery

**Source:** [Wiz](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack), [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/), [Huntress via AlienVault](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package), [Elastic Security Labs](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections), [Datadog](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)

An unknown threat actor compromised an Axios npm maintainer account and published two malicious package versions (v1.14.1 and v0.30.4) on 31 March 2026. The backdoored versions introduced a dependency on `plain-crypto-js`, a newly created trojanized package. A dropper (`setup.js`) downloads platform-specific second-stage RATs from `sfrclak[.]com:8000`, then self-cleans by deleting itself and restoring a clean `package.json`. Axios is present in approximately 80% of cloud environments and receives ~100 million weekly downloads, giving this attack massive blast radius even within a short exposure window. Wiz observed execution in 3% of affected environments before npm removed the packages.

The RAT variants beacon to C2 every 60 seconds, transmitting system inventory and awaiting operator commands. Capabilities include remote shell execution, binary injection, directory browsing, and process listing. The macOS variant is a C++ Mach-O universal binary capable of self-signing injected payloads via `codesign`. The Windows variant establishes persistence via a registry Run key (`MicrosoftUpdate`) and a re-download batch file. The Linux payload is a Python script.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain), T1059 (Command and Scripting Interpreter), T1105 (Ingress Tool Transfer)

#### Indicators of Compromise
```
C2: sfrclak[.]com:8000
Package: plain-crypto-js@4.2.1 (npm)
Malicious versions: axios@1.14.1, axios@0.30.4
SHA256 (macOS): 92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a
SHA256 (Windows): 617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101
Tracking: GHSA-fw8c-xr5c-95f9, MAL-2026-2306
```

> **SOC Action:** Query package management systems and build pipelines for `axios@1.14.1` or `axios@0.30.4`. Search EDR for outbound connections to `sfrclak[.]com:8000` and for processes spawned by `node` executing `setup.js`. On Windows, hunt for registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`. Rotate all credentials on systems where malicious packages executed.

### 3.2 Cisco Source Code Theft via Trivy Supply Chain / TeamPCP Post-Compromise Operations

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-source-code-stolen-in-trivy-linked-dev-environment-breach/), [Wiz](https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild)

TeamPCP, the threat group behind the ongoing supply chain campaign against Trivy, KICS, LiteLLM, and Telnyx, used credentials stolen in the Trivy compromise to breach Cisco's internal development environment. Attackers deployed a malicious GitHub Action plugin to access CI/CD pipelines and AWS accounts, cloning over 300 GitHub repositories containing source code for Cisco AI products (AI Assistants, AI Defense) and customer-owned code from banks, BPOs, and US government agencies. Multiple AWS keys were stolen and used for unauthorized activities. Cisco has isolated affected systems and begun wide-scale credential rotation.

Wiz CIRT observed TeamPCP validating stolen secrets using TruffleHog within hours of the initial Trivy compromise, followed by AWS discovery operations (IAM enumeration, ECS cluster mapping, Secrets Manager listing) and lateral movement via malicious GitHub workflows using stolen Personal Access Tokens.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise), T1078 (Valid Accounts), T1059 (Command Execution), T1530 (Data from Cloud Storage)

> **SOC Action:** Audit all Trivy, LiteLLM, KICS, and Telnyx installations for compromised versions. Review GitHub Actions workflow logs for unauthorized pull requests or workflow triggers. Monitor AWS CloudTrail for `sts:GetCallerIdentity` calls from unexpected source IPs (TruffleHog signature). Rotate all CI/CD secrets, GitHub PATs, and AWS access keys that may have been exposed to compromised tooling.

### 3.3 CISA Emergency Directive: CVE-2026-3055 — Citrix NetScaler ADC Memory Disclosure

**Source:** [Recorded Future News](https://therecord.media/cisa-tells-federal-agencies-to-patch-citrix-netscaler-bug)

CISA ordered federal agencies to patch CVE-2026-3055 by Thursday after watchTowr reported confirmed in-the-wild exploitation over the weekend. The vulnerability (CVSS 9.3) affects Citrix NetScaler ADC and NetScaler Gateway appliances, allowing unauthenticated attackers to leak sensitive memory — a pattern reminiscent of the original CitrixBleed (2023) and CitrixBleed Two (CVE-2025-5777). NetScaler Gateway serves as the authentication front door for many enterprise remote access environments. The original CitrixBleed was leveraged by ransomware gangs and nation-state actors to compromise hospitals, government agencies, and critical infrastructure organisations. CVE-2026-3055 was disclosed and patched by Citrix on 23 March 2026.

> **SOC Action:** Identify all Citrix NetScaler ADC and Gateway appliances in the environment and apply the 23 March patch immediately. Review NetScaler access logs for anomalous unauthenticated requests to the Gateway component. If patching cannot be completed within 24 hours, restrict external access to Gateway endpoints via firewall rules. Treat any unpatched appliance as potentially compromised and initiate forensic triage.

### 3.4 Operation TrueChaos: Chinese-Nexus Zero-Day Targeting Southeast Asian Governments

**Source:** [Check Point Research via AlienVault](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)

Check Point Research disclosed CVE-2026-3502 (CVSS 7.8), a zero-day in the TrueConf video conferencing client's updater validation mechanism. A possible Chinese-nexus threat actor exploited the flaw to distribute Havoc payloads to government endpoints in Southeast Asia via trusted on-premises TrueConf update channels. TrueConf serves over 100,000 organisations globally, including governments, defence departments, and critical infrastructure operators. The vendor released a fix in TrueConf Windows client version 8.5.3 (March 2026).

**MITRE ATT&CK:** T1574.002 (DLL Side-Loading), T1055 (Process Injection), T1105 (Ingress Tool Transfer), T1059.003 (Windows Command Shell)

> **SOC Action:** Identify any TrueConf deployments in the environment and update to version 8.5.3 or later. Hunt for Havoc C2 framework indicators and DLL sideloading from TrueConf updater paths. Government and defence organisations using on-premises TrueConf should audit server integrity and review update logs for anomalous file distributions.

### 3.5 EvilTokens: Device Code Phishing-as-a-Service Targeting Microsoft 365

**Source:** [Sekoia via AlienVault](https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1)

EvilTokens is a new Phishing-as-a-Service kit enabling attackers to harvest Microsoft OAuth device codes for account takeover. The kit has been rapidly adopted since March 2026, targeting employees in finance, HR, logistics, and sales for Business Email Compromise. EvilTokens supports post-compromise operations including token conversion to Primary Refresh Tokens and browser cookies for persistent access, and data exfiltration from Microsoft 365 services. The kit uses domain fronting and custom phishing pages across dozens of attacker-controlled domains.

**MITRE ATT&CK:** T1566 (Phishing), T1528 (Steal Application Access Token), T1550 (Use Alternate Authentication Material)

#### Indicators of Compromise (sample)
```
Domains: authdocspro[.]com, backdoor-hub[.]com, notificationsmanagersec[.]com,
         eventcalender-schedule[.]com, serenitygovsupplys[.]com
Hostnames: docusend.networkssolutionmail[.]com, signaturerequired.thecoolcactus[.]com
```

> **SOC Action:** Block device code phishing domains at the proxy/DNS layer. Review Azure AD sign-in logs for device code authentication flows (`urn:ietf:params:oauth:grant-type:device_code`) from suspicious locations. Implement Conditional Access policies that restrict device code flows to managed devices only. Monitor for anomalous token refresh patterns indicating stolen Primary Refresh Tokens.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks targeting software development and cloud services | Axios npm compromise (5 reports from Wiz, BleepingComputer, Huntress, Elastic, Datadog); TeamPCP campaign against Trivy/KICS/LiteLLM |
| 🔴 **CRITICAL** | Government and critical infrastructure targeting by state-nexus actors | Operation TrueChaos; Cisco/Trivy breach; CISA Citrix NetScaler KEV; Dutch Finance Ministry breach |
| 🟠 **HIGH** | Escalating phishing and credential access techniques across sectors | EvilTokens PhaaS; LinkedIn phishing campaign; Genesis/Akira credential harvesting across 19+ reports |
| 🟠 **HIGH** | RaaS operations expanding with double extortion across multiple verticals | Coinbase Cartel (6 victims); Akira (4 victims); Qilin, Embargo, Worldleaks activity |
| 🟠 **HIGH** | Ransomware groups systematically monetizing stolen data | Leak Bazaar service; Coinbase Cartel 43GB data dumps (Efficy, Verimatrix); ShinyHunters 7.9M Hallmark records |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (31 reports) — Prolific RaaS operator with active .onion infrastructure and FTP-based file exfiltration
- **TeamPCP** (30 reports) — Supply chain threat group targeting developer tools (Trivy, KICS, LiteLLM, Telnyx, Axios-adjacent)
- **Nightspire** (21 reports) — Ransomware operator active across multiple sectors
- **Akira** (16 reports) — Double extortion group targeting corporate networks, VMware ESXi, healthcare, education, manufacturing
- **Hive** (13 reports) — Established ransomware operation with continued victim disclosures
- **Handala** (11 reports) — Hacktivist group with political motivations
- **ShinyHunters** (10 reports) — Data breach and extortion group; 7.9M Hallmark Salesforce records compromised
- **Coinbase Cartel** (7 reports) — Emerging RaaS group with 43GB data dumps from Efficy, Verimatrix, and others
- **Genesis** (8+ victims today) — Extortion group targeting healthcare, finance, legal, and manufacturing sectors

### Malware Families

- **Akira ransomware** (12 reports) — Windows and Linux variants; .akira extension; CryptoAPI-based encryption
- **RaaS platforms** (10 reports) — Generic RaaS tooling across Coinbase Cartel, Qilin, Embargo operations
- **DragonForce ransomware** (6 reports) — Active across multiple sectors
- **PLAY ransomware** (5 reports) — Targeting critical infrastructure and healthcare
- **CanisterWorm** (5 reports) — Propagation-focused malware
- **CrySome RAT** (new) — Advanced .NET RAT with recovery partition persistence, AVKiller, and HVNC capabilities
- **EvilTokens** (new) — Microsoft device code PhaaS kit for OAuth token harvesting

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 58 | [link](https://www.ransomlook.io) | Ransomware victim disclosures from Akira, Genesis, Coinbase Cartel, Qilin, Embargo, Worldleaks, Inc Ransom |
| Microsoft | 36 | [link](https://msrc.microsoft.com) | CVE advisories for Handlebars.js, LIBPNG, Requests, Forge |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Cisco/Trivy breach, Axios compromise coverage |
| AlienVault | 7 | [link](https://otx.alienvault.com) | EvilTokens, Operation TrueChaos, CrySome RAT, Axios, GhostSocks |
| RecordedFutures | 3 | [link](https://therecord.media) | CISA Citrix NetScaler directive, Uranium Finance indictment, Leak Bazaar |
| SANS | 3 | [link](https://isc.sans.edu) | Operational security advisories |
| Wiz | 2 | [link](https://www.wiz.io) | Axios supply chain analysis, TeamPCP post-compromise tracking |
| CISA | 2 | [link](https://www.cisa.gov) | ICS advisories for Anritsu (CVE-2026-3356) and PX4 Autopilot (CVE-2026-1579) |
| Wired Security | 2 | [link](https://www.wired.com/category/security) | US Military GPS reporting |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | GCP Vertex AI permission escalation research |
| BellingCat | 1 | [link](https://www.bellingcat.com) | India BJP AI-generated hate speech investigation |
| Datadog | 1 | [link](https://securitylabs.datadoghq.com) | Axios npm supply chain IOC analysis |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com) | Breach notification data |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com) | Threat intelligence reporting |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs) | Axios supply chain detection rules |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all environments for Axios npm versions 1.14.1 and 0.30.4. Remove malicious artefacts, block `sfrclak[.]com:8000` at the network perimeter, and rotate all credentials on any system where affected packages executed. Run `npm audit` across all build pipelines and production workloads.

- 🔴 **IMMEDIATE:** Patch all Citrix NetScaler ADC and Gateway appliances against CVE-2026-3055. If patching within 24 hours is not feasible, restrict external Gateway access via firewall rules and begin forensic triage on exposed appliances.

- 🟠 **SHORT-TERM:** Audit CI/CD pipelines and developer workstations for exposure to TeamPCP supply chain compromises (Trivy, KICS, LiteLLM, Telnyx). Rotate GitHub PATs, AWS access keys, and any secrets that transited through compromised tooling. Monitor AWS CloudTrail for TruffleHog-pattern `sts:GetCallerIdentity` calls from anomalous IPs.

- 🟠 **SHORT-TERM:** Implement Conditional Access policies restricting Microsoft device code authentication flows to managed, compliant devices. Block EvilTokens phishing domains at DNS/proxy and review Azure AD sign-in logs for device code grant type usage.

- 🟡 **AWARENESS:** Update TrueConf Windows clients to version 8.5.3+ to remediate CVE-2026-3502. Organisations in government and defence sectors using on-premises TrueConf should audit server integrity and review update distribution logs for anomalous payloads.

- 🟢 **STRATEGIC:** Review AI agent permission models in GCP Vertex AI and similar platforms following Unit42 research demonstrating privilege escalation via default service agent configurations. Apply least-privilege principles to all AI agent service accounts.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 133 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
