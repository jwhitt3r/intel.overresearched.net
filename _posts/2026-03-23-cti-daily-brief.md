---
layout: post
title: "CTI Daily Brief: 2026-03-23 — TeamPCP Supply Chain Campaign Escalates to LiteLLM; Iran-linked Pay2Key Targets US Healthcare"
date: 2026-03-24 21:05:00 +0000
description: "63 reports processed across 15 sources. TeamPCP's supply chain campaign expanded from Trivy and Checkmarx GitHub Actions into the Python AI/ML ecosystem via compromised LiteLLM PyPI packages. Iran-linked Pay2Key ransomware targeted a US healthcare organisation amid military conflict. CISA issued critical ICS advisories for Pharos Controls and Schneider Electric. Akira ransomware posted 6 new victims."
category: daily
tags: [cti, daily-brief, teampcp, akira, pay2key, canisterworm, tycoon2fa]
classification: TLP:CLEAR
reporting_period: "2026-03-23"
generated: "2026-03-24"
draft: true
severity: critical
report_count: 63
sources:
  - RansomLock
  - BleepingComputer
  - RecordedFutures
  - Elastic Security Labs
  - CISA
  - AlienVault
  - Crowdstrike
  - Microsoft
  - Wired Security
  - SANS
  - HaveIBeenPwned
  - Sekoia
  - Upwind
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-23 (24h) | TLP:CLEAR | 2026-03-24 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 63 reports from 15 sources over the past 24 hours. The dominant theme is a rapidly expanding supply chain campaign by TeamPCP, which moved beyond CI/CD tooling (Trivy, Checkmarx GitHub Actions) into the Python AI/ML ecosystem by compromising LiteLLM on PyPI — a library with 40,000+ GitHub stars and deep integration across AI agent frameworks. Separately, an Iran-linked ransomware group deployed Pay2Key against a US healthcare organisation amid the ongoing US-Iran military conflict, raising questions about state-directed cyber operations under the cover of ransomware. CISA published two critical ICS advisories affecting Pharos Controls Mosaic Show Controller (CVSS 9.8) and Schneider Electric Plant iT/Brewmaxx (CVSS 9.9). Akira ransomware claimed 6 new victims across legal, engineering, immigration, and hospitality sectors, while Nasir Security — a self-described Hezbollah-linked group — claimed to have conducted the "most massive hack operation in UAE history" targeting energy infrastructure.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 17 | TeamPCP supply chain (LiteLLM, Trivy, Checkmarx, CanisterWorm); Akira ransomware (6 victims); CISA ICS advisories (Pharos Controls, Schneider Electric); Resolv DeFi $24.5M breach; Nasir Security UAE energy claims |
| 🟠 **HIGH** | 12 | Iran-linked Pay2Key healthcare attack; Tycoon2FA PhaaS resurgence; Qilin ransomware; Yanluowang sentencing; multi-vector XWorm/Remcos campaign; Silver Fox tax malware |
| 🟡 **MEDIUM** | 18 | Dutch Finance Ministry breach; HackerOne/Navia breach; Infinite Campus/ShinyHunters; Crunchyroll breach; Mazda data exposure; CISA Schneider EcoStruxure advisory |
| 🟢 **LOW** | 7 | Firefox VPN launch; CrowdStrike product updates; Elastic SOC tooling |
| 🔵 **INFO** | 9 | Microsoft CVE title corrections; exploit reversing series |

## 3. Priority Intelligence Items

### 3.1 TeamPCP Supply Chain Campaign Expands to Python AI/ML Ecosystem

**Source:** [Upwind](https://www.upwind.io/feed/litellm-pypi-supply-chain-attack-malicious-release), [Sysdig / AlienVault](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions), [AlienVault](https://otx.alienvault.com/pulse/69c26c92be4a06388a97f328)

TeamPCP's supply chain campaign escalated significantly on 23–24 March across three distinct vectors. First, malicious LiteLLM versions 1.82.7 and 1.82.8 were published directly to PyPI with no corresponding GitHub release. The payload, embedded in `proxy_server.py` and a `.pth` auto-execution file, deploys a credential stealer targeting SSH keys, AWS/GCP/Azure credentials, Kubernetes secrets, CI/CD configs, and crypto wallets. Stolen data is encrypted with AES-256 + RSA-4096 and exfiltrated to `models.litellm[.]cloud`. Second, the Sysdig TRT confirmed the Trivy GitHub Action compromise spread to Checkmarx's `ast-github-action` (v2.3.28), using an identical stealer with vendor-specific typosquat exfil domains (`scan.aquasecurtiy[.]org` → `checkmarx[.]zone`). Third, a new CanisterWorm variant targets Kubernetes clusters with geopolitically targeted destructive payloads — Iranian systems (identified by timezone/locale) are wiped and force-rebooted, while non-Iranian nodes receive the CanisterWorm backdoor.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise — Software Supply Chain), T1003 (Credential Access), T1078 (Valid Accounts), T1059 (Command and Scripting Interpreter), T1105 (Ingress Tool Transfer), T1552.004 (Unsecured Credentials — Private Keys)

#### Indicators of Compromise

```
Exfil: models.litellm[.]cloud
Exfil: scan.aquasecurtiy[.]org (45.148.10[.]212)
Exfil: checkmarx[.]zone (83.142.209[.]11)
C2: championships-peoples-point-cassette[.]trycloudflare[.]com
C2: souls-entire-defined-routes[.]trycloudflare[.]com
C2: investigation-launches-hearings-copying[.]trycloudflare[.]com
ICP canister: tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io
Malicious packages: litellm==1.82.7, litellm==1.82.8
Malicious action: Checkmarx/ast-github-action@2.3.28
```

> **SOC Action:** Immediately audit all Python environments for `litellm` versions 1.82.7 or 1.82.8 and remove them. Review GitHub Actions workflows for references to `aquasecurity/trivy-action` and `Checkmarx/ast-github-action` — pin to verified commit SHAs rather than mutable tags. Rotate all secrets (cloud credentials, SSH keys, API tokens) on any CI/CD runner that executed these compromised actions or installed the malicious litellm packages. Query network logs for connections to the exfiltration domains listed above. Audit Kubernetes clusters for unexpected DaemonSets and check for the CanisterWorm ICP canister beacon.

### 3.2 Iran-linked Pay2Key Ransomware Targets US Healthcare Organisation

**Source:** [The Record / Recorded Future News](https://therecord.media/iran-linked-ransomware-gang-targeted-us-healthcare-org)

An Iran-linked ransomware group deployed Pay2Key against an unnamed US healthcare organisation in late February, coinciding with the US-Iran military conflict. Beazley Security and Halcyon investigated the incident, finding improved evasion techniques in the ransomware variant. Notably, no data exfiltration was detected — unusual for Pay2Key — suggesting strategic or destructive motives rather than financial gain. The attackers compromised an administrative account several days before deploying encryption and wiped all event logs post-encryption. Halcyon researchers noted Pay2Key "does not always appear to prioritise extortion and financial gain over the destruction of victim environments for strategic impact." The group has targeted 170 victims and collected $8M in ransom payments since mid-2025.

**MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1070 (Indicator Removal), T1078 (Valid Accounts)

> **SOC Action:** Healthcare organisations should review administrative account access for anomalous login patterns, particularly from unexpected geographies. Ensure event log forwarding to a SIEM or immutable log store is configured so that local log deletion cannot destroy evidence. Monitor for Pay2Key-associated TTPs including lateral movement via compromised admin accounts and post-encryption log wiping.

### 3.3 CISA ICS Advisories: Pharos Controls and Schneider Electric

**Source:** [CISA ICSA-26-083-01](https://www.cisa.gov/news-events/ics-advisories/icsa-26-083-01), [CISA ICSA-26-083-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-083-03)

CISA published two critical ICS advisories on 24 March. CVE-2026-2417 affects Pharos Controls Mosaic Show Controller firmware 2.15.3 — a missing authentication vulnerability (CVSS 9.8, AV:N/AC:L/PR:N) that allows unauthenticated remote code execution with root privileges. Pharos recommends upgrading to firmware 2.16+. The advisory affects commercial facilities worldwide. Separately, four vulnerabilities in Schneider Electric's Plant iT/Brewmaxx ICS platform (CVE-2025-49844, CVE-2025-46817, CVE-2025-46818, CVE-2025-46819) enable privilege escalation leading to remote code execution via Redis component flaws including use-after-free, integer overflow, and code injection (CVSS 9.9). Schneider recommends installing patch ProLeiT-2025-001 and disabling Redis eval commands.

> **SOC Action:** Asset owners running Pharos Controls Mosaic Show Controller should upgrade firmware to 2.16+ immediately and ensure controllers are not exposed to the internet. Schneider Electric Plant iT/Brewmaxx operators should install ProLeiT-2025-001, disable Redis eval commands, and isolate ICS networks from business networks. Both advisories warrant scanning for internet-exposed instances using Shodan or Censys.

### 3.4 Akira Ransomware Claims 6 New Victims

**Source:** [RansomLook](https://www.ransomlook.io//group/akira)

Akira ransomware posted 6 new victims to its leak site on 23–24 March: Mooers Immigration (138 GB claimed — passports, SSNs, credit cards), The Russell's Law Firm (15 GB — client PII, police reports, medical records), French Engineering (72 GB — employee documents), Gustavo Preston, Concord Components (batch of 5 organisations including Wefapress, Environment Masters, Fairmont Hot Springs Resort, and Road America), and additional unnamed entities. Akira continues to operate as a non-RaaS group using double extortion, targeting VPN exploitation (T1133), RDP credential theft, and phishing (T1566) for initial access, with ransom demands of $200K–$4M in Bitcoin.

> **SOC Action:** Ensure VPN appliances are patched against known vulnerabilities exploited by Akira (particularly Cisco ASA/FTD and FortiGate). Verify that RDP is not directly exposed to the internet. Monitor for the `.akira` file extension and known Akira Tor infrastructure in network telemetry.

### 3.5 Tycoon2FA Phishing Platform Rebounds After Law Enforcement Disruption

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/tycoon2fa-phishing-platform-returns-after-recent-police-disruption/)

The Tycoon2FA phishing-as-a-service platform returned to pre-disruption activity levels within days of Europol's 4 March takedown, which seized 330 domains. CrowdStrike's Falcon Complete observed volumes drop to 25% on 4–5 March but recover to early-2026 levels shortly after. Tycoon2FA targets Microsoft 365 and Gmail accounts using adversary-in-the-middle techniques to bypass 2FA. Post-compromise activity includes inbox rule creation, hidden folder setup for fraud emails, and BEC preparation. Microsoft previously reported the platform generated 30 million phishing emails per month, accounting for 62% of all emails the company blocked.

**MITRE ATT&CK:** T1566 (Phishing), T1557 (Adversary-in-the-Middle), T1114 (Email Collection)

> **SOC Action:** Review Microsoft 365 and Google Workspace tenants for suspicious inbox rules, hidden folders, and recently added MFA devices. Implement conditional access policies requiring compliant devices. Alert on sign-ins from known PhaaS infrastructure IP ranges. Consider deploying phishing-resistant MFA (FIDO2 hardware keys) for high-value accounts to mitigate AitM attacks.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Supply chain attacks expanding from CI/CD tooling into Python AI/ML ecosystem | LiteLLM PyPI compromise; Trivy → Checkmarx GitHub Action propagation; KICS GitHub Action compromise; CanisterWorm Kubernetes wiper — all attributed to TeamPCP |
| 🔴 **CRITICAL** | Targeted attacks on Middle East energy infrastructure | Nasir Security claims against UAE energy sector; Al-Safi Oil, Rumaila Operating, Oman CC Energy, Dubai Petroleum reported compromised |
| 🟠 **HIGH** | Ransomware activity targeting healthcare and critical infrastructure | Akira (6 victims), Qilin (Aroostook Mental Health), Pay2Key (US healthcare), DragonForce (M3 Group) |
| 🟠 **HIGH** | Geopolitical tensions driving cyber operations involving Iran and Russia | Pay2Key healthcare attack concurrent with US-Iran conflict; CanisterWorm geotargeting Iranian systems; Yanluowang member sentenced |
| 🟠 **HIGH** | Phishing platforms resilient to law enforcement disruption | Tycoon2FA recovered within days of Europol takedown; infrastructure rebuilt with new domains |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **TeamPCP** (10 reports) — Supply chain threat actor behind LiteLLM, Trivy, Checkmarx, and KICS compromises; CanisterWorm Kubernetes wiper
- **Akira** (7 reports) — Ransomware group claiming 6 new victims across legal, engineering, immigration, and hospitality sectors
- **Nightspire** (7 reports) — Ransomware group active across multiple sectors with double extortion TTPs
- **Qilin** (6 reports) — Ransomware group targeting healthcare (Aroostook Mental Health) and retail (Centenario)
- **Handala / Nasir Security** (9+ reports) — Hezbollah-linked threat actor claiming UAE energy sector intrusions
- **ShinyHunters** (4 reports) — Data breach actor linked to Infinite Campus and other breaches
- **UNC6353** (5 reports) — Tracked cluster active across the reporting period
- **Void Manticore** (5 reports) — Iran-nexus threat actor

### Malware Families

- **Akira ransomware** (6 reports) — Double extortion ransomware targeting Windows and Linux/ESXi environments
- **CanisterWorm** (4 reports) — Kubernetes wiper/backdoor using ICP canister for C2, geotargeting Iranian systems
- **TeamPCP Cloud stealer** (4 reports) — Credential stealer deployed via supply chain compromises; targets cloud credentials, SSH keys, CI/CD secrets
- **XWorm / Remcos RAT** — Deployed via multi-vector campaign using VBS, PNG-based payloads, and reflective .NET loading
- **Pay2Key** — Iran-linked ransomware with strategic/destructive motivations alongside financial extortion

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 14 | [link](https://www.ransomlook.io) | Akira (6), Qilin (2), DragonForce, Crypto24, Nasir Security, Inc Ransom, Payload claims |
| BleepingComputer | 10 | [link](https://www.bleepingcomputer.com) | Tycoon2FA resurgence; HackerOne, Infinite Campus, Mazda, Dutch MoF breaches |
| RecordedFutures | 7 | [link](https://therecord.media) | FCC router ban; Iran-linked Pay2Key; Resolv DeFi $24.5M breach; Crunchyroll; Yanluowang sentencing |
| Elastic Security Labs | 4 | [link](https://www.elastic.co/security-labs) | SOC tooling and endpoint investigation guidance |
| CISA | 4 | [link](https://www.cisa.gov) | ICS advisories: Pharos Controls (CVE-2026-2417), Schneider Electric Plant iT/Brewmaxx, Schneider EcoStruxure, GDCM |
| AlienVault | 4 | [link](https://otx.alienvault.com) | CanisterWorm analysis; Trivy→Checkmarx supply chain; KICS compromise; multi-vector malware campaign |
| Crowdstrike | 3 | [link](https://www.crowdstrike.com) | CNAPP product updates; Falcon Data Security |
| Microsoft | 3 | [link](https://msrc.microsoft.com) | CVE-2026-23669, CVE-2026-4438, CVE-2026-4437 informational updates |
| Wired Security | 3 | [link](https://www.wired.com/category/security/) | Privacy reporting; ICE surveillance; geopolitical coverage |
| SANS | 2 | [link](https://isc.sans.edu) | IP KVM detection techniques |
| Sekoia | 1 | [link](https://www.sekoia.io) | Silver Fox tax-themed malware campaign |
| Upwind | 1 | [link](https://www.upwind.io) | LiteLLM supply chain breakdown analysis |
| HaveIBeenPwned | 1 | [link](https://haveibeenpwned.com) | RuneScape Boards breach (222,762 accounts) |
| Schneier | 1 | [link](https://www.schneier.com) | Security commentary |
| Unknown | 3 | — | Telegram-sourced ransomware snapshots and exploit analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all Python environments and CI/CD pipelines for compromised LiteLLM packages (1.82.7/1.82.8), Trivy GitHub Actions, and Checkmarx ast-github-action@2.3.28. Rotate all exposed secrets — cloud credentials, SSH keys, API tokens, Kubernetes service account tokens — on any system that executed compromised code. Pin GitHub Actions to immutable commit SHAs, not mutable version tags.

- 🔴 **IMMEDIATE:** ICS asset owners running Pharos Controls Mosaic Show Controller (firmware <2.16) or Schneider Electric Plant iT/Brewmaxx (v9.60+) should apply patches and verify that controllers are network-isolated and not internet-accessible. Scan for exposed instances via Shodan/Censys.

- 🟠 **SHORT-TERM:** Healthcare organisations should audit administrative account access patterns, ensure immutable log forwarding to a SIEM, and monitor for Pay2Key TTPs including post-encryption log wiping and lateral movement via compromised admin credentials.

- 🟠 **SHORT-TERM:** Deploy phishing-resistant MFA (FIDO2 hardware keys) for Microsoft 365 and Google Workspace high-value accounts to counter Tycoon2FA's adversary-in-the-middle 2FA bypass. Review tenants for suspicious inbox rules and recently added MFA devices.

- 🟡 **AWARENESS:** Monitor for Akira ransomware activity targeting unpatched VPN appliances (Cisco ASA/FTD, FortiGate) and exposed RDP services. Verify VPN firmware is current and RDP is not directly internet-facing. Organisations in legal, engineering, and hospitality sectors are currently within Akira's target profile.

- 🟢 **STRATEGIC:** Evaluate software supply chain security posture — the TeamPCP campaign demonstrates that a single compromised credential can cascade across an entire ecosystem (GitHub Actions → PyPI → Kubernetes). Implement artifact signing verification, dependency pinning, and reproducible build pipelines as countermeasures.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 63 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
