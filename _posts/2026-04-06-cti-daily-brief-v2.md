---
layout: post
title: "CTI Daily Brief: 2026-04-06 — Iranian APT Targets US Critical Infrastructure PLCs; Russian Cyber Units Hijack Home Routers; Flowise RCE Exploited in the Wild"
date: 2026-04-07 20:53:00 +0000
description: "79 reports processed across 15 sources. Dominant themes include Iranian APT targeting of Rockwell/Allen-Bradley PLCs in US critical infrastructure, Russian GRU-linked router hijacking campaigns to steal Microsoft 365 tokens, active exploitation of a max-severity Flowise RCE vulnerability, and a sustained ransomware surge led by The Gentlemen and DragonForce groups across healthcare, manufacturing, and education sectors."
category: daily
tags: [cti, daily-brief, cyberav3ngers, dragonforce, the-gentlemen, flowise, revil]
classification: TLP:CLEAR
reporting_period: "2026-04-06"
generated: "2026-04-07"
draft: true
severity: critical
report_count: 79
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - Cisco Talos
  - Schneier
  - Krebs on Security
  - Sekoia
  - Sysdig
  - Unit42
  - CISA
  - BellingCat
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-06 (24h) | TLP:CLEAR | 2026-04-07 |

## 1. Executive Summary

The pipeline processed 79 reports from 15 sources over the past 24 hours, with 17 rated critical and 27 rated high. The dominant theme is state-sponsored cyber operations: a joint FBI/CISA/NSA advisory warns that Iranian-affiliated APT actors are actively targeting internet-exposed Rockwell/Allen-Bradley PLCs across US water, energy, and government networks, extracting project files and manipulating HMI/SCADA displays. Separately, the UK's NCSC exposed a Russian GRU cyber unit (linked to APT28) hijacking home and small-office routers to steal Microsoft 365 authentication tokens via DNS hijacking. On the vulnerability front, a max-severity Flowise RCE flaw is now confirmed exploited in the wild, and two critical OpenPrinting CUPS vulnerabilities enable remote code execution and path traversal. Ransomware activity remained elevated, with The Gentlemen group claiming 14 new victims across healthcare, manufacturing, and education, and DragonForce adding two more to its leak site.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 17 | Iranian APT vs. US PLCs; Russian router hijacks; Flowise RCE exploitation; CUPS RCE CVEs; GPUBreach attack; Axios supply-chain compromise; DragonForce ransomware |
| 🟠 **HIGH** | 27 | The Gentlemen ransomware surge (14 victims); Massachusetts hospital cyberattack; REvil/GandCrab leadership unmasked; EvilTokens PhaaS; Kubernetes threats; CISA ICS advisory |
| 🟡 **MEDIUM** | 26 | Linux kernel CVEs (ipv6, amdgpu, mac80211, serial, io_uring); Bing EoP; Northern Ireland school network attack; Hong Kong encryption key law; util-linux TOCTOU race |
| 🟢 **LOW** | 3 | Miscellaneous low-severity advisories |
| 🔵 **INFO** | 6 | Informational reporting and tooling updates |

## 3. Priority Intelligence Items

### 3.1 Iranian APT Targeting US Critical Infrastructure PLCs

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-warns-of-iranian-hackers-targeting-critical-infrastructure/)

A joint advisory from the FBI, CISA, NSA, EPA, DOE, and CNMF warns that Iranian-affiliated APT actors are targeting internet-exposed Rockwell/Allen-Bradley programmable logic controllers (PLCs) on US critical infrastructure networks. Attacks have affected Water and Wastewater Systems, Energy, and Government Services sectors since March 2026, resulting in financial losses and operational disruptions. Attackers extracted PLC project files and manipulated data displayed on HMI and SCADA systems. The advisory links this escalation to hostilities between Iran, the US, and Israel. The CyberAv3ngers threat group (IRGC-affiliated) conducted similar campaigns against Unitronics OT devices in late 2023, compromising at least 75 PLCs. The Handala hacktivist group, also Iranian-linked, recently wiped approximately 80,000 devices on the network of US medical giant Stryker.

**MITRE ATT&CK:** T1133 (Exploit Public-Facing Application), T1566 (Phishing)

> **SOC Action:** Audit all internet-exposed OT assets, particularly Rockwell/Allen-Bradley PLCs. Implement firewall segmentation between IT and OT networks. Query network logs for unexpected outbound connections from OT subnets to overseas hosting providers. Enable MFA on all OT network access points and verify PLC firmware is current.

### 3.2 Russian GRU Unit Hijacking Home Routers for Microsoft 365 Token Theft

**Source:** [RecordedFutures](https://therecord.media), [Krebs on Security](https://krebsonsecurity.com), [BleepingComputer](https://www.bleepingcomputer.com/news/security/german-authorities-identify-revil-and-gangcrab-ransomware-bosses/)

The UK's NCSC exposed a Russian GRU-linked cyber unit that compromised home and small-office routers to hijack internet traffic via DNS manipulation. The operation redirected victims to credential-harvesting pages designed to steal Microsoft 365 authentication tokens. Authorities subsequently disrupted the DNS hijacking infrastructure. Correlation analysis links this activity to APT28/Fancy Bear with 0.90 confidence. This campaign aligns with a broader pattern of Russian state actors exploiting consumer-grade networking equipment as operational relay infrastructure.

> **SOC Action:** Query DNS logs for anomalous resolution patterns, particularly for Microsoft 365 authentication endpoints (login.microsoftonline.com, login.live.com). Verify router firmware versions across remote worker equipment. Deploy conditional access policies requiring compliant devices for Microsoft 365 authentication. Hunt for impossible-travel sign-ins across Azure AD/Entra ID.

### 3.3 Max-Severity Flowise RCE Vulnerability Exploited in Attacks

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/max-severity-flowise-rce-vulnerability-now-exploited-in-attacks/)

A maximum-severity remote code execution vulnerability in Flowise, an open-source AI workflow automation platform, is now actively exploited in the wild. Flowise is widely used for building LLM-based applications and AI agent workflows. Exploitation grants attackers full control over the hosting server. Organizations running Flowise instances should treat this as an emergency patching priority.

> **SOC Action:** Identify all Flowise instances in the environment via asset inventory and port scanning. Patch immediately or take offline if patching is not possible. Review server logs for indicators of exploitation including unexpected process spawning and outbound connections. Audit any AI/ML workflow platforms for similar exposure.

### 3.4 Critical OpenPrinting CUPS Vulnerabilities — Remote Code Execution

**Source:** Microsoft MSRC ([CVE-2026-34980](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34980), [CVE-2026-34978](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34978))

Two critical vulnerabilities in OpenPrinting CUPS were disclosed. CVE-2026-34980 allows anonymous Print-Job requests on shared PostScript queues to reach `lp` code execution over the network. CVE-2026-34978 enables path traversal in RSS notify-recipient-uri, allowing file writes outside CacheDir/rss and clobbering of job.cache. Both vulnerabilities affect Unix/Linux print servers running CUPS with shared queues or RSS notification enabled.

> **SOC Action:** Identify all CUPS print servers in the environment. Disable shared PostScript queues and RSS notification where not operationally required. Apply patches when available. Monitor print server logs for anomalous Print-Job submissions from external sources.

### 3.5 Ransomware Surge — The Gentlemen, DragonForce, and Law Enforcement Actions

**Source:** [RansomLock](https://www.ransomlook.io), [BleepingComputer](https://www.bleepingcomputer.com/news/security/german-authorities-identify-revil-and-gangcrab-ransomware-bosses/)

The Gentlemen ransomware group claimed 14 new victims in a single 24-hour period, targeting healthcare (Metropolitan Pediatrics, Hospital del Sur, Burning Rock Biotech), manufacturing (Thai Rung Union Car, EMCO Holding, Thai Special Gas), education (Win Academy), and financial services (Optima Servicios Financieros). DragonForce added two victims (AnchorsGordon, Bit-Wizards), both rated critical. In a positive development, Germany's BKA identified two Russian nationals — Daniil Maksimovich Shchukin (alias UNKN/UNKNOWN) and Anatoly Sergeevitsch Kravchuk — as leaders of the GandCrab and REvil ransomware operations (2019–2021), linked to 130+ extortion cases and $40M+ in damages. Both suspects are believed to be in Russia. Additionally, a Massachusetts hospital began turning ambulances away following a cyberattack, underscoring the real-world patient safety impact of healthcare-sector ransomware.

> **SOC Action:** Verify offline backup integrity for critical systems, especially in healthcare and manufacturing. Confirm EDR coverage across all endpoints. Review network segmentation between clinical/OT and corporate environments. Update ransomware playbooks with The Gentlemen and DragonForce IOCs from RansomLook feeds.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Coordinated cyber espionage by state-affiliated actors | US warns of Iranian hackers targeting critical infrastructure; UK exposes Russian cyber unit hacking home routers; Authorities disrupt router DNS hijacks for M365 token theft |
| 🔴 **CRITICAL** | Increased ransomware targeting critical sectors with sophisticated TTPs | Storm-1175 targets vulnerable web-facing assets; Medusa ransomware uses zero-days within 24h of breach; German authorities unmask REvil leadership |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors globally | 14 The Gentlemen victims; DragonForce claims (AnchorsGordon, Bit-Wizards); Pear group (ARC Dialysis); Gunra group (KUKJE PHARM) |
| 🟠 **HIGH** | Exploitation of vulnerabilities in widely used software and infrastructure | Flowise RCE exploited in the wild; CUPS CVE-2026-34980 remote code execution; CUPS CVE-2026-34978 path traversal |
| 🟠 **HIGH** | Phishing campaigns leveraging AI and exploiting public-facing applications | EvilTokens AI-augmented PhaaS for BEC fraud; Storm-1175 device code phishing; Middle East conflict-linked cyber escalation |
| 🟠 **HIGH** | Geopolitical tensions influencing cyber operations | Middle East conflict driving Iranian APT escalation; Russia-linked espionage via router compromise; Seqrite advisory on conflict-driven cyber escalation |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (53 reports) — Prolific ransomware group with 14 new victims in the reporting period across healthcare, manufacturing, education, and financial sectors
- **Qilin** (43 reports) — Established RaaS operator maintaining high operational tempo
- **Nightspire** (35 reports) — Targeting manufacturing, healthcare, and energy sectors with phishing and exfiltration tactics
- **TeamPCP** (30 reports) — Sustained activity across multiple campaigns
- **DragonForce** (27 reports) — Two new critical-severity victims in the reporting period
- **Akira** (22 reports) — Continued ransomware operations across sectors
- **Hive** (16 reports) — Persistent RaaS presence despite prior law enforcement disruptions
- **Handala** (13 reports) — Iranian-linked hacktivist group; previously wiped 80,000 devices at US medical company Stryker
- **ShinyHunters** (13 reports) — Data theft and extortion operations

### Malware Families

- **DragonForce ransomware** (25 reports) — Primary payload for the DragonForce group's operations
- **Akira ransomware** (18 reports) — Established ransomware family with consistent deployment
- **RaaS (generic)** (8 reports) — Multiple ransomware-as-a-service operations active
- **PLAY ransomware** (8 reports) — Continued operations across sectors
- **CanisterWorm** (7 reports) — Worm-based malware tracked across multiple reporting cycles
- **Gentlemen ransomware** (6 reports) — Payload associated with The Gentlemen group's current surge
- **GandCrab / REvil** — Historical families highlighted by German law enforcement identification of leadership

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 28 | [link](https://www.ransomlook.io) | Ransomware leak site monitoring; DragonForce, The Gentlemen, Gunra, Pear, Safepay, Anubis, Lynx |
| Microsoft | 23 | [link](https://msrc.microsoft.com) | CUPS CVEs, Linux kernel CVEs, Bing EoP |
| BleepingComputer | 6 | [link](https://www.bleepingcomputer.com) | Iranian APT advisory; Flowise RCE; REvil/GandCrab unmasking; GPUBreach |
| RecordedFutures | 5 | [link](https://therecord.media) | Russian router hijacks; Massachusetts hospital; Northern Ireland schools |
| AlienVault | 3 | [link](https://otx.alienvault.com) | TA416 espionage; Axios supply-chain; Kubernetes threats |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com) | Year-in-review vulnerabilities; SaaS notification weaponisation; ransomware trends |
| Schneier | 2 | [link](https://www.schneier.com) | Hong Kong encryption key disclosure law |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | Russia router hacking for M365 token theft |
| Sekoia | 1 | [link](https://blog.sekoia.io) | EvilTokens AI-augmented PhaaS analysis |
| Sysdig | 1 | [link](https://sysdig.com) | Security briefing: March 2026 |
| Unit42 | 1 | [link](https://unit42.paloaltonetworks.com) | Kubernetes environment threats |
| CISA | 1 | [link](https://www.cisa.gov) | Mitsubishi Electric GENESIS64 / ICONICS Suite ICS advisory |
| BellingCat | 1 | [link](https://www.bellingcat.com) | Satellite imagery damage assessment tool for Iran/Gulf conflict |
| SANS | 1 | [link](https://isc.sans.edu) | Advisory content |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all internet-exposed OT assets (Rockwell/Allen-Bradley PLCs, Unitronics) per the FBI/CISA/NSA joint advisory. Disconnect PLCs from the internet or enforce firewall segmentation between IT and OT networks. This addresses the Iranian APT campaign targeting US critical infrastructure (Section 3.1).

- 🔴 **IMMEDIATE:** Patch or take offline all Flowise instances. The max-severity RCE vulnerability is confirmed exploited in the wild and grants full server compromise (Section 3.3).

- 🟠 **SHORT-TERM:** Deploy conditional access policies requiring compliant/managed devices for Microsoft 365 authentication. Hunt for anomalous DNS resolution patterns targeting login.microsoftonline.com and impossible-travel sign-ins in Azure AD/Entra ID to detect Russian GRU router-hijacking activity (Section 3.2).

- 🟠 **SHORT-TERM:** Identify and patch all CUPS print servers, disable shared PostScript queues and RSS notifications where not required. CVE-2026-34980 and CVE-2026-34978 enable remote code execution and arbitrary file writes (Section 3.4).

- 🟡 **AWARENESS:** Healthcare, manufacturing, and education organisations should elevate ransomware readiness. The Gentlemen group claimed 14 victims in 24 hours across these sectors, and a Massachusetts hospital diverted ambulances following a cyberattack. Verify backup integrity and review incident response playbooks (Section 3.5).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 79 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
