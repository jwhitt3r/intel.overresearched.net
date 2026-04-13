---
layout: post
title: "CTI Weekly Brief: 6 Apr – 12 Apr 2026 - State-Sponsored DNS Hijacking, Supply Chain Compromises, and Ransomware Cartel Surge"
date: 2026-04-13 08:14:00 +0000
description: "A high-tempo week dominated by APT28 router-based DNS hijacking for OAuth token theft, dual supply-chain attacks on Axios and DPRK's Contagious Interview campaign, Iranian OT targeting of US critical infrastructure, and aggressive ransomware operations by Coinbase Cartel, DragonForce, and Qilin across global sectors."
category: weekly
severity: critical
tags: [cti, weekly-brief, apt28, coinbase-cartel, contagious-interview, cve-2026-39987, axios, qilin]
classification: TLP:CLEAR
reporting_period_start: "2026-04-06"
reporting_period_end: "2026-04-12"
generated: "2026-04-13"
draft: false
report_count: 587
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - SANS
  - Wired Security
  - Schneier
  - Cisco Talos
  - CISA
  - Unit42
  - Sysdig
  - Krebs on Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 6 Apr – 12 Apr 2026 (7d) | TLP:CLEAR | 2026-04-13 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 587 reports from 15+ sources during the week of 6–12 April 2026, with 79 rated critical and 300 rated high — a significant uptick in high-severity activity. Three dominant themes shaped the week: state-sponsored operations, supply-chain compromise, and an acceleration of ransomware-as-a-service (RaaS) campaigns.

Russia's APT28 (Forest Blizzard) conducted a large-scale DNS hijacking campaign against 18,000+ SOHO routers to steal Microsoft Office OAuth tokens without deploying malware, prompting joint advisories from the UK NCSC and Microsoft. Separately, Iranian-affiliated APTs escalated attacks against US critical infrastructure OT/PLC systems, drawing a multi-agency FBI/CISA/NSA/DOE advisory. On the supply-chain front, both the Axios npm package compromise and North Korea's Contagious Interview campaign (spanning five package ecosystems) demanded immediate developer attention. Actively exploited vulnerabilities in Marimo (CVE-2026-39987), Ivanti EPMM (CVE-2026-1340), Ninja Forms (CVE-2026-0740), Flowise (CVE-2025-59528), and an unpatched Adobe Reader zero-day rounded out a week that kept defenders on high alert. RaaS groups — led by Coinbase Cartel, Qilin, The Gentlemen, DragonForce, and a new entrant Krybit — collectively claimed dozens of victims across healthcare, manufacturing, retail, and government sectors.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 79 | APT28 DNS hijacking; Marimo RCE; Ivanti EPMM KEV; Axios supply chain; DPRK Contagious Interview; Iranian OT attacks; Lapsus$ breaches; Coinbase Cartel campaigns; Adobe Reader zero-day; Flowise RCE; OpenPrinting CUPS RCE |
| 🟠 **HIGH** | 300 | Krybit ransomware wave; Lamashtu multi-victim campaign; Coinbase Cartel (Ralph Lauren, Helzberg, Carters); Shadowbyt3$ data leaks; Everest/Inc Ransom targeting; Chromium CVEs; Blackwater healthcare targeting |
| 🟡 **MEDIUM** | 132 | Chromium type confusion and use-after-free CVEs; BreachForums activity; AI vulnerability discovery discourse; PEAR ransomware targeting healthcare |
| 🟢 **LOW** | 15 | Nightspire lower-confidence claims; miscellaneous advisories |
| 🔵 **INFO** | 61 | Vendor security bulletins; Sysdig March 2026 briefing; Talos Year in Review |

## 3. Priority Intelligence Items

### 3.1 APT28 (Forest Blizzard) Mass DNS Hijacking for OAuth Token Theft

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/04/russia-hacked-routers-to-steal-microsoft-office-tokens/), [RecordedFutures](https://therecord.media/uk-exposes-russian-cyber-unit-hacking-home-routers), [AlienVault / NCSC](https://www.ncsc.gov.uk/news/apt28-exploit-routers-to-enable-dns-hijacking-operations)

Russia's GRU-linked Forest Blizzard (APT28/Fancy Bear) compromised 18,000+ end-of-life SOHO routers (primarily Mikrotik and TP-Link) by modifying DNS settings to point to attacker-controlled servers. This enabled adversary-in-the-middle (AiTM) interception of OAuth authentication tokens from Microsoft Outlook web sessions — bypassing MFA entirely without deploying any malware. Microsoft identified 200+ organisations and 5,000 consumer devices ensnared by the campaign, which peaked in December 2025 and primarily targeted government ministries, law enforcement, and third-party email providers. The UK NCSC issued a parallel advisory confirming Russian cyber actors are compromising routers at scale.

> **SOC Action:** Audit all SOHO and edge router DNS configurations for unauthorised changes. Query network logs for DNS traffic to non-corporate resolvers. Enforce DNSSEC validation. Review Microsoft Entra sign-in logs for anomalous OAuth token issuance from unexpected geolocations. Prioritise firmware updates for Mikrotik and TP-Link devices or decommission end-of-life hardware.

### 3.2 Iranian APTs Targeting US Critical Infrastructure OT/PLC Systems

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-warns-of-iranian-hackers-targeting-critical-infrastructure/), [RecordedFutures](https://therecord.media/fbi-pentagon-warn-iran-hacking-groups-target-ot)

A joint advisory from FBI, CISA, NSA, EPA, DOE, and US Cyber Command warned that Iranian-affiliated APT groups are targeting internet-exposed Rockwell/Allen-Bradley PLCs across water, energy, and government sectors. Attacks have caused operational disruptions and financial losses since March 2026, with threat actors extracting project files and manipulating HMI/SCADA displays. The escalation is assessed as a response to ongoing US-Iran military hostilities. The advisory references CVE-2021-22681 in Rockwell OT products, previously added to CISA's KEV catalogue.

> **SOC Action:** Immediately audit all internet-facing OT/ICS devices. Disconnect PLCs from direct internet access or place behind segmented firewalls. Monitor OT network traffic for connections from overseas hosting providers. Implement MFA for all OT network access. Review and rotate default authentication keys on PLC systems.

### 3.3 Axios npm Supply-Chain Compromise

**Source:** [AlienVault / Elastic Security Labs](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections)

Elastic Security Labs discovered a supply-chain attack via compromised Axios npm package versions 1.14.1 and 0.30.4. A malicious transitive dependency (`plain-crypto-js@4.2.1`) executes during `npm install`, spawning OS-native commands to fetch and run second-stage payloads from `sfrclak[.]com`. The attack chain is consistent across Linux, Windows, and macOS: Node.js spawns a shell, retrieves a remote payload via curl/wget, and executes it in a backgrounded or hidden context.

#### Indicators of Compromise
```
C2: 142.11.206[.]73
Domain: sfrclak[.]com
URL: hxxp[:]//sfrclak[.]com:8000/6202033
SHA256: 58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668
SHA256: 59336a964f110c25c112bcc5adca7090296b54ab33fa95c0744b94f8a0d80c0f
SHA256: 6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7
Malicious dependency: plain-crypto-js@4.2.1
Affected versions: axios 1.14.1, axios 0.30.4
```

> **SOC Action:** Run `npm ls axios` across all CI/CD pipelines and developer workstations. If versions 1.14.1 or 0.30.4 are present, isolate the system and rotate all credentials. Monitor for Node.js processes spawning shell commands with HTTP download patterns (`T1059`, `T1105`). Block `sfrclak[.]com` and `142.11.206[.]73` at the network perimeter.

### 3.4 DPRK Contagious Interview Cross-Ecosystem Supply Chain Campaign

**Source:** [AlienVault / Socket.dev](https://socket.dev/blog/contagious-interview-campaign-spreads-across-5-ecosystems)

North Korea's Contagious Interview operation expanded into a coordinated supply-chain attack across five package ecosystems: npm, PyPI, Go Modules, crates.io, and Packagist. Threat actors published packages impersonating legitimate developer tooling (e.g., `dev-log-core`, `logutilkit`, `logtrace`) under GitHub aliases including `golangorg`. The packages function as malware loaders, fetching staged RAT payloads from Vercel, Render, and Google Drive infrastructure. The Windows-targeted `license-utils-kit` variant includes a full post-compromise implant with keylogging, browser data theft, cryptocurrency wallet exfiltration, and remote shell capabilities (`T1195.001`, `T1036.005`, `T1555.003`).

#### Indicators of Compromise
```
SHA256: 9a541dffb7fc18dc71dbc8523ec6c3a71c224ffeb518ae3a8d7d16377aebee58
SHA256: bb2a89001410fa5a11dea6477d4f5573130261badc67fe952cfad1174c2f0edd
SHA256: 7c5adef4b5aee7a4aa6e795a86f8b7d601618c3bc003f1326ca57d03ec7d6524
Malicious packages: dev-log-core, logger-base, logkitx (npm); logutilkit, apachelicense, fluxhttp, license-utils-kit (PyPI); golangorg/formstash (Go); logtrace (crates.io); golangorg/logkit (Packagist)
```

> **SOC Action:** Audit package manifests across all five ecosystems for the named malicious packages. Implement package provenance verification (npm signatures, Sigstore for PyPI). Monitor developer workstations for unexpected outbound connections to Vercel, Render, and Google Drive download patterns post-install.

### 3.5 Marimo Pre-Auth RCE Exploited Within Hours (CVE-2026-39987)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-marimo-pre-auth-rce-flaw-now-under-active-exploitation/), [Sysdig](https://webflow.sysdig.com/blog/marimo-oss-python-notebook-rce-from-disclosure-to-exploitation-in-under-10-hours)

CVE-2026-39987 (CVSS 9.3) in the Marimo open-source Python notebook platform allows unauthenticated remote code execution via the `/terminal/ws` WebSocket endpoint. Sysdig observed exploitation less than 10 hours after disclosure, with 125 IPs conducting reconnaissance and a methodical operator stealing `.env` credentials and SSH keys within three minutes of initial access. The attacker demonstrated a hands-on approach focused on high-value credential theft rather than automated exploitation (`T1068`, `T1071.001`).

> **SOC Action:** Upgrade Marimo to version 0.23.0 immediately. If upgrade is not possible, block or disable the `/terminal/ws` endpoint. Rotate all cloud credentials and SSH keys on systems running Marimo. Monitor WebSocket connection logs for unauthenticated access to terminal endpoints.

### 3.6 CISA KEV: Ivanti EPMM Code Injection (CVE-2026-1340)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-exploited-ivanti-epmm-flaw-by-sunday/), [CISA](https://www.cisa.gov/news-events/alerts/2026/04/08/cisa-adds-one-known-exploited-vulnerability-catalog)

CISA added CVE-2026-1340 to its KEV catalogue and mandated federal patching by 11 April. This critical code injection vulnerability in Ivanti Endpoint Manager Mobile enables unauthenticated RCE on internet-exposed appliances. Ivanti disclosed the flaw in January alongside CVE-2026-1281, both exploited as zero-days. Shadowserver tracks nearly 950 exposed EPMM instances, with 569 in Europe and 206 in North America.

> **SOC Action:** Patch Ivanti EPMM to the latest version immediately. If patching is not possible, discontinue use or remove from internet exposure. Query asset inventories for EPMM instances and validate patch status. Review Ivanti EPMM logs for indicators of prior compromise.

### 3.7 Adobe Reader Zero-Day Exploited Since December

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploiting-acrobat-reader-zero-day-flaw-since-december/)

An unpatched zero-day in Adobe Reader has been exploited since at least December 2025 using sophisticated "fingerprinting-style" PDF documents with Russian-language lures tied to the oil and gas industry. The exploit leverages `util.readFileIntoStream` and `RSS.addFeed` Acrobat APIs for information harvesting and can chain into RCE/sandbox escape attacks — all without user interaction beyond opening the PDF (`T1204`, `T1059.003`). Adobe has not yet released a patch.

> **SOC Action:** Monitor and block HTTP/HTTPS traffic containing the "Adobe Synchronizer" User-Agent string. Advise users not to open PDF documents from untrusted sources. Consider deploying alternative PDF readers for high-risk users until Adobe issues a patch. Deploy email gateway rules to quarantine PDFs with suspicious embedded JavaScript.

### 3.8 TA416 Resumes European and Middle Eastern Government Espionage

**Source:** [AlienVault](https://otx.alienvault.com/pulse/69d4e667e8ab2d6d4082fc5b)

China-aligned TA416 resumed targeting European government and diplomatic entities (EU/NATO missions) since mid-2025 and expanded to Middle Eastern targets in March 2026 following the Iran conflict. The group employs fake Cloudflare Turnstile pages, OAuth redirect abuse, and C# project files to deliver customized PlugX backdoors via DLL sideloading (`T1129`, `T1566`). Infrastructure relies on re-registered legitimate domains and cloud-based C2.

> **SOC Action:** Monitor for DLL sideloading activity in user profile directories. Block or alert on connections to the domains listed in the AlienVault pulse. Hunt for PlugX/Korplug/ToneShell indicators in memory. Review OAuth redirect configurations for abuse patterns.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware-as-a-Service groups (Coinbase Cartel, DragonForce) targeting multiple sectors with shared RansomLock malware and phishing TTPs | Affordable Oil By DragonForce; Helzberg, Ralph Lauren, Carters By Coinbase Cartel; JBS Brazil sample leak |
| 🔴 **CRITICAL** | State-affiliated actors targeting critical infrastructure across US and Europe | Iranian APT OT/PLC attacks; APT28 DNS hijacking; UK NCSC advisory on router compromise |
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in widely used platforms within hours of disclosure | Marimo CVE-2026-39987 (10h to exploitation); Adobe Reader zero-day since December; Ivanti EPMM zero-day since January |
| 🔴 **CRITICAL** | Software supply-chain attacks as a renewable initial access vector | Axios npm compromise; DPRK Contagious Interview across 5 ecosystems; compromised developer tooling packages |
| 🟠 **HIGH** | Global ransomware campaigns with overlapping TTPs across healthcare, education, and government | Inc Ransom (mastercom, Morgan County GA); The Gentlemen (healthcare, biotech); Krybit (education, ISPs); Lamashtu (textile, engineering) |
| 🟠 **HIGH** | Rise in AI-driven vulnerability discovery and exploitation discourse | Anthropic Mythos cybersecurity analysis; React2Shell rapid weaponisation (Cisco Talos Year in Review) |
| 🟠 **HIGH** | Chromium vulnerability batch affecting technology and government sectors | CVE-2026-5914 Type Confusion in CSS; CVE-2026-5904 Use after free in V8; CVE-2026-5890 Race in WebCodecs |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (66 reports) — Prolific RaaS operator targeting oil & gas, healthcare, manufacturing, and legal sectors globally via phishing and application-layer exploits
- **The Gentlemen** (63 reports) — Rapidly expanding ransomware group hitting healthcare, biotechnology, utilities, industrial, and education sectors with LockBit-adjacent infrastructure
- **Nightspire** (37 reports) — Active across manufacturing, healthcare, energy, and security sectors with phishing-driven data exfiltration campaigns
- **TeamPCP** (31 reports) — Supply-chain focused threat actor exploiting package ecosystems and public-facing applications
- **DragonForce** (27 reports) — Former hacktivist collective transitioned to financially motivated RaaS operations targeting UK retail and government through affiliate network
- **Coinbase Cartel** (27 reports) — Aggressive RaaS group claiming high-profile victims including JBS Brazil, Ralph Lauren, Helzberg, AstraZeneca with onion-based C2 infrastructure
- **Akira** (22 reports) — Persistent ransomware operator maintaining steady operational tempo across multiple sectors
- **Shadowbyt3$** (16 reports) — Data extortion actor targeting education and financial sectors with public data leak campaigns
- **ShinyHunters** (13 reports) — Targeting education, gaming, and technology sectors (McGraw Hill, Rockstar Games, Abrigo)
- **Lapsus$** (reports this week) — Resurfaced with breaches of AstraZeneca and the French Ministry of Agriculture via social engineering and credential theft

### Malware Families

- **RansomLock** (23 reports) — Dominant ransomware payload deployed across multiple RaaS affiliates including DragonForce, Coinbase Cartel, and Lamashtu
- **DragonForce Ransomware** (25 reports) — Customisable affiliate-branded ransomware with shared backend infrastructure
- **Akira Ransomware** (18 reports) — Established double-extortion ransomware maintaining consistent deployment cadence
- **PlugX** (reports this week) — China-linked backdoor delivered by TA416 via DLL sideloading against European diplomatic targets
- **PLAY Ransomware** (8 reports) — Continued operations targeting diverse sectors
- **CanisterWorm** (7 reports) — Worm-like malware with propagation capabilities observed in late March through early April
- **Gentlemen Ransomware** (6 reports) — Emerging ransomware tied to The Gentlemen group operations

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 217 | [link](https://www.ransomlook.io) | Primary ransomware leak site tracker; Coinbase Cartel, Qilin, The Gentlemen, Krybit, Lamashtu victim claims |
| Microsoft | 184 | [link](https://msrc.microsoft.com) | Chromium CVEs, OpenPrinting CUPS RCEs, LIBPNG use-after-free, Go/Flannel critical vulnerabilities |
| BleepingComputer | 42 | [link](https://www.bleepingcomputer.com) | Marimo RCE, Adobe Reader zero-day, Ivanti EPMM KEV, Ninja Forms exploitation, Iranian OT targeting, Flowise RCE |
| RecordedFutures | 31 | [link](https://therecord.media) | FBI/Pentagon Iranian OT advisory, UK Russian router hacking exposure |
| AlienVault | 20 | [link](https://otx.alienvault.com) | DPRK Contagious Interview, TA416 espionage, Axios supply chain, AI-enabled device code phishing, Storm-1175/Medusa |
| SANS | 9 | [link](https://isc.sans.edu) | Vulnerability advisories and scanning activity analysis |
| Wired Security | 8 | [link](https://www.wired.com/category/security) | Anthropic Mythos AI vulnerability implications |
| Schneier | 7 | [link](https://www.schneier.com) | Security commentary and analysis |
| Cisco Talos | 7 | [link](https://blog.talosintelligence.com) | Year in Review covering React2Shell, Log4j persistence, agentic AI exploit development |
| CISA | 5 | [link](https://www.cisa.gov) | KEV catalogue updates (Ivanti EPMM, Contemporary Controls BASC); ICS advisories |
| Unit42 | 3 | [link](https://unit42.paloaltonetworks.com) | AWS AgentCore sandbox escape research |
| Sysdig | 3 | [link](https://sysdig.com) | Marimo RCE exploitation timeline; March 2026 security briefing |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | APT28 router DNS hijacking deep dive |
| Upwind | 4 | [link](https://upwind.io) | Cloud security advisories |
| Wiz | 3 | [link](https://www.wiz.io) | Cloud vulnerability research |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Audit all SOHO router DNS configurations for unauthorised changes and update firmware on Mikrotik/TP-Link devices. Decommission end-of-life network equipment that cannot receive security updates. (Ref: §3.1 APT28 DNS hijacking)

- 🔴 **IMMEDIATE:** Disconnect internet-exposed PLCs and OT devices or enforce firewall segmentation with MFA. Scan for CVE-2021-22681 in Rockwell Automation environments. (Ref: §3.2 Iranian OT targeting)

- 🔴 **IMMEDIATE:** Run `npm ls axios` across all environments and remove compromised versions 1.14.1 and 0.30.4. Block `sfrclak[.]com` and `142.11.206[.]73`. Audit developer workstations for indicators of the Contagious Interview packages across npm, PyPI, Go, crates.io, and Packagist. (Ref: §3.3, §3.4 supply-chain attacks)

- 🔴 **IMMEDIATE:** Patch Ivanti EPMM (CVE-2026-1340), Marimo (to v0.23.0), Ninja Forms File Uploads (to v3.3.27), and Flowise (to v3.1.1). These are all confirmed actively exploited. (Ref: §3.5, §3.6)

- 🟠 **SHORT-TERM:** Deploy network detection for "Adobe Synchronizer" User-Agent strings and quarantine PDFs with embedded JavaScript at email gateways until Adobe patches the Reader zero-day. (Ref: §3.7)

- 🟠 **SHORT-TERM:** Hunt for PlugX/Korplug DLL sideloading activity in user profile directories and monitor OAuth redirect configurations for abuse, particularly in diplomatic and government environments. (Ref: §3.8 TA416)

- 🟡 **AWARENESS:** Track the expanding Krybit and Lamashtu ransomware operations targeting education, ISP, healthcare, and engineering sectors globally. Ensure offline backup integrity and test incident response playbooks for double-extortion scenarios.

- 🟢 **STRATEGIC:** Implement package provenance verification (npm signatures, Sigstore) and dependency pinning across CI/CD pipelines. The convergence of DPRK and criminal supply-chain campaigns across five ecosystems signals that package security is now a critical infrastructure concern. (Ref: §3.3, §3.4)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 587 reports processed across 15 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
