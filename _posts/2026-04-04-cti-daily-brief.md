---
layout: post
title: "CTI Daily Brief: 2026-04-04 — FortiClient EMS Zero-Day Exploited, Axios npm Supply Chain Attack Linked to North Korea, DragonForce RaaS Campaigns Continue"
date: 2026-04-05 20:05:00 +0000
description: "Eight critical reports dominated the 24-hour cycle, led by an actively exploited FortiClient EMS zero-day (CVE-2026-35616), a North Korean supply chain attack on the Axios npm package, and continued DragonForce and PLAY ransomware campaigns targeting business services, legal, and government sectors."
category: daily
tags: [cti, daily-brief, shinyhunters, dragonforce, play-ransomware, cve-2026-35616, unc1069]
classification: TLP:CLEAR
severity: critical
reporting_period: "2026-04-04"
generated: "2026-04-05"
draft: true
report_count: 25
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-04 (24h) | TLP:CLEAR | 2026-04-05 |

## 1. Executive Summary

The pipeline processed 25 reports from 5 sources over the past 24 hours, with 8 rated critical and 3 rated high. The dominant theme is sustained ransomware-as-a-service (RaaS) activity: DragonForce claimed two new victims (Innovision Holdings and Siam Okamura International), PLAY ransomware added Sokolin and Barnes Solicitors LLP to its leak site, and ShinyHunters posted a multi-terabyte breach of ZenBusiness data exfiltrated from Snowflake and Salesforce environments. On the exploitation front, Fortinet released an emergency weekend patch for CVE-2026-35616, a critical FortiClient EMS improper-access-control flaw actively exploited as a zero-day before disclosure. BleepingComputer reported a large-scale React2Shell (CVE-2025-55182) credential-harvesting campaign that compromised 766 hosts in 24 hours. Google Threat Intelligence Group attributed the Axios npm supply chain compromise to UNC1069, a financially motivated North Korean threat actor that used social engineering to deploy RAT malware via a fake Microsoft Teams update.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 8 | FortiClient EMS zero-day; Axios npm supply chain attack; ShinyHunters ZenBusiness breach; DragonForce & PLAY ransomware victims; Kuwait MoI hack claim; Linux kernel mac80211 use-after-free |
| 🟠 **HIGH** | 3 | React2Shell credential theft campaign; PLAY ransomware (Barnes Solicitors); Telegram exploit channel |
| 🟡 **MEDIUM** | 12 | OpenPrinting CUPS CVEs (path traversal, heap overflow, RCE, auth bypass); Linux kernel CVEs (io_uring, serial, amdgpu, IPv6 SRv6); Syria government account compromise |
| 🔵 **INFO** | 2 | CVE-2026-35535, CVE-2026-35414 (limited details published) |

## 3. Priority Intelligence Items

### 3.1 FortiClient EMS Zero-Day Actively Exploited (CVE-2026-35616)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-fortinet-forticlient-ems-flaw-cve-2026-35616-exploited-in-attacks/)

Fortinet released an emergency weekend patch for CVE-2026-35616, an improper access control vulnerability in FortiClient Enterprise Management Server (EMS) versions 7.4.5 and 7.4.6. The flaw allows unauthenticated attackers to execute arbitrary commands via specially crafted requests. Cybersecurity firm Defused discovered the vulnerability and confirmed it was exploited as a zero-day earlier in the week before responsible disclosure. Shadowserver identified over 2,000 exposed FortiClient EMS instances online, concentrated in the USA and Germany. This is the second critical FortiClient EMS flaw in a week, following CVE-2026-21643. FortiClient EMS 7.2 is not affected. Hotfixes are available for 7.4.5 and 7.4.6; version 7.4.7 will include the fix permanently.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

> **SOC Action:** Immediately audit all FortiClient EMS instances for versions 7.4.5 and 7.4.6 and apply the hotfix. Query SIEM for unusual inbound connections to EMS management ports. Review FortiClient EMS logs for unauthenticated API access attempts. If patching is delayed, restrict management interface access to trusted networks only.

### 3.2 Axios npm Supply Chain Attack Attributed to North Korean UNC1069

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/)

North Korean threat actor UNC1069 compromised the Axios npm package through a targeted social engineering campaign against its lead maintainer. Attackers impersonated a legitimate company via a fake Slack workspace, then used a staged Microsoft Teams meeting to trick the developer into installing a fake Teams update that deployed RAT malware (WAVESHAPER.V2). With the stolen npm credentials, attackers published malicious Axios versions 1.14.1 and 0.30.4 containing a trojanised dependency (`plain-crypto-js`) that installed a cross-platform RAT on macOS, Windows, and Linux. The malicious packages were available for approximately three hours before removal. Google Threat Intelligence Group attributed the attack to UNC1069 based on WAVESHAPER.V2 and overlapping infrastructure.

**MITRE ATT&CK:** T1566 (Phishing), T1059.001 (Command and Scripting Interpreter), T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

> **SOC Action:** Query package manager logs and SCA tooling for installations of `axios@1.14.1` or `axios@0.30.4` and the `plain-crypto-js` dependency. Any system that installed these versions should be considered compromised — rotate all credentials, API keys, and SSH keys on affected hosts. Block known UNC1069 infrastructure at the perimeter and hunt for WAVESHAPER.V2 indicators in EDR telemetry.

### 3.3 React2Shell Credential Theft Campaign Compromises 766 Hosts

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-react2shell-in-automated-credential-theft-campaign/)

Cisco Talos attributed a large-scale credential-harvesting campaign to threat cluster UAT-10608, exploiting CVE-2025-55182 (React2Shell) in vulnerable Next.js applications. Attackers deployed automated scripts that harvested environment variables, SSH keys, AWS/GCP/Azure credentials, Kubernetes tokens, and Docker metadata from 766 compromised hosts within 24 hours. Exfiltrated data was sent in chunks via HTTP on port 8080 to a C2 server running the NEXUS Listener framework.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1552 (Unsecured Credentials)

> **SOC Action:** Patch all Next.js deployments against CVE-2025-55182 immediately. Audit outbound HTTP traffic on port 8080 for unexpected data exfiltration patterns. Rotate all cloud credentials, SSH keys, and API tokens on any Next.js hosts. Enforce AWS IMDSv2 across all EC2 instances and enable secret scanning in CI/CD pipelines.

### 3.4 ShinyHunters Claims Multi-Terabyte ZenBusiness Breach

**Source:** [RansomLock](https://www.ransomlook.io//group/shinyhunters)

ShinyHunters posted a claim of breaching ZenBusiness, Inc., alleging exfiltration of several terabytes of data from Snowflake, Mixpanel, and Salesforce environments. The stolen data reportedly includes sensitive PII, financial/KYC records, and business data. ShinyHunters' leak infrastructure remains active, with file servers operating at 91.215.85[.]22.

#### Indicators of Compromise
```
C2: 91.215.85[.]22
Domain: shinyhunte[.]rs
```

> **SOC Action:** If your organisation uses ZenBusiness services, monitor for credential reuse from any exposed data. Query network logs for connections to 91.215.85[.]22. Review Snowflake audit logs for anomalous data export activity and enforce MFA on all SaaS platform service accounts.

### 3.5 DragonForce and PLAY Ransomware Continue Multi-Sector Campaigns

**Source:** [RansomLock — DragonForce](https://www.ransomlook.io//group/dragonforce), [RansomLock — PLAY](https://www.ransomlook.io//group/play)

DragonForce claimed two new victims in the past 24 hours: Innovision Holdings and Siam Okamura International Co. The group continues operating as a RaaS cartel with customisable payloads and shared Tor-based infrastructure. Separately, the Hive-affiliated PLAY ransomware group added Sokolin (wine retailer) and Barnes Solicitors LLP (UK legal services) to its leak site. PLAY employs intermittent encryption to evade detection and uses Tor hidden services for C2 and data exfiltration. AI correlation analysis identified a link between the PLAY victims and the Axios supply chain attack via shared phishing TTPs (T1566).

**MITRE ATT&CK:** T1566 (Phishing), T1486 (Data Encrypted for Impact), T1071 (Application Layer Protocol)

> **SOC Action:** Ensure offline backup integrity for all critical systems. Review phishing filter efficacy and simulate spear-phishing exercises targeting developer and legal teams. Hunt for PLAY ransomware ransom note filenames (`ReadMe.txt`, `play.txt`) and DragonForce ransom note patterns (`readme.xt`, `[rand].README.txt`) across file shares.

### 3.6 Nasir Security Claims Kuwait Ministry of Interior Compromise

**Source:** [RansomLock](https://www.ransomlook.io//group/nasir%20security)

Nasir Security, a group claiming Hezbollah affiliation, posted a claim of compromising Kuwait's Ministry of Interior. This follows a pattern of claimed attacks on Gulf state targets including Dubai Airport, UAE Federal Customs Authority, and multiple oil companies (Al-Safi Oil, Rumaila Operating Organisation, Oman CC Energy Development, Dubai Petroleum) dating back to March 2026. Attribution confidence is low — the group's claims have not been independently verified, and the geopolitical framing suggests possible hacktivism or information operations rather than confirmed intrusions.

> **SOC Action:** Organisations with Gulf state government or energy sector exposure should review access controls and monitor for anomalous authentication from unexpected geographies. Treat these claims as unverified but worthy of defensive awareness.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Ransomware and data breaches targeting critical sectors (financial services, government, business services) | ShinyHunters ZenBusiness breach; DragonForce Innovision Holdings; Nasir Security Kuwait MoI claim |
| 🔴 **CRITICAL** | Hive-affiliated PLAY ransomware coordinated campaign against legal and retail sectors | Barnes Solicitors LLP (PLAY); Sokolin (PLAY); correlated via shared infrastructure and TTPs |
| 🔴 **CRITICAL** | Increased RaaS adoption with DragonForce cartel model enabling rapid multi-sector targeting | DragonForce Siam Okamura; DragonForce Innovision Holdings; 5 DragonForce victims in prior 24h batch |
| 🟠 **HIGH** | Active exploitation of vulnerabilities in widely deployed software components | FortiClient EMS CVE-2026-35616; React2Shell CVE-2025-55182 credential theft campaign |
| 🟠 **HIGH** | Supply chain attacks targeting open-source developer ecosystems | Axios npm compromise by UNC1069; correlated with prior prt-scan campaign and Claude Code leak malware |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (39 reports) — Prolific ransomware operator with sustained campaign activity across multiple sectors
- **Nightspire** (31 reports) — Active ransomware group with consistent victim postings
- **TeamPCP** (29 reports) — Persistent threat actor tracked since mid-March
- **DragonForce** (25 reports) — RaaS cartel with two new victims this cycle; last seen today
- **Akira** (19 reports) — Ransomware operator maintaining steady operational tempo
- **Hive** (14 reports) — Affiliated with PLAY ransomware operations observed today
- **ShinyHunters** (13 reports) — Data breach specialist; posted ZenBusiness breach today

### Malware Families

- **DragonForce Ransomware** (24 reports) — Primary payload for DragonForce RaaS cartel
- **Akira Ransomware** (15 reports) — Distinct ransomware family with dedicated infrastructure
- **PLAY Ransomware** (6 reports) — Hive-affiliated variant using intermittent encryption
- **CanisterWorm** (7 reports) — Worm observed in late March campaigns
- **Qilin Ransomware** (5 reports) — Payload associated with Qilin threat actor
- **Vidar** (5 reports) — Information stealer observed in distribution campaigns

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 14 | [link](https://msrc.microsoft.com/update-guide) | Linux kernel and OpenPrinting CUPS vulnerability advisories |
| RansomLock | 6 | [link](https://www.ransomlook.io) | Ransomware leak site monitoring — DragonForce, PLAY, ShinyHunters, Nasir Security |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com) | FortiClient EMS zero-day, Axios npm supply chain, React2Shell campaign |
| Wired Security | 1 | [link](https://www.wired.com/category/security/) | Syria government account compromise analysis |
| Unknown | 1 | — | Telegram exploit channel (source redacted) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Apply Fortinet hotfixes for FortiClient EMS 7.4.5 and 7.4.6 to remediate CVE-2026-35616. Over 2,000 instances are exposed online and the vulnerability is under active zero-day exploitation.

- 🔴 **IMMEDIATE:** Audit all systems for installations of `axios@1.14.1`, `axios@0.30.4`, or the `plain-crypto-js` dependency. Treat any match as a confirmed compromise — wipe and rebuild affected hosts, rotate all credentials, and hunt for WAVESHAPER.V2 persistence.

- 🟠 **SHORT-TERM:** Patch all Next.js deployments against CVE-2025-55182 (React2Shell) and rotate cloud credentials, SSH keys, and API tokens on any potentially affected hosts. Enforce AWS IMDSv2 and review outbound traffic on port 8080.

- 🟠 **SHORT-TERM:** Apply all OpenPrinting CUPS patches (CVE-2026-34978, CVE-2026-34979, CVE-2026-34980, CVE-2026-27447, CVE-2026-34990) — the batch includes a path traversal, heap overflow, unauthenticated RCE, and authorisation bypass.

- 🟡 **AWARENESS:** Monitor for continued DragonForce and PLAY ransomware activity. Both groups posted multiple victims in this cycle and correlation analysis links them to sustained campaigns across legal, retail, and manufacturing sectors. Validate offline backup integrity and test restoration procedures.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 25 reports processed across 4 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
