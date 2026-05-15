---
layout: post
title:  "CTI Daily Brief: 2026-05-14 - Cisco SD-WAN Zero-Day Added to CISA KEV; WordPress Burst Statistics Auth Bypass Under Mass Exploitation; TanStack Supply Chain Hits Mistral and OpenAI"
date:   2026-05-15 09:00:00 +0000
description: "Two critical vulnerabilities under active exploitation (Cisco Catalyst SD-WAN CVE-2026-20182 added to CISA KEV; Burst Statistics WordPress plugin CVE-2026-8181 with 7,400+ blocked attacks in 24h), TanStack npm supply chain campaign now confirmed at OpenAI and Mistral AI with TeamPCP advertising stolen Mistral repos, and continued ransomware activity from The Gentlemen, Inc Ransom, and Cmd Organization."
category: daily
tags: [cti, daily-brief, teampcp, the-gentlemen, inc-ransom, cve-2026-20182, cve-2026-8181, supply-chain, ransomware]
classification: TLP:CLEAR
reporting_period: "2026-05-14"
generated: "2026-05-15"
draft: true
severity: critical
report_count: 12
sources:
  - BleepingComputer
  - RecordedFutures
  - RansomLook
  - SANS
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-05-14 (24h) | TLP:CLEAR | 2026-05-15 |

## 1. Executive Summary

Twelve reports were processed across four sources in the last 24 hours, with two rated critical and eight rated high. The dominant operational theme is exploitation of widely-deployed software: Cisco disclosed a critical Catalyst SD-WAN Controller authentication bypass (CVE-2026-20182, CVSS 10.0) actively exploited in zero-day attacks, and CISA added it to the Known Exploited Vulnerabilities catalogue with a federal patch deadline of May 17, 2026. In parallel, attackers are mass-exploiting CVE-2026-8181 in the Burst Statistics WordPress plugin (~115,000 sites still unpatched), with Wordfence blocking over 7,400 attacks in 24 hours. The TanStack npm/PyPI supply chain campaign expanded further, with OpenAI confirming credential exfiltration from two employee devices and TeamPCP advertising ~450 Mistral AI repositories (5 GB) for sale at $25,000. Ransomware operators The Gentlemen, Inc Ransom, and Cmd Organization continued posting new victims across healthcare, agribusiness, legal services, and printing sectors.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | Cisco SD-WAN CVE-2026-20182 (CISA KEV); Burst Statistics WordPress CVE-2026-8181 |
| 🟠 **HIGH** | 8 | TeamPCP / Mistral AI repo sale; OpenAI TanStack breach; Gentlemen (×4), Inc Ransom, Cmd Organization victim postings |
| 🟡 **MEDIUM** | 1 | SANS guest diary on Outlaw/Shellbot SSH library signature update |
| 🔵 **INFO** | 1 | SANS ISC Stormcast podcast |

## 3. Priority Intelligence Items

### 3.1 Cisco Catalyst SD-WAN Zero-Day Exploited (CVE-2026-20182) — CISA KEV

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-warns-of-new-critical-sd-wan-flaw-exploited-in-zero-day-attacks/)

Cisco disclosed a critical (CVSS 10.0) authentication bypass in Cisco Catalyst SD-WAN Controller and SD-WAN Manager (on-prem and cloud deployments). The flaw stems from a broken peering authentication mechanism: an unauthenticated attacker sending crafted requests can log in as an internal high-privileged non-root account, then access NETCONF to manipulate SD-WAN fabric routing. Cisco detected in-the-wild exploitation in May 2026. The flaw was discovered by Rapid7 while researching CVE-2026-20127 (fixed February 2026 and also exploited as a zero-day by threat actor UAT-8616 since 2023). CISA has added CVE-2026-20182 to the KEV catalogue with a federal patch deadline of May 17, 2026. No complete workaround exists — only patching mitigates the issue.

**Affected products:** Cisco Catalyst SD-WAN Controller, Cisco Catalyst SD-WAN Manager (on-prem and SD-WAN Cloud)

**MITRE ATT&CK:** T1078 (Valid Accounts), T1071.001 (Web Protocols), T1098.002 (Account Manipulation)

#### Indicators of Compromise
```
Auth log entry: "Accepted publickey for vmanage-admin" from unknown IPs in /var/log/auth.log
Example: 2026-02-10T22:51:36+00:00 vm sshd[804]: Accepted publickey for vmanage-admin from [REDACTED PORT] ssh2: RSA SHA256:[REDACTED]
Behaviour: Unauthorised peering events / rogue device registrations in SD-WAN fabric
Related actor: UAT-8616 (linked to prior CVE-2026-20127 exploitation)
```

> **SOC Action:** Patch Catalyst SD-WAN Controller and Manager immediately — federal agencies must comply by May 17, 2026 and private sector should match. Restrict management/control-plane interfaces to trusted internal networks or allowlisted IPs only. Pull `/var/log/auth.log` from all SD-WAN Controllers and grep for `Accepted publickey for vmanage-admin`; cross-reference source IPs against the System IPs configured in SD-WAN Manager (WebUI > Devices > System IP) and open a Cisco TAC case for any anomalies. Audit SD-WAN Controller logs for unexpected peering events or rogue device registrations.

### 3.2 Burst Statistics WordPress Plugin Auth Bypass Under Mass Exploitation (CVE-2026-8181)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-auth-bypass-flaw-in-burst-statistics-wordpress-plugin/)

Wordfence disclosed CVE-2026-8181 in the Burst Statistics WordPress plugin (200,000 active installs), a privacy-focused analytics plugin marketed as a Google Analytics alternative. The flaw, introduced in v3.4.0 (released 23 April) and present in v3.4.1, allows unauthenticated attackers who know a valid admin username to fully impersonate that administrator during REST API requests — including WordPress core endpoints like `/wp-json/wp/v2/users` — by sending any arbitrary incorrect password in a Basic Authentication header. The root cause is misinterpretation of `wp_authenticate_application_password()` return values, treating both `WP_Error` and `null` as successful authentication and then calling `wp_set_current_user()` with the attacker-supplied username. In the worst case, attackers can create new admin accounts with zero prior authentication. Wordfence blocked over 7,400 attacks in the 24 hours preceding publication. WordPress.org download stats suggest roughly 115,000 sites remain exposed.

**Affected product:** Burst Statistics WordPress plugin v3.4.0–3.4.1 (patched in v3.4.2 released 12 May 2026)

**MITRE ATT&CK:** T1078.004 (Valid Accounts: Application Service), T1133 (External Remote Services), T1190 (Exploit Public-Facing Application)

> **SOC Action:** Inventory all managed WordPress estates for the Burst Statistics plugin; force-update to v3.4.2 or disable the plugin entirely. For sites that ran v3.4.0 or v3.4.1 between 23 April and 12 May, audit `wp_users` for new administrator-role accounts created in that window, review REST API access logs for `/wp-json/wp/v2/users` POST requests with Basic Authentication headers, and rotate all admin credentials. Block POST requests to `/wp-json/wp/v2/users` from non-allowlisted IPs at the WAF where business logic permits.

### 3.3 TanStack npm Supply Chain Campaign Hits Mistral AI and OpenAI; TeamPCP Advertises Stolen Repos

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/teampcp-hackers-advertise-mistral-ai-code-repos-for-sale/), [The Record (Recorded Future)](https://therecord.media/openai-asks-macos-users-to-update-tanstack-npm)

The Mini Shai-Hulud / TanStack supply-chain campaign continued to expand. Mistral AI confirmed to BleepingComputer that attackers compromised a codebase management system after a developer device was hit by the TanStack supply-chain attack, contaminating SDK packages for a brief window. TeamPCP is now advertising ~450 Mistral repositories (~5 GB covering training, fine-tuning, benchmarking, model delivery, and inference assets) for sale on a hacker forum at $25,000, threatening to leak the data publicly within a week if no buyer is found. Mistral states the impacted data was not part of its core code repositories and that hosted services, managed user data, and research/testing environments were not compromised.

In parallel, OpenAI confirmed two employee devices were impacted, with malware behaving consistently with the publicly described credential-stealer payload and accessing "a limited subset of internal source code repositories." OpenAI said only limited credential material was successfully exfiltrated, rotated code-signing certificates, and is requiring macOS users to update OpenAI desktop apps before 12 June 2026 — after which un-updated installs will stop receiving updates and may fail to launch. The originating npm package compromise affected 84 artefacts (some with 12M+ weekly downloads), and UK government officials indicated the malicious packages were uploaded in two phases on 29 April and 11 May. The malware self-propagates by republishing the victim's other packages.

**Affected ecosystem:** npm and PyPI (TanStack, Mistral AI SDKs, plus downstream UiPath, Guardrails AI, OpenSearch, and others); OpenAI macOS desktop app code-signing certificates

**MITRE ATT&CK:** T1195.002 (Compromise Software Supply Chain), T1078.004 (Valid Accounts: Application Access Token), T1566 (Phishing), T1190 (Exploitation for Client Execution)

> **SOC Action:** Force-update OpenAI macOS desktop apps before 12 June 2026 — block legacy signing-certificate execution at endpoint allowlisting/Gatekeeper policy after that date. Audit `package-lock.json`, `pnpm-lock.yaml`, and `requirements.txt` history across the last 30 days for any TanStack, Mistral, UiPath, Guardrails AI, or OpenSearch package versions published between 29 April and 11 May 2026; pin to known-clean versions. Rotate any npm/PyPI publish tokens, CI/CD secrets, and code-signing keys exposed to developer workstations that installed affected packages. Hunt EDR for credential-stealer behaviour from `node`, `npm`, and Python interpreters on developer endpoints during the same window.

### 3.4 The Gentlemen Ransomware: Coordinated Multi-Sector Posting Wave

**Source:** [RansomLook (group: The Gentlemen)](https://www.ransomlook.io//group/the%20gentlemen)

The Gentlemen ransomware group posted four new victim disclosures in a single posting wave on 15 May 2026 UTC, covering geographically and sectorally distinct organisations: Ponisch Abogados (Mexican–German legal services), Digiprint (Polish printing industry), Instituut voor de Nederlandse Taal (Dutch/Flemish language research institute), and Grupo Alvorada (Brazilian agribusiness / poultry). RansomLook tracks the group at 412 posts all-time with 85 in the last 30 days and 24 in the last 7, indicating sustained operational tempo despite ~20% average leak-site uptime. Reference research: Trend Micro, "Unmasking the Gentlemen Ransomware" (Sept 2025). Cross-batch correlation engine flagged these as one campaign (confidence 0.90) on shared malware family, T1496 (Resource Hijacking), and overlapping sectors.

**Affected sectors:** Legal services, printing/manufacturing, academic/research, agribusiness

**MITRE ATT&CK:** T1496 (Resource Hijacking), T1486 (Data Encrypted for Impact), T1189 (Drive-by Compromise), T1078 (Valid Accounts), T1071.001 (Web Protocols), T1204 (User Execution)

#### Indicators of Compromise
```
Tox ID: F8E24C7F5B12CD69C44C73F438F65E9BF560ADF35EBBDF92CF9A9B84079F8F04060FF98D098E
Leak site: hxxp[://]tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion/
Chat server: hxxp[://]i2ohjeeqe37jre4f2u7pyq73cbm6lecumdxapkvrlryna6rc3it4zsid[.]onion/
```

> **SOC Action:** Add the Tox ID and onion addresses above to internal threat-intel watchlists and DNS sinkhole/Tor-exit monitoring. For organisations in legal services, printing, agribusiness, or academic research sectors, prioritise tabletop validation of ransomware playbooks and confirm immutable backup coverage for primary file servers and database hosts. Query EDR for `T1496` resource-hijacking indicators (unexpected high-CPU processes, unrecognised cryptominer-style binaries) on internet-facing hosts.

### 3.5 Inc Ransom and Cmd Organization Maintain Healthcare/Numismatics Pressure

**Source:** [RansomLook — Inc Ransom](https://www.ransomlook.io//group/inc%20ransom), [RansomLook — Cmd Organization](https://www.ransomlook.io//group/cmd%20organization)

Inc Ransom posted United Quality Cooperative (uqcoop.com) on 15 May 2026, continuing a campaign that includes Silergy Corp (13 May), Bideawee, RBH Aerospace, and Calsoft Inc earlier in May — 41 posts in the last 30 days. The group operates multiple leak and chat onion services with fluctuating uptime. Cmd Organization, a smaller but currently 100%-uptime group (8 total posts), added Houston Eye Associates, Goodstone Group, and Ira & Larry Goldberg Coins & Collectibles on 14 May, demonstrating focus on healthcare and numismatics/collectibles verticals. The correlation engine linked Inc Ransom and Cmd Organization activity through shared healthcare-sector targeting at confidence 0.70.

**Affected sectors:** Cooperatives, healthcare (ophthalmology), numismatics/collectibles, manufacturing, biotech

**MITRE ATT&CK:** T1486 / T1485 (Data Encrypted for Impact), T1566 (Phishing), T1189 (Drive-by Compromise), T1496 (Resource Hijacking), T1071 (Application Layer Protocol)

#### Indicators of Compromise
```
Inc Ransom leak (up): hxxp[://]incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion/blog/disclosures
Inc Ransom backup: hxxp[://]incbacg6bfwtrlzwdbqc55gsfl763s3twdtwhp27dzuik6s6rwdcityd[.]onion
Inc Ransom payment chat: hxxp[://]incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid[.]onion/
Cmd Organization leak: hxxp[://]cmdnkiqjije2tllr3biee2sjgj3i4robg2cbtilbnytdhh2wy3syrlyd[.]onion/
Cmd Organization clear: hxxps[://]cmdofficial[.]com/
```

> **SOC Action:** Healthcare and cooperative-sector defenders should harden externally-exposed VPN/RDP and email gateways and validate offline backup integrity within 7 days. Block the listed onion gateways at egress proxies and Tor-aware DLP rules. For confirmed victims, escalate to law-enforcement reporting channels and engage incident response before any extortion engagement.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software and plugins | Burst Statistics WordPress CVE-2026-8181 (mass exploitation, 7,400+ blocks/24h); Cisco Catalyst SD-WAN CVE-2026-20182 (CISA KEV, in-the-wild) |
| 🔴 **CRITICAL** | Elevation-of-privilege vulnerabilities in .NET and other frameworks actively exploited (carried from prior batch) | CVE-2026-32177, CVE-2026-35433 (.NET EoP) |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with overlapping tactics | United Quality Cooperative (Inc Ransom); Digiprint, Ponisch Abogados, Grupo Alvorada, Instituut voor de Nederlandse Taal (The Gentlemen) |
| 🟠 **HIGH** | Supply-chain attacks targeting software development and technology sectors | TanStack/Mistral compromise; OpenAI macOS code-signing rotation; node-ipc credential-stealing; Backdoored Cemu / Mistral campaign |
| 🟠 **HIGH** | Continued phishing and ransomware tactics by multiple actors (Qilin, KongTuke, deepfake impersonation campaigns) | CVE-2026-42897 MS Exchange spoofing; Schulte-Lindhorst (Qilin); KongTuke MS Teams; deepfake-impersonation Python backdoor |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (108 reports, last seen 2026-05-14) — most prolific ransomware operator over the trailing 30-day window
- **Akira** (59 reports) — sustained activity across multiple sectors
- **The Gentlemen** (58 reports, last seen 2026-05-15) — coordinated four-victim drop on 15 May
- **ShinyHunters** (33 reports) — extortion / data-theft brokerage
- **Inc Ransom** (25 reports, last seen 2026-05-15) — active healthcare and cooperative targeting
- **TeamPCP** (24 reports, last seen 2026-05-14) — supply-chain breach and data-sale extortion against Mistral AI and OpenAI
- **Everest** (24 reports) — continuing leak-site postings
- **Coinbase Cartel** (16 reports) — financial-sector adjacent extortion

### Malware Families
- **Akira ransomware** (32 reports) — RaaS, multi-sector
- **Tox1 / Tox** (31 / 15 reports) — communication identifier used by The Gentlemen and other groups
- **RaaS** (18 reports) — generic ransomware-as-a-service taxonomy tag
- **Qilin** (13 reports) — ransomware family
- **Shellbot / Outlaw "Dota" family** — see Section 3 reference; updated libssh client library and hassh value signal evolution of long-running crypto-mining/SSH-brute campaign

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 6 | [link](https://www.ransomlook.io/) | Aggregate leak-site monitoring for The Gentlemen (4), Inc Ransom (1), Cmd Organization (1) |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com/) | Primary coverage of CVE-2026-20182 (Cisco SD-WAN), CVE-2026-8181 (Burst Statistics), and TeamPCP/Mistral repo sale |
| SANS | 2 | [link](https://isc.sans.edu/) | Outlaw/Shellbot signature update guest diary; daily ISC Stormcast podcast |
| RecordedFutures | 1 | [link](https://therecord.media/openai-asks-macos-users-to-update-tanstack-npm) | OpenAI confirmation of TanStack supply-chain impact and macOS signing-certificate rotation |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Cisco Catalyst SD-WAN Controller and Manager for CVE-2026-20182 ahead of the CISA KEV federal deadline of 17 May 2026; pull `/var/log/auth.log` and audit for unauthorised `vmanage-admin` publickey acceptances and rogue peering events.
- 🔴 **IMMEDIATE:** Force-update or disable the Burst Statistics WordPress plugin (CVE-2026-8181) on all managed sites; audit `wp_users` for unauthorised admin-role accounts created between 23 April and 12 May 2026 and rotate admin credentials on previously-vulnerable sites.
- 🟠 **SHORT-TERM:** Audit npm/PyPI dependency lockfiles for TanStack / Mistral / UiPath / Guardrails AI / OpenSearch package versions published 29 April–11 May 2026; rotate any developer-workstation-accessible publish tokens, CI/CD secrets, and code-signing keys. Block legacy OpenAI macOS code-signing certificates after 12 June 2026.
- 🟠 **SHORT-TERM:** Healthcare, cooperative, legal-services, and printing-sector defenders should validate offline/immutable backup coverage and run a ransomware tabletop this week; add the published Tox ID, onion gateways, and `cmdofficial[.]com` to watchlists and egress block policies.
- 🟡 **AWARENESS:** Distribute updated Outlaw/Shellbot SSH-library signatures (new hassh value per SANS guest diary) to detection engineering; review `authorized_keys` on Linux fleet for the historically static `mdrfckr` campaign key.
- 🟢 **STRATEGIC:** Treat developer-workstation supply-chain risk (npm/PyPI/CI-CD-credential theft) as a peer to traditional perimeter risk — invest in package allowlisting, build-time SBOM generation, and short-lived publish tokens to limit blast radius of the next Shai-Hulud-class event.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 12 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
