---
layout: post
title:  "CTI Daily Brief: 2026-06-22 - Aurora ESA data exposure, Klue/Salesforce supply chain extortion, 3CX Lazarus campaign"
date:   2026-06-22 20:06:00 +0000
description: "41 reports across 12 sources. Aurora ransomware exposed 30+ years of ESA aerospace materials data; Icarus extortion campaign exploits Klue OAuth tokens against Salesforce; Lazarus 3CXDesktopApp supply chain intrusion guidance published; Brazilian Civil Defense alert system hijacked."
category: daily
tags: [cti, daily-brief, aurora, the-gentlemen, akira, icarus, lazarus-group, klue, 3cxdesktopapp]
classification: TLP:CLEAR
reporting_period: "2026-06-22"
generated: "2026-06-22"
draft: true
severity: high
report_count: 41
sources:
  - RansomLook
  - BleepingComputer
  - Wired Security
  - SANS
  - Schneier
  - Datadog
  - AlienVault
  - RecordedFutures
  - Crowdstrike
  - Wiz
  - Upwind
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-22 (24h) | TLP:CLEAR | 2026-06-22 |

## 1. Executive Summary

The pipeline processed 41 reports across 12 sources in the last 24 hours, dominated by ransomware leak-site activity (24 of 41 from RansomLook). The headline finding is the Aurora ransomware group's exposure of two complete NAS snapshots from Aerospace & Advanced Composites GmbH (AAC) — an Austrian aerospace materials R&D firm with deep ESA ties — including 30+ years of thermal vacuum test archives, 137 executed NDAs (Airbus, Tesla, ESA, Samsung SDI, CERN), Bitlocker recovery keys, and an IT credentials master spreadsheet. A second major item is the "Icarus" extortion campaign tied to the Klue supply chain compromise: a dormant OAuth credential was used to fan out across customer Salesforce and Gong instances starting 11 June, with extortion emails arriving by 16 June. AlienVault republished IOC-rich detection guidance for the Lazarus Group (Labyrinth Chollima) 3CXDesktopApp trojanized installer campaign, and Brazil's National Civil Defense Alert system was hijacked to push false high-severity emergency alerts via cell broadcast and SMS. No new CISA KEV additions appeared in today's collection, and no individual reports were rated critical — however the correlation engine elevated Aurora's aerospace targeting to a critical-risk trend.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 0 | No critical-rated reports this period (Aurora aerospace activity rated as critical-risk trend) |
| 🟠 **HIGH** | 31 | Aurora ESA exposure; The Gentlemen RaaS spree (Tox1); Akira NTD Apparel; Klue/Icarus Salesforce extortion; Brazil alert-system hijack; 3CX/Lazarus IOC update |
| 🟡 **MEDIUM** | 2 | Microsoft AutoGen Studio "AutoJack" RCE chain; Wallstreet monitoring of Omax Autos |
| 🔵 **INFO** | 8 | Windows 11 26H2 announcement; OpenAI "Patch the Planet"; CrowdStrike CDR survey; Wiz Windows runtime sensor; SANS webshell diary |

## 3. Priority Intelligence Items

### 3.1 Aurora ransomware exposes 30+ years of ESA-linked aerospace R&D data

**Source:** [RansomLook (Aurora leak site)](https://www.ransomlook.io//group/aurora)

Aurora has published two complete NAS snapshots stolen from Aerospace & Advanced Composites GmbH (AAC), a Wiener Neustadt-based aerospace materials R&D firm with deep ties to the European Space Agency. The `aacdata` snapshot (31 December 2022, 123 GB) contains the company's complete Testhouse/R&D/engineering share, the ESA thermal vacuum test archive, polymer composite formulations, and 22 Outlook PST backups. The `aacdata1` snapshot (14 January 2025, 86 GB) contains the administrative share including the managing director's full PC backup, 15 years of financial statements, shareholder agreements, and — operationally critical — the IT credentials master spreadsheet (`AAC CODES.xlsx`) containing every system password plus browser-stored logins for ESA SSO. Additionally exposed: 12 Bitlocker recovery keys enabling full-disk decryption of 6 laptops, 137 executed NDAs with partners including Airbus, RUAG, Safran, Thales, ESA, BMW, Tesla, Google, Samsung SDI, CERN, and DLR. The same leak post also exposed data from Dutch civil engineering contractor NTP B.V. and German manufacturer Kochs GmbH (22 GB of MSSQL payroll backups). The correlation batch elevated Aurora's repeated aerospace and civil engineering targeting to a **critical**-risk trend.

**Affected:** Aerospace materials R&D, civil engineering contractors, manufacturing (German DACH region), and named third parties via NDA exposure.

**MITRE:** T1486 (Data Encrypted for Impact), T1204 (User Execution).

> **SOC Action:** If your organisation has any current or historical NDA, supplier, or research partnership with AAC, ESA-affiliated entities, or any of the named partners (Airbus/RUAG/Safran/Thales/Samsung SDI/CERN/DLR/Tesla/BMW), assume associated credentials and project documents are exposed. Force-rotate any shared SSO credentials linked to ESA partner portals, audit federation trust paths, and hunt for stolen-credential reuse against your VPN/SSO logs over the last 14 days.

### 3.2 Klue supply chain compromise — "Icarus" extortion via Salesforce/Gong OAuth tokens

**Source:** [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/)

On 11 June 2026, a threat actor self-identifying as **Icarus** (active since at least 28 April 2026) compromised Klue — a competitive-intelligence platform used by hundreds of enterprises to sync battlecard data with CRMs — using a dormant credential left over from a prototype integration that was never decommissioned. By 13 June Klue had revoked OAuth credentials, but the attacker had already harvested OAuth tokens for both Salesforce and Gong and was using Python scripts (`Python-urllib/3.12`, `Python-urllib/3.14`, and user-agent `5238`) to query `/services/data/v59.0/query/*` REST endpoints across customer Salesforce orgs. Extortion emails (subject: "top secret email", 48h deadline, Session Messenger contact) began arriving 16 June. Huntress has publicly confirmed compromise of CRM contacts, price quotes, and sales communications. In a subset of victims the actor used OAuth **refresh** tokens to maintain access.

**Affected:** Salesforce and Gong customers of Klue Battlecards integration; CRM data including business contacts, price quotes, and sales communications.

**MITRE:** T1071 (Application Layer Protocol), T1196 (Masquerading), T1078 (Valid Accounts via OAuth).

#### Indicators of Compromise
```
User-Agent: Python-urllib/3.12
User-Agent: Python-urllib/3.14
User-Agent: 5238
Salesforce field: application:"Klue Battlecards"
Salesforce field: connected_app_name:"Klue Battlecards"
Endpoint accessed: /services/data/v59.0/query/*
Extortion subject line: "top secret email"
Extortion contact channel: Session Messenger
```

> **SOC Action:** In Salesforce, immediately revoke the Klue Battlecards connected app and any OAuth refresh tokens issued to it; query Event Monitoring `LoginEvent` and API event logs for `application:"Klue Battlecards"` or `connected_app_name:"Klue Battlecards"` between 2026-06-11 and 2026-06-13 and treat any query volume against `/services/data/v59.0/query/*` as exfiltration. Repeat the same exercise in Gong. Audit your full third-party OAuth inventory for prototype, abandoned, or unowned integrations and disable any without a current business owner.

### 3.3 Lazarus Group (Labyrinth Chollima) 3CXDesktopApp supply chain — refreshed IOCs

**Source:** [AlienVault OTX Pulse](https://otx.alienvault.com/pulse/6a38d6259f636193112c9c1c)

AlienVault republished a hunting and detection package for the trojanized 3CXDesktopApp supply chain compromise attributed to Lazarus Group / Labyrinth Chollima. The campaign distributes signed installers across Windows, macOS, and Linux that deploy a compromised `ffmpeg.dll`, which beacons over HTTPS to attacker-controlled infrastructure to retrieve second-stage payloads (`ArcfeedLoader`, `TxRLoader`). The pulse contains a substantial set of domains and SHA-256 hashes covering both stages.

**Affected:** Any organisation running the 3CXDesktopApp softphone on Windows/macOS/Linux.

**MITRE:** T1195.002 (Compromise Software Supply Chain), T1036.005, T1055, T1059, T1071.001, T1071.004, T1573.

#### Indicators of Compromise
```
Domains (defanged):
  akamaicontainer[.]com
  akamaitechcloudservices[.]com
  azuredeploystore[.]com
  azureonlinecloud[.]com
  azureonlinestorage[.]com
  dunamistrd[.]com
  glcloudservice[.]com
  journalide[.]org
  msedgepackageinfo[.]com
  msstorageazure[.]com
  msstorageboxes[.]com
  officeaddons[.]com
  officestoragebox[.]com
  pbxcloudeservices[.]com
  pbxphonenetwork[.]com
  pbxsources[.]com
  qwepoi123098[.]com
  sbmsa[.]wiki
  visualstudiofactory[.]com
  zacharryblogs[.]com

SHA-256:
  5407cda7d3a75e7b1e030b1f33337a56f293578ffa8b3ae19c671051ed314290
  59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983
  7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896
  92005051ae314d61074ed94a52e76b1c3e21e7f0e8c1d1fdd497a006ce45fa61
  aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868
  b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb
  dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc
  e6bbc33815b9f20b0cf832d7401dd893fbc467c800728b5891336706da0dbcec
  fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405
```

> **SOC Action:** Push the 20 domains above into DNS sinkhole / proxy blocklists immediately and pivot on historical DNS for hits going back 12 months. Hunt `ffmpeg.dll` file hashes on any host that has ever run 3CXDesktopApp, and alert on any host beaconing to `*.akamai*` or `*.azureonline*` lookalike domains not in your approved CDN inventory. Treat any historical 3CXDesktopApp install as suspect until version-confirmed clean.

### 3.4 Brazil Civil Defense Alert system hijacked — false emergency alerts pushed via cell broadcast

**Source:** [The Record (Recorded Future News)](https://therecord.media/suspected-cyberattack-triggers-false-emergency-alerts-brazil)

Brazil's National Protection and Civil Defense Secretariat has suspended its mobile emergency alert platform after an unauthorised actor outside the official civil defense network remotely triggered at least 10 false alerts at the system's highest severity level. Nine alerts were distributed via cell broadcast, one via SMS; one was reportedly tagged with the word "misanthropy". States affected include São Paulo, Rio de Janeiro, Paraná, Mato Grosso do Sul, and the Federal District. Authorities have blocked external access to the Public Alert Dissemination Interface. The Federal Police are investigating; no suspect has been identified. Authorities stated there is no evidence of "structural damage" to the core infrastructure.

**Affected:** Brazilian public emergency alerting capability; downstream risk of public-trust erosion and emergency-fatigue.

**MITRE:** T1071 (Application Layer Protocol), T1105 (Ingress Tool Transfer).

> **SOC Action:** For operators of public alerting, mass-notification, or cell-broadcast systems anywhere: audit administrative interfaces for internet exposure, enforce IP allow-listing and hardware-key MFA on dissemination consoles, and verify that out-of-network operators cannot push high-severity messages. Treat any non-decommissioned legacy "dissemination interface" as in-scope. Brief comms/PR teams on monitoring for spoofed alert content.

### 3.5 The Gentlemen RaaS — sustained multi-victim spree across manufacturing, biotech, and real estate

**Source:** [RansomLook (The Gentlemen leak site)](https://www.ransomlook.io//group/the%20gentlemen)

The Gentlemen ransomware group posted 10 victims to its leak site in the last 24 hours, including MBO GmbH, CTM India Limited (motherson INDIA), GIA Partners, Hooke Laboratories, Rowley Properties, Canada Wide Media, ErgoMed, Royal Thai Navy Housing Cooperative, International Freight Services, and Keywest Projects. The group is using the Tox1 protocol for affiliate coordination, deploys captcha-protected leak sites, and exhibits ~32% leak-site uptime over the last 30 days. The Gentlemen is the highest-volume actor in our pipeline over the last 30 days (82 reports) and is associated with T1071.001 (web protocol C2) and T1204 (user execution).

**Affected:** Manufacturing, biotechnology, real estate, logistics, media, and government-adjacent sectors in India, Thailand, Canada, Germany, and the US.

**MITRE:** T1071.001, T1204, T1486.

> **SOC Action:** Add The Gentlemen's known onion infrastructure (`tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion`) to dark-web monitoring. For mid-market manufacturing/biotech/real-estate clients: confirm offline backups within 24h RPO and validate that backup catalogues are not accessible from the production AD domain. Increase egress sampling on Tor and Tox-related ports.

### 3.6 Microsoft AutoGen Studio "AutoJack" — agent-driven RCE via three chained flaws

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-fixes-autogen-studio-flaw-that-enabled-code-execution/)

Microsoft has remediated a vulnerability chain dubbed **AutoJack** in AutoGen Studio (the GUI for the AutoGen multi-agent framework). The chain combines (1) an MCP WebSocket that implicitly trusts localhost origins, (2) authentication middleware that excludes `/api/mcp/*` routes from auth checks while the MCP WebSocket itself has no authentication, and (3) a base64-encoded `server_params` URL value passed straight to the process-launching code. A developer's AI agent visiting a malicious webpage could be coerced into launching attacker-supplied PowerShell, Bash, or executables under the developer's account. Microsoft confirmed the issue was caught **before any PyPI release**, so only developers building from the `main` GitHub branch between the MCP plugin landing and commit `b047730` are exposed.

**Affected:** Developers running AutoGen Studio from GitHub source (not PyPI) during the exposure window; AI agent workstations more broadly as a pattern.

**MITRE:** T1059 (Command and Scripting Interpreter), T1071.001.

> **SOC Action:** Inventory AutoGen Studio installs on developer endpoints; confirm any developer-built copy is at or past commit `b047730` and verify no `autogenstudio` install pre-dates package `0.4.2.2`. Pattern more broadly: hunt for local MCP WebSocket endpoints on developer hosts and block external WebSocket origins from reaching `localhost` MCP listeners. Treat developer AI-agent browsers as untrusted-input ingestion points.

### 3.7 Akira double-extortion adds NTD Apparel (62 GB data threat)

**Source:** [RansomLook (Akira leak site)](https://www.ransomlook.io//group/akira)

Akira has listed NTD Apparel on its leak site and threatened to release 62 GB of corporate data including employee passports, SSNs, driver's licences, medical and contact details, projects, client information, and confidential agreements. Akira continues to operate as an independent (non-RaaS) actor with 100% leak-site uptime over the last 30 days and 31 posts in that window. Initial-access pattern remains unpatched VPN appliances, compromised RDP, phishing, and abuse of legitimate remote administration tools; the Windows variant appends `.akira` extensions via the Windows CryptoAPI.

**Affected:** Apparel and licensed-products retail; broader pattern continues to hit education, manufacturing, and healthcare.

**MITRE:** T1078 (Valid Accounts), T1133 (External Remote Services), T1566 (Phishing), T1486.

> **SOC Action:** Confirm all SSL VPN appliances (Cisco ASA/Fortinet/SonicWall/Citrix) are patched current and that MFA is enforced; query EDR for `vssadmin delete shadows`, `wmic shadowcopy delete`, and `bcdedit /set bootstatuspolicy ignoreallfailures` execution in the last 30 days. Validate that ESXi management interfaces are not exposed and that VMware vCenter is at current patch level.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|--------------------|
| 🔴 **CRITICAL** | Aurora ransomware group continues to target aerospace and civil engineering sectors | Aerospace & Advanced Composites GmbH; NationsBuilders Insurance Services |
| 🟠 **HIGH** | Increased ransomware activity targeting diverse sectors with overlapping TTPs (T1071.001, T1204) | Ntd Apparel By akira; NEW PRINZ EUGEN SITE |
| 🟠 **HIGH** | Phishing campaigns evolving with advanced techniques targeting high-profile events | World Cup Scams Are Getting Harder to Spot; Prinz Eugen activity |
| 🟠 **HIGH** | Increased availability of sophisticated ransomware tools at low cost ($20 builders) | Telegram (channel name redacted) — two posts advertising ransomware builder |
| 🟠 **HIGH** | Phishing as a common TTP across multiple sectors (T1566) | jaggroup.com data dump; Wall ISD; Taiwan Sintong Machinery |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (82 reports, last 30d) — Tox1-based RaaS, multi-sector, ~32% leak-site uptime
- **Qilin** (68 reports) — RaaS targeting financial, manufacturing, government (e.g., Central Bank of Libya today)
- **Deadlock** (55 reports) — concentrated activity mid-June
- **Lockbit5** (39 reports) — sustained activity through 18 June
- **DragonForce** (38 reports) — RaaS, ex-hacktivist origins, retail/government targeting
- **Akira** (28 reports) — independent (non-RaaS) double-extortion, 100% uptime
- **Nightspire** (27 reports) — sustained leak-site activity
- **ShinyHunters** (23 reports) — data-broker activity
- **Aurora** (19 posts all-time on leak site, 9 in last 7d) — aerospace, civil engineering, manufacturing

### Malware Families

- **Tox1** (59 reports) — primary affiliate-coordination malware for The Gentlemen
- **Other1** (38 reports) — ransomware family clustering
- **Tox** (37 reports) — communication protocol abuse
- **Lockbit5** (14 reports) — ransomware payload
- **Akira ransomware** (13 reports) — CryptoAPI-based encryptor, `.akira` extension
- **Nightspire** (11 reports) — ransomware family
- **Deadlock** (10 reports) — ransomware family
- **Nova** (9 reports) — formerly RALord, rebranded RaaS
- **ArcfeedLoader / TxRLoader** — Lazarus Group second-stage loaders (3CX campaign)

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 24 | [link](https://www.ransomlook.io/) | Ransomware leak-site aggregator — Aurora, Akira, The Gentlemen, DragonForce, Qilin, CMD Organization, Stormous, Prinz Eugen, Wallstreet |
| BleepingComputer | 3 | [link](https://www.bleepingcomputer.com) | AutoGen Studio "AutoJack" fix; "Search Your Target" credential markets; Windows 11 26H2 |
| Unknown (Telegram) | 3 | — | Two $20 ransomware-builder ads; JSC exploitation primer (Telegram channel names redacted per policy) |
| Wired Security | 2 | [link](https://www.wired.com/story/world-cup-scams-are-getting-harder-to-spot/) | 2026 FIFA World Cup AI-driven scam scaling; OpenAI "Patch the Planet" |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/33096) | ZypeerShell PHP webshell; ISC Stormcast |
| AlienVault | 1 | [link](https://otx.alienvault.com/pulse/6a38d6259f636193112c9c1c) | 3CXDesktopApp / Lazarus IOC pulse |
| Datadog | 1 | [link](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/) | Klue / Icarus Salesforce detection guide |
| RecordedFutures | 1 | [link](https://therecord.media/suspected-cyberattack-triggers-false-emergency-alerts-brazil) | Brazil Civil Defense Alert hijack |
| Schneier | 1 | [link](https://www.schneier.com) | Wearables and athlete biometric privacy |
| Crowdstrike | 1 | [link](https://www.crowdstrike.com/en-us/blog/crowdstrike-state-of-cdr-survey-key-takeaways/) | 94% cloud-breach figure (CDR Survey) |
| Wiz | 1 | [link](https://www.wiz.io/blog/wiz-runtime-sensor-for-your-windows-environment) | Wiz Runtime Sensor for Windows GA |
| Upwind | 1 | [link](https://www.upwind.io/feed/upwind-asm-attack-surface-management-exploitability) | Attack Surface Management launch |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Block and sinkhole the 20 Lazarus/3CX domains listed in §3.3, hunt the nine SHA-256 hashes across the estate, and audit any host that has ever run 3CXDesktopApp for `ffmpeg.dll` hash matches. (Ref: §3.3)
- 🔴 **IMMEDIATE:** If you are a Salesforce or Gong tenant, revoke the Klue Battlecards connected app and any associated OAuth refresh tokens, then run the detection queries in §3.2 over Salesforce Event Monitoring logs spanning 11–13 June 2026. (Ref: §3.2)
- 🟠 **SHORT-TERM:** Inventory all third-party OAuth integrations into CRM/sales-engagement platforms; disable any without a named business owner or active integration use. Treat dormant credentials as the highest-priority technical debt this quarter. (Ref: §3.2)
- 🟠 **SHORT-TERM:** Force credential rotation and federation review for any organisation with current or prior ESA/aerospace supply-chain ties to AAC; assume the IT credentials master spreadsheet and Bitlocker recovery keys in §3.1 are in adversary hands. (Ref: §3.1)
- 🟡 **AWARENESS:** Brief developer teams that AutoGen Studio installs built from GitHub `main` before commit `b047730` are vulnerable to AutoJack — verify pinned version `autogenstudio 0.4.2.2` on PyPI, and treat developer AI-agent browsers as untrusted ingress paths. (Ref: §3.6)
- 🟢 **STRATEGIC:** With $20 ransomware builders now openly marketed on Telegram and "search your target" credential-broker services maturing into a productised layer between infostealer logs and account takeover, assume credential-led intrusions will continue to dominate the threat landscape; prioritise phishing-resistant MFA (FIDO2) on all internet-facing identity, and integrate infostealer-log monitoring into the IR programme.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 41 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
