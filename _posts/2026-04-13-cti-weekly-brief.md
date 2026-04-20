---
layout: post
title:  "CTI Weekly Brief: 2026-04-13 to 2026-04-19 - Microsoft Patch Tuesday delivers 167 fixes and two zero-days as RedSun LPE, protobuf.js RCE and Nginx UI exploitation escalate alongside a surging Everest/Qilin/Gentlemen ransomware wave"
date:   2026-04-20 08:13:20 +0000
description: "Microsoft shipped 167 April fixes with two zero-days (CVE-2026-32201 exploited; CVE-2026-33825 Defender LPE public) while a second Defender zero-day PoC (RedSun) grants SYSTEM on fully patched hosts. A critical protobuf.js RCE, actively exploited Nginx UI auth bypass (CVE-2026-33032), and Marimo RCE (CVE-2026-39987) delivering NKAbuse via Hugging Face dominated vulnerability activity. Ransomware activity from Everest, Qilin, The Gentlemen, Coinbase Cartel, DragonForce and Kairos saturated leak-site telemetry."
category: weekly
tags: [cti, weekly-brief, everest, qilin, dragonforce, coinbase-cartel, the-gentlemen, nkabuse, ransomlock, cve-2026-32201, cve-2026-33825, cve-2026-33032, cve-2026-39987]
classification: TLP:CLEAR
reporting_period_start: "2026-04-13"
reporting_period_end: "2026-04-19"
generated: "2026-04-20"
draft: false
severity: critical
report_count: 687
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - Schneier
  - SANS
  - Wired Security
  - Wiz
  - Sysdig
  - Cisco Talos
  - Upwind
  - CISA
  - ESET Threat Research
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-13 to 2026-04-19 (7d) | TLP:CLEAR | 2026-04-20 |

## 1. Executive Summary

The CognitiveCTI pipeline ingested 687 reports across 15 sources between 13 and 19 April 2026, anchored by Microsoft's April Patch Tuesday (167 fixes including two zero-days) and an extraordinary volume of ransomware leak-site activity tracked via RansomLock (185 reports). Confirmed in-the-wild exploitation escalated on three fronts this week: CVE-2026-32201 (Microsoft SharePoint Server spoofing), CVE-2026-33032 (Nginx UI with MCP support — full unauthenticated server takeover), and CVE-2026-39987 (Marimo reactive Python notebook — used to push a new NKAbuse variant from Hugging Face Spaces).

A second Microsoft Defender zero-day proof-of-concept — "RedSun" — was published by researcher "Chaotic Eclipse" after Patch Tuesday and verified by independent analysts to grant SYSTEM on fully patched Windows 10, 11, and Server. Critical supply-chain risk rose further with a protobuf.js RCE (GHSA-xq3m-2v4x-88gg) affecting a library with ~50M weekly npm downloads, and with Cisco's out-of-cycle Webex/ISE patches requiring customer action. On the ransomware side, the Everest group dominated the 20 April correlation batch with double-extortion operations spanning government, healthcare, manufacturing and IT services; Qilin, The Gentlemen, Coinbase Cartel, Kairos, Blackwater and DragonForce all produced double-digit new victim posts.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 100 | April Patch Tuesday RCE/EoP cluster, Chromium PDFium/V8 batch, Cisco Webex/ISE, Nginx UI CVE-2026-33032, Marimo CVE-2026-39987, protobuf.js GHSA-xq3m-2v4x-88gg, Horner ICS, AVEVA Pipeline Sim |
| 🟠 **HIGH** | 422 | RansomLock-sourced victim disclosures (Everest, Qilin, The Gentlemen, Coinbase Cartel, DragonForce, Kairos, Blackwater, Payouts King, nightspire, Akira, ShinyHunters), Ukrainian APT28 campaign reporting |
| 🟡 **MEDIUM** | 82 | Library CVEs (libpng, Axios, tar-rs, XZ Utils, Handlebars), wolfSSL certificate handling chain, Python CVE-2026-4786/6100 |
| 🟢 **LOW** | 10 | Miscellaneous advisory and compatibility notices |
| 🔵 **INFO** | 73 | Vendor commentary, policy coverage, background analyses |

## 3. Priority Intelligence Items

### 3.1 Microsoft April 2026 Patch Tuesday — 167 fixes, two zero-days (one exploited)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-april-2026-patch-tuesday-fixes-167-flaws-2-zero-days/), [BleepingComputer (Windows 10 KB5082200)](https://www.bleepingcomputer.com/news/microsoft/microsoft-releases-windows-10-kb5082200-extended-security-update/)

Microsoft released fixes for 167 flaws on 14 April including 8 Critical bugs (seven RCEs and one DoS). Two zero-days were addressed: **CVE-2026-32201**, a Microsoft SharePoint Server spoofing vulnerability that was actively exploited in attacks, and **CVE-2026-33825**, a publicly disclosed Microsoft Defender elevation-of-privilege flaw granting SYSTEM privileges (patched via Defender Antimalware Platform 4.18.26050.3011). The broader release includes 93 elevation-of-privilege bugs, 20 RCEs, 21 information disclosure, 13 security-feature-bypass, 10 DoS, and 9 spoofing vulnerabilities. High-impact Office RCEs (CVE-2026-32197/32199 Excel, CVE-2026-32190 Office, CVE-2026-33114 Word, CVE-2026-32200 PowerPoint) can be triggered via preview pane or malicious documents. Windows 10 customers receive the rollup via KB5082200, which also hardens .rdp file handling and reports Secure Boot certificate rollout status.

**Affected products / sectors:** Windows 10/11/Server, Microsoft 365 Office apps, SharePoint Server, Windows Defender, Hyper-V, Windows TCP/IP, Active Directory, Azure Logic Apps. All sectors exposed.

#### Indicators of Compromise

```
No file-level IOCs published by Microsoft for either zero-day.
Actively exploited: CVE-2026-32201 (SharePoint Server spoofing)
Publicly disclosed: CVE-2026-33825 (Defender EoP → SYSTEM)
```

> **SOC Action:** 🔴 Deploy April cumulative updates and Defender Antimalware Platform ≥ 4.18.26050.3011 cluster-wide this week. Confirm automatic platform update has executed on EDR-managed endpoints (`Get-MpComputerStatus | Select AMEngineVersion, AMServiceVersion`). For SharePoint, treat CVE-2026-32201 as actively exploited — audit recent on-prem SharePoint authentication and Graph/SP web service logs for anomalous spoofed identity usage and sensitive list reads. Prioritise Office client patching on any endpoint that handles external attachments; disable preview pane in Outlook for high-risk mailboxes until patched (MITRE ATT&CK T1068, T1566).

### 3.2 Microsoft Defender "RedSun" zero-day PoC grants SYSTEM on fully patched Windows

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/new-microsoft-defender-redsun-zero-day-poc-grants-system-privileges/)

Researcher "Chaotic Eclipse" published a second Defender zero-day PoC — "RedSun" — just two weeks after releasing the "BlueHammer" PoC that became CVE-2026-33825. RedSun is a local privilege-escalation bug that remains unpatched after April Patch Tuesday. Exploitation leverages the Cloud Files API: Defender rewrites a file tagged as malicious back to its original location, and the PoC uses an oplock to win a volume shadow copy race plus a directory junction/reparse point to redirect the rewrite to `C:\Windows\system32\TieringEngineService.exe`. The Cloud Files infrastructure then runs the attacker-planted `TieringEngineService.exe` as SYSTEM. Will Dormann (Tharros) confirmed the exploit works against fully patched Windows 10, 11, and Server 2019+. The researcher states the PoC was published in protest at their MSRC disclosure experience, making weaponisation by commodity operators highly likely in the near term.

**Affected products / sectors:** Windows 10, Windows 11, Windows Server 2019+ with Microsoft Defender enabled — effectively all managed Windows estates.

#### Indicators of Compromise

```
Attack primitive: EICAR string (embedded/encrypted) + oplock + directory junction
Target path (writeback): C:\Windows\system32\TieringEngineService.exe
Threat actor / handle: Chaotic Eclipse (researcher)
Referenced related CVE: CVE-2026-33825 (BlueHammer)
```

> **SOC Action:** 🔴 Until Microsoft ships a fix, hunt for suspicious writes to `C:\Windows\system32\TieringEngineService.exe` and for reparse-point / directory-junction creation under user-writable paths paired with `CldFlt`/Cloud Files activity. In EDR, alert on any non-installer process creating `TieringEngineService.exe` or setting FILE_ATTRIBUTE_REPARSE_POINT under `C:\Users\*`. Raise AV/EDR sensitivity on EICAR-adjacent samples and validate that Defender telemetry is forwarded for retro-hunts (MITRE ATT&CK T1068, T1055 / reparse-point abuse T1564.009).

### 3.3 Critical protobuf.js RCE — GHSA-xq3m-2v4x-88gg (~50M weekly npm downloads)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-flaw-in-protobuf-library-enables-javascript-code-execution/)

Endor Labs published PoC details on 18 April for a critical RCE in protobuf.js, the JavaScript Protocol Buffers implementation downloaded nearly 50 million times per week via npm. The library builds JavaScript functions from protobuf schemas by concatenating strings and executing them through `Function()`, but does not validate schema-derived identifiers such as message names. A malicious schema therefore injects arbitrary code that executes whenever an application decodes messages defined by it, granting access to environment variables, credentials, databases, and internal systems — and enabling lateral movement. Affected versions are ≤ 8.0.0 and ≤ 7.5.4; patched in 8.0.1 (4 April) and 7.5.5 (15 April). No in-the-wild exploitation has been confirmed yet, but Endor Labs characterised exploitation as "straightforward." No formal CVE has been assigned; tracked as GHSA-xq3m-2v4x-88gg.

**Affected products / sectors:** Any Node.js service, Electron app or developer workstation loading `.proto` schemas from untrusted sources. Disproportionate exposure across cloud-native, fintech, real-time collaboration and microservices stacks.

#### Indicators of Compromise

```
Advisory: GHSA-xq3m-2v4x-88gg
Fixed versions: protobuf.js 8.0.1, 7.5.5
Attack primitive: attacker-supplied .proto schema → Function() injection
```

> **SOC Action:** 🟠 Inventory protobuf.js direct and transitive dependencies via SBOM or `npm ls protobufjs`; force upgrades to 8.0.1 / 7.5.5. Treat any schema loaded from third-party/field-supplied data as untrusted and prefer precompiled static schemas in production. Block outbound egress from CI/CD and Node runtimes to unapproved destinations until patched to contain credential-exfil scenarios (MITRE ATT&CK T1059.001, T1588).

### 3.4 Nginx UI CVE-2026-33032 — unauthenticated server takeover under active exploitation

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-nginx-ui-auth-bypass-flaw-now-actively-exploited-in-the-wild/)

Recorded Future flagged CVE-2026-33032 as actively exploited in this week's CVE Landscape report. The flaw — in Nginx UI with Model Context Protocol (MCP) support — leaves the `/mcp_message` endpoint unauthenticated, so any network attacker can invoke all 12 MCP tools (7 of them destructive), including restarting nginx and creating, modifying or deleting nginx configuration files. A single unauthenticated request chain (SSE connection → MCP session → `sessionID` replay) yields full server takeover. Pluto Security AI reported the issue on 14 March; NGINX fixed it in 2.3.4 on 15 March. Public PoC and technical details followed at the end of March. Shodan identifies approximately 2,600 exposed instances, concentrated in China, the United States, Indonesia, Germany and Hong Kong. Current secure version is 2.3.6.

**Affected products / sectors:** Nginx UI (MCP-enabled) 2.3.3 and earlier. Highest risk to cloud edge, SaaS reverse-proxy tiers, and developer lab environments.

#### Indicators of Compromise

```
CVE: CVE-2026-33032
Vulnerable endpoint: /mcp_message (unauthenticated)
Fixed version: Nginx UI ≥ 2.3.4 (current 2.3.6)
Exploitation state: active (per Recorded Future CVE Landscape)
```

> **SOC Action:** 🔴 Enumerate all Nginx UI deployments; upgrade to ≥ 2.3.6 immediately. Block inbound access to `/mcp_message` at the WAF / reverse proxy pending upgrade. Review nginx config change history, systemd/service restart logs and access logs for POSTs to `/mcp_message` and suspicious `sessionID` replay. Restrict Nginx UI to a management VLAN or require mTLS (MITRE ATT&CK T1190, T1078).

### 3.5 Marimo CVE-2026-39987 — NKAbuse variant deployed via Hugging Face Spaces

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-marimo-flaw-to-deploy-nkabuse-malware-from-hugging-face/)

Sysdig observed multiple exploitation campaigns against CVE-2026-39987 — a critical pre-auth RCE in Marimo reactive Python notebooks — starting within 10 hours of public disclosure. The primary campaign (from 12 April) uses a typosquatted Hugging Face Space named `vsccode-modetx` hosting an `install-linux.sh` dropper and a `kagent` binary that impersonates a legitimate Kubernetes AI agent. Post-exploitation, `curl` fetches the dropper from Hugging Face's legitimate HTTPS endpoint — bypassing reputation filters — then installs `kagent`, which Sysdig identifies as a previously undocumented variant of NKAbuse (first documented by Kaspersky, December 2023). The new variant references NKN Client Protocol, WebRTC/ICE/STUN for NAT traversal, proxy management, and structured command handling, and functions as a RAT executing shell commands. Persistence is established via systemd, cron or macOS LaunchAgent. Parallel operators have been observed: a Germany-based actor attempting 15 reverse-shell techniques and pivoting to PostgreSQL after scraping `.env` credentials, and a Hong Kong operator dumping all 16 Redis databases for session tokens. Users must upgrade to Marimo ≥ 0.23.0 or block external access to `/terminal/ws`.

**Affected products / sectors:** Marimo ≤ 0.22.x notebooks exposed to the internet — data science, ML engineering, and research environments; any service with `.env`-stored DB/Redis credentials.

#### Indicators of Compromise

```
CVE: CVE-2026-39987
Malware family: NKAbuse (new variant, aka kagent)
Hugging Face Space (defanged): hxxps[:]//huggingface[.]co/spaces/vsccode-modetx
Dropper: install-linux[.]sh
Binary: kagent
Network: NKN Client Protocol, WebRTC/ICE/STUN
Persistence: systemd / cron / macOS LaunchAgent
Vulnerable endpoint: /terminal/ws
```

> **SOC Action:** 🔴 Upgrade Marimo to ≥ 0.23.0; where not feasible, block `/terminal/ws` at the network edge. In EDR, alert on `curl` or `wget` to `huggingface.co/spaces/*` from non-interactive server processes and on new systemd units, cron entries or LaunchAgents named `kagent`. Hunt for outbound NKN/WebRTC traffic from non-browser workloads and rotate any `.env`-stored PostgreSQL and Redis credentials on affected hosts (MITRE ATT&CK T1190, T1105, T1053.003, T1071, T1562).

### 3.6 Cisco Webex and Identity Services Engine — four critical flaws, one requires customer action

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-says-critical-webex-services-flaw-requires-customer-action/)

Cisco disclosed four critical vulnerabilities on 16 April. **CVE-2026-20184** is an improper certificate validation flaw in the Webex Services SSO / Control Hub integration that let unauthenticated remote attackers impersonate any user by supplying a crafted token to a service endpoint. Although Cisco has fixed the server-side issue, SSO-integrated customers must upload a new SAML certificate for their IdP to Control Hub to avoid service interruption. Three additional critical bugs in Cisco Identity Services Engine (ISE) — **CVE-2026-20147, CVE-2026-20180 and CVE-2026-20186** — allow arbitrary command execution on the underlying OS with administrative credentials. Ten medium-severity ISE flaws (auth bypass, privilege escalation, DoS) were patched alongside. Cisco's PSIRT reports no in-the-wild exploitation at time of publication, but notes the advisories follow March's maximum-severity CVE-2026-20131 (Cisco FMC) which was exploited as a zero-day by the Interlock ransomware group since January 2026.

**Affected products / sectors:** Cisco Webex (cloud, SSO-integrated tenants), Cisco Identity Services Engine. High exposure: enterprise collaboration, federal, regulated industries.

#### Indicators of Compromise

```
CVEs: CVE-2026-20184 (Webex SSO), CVE-2026-20147, CVE-2026-20180, CVE-2026-20186 (ISE)
Attack primitive (Webex): crafted token → user impersonation via Control Hub endpoint
Customer action: upload new SAML cert for IdP in Control Hub
```

> **SOC Action:** 🟠 Webex SSO customers must upload the new SAML certificate for their IdP in Control Hub before the rotation deadline to retain access; review Control Hub sign-in audit logs for suspicious IdP-impersonated sessions during the exposure window. Patch ISE to the fixed releases and rotate any administrative credentials used against unpatched ISE instances (MITRE ATT&CK T1078, T1190, T1136).

### 3.7 Chromium PDFium / V8 / Turbofan critical batch

**Source:** Microsoft Security Response Center (Chromium advisories)

Microsoft issued critical advisories mirroring Google's Chromium fixes for five memory-safety bugs: **CVE-2026-6306** and **CVE-2026-6305** (heap buffer overflows in PDFium), **CVE-2026-6361** (additional PDFium heap buffer overflow), **CVE-2026-6301** (type confusion in Turbofan) and **CVE-2026-6363** (type confusion in V8). The AI correlation layer flagged Chromium exploitation as a cross-batch critical trend this week alongside active exploitation of Apache ActiveMQ. Google shipped 80 Edge/Chromium fixes this cycle that are not counted in Microsoft's 167.

**Affected products / sectors:** Microsoft Edge and all Chromium-based browsers; desktop and managed-fleet exposure universal.

#### Indicators of Compromise

```
CVEs: CVE-2026-6301, CVE-2026-6305, CVE-2026-6306, CVE-2026-6361, CVE-2026-6363
No public in-the-wild exploitation confirmed for this batch at time of writing.
```

> **SOC Action:** 🟠 Force browser update via policy (Edge Update, Chrome Update for Business) across all managed endpoints; verify fleet compliance within 72 hours. Enable Enhanced / Improved Security Mode for high-risk groups until patch deployment is confirmed (MITRE ATT&CK T1203, T1189).

### 3.8 Ransomware wave — Everest dominates; Qilin, The Gentlemen, Coinbase Cartel, Kairos, Blackwater, DragonForce active

**Source:** RansomLock leak-site telemetry via CognitiveCTI correlation batches 65–79 (13–20 April 2026)

The 20 April correlation batch (#79) identified Everest as the week's dominant ransomware operator, posting eight new victims across government, healthcare, manufacturing and IT services in North America, Europe and Asia (Umiles Group, Tokoparts, Straight Line Logistics, PT Brantas Abipraya, Nutrabio, Citizens Bank, Complete Aircraft Group, Frost Bank, Parque Eólico Toabré). Everest has shifted to a primarily data-extortion posture. Across the week the correlation engine surfaced additional trends: Qilin expanding into logistics and healthcare (Nanometrics, Henley; a years-old Qilin-linked attack continues to disrupt London healthcare); "The Gentlemen" (also tracked in lowercase as "the gentlemen") publishing seven new victims including Bmtp, Teleos Systems, Laboratório Santa Luzia, Jumbo Transport, Anderlues, Jean Cultural and The Marton Agency; Coinbase Cartel and Kairos pairing healthcare, technology and logistics targets; Blackwater hitting Grupo EBD and Minidoka Memorial Hospital; and Payouts King using QEMU VMs to bypass endpoint security. DragonForce and shadowbyt3$ remain among the top-five weekly threat actors by report count. All campaigns share T1566 phishing, T1078 valid accounts, and T1486 data-encrypted-for-impact; RansomLock and Tox1 are the most frequently cited malware families.

**Affected products / sectors:** Government, healthcare, manufacturing, IT services, logistics, financial services, education, legal services.

#### Indicators of Compromise

```
Top ransomware actors (report_count, last 30d):
  qilin (58), The Gentlemen (52), nightspire (38), TeamPCP (30),
  Coinbase Cartel (28), dragonforce (27), DragonForce (26),
  Qilin (25), the gentlemen (24), shadowbyt3$ (22), Akira (22),
  coinbase cartel (21), RansomLock (16), Hive (16), ShinyHunters (15),
  Everest — new in batch #79 with 8 fresh postings
Top ransomware families: RansomLock (45), dragonforce ransomware (26),
  Akira ransomware (18), Tox1 (12), Gentlemen ransomware (8),
  PLAY ransomware (8)
Primary TTPs: T1566 (Phishing, 184 mentions), T1068 (EoP, 84),
  T1078 (Valid Accounts, 54), T1486 (Data Encrypted for Impact, 34),
  T1071.001 (Web Protocols, 69)
```

> **SOC Action:** 🟠 Prioritise phishing-resistant MFA (FIDO2) and conditional-access blocks on legacy auth for users in exposed sectors. Hunt Everest/Qilin/Gentlemen indicators in EDR against shared TTPs (phishing, valid-accounts, application-layer C2). For healthcare and logistics verticals specifically, validate offline backup recoverability this week given compounded Everest + Qilin + Blackwater pressure. Evaluate Payouts King's QEMU-based evasion: alert on `qemu-system-*` or unexpected hypervisor binaries on endpoint fleet outside of approved virtualisation hosts (MITRE ATT&CK T1566, T1078, T1486, T1562.009).

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Ransomware-as-a-Service (RaaS) groups targeting multiple sectors globally | "ASTM Group By coinbase cartel" (batch #77, 19 Apr) |
| 🔴 CRITICAL | Vulnerabilities in technology infrastructure leading to potential exploitation | protobuf.js RCE (GHSA-xq3m-2v4x-88gg); "It Takes 2 Minutes to Hack the EU's New Age-Verification App" (batch #76, 18 Apr) |
| 🔴 CRITICAL | Chromium vulnerabilities being actively exploited across multiple sectors | CVE-2026-6304 use-after-free in Graphite; CISA flags Apache ActiveMQ flaw as actively exploited (batch #74, 17 Apr) |
| 🔴 CRITICAL | Exploitation of zero-day vulnerabilities in widely used software platforms | "Recently leaked Windows zero-days now exploited in attacks"; RedSun Defender zero-day PoC (batch #73, 17 Apr) |
| 🔴 CRITICAL | Exploitation of software supply chain vulnerabilities | Q1 vulnerability pulse; CVE-2026-39987 Marimo → NKAbuse via Hugging Face (batch #72, 16 Apr) |
| 🔴 CRITICAL | Targeting of critical infrastructure and government sectors with sophisticated malware | "New AgingFly malware used in attacks on Ukraine govt, hospitals"; McGraw-Hill 13.5M breached accounts (batch #71, 16 Apr) |
| 🔴 CRITICAL | Rise of AI-driven cyber threats and misuse of workflow automation platforms | "The n8n n8mare: How threat actors are misusing AI workflow automation"; Trust Wallet QR phishing crypto takeover (batch #70, 15 Apr) |
| 🔴 CRITICAL | Persistent ransomware activities by groups such as DragonForce | Curtis Design Group, McCOR, bela-pharm victim listings by DragonForce (batch #69, 15 Apr) |
| 🔴 CRITICAL | Ransomware groups leveraging zero-day vulnerabilities for high-impact attacks | "March 2026 CVE Landscape … Interlock Ransomware Group Exploits Cisco FMC Zero-Day" (batch #68, 14 Apr) |
| 🔴 CRITICAL | Vulnerabilities in critical infrastructure components are being actively exploited | CVE-2026-3184 util-linux hostname canonicalization bypass; wolfSSL forged certificate use (batch #67, 14 Apr) |
| 🟠 HIGH | Everest ransomware group consistently targeting multiple sectors with double-extortion tactics | Umiles Group, Tokoparts, Straight Line Logistics, PT Brantas Abipraya, Nutrabio, Citizens Bank, Complete Aircraft Group, Frost Bank (batch #79, 20 Apr) |
| 🟠 HIGH | RaaS groups like Qilin are expanding operations into logistics and healthcare | Nanometrics, Henley (batch #78, 19 Apr) |
| 🟠 HIGH | Increased ransomware activity with overlapping TTPs and actors — "The Gentlemen" cluster | Bmtp, Teleos Systems, Laboratório Santa Luzia, Jumbo Transport, Anderlues, Jean Cultural, The Marton Agency (batch #78, 19 Apr) |
| 🟠 HIGH | Increased exploitation of vulnerabilities in widely used software libraries and frameworks | CVE-2026-4786 (Python `webbrowser.open` command injection); CVE-2026-6100 Python decompressor UAF; CVE-2026-33056 tar-rs (batch #77, 19 Apr) |
| 🟠 HIGH | Targeted cyber campaigns against government and law enforcement agencies, particularly in Ukraine | "Ukraine confirms suspected APT28 campaign targeting prosecutors, anti-corruption agencies" (batch #74, 17 Apr) |
| 🟠 HIGH | Increased use of AI in cybercrime operations | New ATHR vishing platform with AI voice agents; Google expanding Gemini to fight malicious ads (batch #72, 16 Apr) |
| 🟠 HIGH | Ransomware actors using advanced evasion (QEMU VMs) | Payouts King QEMU bypass (batch #74, 17 Apr) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **qilin** (58 reports) — dominant RaaS operator; logistics and healthcare expansion this week
- **The Gentlemen** (52 reports) — fast-emerging ransomware cluster first seen 06 Apr 2026; seven new victims in batch #78
- **nightspire** (38 reports) — sustained data-extortion postings
- **TeamPCP** (30 reports) — steady multi-sector activity
- **Coinbase Cartel** (28 reports) — paired with Kairos in batch #76; healthcare, technology, logistics
- **DragonForce** (27 reports; additional 26 under alternate casing) — persistent RaaS presence; leveraging RansomLock
- **shadowbyt3$** (22 reports) — continued post-exposure from batch #67 reporting
- **Akira** (22 reports) — ransomware operations continuing
- **coinbase cartel** (21 reports) — alternate casing of same actor cluster
- **RansomLock** (16 reports as actor-label) — pipeline-assigned label for RansomLock-sourced victim posts
- **Hive** (16 reports) — resurfaced mentions
- **ShinyHunters** (15 reports) — data-leak / extortion activity

### Malware Families

- **RansomLock** (45 reports) — leak-site tracker source; ubiquitous across ransomware coverage
- **Ransomware** / **ransomware** (generic, 28+12) — aggregated family references
- **DragonForce ransomware** (26 + 9 under variant casing) — most mentioned named family
- **Akira ransomware** (18) — sustained campaigns
- **RaaS / raas** (15+7) — aggregated model references
- **Tox1 / Tox** (12+7) — leak-site-linked family
- **Gentlemen ransomware** (8) — new family concentrated in The Gentlemen campaign
- **PLAY ransomware / PLAY** (8+7) — continued mentions
- **Qilin** (6) — family-level references
- **NKAbuse** (mentioned in Priority Item 3.5) — new Marimo-delivered variant (`kagent`), not yet in top-entities aggregate

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 318 | [link](https://msrc.microsoft.com/update-guide/) | MSRC / Chromium mirror + April Patch Tuesday volume |
| RansomLock | 185 | — | Leak-site aggregator feeding ransomware victim posts (Telegram-adjacent; URL withheld per editorial rules) |
| BleepingComputer | 49 | [link](https://www.bleepingcomputer.com) | Primary analytic coverage of Microsoft Patch Tuesday, Cisco Webex, Nginx UI, Marimo, RedSun, protobuf.js |
| AlienVault | 34 | [link](https://otx.alienvault.com) | OTX pulses and open threat exchange data |
| Unknown | 16 | — | Unattributed feed entries pending source normalization |
| RecordedFutures | 14 | [link](https://www.recordedfuture.com) | CVE Landscape report flagged CVE-2026-33032 Nginx UI as actively exploited |
| Schneier | 12 | [link](https://www.schneier.com) | Policy and cryptography commentary |
| SANS | 11 | [link](https://isc.sans.edu) | ISC diaries including April Patch Tuesday |
| Wired Security | 7 | [link](https://www.wired.com/category/security/) | Investigative and policy reporting |
| Wiz | 6 | [link](https://www.wiz.io/blog) | Cloud security research |
| Sysdig | 6 | [link](https://sysdig.com/blog/) | Primary source for Marimo/NKAbuse Hugging Face campaign analysis |
| Cisco Talos | 5 | [link](https://blog.talosintelligence.com) | Threat research |
| Upwind | 5 | [link](https://www.upwind.io/blog) | Cloud runtime security |
| CISA | 5 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | ICS advisories (Horner Automation, AVEVA Pipeline Simulation) |
| ESET Threat Research | 2 | [link](https://www.welivesecurity.com) | Research commentary |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Deploy Microsoft April 2026 cumulative updates (Windows, Office, SharePoint) and Defender Antimalware Platform ≥ 4.18.26050.3011 fleet-wide this week. Treat CVE-2026-32201 (SharePoint spoofing) as actively exploited during retro-hunts. (Priority Item 3.1.)
- 🔴 **IMMEDIATE:** Patch Nginx UI to ≥ 2.3.6 and block `/mcp_message` at the edge until confirmed; CVE-2026-33032 is under active exploitation with ~2,600 exposed instances. (Priority Item 3.4.)
- 🔴 **IMMEDIATE:** Upgrade Marimo to ≥ 0.23.0 or block `/terminal/ws`; alert on `curl huggingface.co/spaces/*` from server workloads and rotate `.env`-stored DB/Redis credentials on Marimo hosts. (Priority Item 3.5.)
- 🔴 **IMMEDIATE:** Until Microsoft patches RedSun, hunt for writes to `C:\Windows\system32\TieringEngineService.exe` and reparse-point creation paired with Cloud Files API activity. (Priority Item 3.2.)
- 🟠 **SHORT-TERM:** Inventory and upgrade protobuf.js (target 8.0.1 / 7.5.5); treat external `.proto` schemas as untrusted input in CI/CD and production. (Priority Item 3.3.)
- 🟠 **SHORT-TERM:** Webex SSO customers must upload new SAML certificates for their IdP in Control Hub and patch ISE to address CVE-2026-20147/20180/20186. (Priority Item 3.6.)
- 🟠 **SHORT-TERM:** Force Chromium/Edge updates via policy and verify fleet compliance within 72 hours for CVE-2026-6301/6305/6306/6361/6363. (Priority Item 3.7.)
- 🟡 **AWARENESS:** Monitor Everest, Qilin, The Gentlemen, Coinbase Cartel, Kairos, Blackwater, DragonForce and Payouts King leak-site postings; healthcare and logistics verticals should rehearse offline backup recovery this week given compounded pressure. Alert on unexpected QEMU hypervisor binaries outside approved virtualisation hosts. (Priority Item 3.8.)
- 🟢 **STRATEGIC:** Reduce exposure to supply-chain RCE classes by mandating SBOMs, pinning npm dependencies, and preferring precompiled/static schemas for serialization libraries; assess AI-agent / MCP endpoints (Nginx UI, n8n, Marimo) across the estate as a new high-value attack surface class and add management-plane isolation to security architecture patterns. (Priority Items 3.3, 3.4, 3.5 and correlation trend on AI-workflow misuse.)

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 687 reports processed across 15 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
