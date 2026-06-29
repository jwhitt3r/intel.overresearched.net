---
layout: post
title:  "CTI Weekly Brief: 2026-06-22 to 2026-06-28 - Cisco SD-WAN Zero-Day, ShinyHunters PeopleSoft Campaign, and Ransomware Surge Across Sectors"
date:   2026-06-29 09:00:00 +0000
description: "366 reports processed across 11 correlation batches. Multiple CISA KEV additions and emergency BOD 26-04 directives; confirmed in-the-wild exploitation of Cisco Catalyst SD-WAN (CVE-2026-20245), Ubiquiti UniFi, Lantronix EDS5000, Cisco UCM, and PTC Windchill. ShinyHunters continued exploiting PeopleSoft zero-day after patch release. China-nexus Operation DragonReturn targeted Indian tax infrastructure. Sustained ransomware activity from Qilin, Stormous, Inc Ransom, Play, Redact, DragonForce, and The Gentlemen, alongside a 14.2M-record ISP breach and a 2.7M-account Sysco extortion."
category: weekly
tags: [cti, weekly-brief, shinyhunters, qilin, stormous, cve-2026-20245, cve-2024-40766]
classification: TLP:CLEAR
reporting_period_start: "2026-06-22"
reporting_period_end: "2026-06-28"
generated: "2026-06-29"
draft: false
severity: critical
report_count: 366
sources:
  - BleepingComputer
  - Microsoft
  - CISA
  - AlienVault
  - SANS
  - Schneier
  - Wired Security
  - Intel471
  - Sysdig
  - HaveIBeenPwned
  - RansomLook
  - RecordedFutures
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-22 to 2026-06-28 (7d) | TLP:CLEAR | 2026-06-29 |

## 1. Executive Summary

The pipeline processed 366 reports across 11 correlation batches during the week of 22–28 June 2026, with 15 rated critical and 252 high. The week was dominated by confirmed in-the-wild exploitation of network edge infrastructure: CISA issued Binding Operational Directive 26-04 enforcement against Cisco Unified Communications Manager (CVE-2026-20230), PTC Windchill/FlexPLM (CVE-2026-12569), Cisco Catalyst SD-WAN Manager (CVE-2026-20245), Ubiquiti UniFi OS (CVE-2026-34908/34909/34910), and Lantronix EDS5000 (CVE-2025-67038). Mandiant published the first detailed analysis of the Cisco SD-WAN zero-day intrusion chain, in which threat actors used rogue peering connections plus a malicious CSV upload to escalate to root on service-provider infrastructure.

ShinyHunters continued exploiting the PeopleSoft Enterprise PeopleTools zero-day (CVE-2026-35273) after Oracle's 10 June patch, with Intel 471 reporting 110 compromised U.S. education organisations and victims in the European Council. SANS reported sustained Akira and Fog ransomware exploitation of SonicWall CVE-2024-40766, with encryption observed in under four hours from initial access. Seqrite attributed Operation DragonReturn, a China-nexus DcRAT phishing campaign, to spear-phishing lures targeting India's Ministry of Finance tax filing season. Ransomware leak-site activity dominated the high-severity volume, with The Gentlemen (84 reports), Qilin (69), and Stormous (16) leading; a 14.2 million-record KDDI ISP breach and the ShinyHunters-attributed 2.7 million-account Sysco extortion campaign added to the data-exposure tally. Three CISA ICS advisories — Daktronics, EVoke charging stations, and the pydicom medical library — carried unauthenticated root-level impact.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 15 | Cisco SD-WAN (CVE-2026-20245), Cisco UCM (CVE-2026-20230), PTC Windchill, Ubiquiti UniFi, ShinyHunters PeopleSoft, SonicWall, Langflow, Operation DragonReturn, three CISA ICS advisories, Linux kernel DirtyClone (CVE-2026-43503), OpenBSD PPP (CVE-2026-55706) |
| 🟠 **HIGH** | 252 | Chromium use-after-free batch (CVE-2026-13021 through 13038); ransomware leak posts from Qilin, Stormous, Inc Ransom, Play, Redact, DragonForce, The Gentlemen, Krybit, 3AM, Safepay; Sysco and KDDI breaches; AI coding-agent supply-chain attack |
| 🟡 **MEDIUM** | 36 | Telegram proxy distribution channels; Gamaredon tunneling research; LastPass user data exposure |
| 🟢 **LOW** | 6 | Misc. leak-site updates and low-impact configuration disclosures |
| 🔵 **INFO** | 57 | Background actor profiles, threat-intel reposts |

## 3. Priority Intelligence Items

### 3.1 Cisco Catalyst SD-WAN Manager Zero-Day Exploited for Root Access (CVE-2026-20245)

**Source:** [Google Cloud / Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager), [BleepingComputer](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)

Mandiant disclosed a year-long intrusion at a service provider in which an unidentified threat actor exploited CVE-2026-20245 — a command-injection flaw in the Cisco Catalyst SD-WAN Manager (vManage), Controller (vSmart), and Validator (vBond) CLI — to escalate from a compromised admin account to root. Initial access began in late 2025 via rogue SD-WAN peering connections, likely abusing previously undisclosed authentication-bypass flaws CVE-2026-20127 and CVE-2026-20182. The actor uploaded a malicious CSV (`evil_tenant.csv`) through the tenant-upload feature, used the resulting root execution to back up `/etc/passwd` and `/etc/shadow`, created an account named `troot`, and executed a validation script confirming all anti-forensic cleanup had been completed. The activity was added to CISA KEV and is bound by BOD 26-04.

**Affected products:** Cisco Catalyst SD-WAN Manager, Controller, Validator.

#### Indicators of Compromise

```
IP: 23.245.7[.]178
IP: 45.32.38[.]160
IP: 76.92.245[.]217
IP: 126.51.108[.]152
IP: 153.186.231[.]233
IP: 167.179.79[.]189
IP: 207.190.37[.]94
IP: 209.137.225[.]101
SHA-256: b82936f37648518425c7d3cf9e09eaffa41d7cdb3840f6a40287e3a108880f7b
Rogue Account: troot
Payload Filename: evil_tenant.csv
```

MITRE ATT&CK: T1190, T1078, T1059, T1068, T1136, T1098, T1070.004, T1070.006, T1485, T1133.

> **SOC Action:** Upgrade SD-WAN Manager/Controller/Validator to the fixed releases listed in the Cisco advisory immediately. Audit for non-default local accounts on all SD-WAN appliances (especially `troot`-style names) and review `/var/log/secure` for `su` invocations from `vmanage-admin`. Block egress to the listed IPs and hunt for inbound peering from non-allowlisted ASNs. Restore `/etc/passwd` and `/etc/shadow` from known-good backups if compromise is suspected.

### 3.2 CISA BOD 26-04: Cisco Unified Comms Manager and PTC Windchill RCEs Added to KEV

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-sets-urgent-deadline-to-fix-cisco-flaw-exploited-in-attacks/)

CISA gave federal agencies until Sunday 28 June to remediate two new KEV additions. CVE-2026-20230 is an unauthenticated server-side request forgery in Cisco Unified Communications Manager Server; the threat-detection firm Defused observed exploitation that wrote arbitrary text files to affected endpoints. CVE-2026-12569 is a deserialization-of-untrusted-data RCE in PTC Windchill and FlexPLM affecting all versions up to 11.0 and multiple branches of 11.1, 11.2, 12.0, 12.1, and 13.0; PTC disclosed the issue on 18 June and active exploitation is confirmed. Threat-actor attribution is not yet public.

**Affected products:** Cisco Unified Communications Manager (all unpatched), PTC Windchill, PTC FlexPLM.

> **SOC Action:** Patch Cisco UCM to the fixed release from the 3 June 2026 advisory. For PTC, apply vendor patches across all Windchill 11.x–13.x branches; if patching is delayed, isolate Windchill/FlexPLM front-ends from internet exposure and proxy via authenticated reverse proxies. Search web-server access logs for anomalous HTTP requests with crafted Host or X-Forwarded-* headers against the UCM management interface.

### 3.3 Ubiquiti UniFi OS Chain and Lantronix EDS5000 Added to KEV

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-of-max-severity-ubiquiti-flaws-exploited-in-attacks/)

CISA added four vulnerabilities to its KEV catalogue covering Ubiquiti UniFi OS (CVE-2026-34908 access-control bypass, CVE-2026-34909 directory traversal, CVE-2026-34910 command injection) and Lantronix EDS5000 (CVE-2025-67038 root-level command injection in the HTTP RPC failed-auth logging module). Bishop Fox previously demonstrated that the three Ubiquiti flaws chain into unauthenticated remote code execution with elevated privileges and has released a free detection script. CISA marked the ransomware-use flag as "Unknown" but enforced three-day BOD 26-04 remediation.

**Affected products:** Ubiquiti UniFi OS, Lantronix EDS5000 (firmware 2.1.0.0R3).

MITRE ATT&CK: T1190, T1068, T1059.001, T1090.002.

> **SOC Action:** Upgrade all UniFi OS appliances to the May 2026 patches and EDS5000 to firmware 2.2.0.0R1. Run the Bishop Fox detection script (publicly available on GitHub) against your UniFi estate. Block UniFi web management interfaces from internet exposure; restrict the Lantronix HTTP RPC endpoint to a management VLAN.

### 3.4 ShinyHunters PeopleSoft Zero-Day Continues Post-Patch (CVE-2026-35273)

**Source:** [Intel 471](https://www.intel471.com/blog/shinyhunters-0-day-attacks-after-patching-find-out-if-you-were-breached)

ShinyHunters exploited an unauthenticated RCE zero-day in Oracle PeopleSoft Enterprise PeopleTools beginning in late May, persisting through and beyond Oracle's 10 June 2026 patch release. The cluster claimed 110 U.S. education organisations along with government and commercial victims including the European Council. Tradecraft included disguising MeshCentral remote-administration agents as Microsoft Azure services (`meshagent32-azure-ops.exe`, `meshagent64-azure-ops.exe`) for C2, living-off-the-land techniques to blend into cloud traffic, and ransomware deployment where exfiltration could not be completed. Open directories exposed on 142.11.200[.]186–190 included staged binaries and `.bash_history` files documenting attacker activity.

**Affected products:** Oracle PeopleSoft Enterprise PeopleTools.

#### Indicators of Compromise

```
IP: 142.11.200[.]186
IP: 142.11.200[.]187
IP: 142.11.200[.]188
IP: 142.11.200[.]189
IP: 142.11.200[.]190
File: meshagent32-azure-ops.exe (SHA-256: c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f)
File: meshagent64-azure-ops.exe
```

MITRE ATT&CK: T1190, T1059.005, T1071.001, T1036, T1570.002.

> **SOC Action:** Confirm PeopleSoft Enterprise PeopleTools is patched to the 10 June 2026 baseline and restrict external access to all PeopleSoft endpoints. Hunt EDR data for `meshagent*.exe` filenames originating from non-Microsoft signed binaries, MeshCentral C2 over HTTPS to non-Azure-attested IP ranges, and the listed 142.11.200[.]0/29 block. Replay 60 days of web logs for the PeopleTools application path looking for the IOC IPs and the documented exploit signatures.

### 3.5 SonicWall CVE-2024-40766 — Akira and Fog Sustain Sub-4-Hour Encryption Times

**Source:** [SANS ISC](https://isc.sans.edu/diary/rss/33094)

SANS revisited the still-exploited CVE-2024-40766, an improper-access-control flaw in SonicOS management and SSLVPN on Gen 5/6/7 firewalls (CVSS 9.3). Akira (≈75%) and Fog (≈25%) continued targeting Gen 7 devices in July–August 2025 and into 2026, with Arctic Wolf documenting encryption inside four hours (one case at 55 minutes) from initial access. Many compromised organisations had migrated Gen 6→Gen 7 without resetting local user passwords. Compounding the issue, SonicWall confirmed in September 2025 that all MySonicWall configuration-backup files were accessed by attackers; ReliaQuest later reported in-the-wild abuse of CVE-2024-12802 (MFA bypass) on Gen 6 devices where the firmware patch alone is insufficient without six manual LDAP reconfiguration steps.

**Affected products:** SonicWall Gen 5/6/7 firewalls (SonicOS ≤5.9.2.14-12o, ≤6.5.4.14-109n, ≤7.0.1-5035).

MITRE ATT&CK: T1078, T1110.

> **SOC Action:** Reset all local SonicWall user passwords (including service accounts) on any device migrated from Gen 6 to Gen 7. Assume MySonicWall configuration backups are compromised; rotate any credentials embedded in those backups. For Gen 6 fleets, complete the six manual LDAP reconfiguration steps for the CVE-2024-12802 mitigation — do not rely on firmware version alone. Hunt for SSLVPN authentications from low-reputation ASNs and rapid lateral-movement patterns (file-share enumeration within minutes of VPN sign-in).

### 3.6 Operation DragonReturn — China-Nexus DcRAT Campaign Targets Indian Tax Infrastructure

**Source:** [AlienVault / Seqrite](https://www.seqrite.com/blog/operation-dragonreturn-china-nexus-cyber-espionage-campaign-targeting-govt-of-india-mof-tax-infrastructure-via-multi-stage-dcrat-deployment/)

Seqrite Lab attributed an active spear-phishing campaign — first observed 18 May, persisting as of 17 June — to a China-nexus cluster with operational overlap with Void Arachne. The campaign impersonates the Indian Ministry of Finance Income Tax Department, exploiting the AY2026-27 ITR filing season with bilingual Hindi-English lures referencing real Income Tax Act sections (271(1)(c)). A latest-payload variant achieved a 0/66 VirusTotal detection rate through active rotation, fileless execution, and steganography in a multi-stage DcRAT deployment. Attribution is hedged at "China-nexus" — preserve that uncertainty.

**Affected sectors:** Indian government, corporate finance teams, tax professionals, government contractors.

#### Indicators of Compromise

```
Domain: govtop[.]one
Domain: 1kkkkddd[.]com
Domain: ikkkkddd[.]com
Domain: jiayingjing[.]com
Domain: kkxqbh[.]top
Domain: simaqz[.]com
URL: hxxp[://]govtop[.]one/incometax
IP: 117.44.201[.]119
IP: 118.107.0[.]197
IP: 204.194.48[.]250
IP: 223.26.63[.]40
IP: 27.50.54[.]191
SHA-256: 19ca5fe04ca45a18c5bad9658ff73a8f39fe20ced78f690595f1b4c5a90af324
SHA-256: 2f2f8f92af86fb962c30c4c1c9d673f9d94886373d0fcf78f8d105c051ffc643
SHA-256: a8614dfad5fd2a79302a7c4829a0fed6f3a0a46b11beb28f89531cdfa83d32b3
SHA-256: c6fc06db6a1318152c09200352b40c8fa794f1089988835c1df92174347be8ec
SHA-256: fc17d5b4d64cb61a5aa8fb6bbe1e94885f129b2bf8ee91bca1ccca2b537f6616
```

MITRE ATT&CK: T1566.001, T1566.002, T1204.002, T1547.001, T1543.003, T1055, T1027, T1497, T1071.001, T1095, T1573, T1041.

> **SOC Action:** Block the listed domains and IPs at the perimeter and proxy. Hunt mail gateways for inbound messages spoofing Income Tax Department of India branding with bilingual Hindi-English text, the reference number pattern `No. TAX/PEN/2026-142`, or links to `govtop[.]one`. Query EDR for child processes spawned by Outlook → rundll32 (T1218.011) and for the listed SHA-256 hashes.

### 3.7 Langflow CVE-2026-55255 — IDOR-Driven API Key Theft

**Source:** [Sysdig](https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited)

Sysdig Threat Research Team observed the first active in-the-wild exploitation of CVE-2026-55255 on 25 June, a CVSS 9.9 cross-tenant IDOR in Langflow's `POST /api/v1/responses` endpoint. The flaw — fixed in PR #12832 / Langflow 1.9.1 — lets an authenticated caller execute any other user's flow by passing its UUID, since the database lookup omits a `user_id` ownership check. Operators were observed enumerating `/api/v1/flows/` to harvest UUIDs and replaying them with the prompt injection input `"leak api keys"` against the IDOR endpoint. Sysdig's finding is notable as a counter-example to CVSS-led prioritisation: the same operator put far more effort into CVE-2026-33017 (CVSS 9.3 RCE) because it required less skill, despite being lower-scored.

**Affected products:** Langflow <1.9.1.

MITRE ATT&CK: T1048, T1068.

> **SOC Action:** Upgrade Langflow to 1.9.1 immediately. For environments that cannot patch, restrict `/api/v1/responses` to authenticated tenant-isolated callers via reverse-proxy rules and disable UUID-based flow lookups. Rotate any API keys embedded in Langflow flows and scan flow definitions for hard-coded secrets.

### 3.8 CISA ICS Advisories: Daktronics, EVoke EV Chargers, and pydicom

**Source:** [CISA ICSA-26-176-04](https://www.cisa.gov/news-events/ics-advisories/icsa-26-176-04), [CISA ICSA-26-176-02](https://www.cisa.gov/news-events/ics-advisories/icsa-26-176-02), [CISA ICSMA-26-176-01](https://www.cisa.gov/news-events/ics-advisories/icsma-26-176-01)

Three CISA advisories on 25 June carried unauthenticated root or arbitrary-file-write impact. Daktronics Controller Firmware (VFC-DMP-5000, DMP-5000, DMP-8000) contained CVE-2026-28701 path traversal, CVE-2026-33560 unrestricted file upload, and hard-coded credentials — chainable to unauthenticated root (CVSS v4 9.3). EVoke Systems Charging Station Management System exposed unauthenticated WebSocket endpoints permitting charger impersonation and session-handling weaknesses (CVSS v3 9.4) — affects all EVoke CSMS versions. The pydicom `pynetdicom` library (versions ≥1.0.0 < 3.0.4) used attacker-supplied DICOM dataset values directly in `os.path.join()`, allowing unauthenticated arbitrary file writes against healthcare imaging infrastructure (CVE-2026-56445, CVSS 9.1); the maintainer has not responded to CISA coordination requests.

**Affected sectors:** Commercial facilities, energy, transport, healthcare and public health.

> **SOC Action:** Update Daktronics firmware to 8.117.0.x, 9.43.0.x, or 10.34.0.x branches and rotate default device credentials. For EVoke CSMS, allow-list charger IDs at the CSMS inventory layer; verify each charger negotiates OCPP Security Profile 2 or 3 where firmware supports it. For pydicom — pin or fork `pynetdicom <3.0.4` is not available; isolate DICOM C-STORE listeners behind network ACLs that only permit known PACS endpoints, and validate dataset elements at an ingress proxy until the upstream project responds.

### 3.9 Linux Kernel "DirtyClone" Local Privilege Escalation (CVE-2026-43503)

**Source:** Telegram (channel name redacted)

A critical local privilege escalation and page-cache write primitive in the Linux kernel was disclosed via TLP:AMBER+STRICT channels as CVE-2026-43503 ("DirtyClone"). The disclosure asserts unauthorised access and modification capabilities at a privileged level; specific exploitation technique details were not included in the source material. Because the source is Telegram, attribution is hedged and the channel link is intentionally redacted.

> **SOC Action:** Track upstream kernel release notes and distribution backports for CVE-2026-43503 and apply once vendor patches are confirmed. Enforce least-privilege execution on multi-tenant Linux hosts and tighten kernel keyring/page-cache observability via auditd rules covering `mmap`/`madvise` anomalies on shared file-backed pages. Defer trust in any third-party PoC pending official advisory.

### 3.10 AI Coding Agents Tricked into Running Malware from Clean GitHub Repos

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/clean-github-repo-tricks-ai-coding-agents-into-running-malware/)

Researchers documented a supply-chain attack against AI coding agents that uses an outwardly clean GitHub repository as the payload carrier. When the agent encounters a contrived setup error during initialisation (`python3 -m axiom init`), it executes a shell script that fetches second-stage configuration from an attacker-controlled DNS TXT record and opens a reverse shell running with the developer's privileges. The technique sidesteps repo-content scanning by triggering only at runtime.

> **SOC Action:** Restrict AI coding agents to non-privileged service accounts inside containerised sandboxes with egress restrictions. Block outbound DNS queries to TXT records on unfamiliar domains from developer workstations and CI runners. Forbid agent execution of arbitrary `init`-style commands without explicit human confirmation; review agent-tool allow-lists.

### 3.11 KDDI ISP Breach and Sysco Extortion — Mass Credential Exposure

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/), [HaveIBeenPwned](https://haveibeenpwned.com/Breach/Sysco)

KDDI Corporation disclosed unauthorised access to a shared email system supporting six ISPs, exposing up to 14.2 million email logins through a third-party software vulnerability. Encryption status of credentials was not fully specified. Separately, HaveIBeenPwned ingested 2,691,852 unique addresses from the Sysco breach attributed to a ShinyHunters "pay or leak" extortion campaign — connecting the breach to the same actor cluster behind the PeopleSoft zero-day activity covered in 3.4.

> **SOC Action:** Treat KDDI-region email addresses as exposed; force password resets for matching accounts in federated identity systems and prompt for MFA enrolment. Cross-reference the Sysco corporate domain against any third-party vendor access lists and rotate any shared B2B credentials. Monitor for credential-stuffing waves against external auth surfaces in the 14 days following disclosure.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Exploitation of zero-day vulnerabilities affecting critical infrastructure sectors | ShinyHunters PeopleSoft zero-day; Mandiant Cisco SD-WAN CVE-2026-20245 root access |
| 🔴 CRITICAL | Exploitation of critical vulnerabilities in widely used software and systems | DirtyClone Linux kernel (CVE-2026-43503); Langflow CVE-2026-55255 IDOR |
| 🔴 CRITICAL | Sophisticated cyber-espionage campaigns targeting government infrastructure | Operation DragonReturn (India MoF); CL-STA-1062 Southeast Asian governments |
| 🔴 CRITICAL | Exploitation of vulnerabilities in industrial control systems | Yokogawa FAST/TOOLS and CI Server; Horner Automation Cscape |
| 🔴 CRITICAL | Ransomware groups targeting multiple sectors with sophisticated techniques | Redact (Hologic, FCCI Insurance); Play (J&J Gaming, Kuhnline) |
| 🔴 CRITICAL | Aurora ransomware group continues to target aerospace and civil engineering sectors | Aerospace & Advanced Composites GmbH; NationsBuilders Insurance Services |
| 🟠 HIGH | Increased activity of ransomware groups targeting multiple sectors globally | Qilin (Axionlog, NASCO, 1-800-dentist, Transcore); Stormous (impulso-store, higuchi-inc) |
| 🟠 HIGH | Increased targeting of critical infrastructure sectors with ransomware and phishing campaigns | Ford Mexico (Krybit); Thyssenkrupp Marine Systems/Atlas Elektronik (The Gentlemen) |
| 🟠 HIGH | Rising incidents of data breaches involving large-scale account compromises | Sysco — 2.7M accounts; KDDI — 14.2M email logins |
| 🟠 HIGH | Increased targeting of technology sectors with sophisticated exploitation techniques | Chromium CVE-2026-13025 DevTools; Cisco UCM CVE-2026-20230 |
| 🟠 HIGH | Inc Ransom expanding targets across multiple sectors | callhorton.com; johndufourlaw.com; theswansonlawgroup.com |
| 🟠 HIGH | Increased ransomware targeting healthcare and critical manufacturing sectors | Clearview Eye Centre (Interlock); Daktronics Controller Firmware |
| 🟠 HIGH | Targeting of critical infrastructure by threat actors focused on government and energy | CL-STA-1062 Southeast Asian Governments and Critical Infrastructure; Gamaredon 2025 alliances |
| 🟡 MEDIUM | Telegram channels distributing proxy services potentially linked to malicious activities | Multiple Turbotelproxy posts via TLP:AMBER+STRICT feeds |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (84 reports) — Maritime defence and legal services targeting; observed against Thyssenkrupp Marine Systems / Atlas Elektronik and Ayres Carr & Sullivan, P.C. Tox/captcha-protected leak parser; ~33% 30-day uptime.
- **Qilin** (69 reports) — RaaS continuing despite degraded onion infrastructure; new victims include Axionlog, NASCO, 1-800-dentist, Transcore, Aptora.
- **Lockbit5** (39 reports) — Sustained leak-site activity through mid-June.
- **Akira** (30 reports) — Primary CVE-2024-40766 SonicWall SSLVPN exploiter, ≈75% of observed intrusions.
- **DragonForce** (22 reports) — Cartel-style RaaS with affiliate-customisable payloads and shared leak infrastructure.
- **ShinyHunters** (20 + 18 case-variant) — PeopleSoft zero-day campaign plus the Sysco extortion leak.
- **Stormous** (16 reports) — Coordinated multi-domain data dumps against maglificioliliana.com and affiliated retail/food brands.
- **Inc Ransom** (16 reports) — Expanding into legal-services targeting (callhorton.com, johndufourlaw.com, theswansonlawgroup.com).
- **Nova** (21 reports), **Nightspire** (18), **Icarus** (14), **WorldLeaks** (10) — Continuing high-volume leak-site posters.
- **Deadlock** (55 reports), **RansomLook** (9 — listing entity, not an actor) — Volume-driven pipeline noise.

### Malware Families

- **Akira ransomware / Akira Ransomware** (15 + 9 reports) — Active in SonicWall SSLVPN intrusions.
- **Lockbit5** (14 reports) and **LockBit** (8) — Continued affiliate activity.
- **Qilin** ransomware (10 reports) — Ties to Lee International, ISOPLUS, and June 28–29 fresh victims.
- **Nova** (10 reports), **RALord** (10), **Deadlock** (10) — Mid-tier RaaS chatter.
- **DcRAT** — Multi-stage payload deployed in Operation DragonReturn (covered in 3.6).
- **Miasma** (9 reports), **Nightspire** (8), **3AM ransomware** (8) — 3AM employs email bombing + vishing into Microsoft Quick Assist for VM-based backdoor deployment (Rust binary, `.threeamtime` extension).
- **MeshCentral (abused)** — ShinyHunters used MeshCentral disguised as Azure services for C2.
- Note: "RansomLook", "Tox", "Tox1", "Other1" in the entity pipeline represent infrastructure/listing artefacts rather than discrete families; they have been excluded from operational interpretation.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLook | 149 | [link](https://www.ransomlook.io/) | Leak-site aggregation feeding ransomware victim counts |
| BleepingComputer | 40 | [link](https://www.bleepingcomputer.com/news/security/cisa-warns-of-max-severity-ubiquiti-flaws-exploited-in-attacks/) | Primary coverage of CISA KEV directives, Cisco SD-WAN, KDDI |
| Unknown | 33 | — | Mostly TLP:AMBER+STRICT vulnerability disclosures via Telegram (links redacted per policy) |
| AlienVault | 30 | [link](https://otx.alienvault.com/) | Operation DragonReturn, Cisco SD-WAN Mandiant reposts, CL-STA-1062 |
| Microsoft | 25 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-13025) | Chromium use-after-free batch (CVE-2026-13021 through 13038) |
| CISA | 18 | [link](https://www.cisa.gov/news-events/ics-advisories/icsa-26-176-04) | ICS advisories (Daktronics, EVoke, pydicom) and KEV BOD enforcement |
| RecordedFutures | 15 | [link](https://www.recordedfuture.com/) | Threat-actor profile updates |
| SANS | 9 | [link](https://isc.sans.edu/diary/rss/33094) | CVE-2024-40766 SonicWall deep-dive |
| Schneier | 8 | [link](https://www.schneier.com/) | Commentary; not in critical path |
| Upwind | 6 | [link](https://www.upwind.io/) | Cloud-native threat research |
| Wiz | 5 | [link](https://www.wiz.io/) | Cloud security advisories |
| Wired Security | 5 | [link](https://www.wired.com/category/security/) | LastPass user data exposure |
| Unit42 | 4 | [link](https://unit42.paloaltonetworks.com/) | CL-STA-1062 reporting |
| ESET Threat Research | 3 | [link](https://www.welivesecurity.com/) | Gamaredon 2025 retrospective |
| HaveIBeenPwned | 3 | [link](https://haveibeenpwned.com/) | Sysco breach ingest |
| Intel471 | 1 | [link](https://www.intel471.com/blog/shinyhunters-0-day-attacks-after-patching-find-out-if-you-were-breached) | ShinyHunters PeopleSoft post-patch hunting guidance |
| Sysdig | 1 | [link](https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited) | Langflow CVE-2026-55255 first-observed exploitation |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Cisco Catalyst SD-WAN Manager/Controller/Validator (CVE-2026-20245), Cisco Unified Communications Manager (CVE-2026-20230), PTC Windchill/FlexPLM (CVE-2026-12569), Ubiquiti UniFi OS (CVE-2026-34908/34909/34910), and Lantronix EDS5000 (CVE-2025-67038). BOD 26-04 deadlines have already passed for federal agencies.
- 🔴 **IMMEDIATE:** Confirm Oracle PeopleSoft Enterprise PeopleTools is patched and run a 60-day historical hunt for the ShinyHunters IOCs in 3.4. Treat education and government PeopleSoft deployments as priority hunt targets.
- 🟠 **SHORT-TERM:** For any SonicWall fleet that migrated Gen 6 → Gen 7 since 2024, reset all local user passwords and complete the six manual LDAP reconfiguration steps for CVE-2024-12802. Rotate all credentials embedded in MySonicWall configuration backups.
- 🟠 **SHORT-TERM:** Upgrade Langflow to 1.9.1 and rotate API keys referenced in any flow definitions. Audit AI-coding-agent execution sandboxes and restrict outbound DNS to vetted resolvers to mitigate the GitHub-bait technique in 3.10.
- 🟠 **SHORT-TERM:** Block the Operation DragonReturn domains and IPs in 3.6, especially for India-based subsidiaries and tax/finance workflows. Add the China-nexus DcRAT indicators to mail-gateway and EDR allow-lists.
- 🟡 **AWARENESS:** Distribute the Sysco and KDDI breach indicators to identity, fraud, and helpdesk teams; expect credential-stuffing volume to rise over the next two weeks. Review B2B vendor accounts for exposure.
- 🟡 **AWARENESS:** For ICS operators, prioritise Daktronics firmware updates, EVoke charger-ID allow-listing, and pydicom `pynetdicom` C-STORE network isolation while upstream remediation is pending.
- 🟢 **STRATEGIC:** Decouple CVSS from prioritisation as illustrated by the Langflow case in 3.7 — instrument exploitation telemetry (CISA KEV inclusion, EPSS, Sysdig/GreyNoise observed activity) into the patch-decision workflow, and treat lower-CVSS RCEs in widely deployed AI/ML stacks with equal urgency to higher-CVSS IDORs.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 366 reports processed across 11 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
