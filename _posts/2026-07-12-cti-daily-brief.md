---
layout: post
title:  "CTI Daily Brief: 2026-07-12 - CISA warns of actively exploited Joomla RCE; UK/EU sanction Russia's FSB Center 16 over Poland grid attack"
date:   2026-07-13 20:15:00 +0000
description: "47 reports processed. CISA flags actively exploited RCE in Joomla iCagenda and Balbooa Forms extensions; UK, EU and nine allies formally attribute Poland's near-blackout attack to FSB Center 16 and issue a joint router-hygiene advisory; DragonForce, Anubis and Akira ransomware activity dominates; APT37 spear-phishing campaign deploys RokRAT."
category: daily
tags: [cti, daily-brief, dragonforce, anubis, apt37, fsb-center-16, joomla-rce]
classification: TLP:CLEAR
reporting_period: "2026-07-12"
generated: "2026-07-13"
draft: true
report_count: 47
severity: critical
sources:
  - BleepingComputer
  - RecordedFutures
  - CISA
  - AlienVault
  - SANS
  - RansomLook
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-12 (24h) | TLP:CLEAR | 2026-07-13 |

## 1. Executive Summary

The pipeline ingested 47 reports across 13 sources in the last 24 hours, with one critical and 31 high-severity items. Two themes dominate: state-sponsored activity attributed to Russia's FSB Center 16 — culminating in the first joint UK/EU cyber-sanctions package tied to the near-blackout attack on Poland's energy grid and a co-sealed router-hygiene advisory from CISA, NSA, FBI and nine allied agencies — and a continuing high-volume ransomware wave led by DragonForce (six victim posts), Anubis (four), Akira, Space Bears and Qilin. CISA's `AA26-194A` names Berserk Bear, Energetic Bear, Dragonfly, Crouching Yeti, Ghost Blizzard and Static Tundra as tracking clusters overlapping FSB Center 16. The one critical item is CISA's warning of active exploitation of RCE flaws in the iCagenda and Balbooa Forms extensions for Joomla via arbitrary file upload; there is no CISA KEV addition in the collected reports. Also of note: WP-SHELLSTORM exposed its own toolkit for 22 days revealing 1.4M targeted WordPress sites and 27 weaponised CVEs; APT37 ran a spear-phishing campaign delivering RokRAT via cloud storage; and SANS observed distributed scanning for exposed MCP servers and AI-assistant credential files.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | CISA warning on actively exploited Joomla iCagenda / Balbooa Forms RCE |
| 🟠 **HIGH** | 31 | Ransomware victim listings (DragonForce, Anubis, Akira, Space Bears, Qilin, Safepay, Nightspire, Gunra, Anubis, PayoutsKing, PEAR, Syndicate); CISA/allies Russian router advisory; UK/EU FSB sanctions; CrashStealer macOS infostealer; WP-SHELLSTORM opendir exposure; APT37 RokRAT; nginx 1.30.0 RCE chain; MCP-server scanning |
| 🟡 **MEDIUM** | 6 | Secondary correlations and follow-on analysis |
| 🟢 **LOW** | 1 | Low-impact peripheral report |
| 🔵 **INFO** | 8 | Contextual and threat-actor profile items |

## 3. Priority Intelligence Items

### 3.1 CISA warns of actively exploited RCE in Joomla iCagenda and Balbooa Forms extensions

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-of-actively-exploited-rce-flaws-in-joomla-extensions/)

CISA reports active exploitation of vulnerabilities in the iCagenda events extension and Balbooa Forms extension for Joomla. Attackers achieve remote code execution by abusing arbitrary file upload functionality in the affected components, mapping to MITRE ATT&CK `T1190 - Exploit Public-Facing Application` and post-exploitation `T1071 - Application Layer Protocol` for C2. This report correlates with the WP-SHELLSTORM operation (Section 3.4), which has been weaponising CMS extension flaws at internet scale — the two together indicate a broad, ongoing campaign against loosely maintained WordPress and Joomla plugin ecosystems.

> **SOC Action:** Immediately inventory public-facing Joomla instances and audit for the iCagenda and Balbooa Forms extensions. Disable both until vendor-confirmed patched builds are deployed. Hunt web-server logs for anomalous POST requests to plugin upload endpoints followed by execution of newly written PHP files in the web root; block outbound connections from the web tier to arbitrary internet destinations; add a WAF rule for uploads of files with `.php`, `.phtml`, `.phar` extensions or double-extension bypass patterns to plugin URIs.

### 3.2 UK, EU and allies attribute Poland grid attack to FSB Center 16; joint router-hygiene advisory issued

**Sources:** [CISA AA26-194A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a), [The Record (Recorded Future)](https://therecord.media/russia-blamed-for-poland-grid-cyberattack-in-joint-uk-eu-sanctions-package), [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-and-allies-share-defense-tips-against-russian-hackers-targeting-critical-infrastructure/)

The UK and EU jointly attributed the December 2025 attack that came "very close" to a Polish energy-grid blackout to Russia's FSB Center 16, the FSB's signals intelligence arm. Initial cybersecurity-industry attribution to Sandworm was disputed by CERT Polska, whose infrastructure analysis matched an FSB-linked cluster. The sanctions package targets more than 30 individuals and entities, including operators behind the Lumma Stealer credential-theft malware and figures tied to the pro-Kremlin Rybar blog. In parallel, CISA, NSA, FBI, DC3 and agencies from Australia, Canada, New Zealand, the UK, Czechia, Denmark, Estonia, Finland, France, Italy, Poland and Sweden released joint advisory `AA26-194A` on FSB Center 16 targeting of poorly configured routers across Communications, Defense Industrial Base, Energy and Finance sectors. The advisory names tracked clusters Berserk Bear, Energetic Bear, Crouching Yeti, Dragonfly, Ghost Blizzard and Static Tundra as commonly overlapping with FSB Center 16 activity.

> **SOC Action:** Enumerate all internet-facing routers, VPN concentrators and edge network devices; confirm each is on a vendor-supported firmware track with the latest patches applied. Disable Telnet, unauthenticated SNMP and unnecessary management protocols; enforce out-of-band or ACL-restricted management access only. Rotate credentials on any edge device that has not been rotated in the past 12 months, and hunt for the TTPs (`T1190`, `T1078 - Valid Accounts`, `T1210 - Exploitation of Remote Services`) enumerated in `AA26-194A`. If your organisation touches any of the named sectors, treat this as an active-threat baseline exercise, not a compliance checkbox.

### 3.3 APT37 "Operation Capsule Vault" delivers RokRAT via spear-phishing and cloud C2

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a5414fab18f9d7456d7eda8)

A spear-phishing campaign attributed to APT37 targeted individuals in research, policy and academic fields with emails posing as materials from an actual academic conference. The chain: a cloud-hosted ISO delivers a PIF executable disguised as a PDF; a multi-stage loader using the `EMBED_PAYLOAD_v2` structure extracts and sequentially executes embedded documents and payloads in memory; shellcode is injected into `explorer.exe` to deploy a RokRAT variant. C2 traffic is proxied through legitimate cloud storage services — pCloud, Dropbox and Yandex Cloud — mapping to `T1102 - Web Service` and `T1071.001 - Application Layer Protocol: Web Protocols`. Additional techniques observed include `T1566.001 - Spearphishing Attachment`, `T1055 - Process Injection`, `T1027 - Obfuscated Files or Information` and `T1140 - Deobfuscate/Decode Files or Information`. Attribution is based on infrastructure overlap, code similarities and operational patterns.

#### Indicators of Compromise
```
C2 IPs:
  160.238.37[.]100
  160.238.37[.]95
  5.180.208[.]57
  5.180.208[.]60
  89.147.101[.]197
  89.187.161[.]220
```

> **SOC Action:** Hunt EDR telemetry for shellcode injection into `explorer.exe` and for `.pif` files executing from user Downloads or mounted `.iso` volumes. Block or alert on outbound API traffic from workstations to `pcloud.com`, `dropbox.com` and `yandex.cloud` when originating from non-standard user contexts (system accounts, unattended service accounts). Alert email gateways on inbound messages carrying links to cloud-hosted ISO files. Add the six APT37 C2 IPs to blocklists and retro-hunt 90 days of proxy/firewall logs.

### 3.4 WP-SHELLSTORM opendir exposes 1.4M targeted WordPress sites, 27 weaponised CVEs

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a54b716f22fd928cabf4eb8)

A financially motivated cybercrime group tracked as WP-SHELLSTORM inadvertently exposed its full toolkit, logs and target list by leaving a Python `SimpleHTTPServer` open for 22 days. The intended operation targeted over 1.4 million domains using 27 weaponised CVEs and had deployed more than 5,700 active webshells across WordPress and Joomla platforms. A parallel campaign hit Apache Nacos, XXL-Job and Spring Boot infrastructure, exfiltrating 613 configuration files from 11 victims across nine organisations in May 2026 — compromising cloud credentials, database passwords and payment system keys. The actor is described as Chinese-linked and used obfuscated webshells (BestShell, Godzilla, VShell) and SNOWLIGHT implants. Key ATT&CK techniques: `T1190 - Exploit Public-Facing Application`, `T1505.003 - Web Shell`, `T1552.001 - Credentials in Files`, `T1552.004 - Private Keys`, `T1078.004 - Cloud Accounts`, `T1071.001 - Web Protocols`.

#### Indicators of Compromise
```
C2 IPs:
  113.196.56[.]150
  113.196.59[.]51
  137.175.93[.]126
  43.108.17[.]80
Hostname: xs.xxooonline.eu[.]cc
SHA-256:  84f7e396a48913851a10cc78c5cc22a25634564abd0694465236d2f365e2bdee
```

> **SOC Action:** Search web-server file systems for unexpected `.php`, `.jsp`, `.aspx` files under CMS plugin, theme and upload directories with modification dates in the last 90 days; hash-match against the SHA-256 above. Query egress logs for connections to the four listed IPs and to `xs.xxooonline.eu[.]cc`. For Apache Nacos, XXL-Job and Spring Boot Actuator, confirm authentication is enabled and `/actuator/env`, `/actuator/heapdump` are not internet-exposed. Rotate any cloud, database or payment-key credential that has been stored in a plaintext configuration file on an internet-facing host.

### 3.5 CrashStealer macOS infostealer masquerades as Apple crash-reporting tool

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-crashstealer-malware-poses-as-apple-crash-reporting-tool/)

A new macOS infostealer named CrashStealer impersonates Apple's legitimate crash-reporting binary to blend into normal system activity. On execution it targets stored credentials, the login keychain, and cryptocurrency wallet data. Reported techniques include `T1566 - Phishing` (initial delivery lure) and `T1003 - OS Credential Dumping`. This continues a broader 2026 pattern of macOS infostealers targeting developer and Web3 user populations.

> **SOC Action:** For macOS fleets, alert on any process named similar to Apple crash-reporting binaries (`CrashReporter`, `crash_report`, etc.) executing from user-writable paths (`~/Downloads`, `~/Library/Application Support`, `/tmp`) rather than `/System/Library/CoreServices/`. Query EDR for keychain access by unsigned or ad-hoc-signed binaries. Notify crypto-holding staff to treat any prompt to "run a crash-reporting update" as suspicious and to report before executing.

### 3.6 SANS: distributed scanning for exposed MCP servers and AI-assistant credentials

**Source:** [SANS ISC Diary 33150](https://isc.sans.edu/diary/rss/33150)

SANS ISC reports two weeks of Apache/ModSecurity logs from a single small web host showing a distributed scan of approximately 200 requests explicitly targeting Model Context Protocol servers (via full JSON-RPC 2.0 `initialize` handshakes with `protocolVersion: "2025-03-26"`), locally exposed LLM endpoints, and AI-assistant configuration/credential files written by tools such as Claude and Cursor. The MCP handshake category came from 49 distinct source IPs, indicating a broad rather than single-researcher scan. An exposed unauthenticated MCP server functions as a machine-readable menu of tools and data sources an AI agent can invoke — a high-value target for the scanner.

> **SOC Action:** Inventory all MCP servers exposed to the internet and confirm authentication is enforced on every one; where possible, place them behind identity-aware proxies or private networking only. Add WAF rules or IDS signatures for JSON-RPC 2.0 `initialize` calls to unexpected URIs (e.g. `POST /mcp` on hosts not intended to serve MCP). Audit developer laptops and web-served project directories for accidental deployment of `.claude/`, `.cursor/`, `.env`, `.mcp.json` and similar files; add them to `.gitignore` templates and enforce with pre-commit hooks.

### 3.7 Ransomware surge: DragonForce, Anubis, Akira, Space Bears dominate victim listings

**Source:** RansomLook (aggregated across 22 leak-site posts)

RansomLook posted 22 ransomware-related victim entries in the 24-hour window. Six were attributed to DragonForce (Al-Saidi Factory, STEP Oiltools, Northeast Rescue Systems, Nicholson y Cano Abogados, degeremcia.com, Trans World Trading — sectors: retail, government, logistics, manufacturing). Four to Anubis (Casper Orthopedics, Surtifamiliar, Community Advocates, Boston Orthotics — healthcare and community services). Two to Akira (Transworld Signs, Ironmark). Two to Space Bears (Turbosoft, Techpol-System — IT solutions and industrial power). Additional single-victim posts from Qilin (TitanTV, Inc.), Safepay, Nightspire, PayoutsKing, PEAR, Gunra and Syndicate (NAYAX, an Israeli fintech). The pipeline's correlation engine grouped these into high-confidence actor clusters (DragonForce 0.90, Anubis 0.95, Akira 0.90). Common initial-access vectors reported across these families remain unpatched VPN services, compromised RDP credentials and phishing (`T1566`, `T1078`, `T1133 - External Remote Services`).

> **SOC Action:** Confirm patch level on all internet-facing VPN concentrators (Ivanti, Fortinet, Citrix, Palo Alto GlobalProtect) is current, and that MFA is enforced on every remote-access account. Hunt for `.akira` file extensions and known Anubis ransom-note filenames. For any organisation in retail, healthcare, legal or industrial manufacturing, review backup restore procedures against a DragonForce-style double-extortion timeline (data exfiltration prior to encryption) — the pipeline's correlation for DragonForce and Akira both list corporate networks and ESXi as primary targets, so validate VMware ESXi patch level and SSH exposure specifically.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased ransomware activities targeting critical infrastructure sectors globally | US sanctions on 1VPNS for aiding ransomware groups; UK/EU sanctions on FSB Center 16 for Poland grid attack |
| 🟠 **HIGH** | Sophisticated phishing campaigns used to facilitate malware deployment | Qilin (TitanTV, Inc.); CrashStealer macOS; APT37 Operation Capsule Vault |
| 🟠 **HIGH** | Exploitation of infrastructure vulnerabilities in web services | nginx 1.30.0 Rift + PoolSlip RCE chain; CISA Joomla iCagenda / Balbooa Forms |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with overlapping actors and tactics | DragonForce (Al-Saidi Factory, STEP Oiltools); Anubis (Casper Orthopedics, Surtifamiliar, Community Advocates) |
| 🟠 **HIGH** | Ransomware activity targeting multiple sectors with a focus on hospitality and technology | M3rx cluster (eclective.ie, foreconinc.com, wrtworld.com); D1r cluster (Bosch, ARM, Synopsys) |
| 🟡 **MEDIUM** | Systematic scanning for exposed protocols and credentials indicating a focus on application-layer vulnerabilities | SANS ISC MCP/AI-assistant credential scan diary |
| 🟡 **MEDIUM** | Increased use of sophisticated TTPs such as Ingress Tool Transfer across different malware campaigns | RedHook Android via Wireless ADB; Synopsys By D1r |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **The Gentlemen** (109 reports) — highest-volume actor in the pipeline over the last 30 days; primarily leak-site aggregation.
- **Qilin** (75 reports) — active RaaS group; new TitanTV, Inc. victim post today.
- **Deadlock** (66 reports) — sustained leak-site activity.
- **Lockbit5** (36 reports) — continued presence despite historical takedowns.
- **Akira** (24 reports) — new posts today: Transworld Signs, Ironmark.
- **DragonForce** (23 reports) — six new victim posts today; RaaS with cartel-like affiliate model.
- **Anubis** (17 reports) — four new victim posts today across healthcare and community services.
- **ShinyHunters** (17 reports) — ongoing extortion activity.
- **Nova** (17 reports) — sustained activity.
- **Stormous** (15 reports) — active but no new posts today.

### Malware Families
- **RansomLook** (152 reports) — aggregation tag rather than a standalone family; reflects leak-site coverage volume.
- **Tox1** (74 reports) — Tox-protocol C2 tracker.
- **Other1** (46 reports) — pipeline-generic tag.
- **Tox** (45 reports) — Tox messaging protocol used by multiple ransomware groups for negotiation.
- **Anubis ransomware** (14 reports) / **Anubis banking trojan** (12 reports) — dual-purpose kit.
- **Akira ransomware** (12 reports) — Windows and Linux/ESXi variants.
- **Deadlock** (12 reports).
- **The Gentlemen Ransomware** (12 reports).
- **Qilin** (10 reports).

Notable single-day additions from today's collection: **CrashStealer** (new macOS infostealer), **RokRAT** (APT37 payload in Operation Capsule Vault), **SNOWLIGHT / Godzilla / VShell / BestShell** (WP-SHELLSTORM toolkit), **Lumma Stealer** (named in UK/EU sanctions package).

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|--------:|-----|-------|
| RansomLook | 22 | [link](https://www.ransomlook.io) | Ransomware leak-site aggregation; primary source of today's victim posts across 10+ groups |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Broke the CISA Joomla RCE story; also covered CrashStealer and the US/allies Russian router advisory |
| RecordedFutures | 3 | [link](https://therecord.media) | UK/EU FSB sanctions and 1VPNS designation |
| AlienVault | 3 | [link](https://otx.alienvault.com) | APT37 Operation Capsule Vault; WP-SHELLSTORM opendir; AiTM phishing operator exposure |
| SANS | 2 | [link](https://isc.sans.edu) | ISC diary on distributed MCP-server / AI-assistant credential scanning |
| Unknown | 2 | — | Includes one Telegram-sourced nginx 1.30.0 RCE exploit chain (channel name redacted, TLP:AMBER+STRICT) |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | Contextual coverage |
| CISA | 1 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a) | Joint advisory AA26-194A on FSB Center 16 router targeting |
| Wiz | 1 | [link](https://www.wiz.io) | Cloud-security analysis |
| Upwind | 1 | [link](https://www.upwind.io) | Runtime cloud analysis |
| Schneier | 1 | [link](https://www.schneier.com) | Contextual commentary |
| Microsoft | 1 | [link](https://www.microsoft.com/security/blog) | Microsoft Security coverage |
| Wired Security | 1 | [link](https://www.wired.com/category/security) | Contextual coverage |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Inventory public-facing Joomla instances for the iCagenda events extension and the Balbooa Forms extension; disable or block external access to both until vendor-patched builds are deployed. Add WAF rules blocking file uploads with executable extensions to plugin URIs (ties to Section 3.1).
- 🔴 **IMMEDIATE:** If your organisation operates in Communications, Defense Industrial Base, Energy, or Finance sectors — or ships products into them — execute CISA advisory `AA26-194A` as an active-threat baseline. Enumerate edge routers, confirm firmware currency, disable Telnet/unauth-SNMP, restrict management planes to out-of-band or ACL-scoped networks, rotate device credentials (ties to Section 3.2).
- 🟠 **SHORT-TERM:** Add the six APT37 C2 IPs and the four WP-SHELLSTORM C2 IPs from Sections 3.3 and 3.4 to firewall/proxy blocklists; retro-hunt 90 days of egress logs. Search macOS fleets for CrashStealer-style masquerading processes running from user-writable paths (Section 3.5).
- 🟠 **SHORT-TERM:** For every internet-facing MCP server and AI-assistant deployment, verify authentication is enforced and configuration files (`.claude/`, `.cursor/`, `.mcp.json`, `.env`) are not served publicly; add WAF/IDS rules on JSON-RPC 2.0 `initialize` calls to unexpected URIs (Section 3.6).
- 🟡 **AWARENESS:** Brief SOC and IR staff that DragonForce, Anubis, Akira and Space Bears are actively adding victims and that the pipeline's correlation engine is treating these as clustered campaigns. Validate VMware ESXi patch level and SSH exposure specifically — Akira's Linux variant continues to target ESXi (Section 3.7).
- 🟢 **STRATEGIC:** Treat the WP-SHELLSTORM and CISA Joomla items together as a signal that the CMS-extension ecosystem remains a primary bulk-compromise target; longer-term, reduce plugin surface area on any internet-facing CMS deployment and shift high-risk workflows (payments, cloud-credential storage) off shared web hosts.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 47 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
