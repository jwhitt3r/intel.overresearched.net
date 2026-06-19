---
layout: post
title:  "CTI Daily Brief: 2026-06-18 - CISA KEV adds Splunk CVE-2026-20253 (active exploitation); FortiBleed credentials leak; Aurora data breaches"
date:   2026-06-19 20:10:00 +0000
description: "Two critical items dominate: CISA orders federal patching of an actively exploited Splunk Enterprise flaw (CVE-2026-20253) by Sunday, and the Aurora group leaks proprietary code and credentials from Hagerman & Company and ALS Global. CISA also warns of FortiBleed (~74k Fortinet credentials exposed); Operation Endgame 4.0 disrupts the Evil Corp-linked SocGholish botnet; Gentlemen RaaS expands EDR-killer arsenal; Gamaredon weaponizes WinRAR CVE-2025-8088 against Ukraine; new OXLOADER + CASTLESTEALER malvertising chain identified."
category: daily
tags: [cti, daily-brief, qilin, aurora, shinyhunters, gamaredon, the-gentlemen, oxloader, castlestealer, socgholish, cve-2026-20253, cve-2025-8088, fortibleed]
classification: TLP:CLEAR
reporting_period: "2026-06-18"
generated: "2026-06-19"
draft: true
severity: critical
report_count: 40
sources:
  - BleepingComputer
  - RansomLock
  - AlienVault
  - HaveIBeenPwned
  - RecordedFutures
  - SANS
  - Elastic Security Labs
  - Microsoft
  - Schneier
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-18 (24h) | TLP:CLEAR | 2026-06-19 |

## 1. Executive Summary

Forty reports were processed across the last 24 hours from eleven sources, with the threat landscape dominated by two critical items: CISA's addition of Splunk Enterprise CVE-2026-20253 to the KEV catalogue with a Sunday patch deadline for federal agencies after confirmed in-the-wild exploitation, and Aurora group double-extortion leaks of Hagerman & Company and ALS Global exposing source code, plaintext Oracle SYS credentials, defense-related engineering vault databases and 1,018 passport scans. CISA separately urged Fortinet customers to act on "FortiBleed" — approximately 74,000 SSL VPN/firewall credentials linked to a Russian-speaking actor running 1.16 billion credential-stuffing attempts against 320,000+ FortiGate targets. International law enforcement disrupted the Evil Corp-linked SocGholish botnet (Operation Endgame 4.0), taking down 100+ servers and disinfecting ~15,000 WordPress sites; HIBP ingested 153,527 associated email accounts. Ransomware activity remains heavy with Qilin, The Gentlemen (now wielding a multi-EDR-killer framework), Nightspire, Aurora and ShinyHunters (Ralph Lauren breach, 139,903 accounts) all posting. Two new evasion-focused malware families surfaced: OXLOADER → CASTLESTEALER via Google Ads, and the FlutterShell macOS backdoor abusing the Flutter framework. Gamaredon continues weaponizing WinRAR CVE-2025-8088 against Ukrainian military targets.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | CISA KEV Splunk CVE-2026-20253 (active exploitation); Aurora dual-victim data breach (Hagerman, ALS Global) |
| 🟠 **HIGH** | 25 | FortiBleed; Operation Endgame 4.0 (SocGholish/Evil Corp); Gentlemen EDR-killers; Gamaredon WinRAR; OXLOADER/CASTLESTEALER; FlutterShell macOS; Ralph Lauren (ShinyHunters); ongoing Qilin, Nightspire, Aurora, Anubis, Cloak postings |
| 🟡 **MEDIUM** | 6 | Texas Parks & Wildlife 3M licence breach; AI-agent identity risk; SANS IPv4-mapped IPv6 phishing; AI-generated harassment indictment |
| 🟢 **LOW** | 1 | Microsoft June 2026 Recycle Bin prompt regression |
| 🔵 **INFO** | 6 | CVE-2026-42903 (Kerberos DoS); MFA-bypass webinar; UK ICO commissioner resignation; Anthropic Fable export classification |

## 3. Priority Intelligence Items

### 3.1 CISA: Splunk Enterprise CVE-2026-20253 Actively Exploited — Federal Patch Deadline Sunday

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-splunk-enterprise-flaw-actively-exploited-patch-by-sunday/)

CISA added CVE-2026-20253 to its actively exploited list and issued a directive under BOD 26-04 ordering FCEB agencies to patch Splunk Enterprise by Sunday, 22 June 2026. The flaw affects Splunk Enterprise 10.2.0–10.2.3 and 10.0.0–10.0.6, and stems from a missing authentication control on the PostgreSQL sidecar service endpoint, permitting unauthenticated network-reachable users to create or truncate arbitrary files. WatchTowr published a technical writeup and PoC on 12 June; Splunk's PSIRT confirmed limited exploitation in the wild on 18 June. Shadowserver tracks 1,400+ internet-exposed Splunk instances (952 in North America, 223 in Europe). Splunk's documented mitigation is to disable the PostgreSQL sidecar service, which will break Edge Processor, OpAmp and SPL2 data pipelines.

**Affected products:** Splunk Enterprise 10.0.0–10.0.6, 10.2.0–10.2.3.

> **SOC Action:** Patch to a fixed Splunk Enterprise release immediately (FCEB deadline 22 June). Where patching is blocked, disable the PostgreSQL sidecar endpoint and validate Edge Processor / OpAmp / SPL2 pipeline impact. Hunt EDR/host telemetry for unexpected file creation or truncation events under Splunk service accounts; ingest Shadowserver Splunk exposure lists into asset inventory and cross-check internet-reachable instances.

---

### 3.2 Aurora Group Leaks Hagerman & Company and ALS Global — Source Code, Oracle SYS Credentials, 1,018 Passports

**Source:** [RansomLook (Aurora)](https://www.ransomlook.io//group/aurora)

The Aurora extortion group posted two high-impact victims overnight. **Hagerman & Company** — an Autodesk Platinum Partner serving 250+ enterprise customers in manufacturing, energy, defence, healthcare and education — had complete proprietary source code for 15+ commercial products (including the HNC Licensing System) exposed, 8+ plaintext .udl database credential files including an Oracle SYS DBA account (`Hagerman@1!`) reused across systems, engineering vault databases for 14+ critical-infrastructure entities (NYPA's seven power plants including Niagara Falls, Kinder Morgan's Elba Island LNG terminal, HydroOne, Phillips 66, Chevron, eight petroleum refineries), NASA IT security requirements, Lockheed Martin and Boeing-SVS configurations, JPL configurations, 1.6 GB of Azure DevOps transaction logs, and third-party DB credentials for Michigan State, Cal State Long Beach and Beth Israel Deaconess. **ALS Global** (ASX:ALQ, AUD 3.19B revenue, 65+ countries) lost ~400–500 employee home directories, the company's 1Password emergency-recovery kit PDF, 291 plaintext password files, 1,018 passport/ID scans, 601 banking-detail files, 1,986 salary/payroll files, 453 medical/drug-test/injury records (GDPR Art. 9), 57 PST archives, 7,327 client laboratory results under NDA, 20 GB of proprietary analytical methods (PFAS, dioxin, glyphosate LC-MS/GC-MS), and 7.2 GB of internal research reports.

**Affected sectors:** Manufacturing, energy, defence, healthcare, education (Hagerman); testing/inspection/certification, critical infrastructure (ALS Global).

> **SOC Action:** For any organisation in Hagerman's downstream customer list, treat the HNC Licensing System and reused Oracle SYS credential `Hagerman@1!` as compromised — force-reset and audit any system that may share or trust those credentials. ALS clients and partners holding shared credentials, vault data or 1Password recovery material from ALS should rotate immediately and assume insider-style access from leaked PSTs. Critical-infrastructure operators named in the engineering vault dump (NYPA, Kinder Morgan, HydroOne, Phillips 66, Chevron, NASA, Lockheed Martin, Boeing-SVS, JPL) should engage their Aurora-victim-exposure workflow and review network segmentation around any AutoCAD/Inventor design environments touched by Hagerman engineers.

---

### 3.3 CISA "FortiBleed" Advisory — ~74,000 Fortinet SSL VPN Credentials Exposed

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-warns-fortinet-users-to-secure-devices-after-fortibleed-leak/)

CISA issued a public advisory after researcher Volodymyr "Bob" Diachenko discovered an exposed server containing valid Fortinet VPN credentials (usernames, email addresses, plaintext passwords) for 73,932 firewall URLs across 21,632 unique domains and 194 countries. Affected organisations include Samsung, Mercedes-Benz, Foxconn, Chevron, Comcast, AT&T, Toyota, and many government and critical-infrastructure operators across telecoms, healthcare, financial services and manufacturing. Top-affected geographies are India, the United States, Taiwan, Mexico, Turkey, Thailand, Colombia, Malaysia, Chile and the UAE. Hudson Rock independently confirmed the dataset and operates a free FortiBleed lookup tool. Diachenko attributes the operation to a Russian-speaking threat group conducting approximately 1.16 billion credential-stuffing attempts against 320,000+ FortiGate targets to intercept SSL VPN authentication hashes; the source of the underlying configuration files is unknown. ATT&CK: **T1078 — Valid Accounts**, **T1566 — Phishing**.

> **SOC Action:** Per CISA: terminate all SSL VPN and administrative sessions on FortiGate appliances, reset every VPN and admin password, enforce phishing-resistant MFA on remote access, and review FortiGate logs for unauthorised access, anomalous VPN session origins and lateral movement following first authentication. Store admin credentials using PBKDF2, remove management interfaces from the public internet, and audit for unauthorised local accounts. Cross-check organisation domains against Hudson Rock's FortiBleed lookup before assuming "not affected".

---

### 3.4 Operation Endgame 4.0 — International Takedown of SocGholish/Evil Corp Infrastructure

**Source:** [The Record (Recorded Future)](https://therecord.media/socgholish-botnet-disrupted), [Have I Been Pwned](https://haveibeenpwned.com/Breach/OperationEndgame4)

Dutch, Canadian, US and German law enforcement, coordinated through Europol and Eurojust, dismantled the SocGholish (FakeUpdates) botnet linked to the Russia-based Evil Corp group. Operations seized domain names, shut down 100+ servers and remediated ~15,000 compromised WordPress sites. The FBI Cyber Division confirms SocGholish has historically served as the initial-access foothold for **DoppelPaymer, WastedLocker, Hades, LockBit and RansomHub**, and was originally tied to Evil Corp's Dridex banking malware (US-sanctioned 2019). Authorities provided HIBP with 153,527 impacted email addresses and 500,000+ previously unseen passwords from the operation. The action follows multiple prior Endgame phases against Dropper-as-a-Service infrastructure.

> **SOC Action:** Hunt for SocGholish/FakeUpdates indicators in proxy/DNS logs over the past 90 days — focus on `*.js` injections from compromised legitimate sites prompting fake browser/Chrome update overlays, and on traffic to disrupted C2 domains (request the latest seizure-list IOC pack from your ISAC/FBI liaison). Treat any host that historically called out to SocGholish C2s as compromised pre-takedown; perform credential resets and review for downstream LockBit/RansomHub follow-on stages. Force users whose emails appear in the HIBP Operation Endgame 4 dataset to rotate passwords on any account where credentials were reused.

---

### 3.5 The Gentlemen RaaS — GentleKiller Plus External EDR-Killer Arsenal (BYOVD)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/gentlemen-ransomware-uses-multiple-edr-killers-to-disable-defenses/)

ESET researchers documented the Gentlemen RaaS gang's evolving EDR-killer toolkit. The primary tool, **GentleKiller**, has at least eight variants impersonating Kaspersky, Valorant, Javelin and WatchDog. Each variant ships a different vulnerable driver (BYOVD) for kernel-level privilege escalation, but variants share strings, obfuscation patterns and process-killing logic — a modular framework designed to swap drivers as new vulnerable signatures are discovered. GentleKiller targets 400+ processes from approximately 48 security vendors including Microsoft, CrowdStrike, SentinelOne, Palo Alto, Sophos, Trend Micro, ESET, Bitdefender, McAfee/Trellix and Kaspersky. Binaries are protected with Enigma and Themida and signed with stolen (now-invalid) digital certificates. The group also leverages external tools: **HexKiller** (formerly Warlock), **ThrottleBlood** (linked to MesudaLocker and DragonForce), **HavocKiller**, and **OxideHarvest** (Rust-based credential stealer). ESET notes Gentlemen affiliates select targets partially based on FortiGate configuration — a notable overlap with the FortiBleed dataset (see 3.3). ATT&CK: **T1562.001 — Disable or Modify Tools**, **T1068 — Exploitation for Privilege Escalation**.

> **SOC Action:** Enable Microsoft's vulnerable-driver block list and equivalent kernel-driver allowlisting on all endpoints; alert on driver loads matching the published GentleKiller driver hash list. Monitor for execution of binaries signed with revoked certificates and for unsigned drivers attempting to load into kernel space. Cross-reference any FortiGate appliance that appears in FortiBleed (3.3) with internal segmentation — Gentlemen affiliates appear to use Fortinet configuration data to prioritise victims. Hunt for OxideHarvest-style Rust-built credential dumping (LSASS reads from non-standard binaries) in EDR.

---

### 3.6 Gamaredon Weaponizes WinRAR CVE-2025-8088 Against Ukraine

**Source:** [Nextron Research via AlienVault](https://x.com/nextronresearch/status/2067508038542545203)

Nextron Research documented an ongoing Gamaredon campaign active since February 2026 (most recent samples June 2026) targeting Ukrainian victims. Lures are Ukrainian military and conscription-themed documents (e.g., "Відомість про самовільне залишення військової частини", "Повідомлення") packaged as `.rar` archives whose contents appear to the victim as PDFs. The archive abuses CVE-2025-8088, a WinRAR path-traversal flaw, via a malicious NTFS alternate data stream containing a `..\..\..\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` traversal sequence — extracting the RAR silently writes a `.lnk` into the user's Startup folder with no further user action. On next logon a hidden PowerShell stager executes with anti-analysis checks (debugger detection, disk-space checks, sandbox-evasion sleeps) before reaching out for the next stage. ATT&CK: **T1566.001**, **T1204.002**, **T1547.001**, **T1059.001**, **T1027**, **T1497**, **T1564.004**.

#### Indicators of Compromise

```
SHA256: 0a9bc91e7ea2c3931f662eea37c00c7c26c8996b65f6f7afe6cce8f6114f94b6
SHA256: 39dd1bd3bccc314d8933e5c41ed2ab084e4e20af569f77b7cf09abc5855b9483
SHA256: 1ebbdf3671cd5ca25a8a8e7ca2f6e46dd22c631e01bfcc5c909ae2fd680bf458
SHA256: f668bd551859007cf2cc2a62bf0bf5414870a04e9782590c9bf85c849ddb308b
SHA256: 1c170b7470d507378ddb78e9d66305f1184e965baaf2d27ededb23a318a58953
SHA256: bf338d88f60c0d352cd0d1b5e4bc6a1d9f1ac8fe1df48516ec0042cafda821e9
SHA256: 507b2fcdae058cebbd550965b90c44e878d7a2463058c846eeb68f0dc1b48eda
SHA256: f9d2907d6b1de3078a0f111cc98764a92baf5ebd06cc8ab02637a65eff3b7f3a
SHA256: cb65f5873c72d707371ec56fb8ba501a5c7f5940e9c5a2d28c9b379ce216900c
SHA256: 2add9429d2822ae0c01c08bbd66c3a110ef2e9c3a00cded1477657e9024e391e
CVE: CVE-2025-8088 (WinRAR path traversal)
```

> **SOC Action:** Confirm WinRAR is patched to a fixed version on every endpoint (CVE-2025-8088); block legacy WinRAR installs through software inventory. Add a detection for `.lnk` files appearing in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` immediately after a `.rar` extraction process. Hunt EDR for PowerShell launches with `-w hidden` parameters spawning from Explorer or WinRAR child processes. Prioritise these hunts for any Ukraine-aligned partner organisations.

---

### 3.7 OXLOADER → CASTLESTEALER Malvertising Chain (Russian-Speaking Actor)

**Source:** [Elastic Security Labs via AlienVault](https://www.elastic.co/security-labs/oxloader-malware-loader-infostealer)

Elastic Security Labs published the first public analysis of **OXLOADER**, a previously undocumented Windows loader delivering the **CASTLESTEALER** infostealer. Distribution is via malicious Google Ads impersonating Node.js LTS, redirecting through `node-js[.]prentiva99[.]info` (now offline) and `app[.]miloyannopoulos[.]com` to a Storj-hosted batch script that displays a fake installer UI and downloads the loader. The loader employs `.reloc` section abuse for shellcode staging, five anti-VM/language checks (including CIS-region and Russian-language exclusions pointing to a Russian-speaking financially motivated actor), control-flow flattening, opaque predicates, mixed Boolean-arithmetic obfuscation, and self-modifying decryption stubs — yielding low detection rates across static engines and sandboxes. ATT&CK: **T1027**, **T1204**, **T1003**, **T1137**, **T1068**.

#### Indicators of Compromise

```
Domain: node-js[.]prentiva99[.]info
URL: hxxp[://]app[.]miloyannopoulos[.]com/download?subid1=download
URL: hxxp[://]link[.]storjshare[.]io/raw/jux4e4ky5mruo4jkxsssp42sau4q/ruslan/BATPackageBuilderSetup.bat
URL: hxxp[://]link[.]storjshare[.]io/raw/jwwvr4oskkkjsgevt774ta62ehya/ruslan/aBsvwbdas.exe
URL: hxxps[://]link[.]storjshare[.]io/raw/jv5uebuqwzfpmtahj34q753ptykq/node/BATPackageBulderSetup.bat
SHA256: 39019279686c820c3af5684012a0085a7e2109f612c9fab886dd0577ace5b5c6
SHA256: 4ec9d9d4d10ad78fc6d7bda7cb17d52984878ccd2dd4302fd1cef152313b9741
SHA256: 9a9939dff297997732aaade9b243d695632cbd64033c5fbcb9de3d09b7e6c28d
SHA256: c85f2765a6c3c3f3907c17e57df12f8f68826f74bff3bbfd272af50666d065fe
SHA256: de4f51649ec1a33071854aefe93ffb3fc225e19f802d8dd914676dd5dfef2615
SHA256: fdfc7831e5c24cfa80152860dfe8c056ba079f7df1393bf6bb7b18ed974eda37
```

> **SOC Action:** Block traffic to `link.storjshare.io` raw URLs at the proxy (Storj is being abused as a delivery CDN). Alert on Edge/Chrome processes launching `.bat` files from user Downloads with `-Verb RunAs` PowerShell parameters. Hunt for Common Language Runtime loaded from non-standard memory regions in .NET-naive processes (CASTLESTEALER signature). Block the listed C2/staging URLs and load the listed SHA-256s into EDR custom IOC sets.

---

### 3.8 Operation FlutterBridge — FlutterShell macOS Backdoor Abuses Flutter Framework

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a34874a01c1f77a4c242d5b)

Active December 2025–March 2026 and tracked as cluster CL-CRI-1089, FlutterShell is a macOS backdoor distributed via malvertising on Google and YouTube. Architecture is a thin Mach-O launcher plus a large Flutter payload dylib. Across three observed generations, the operators rotated Apple Developer signing certificates, increased Dart obfuscation depth and renamed bridge commands. The backdoor loads attacker-controlled JavaScript from C2 servers into a WKWebView, executing commands at runtime via a JavaScript-to-native bridge (`flutterInvoke`). Primary impact is Chrome hijacking — replacing the default search provider with `sinterfumesco[.]com` — and persistence via silent Sparkle framework updates. ATT&CK: **T1566**, **T1204.002**, **T1543.001**, **T1071.001**, **T1027**, **T1041**.

#### Indicators of Compromise

```
Domain: sinterfumesco[.]com
Domain: atsheisdomestic[.]org
Domain: etoftheappyrince[.]org
Domain: healightejustb[.]org
SHA256: 134517796178a150a1585672be134169d6877082b598d840baa3f37b0222be26
SHA256: 2c5bc9e95e1e9b73e3ba8870a008802899866a2c0e2e10112aefddf7a96af04e
SHA256: 32da1437a2734224406c7e5e8d756f0c0cd58c0c959478571cbfc0cd564d018a
SHA256: 363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34
SHA256: 6c3f61d46d4de26b9cb16808bf17c33ae69f651a4b879e7b5612ff7f548e2a82
SHA256: bf90fb31e6024d7e6616f5acd0e8aa28738a9095a508c1a986e1e974cb9e79a0
SHA256: cc4f048e66c5ab3c0f1d767bb8fc464d082641f4888ea3cd14ea3775077c4bf2
SHA256: f544bfab72d380cc20692d8ec9d31ea666785fe225dccd55beab29a3c0fdfad2
SHA256: fc091ddb4d845280aeb7745cfdb6b7cb0013abc35db9e634f055b8e8fb0b5b1e
```

> **SOC Action:** Block listed C2 domains at the egress proxy and add SHA-256s to macOS EDR detection sets. For macOS fleets, alert on Sparkle-framework update writes originating from non-vendor binaries and on Chrome default-search-provider modifications writing `sinterfumesco[.]com`. Audit recently-trust-approved Apple Developer IDs across managed devices; revoke and re-baseline trust for any newly-seen signing certificates.

---

### 3.9 ShinyHunters Pay-or-Leak Hits Ralph Lauren — 139,903 Salesforce Records

**Source:** [Have I Been Pwned](https://haveibeenpwned.com/Breach/RalphLauren)

ShinyHunters published data claimed to be obtained from Ralph Lauren's Salesforce instance as part of an ongoing "pay or leak" extortion campaign. The dataset includes 140,000 unique email addresses with names, phone numbers, gender and age-group data — consistent with marketing-tier Salesforce schemas. The campaign matches the wider ShinyHunters Salesforce-targeting pattern observed against multiple retail and tech victims in recent weeks. No further TTPs disclosed in the source report.

> **SOC Action:** For organisations running Salesforce: enforce phishing-resistant MFA on all Salesforce admin and integration users; review and time-bound Connected Apps and OAuth refresh tokens; rotate any service-account credentials used for Salesforce data sync. Notify customer-care/marketing teams that this dataset will fuel targeted phishing and SIM-swap pretexts in the next 30 days.

---

### 3.10 Operation Poisson — VPN-Mesh Persistence Surviving C2 Takedown

**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a3526fcbaffc5909dd73ce4)

A 339-command analysis of a French-speaking threat actor ("Poisson") targeting a French automotive small business and four individuals over 33 days. The attacker deployed a 70-line Python keylogger to harvest banking and email credentials, used free-tier infrastructure (Havoc C2, Backblaze B2, DuckDNS), and — critically — installed OpenSSH and Tailscale on victim machines. When the Havoc C2 server was taken offline for 18 days, the attacker's access persisted through the Tailscale VPN mesh, demonstrating that C2 takedown alone is insufficient remediation. ATT&CK: **T1021.004**, **T1056.001**, **T1059.001**, **T1070.004**, **T1055**, **T1573**.

#### Indicators of Compromise

```
IPv4: 217.154.162[.]45
IPv4: 217.154.217[.]139
Domain: wawsenti[.]duckdns[.]org
Hostname: pois43[.]s3[.]eu-central-003[.]backblazeb2[.]com
Hostname: sentiwaw[.]s3[.]eu-central-003[.]backblazeb2[.]com
Hostname: w456w5[.]s3[.]eu-central-003[.]backblazeb2[.]com
SHA256: 0378a5ef51b008aa2d6b76bd44a0bf061339bc3b737a188ec82029444d4d18fe
SHA256: 1f00fd604bb18bbe3081f9ce8d741c4029d2a2125eb8888ac4e0d955938059d6
SHA256: 291cb1fd0f2709b4457447cbb87adacf5c36c1bcb0f8754524024d44174bb195
SHA256: 3b7642b0f84e83a36334c608655c6cb7aae774839a6a3488526b853d89830a60
SHA256: aa7ea19e34567458b4ee66a7cd274181764984bf32123f756a7fdc64d5857b31
SHA256: c79091ceae7cd592fc08e4854cda7c1182af762b6b126371cc604debdc995fc7
SHA256: f06e7e1a4363a01ba2a4fee2e28abdd623abf4194bda373f23ff0e151b5c2b45
```

> **SOC Action:** Inventory all corporate endpoints for unauthorised OpenSSH server installs, Tailscale clients, and RustDesk binaries — these legitimate tools require explicit business justification. When responding to any credential-theft incident, do not rely on C2 takedown alone: enumerate all VPN mesh memberships and SSH `authorized_keys` files on affected hosts and rotate or remove. Block Backblaze B2 `s3.eu-central-003.backblazeb2.com` subdomains at the proxy unless business-justified.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in critical infrastructure and technology sectors | F5 NGINX out-of-band patches, Entra Agent ID cross-tenant compromise (batch 181) |
| 🟠 **HIGH** | Increased ransomware activity across various sectors with a focus on RaaS models | Sparkle Pools, PJ Daly Contracting, Roth Industries (all Qilin) (batch 183) |
| 🟠 **HIGH** | Advanced obfuscation techniques used to evade detection in malware delivery | FlutterShell macOS backdoor; OXLOADER/CASTLESTEALER; Gamaredon WinRAR (batch 183) |
| 🟠 **HIGH** | Ransomware groups (Nightspire, Gentlemen) enhancing capabilities with advanced EDR-killing tools | Gentlemen EDR-killer framework analysis; Nightspire postings (batch 182) |
| 🟠 **HIGH** | Increased exploitation of cloud service vulnerabilities, particularly Microsoft Azure and Dynamics | CVE-2026-48584 Azure Synapse EoP; CVE-2026-47647 Dynamics 365 EoP (batch 182) |
| 🟠 **HIGH** | Operation Endgame's continued disruption of major cybercrime operations | Operation Endgame vs. SocGholish Fake Updates; HIBP 154k ingest (batch 182) |
| 🟡 **MEDIUM** | Phishing remains a prevalent TTP across multiple campaigns | Qilin Sparkle Pools; Stormous MLIT data dump; Texas govt breach (batch 183) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **The Gentlemen** (75 reports, last seen 2026-06-19) — RaaS expanding EDR-killer toolkit; FortiGate-aware target selection.
- **Qilin** (67 reports, last seen 2026-06-19) — Highest-volume RaaS over the period; four new victims posted yesterday (Sparkle Pools, Roth Industries, PJ Daly Contracting, THL Project Management).
- **Deadlock** (55 reports, last seen 2026-06-15) — Continued posting cadence; no new victims in this 24h cycle.
- **Lockbit5** (39 reports, last seen 2026-06-18) — Latest LockBit variant continuing high-volume sectoral victim posting.
- **DragonForce** (37 reports, last seen 2026-06-16) — Linked indirectly via ThrottleBlood EDR-killer overlap with Gentlemen.
- **Akira** (31 reports, last seen 2026-06-18) — Continued mid-volume RaaS activity.
- **Nightspire** (26 reports, last seen 2026-06-18) — Active since March 2026; 27% 30-day uptime; healthcare, jewellery and public-library victims.
- **Shinyhunters / ShinyHunters** (23 + 21 reports) — Ralph Lauren and icsecurity.com leaks tied to ongoing Salesforce "pay or leak" campaign.
- **Aurora** — Dual critical-severity leak (Hagerman & Company + ALS Global) in this cycle.
- **Gamaredon** — Russian-linked intrusion set running ongoing Ukraine-targeted WinRAR campaign.

### Malware Families

- **RansomLook** (138 reports) — Pipeline tracking artefact appearing as malware label on Ransomlook-sourced postings.
- **Tox1 / Tox** (55 / 34 reports) — Messaging tooling consistently used across Gentlemen and other RaaS operations.
- **OXLOADER + CASTLESTEALER** — Newly documented Windows loader/infostealer pair (Elastic Security Labs).
- **FlutterShell** — New macOS backdoor abusing Flutter framework (Operation FlutterBridge).
- **SocGholish (FakeUpdates)** — Major Evil Corp-linked dropper disrupted by Operation Endgame 4.0.
- **GentleKiller / HexKiller / ThrottleBlood / HavocKiller / OxideHarvest** — Gentlemen RaaS EDR-killer suite.
- **Lockbit5** (14 reports) — Latest LockBit codebase associated with high-volume victim posting.
- **Akira ransomware** (14 reports) — Continued operational visibility.
- **Nightspire** (11 reports) — Branded ransomware appearing across multiple sectors.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 16 | [link](https://www.ransomlook.io/) | Dominant volume; Qilin, Aurora, The Gentlemen, Nightspire, Stormous, Anubis, Cloak, ShinyHunters, Icarus, Pear, Nova victim postings |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com/news/security/cisa-splunk-enterprise-flaw-actively-exploited-patch-by-sunday/) | Lead coverage on both critical items (Splunk KEV, FortiBleed); Gentlemen EDR-killer analysis; Texas breach |
| AlienVault | 4 | [link](https://otx.alienvault.com/pulse/6a34874a01c1f77a4c242d5b) | OXLOADER, FlutterShell, Operation Poisson, Gamaredon WinRAR analysis |
| HaveIBeenPwned | 2 | [link](https://haveibeenpwned.com/Breach/OperationEndgame4) | Operation Endgame 4.0 (154k), Ralph Lauren (140k) |
| RecordedFutures | 2 | [link](https://therecord.media/socgholish-botnet-disrupted) | SocGholish takedown; UK ICO commissioner resignation |
| SANS | 2 | [link](https://isc.sans.edu/diary/rss/33090) | Belgian-bank IPv4-mapped IPv6 phishing technique |
| Unknown (Telegram) | 2 | — | Telegram proxy / OSINT material (channel redacted per editorial rules) |
| Wired Security | 1 | [link](https://www.wired.com/story/how-peter-thiels-private-dialog-club-secretly-ranks-its-members/) | Dialog Club ranking exposé (info) |
| Schneier | 1 | — | Anthropic Fable export classification commentary (info) |
| Microsoft | 1 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42903) | CVE-2026-42903 Windows Kerberos DoS (informational) |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/oxloader-malware-loader-infostealer) | OXLOADER/CASTLESTEALER primary technical analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Splunk Enterprise (CVE-2026-20253) before the FCEB Sunday deadline; where patching is blocked, disable the PostgreSQL sidecar service and accept the documented Edge Processor / OpAmp / SPL2 pipeline impact. Hunt for unauthenticated file-creation events on existing Splunk hosts. (Ref: §3.1)
- 🔴 **IMMEDIATE:** Cross-check organisational domains against Hudson Rock's FortiBleed lookup; if exposed, follow CISA's full remediation playbook — terminate all SSL VPN/admin sessions, rotate every VPN and admin password, enforce phishing-resistant MFA, remove management interfaces from the public internet, and audit for unauthorised local accounts. (Ref: §3.3)
- 🟠 **SHORT-TERM:** Patch WinRAR to address CVE-2025-8088 across the entire endpoint estate and deploy a detection for `.lnk` files appearing in user Startup folders immediately after archive extraction. Prioritise Ukraine-aligned partners. (Ref: §3.6)
- 🟠 **SHORT-TERM:** Enable Microsoft's vulnerable-driver block list (or equivalent kernel-driver allowlisting) and alert on revoked-certificate driver loads to blunt GentleKiller/HexKiller/ThrottleBlood/HavocKiller. Tie this work to FortiBleed remediation, given Gentlemen's FortiGate-aware targeting. (Ref: §3.5)
- 🟡 **AWARENESS:** Brief incident-response teams that VPN-mesh-based persistence (Tailscale, OpenSSH, RustDesk) survives C2 takedown — Operation Poisson is a working example. Update runbooks to enumerate mesh memberships and SSH authorized_keys on every compromised host before declaring containment. (Ref: §3.10)
- 🟢 **STRATEGIC:** For organisations downstream of major data breaches in this cycle (Aurora's Hagerman / ALS Global dumps; ShinyHunters' Ralph Lauren Salesforce leak), assume that shared credentials, vault recovery material and downstream third-party DB credentials are compromised and execute a structured trust-rebaseline rather than ad-hoc password resets. (Ref: §3.2, §3.9)

---

*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 40 reports processed across 3 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
