---
layout: post
title:  "CTI Monthly Report: June 2026 - Record 200-flaw Microsoft Patch Tuesday with wormable zero-day, ShinyHunters PeopleSoft exploitation continuing post-patch, three Cisco zero-days, Mini Shai-Hulud/Miasma supply-chain expansion"
date:   2026-07-22 08:13:22 +0000
description: "June 2026 monthly threat intelligence report: 2,231 reports across 54 correlation batches. Headlines include Microsoft's largest-ever Patch Tuesday (200+ flaws, wormable CVE-2026-45657 under active attack, three publicly disclosed zero-days); actively exploited Windows Netlogon RCE (CVE-2026-41089); ShinyHunters continuing to exploit Oracle PeopleSoft CVE-2026-35273 after the June 10 patch, with Nissan disclosing an employee breach; three Cisco zero-days (Catalyst SD-WAN Manager CVE-2026-20245, vManage CVE-2026-20262, Unified CM CVE-2026-20230); SimpleHelp CVE-2026-48558 delivering the new Djinn Stealer and added to CISA KEV; Mini Shai-Hulud/Miasma expanding into GitHub Actions and the Go ecosystem; malicious skills on AI agent marketplaces; and Operation DragonReturn, a campaign with TTP overlaps to a China-nexus cluster targeting Indian tax infrastructure."
category: monthly
tags: [cti, monthly-report, qilin, the-gentlemen, dragonforce, akira, shinyhunters, mustang-panda, gamaredon, cve-2026-45657, cve-2026-41089, cve-2026-35273, cve-2026-20245, cve-2026-48558, cve-2026-10520]
classification: TLP:CLEAR
reporting_period: "June 2026"
generated: "2026-07-22"
severity: "critical"
draft: true
report_count: 2231
sources:
  - RansomLock
  - Microsoft
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - CISA
  - SANS
  - ESET Threat Research
  - Unit42
  - Intel471
  - Sysdig
  - CertEU
  - Wired Security
  - Schneier
---
| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| June 2026 (1–30 Jun 2026) | TLP:CLEAR | 22 Jul 2026 |

## 1. Executive Summary

June 2026 produced 2,231 reports across 54 correlation batches, with 205 critical and 1,327 high-severity items. Four pressure fronts defined the month. First, Microsoft shipped its largest Patch Tuesday on record — between 200 and 206 flaws depending on the counting source — including CVE-2026-45657, a CVSS 9.8 wormable flaw deep in the Windows core reported as under active attack, three publicly disclosed zero-days (CTFMON LPE, HTTP/2 Bomb DoS, BitLocker bypass), and the separately named YellowKey, GreenPlasma and MiniPlasma cluster; CERT-EU separately flagged CVE-2026-41089, an actively exploited unauthenticated Netlogon RCE granting SYSTEM on domain controllers. Second, ShinyHunters continued exploiting the Oracle PeopleSoft zero-day CVE-2026-35273 after Oracle's June 10 mitigation, with Intel 471 confirming post-patch exploitation and Nissan disclosing an employee data breach traced to the campaign. Third, network and remote-access infrastructure was hit repeatedly: three Cisco zero-days (Catalyst SD-WAN Manager CVE-2026-20245, exploited for root via malicious CSV upload per Mandiant; vManage CVE-2026-20262; Unified CM SSRF CVE-2026-20230 under CISA deadline), Ivanti Sentry CVE-2026-10520 (CISA three-day directive), Fortinet FortiSandbox, Ubiquiti UniFi OS, Splunk Enterprise CVE-2026-20253, F5 NGINX out-of-band patches, Joomla JCE CVE-2026-48907, and SimpleHelp CVE-2026-48558 — the last delivering the previously undocumented cross-platform Djinn Stealer and added to CISA KEV on June 29. CISA issued a directive requiring federal agencies to patch actively exploited critical flaws within three days. Fourth, the software supply chain remained under sustained attack: Mini Shai-Hulud and Miasma variants spread through npm packages, GitHub Actions and into the Go ecosystem, 140+ npm packages were compromised in one coordinated attack, and Polymarket customers lost roughly $3 million to injected JavaScript from a third-party vendor. A distinct new front emerged in the AI ecosystem — malicious skills on the OpenClaw/ClawHub agent marketplace, a one-click Microsoft 365 Copilot data-theft technique, and an FBI-disrupted AI-powered phishing service running about a million URLs. Ransomware tempo stayed high with Qilin, The Gentlemen, DragonForce and Akira dominant, while law enforcement landed real blows: Operation Endgame disrupted Amadey and Stealc, police raided the SocGholish network tied to Evil Corp, and a Ukrainian national pleaded guilty over Conti.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|------:|-------------|
| 🔴 **CRITICAL** | 205 | Microsoft June Patch Tuesday RCE/LPE backlog (Remote Desktop Client, Windows Graphics, DWM Core, NT OS Kernel, WinSock AFD, Office); wormable CVE-2026-45657; Netlogon CVE-2026-41089; Oracle PeopleSoft CVE-2026-35273; Cisco CVE-2026-20245 / 20262 / 20230; SimpleHelp CVE-2026-48558; Ivanti Sentry CVE-2026-10520; Fortinet FortiSandbox; Ubiquiti UniFi OS; Splunk CVE-2026-20253; F5 NGINX; Joomla JCE CVE-2026-48907; Langflow CVE-2026-55255; Operation DragonReturn |
| 🟠 **HIGH** | 1,327 | RaaS victim postings across Qilin, The Gentlemen, DragonForce, Akira, Stormous, Inc Ransom, Settra, Anubis, Nova, Icarus; Mini Shai-Hulud / Miasma supply-chain waves; KDDI 14.2M ISP logins; Sysco 2,691,852 accounts; Mustang Panda, Gamaredon, Turla and GhostShell espionage; AI agent marketplace abuse; Operation Endgame and SocGholish takedowns |
| 🟡 **MEDIUM** | 353 | Smaller RaaS affiliates; Telegram-proxy phishing distribution; routine CVE disclosures; CISA KEV catalogue additions |
| 🟢 **LOW** | 59 | Minor product advisories; Windows servicing and hotpatching notices |
| 🔵 **INFO** | 287 | ISC StormCast podcasts; vendor explainers and webinars; policy and legal coverage |

## 3. Key Events

### 3.1 Microsoft June 2026 Patch Tuesday — largest on record, wormable flaw under active attack

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-june-2026-patch-tuesday-fixes-3-zero-day-200-flaws/), [Recorded Future](https://therecord.media/microsoft-ships-largest-patch-tuesday-on-record), [SANS ISC](https://isc.sans.edu/diary/rss/33064), [BleepingComputer (zero-days)](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-yellowkey-greenplasma-miniplasma-zero-days/)

Microsoft's June release was the largest Patch Tuesday it has ever shipped. BleepingComputer counted 200 flaws and three publicly disclosed zero-days; SANS ISC counted 204 vulnerabilities including critical issues in Microsoft cloud services and Edge. Recorded Future highlighted CVE-2026-45657, rated 9.8 and described as a wormable flaw deep in the Windows core that could let a remote attacker take control of a machine without user interaction — reported as under active attack.

The three publicly disclosed zero-days were a Windows CTFMON elevation-of-privilege flaw (CVE-2026-45586), the HTTP/2 "HTTP/2 Bomb" denial-of-service issue in HPACK handling (CVE-2026-49160), and a BitLocker security feature bypass. Separately, Microsoft patched three vulnerabilities disclosed by a researcher using the handle "Nightmare Eclipse" and tracked as YellowKey, GreenPlasma and MiniPlasma, which could grant SYSTEM privileges or bypass BitLocker.

The critical cluster in this release is heavily weighted toward client-side and kernel attack surface: Remote Desktop Client heap overflows (CVE-2026-42913, CVE-2026-42993, CVE-2026-44799, CVE-2026-44801), Windows Graphics/Win32K integer overflows (CVE-2026-44803, CVE-2026-44812), DWM Core Library use-after-free (CVE-2026-44802, CVE-2026-44813), NT OS Kernel integer underflows (CVE-2026-42916, CVE-2026-42980), WinSock AFD use-after-free (CVE-2026-45596, CVE-2026-45598), Windows TCP/IP (CVE-2026-42904), Cryptographic Services (CVE-2026-44810), Secure Boot and Boot Manager bypasses (CVE-2026-45654, CVE-2026-47656), and Microsoft Office RCE (CVE-2026-45463).

> **SOC Action:** Treat CVE-2026-45657 as the priority — its wormable, no-interaction profile means perimeter-exposed and lateral-reachable Windows hosts should be patched ahead of the rest of the release. Confirm outbound RDP client usage is inventoried before deferring the Remote Desktop Client RCE cluster (T1203); those four CVEs are exploitable against users connecting *out* to attacker-controlled servers, not just inbound RDP.

### 3.2 Windows Netlogon CVE-2026-41089 — actively exploited unauthenticated SYSTEM RCE on domain controllers

**Source:** [CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-007/)

CERT-EU published advisory 2026-007 covering CVE-2026-41089, a stack-based buffer overflow in Windows Netlogon allowing unauthenticated attackers to execute arbitrary code with SYSTEM privileges on affected domain controllers. The advisory states the flaw has been actively exploited and recommends immediate patching.

> **SOC Action:** Patch domain controllers out-of-cycle. Until patched, restrict inbound TCP/445 and RPC endpoint mapper access to DCs to management subnets only, and hunt for anomalous `lsass.exe` or `netlogon` child processes and unexpected service creation on DCs (T1543.003, T1210).

### 3.3 Oracle PeopleSoft CVE-2026-35273 — ShinyHunters exploitation continued after the patch

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/oracle-mitigates-peoplesoft-zero-day-exploited-in-data-theft-attacks/), [Intel 471](https://www.intel471.com/blog/shinyhunters-0-day-attacks-after-patching-find-out-if-you-were-breached), [BleepingComputer (Nissan)](https://www.bleepingcomputer.com/news/security/nissan-discloses-employee-data-breach-linked-to-oracle-zero-day-attacks/)

Oracle mitigated CVE-2026-35273 on June 10 — an unauthenticated remote code execution flaw in Oracle PeopleSoft Enterprise Applications actively exploited by ShinyHunters for data theft, with the education sector the primary target. Intel 471 subsequently reported that ShinyHunters continued exploiting the vulnerability *after* Oracle released patches, and published guidance for organisations to determine retrospectively whether they were breached. On June 29, Nissan disclosed a breach of current and former employee data attributed to the same Oracle PeopleSoft exploitation campaign.

> **SOC Action:** Patching alone does not close this out. For any PeopleSoft/PeopleTools instance, review web server and application logs back to before June 10 for unauthenticated POST requests to PeopleTools servlet paths, unexpected file writes under the PS_HOME web directory, and outbound transfers of bulk record sets. Rotate PeopleSoft integration and service-account credentials regardless of patch status.

### 3.4 Three Cisco zero-days — Catalyst SD-WAN Manager, vManage, Unified CM

**Source:** [Mandiant / Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager), [BleepingComputer (SD-WAN)](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/), [BleepingComputer (vManage)](https://www.bleepingcomputer.com/news/security/cisco-fixes-sd-wan-vmanage-flaw-exploited-in-zero-day-attacks/), [BleepingComputer (Unified CM)](https://www.bleepingcomputer.com/news/security/cisa-sets-urgent-deadline-to-fix-cisco-flaw-exploited-in-attacks/)

Mandiant identified CVE-2026-20245 in Cisco Catalyst SD-WAN Manager, exploited as a zero-day: a file upload feature failed to filter malicious data in CSV uploads, allowing privilege escalation to root. Attackers chained an authentication bypass, injected commands and created rogue root accounts for persistence. Cisco separately patched CVE-2026-20262 in SD-WAN vManage on June 15, also exploited in zero-day attacks through insufficient validation of user-supplied input during file uploads. On June 26, CISA set an urgent remediation deadline for CVE-2026-20230, a server-side request forgery flaw in Cisco Unified Communications Manager under active exploitation, alongside a critical RCE in PTC Windchill and FlexPLM.

> **SOC Action:** Enumerate local accounts on SD-WAN Manager and vManage appliances and diff against your known-good baseline — rogue root account creation is the documented persistence mechanism (T1136, T1078). Review appliance upload directories for CSV artefacts with embedded command syntax and pull management-plane authentication logs for the period before patching.

### 3.5 SimpleHelp CVE-2026-48558 delivers Djinn Stealer; added to CISA KEV

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-simplehelp-flaw-deploy-new-djinn-infostealer-taskweaver-malware/), [CISA](https://www.cisa.gov/news-events/alerts/2026/06/29/cisa-adds-one-known-exploited-vulnerability-catalog)

Attackers are exploiting CVE-2026-48558 in SimpleHelp remote support software to execute arbitrary code via a specially crafted request and deploy Djinn Stealer, a previously undocumented cross-platform information stealer targeting Windows, macOS and Linux. Djinn harvests browser credentials, cryptocurrency wallets and contact data. CISA added the flaw — which it characterises as an authentication bypass — to the Known Exploited Vulnerabilities catalogue on June 29 under Binding Operational Directive 26-04.

> **SOC Action:** SimpleHelp is an RMM tool, so exploitation gives attackers a trusted software-deployment channel (T1219). Patch immediately, then review SimpleHelp session logs for sessions not matching a helpdesk ticket, and hunt for new cross-platform binaries writing to browser profile directories and wallet paths on hosts where the SimpleHelp agent is installed.

### 3.6 Perimeter and infrastructure exploitation wave — Ivanti, Fortinet, Ubiquiti, Splunk, F5, Joomla, SonicWall

**Source:** [BleepingComputer (Ivanti)](https://www.bleepingcomputer.com/news/security/cisa-gives-feds-3-days-to-patch-ivanti-flaw-exploited-in-attacks/), [BleepingComputer (Ivanti advisory)](https://www.bleepingcomputer.com/news/security/new-max-severity-ivanti-sentry-flaw-allows-code-execution-as-root/), [BleepingComputer (FortiSandbox)](https://www.bleepingcomputer.com/news/security/critical-fortinet-fortisandbox-flaws-now-exploited-in-attacks/), [BleepingComputer (Ubiquiti)](https://www.bleepingcomputer.com/news/security/cisa-warns-of-max-severity-ubiquiti-flaws-exploited-in-attacks/), [BleepingComputer (Splunk)](https://www.bleepingcomputer.com/news/security/cisa-splunk-enterprise-flaw-actively-exploited-patch-by-sunday/), [BleepingComputer (F5)](https://www.bleepingcomputer.com/news/security/f5-issues-out-of-band-patches-for-critical-nginx-vulnerabilities/), [BleepingComputer (Joomla)](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-joomla-plugin-flaw-by-friday/), [SANS ISC (SonicOS)](https://isc.sans.edu/diary/rss/33094), [BleepingComputer (CISA directive)](https://www.bleepingcomputer.com/news/security/cisa-tells-govt-agencies-to-patch-critical-exploited-flaws-in-3-days/)

June saw near-continuous exploitation of internet-facing infrastructure:

- **Ivanti Sentry CVE-2026-10520** — maximum-severity OS command injection allowing code execution as root, plus an authentication bypass; CISA gave federal agencies three days to patch.
- **Fortinet FortiSandbox CVE-2026-39813, CVE-2026-39808, CVE-2026-25089** — now exploited, allowing unauthenticated privilege escalation and remote code execution.
- **Ubiquiti UniFi OS CVE-2026-34908 and CVE-2026-34909** (access control bypass and directory traversal) plus Lantronix serial-to-ethernet flaws — CISA warned of active exploitation.
- **Splunk Enterprise CVE-2026-20253** — unauthenticated file operations via an exposed PostgreSQL sidecar service; CISA set a Sunday deadline.
- **F5 NGINX** — out-of-band patches for critical RCE and DoS flaws in `ngx_http_v3_module` and `ngx_http_proxy_v2_module`.
- **Joomla Widget Factory JCE CVE-2026-48907** — maximum-severity improper access control enabling code execution, under CISA order.
- **SonicOS CVE-2024-40766** — SANS ISC noted the patch fixed the bug but left insecure configurations intact; Akira and Fog ransomware continue to exploit it.

Underpinning all of this, CISA issued a directive on June 11 requiring US government agencies to patch actively exploited critical vulnerabilities within three days.

> **SOC Action:** Build a standing inventory of the seven appliance classes above with owner, version and internet exposure. For each, alert on administrative authentication from non-management source ranges and on configuration-file modification outside change windows. For SonicWall specifically, audit configurations rather than relying on patch level (T1190).

### 3.7 Supply-chain wave — Mini Shai-Hulud and Miasma expand into GitHub Actions and Go

**Source:** [AlienVault / Socket (ImmobiliareLabs)](https://socket.dev/blog/miasma-mini-shai-hulud-hits-immobiliarelabs-npm-packages), [AlienVault (LeoPlatform)](https://otx.alienvault.com/pulse/6a3df898a72c3bb83671b47b), [Recorded Future](https://therecord.media/github-dismissed-reports-shai-hulud-deep-specter), [BleepingComputer (Polymarket)](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)

The Shai-Hulud lineage continued mutating through June. A malicious `miasma-mini-shai-hulud` npm package targeted developer infrastructure to steal credentials, leveraging GitHub Actions and affecting ImmobiliareLabs packages. A parallel Mini Shai-Hulud campaign hit LeoPlatform npm packages and GitHub Actions and expanded into the Go ecosystem, using `binding.gyp` install-time execution, Bun-staged JavaScript malware and encrypted credential exfiltration. Researchers told Recorded Future that GitHub had dismissed earlier reports of the design flaws the worm exploits — backdated commit timestamps and fake author metadata used to evade detection. A coordinated attack compromised more than 140 npm packages, and the Mastra supply chain was compromised via an `easy-day-js` dropper pulling a cross-platform RAT into `@mastra` installs. Outside the package ecosystems, Polymarket customers lost approximately $3 million after malicious JavaScript was injected through a third-party vendor, causing users to approve fraudulent transactions; LastPass confirmed a data breach stemming from the Klue supply-chain attack against Salesforce instances.

> **SOC Action:** Block install-time script execution in CI (`npm ci --ignore-scripts`, and audit `binding.gyp` and `setup.py` in any dependency added since May). Rotate any credential exposed to a build runner that installed npm or Go dependencies in June. Alert on GitHub Actions workflow files modified by non-human accounts and on commits whose author metadata does not match a known signing key (T1195.002).

### 3.8 AI ecosystem becomes a first-class attack surface

**Source:** [Unit 42](https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/), [AlienVault (ClawHub)](https://otx.alienvault.com/pulse/6a3b512e73c8b7fb25b84c38), [Sysdig](https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited)

Unit 42 documented malicious actors exploiting the OpenClaw Skill Marketplace to conduct supply-chain attacks, with malicious skills using semantic instruction hijacking for evasion and carrying infostealer capabilities that bypassed marketplace security review. Corroborating research identified five malicious skills on ClawHub's AI agent marketplace between February and May 2026 that evaded detection, including macOS infostealers. Separately, Sysdig observed active exploitation of Langflow CVE-2026-55255, a CVSS 9.9 cross-tenant insecure direct object reference in the AI development platform, and noted the instructive point that the lower-scored CVE-2026-33017 (CVSS 9.3) was exploited *more* often because it required less attacker effort. June also brought a reported one-click Microsoft 365 Copilot data-theft technique and an AI-generated ClickFix campaign delivering SmartRAT.

> **SOC Action:** Treat agent skill/plugin marketplaces as an unreviewed dependency source. Inventory which AI agent frameworks and marketplaces are installed on developer endpoints, and apply the same allowlisting you apply to browser extensions. For Langflow, patch and restrict tenant-scoped API access — CVSS score is a poor proxy for exploitation likelihood here.

### 3.9 Ransomware operational tempo — Qilin, The Gentlemen, DragonForce, Akira

**Source:** [AlienVault](https://otx.alienvault.com/pulse/6a429369377f216bcfbdda03), [RansomLook](https://www.ransomlook.io/), [Recorded Future (Conti)](https://www.bleepingcomputer.com/news/security/ukrainian-national-pleads-guilty-to-role-in-conti-ransomware-operation/)

RaaS activity dominated report volume, with 717 RansomLook-sourced victim postings in June. Correlation batches repeatedly clustered Qilin (education, healthcare, manufacturing, government), The Gentlemen (including Thyssenkrupp Marine Systems / Atlas Elektronik), DragonForce (manufacturing, pharma, retail), Akira, Stormous, Inc Ransom, Settra, Anubis, Nova, Interlock, Krybit (including ford.mx) and Icarus (targeting Salesforce data). The commoditisation trend was explicit: a BLACKNET-00 RaaS platform was analysed as "weaponizing mediocrity," and Telegram-sourced posts advertised a ransomware builder for $20.

An AlienVault-reported intrusion illustrates current Akira tradecraft end-to-end: SEO poisoning delivered trojanised ManageEngine OpManager installers carrying Bumblebee to privileged administrators, followed by credential dumping with `wbadmin`, creation of enterprise-admin backdoor accounts, RustDesk for persistence, AdaptixC2 beacons, LSASS dumping across multiple systems, attempted Veeam credential theft, SFTP exfiltration via FileZilla, and Akira deployment across root and child domains within 44 hours — with re-encryption of the child domain two days later.

#### Indicators of Compromise — Bumblebee → AdaptixC2 → Akira

```
Domain: opmanager[.]pro
Domain: angryipscanner[.]org
Domain: ip-scanner[.]org
Domain: axiscamerastation[.]org
Domain: 2rxyt9urhq0bgj[.]org
Domain: ev2sirbd269o5j[.]org
Domain: ijt0l3i8brit6q[.]org
IP: 109.205.195[.]211
IP: 172.96.137[.]160
IP: 193.242.184[.]150
SHA256: 186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da
SHA256: 18b8e6762afd29a09becae283083c74a19fc09db1f2c3412c42f1b0178bc122a
SHA256: 6ba5d96e52734cbb9246bcc3decf127f780d48fa11587a1a44880c1f04404d23
SHA256: a14506c6fb92a5af88a6a44d273edafe10d69ee3d85c8b2a7ac458a22edf68d2
SHA256: a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331
SHA256: de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d
```

Techniques: T1566 (Phishing/SEO poisoning), T1204.002 (User Execution), T1078.002 (Valid Accounts), T1003.001/T1003.003 (OS Credential Dumping), T1136.002 (Create Account), T1543.003 (Windows Service), T1071.001 (Web Protocols C2), T1041 (Exfiltration Over C2), T1486 (Data Encrypted for Impact).

> **SOC Action:** Alert on downloads of IT admin tooling installers (OpManager, Angry IP Scanner, Axis Camera Station) from domains other than the vendor's canonical domain, and block the typosquats above. Query EDR for `wbadmin` execution on domain controllers and for RustDesk installation on servers — neither belongs in most environments (T1219). The 44-hour dwell time means detection must fire at the installer stage, not at encryption.

### 3.10 Operation DragonReturn — campaign with China-nexus TTP overlaps targets Indian tax infrastructure

**Source:** [Seqrite via AlienVault](https://www.seqrite.com/blog/operation-dragonreturn-china-nexus-cyber-espionage-campaign-targeting-govt-of-india-mof-tax-infrastructure-via-multi-stage-dcrat-deployment/)

Seqrite Labs documented a spear-phishing campaign impersonating the Income Tax Department of India's Ministry of Finance, delivering DcRAT through a multi-stage chain using fileless execution and steganography. Seqrite attributes the campaign to a cluster demonstrating "operational and technical similarities" and "overlapping TTPs" with a China-nexus threat actor — the report stops short of a definitive attribution, and Void Arachne appears in the entity index as a referenced actor rather than a confirmed one. The campaign was first observed on May 18, 2026 and remained active as of June 17, with the latest payload variant achieving a 0/66 VirusTotal detection rate, indicating active payload rotation. The lure clones a legitimate government utility filename and reproduces bilingual Hindi-English Office Memorandum formatting with real Income Tax Act citations.

#### Indicators of Compromise — Operation DragonReturn

```
URL: hxxp[:]//govtop[.]one/incometax
Domain: govtop[.]one
Domain: 1kkkkddd[.]com
Domain: ikkkkddd[.]com
Domain: jiayingjing[.]com
Domain: kkxqbh[.]top
Domain: simaqz[.]com
IP: 117.44.201[.]119
IP: 118.107.0[.]197
IP: 204.194.48[.]250
IP: 223.26.63[.]40
IP: 27.50.54[.]191
SHA256: 19ca5fe04ca45a18c5bad9658ff73a8f39fe20ced78f690595f1b4c5a90af324
SHA256: 2f2f8f92af86fb962c30c4c1c9d673f9d94886373d0fcf78f8d105c051ffc643
SHA256: 34d1231a3bf1e13a9b90daecb5c74d52aea94ca54427b203d77e1adc61a5c4f9
SHA256: 4a040770fd81d0db9e04cb8dbd2e07e61969072962bb4e736b7c7001444cc2fa
SHA256: 589aa1f7252cae74538343cd35443c0a8f58ed280f2016918b6e539a0c09529a
SHA256: 5a00485968679dc0ed6d80b659f48287603864c223e952918d2c2aaddfa2d280
SHA256: 5e97f7c17bf0466355be0438c7cc3e2e4d125e31368f2fbcb8e1d79cb97f137a
SHA256: 6c774188a54ae07ae896abdf1ea6695cc29f529388888665e05322af3e9178e1
SHA256: 7e142c8fa614cc39d0453aa648b12209821c6bcbb77ee02094f70161b40d50ae
SHA256: 8ed95259300ca268279867d2999d9c4f6585c6c45308635fc39af87da27546b5
SHA256: a8614dfad5fd2a79302a7c4829a0fed6f3a0a46b11beb28f89531cdfa83d32b3
SHA256: b0fcd7d9396e70b89e8292f6b80f933607b6fc9a9d3d4dd4ca69b408a2625932
SHA256: c6651d6ce31c3a00357e579981d48c0da942b5bbe1582bf3d612a07dc3bc0ff6
SHA256: c6fc06db6a1318152c09200352b40c8fa794f1089988835c1df92174347be8ec
SHA256: ec5d4103b3d97885e9575ad045b2ef5467bf9fccf71828e418e6488d78983146
SHA256: eccff5c026a01cbe91db45cd0289f8822985aa5183f096d8add69762696d100d
SHA256: fc17d5b4d64cb61a5aa8fb6bbe1e94885f129b2bf8ee91bca1ccca2b537f6616
```

Techniques: T1566.001/T1566.002 (Spearphishing), T1027 (Obfuscated Files), T1055 (Process Injection), T1140 (Deobfuscate/Decode), T1497 (Virtualisation/Sandbox Evasion), T1547.001 (Registry Run Keys), T1548.002 (Bypass UAC), T1562.001 (Impair Defenses), T1573 (Encrypted Channel).

> **SOC Action:** Block the domains and IPs above at egress. Given the 0/66 detection rate, signature-based controls will not catch current variants — hunt behaviourally for `rundll32.exe` and signed-binary proxy execution spawning from user download directories, and for outbound TLS to newly registered `.top` and `.com` domains with no prior organisational history (T1518.001).

### 3.11 Russian state targeting of commercial messaging platforms

**Source:** [Recorded Future](https://therecord.media/10million-reward-us-russian-hackers-unc4221-unc5792), [CISA](https://www.cisa.gov/resources-tools/resources/russian-intelligence-services-continue-target-commercial-messaging-applications), [Recorded Future (Ukraine)](https://therecord.media/russia-ukraine-social-engineering-messaging-accounts)

The US posted a $10 million reward for information on Russian cyber groups UNC5792 and UNC4221, which target Signal and WhatsApp accounts of high-profile individuals using social engineering to steal backup recovery keys and gain account access. CISA and the FBI updated their public service announcement on Russian intelligence services targeting commercial messaging applications, adding new tactics and phishing message examples. Ukraine's security service reported Russian intelligence using social engineering — including impersonation of official support services — to breach messaging accounts of government officials and military personnel.

> **SOC Action:** For executives and staff in scope for state-actor targeting, disable or PIN-protect chat backup and linked-device features in Signal and WhatsApp, and brief them that legitimate support services never request recovery keys or QR-code scans. Add linked-device enrolment to your alerting where MDM visibility allows (T1566, T1656).

### 3.12 Additional significant June activity

**Source:** [BleepingComputer (KDDI)](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/), [BleepingComputer (RoguePlanet)](https://www.bleepingcomputer.com/news/microsoft/microsoft-working-on-defender-patch-for-rogueplanet-zero-day/), [BleepingComputer (phpBB)](https://www.bleepingcomputer.com/news/security/phpbb-forum-fixes-auth-bypass-bug-lurking-for-a-decade/), [Recorded Future (SocGholish)](https://therecord.media/socgholish-botnet-disrupted), [Recorded Future (CaaS)](https://therecord.media/stealc-amadey-socgholish-malware-takedown-europol-microsoft), [AlienVault (Mustang Panda)](https://www.acronis.com/en/tru/posts/mustang-panda-targets-indias-government-and-energy-sectors/), [ESET](https://www.welivesecurity.com/en/eset-research/gamaredon-2025-leveraging-tunnels-workers-dead-drops-new-alliances/), [AlienVault (AryStinger)](https://otx.alienvault.com/pulse/6a332459370e15b403bb6a4e), [Wired](https://www.wired.com/story/the-pentagon-is-looking-into-the-dialog-data-exposure-for-unmasking-national-security-officials/)

- **KDDI Corporation breach** — up to 14.2 million email logins exposed across six ISPs via a third-party software vulnerability. Sysco separately reported 2,691,852 breached accounts.
- **RoguePlanet** — an unpatched Windows Defender zero-day using a race condition to spawn SYSTEM command prompts on fully patched Windows systems; Microsoft was still developing a fix as of June 17.
- **phpBB** — a decade-old authentication bypass (versions up to 3.3.16 and 4.0.0-a2) allowing login as any user, including administrators, with a single HTTP request.
- **Law enforcement** — police raided the SocGholish network tied to Evil Corp, taking down 100+ servers and disinfecting roughly 15,000 compromised WordPress sites; Microsoft and international law enforcement undercut three cybercrime-as-a-service operations behind SocGholish, Amadey and Stealc, with ESET participating in Operation Endgame; a Ukrainian national pleaded guilty over Conti (1,000+ victims); Poland arrested four in a SIM-swapping gang with FBI and HSI support; DraftKings hacker "Snoopy" received 18 months.
- **Espionage** — Mustang Panda targeted Indian government and energy sectors with ZOHOMURK and MINIRECON via SHARDLOADER, abusing Zoho WorkDrive for C2; ESET published Gamaredon's 2025 tradecraft (tunnels, Cloudflare workers, dead drops, new alliances); Turla's STOCKSTAY was documented; GhostShell targeted Ukraine's UAV supply chain with Besomar-themed malware; AryStinger compromised 4,300+ outdated RTL819X-chipset routers and NAS devices as reconnaissance springboards; CL-STA-1062 targeted Southeast Asian governments and critical infrastructure.
- **Dialog data exposure** — a misconfigured website exposed personal information of US national security personnel, including an NSC intelligence official and an active-duty intelligence officer; the Pentagon opened a review.
- **FIFA 2026 World Cup phishing** — mass phishing campaigns exploiting fan interest, alongside an AiTM phishing kit harvesting AWS console credentials.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of critical vulnerabilities in widely-used software | "Critical SimpleHelp flaw exploited to deploy new stealer malware"; "Hackers now exploit critical Oracle E-Business flaw in attacks" (batch 202) |
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities affecting critical infrastructure sectors | "ShinyHunters' 0-day attacks: After patching, find out if you were breached"; "Mandiant reveals how Cisco SD-WAN zero-day attacks gained root access" (batch 194) |
| 🔴 **CRITICAL** | Sophisticated cyber-espionage campaigns targeting government infrastructure | "Operation DragonReturn"; "CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure" (batch 197) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities leading to supply chain attacks | "Mastra Supply Chain Compromise: easy-day-js Dropper Pulls a Cross-Platform RAT"; "GitHub dismissed security reports on flaws now exploited by supply-chain worm" (batch 179) |
| 🔴 **CRITICAL** | Sophisticated use of obfuscation techniques in malware campaigns | "ClickFix Campaign Generated Via AI Delivers SmartRAT"; "140+ npm Packages Compromised in Coordinated Supply Chain Attack" (batch 180) |
| 🔴 **CRITICAL** | Widespread exploitation of Remote Desktop Protocol vulnerabilities | "CVE-2026-42913 Remote Desktop Client RCE"; "CVE-2026-45464 Microsoft SharePoint Server Spoofing" (batch 165) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in industrial control systems | "Yokogawa FAST/TOOLS and CI Server"; "Horner Automation Cscape" (batch 195); "Siemens SINEC INS"; "Impact of Linux Kernel vulnerabilities on B&R products" (batch 191) |
| 🟠 **HIGH** | Increased ransomware activity targeting multiple sectors with overlapping TTPs | Qilin victim cluster: Kunert Fashion, Musashino University, Metal Sur Famin, Lam Soon, Bristol Place, Gsma (batch 202, confidence 0.90) |
| 🟠 **HIGH** | Exploitation of supply chain vulnerabilities in CRM systems such as Salesforce | "LastPass confirms data breach in Klue supply chain attack"; "Detecting the Klue supply chain attack in Salesforce instances" (batch 191) |
| 🟠 **HIGH** | Cybercrime-as-a-service operations being disrupted | "ESET takes part in Operation Endgame to disrupt Amadey and Stealc"; "Three 'cybercrime as a service' operations undercut by Microsoft, law enforcement" (batch 194) |
| 🟠 **HIGH** | Phishing campaigns exploiting global events | "FIFA 2026 Security Alert: Cybercriminals Exploit Fan Excitement with Mass Phishing"; "Behind the console: An AiTM phishing kit harvesting AWS console credentials" (batch 195) |
| 🟠 **HIGH** | Increased availability of sophisticated ransomware tools at low cost | Telegram-advertised $20 ransomware builder; "BLACKNET-00: The Ransomware-as-a-Service Platform That Weaponizes Mediocrity" (batches 188, 192) |
| 🟡 **MEDIUM** | Phishing campaigns leveraging Telegram proxies for malicious activities | Telegram proxy configuration distribution observed across batches 173, 174, 175, 199, 202 |

Batch 202 (29 June, 63 reports) summarised the closing state of the month: "critical vulnerabilities in widely-used software like SimpleHelp and Oracle E-Business Suite are being actively exploited, posing significant risks to organizations worldwide," alongside ransomware concentration in Qilin and DragonForce and state-linked targeting of Signal and WhatsApp.

**Data gap:** `cti_get_trend_snapshots` returned no records for 1–30 June 2026. Quantitative entity-frequency and severity-shift comparisons against May are unavailable for this period.

## 5. Trending Entities (Pipeline-Wide)

The entity index reflects a rolling 30-day window (approximately 22 Jun – 22 Jul 2026) rather than the calendar month, so counts below overlap into July.

### Threat Actors

- **The Gentlemen** (97 reports) — highest-volume actor in the index; June victims include Thyssenkrupp Marine Systems / Atlas Elektronik and UiTM Holdings
- **Qilin** (90 reports) — most persistent RaaS operation across education, healthcare, manufacturing and government
- **DragonForce** (42 reports) — manufacturing, pharmaceutical, retail and logistics targeting
- **Akira** (28 reports) — healthcare and manufacturing; SonicWall and SEO-poisoning initial access
- **Nova** (19 reports) — rebranded from RALord, operating a RaaS model
- **Inc Ransom** (18 reports) — legal services, medical and manufacturing
- **Stormous** (14 reports) — retail and finance, data-dump-led extortion
- **Anubis** (13 reports) — associated with both Anubis ransomware and the Anubis banking trojan
- **Safepay** (12 reports)
- **Krybit** (11 reports) — victims include ford.mx
- **Chaos** (11 reports) — double-extortion
- **Cmd Organization** (11 reports)
- **ShinyHunters** (11 reports) — Oracle PeopleSoft zero-day extortion campaign
- **Deadlock** (11 reports)
- **Genesis** (10 reports)

### Malware Families

- **RansomLook** (119 reports) — leak-site tracking artefact rather than a discrete family; indicates RaaS posting volume
- **Tox1** (54) / **Tox** (29) — Tox protocol used for ransomware victim negotiation
- **Other1** (43) — pipeline classification placeholder
- **Akira ransomware** (14)
- **DragonForce ransomware** (14)
- **Chaos Ransomware** (12)
- **The Gentlemen ransomware** (12, plus 9 under a case variant)
- **Anubis ransomware** (11) / **Anubis banking trojan** (10)
- **RALord** (10) / **Nova** (10)
- **Qilin** (9)

Named June malware not yet consolidated in the entity index includes Djinn Stealer, TaskWeaver, DcRAT, ZOHOMURK, MINIRECON, SHARDLOADER, Bumblebee, AdaptixC2, SmartRAT, Miasma/Mini Shai-Hulud, AryStinger and SharkLoader.

### Vulnerabilities

The vulnerability entity index holds only 6 entries, each with a single report and all referencing legacy CVEs (CVE-2023-2868, CVE-2024-42009, CVE-2025-49113, CVE-2023-26360, CVE-2023-29298, CVE-2023-29300). June's operationally significant CVEs are not represented in the entity index and were sourced from report bodies instead — an indexing gap worth raising with the pipeline owner.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|--------:|-----|-------|
| RansomLock | 717 | [link](https://www.ransomlook.io/) | Ransomware leak-site victim postings; drives high-severity volume |
| Microsoft | 628 | [link](https://msrc.microsoft.com/update-guide/) | MSRC advisories; June Patch Tuesday accounts for the bulk |
| BleepingComputer | 199 | [link](https://www.bleepingcomputer.com) | Primary coverage of active exploitation and breach disclosure |
| Telegram (channel names redacted) | 185 | — | TLP:AMBER+STRICT OSINT; exploit trading, ransomware builder sales, proxy distribution |
| AlienVault | 134 | [link](https://otx.alienvault.com) | OTX pulses; principal IOC source including DragonReturn and Bumblebee/Akira |
| RecordedFutures | 66 | [link](https://therecord.media) | Law enforcement operations, policy and attribution reporting |
| CISA | 50 | [link](https://www.cisa.gov) | KEV additions and binding operational directives |
| SANS | 37 | [link](https://isc.sans.edu) | ISC diaries and StormCast |
| Other (Schneier, Wired Security, ESET, Unit42, Intel471, Sysdig, CertEU, Cisco Talos, Crowdstrike, Wiz, Upwind, BellingCat) | ~215 | — | Long-tail vendor research and analysis |

## 7. Consolidated Recommendations

### Patching

- 🔴 **IMMEDIATE:** Patch CVE-2026-41089 (Netlogon) on all domain controllers out-of-cycle — actively exploited, unauthenticated, SYSTEM-level (§3.2).
- 🔴 **IMMEDIATE:** Apply the June Patch Tuesday release prioritising CVE-2026-45657 (wormable, 9.8, under active attack) ahead of the remaining 200+ fixes (§3.1).
- 🔴 **IMMEDIATE:** Patch every appliance in §3.6 that is internet-facing — Ivanti Sentry, FortiSandbox, UniFi OS, Splunk, NGINX, Joomla JCE — and SimpleHelp CVE-2026-48558 (§3.5).
- 🟠 **SHORT-TERM:** Patch Cisco Catalyst SD-WAN Manager, vManage and Unified CM, and treat patching as insufficient on its own — see the account audit under Hunting (§3.4).
- 🟠 **SHORT-TERM:** Audit SonicWall SonicOS configurations rather than patch level; CVE-2024-40766 remains exploitable through insecure configuration after patching (§3.6).

### Detection

- 🔴 **IMMEDIATE:** Block and alert on the DragonReturn and Bumblebee/Akira indicators in §3.9 and §3.10 at egress and on endpoint.
- 🟠 **SHORT-TERM:** Alert on `wbadmin` execution on domain controllers, RustDesk installation on servers, and LSASS access by non-security processes — the documented Akira chain (§3.9).
- 🟠 **SHORT-TERM:** Alert on administrative authentication to network appliances from outside management subnets, and on appliance configuration changes outside change windows (§3.6).
- 🟡 **AWARENESS:** Signature detection is failing against actively rotated payloads (0/66 VirusTotal for the current DragonReturn variant); weight behavioural detections accordingly (§3.10).

### Hunting

- 🔴 **IMMEDIATE:** For any Oracle PeopleSoft instance, hunt retrospectively to before June 10 — patching post-dates confirmed exploitation and ShinyHunters continued after the fix shipped (§3.3).
- 🔴 **IMMEDIATE:** Enumerate local and root accounts on Cisco SD-WAN Manager and vManage appliances and diff against baseline; rogue root account creation is the documented persistence mechanism (§3.4).
- 🟠 **SHORT-TERM:** Hunt CI/CD runners and developer endpoints for install-time script execution from npm, Go and GitHub Actions dependencies added since May, and rotate any credential exposed to those runners (§3.7).
- 🟠 **SHORT-TERM:** Review SimpleHelp and other RMM session logs for sessions without a matching helpdesk ticket (§3.5).
- 🟡 **AWARENESS:** Inventory AI agent frameworks and skill marketplaces installed on developer endpoints (§3.8).

### Policy

- 🔴 **IMMEDIATE:** Adopt a three-day remediation SLA for CISA KEV-listed vulnerabilities on internet-facing assets, matching the June 11 federal directive (§3.6).
- 🟠 **SHORT-TERM:** Set `--ignore-scripts` as the default for CI dependency installs and require review for any dependency shipping `binding.gyp`, `postinstall` or `setup.py` execution (§3.7).
- 🟠 **SHORT-TERM:** Extend third-party risk review to front-end JavaScript vendors — the Polymarket loss came through an injected script, not a package (§3.7).
- 🟡 **AWARENESS:** Apply extension-style allowlisting to AI agent skills and plugins; marketplace review demonstrably failed to catch infostealers (§3.8).
- 🟢 **STRATEGIC:** Maintain a standing inventory of the appliance classes exploited in June — VPN, firewall, sandbox, SD-WAN controller, unified comms, log platform, web server, RMM — with owner, version and exposure status.

### Training

- 🔴 **IMMEDIATE:** Brief executives and state-actor-targeted staff that legitimate messaging support never requests recovery keys or device-linking QR scans (§3.11).
- 🟠 **SHORT-TERM:** Brief IT administrators specifically on SEO-poisoned admin tooling downloads — the Akira chain succeeded because privileged users ran trojanised installers (§3.9).
- 🟡 **AWARENESS:** Refresh finance and tax-team phishing training ahead of filing seasons; DragonReturn cloned a legitimate government utility filename and used real statutory citations (§3.10).
- 🟢 **STRATEGIC:** Add supply-chain compromise to the incident response exercise calendar, covering package registries, CI runners and third-party front-end scripts as distinct scenarios (§3.7).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 2,231 reports processed across 54 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
