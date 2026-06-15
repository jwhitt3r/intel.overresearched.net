---
layout: post
title:  "CTI Weekly Brief: 2026-06-08 to 2026-06-14 - Microsoft mega-Patch Tuesday, Ivanti Sentry and Oracle PeopleSoft zero-days under active exploitation"
date:   2026-06-15 08:12:36 +0000
description: "Microsoft ships record 200-flaw Patch Tuesday with three zero-days; CISA orders 3-day patch for actively exploited Ivanti Sentry (CVSS 10) and Windows Netlogon; ShinyHunters weaponise Oracle PeopleSoft zero-day against higher-ed; Qilin chains Check Point VPN bypass into ransomware."
category: weekly
tags: [cti, weekly-brief, qilin, shinyhunters, dragonforce, ivanti-sentry, cve-2026-35273, cve-2026-10520, cve-2026-50751, mltbackdoor]
classification: TLP:CLEAR
reporting_period_start: "2026-06-08"
reporting_period_end: "2026-06-14"
generated: "2026-06-15"
draft: false
severity: critical
report_count: 768
sources:
  - Microsoft
  - BleepingComputer
  - RansomLook
  - AlienVault
  - RecordedFutures
  - CISA
  - CertEU
  - SANS
  - Schneier
  - Wired Security
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-06-08 to 2026-06-14 (7d) | TLP:CLEAR | 2026-06-15 |

## 1. Executive Summary

The pipeline processed 768 reports across 14 correlation cycles during the reporting week, with 122 rated critical and 388 rated high — an unusually heavy week driven by Microsoft's record June Patch Tuesday and three independent waves of active exploitation in enterprise edge devices. Microsoft shipped fixes for 200 flaws and three publicly disclosed zero-days (CTFMON CVE-2026-45586, HTTP/2 "Bomb" CVE-2026-49160, BitLocker bypass CVE-2026-50507) alongside a separately tracked, actively exploited Windows Netlogon RCE (CVE-2026-41089, CVSS 9.8). CISA invoked a three-day patch deadline for federal agencies on a maximum-severity Ivanti Sentry OS command-injection flaw (CVE-2026-10520, CVSS 10.0) that has been used to backdoor exposed gateways, and the ShinyHunters extortion crew was confirmed to be exploiting an unauthenticated Oracle PeopleSoft zero-day (CVE-2026-35273) to siphon data from roughly 100 organisations — Mandiant assesses 68% are in the higher-education sector. Check Point disclosed in-the-wild abuse of an IKEv1 authentication bypass (CVE-2026-50751) chained into Qilin ransomware intrusions, and Veeam patched a domain-user RCE in Backup & Replication (CVE-2026-44963) that traditionally attracts ransomware operators within days. Ransomware-as-a-Service activity remained elevated: Qilin, DragonForce, Akira, Nightspire, and the newly visible Coinbase Cartel and ShadowByt3$ groups accounted for the bulk of leak-site volume, with ShinyHunters separately tied to high-volume breach disclosures (Berkadia 305k, Infinite Campus 137k). Headline malware tradecraft this week is ThreatLabz's analysis of MLTBackdoor, a heavily obfuscated BOF-loading implant delivered via ClickFix lures on automotive websites and assessed as a ransomware precursor.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 122 | Microsoft June Patch Tuesday (200 flaws, 3 zero-days); Ivanti Sentry CVE-2026-10520/10523; Oracle PeopleSoft CVE-2026-35273; Check Point VPN CVE-2026-50751; Windows Netlogon CVE-2026-41089; Veeam B&R CVE-2026-44963; phpBB auth bypass; Zcash Orchard flaw |
| 🟠 **HIGH** | 388 | Sustained Qilin/DragonForce/Akira/Nightspire RaaS leak-site activity; ShinyHunters extortion (Berkadia, Infinite Campus, coe.int); Coinbase Cartel and ShadowByt3$ campaigns; SQLite FTS5 corruption (CVE-2026-11822); gitoxide command injection (CVE-2026-40034) |
| 🟡 **MEDIUM** | 136 | Telegram-proxy phishing distribution; supporting Microsoft EoP/info-disclosure CVEs; CISA KEV catalogue additions |
| 🟢 **LOW** | 25 | Minor advisories and de-duplicated leak-site reposts |
| 🔵 **INFO** | 97 | Pipeline correlation entries and contextual landscape summaries |

## 3. Priority Intelligence Items

### 3.1 Ivanti Sentry CVE-2026-10520 / CVE-2026-10523 — CISA emergency three-day patch deadline

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-max-severity-ivanti-sentry-flaw-allows-code-execution-as-root/), [BleepingComputer (CISA directive)](https://www.bleepingcomputer.com/news/security/cisa-gives-feds-3-days-to-patch-ivanti-flaw-exploited-in-attacks/), [CERT-EU 2026-008](https://cert.europa.eu/publications/security-advisories/2026-008/)

Ivanti patched two critical flaws in its Sentry (formerly MobileIron Sentry) secure mobile gateway. CVE-2026-10520 is a CVSS 10.0 OS command-injection vulnerability allowing unauthenticated remote attackers to execute code as root; CVE-2026-10523 (CVSS 9.9) is an authentication bypass permitting creation of rogue administrative accounts. CISA's directive to U.S. federal agencies cites confirmed exploitation in the wild, with multiple exposed Sentry gateways already backdoored despite available patches. Fixed in Sentry R10.5.2, R10.6.2, and R10.7.1.

**Affected products / sectors:** Ivanti Sentry secure mobile gateway; enterprise mobility deployments across government, finance, healthcare. ATT&CK: T1190 (Exploit Public-Facing Application), T1078.004 (Valid Accounts: Domain Account), T1071.001 (Application Layer Protocol: Web Protocols).

> **SOC Action:** Identify all Internet-exposed Sentry instances via external attack surface management; upgrade to R10.5.2 / R10.6.2 / R10.7.1 within 72 hours. For any device that was Internet-reachable prior to patching, treat as potentially compromised: pull `/var/log` and Tomcat access logs, hunt for newly created administrator accounts in the Sentry portal user store, and review system command execution outside of Ivanti-signed processes (auditd `execve` events under the Sentry service account).

### 3.2 Oracle PeopleSoft CVE-2026-35273 — ShinyHunters zero-day campaign against higher education

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/oracle-mitigates-peoplesoft-zero-day-exploited-in-data-theft-attacks/)

Oracle issued an emergency Security Alert mitigation for CVE-2026-35273, an unauthenticated remote code execution flaw in PeopleSoft PeopleTools 8.61 and 8.62 (CVSS 9.8). BleepingComputer and Mandiant confirm the ShinyHunters extortion group exploited the flaw as a zero-day, claiming theft of data from approximately 300 instances belonging to over 100 organisations — 68% of notified victims are in the higher-education sector. Attackers used custom MeshCentral remote-management agents masquerading as Microsoft Azure infrastructure for C2.

**Affected products / sectors:** Oracle PeopleSoft Enterprise Applications and PeopleTools 8.61–8.62; primarily universities/colleges, also commercial finance and HR deployments. ATT&CK: T1190, T1071, T1078, T1566.002.

#### Indicators of Compromise
```
C2 / staging: 142.11.200[.]186
              142.11.200[.]187
              142.11.200[.]188
              142.11.200[.]189
              142.11.200[.]190
              108.174.202[.]99
              176.120.22[.]24
TTP marker: MeshCentral agents impersonating Microsoft Azure services
```

> **SOC Action:** Apply the Oracle emergency mitigation immediately; pending the full patch, restrict PeopleSoft web tier exposure with WAF allow-listing. Block the listed IPs at perimeter and EDR. Hunt for unexpected MeshCentral binaries (`meshagent.exe`, `meshcentral.js`) and outbound TLS to `*.azure*` domains that are not in your tenant. Audit PeopleSoft admin role grants over the past 30 days; review WebLogic stdout/stderr logs for anomalous `weblogic.Deployer` activity.

### 3.3 Check Point VPN CVE-2026-50751 — IKEv1 authentication bypass chained into Qilin ransomware

**Source:** [AlienVault / Check Point Research](https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol)

Check Point Research confirmed active exploitation of CVE-2026-50751 (CVSS 9.3), a logic flaw in IKEv1 certificate validation that lets attackers establish a Remote Access / Mobile Access VPN session without a valid password. Exploitation has been observed against a few dozen organisations globally, with at least one case involving post-compromise activity attributed to a Qilin ransomware affiliate. Affected products include Mobile Access / SSL VPN, Remote Access VPN, and Spark Firewall on R80.20.X through R82.10. A related MITM flaw (CVE-2026-50752, CVSS 7.4) was found via Check Point's BLAST AI code-analysis platform but has not been observed in the wild.

**Affected products / sectors:** Check Point Quantum gateways and Spark firewalls running deprecated IKEv1; cross-sector targeting consistent with Qilin's victimology. ATT&CK: T1190, T1133, T1078, T1071.001, T1486 (Data Encrypted for Impact), T1021, T1090.003, T1573.

#### Indicators of Compromise
```
IPs: 144.208.127[.]155
     162.33.177[.]101
     209.182.225[.]136
     38.54.107[.]167
     38.54.88[.]201
     38.60.157[.]139
     45.61.136[.]173
```

> **SOC Action:** Apply Check Point hotfix per sk185033 and migrate IKEv1 to IKEv2; if migration is not feasible immediately, disable IKEv1 Remote Access and Mobile Access blades. Pull VPN authentication logs for the past 30 days and alert on successful sessions where the IKE proposal indicates IKEv1 + certificate auth from a source IP that has never previously authenticated for that user. Block listed IPs at perimeter; correlate any matches with subsequent SMB/RDP traversal as Qilin pre-encryption indicators.

### 3.4 Microsoft June 2026 Patch Tuesday — 200 flaws, three publicly disclosed zero-days

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-june-2026-patch-tuesday-fixes-3-zero-day-200-flaws/), [SANS ISC](https://isc.sans.edu/diary/rss/33064), [Recorded Future](https://therecord.media/microsoft-ships-largest-patch-tuesday-on-record)

Microsoft's largest Patch Tuesday on record covers 200 flaws excluding the parallel 360 Chromium fixes shipped by Google. 33 are rated Critical (28 RCE, 4 EoP, 1 info disclosure). Three publicly disclosed zero-days: CVE-2026-45586 (CTFMON local SYSTEM EoP, branded "YellowKey" by researcher "Nightmare Eclipse"), CVE-2026-49160 (HTTP/2 "HTTP/2 Bomb" DoS via header-table resource exhaustion, attributed to Calif.io), and CVE-2026-50507 (BitLocker security feature bypass — branded "GreenPlasma"/"MiniPlasma" in BleepingComputer coverage). Recorded Future separately notes CVE-2026-45657 as a 9.8-rated "wormable" Windows core flaw and CVE-2026-41091 as an actively exploited Microsoft Defender EoP. Multiple Remote Desktop Client heap overflows (CVE-2026-44799/44801/42985/42992/42993) and Windows DWM Core use-after-frees (CVE-2026-44802/44804/44808/44811/44813) appear in the same drop.

**Affected products / sectors:** Windows client and server estates across all sectors; HTTP/2-fronted web services (IIS, http.sys); Remote Desktop deployments; BitLocker-protected endpoints. ATT&CK: T1068 (Exploitation for Privilege Escalation), T1190, T1078.001 (Local Accounts), T1497.

> **SOC Action:** Prioritise patching domain controllers (CVE-2026-41089 Netlogon — see 3.5), then any Internet-facing HTTP/2 services and Remote Desktop Gateways. For the HTTP/2 Bomb, apply the new `MaxHeadersCount` registry setting per KB5102602 even where the cumulative is not yet deployed. Hunt EDR for `mshta.exe` and `rundll32.exe` spawning from user temp directories (continuing T1218 abuse patterns) and for unexpected `ctfmon.exe` parent-child chains as a YellowKey post-exploitation signal.

### 3.5 Windows Netlogon CVE-2026-41089 — actively exploited domain-controller RCE

**Source:** [CERT-EU 2026-007](https://cert.europa.eu/publications/security-advisories/2026-007/)

A stack-based buffer overflow in Windows Netlogon (CVSS 9.8) allows unauthenticated attackers to execute arbitrary code with SYSTEM privileges on domain controllers by sending crafted packets. Originally addressed by Microsoft on 12 May 2026, the Belgian Centre for Cybersecurity (CCB) has confirmed active exploitation in the wild. Affected versions span Windows Server 2012/2012 R2 through Windows Server 2025.

**Affected products / sectors:** All Active Directory environments. ATT&CK: T1203 (Exploitation for Privilege Escalation), T1078.003.

> **SOC Action:** Confirm domain controllers are at or above the patched builds (2016 ≥ 10.0.14393.9140, 2019 ≥ 10.0.17763.8755, 2022 ≥ 10.0.20348.5074, 2022 23H2 ≥ 10.0.25398.2330, 2025 ≥ 10.0.26100.32772). Restrict RPC over Netlogon (TCP/445, dynamic high ports) at the network layer to only known administrative subnets. Hunt for unexpected SYSTEM-context process creation on DCs and for anomalous `lsass.exe` child processes; review Windows Security event 4688 on DCs for unsigned binaries.

### 3.6 Veeam Backup & Replication CVE-2026-44963 — domain-user RCE in a high-value ransomware target

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-veeam-vulnerability-exposes-backup-servers-to-rce-attacks/)

Veeam patched CVE-2026-44963 in Backup & Replication 12.3.2.4854. The flaw lets any authenticated low-privilege domain user achieve RCE on a domain-joined VBR server. Version 13.x is not affected due to architectural changes; however, the bulk of the install base — across 82% of the Fortune 500 — remains on the 12.x line and Veeam explicitly warns of imminent reverse-engineering of the patch. Historical precedent (CVE-2024-40711 weaponised by Akira/Fog/Frag, prior FIN7/Cuba/Conti use) makes this a near-certain ransomware target.

**Affected products / sectors:** Veeam Backup & Replication ≤ 12.3.2.4465 joined to a Windows domain. ATT&CK: T1068, T1136.

> **SOC Action:** Upgrade to VBR 12.3.2.4854 (or move to 13.x). Where upgrade cannot happen immediately, remove the VBR server from the Windows domain per Veeam's long-standing best practice and restrict console access to a jump-host. Alert on VBR service account logons originating from non-administrative hosts and on `Veeam.Backup.Manager.exe` spawning `cmd.exe`/`powershell.exe`.

### 3.7 phpBB authentication bypass — decade-old flaw, trivial exploit

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/phpbb-forum-fixes-auth-bypass-bug-lurking-for-a-decade/)

Aikido disclosed a critical authentication bypass in phpBB ≤ 3.3.16 and ≤ 4.0.0-a2 that has been latent for ten years. A single HTTP request in the default configuration logs the attacker in as any user — including administrators. Patched in 3.3.17 (no 4.x fix yet). RCE is not directly achievable due to a separate Admin Control Panel password gate, but administrator access exposes private messages, content, and account modification across the forum. Aikido withheld technical details to allow patching but contacted large operators directly.

**Affected products / sectors:** Public-facing phpBB-powered forums (thousands of community sites, niche professional forums, customer communities). ATT&CK: T1078, T1566.

> **SOC Action:** Inventory any phpBB instances in your estate (including marketing-managed community properties) and upgrade to 3.3.17. For 4.0.0-a2 deployments, restrict the forum behind WAF or basic auth until a 4.x patch ships. Review web access logs for unusual session cookie creation patterns and anomalous administrator logins from new geolocations or user-agents.

### 3.8 MLTBackdoor — ClickFix-delivered BOF loader assessed as ransomware precursor

**Source:** [AlienVault / Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor)

Zscaler ThreatLabz published a technical analysis of MLTBackdoor, a new implant first observed in May 2026 and assessed as a likely ransomware-related foothold. The infection chain begins with a ClickFix lure on automotive-themed pages: the victim is socially engineered into pasting a `conhost.exe --headless cmd /c ...` command that drops a tar archive, sideloads `endpointdlp.dll` via the signed Microsoft Defender binary `mpextms.exe`, and decrypts an RC4-wrapped second-stage payload. MLTBackdoor uses indirect syscalls, API hashing, LLVM-based Mixed Boolean-Arithmetic plus Control-Flow Flattening obfuscation, and a DGA for C2 resilience; its primary feature is a BOF (Beacon Object File) loader for runtime capability expansion.

**Affected products / sectors:** Windows endpoints; industrial and automotive verticals so far. ATT&CK: T1566 (Phishing), T1204 (User Execution — ClickFix), T1027 / T1027.002 (Obfuscation), T1055 / T1055.001 (Process Injection), T1071.001, T1105, T1140, T1497.001/.003, T1573.002.

#### Indicators of Compromise
```
C2 domains (defanged):
  hrs2y15sungu[.]com
  powwowski[.]com
  carrolc[.]com
  cwrtwright[.]com
  thomphon[.]com
URL: hxxp[://]powwowski[.]com/payloads/update.zip
URL: hxxps[://]hrs2y15sungu[.]com/d
Selected SHA-256:
  0ca2edf9982f58e63cc49ba69fb9a88762d1f220ed9482810b512d4add0f8f0b
  1d09357b6a096fdc35cd5c873eed15665d6b3c879d20c8cf01e6bca0005512cf
  46b2155c1e71b840d4b7a2e94410b89a61e2446523e6f497206d402eb02e0e93
  9c8384f93b9d347a716ea3e55b9a01250473f667b95d467126c048256b0049e9
  ced6b0f44410f6133ad63b61e04613a8b56cc3338d7b34497540e9541163e7ec
  d51ce268a585657226510586e47c58a47cee2f2bf2049008760c58dc4e6ba650
  fe8557d454adc7a91162495628d269738b92b4b5d7e5d620fc3f38c27a9a41a7
```

> **SOC Action:** Block listed domains/URLs and SHA-256s at proxy and EDR. Detect ClickFix delivery by alerting on `conhost.exe` spawned with the `--headless` flag from `explorer.exe` (paste-and-run pattern) and on `mpextms.exe` loading a non-Microsoft-signed DLL. Hunt for `mpextms.exe` parent-process anomalies and unusual `curl.exe` invocations writing into `%LocalAppData%\Temp\`. Restrict `cmd.exe` and PowerShell launching from Run dialog via attack-surface-reduction rules where feasible.

### 3.9 ShinyHunters / Coinbase Cartel / ShadowByt3$ — extortion ecosystem broadens

**Source:** [HaveIBeenPwned summary via correlation batches 173–175], [BleepingComputer (PeopleSoft)](https://www.bleepingcomputer.com/news/security/oracle-mitigates-peoplesoft-zero-day-exploited-in-data-theft-attacks/)

Beyond the PeopleSoft campaign, ShinyHunters appeared in leak-site activity tied to Berkadia (305,216 accounts), Infinite Campus (137,123 accounts), Charisma Media, and `coe.int`. The Coinbase Cartel actor publicly listed Demand.io and Cambridge Mobile Telematics, and ShadowByt3$ posted leaks for Hotelogix, Stride Learning, the University of Georgia, Cropwise (Syngenta), and a claimed Starbucks operation. DragonForce continued sustained RaaS pressure on UAE construction, hospitality, and shipping targets (Cheoy Lee Shipyards, Corniche Hotel Abu Dhabi, Al Shafar GRC).

**Affected products / sectors:** Education, hospitality, retail, telematics/automotive, professional services, NGOs. ATT&CK: T1078, T1566, T1486, T1041 (Exfiltration Over C2), T1567.

> **SOC Action:** Treat any externally exposed CRM, HR, or SaaS-integration tenant as priority for credential hygiene: rotate API tokens, enforce phishing-resistant MFA for admin roles, and review OAuth grants for unexpected third-party scopes. For education-sector defenders, prioritise PeopleSoft mitigations (3.2) and audit federated identity providers for anomalous SAML assertion issuers — a recurring ShinyHunters access vector across the past year.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software and systems, particularly Microsoft products | Microsoft patches YellowKey, GreenPlasma, MiniPlasma zero-days; June 2026 Patch Tuesday (206 fixes, 3 publicly disclosed zero-days); CVE-2026-10846 DNS response verification; CVE-2026-11822 SQLite FTS5 memory corruption (batches 165, 166, 172) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in widely used software and platforms | CVE-2026-49975 Apache mod_http2 DoS; CVE-2026-46683 Snappy SSRF / local file read; Oracle PeopleSoft zero-day (batch 169) |
| 🔴 **CRITICAL** | Sophisticated phishing campaigns leveraging AI technologies | FBI disrupts massive AI-powered phishing service using a million URLs (batch 174) |
| 🔴 **CRITICAL** | Exploitation of vulnerabilities in AI development platforms | Path traversal flaw in AI dev platform Langflow exploited in attacks (batch 167) |
| 🔴 **CRITICAL** | Widespread exploitation of Remote Desktop Protocol vulnerabilities | CVE-2026-42913 Remote Desktop Client RCE; CVE-2026-45464 SharePoint spoofing; multiple Remote Desktop Client heap overflows in Patch Tuesday (batch 165) |
| 🔴 **CRITICAL** | Exploitation of critical vulnerabilities across various software platforms | Gogs critical zero-day RCE; UniFi OS unauthenticated root; PAN-OS CVE-2026-0257 active exploitation (batch 163) |
| 🟠 **HIGH** | Ransomware-as-a-Service groups targeting multiple sectors globally | DragonForce hitting The DRM, Cheoy Lee Shipyards, Al Ishrak Contracting, Corniche Hotel Abu Dhabi, A. Liberty Engineering, Al Shafar GRC (batch 170) |
| 🟠 **HIGH** | RaaS double-extortion uplift | 3am (molinoscabodi, jetmachprod, palmero); Anubis (Singing River Health System, D&M Contractors); Nova (Bandung) (batches 171, 173, 174) |
| 🟠 **HIGH** | Targeting of commercial real estate and education sectors by ShinyHunters | Berkadia 305,216 accounts; Infinite Campus 137,123 accounts (batch 175) |
| 🟠 **HIGH** | Ransomware groups targeting critical sectors with advanced TTPs | Charisma Media, coe.int by ShinyHunters; ex-school-district employee jailed for hacks (batch 173) |
| 🟠 **HIGH** | Increased ransomware against education and hospitality by ShadowByt3$ | Hotelogix, Stride Learning, University of Georgia, Cropwise (Syngenta), Starbucks claim (batch 172) |
| 🟠 **HIGH** | RaaS adoption by Coinbase Cartel across diverse sectors | Demand.io, Cambridge Mobile Telematics (batch 172) |
| 🟠 **HIGH** | Increased exploitation of vulnerabilities in widely used software libraries and tools | CVE-2026-11822 SQLite FTS5 memory corruption; CVE-2026-40034 gitoxide command injection (batch 171) |
| 🟠 **HIGH** | Telegram-proxy-driven phishing distribution | Multiple `@Turbotelproxy` configurations linked to phishing infrastructure (batch 175) |
| 🟠 **HIGH** | Government sectors facing heightened cyber threats and exploited vulnerabilities | CISA KEV additions; CISA Ivanti 3-day directive; lapse of US surveillance program; DragonForce against government-linked targets (batch 170) |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (72 reports) — RaaS dominating leak-site volume; chained into Check Point IKEv1 bypass exploitation this week.
- **The Gentlemen** (51 reports) — Persistent RaaS leak-site activity across mid-market victims.
- **DragonForce** (41 reports) — Heavy targeting of UAE construction, hospitality and shipping (batches 168, 170).
- **Akira** (33 reports) — Continues to weaponise enterprise edge flaws; historical Veeam exploiter (relevant to 3.6).
- **Nightspire** (26 reports) — RaaS posting healthcare and manufacturing victims.
- **TeamPCP** (25 reports) — Mid-tier RaaS leak-site operator.
- **Nova** (23 reports) — Active RaaS; named in trend 411.
- **ShinyHunters** (22 reports, + 14 under alternate casing) — Oracle PeopleSoft zero-day campaign; Berkadia, Infinite Campus, coe.int, Charisma Media.
- **Lockbit5** (20 reports) — Continued post-rebrand activity.
- **Stormous** (19 reports) — Sustained leak-site volume.
- **Inc Ransom** (13 reports) — Cross-sector RaaS.
- **Coinbase Cartel** (12 reports) — Emerging RaaS, Demand.io and Cambridge Mobile Telematics named this week.
- **Safepay** (11 reports) — Lower-volume RaaS.
- **Genesis** (10 reports) — Stealer-related ecosystem references.

### Malware Families

- **RansomLook** (106 reports) — Leak-site aggregation tag, not a true family; reflects scale of RaaS posting.
- **Tox1 / Tox / Tox2** (33 / 22 / 10 reports) — Pipeline tagging of Tox-protocol ransomware C2 patterns.
- **Akira ransomware** (17 reports) — Continued double-extortion campaigns.
- **Nightspire** (12 reports) — Both threat-actor and malware tagging in pipeline.
- **Shai-Hulud / Mini Shai-Hulud** (12 / 12 reports) — Recurring malware family references; analyst should verify against named campaign reporting.
- **RALord** (12 reports) — Pipeline-tracked ransomware family.
- **Qilin** (9 reports as malware) — Pipeline distinguishes Qilin payload vs. group.
- **Lockbit5** (9 reports) — Post-rebrand family tagging.
- **MLTBackdoor** (Zscaler analysis this week) — New BOF-loader implant; ransomware precursor (see 3.8).

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 321 | [link](https://msrc.microsoft.com/update-guide) | Largest Patch Tuesday on record drove volume |
| RansomLook | 196 | [link](https://www.ransomlook.io/) | Leak-site aggregator; reflects RaaS posting volume |
| Unknown | 88 | — | Mix of unattributed feeds; includes some Telegram-origin items |
| BleepingComputer | 51 | [link](https://www.bleepingcomputer.com) | Primary outlet for Ivanti, Oracle PeopleSoft, Veeam coverage |
| AlienVault | 20 | [link](https://otx.alienvault.com/) | Carried Check Point CVE-2026-50751 and Zscaler MLTBackdoor analyses |
| RecordedFutures | 17 | [link](https://therecord.media) | Patch Tuesday and wormable CVE-2026-45657 coverage |
| Wired Security | 12 | [link](https://www.wired.com/category/security/) | Policy and surveillance reporting |
| Schneier | 11 | [link](https://www.schneier.com) | Notable Zcash Orchard advisory |
| CISA | 8 | [link](https://www.cisa.gov/news-events/cybersecurity-advisories) | Yarbo ICS advisory and KEV directives |
| SANS | 7 | [link](https://isc.sans.edu) | Patch Tuesday technical breakdown |
| Crowdstrike | 5 | [link](https://www.crowdstrike.com/blog/) | Adversary research |
| Unit42 | 4 | [link](https://unit42.paloaltonetworks.com) | Threat research |
| Upwind | 4 | [link](https://www.upwind.io/feed) | Cloud security |
| Wiz | 4 | [link](https://www.wiz.io/blog) | Cloud security research |
| HaveIBeenPwned | 3 | [link](https://haveibeenpwned.com) | Breach disclosures driving ShinyHunters trend |
| CertEU | 2 | [link](https://cert.europa.eu/publications/security-advisories/) | Advisories 2026-007 (Netlogon) and 2026-008 (Ivanti) |
| Telegram (channel name redacted) | — | — | Proxy-distribution and unattributed advisories; not linked per policy |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Apply the Ivanti Sentry hotfix (R10.5.2 / R10.6.2 / R10.7.1) within 72 hours and forensically review any previously Internet-exposed gateway for rogue admin accounts — CISA's KEV-linked deadline is operational reality, not a guideline (3.1).
- 🔴 **IMMEDIATE:** Apply Oracle's PeopleSoft emergency mitigation, block the ShinyHunters IP set at perimeter, and hunt MeshCentral binaries impersonating Azure infrastructure — higher-education defenders especially (3.2).
- 🔴 **IMMEDIATE:** Patch domain controllers for Windows Netlogon CVE-2026-41089 if not already deployed in the May cumulative; constrain RPC over Netlogon to known admin subnets and review DC process trees for SYSTEM-context anomalies (3.5).
- 🔴 **IMMEDIATE:** Push Check Point IKEv1 hotfix sk185033 and disable IKEv1 Remote Access / Mobile Access where migration to IKEv2 is not yet possible; hunt for Qilin handoff (lateral SMB/RDP into file shares pre-encryption) (3.3).
- 🟠 **SHORT-TERM:** Roll June Microsoft cumulative updates with priority on RDP gateways, IIS / http.sys frontends (apply `MaxHeadersCount` per KB5102602), and BitLocker-protected fleet endpoints (3.4).
- 🟠 **SHORT-TERM:** Upgrade Veeam Backup & Replication to 12.3.2.4854 (or 13.x); remove VBR from the Windows domain per Veeam best practice ahead of the certain reverse-engineering window (3.6).
- 🟡 **AWARENESS:** Build EDR detections for ClickFix-style social-engineering chains — alert on `conhost.exe --headless` execution and on `mpextms.exe` sideloading non-Microsoft DLLs — covering MLTBackdoor and the broader class (3.8).
- 🟡 **AWARENESS:** Inventory phpBB and other long-tail web-app deployments under marketing/community ownership; patch phpBB to 3.3.17 and gate any 4.x preview behind authentication (3.7).
- 🟢 **STRATEGIC:** Treat enterprise SaaS — PeopleSoft, Salesforce, Veeam, identity providers — as Tier-0 alongside Active Directory: rotate integration tokens quarterly, enforce phishing-resistant MFA for administrators, and continuously audit OAuth grants for unexpected third-party scopes. The ShinyHunters / Coinbase Cartel / ShadowByt3$ extortion ecosystem is increasingly SaaS-first (3.9).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 768 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
