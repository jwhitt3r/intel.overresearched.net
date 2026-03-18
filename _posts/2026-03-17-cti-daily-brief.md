---
layout: post
title: "CTI Daily Brief: 2026-03-17 - DarkSword iOS zero-day exploit chain proliferates; Interlock ransomware exploits Cisco FMC zero-day; CISA adds Zimbra XSS to KEV"
date: 2026-03-18 21:05:00 +0000
description: "Critical 24-hour period dominated by the DarkSword iOS exploit chain targeting hundreds of millions of devices across four countries, Interlock ransomware leveraging a Cisco Secure FMC zero-day exploited since January, CISA KEV addition of Zimbra XSS, and DPRK-linked cryptocurrency theft campaigns."
category: daily
tags: [cti, daily-brief, darksword, interlock, unc6353, glassworm, lazarus-group, cve-2026-20131, cve-2026-3564]
classification: TLP:CLEAR
reporting_period: "2026-03-17"
generated: "2026-03-18"
draft: false
report_count: 37
sources:
  - AlienVault
  - BleepingComputer
  - RecordedFutures
  - Microsoft
  - SANS
  - Wired Security
  - Cisco Talos
  - CISA
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-03-17 (24h) | TLP:CLEAR | 2026-03-18 |

## 1. Executive Summary

The pipeline processed 37 reports from 9 sources over the past 24 hours, with 11 rated critical and 9 high. The dominant theme is a surge in zero-day exploitation across enterprise and mobile platforms. The DarkSword iOS exploit chain, leveraging six zero-day vulnerabilities (CVE-2025-31277, CVE-2025-43529, CVE-2026-20700, CVE-2025-14174, CVE-2025-43510, CVE-2025-43520), has been adopted by multiple threat actors including suspected Russian espionage group UNC6353, commercial surveillance vendors, and UNC6748, with campaigns confirmed in Saudi Arabia, Turkey, Malaysia, and Ukraine. Separately, the Interlock ransomware gang exploited CVE-2026-20131 in Cisco Secure FMC as a zero-day for 36 days before disclosure. CISA added CVE-2025-66376 (Zimbra ZCS XSS) to the Known Exploited Vulnerabilities catalogue. DPRK-linked actors continued targeting the cryptocurrency sector, with the Lazarus Group stealing 18,500 records from Bitrefill and the Contagious Trader campaign weaponising GitHub trading bots.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 11 | DarkSword iOS exploit chain (3 reports); Interlock/Cisco FMC zero-day; ConnectWise ScreenConnect CVE-2026-3564; CISA KEV Zimbra XSS; GlassWorm supply-chain; DPRK Contagious Trader; Marquis 672K breach; Wazuh RCE; VMware Aria Operations privesc |
| 🟠 **HIGH** | 9 | SnappyClient C2 framework; LeakNet ClickFix ransomware; Konni Group spear-phishing; Horabot banking trojan; Bitrefill/Lazarus breach; Nordstrom email compromise; BreachForums migration; refund fraud economy |
| 🟡 **MEDIUM** | 14 | APT28 Operation Roundish; Apple WebKit CVE-2026-20643; Spark Stealer Minecraft mod; CISA Iran threat posture; Russia internet whitelist; BreachForums Telegram activity; Microsoft CVEs; fake shop network |
| 🟢 **LOW** | 2 | SANS Adminer scanning activity; ISC Stormcast podcast |

## 3. Priority Intelligence Items

### 3.1 DarkSword iOS Exploit Chain Adopted by Multiple Threat Actors

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-darksword-ios-exploit-used-in-infostealer-attack-on-iphones/), [AlienVault](https://otx.alienvault.com/pulse/69bac861fe18a3b724f976fe), [Wired Security](https://www.wired.com/story/hundreds-of-millions-of-iphones-can-be-hacked-with-a-new-tool-found-in-the-wild/)

Google Threat Intelligence Group, Lookout, and iVerify disclosed DarkSword, a full-chain iOS exploit kit targeting devices running iOS 18.4 through 18.7. The chain exploits six vulnerabilities to achieve sandbox escape, privilege escalation, and remote code execution, deploying three JavaScript-based malware families: GHOSTBLADE (dataminer stealing crypto wallet data, iMessage, Telegram, WhatsApp, email, and location data), GHOSTKNIFE (backdoor for account enumeration and data exfiltration), and GHOSTSABER (backdoor with JavaScript execution and file listing capabilities).

Active since November 2025, DarkSword has been adopted by UNC6748 (targeting Saudi Arabia via a Snapchat-impersonation site), PARS Defense (Turkish commercial surveillance vendor, campaigns in Turkey and Malaysia), and UNC6353 (suspected Russian espionage group, watering hole attacks against Ukrainian websites since December 2025). Lookout researchers noted signs of LLM-assisted codebase expansion. Apple addressed all exploited flaws in the latest iOS releases; devices running iOS 18.8+ are not affected.

**CVEs:** CVE-2025-31277, CVE-2025-43529, CVE-2026-20700, CVE-2025-14174, CVE-2025-43510, CVE-2025-43520

**MITRE ATT&CK:** T1190, T1203, T1068, T1059.007, T1056.001, T1113, T1005, T1204.001

#### Indicators of Compromise
```
Domain: 0x436cc4[.]open
Domain: 0x1fedd2[.]open
Domain: sahibndn[.]io
Domain: snapshare[.]chat
Hostname: static[.]cdncounter[.]net
Hostname: e5[.]malaymoil[.]com
Hostname: sqwas[.]shapelie[.]com
SHA256: 2e5a56beb63f21d9347310412ae6efb29fd3db2d3a3fc0798865a29a3c578d35
URL: hxxps[:]//static[.]cdncounter[.]net/assets/index.html
URL: hxxps[:]//static[.]cdncounter[.]net/widgets.js?uhfiu27fajf2948fjfefaa42
```

> **SOC Action:** Verify all managed iOS devices are updated to iOS 18.8 or later. Query MDM for devices still running iOS 18.4–18.7 and prioritise forced updates. Block the listed domains and hostnames at the DNS/proxy layer. Hunt for network connections to `cdncounter[.]net` and `shapelie[.]com` in proxy logs.

### 3.2 Interlock Ransomware Exploits Cisco Secure FMC Zero-Day (CVE-2026-20131)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/interlock-ransomware-exploited-secure-fmc-flaw-in-zero-day-attacks-since-january/)

The Interlock ransomware gang exploited CVE-2026-20131, a maximum-severity RCE vulnerability in Cisco Secure Firewall Management Center (FMC), as a zero-day starting January 26, 2026 — 36 days before Cisco's March 4 disclosure. The flaw allows unauthenticated attackers to execute arbitrary Java code as root via the FMC web interface. Post-exploitation, Interlock deployed NodeSnake and Slopoly malware (the latter suspected of being AI-generated). Amazon's threat intelligence team confirmed the pre-disclosure exploitation timeline. Interlock has previously claimed attacks on DaVita, Kettering Health, Texas Tech University, and the City of Saint Paul.

**MITRE ATT&CK:** T1190, T1210

> **SOC Action:** Confirm all Cisco Secure FMC instances are patched to the version released March 4, 2026. If running an unpatched version, treat the appliance as potentially compromised: audit FMC access logs for anomalous web interface authentication since January 26, check for unexpected Java processes running as root, and engage IR if indicators are found. Restrict FMC management interface access to trusted administrative networks only.

### 3.3 CISA Adds Zimbra ZCS XSS (CVE-2025-66376) to KEV Catalogue

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/03/18/cisa-adds-one-known-exploited-vulnerability-catalog)

CISA added CVE-2025-66376, a cross-site scripting vulnerability in Synacor Zimbra Collaboration Suite (ZCS), to the Known Exploited Vulnerabilities catalogue based on evidence of active exploitation. The flaw allows attackers to execute malicious scripts in victims' browsers, potentially compromising email data and session tokens. Federal agencies are required to remediate per BOD 22-01 timelines.

> **SOC Action:** Identify all Zimbra ZCS deployments in the environment and apply the vendor patch immediately. Review Zimbra webmail access logs for suspicious script injection patterns or anomalous session activity. Consider deploying Content Security Policy headers on Zimbra frontends to limit XSS impact.

### 3.4 ConnectWise ScreenConnect Cryptographic Flaw (CVE-2026-3564)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/connectwise-patches-new-flaw-allowing-screenconnect-hijacking/)

ConnectWise disclosed CVE-2026-3564, a critical cryptographic signature verification vulnerability in ScreenConnect versions prior to 26.1. Exploitation allows extraction of ASP.NET machine keys, enabling unauthorized session authentication and privilege escalation. While ConnectWise states no confirmed exploitation of this specific CVE has occurred, researchers observed wild attempts to abuse disclosed machine key material, and unverified claims suggest Chinese hackers have leveraged similar flaws for years. Cloud-hosted customers were automatically updated; on-premises deployments require manual upgrade to version 26.1.

> **SOC Action:** Upgrade all on-premises ScreenConnect instances to version 26.1 immediately. Rotate ASP.NET machine keys on any ScreenConnect server that was publicly exposed while running a version prior to 26.1. Audit ScreenConnect authentication logs for sessions not traceable to known administrator accounts.

### 3.5 DPRK Cryptocurrency Targeting: Contagious Trader and Bitrefill Breach

**Source:** [AlienVault](https://otx.alienvault.com/pulse/69ba83542e3e56c9806b9659), [Recorded Future](https://therecord.media/crypto-platform-accuses-north-korea-hack)

Two concurrent DPRK-linked campaigns targeted the cryptocurrency sector. The Contagious Trader campaign deploys weaponised cryptocurrency trading bots on GitHub, using malicious npm dependencies to exfiltrate private keys and sensitive data via Vercel infrastructure. The campaign overlaps with FAMOUS CHOLLIMA TTPs. Separately, Bitrefill attributed a March 1 breach to the Lazarus Group: attackers compromised an employee laptop, escalated to production secrets, and stole 18,500 purchase records containing crypto payment addresses and metadata. Some company cryptocurrency wallets were drained.

**MITRE ATT&CK:** T1195.002, T1059.007, T1547.001, T1071.001, T1132.001, T1078, T1552

#### Indicators of Compromise (Contagious Trader)
```
C2: 154.38.188[.]168
C2: 23.137.105[.]114
C2: 39.144.60[.]174
Domain: aurevian[.]cloud
Domain: clob-polymarket[.]com
Domain: polymarket-clob[.]com
Domain: polblxpnl[.]space
Hostname: api[.]bpkythuat[.]com
Hostname: api[.]fivefingerz[.]dev
Hostname: api[.]mywalletsss[.]store
Hostname: api[.]soladify[.]fun
```

> **SOC Action:** Scan developer workstations for npm packages originating from the listed domains. Block the C2 IP addresses at the perimeter. Alert on outbound connections from development environments to `*.vercel.app` domains that are not part of sanctioned projects. Review GitHub repository dependencies for any references to the Contagious Trader trading bot projects.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Increased exploitation of zero-day vulnerabilities across multiple sectors | Interlock/Cisco FMC zero-day (36 days pre-disclosure); DarkSword iOS 6-CVE chain adopted by 3+ threat actors; ConnectWise ScreenConnect machine key abuse |
| 🔴 **CRITICAL** | Increased targeting of critical infrastructure and financial services | Lazarus/Bitrefill crypto theft; Marquis fintech breach impacting 74 U.S. banks |
| 🟠 **HIGH** | State-sponsored actors leveraging sophisticated malware and TTPs | DPRK Contagious Trader weaponising GitHub/npm; DarkSword proliferating to Russian and Turkish state-linked actors; APT28 Operation Roundish targeting Ukrainian government |
| 🟠 **HIGH** | Rise in phishing and social engineering targeting financial/crypto sectors | Marquis breach via SonicWall compromise; Nordstrom email system abuse for crypto scams; fake Pudgy World phishing site |
| 🟡 **MEDIUM** | Phishing as persistent initial access vector | GlassWorm supply-chain via GitHub account takeovers; BreachForums database migration enabling credential abuse |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala** (9 reports) — Iran-linked group targeting medical sectors; CISA notes ongoing activity despite broader Iran conflict
- **Void Manticore** (4 reports) — Iranian threat actor with persistent campaign activity
- **UNC6353** (3 reports) — Suspected Russian espionage group; primary operator of DarkSword against Ukrainian targets
- **LeakNet** (2 reports) — Ransomware operator scaling operations with ClickFix lures and Deno-based loaders
- **APT28 / Fancy Bear** (2 reports) — GRU-linked; Operation Roundish Roundcube exploitation toolkit targeting Ukrainian government mail systems
- **Medusa ransomware gang** (2 reports) — Claimed attacks on Mississippi hospital and New Jersey county
- **Lazarus Group** (2 reports) — DPRK; Bitrefill crypto platform breach and ongoing cryptocurrency theft operations
- **Laundry Bear** (2 reports) — Emerging threat actor under observation
- **Konni Group** (2 reports) — Spear-phishing campaigns using KakaoTalk for RAT distribution

### Malware Families

- **Slopoly** (3 reports) — AI-suspected ransomware payload deployed by Interlock; delivered via Cisco FMC exploitation
- **HijackLoader** (3 reports) — Loader delivering SnappyClient and other implants via DLL side-loading
- **Coruna** (3 reports) — iOS exploit kit predecessor to DarkSword
- **NodeSnake** (2 reports) — RAT deployed by Interlock in university and enterprise intrusions
- **GHOSTBLADE / GHOSTKNIFE / GHOSTSABER** (2 reports each) — DarkSword JavaScript malware families for iOS data exfiltration
- **GlassWorm** (1 report) — Supply-chain malware targeting 400+ repos across GitHub, npm, VSCode, OpenVSX
- **Medusa ransomware** (2 reports) — Active ransomware operation targeting healthcare and local government

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| AlienVault | 10 | [link](https://otx.alienvault.com) | OTX pulses covering DarkSword, Contagious Trader, Horabot, SnappyClient, LeakNet, Konni, and Operation Roundish |
| BleepingComputer | 8 | [link](https://www.bleepingcomputer.com) | Primary coverage of DarkSword, Interlock/Cisco FMC, ScreenConnect, Marquis breach, GlassWorm, and Nordstrom |
| Recorded Future | 5 | [link](https://therecord.media) | Bitrefill/Lazarus, CISA Iran posture, Marquis breach, Russia internet restrictions, election threat assessment |
| Unknown | 5 | — | Telegram-sourced reports (VMware Aria, Wazuh RCE, BreachForums activity); channel URLs redacted per policy |
| Microsoft | 3 | [link](https://msrc.microsoft.com) | CVE-2026-4111 Libarchive DoS, CVE-2025-71239, CVE-2026-23241 Linux kernel audit |
| SANS | 2 | [link](https://isc.sans.edu) | Adminer scanning diary; ISC Stormcast podcast |
| Wired Security | 2 | [link](https://www.wired.com/category/security) | DarkSword coverage; War Machine livestream |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com) | DispatchLogger COM analysis tool release |
| CISA | 1 | [link](https://www.cisa.gov) | KEV catalogue addition: Zimbra ZCS CVE-2025-66376 |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Cisco Secure FMC to the March 4, 2026 release addressing CVE-2026-20131. Any unpatched FMC exposed since January 26 should be treated as potentially compromised and subjected to forensic review for NodeSnake/Slopoly artifacts.

- 🔴 **IMMEDIATE:** Force-update all managed iOS devices to iOS 18.8 or later to close the six DarkSword vulnerabilities. Block DarkSword C2 domains (`cdncounter[.]net`, `shapelie[.]com`, `malaymoil[.]com`, `0x436cc4[.]open`) at DNS resolvers and web proxies.

- 🟠 **SHORT-TERM:** Upgrade on-premises ConnectWise ScreenConnect to version 26.1, rotate ASP.NET machine keys, and audit session logs for unauthorised authentication since CVE-2026-3564 disclosure. Patch Zimbra ZCS against CVE-2025-66376 per CISA KEV remediation timelines.

- 🟠 **SHORT-TERM:** Scan developer environments for GlassWorm indicators: the `lzcdrtfxyqiplpd` marker variable, `~/init.json` persistence files, and unexpected `~/node-v22*` installations. Audit npm dependencies and VSCode extensions installed since October 2025 against published IOC lists from Step Security and Aikido.

- 🟡 **AWARENESS:** Monitor for DPRK cryptocurrency-targeting campaigns. Alert on developer workstation connections to Contagious Trader C2 infrastructure. Brief cryptocurrency operations teams on the Bitrefill breach TTPs, particularly the pattern of compromised employee laptops leading to production secret exfiltration.

- 🟢 **STRATEGIC:** Evaluate enterprise exposure to supply-chain attacks via open-source package ecosystems (npm, PyPI, VSCode extensions). The convergence of GlassWorm and Contagious Trader campaigns indicates state and criminal actors are systematically targeting developer toolchains as a scalable initial access vector.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 37 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
