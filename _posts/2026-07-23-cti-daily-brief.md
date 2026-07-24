---
layout: post
title:  "CTI Daily Brief: 2026-07-23 - Check Point management auth-bypass CVE-2026-16232 exploited in the wild; federal agencies confirm ongoing PLC attacks on U.S. critical infrastructure"
date:   2026-07-24 20:07:38 +0000
description: "CVE-2026-16232 authentication bypass exploited against internet-exposed security management products; six federal agencies confirm active PLC exploitation disrupting U.S. water and energy sectors; Clop targets PTC Windchill/FlexPLM; Shai-Hulud npm worm resurfaces in intercom-client; Play, Qilin and The Gentlemen sustain ransomware activity."
category: daily
tags: [cti, daily-brief, cve-2026-16232, cyber-av3ngers, clop]
classification: TLP:CLEAR
reporting_period: "2026-07-23"
generated: "2026-07-24"
draft: true
report_count: 47
severity: critical
sources:
  - RansomLock
  - BleepingComputer
  - AlienVault
  - Microsoft
  - RecordedFutures
  - Wired Security
  - SANS
  - BellingCat
  - Elastic Security Labs
  - Schneier
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-23 (24h) | TLP:CLEAR | 2026-07-24 |

## 1. Executive Summary

The pipeline processed 47 reports across 11 sources for the period, with the threat picture dominated by active exploitation of network-edge infrastructure and a heavy cadence of ransomware leak-site activity. Two critical items anchor the brief: an authentication bypass in Check Point security management products (CVE-2026-16232) confirmed exploited in the wild against internet-exposed, IP-unrestricted deployments, and a joint six-agency advisory (AA26-097A) confirming ongoing exploitation of internet-facing PLCs across U.S. water, energy, and government facilities — now expanded beyond Rockwell/Allen-Bradley to Schneider Electric and Siemens equipment, with confirmed operational disruption. Extortion actor Clop began targeting internet-exposed PTC Windchill and FlexPLM instances for data theft, and the Shai-Hulud npm supply-chain worm resurfaced in a compromised intercom-client@7.0.4 package (361,510 weekly downloads) harvesting GitHub credentials. Ransomware operators Play, Qilin, The Gentlemen, DragonForce, and Akira sustained high-volume leak-site postings, and a nation-state espionage operation against Thailand's Ministry of Finance was found running an autonomous AI agent ("Hermes") in unattended mode. No new CISA KEV additions appeared in this period's reports, though the PLC advisory references AA26-097A and correlation analysis continued to flag cloud-service privilege escalation and Zimbra webmail phishing as critical trends.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | Check Point CVE-2026-16232 auth bypass (in-the-wild); ongoing PLC exploitation of U.S. critical infrastructure |
| 🟠 **HIGH** | 23 | Clop→Windchill/FlexPLM; Shai-Hulud npm worm; Thailand MoF AI-agent espionage; Kimsuky APT (S. Korea); hotel Wi-Fi DNS hijack; Play/Qilin/Akira/DragonForce/Nova RaaS activity |
| 🟡 **MEDIUM** | 13 | Chick-fil-A credential stuffing; Europol "The Com" takedown; seunshare CVEs; Devs Palace ERP CVEs; Inc Ransom postings |
| 🔵 **INFO** | 9 | SANS ISC Stormcast; Microsoft 365 outage post-mortem; Bellingcat Mali drone OSINT; scam-compound imagery |

_No low-severity reports were returned for this period._

## 3. Priority Intelligence Items

### 3.1 Check Point Management Auth Bypass (CVE-2026-16232) Exploited in the Wild
**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a6375b8843a154abdf4a0f0)

A July 2026 security update addresses multiple vulnerabilities in Check Point management products, including a critical authentication bypass, **CVE-2026-16232**, confirmed exploited in the wild against a limited number of customers whose Security Management or Multi-Domain Management is exposed directly to the internet without IP restrictions. Two further flaws (CVE-2026-62144, CVE-2026-62145) cover authentication bypass with privilege escalation and local privilege escalation in the GaiaOS WebUI. Exploitation maps to external remote services (T1133), exploitation of public-facing applications (T1190), and valid-accounts/privilege-escalation techniques (T1078, T1068, T1548). Smart-1 Cloud customers are already protected; all impacted customers have been notified.

#### Indicators of Compromise
```
Exploitation source IPs (4 of 6 published, per pipeline data):
139.28.37[.]250
151.241.99[.]207
151.241.99[.]233
158.62.198[.]182
```

> **SOC Action:** Immediately restrict management interface access to a management-only network segment or allow-listed jump hosts — never expose Security Management / Multi-Domain Management to the internet. Apply the latest Jumbo hotfix. Block and hunt the four source IPs across perimeter and management-plane logs, and audit GaiaOS WebUI accounts for unexpected privilege changes or new administrative logins (T1078, T1548).

### 3.2 Ongoing PLC Exploitation Against U.S. Critical Infrastructure (CISA AA26-097A)
**Source:** [Trend Micro / AlienVault OTX](https://www.trendmicro.com/en_us/research/26/g/plc-exploitation.html)

Six federal agencies (FBI, CISA, NSA, EPA, DoE, and U.S. Cyber Command) revised joint advisory **AA26-097A** on 22 July 2026, warning that nation-state and APT actors are actively exploiting internet-facing programmable logic controllers (PLCs) across U.S. government services, water systems, and energy infrastructure. Attackers scan for exposed PLCs, connect using legitimate engineering software as an authorized technician would, then alter controller logic and manipulate operator (HMI) displays so personnel cannot visually detect the tampering. Unlike a largely disruption-free 2023 campaign, this activity has caused **confirmed operational disruption and financial loss**. The July update widens manufacturer scope beyond Rockwell/Allen-Bradley to **Schneider Electric and Siemens**, and adds detection guidance for malicious changes hidden in shared, reusable code modules. Pipeline data associates the activity with the **Cyber Av3ngers** intrusion set (IRGC-CEC) and the **IOCONTROL** malware family. Techniques include network service scanning (T1046), external remote services (T1133), valid accounts (T1078/T1078.003), indicator removal (T1070.004), and impair-defenses (T1562.001).

#### Indicators of Compromise
```
Domains:
ocferda[.]com
tylarion867mino[.]com
uuokhhfsdlk.tylarion867mino[.]com

IPs:
135.136.1[.]133      141.11.164[.]153
175.110.121[.]39     175.110.121[.]42     175.110.121[.]107
185.225.17[.]225     192.142.54[.]79      79.133.46[.]209
84.200.205[.]165     88.80.150[.]199      88.80.150[.]200
88.80.150[.]202      185.82.73[.]162      185.82.73[.]164
185.82.73[.]165      185.82.73[.]167      185.82.73[.]168
185.82.73[.]170      185.82.73[.]171      185.82.73[.]175
```

> **SOC Action:** Enumerate all internet-facing PLCs/HMIs (Rockwell, Schneider Electric, Siemens) and remove them from direct internet exposure; place OT behind VPN with MFA and network segmentation. Cross-reference the IOC IPs/domains against firewall, NetFlow, and OT DMZ logs. Baseline and monitor controller project files (e.g., .ACD) for unauthorized logic changes, and validate HMI display integrity against controller state independently. Review AA26-097A detection guidance for tampering hidden in shared code modules.

### 3.3 Clop Extortion Campaign Against PTC Windchill and FlexPLM
**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/clop-ransomware-targets-windchill-flexplm-in-data-theft-attacks/)

The Clop (Cl0p) extortion group is targeting internet-exposed PTC **Windchill** and **FlexPLM** product-lifecycle-management instances in a data-theft campaign, consistent with the group's established pattern of mass-exploiting a single enterprise application to exfiltrate data before extortion (T1190, T1485). PLM systems hold engineering, design, and supply-chain IP, making exposed instances high-value targets.

> **SOC Action:** Inventory and remove internet exposure of PTC Windchill and FlexPLM; place them behind VPN/SSO with MFA. Hunt for anomalous bulk reads/exports from PLM databases and unfamiliar service-account activity (T1485). Prioritize vendor patch levels on these appliances and monitor egress for large outbound transfers to unknown destinations.

### 3.4 Shai-Hulud npm Supply-Chain Worm Resurfaces in intercom-client@7.0.4
**Source:** [AlienVault OTX](https://otx.alienvault.com/pulse/6a62bd8f2c1c294fc422b9b7)

The Intercom TypeScript library **intercom-client@7.0.4** (361,510 weekly downloads) was published with malicious code that executes a `preinstall` hook, downloads the Bun runtime, and extracts GitHub credentials via `gh auth token` (T1059, T1204). Command-and-control abuses GitHub's commit-search API to query strings embedded in public repositories, blending C2 into a legitimate service (T1071.001). The tradecraft matches prior **Shai-Hulud** compromises, which self-propagate worm-like by reusing stolen credentials to poison additional npm packages — the November 2025 wave affected over 1,000 packages.

#### Indicators of Compromise
```
C2 hostname: zero.masscan[.]cloud
Malicious package: intercom-client@7.0.4 (npm)
```

> **SOC Action:** Pin/deny intercom-client@7.0.4 in dependency manifests and lockfiles; roll back to a known-good version. Block `zero.masscan[.]cloud` at DNS/egress. Rotate any GitHub tokens on CI runners or developer hosts that installed the package, and disable npm install scripts in CI (`--ignore-scripts`) where feasible. Hunt build logs for unexpected Bun runtime downloads and `gh auth token` invocations during dependency install (T1204).

### 3.5 Autonomous AI-Agent Espionage Against Thailand's Ministry of Finance
**Source:** [Hunt.io / AlienVault OTX](https://hunt.io/blog/thailand-ministry-finance-targeted-with-hermes-ai-agent)

Hunt.io and researcher Bob Diachenko identified three open directories (585 files, 470 MB) on 43.246.208[.]207 (AS132883, Hong Kong) staging an intrusion into Thailand's Ministry of Finance from 9–13 July 2026. The operation was largely driven by **Hermes**, an autonomous AI agent run in unattended "YOLO" mode that enumerated ministry hosts and captured LinPEAS output without operator approval prompts. The actor deployed an unreported Go implant named **Hades** (with ShadowPad/POISONPLUG.SHADOW and VShell tooling), suo5 HTTP tunnels, and webshells, and staged exploits including CVE-2021-4034 (PwnKit) and CVE-2021-3156 (sudo) alongside newer CVEs, targeting government and finance across eleven countries. Techniques span exploit public-facing application (T1190), webshell (T1505.003), scheduled task (T1053), and screen capture (T1113).

#### Indicators of Compromise
```
IPs:
43.246.208[.]207   103.97.0[.]57   202.181.27[.]115

Domain / hostname:
mail4[.]pl
redhatupdating432.dnsrd[.]com

SHA-256 (selected):
0f8c905aa25c86f85454acb7e77bf5c50220c2a82e5b69a33741e55c8a85f2fc
2a4cb412efa93fed7c3b3b3e49d6247b11a95ce9fddf71d9fe9db8e5f0068e0d
5633bc0033fde3aad929d6cbd47c554e264180360b017aae04687c2d6d83f753
```

> **SOC Action:** Patch the staged legacy Linux privilege-escalation CVEs (CVE-2021-4034, CVE-2021-3156) across the estate — they remain reliable post-access escalators. Block the listed IPs/domains and hunt for suo5 tunneling and webshell drops on internet-facing web/mail infrastructure (T1505.003). Alert on hardcoded-credential HiveServer2/WebHDFS access to Hadoop clusters, and monitor for unattended agent-like command bursts (rapid, sequential enumeration) in shell/EDR telemetry.

### 3.6 Additional High-Priority Activity
**Sources:** [BleepingComputer — hotel Wi-Fi DNS](https://www.bleepingcomputer.com/news/security/hackers-hijack-hotel-wi-fi-dns-to-steal-microsoft-365-accounts/), [AlienVault OTX — Kimsuky APT](https://otx.alienvault.com/pulse/6a635bdf995351cf539c3b56)

Attackers are altering DNS settings on hotel and conference-center guest Wi-Fi to redirect corporate travelers to counterfeit Microsoft 365 login pages for credential theft (T1566). Separately, AhnLab's June 2026 review attributes multiple spear-phishing APT campaigns against South Korea to **Kimsuky**, using LNK-file lures to deliver XenoRAT, PebbleDash, and AutoIt/Python backdoors with Task Scheduler persistence and DLL side-loading (T1566.001, T1547.001). An AD CS domain-controller impersonation vulnerability (CVE-2026-54121, "Certighost") was also circulating via restricted-distribution channels — treat as awareness-only pending vendor confirmation.

#### Indicators of Compromise
```
Kimsuky lure domains:
bohyeonsanvil[.]com
kumhosports[.]com
```

> **SOC Action:** Advise travelling staff to use corporate VPN on untrusted Wi-Fi and to verify the Microsoft 365 URL/certificate before authenticating; enforce phishing-resistant MFA (FIDO2). Block the Kimsuky lure domains and hunt for LNK execution spawning PowerShell/`curl.exe` from user download/temp paths (T1204.002, T1059.001). Review AD CS enrollment permissions for low-privilege certificate-request abuse.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of cloud services/infrastructure focused on elevation of privilege | CVE-2026-58275 (Azure DNS EoP); CVE-2026-58630 (Azure App Service on Azure Stack Hub EoP) |
| 🔴 **CRITICAL** | Russia-linked phishing campaigns exploiting Zimbra webmail vulnerabilities | "Russian State-Supported Cyber Actors…Zimbra Collaboration Suite"; "International alert…Russia-linked attacks on Zimbra webmail" |
| 🟠 **HIGH** | Increased ransomware activity across multiple sectors, Play Ransomware particularly active | The DeBruler / Record Go Alquiler / Restaurant Depot (all By Play) |
| 🟠 **HIGH** | Increased ransomware targeting healthcare and manufacturing | Bulwark Exterminating (killsec3); Wunschkind Klinik Dr Brunbauer (the gentlemen) |
| 🟡 **MEDIUM** | Exploitation of DNS vulnerabilities across applications | CVE-2026-55991 (libngtcp2 DoQ); CVE-2026-12080 (qemu-guest-agent symlink LPE) |
| 🟡 **MEDIUM** | Phishing sustained as a primary entry vector | inc ransom postings; New Dolphin X AI-targeting malware |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (108 reports) — RaaS group; multiple leak-site postings this period (Ejército Argentino, Highline Community College, Stryker, Kean University)
- **The Gentlemen** (104 reports) — extortion actor using Tox comms; targeted Advanced Marketing across MX/AT/CA/US
- **DragonForce** (42 reports) — RaaS collective offering customizable affiliate payloads; new victim "ID engineering"
- **Akira** (25 reports) — double-extortion, VMware ESXi and unpatched VPN focus; new victim "Emerge2 Digital"
- **Inc Ransom** (17 reports) — active against healthcare/industrial domains (autismuslink.ch, cabincreekhealth.com)
- **Nova** (17 reports) — RALord rebrand, captcha-gated RaaS leak site

### Malware Families
- **RansomLook** (129 reports) — leak-site parser tag spanning most ransomware postings this period
- **Tox1 / Tox** (57 / 30 reports) — Tox messaging protocol used for actor C2/negotiation (The Gentlemen, Qilin, payoutsking)
- **PLAY Ransomware** (multiple) — intermittent-encryption ransomware; sustained new-victim activity
- **IOCONTROL** — ICS/OT malware referenced in the PLC critical-infrastructure advisory
- **XenoRAT / PebbleDash** — RATs delivered in Kimsuky spear-phishing against South Korea

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 18 | [link](https://www.ransomlook.io/) | Ransomware leak-site postings (Play, Qilin, The Gentlemen, Akira, Inc Ransom, Nova) |
| BleepingComputer | 9 | [link](https://www.bleepingcomputer.com/news/security/clop-ransomware-targets-windchill-flexplm-in-data-theft-attacks/) | Clop/Windchill, hotel Wi-Fi DNS hijack, Dolphin X, Origin Energy breach |
| AlienVault | 5 | [link](https://otx.alienvault.com/pulse/6a6375b8843a154abdf4a0f0) | CVE-2026-16232 advisory, PLC exploitation, Shai-Hulud, Thailand MoF, Kimsuky |
| Unknown | 5 | — | Telegram-sourced (Certighost/AD CS) and Devs Palace ERP CVE alerts |
| Microsoft | 3 | [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59677) | seunshare (CVE-2026-59677/59676) and xfs (CVE-2026-64600) advisories |
| RecordedFutures | 2 | [link](https://therecord.media/wrench-attacks-against-cryptocurrency-holders) | Crypto "wrench" attacks; UK cyber-policy continuity |
| Wired Security | 1 | [link](https://www.wired.com/story/satellite-images-reveal-how-giant-scam-compounds-keep-on-expanding/) | Satellite OSINT on Myanmar scam compounds |
| SANS | 1 | [link](https://isc.sans.edu/diary/rss/33182) | ISC Stormcast daily podcast (threat level green) |
| BellingCat | 1 | [link](https://www.bellingcat.com/news/2026/07/24/shahed-type-drones-filmed-during-attack-on-mali-villages/) | Geolocated Shahed-136 drone strikes in Mali |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/agentic-soc-token-budget-architecture) | Agentic SOC cost-architecture research |
| Schneier | 1 | — | Essay on an AI "Genie coefficient" |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Remove Check Point Security/Multi-Domain Management interfaces from direct internet exposure, apply the latest Jumbo hotfix for CVE-2026-16232, and hunt the four exploitation source IPs across management-plane logs (ref. 3.1).
- 🔴 **IMMEDIATE:** Inventory and de-expose internet-facing PLCs/HMIs (Rockwell, Schneider Electric, Siemens) per CISA AA26-097A; cross-check IOC IPs/domains against OT DMZ logs and validate controller logic and HMI display integrity (ref. 3.2).
- 🟠 **SHORT-TERM:** Remove internet exposure of PTC Windchill/FlexPLM and block/rotate around the Shai-Hulud npm compromise — deny intercom-client@7.0.4, block zero.masscan[.]cloud, and rotate GitHub tokens on affected CI/dev hosts (ref. 3.3, 3.4).
- 🟠 **SHORT-TERM:** Patch legacy Linux LPE CVEs (CVE-2021-4034, CVE-2021-3156) staged in the Thailand MoF operation and hunt for suo5 tunnels/webshells on internet-facing web and mail infrastructure (ref. 3.5).
- 🟡 **AWARENESS:** Brief travelling staff on hotel/conference Wi-Fi DNS-hijack M365 phishing and enforce VPN + phishing-resistant MFA; block Kimsuky lure domains and monitor LNK→PowerShell execution (ref. 3.6).
- 🟢 **STRATEGIC:** Treat cloud-service privilege-escalation (Azure EoP) and Russia-linked Zimbra webmail phishing as sustained critical trends — prioritize webmail patching, tenant privilege reviews, and conditional-access hardening (ref. 4).

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 47 reports processed across 2 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
