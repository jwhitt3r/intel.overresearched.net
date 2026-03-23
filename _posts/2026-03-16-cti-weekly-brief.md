---
layout: post
title: "CTI Weekly Brief: 16 Mar – 22 Mar 2026 — Trivy Supply-Chain Compromise, Cisco FMC Zero-Day Exploitation, and FBI Dismantles Iranian MOIS Infrastructure"
date: 2026-03-23 09:15:00 +0000
description: "A high-tempo week dominated by the TeamPCP supply-chain attack on Trivy GitHub Actions, active zero-day exploitation of Cisco Secure FMC by Interlock ransomware, FBI seizures of Iranian Handala infrastructure after the Stryker wiper incident, and the DarkSword iOS exploit chain proliferating across multiple threat actors."
category: weekly
tags: [cti, weekly-brief, teampcp, interlock, handala, darksword, qilin, nightspire]
classification: TLP:CLEAR
severity: critical
reporting_period_start: "2026-03-16"
reporting_period_end: "2026-03-22"
generated: "2026-03-23"
draft: false
report_count: 365
sources:
  - Microsoft
  - BleepingComputer
  - AlienVault
  - RecordedFutures
  - RansomLock
  - CISA
  - SANS
  - Wired Security
  - Unit42
  - Crowdstrike
  - Elastic Security Labs
  - Krebs on Security
  - Upwind
  - Wiz
---
| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 16 Mar – 22 Mar 2026 (7d) | TLP:CLEAR | 2026-03-23 |

## 1. Executive Summary

The CognitiveCTI pipeline processed 365 reports from 15+ sources during the week of 16–22 March 2026. Eighty reports were rated critical and 112 high, reflecting the most active week of the month so far. Three dominant storylines shaped the landscape: a sophisticated supply-chain compromise of the Trivy vulnerability scanner by the TeamPCP threat group that poisoned GitHub Actions workflows affecting potentially 10,000+ downstream repositories; confirmed zero-day exploitation of a max-severity Cisco Secure Firewall Management Center flaw (CVE-2026-20131) by the Interlock ransomware gang since late January, prompting CISA to mandate federal patching by 22 March; and the FBI's seizure of four domains tied to Iran's Ministry of Intelligence and Security (MOIS) following the Handala group's destructive wiper attack on medical technology giant Stryker that erased approximately 80,000 devices.

Additional high-impact developments include Google Threat Intelligence Group's disclosure of the DarkSword iOS exploit chain leveraging six zero-day vulnerabilities and now adopted by multiple state-sponsored actors; active exploitation of a critical Microsoft SharePoint RCE flaw (CVE-2026-20963); Oracle's emergency out-of-band patch for an unauthenticated RCE in Identity Manager (CVE-2026-21992); and a coordinated U.S.–Canadian–German takedown of four IoT botnets (Aisuru, Kimwolf, JackSkid, Mossad) responsible for record-breaking DDoS campaigns. Ransomware activity remained elevated with Qilin, Nightspire, and Interlock driving the bulk of victim claims.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 80 | Cisco FMC zero-day; Trivy supply-chain compromise; Oracle Identity Manager RCE; SharePoint RCE exploitation; DarkSword iOS chain; Chromium WebRTC/Blink/V8 CVEs; CISA ICS advisories |
| 🟠 **HIGH** | 112 | Qilin ransomware campaign; Nightspire multi-sector targeting; Phishing campaigns abusing Azure Monitor; Libsoup HTTP smuggling; Microsoft product CVE batch |
| 🟡 **MEDIUM** | 137 | Chromium DevTools and policy bugs; Linux kernel netfilter/apparmor fixes; AI-assisted malware analysis; Citrix zero-day retrospective |
| 🟢 **LOW** | 14 | Samsung compatibility advisories; Minor policy implementation issues |
| 🔵 **INFO** | 22 | SANS ISC Stormcasts; General security awareness content |

## 3. Priority Intelligence Items

### 3.1 Trivy Supply-Chain Compromise via GitHub Actions Tag Poisoning (TeamPCP)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/trivy-vulnerability-scanner-breach-pushed-infostealer-via-github-actions/), [Upwind](https://www.upwind.io/feed/trivy-supply-chain-incident-github-actions-compromise-breakdown), [Wiz](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack), [AlienVault](https://otx.alienvault.com/pulse/69bd18a7cc27dfdfaf6f56a4)

The threat group TeamPCP (also tracked as DeadCatx3, PCPcat, ShellForce, CipherForce) compromised the Aqua Security Trivy vulnerability scanner through a second-stage attack exploiting credentials that survived an incomplete rotation after a prior February breach by an autonomous AI bot (hackerbot-claw). The attackers force-pushed 75 of 76 version tags in the `aquasecurity/trivy-action` GitHub repository to malicious commits, silently replacing `entrypoint.sh` with an infostealer payload. Any workflow referencing these tags executed attacker code before running legitimate scans.

The infostealer harvested SSH keys, cloud credentials (AWS, GCP, Azure, Kubernetes), CI/CD secrets, database configurations, TLS private keys, cryptocurrency wallets, and shell history. Data was encrypted into `tpcp.tar.gz` and exfiltrated to a typosquatted C2 at `scan.aquasecurtiy[.]org`. A fallback mechanism created a public repository named `tpcp-docs` in the victim's GitHub account. Trojanized binaries propagated to GitHub Releases, Docker Hub, GHCR, and Amazon ECR. Additional credentials (GPG keys, Docker Hub, Twitter, Slack) were exfiltrated via a Cloudflare Tunnel endpoint at `plug-tab-protective-relay.trycloudflare[.]com`.

**MITRE ATT&CK:** T1195.002 (Supply Chain Compromise), T1552 (Unsecured Credentials), T1567.002 (Exfiltration to Cloud Storage), T1078 (Valid Accounts), T1059.004 (Unix Shell)

#### Indicators of Compromise
```
C2: scan.aquasecurtiy[.]org
C2: plug-tab-protective-relay.trycloudflare[.]com
SHA256: 18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a
Exfil archive: tpcp.tar.gz
Fallback repo: tpcp-docs (created in victim GitHub accounts)
```

> **SOC Action:** Audit all GitHub Actions workflows referencing `aquasecurity/trivy-action` — pin to full commit SHA, not mutable tags. Rotate any CI/CD secrets that may have been exposed since 19 March. Search for outbound connections to `scan.aquasecurtiy[.]org` and `*.trycloudflare[.]com` in proxy/DNS logs. Check GitHub accounts for unexpected `tpcp-docs` repositories.

### 3.2 Cisco Secure FMC Zero-Day Exploited by Interlock Ransomware (CVE-2026-20131)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-cisco-flaw-by-sunday/), [Recorded Future](https://therecord.media/cisco-ransomware-interlock-firewalls)

CISA mandated federal agencies patch CVE-2026-20131 in Cisco Secure Firewall Management Center by 22 March after Amazon threat intelligence researchers confirmed the Interlock ransomware gang exploited the vulnerability as a zero-day since 26 January — more than five weeks before Cisco published the advisory on 4 March. The flaw is an insecure deserialization of a user-supplied Java byte stream in the web management interface, enabling unauthenticated remote code execution as root. No workarounds exist.

Interlock, active since September 2024, has claimed high-profile victims including DaVita, Kettering Health, Texas Tech University System, and the city of Saint Paul, Minnesota. Amazon researchers discovered the exploitation through a misconfigured Interlock staging server containing custom malware, reconnaissance scripts, and the ransomware negotiation portal. The group uses ClickFix for initial access alongside custom RATs NodeSnake and Slopoly. Analysts have identified possible links between Interlock and Rhysida. Operators appear to work in the UTC+3 timezone.

**MITRE ATT&CK:** T1210 (Exploitation of Remote Services), T1059.001 (PowerShell)

> **SOC Action:** Immediately verify Cisco Secure FMC instances are patched to a version addressing CVE-2026-20131. If unable to patch, restrict web management interface access to trusted management networks only. Hunt for indicators of Interlock post-exploitation: NodeSnake and Slopoly malware families, ScreenConnect/ConnectWise usage, and ClickFix-style initial access lures.

### 3.3 FBI Seizes Iranian MOIS / Handala Infrastructure After Stryker Wiper Attack

**Source:** [Recorded Future](https://therecord.media/fbi-takes-down-leak-sites-iran-mois), [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-seizes-handala-data-leak-site-after-stryker-cyberattack/)

The FBI seized four domains — `Justicehomeland[.]org`, `Handala-Hack[.]to`, `Karmabelow80[.]org`, and `Handala-Redwanted[.]to` — used by Iran's Ministry of Intelligence and Security (MOIS) operating under the Handala moniker. The seizure followed Handala's destructive attack on medical technology company Stryker, in which the group compromised a Windows domain administrator account, created a Global Administrator account, and issued Microsoft Intune's native "wipe" command to factory-reset approximately 80,000 corporate and personal devices across the U.S., Ireland, India, and other countries.

The attack directly disrupted emergency medical services in Maryland hospitals, forcing clinicians to rely on radio communication. Court documents tied Handala to MOIS operations dating to 2022, including attacks on Albania's government and the targeting of Israeli Defence Force personnel. Handala has acknowledged the seizures on Telegram and stated it is building new infrastructure.

> **SOC Action:** Review Microsoft Intune hardening guidance released jointly by Microsoft and CISA. Enforce conditional access policies, limit Global Administrator privileges, and enable tamper protection on Intune-managed devices. Monitor for creation of new Global Admin accounts and anomalous Intune wipe commands. Block the seized domains at your perimeter.

### 3.4 DarkSword iOS Exploit Chain Proliferating Across State-Sponsored Actors

**Source:** [AlienVault / Google TAG](https://otx.alienvault.com/pulse/69bac861fe18a3b724f976fe)

Google Threat Intelligence Group disclosed DarkSword, a full-chain iOS exploit leveraging six zero-day vulnerabilities targeting iOS 18.4 through 18.7. Since November 2025, multiple commercial surveillance vendors and suspected state-sponsored actors — including UNC6353, a suspected Russian espionage group — have deployed DarkSword in campaigns targeting users in Saudi Arabia, Turkey, Malaysia, and Ukraine. The exploit chain delivers three distinct malware families: GHOSTBLADE, GHOSTKNIFE, and GHOSTSABER. UNC6353 incorporated DarkSword into watering-hole campaigns on compromised Ukrainian websites. The proliferation mirrors the earlier Coruna iOS exploit kit pattern.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1203 (Exploitation for Client Execution), T1068 (Exploitation for Privilege Escalation), T1113 (Screen Capture), T1123 (Audio Capture)

#### Indicators of Compromise
```
Domain: 0x436cc4[.]open
Domain: snapshare[.]chat
Domain: sahibndn[.]io
Host: static.cdncounter[.]net
Host: e5.malaymoil[.]com
Host: sqwas.shapelie[.]com
SHA256: 2e5a56beb63f21d9347310412ae6efb29fd3db2d3a3fc0798865a29a3c578d35
```

> **SOC Action:** Ensure all managed iOS devices are updated to iOS 18.8 or later. Monitor MDM telemetry for devices running iOS 18.4–18.7. Block the listed C2 domains and hostnames at DNS and proxy layers. High-risk users in government and diplomatic roles should verify device integrity through Apple's Lockdown Mode.

### 3.5 Microsoft SharePoint RCE Actively Exploited (CVE-2026-20963)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/critical-microsoft-sharepoint-flaw-now-exploited-in-attacks/)

CISA confirmed active exploitation of CVE-2026-20963, a critical deserialization vulnerability in Microsoft SharePoint Server patched in January 2026. The flaw enables unauthenticated remote code execution in low-complexity attacks. Affected versions include SharePoint Enterprise Server 2016, SharePoint Server 2019, and SharePoint Server Subscription Edition. End-of-support versions (2007, 2010, 2013) are also vulnerable but no longer receive updates. CISA ordered FCEB agencies to patch by 21 March.

**MITRE ATT&CK:** T1210 (Exploitation of Remote Services)

> **SOC Action:** Verify all SharePoint Server instances are patched against CVE-2026-20963. Organisations running end-of-support SharePoint versions should migrate to a supported version immediately. Monitor IIS logs for anomalous POST requests to SharePoint endpoints indicative of deserialization exploitation.

### 3.6 CVE-2026-33017: Langflow AI Pipeline RCE Exploited Within 20 Hours

**Source:** [Sysdig / AlienVault](https://www.sysdig.com/blog/cve-2026-33017-how-attackers-compromised-langflow-ai-pipelines-in-20-hours)

CVE-2026-33017 is an unauthenticated remote code execution vulnerability in Langflow, the popular open-source platform for building AI agent workflows (145,000+ GitHub stars). The flaw allows arbitrary Python code execution via the public flow build endpoint (`POST /api/v1/build_public_tmp/{flow_id}/flow`). Sysdig TRT observed exploitation 20 hours after advisory publication — without a public PoC. Attackers built working exploits directly from the advisory description, scanning for vulnerable instances and exfiltrating credentials and database keys. This represents a significant AI supply-chain risk.

#### Indicators of Compromise
```
IP: 83.98.164[.]238
Host: d6tcpc6flblph01gdcb0ku9ixih393m54.oast[.]live
Host: d6tcpe7nsv6kk9rdrpggi37zmjfxw9imr.oast[.]me
Host: d6td5s9qte0bea7273e0wuou77jjx77uk.oast[.]pro
Host: d6tgbe1qte0a8rkffb3gqabqm8517exd3.oast[.]fun
```

> **SOC Action:** Immediately patch or restrict access to any internet-facing Langflow instances. If patching is not possible, disable the public flow build endpoint. Audit Langflow instances for unexpected outbound connections to OAST (out-of-band application security testing) domains. Review connected database credentials for signs of compromise.

### 3.7 U.S./Canada/Germany Dismantle Record-Breaking IoT Botnets

**Source:** [Krebs on Security](https://krebsonsecurity.com/2026/03/feds-disrupt-iot-botnets-behind-huge-ddos-attacks/), [Wired Security](https://www.wired.com/story/us-takes-down-botnets-used-in-record-breaking-cyberattacks/)

The DOJ, supported by law enforcement in Canada and Germany, dismantled infrastructure behind four IoT botnets — Aisuru, Kimwolf, JackSkid, and Mossad — that compromised over three million devices (routers, cameras) and launched hundreds of thousands of DDoS attacks. Aisuru alone issued 200,000+ attack commands; JackSkid issued 90,000+. Kimwolf introduced a novel spreading mechanism enabling propagation within victims' internal networks. Suspects include a 22-year-old Canadian and a 15-year-old in Germany.

> **SOC Action:** Verify IoT device firmware is current and default credentials are changed. Segment IoT devices onto isolated VLANs with restricted outbound access. Monitor for anomalous traffic volumes from network-connected cameras and routers.

### 3.8 Oracle Identity Manager Emergency Patch (CVE-2026-21992)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/oracle-pushes-emergency-fix-for-critical-identity-manager-rce-flaw/)

Oracle released an out-of-band security update for CVE-2026-21992 (CVSS 9.8), an unauthenticated RCE in Oracle Identity Manager versions 12.2.1.4.0 and 14.1.2.1.0 and Oracle Web Services Manager. The flaw is remotely exploitable over HTTP with low complexity and no user interaction. Oracle has not confirmed whether the vulnerability has been exploited in the wild but declined to comment on its exploitation status.

> **SOC Action:** Apply the emergency patch immediately on all Oracle Identity Manager and Web Services Manager instances. If patching is delayed, restrict HTTP access to the management interface from untrusted networks. Monitor for unexpected process execution or outbound connections from Oracle middleware hosts.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **CRITICAL** | Exploitation of zero-day vulnerabilities in Citrix products | Citrix CVE-2025-6543 used as zero-day since May 2025; Citrix Netscaler backdoors targeting governments |
| 🔴 **CRITICAL** | CI/CD supply-chain attacks via GitHub Actions compromise | Trivy supply chain incident; widespread tag compromise affecting 10,000+ workflows |
| 🔴 **CRITICAL** | Increased exploitation of critical infrastructure and government sector vulnerabilities | Oracle Identity Manager RCE; FBI Iran MOIS takedown; CISA Cisco FMC emergency directive |
| 🔴 **CRITICAL** | Zero-day exploitation surging across mobile and network platforms | DarkSword iOS 6-vuln chain; Interlock Cisco FMC zero-day since January; Langflow RCE within 20h |
| 🟠 **HIGH** | Qilin ransomware group expanding operations across multiple sectors | Six confirmed victims in transport, real estate, technology, entertainment sectors in a single week |
| 🟠 **HIGH** | Phishing campaigns targeting cloud credentials via legitimate services | AWS console credential phishing; Azure Monitor callback phishing; Tycoon2FA PaaS platform persistence |
| 🟠 **HIGH** | Increased ransomware activity with overlapping TTPs across Nightspire, CipherForce, and Inc Ransom | Shared targeting of healthcare, finance, and manufacturing sectors |
| 🟠 **HIGH** | AI-assisted attack development and evasion techniques maturing | AI-assisted reverse engineering of IoT firmware; malware sandbox evasion using mathematical detection |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Handala / MOIS** (14 reports) — Iranian state-linked hacktivist group; FBI seized leak site infrastructure after Stryker wiper attack
- **Nightspire** (7 reports) — Ransomware group targeting healthcare, finance, and manufacturing across Europe
- **Void Manticore** (5 reports) — Iranian threat actor associated with destructive operations
- **Qilin** (4 reports) — Ransomware-as-a-service operator with six new victims this week across diverse sectors
- **TeamPCP / ShellForce / CipherForce** (4 reports) — Supply-chain attack group behind Trivy compromise; also tracked as DeadCatx3 and PCPcat
- **APT28 / Fancy Bear** (4 reports) — Russian GRU-linked espionage group; ongoing phishing campaigns
- **JackSkid** (4 reports) — Botnet operator; infrastructure disrupted in international law enforcement action
- **Aisuru** (4 reports) — IoT botnet operator; dismantled by DOJ, launched 200K+ DDoS commands
- **UNC6353** (4 reports) — Suspected Russian espionage group using DarkSword iOS exploits in Ukrainian watering-hole campaigns

### Malware Families

- **Slopoly** (4 reports) — Custom malware used by Interlock ransomware group
- **DarkSword** (3 reports) — iOS full-chain exploit kit deploying GHOSTBLADE, GHOSTKNIFE, GHOSTSABER
- **NodeSnake** (3 reports) — Custom RAT associated with Interlock ransomware operations
- **Perseus** (3 reports) — Android malware exfiltrating data from note-taking apps
- **ScreenConnect** (3 reports) — Legitimate RMM tool abused by multiple threat actors for persistent access
- **HijackLoader** (3 reports) — Modular loader used in multi-stage malware delivery
- **SILENTCONNECT** (2 reports) — Newly documented loader delivering ScreenConnect via VBScript and in-memory PowerShell
- **VoidStealer** (2 reports) — Chrome credential stealer using debug protocol
- **TeamPCP Cloud Stealer** (2 reports) — Infostealer deployed through Trivy supply-chain compromise
- **Interlock** (2 reports) — Ransomware used in Cisco FMC zero-day exploitation campaign

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft | 113 | [link](https://msrc.microsoft.com) | Chromium CVEs, kernel vulnerabilities, M365 Copilot and Azure service flaws |
| BleepingComputer | 47 | [link](https://www.bleepingcomputer.com) | Primary coverage of Trivy, Cisco FMC, Handala, SharePoint, and Oracle incidents |
| AlienVault | 42 | [link](https://otx.alienvault.com) | DarkSword iOS analysis, GitHub Actions IOCs, Langflow CVE-2026-33017, VoidStealer |
| RansomLock | 29 | [link](https://www.ransomlook.io) | Ransomware victim claims from Nightspire, CipherForce, Qilin, Inc Ransom, LeakedData |
| RecordedFutures | 25 | [link](https://therecord.media) | FBI Iran takedown, Interlock Cisco FMC, Android malware campaign |
| CISA | 16 | [link](https://www.cisa.gov) | KEV additions, ICS advisories (Schneider Electric, Mitsubishi, CTEK, IGL-Technologies) |
| SANS | 10 | [link](https://isc.sans.edu) | Daily ISC Stormcasts and handler diary entries |
| Wired Security | 8 | [link](https://www.wired.com/category/security/) | IoT botnet takedown, DarkSword mobile threat coverage |
| Unit42 | 6 | [link](https://unit42.paloaltonetworks.com) | Threat actor research and malware analysis |
| Crowdstrike | 5 | [link](https://www.crowdstrike.com/blog/) | Threat intelligence and adversary tracking |
| Elastic Security Labs | 4 | [link](https://www.elastic.co/security-labs) | SILENTCONNECT loader discovery and analysis |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com) | Vulnerability intelligence and threat research |
| Upwind | 3 | [link](https://www.upwind.io) | Trivy supply-chain incident forensic breakdown |
| Krebs on Security | 1 | [link](https://krebsonsecurity.com) | IoT botnet disruption and suspect identification |
| Wiz | 1 | [link](https://www.wiz.io/blog) | Trivy supply-chain attack comprehensive analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Cisco Secure Firewall Management Center against CVE-2026-20131 — actively exploited as a zero-day by Interlock ransomware since January 2026. No workarounds exist; restrict web management access if unable to patch immediately.

- 🔴 **IMMEDIATE:** Audit all GitHub Actions workflows referencing `aquasecurity/trivy-action` and rotate CI/CD secrets exposed since 19 March. Pin all GitHub Action references to immutable commit SHAs rather than mutable version tags.

- 🔴 **IMMEDIATE:** Patch Microsoft SharePoint Server against CVE-2026-20963 (deserialization RCE) — confirmed active exploitation. Migrate end-of-support SharePoint versions (2007/2010/2013) to supported releases.

- 🟠 **SHORT-TERM:** Apply Oracle's emergency patch for CVE-2026-21992 on all Identity Manager and Web Services Manager instances. Restrict HTTP access to management interfaces pending patch deployment.

- 🟠 **SHORT-TERM:** Update all managed iOS devices to 18.8+ to mitigate the DarkSword exploit chain. Enable Lockdown Mode for high-risk users in government and diplomatic roles. Block DarkSword C2 domains at DNS resolvers.

- 🟠 **SHORT-TERM:** Harden Microsoft Intune configurations following CISA/Microsoft guidance post-Stryker incident — enforce conditional access, restrict Global Admin creation, and enable tamper protection on all managed endpoints.

- 🟡 **AWARENESS:** Patch or isolate any internet-facing Langflow instances to address CVE-2026-33017 (unauthenticated RCE). The 20-hour exploit development timeline from advisory to in-the-wild exploitation highlights the need for rapid patching of AI infrastructure.

- 🟢 **STRATEGIC:** Implement GitHub Actions tag pinning policies organisation-wide. The Trivy incident demonstrates that mutable tag references in CI/CD pipelines represent a systemic supply-chain risk. Evaluate commit-SHA pinning and Sigstore verification for all third-party Actions.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 365 reports processed across 12 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
