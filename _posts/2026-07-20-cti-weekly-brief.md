---
layout: post
title:  "CTI Weekly Brief: 2026-07-20 to 2026-07-26 - Russian webmail espionage, active edge-appliance and SharePoint exploitation, and a broad RaaS surge"
date:   2026-07-27 08:20:00 +0000
description: "575 reports across the week: nation-state Zimbra webmail espionage (LAUNDRY BEAR/CL-STA-1114), confirmed PLC attacks on US critical infrastructure, active exploitation of SharePoint, SonicWall, Check Point, Palo Alto, ServiceNow and Langflow, and a heavy ransomware-as-a-service surge led by Qilin, The Gentlemen and DragonForce."
category: weekly
tags: [cti, weekly-brief, laundry-bear, qilin, cyber-av3ngers, cve-2025-66376, cve-2026-50522]
classification: TLP:CLEAR
reporting_period_start: "2026-07-20"
reporting_period_end: "2026-07-26"
generated: "2026-07-27"
draft: false
report_count: 575
severity: critical
sources:
  - CISA
  - Microsoft
  - BleepingComputer
  - Unit42
  - AlienVault
  - CertEU
  - SANS
  - Wiz
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-07-20 to 2026-07-26 (7d) | TLP:CLEAR | 2026-07-27 |

## 1. Executive Summary

The pipeline processed 575 reports across 15 sources this week, correlated over 14 analysis batches. The dominant story is a convergence of nation-state espionage and mass exploitation of internet-facing infrastructure. A multi-agency advisory (NSA, FBI, CISA, MIVD/AIVD and allies) attributed an ongoing zero-click Zimbra webmail espionage campaign to the Russian state-supported actor tracked as **LAUNDRY BEAR / Void Blizzard** (Unit 42 cluster **CL-STA-1114**), exploiting **CVE-2025-66376** to exfiltrate 90 days of victim email simply on message view. In parallel, six federal agencies confirmed active **PLC exploitation against US critical infrastructure** (water, energy, government), now causing real operational disruption and expanded to Schneider Electric and Siemens equipment, with activity linked to Iran-nexus **Cyber Av3ngers** and **IOCONTROL** malware.

Confirmed in-the-wild exploitation dominated the vulnerability picture. Attackers are stealing SharePoint machine keys via **CVE-2026-50522** to persist through patching; **wp2shell** WordPress flaws (**CVE-2026-63030 / CVE-2026-60137**) are being used to plant webshells; and a cluster of edge appliances fell to zero-days — **SonicWall SMA1000**, **Check Point SmartConsole/GaiaOS** (**CVE-2026-16232** exploited in the wild), and a **Palo Alto PAN-OS GlobalProtect** authentication bypass now weaponised by the **Qilin** ransomware gang. CISA ordered urgent federal patching of an actively exploited **Langflow** RCE, and a critical **ServiceNow** code-execution flaw (**CVE-2026-6875**) came under attack. Microsoft's July release added a critical **M365 Copilot RCE** (CVE-2026-50517) and a **Microsoft Account RCE** (CVE-2026-56165) alongside a large Azure elevation-of-privilege cluster. Ransomware-as-a-service remained the highest-volume category by far, with **Qilin, The Gentlemen, DragonForce, Genesis, Deadlock, Play and Akira** driving 354 high-severity postings and Clop separately claiming Windchill/FlexPLM data theft.

## 2. Severity Distribution

Counts reflect all 575 reports in the reporting period.

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 44 | Russian Zimbra webmail espionage; PLC attacks on US critical infrastructure; SharePoint, SonicWall, Check Point, Palo Alto, ServiceNow, Langflow, wp2shell exploitation; Microsoft July Azure/Copilot/Account CVEs |
| 🟠 **HIGH** | 354 | Ransomware-as-a-service surge (Qilin, The Gentlemen, DragonForce, Genesis, Deadlock, Play, Akira); Chromium browser CVEs; Clop data-theft |
| 🟡 **MEDIUM** | 102 | Kernel and library CVEs; phishing tooling; assorted vulnerability analyses |
| 🟢 **LOW** | 15 | Lower-impact advisories and single-source items |
| 🔵 **INFO** | 60 | Vendor and research background material |

## 3. Priority Intelligence Items

### 3.1 Russian State-Supported Zero-Click Zimbra Webmail Espionage (LAUNDRY BEAR / CL-STA-1114)

**Source:** [CISA AA26-204A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a), [Unit 42](https://unit42.paloaltonetworks.com/russian-webmail-espionage/)

A coalition of agencies — NSA, FBI, CISA, DCSA, DC3, Treasury, NCIS, the Netherlands MIVD/AIVD and Australia's ASD ACSC — warned that a Russian state-supported APT tracked primarily as **LAUNDRY BEAR** (overlapping with **Void Blizzard**, and with Unit 42's activity cluster **CL-STA-1114**) has compromised Western government and commercial organisations running the Zimbra Collaboration Suite since at least July 2025. The campaign abuses **CVE-2025-66376**, a view-based (zero-click) cross-site scripting flaw patched in November 2025 but still widely unremediated. Merely viewing a malicious email in a vulnerable webmail client triggers an obfuscated, Base64-encoded JavaScript payload delivered via an invisible SVG element. The payload exfiltrates the victim's last 90 days of email and search history, the organisation's Global Address List, login credentials, CSRF tokens and 2FA scratch codes to attacker C2. Targeting spans government, defense, transportation and financial organisations across NATO states, Ukraine, CIS countries and Africa. Unit 42 observed at least nine C2 IPs and nine domains, each active ~35 days on average.

> **SOC Action:** Confirm all Zimbra Collaboration Suite instances are patched past the November 2025 fix for CVE-2025-66376; treat any internet-exposed unpatched ZCS as presumed-compromised. Hunt webmail proxy/CDN logs for anomalous outbound POSTs from the webmail render context to newly-registered external domains, and for base64/SVG-embedded script in inbound HTML mail bodies. Force credential and session-token resets and revoke 2FA scratch codes for any account that opened suspect mail. Pull the C2 IOC list from the Unit 42 report for retro-hunt.

**MITRE ATT&CK:** T1566 (Phishing), T1071.001 (Web Protocols), T1003 (OS Credential Dumping)

### 3.2 Confirmed PLC Exploitation Against US Critical Infrastructure (Cyber Av3ngers / IOCONTROL)

**Source:** [Trend Micro / AlienVault OTX](https://www.trendmicro.com/en_us/research/26/g/plc-exploitation.html)

Six federal agencies (FBI, CISA, NSA, EPA, DOE and US Cyber Command) revised joint advisory **AA26-097A** on 22 July, warning that nation-state/APT actors are actively exploiting internet-facing programmable logic controllers across US water, energy and government facilities. Attackers scan for exposed PLCs and connect using legitimate engineering software the way an authorised technician would, then alter controller logic and — critically — manipulate operator HMI displays so staff cannot visually detect the tampering. Unlike a largely disruption-free 2023 campaign, this activity has caused **confirmed operational disruption and financial loss**. The July update widened the manufacturer scope beyond Rockwell Automation / Allen-Bradley to include **Schneider Electric and Siemens**, and added detection guidance for malicious changes hidden in shared, reusable code modules. Reporting links the activity to Iran-nexus **Cyber Av3ngers** and **IOCONTROL** malware.

#### Indicators of Compromise
```
Malware:   IOCONTROL, MALPDB
Domain:    ocferda[.]com
Domain:    tylarion867mino[.]com
Host:      uuokhhfsdlk.tylarion867mino[.]com
IP:        135.136.1[.]133
IP:        141.11.164[.]153
IP:        175.110.121[.]39
IP:        175.110.121[.]42
IP:        175.110.121[.]107
IP:        185.225.17[.]225
IP:        185.82.73[.]162
IP:        185.82.73[.]164
IP:        185.82.73[.]165
IP:        185.82.73[.]167
IP:        185.82.73[.]168
IP:        185.82.73[.]170
IP:        185.82.73[.]171
IP:        185.82.73[.]175
IP:        192.142.54[.]79
IP:        79.133.46[.]209
IP:        84.200.205[.]165
IP:        88.80.150[.]199
IP:        88.80.150[.]200
IP:        88.80.150[.]202
```

> **SOC Action:** Remove PLCs and engineering workstations from direct internet exposure; place them behind VPN with MFA and strict IP allow-listing. Block/alert on the C2 IOCs above at the perimeter and in OT DMZ egress. Baseline and integrity-monitor PLC project files (e.g., Rockwell .ACD) and controller logic, alerting on out-of-band changes and on HMI/display value mismatches versus sensor telemetry. Review Schneider Electric and Siemens assets, not just Rockwell/Allen-Bradley.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1133 (External Remote Services), T1078 (Valid Accounts), T1112 (Modify Registry/Data), T1070.004 (Indicator Removal), T1046 (Network Service Scanning)

### 3.3 SharePoint Machine-Key Theft for Post-Patch Persistence (CVE-2026-50522)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-sharepoint-rce-flaw-exploited-to-steal-machine-keys/), [CERT-EU 2026-009](https://cert.europa.eu/publications/security-advisories/2026-009/)

Attackers are actively exploiting **CVE-2026-50522**, a critical Microsoft SharePoint RCE, to steal server **machine keys** (ASP.NET `validationKey`/`decryptionKey`). Because the stolen keys allow attackers to forge valid `__VIEWSTATE` payloads, they retain authenticated access **even after the server is patched** — patching alone does not evict them. CERT-EU flagged the same critical SharePoint exposure in advisory 2026-009.

> **SOC Action:** Patch SharePoint immediately, then **rotate machine keys** on every affected server (`Update-SPMachineKey` / rotate `machineKey` in web.config) and recycle app pools — this is mandatory for eviction, not optional. Hunt IIS logs for anomalous `__VIEWSTATE` POSTs to `/_layouts/` and for `w3wp.exe` spawning `cmd.exe`/`powershell.exe`. Assume compromise on any server exposed before patching.

**MITRE ATT&CK:** T1078 (Valid Accounts), T1550.003 (Use Alternate Authentication Material)

### 3.4 Network Edge Appliance Zero-Days: SonicWall, Check Point and Palo Alto

**Source:** [BleepingComputer — SonicWall](https://www.bleepingcomputer.com/news/security/sonicwall-sma1000-flaws-exploited-as-zero-days-to-push-custom-malware/), [BleepingComputer — Check Point](https://www.bleepingcomputer.com/news/security/check-point-patches-smartconsole-zero-day-exploited-in-attacks/), [AlienVault OTX — Check Point advisory](https://otx.alienvault.com/pulse/6a6375b8843a154abdf4a0f0), [BleepingComputer — Palo Alto](https://www.bleepingcomputer.com/news/security/critical-globalprotect-vpn-bug-now-exploited-in-ransomware-attacks/)

Three separate edge-appliance vendors reported active zero-day exploitation this week. Two **SonicWall SMA1000** flaws were exploited for weeks to install custom malware on VPN appliances. **Check Point** disclosed and patched an actively exploited SmartConsole/GaiaOS chain — **CVE-2026-16232** (authentication bypass, exploited in the wild against management interfaces exposed directly to the internet without IP restrictions), plus **CVE-2026-62144** and **CVE-2026-62145** (auth-bypass-with-privilege-escalation and local privilege escalation in the GaiaOS WebUI). Separately, the **Qilin** ransomware gang is exploiting a critical **Palo Alto PAN-OS GlobalProtect authentication bypass** to breach networks, per Arctic Wolf — a direct pivot from initial-access flaw to ransomware.

#### Indicators of Compromise
```
Check Point exploitation source IPs:
IP:  139.28.37[.]250
IP:  151.241.99[.]207
IP:  151.241.99[.]233
IP:  158.62.198[.]182
```

> **SOC Action:** Remove all appliance management interfaces (SonicWall SMA, Check Point SmartConsole/Gaia WebUI, PAN-OS GlobalProtect admin) from direct internet exposure and enforce IP allow-listing. Apply the latest SonicWall firmware and Check Point Jumbo hotfix; patch PAN-OS GlobalProtect. Block the Check Point exploitation IPs above. Given Qilin's use of the Palo Alto flaw, prioritise VPN gateways for compromise assessment and review VPN auth logs for GlobalProtect logins bypassing MFA.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1133 (External Remote Services), T1078 (Valid Accounts), T1068 (Exploitation for Privilege Escalation), T1071.001 (Web Protocols)

### 3.5 wp2shell WordPress Mass Exploitation (CVE-2026-63030 / CVE-2026-60137)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-wp2shell-wordpress-flaws-exploited-to-install-webshells/), [SANS ISC](https://isc.sans.edu/diary/WordPress+Exploitation+Underway+CVE-2026-63030/), [AlienVault OTX](https://otx.alienvault.com/), [Wiz](https://www.wiz.io/)

The **wp2shell** vulnerability suite in WordPress Core — **CVE-2026-63030** and **CVE-2026-60137** — is under active exploitation to deploy persistent webshells and install malicious plugins on affected servers. SANS ISC confirmed exploitation underway from 20 July, and the flaws featured in CISA KEV additions during the week. Multiple independent sources (BleepingComputer, SANS, AlienVault, Wiz) corroborated in-the-wild activity, marking this a broad, opportunistic campaign against internet-facing WordPress.

> **SOC Action:** Update WordPress Core to the patched release immediately across all hosted sites. Hunt web roots for newly-created PHP files (`wp-content/uploads/`, `wp-content/plugins/`) with base64/eval webshell patterns, and review recently installed/activated plugins. Alert on POSTs to admin-ajax or REST endpoints followed by writes to web-accessible paths. Restrict outbound connections from web servers.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell)

### 3.6 Actively Exploited RCEs: ServiceNow and Langflow (CISA KEV)

**Source:** [BleepingComputer — ServiceNow](https://www.bleepingcomputer.com/news/security/critical-servicenow-code-execution-flaw-now-exploited-in-attacks/), [BleepingComputer — Langflow](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-langflow-rce-flaw/)

A critical code-execution flaw in the **ServiceNow AI Platform**, **CVE-2026-6875**, came under active exploitation per threat-intel firm Defused, enabling arbitrary command execution and unauthorised access. Separately, CISA issued an urgent directive ordering federal agencies to patch an actively exploited **remote code execution flaw in Langflow**, the visual framework for building AI agents. Both reflect a continuing theme of attackers targeting AI/automation tooling as high-value, often internet-exposed application surfaces.

> **SOC Action:** Inventory ServiceNow (especially AI Platform components) and Langflow deployments; apply vendor patches on an emergency basis and treat as KEV-priority. Restrict Langflow/ServiceNow admin and API surfaces to trusted networks. Query application and web logs for unexpected process execution, new integration/credential creation, and outbound connections from these hosts.

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1203 (Exploitation for Client Execution), T1078 (Valid Accounts)

### 3.7 Microsoft July 2026 Release: Copilot RCE, Account RCE and Azure EoP Cluster

**Source:** [Microsoft MSRC — M365 Copilot](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50517), [Microsoft MSRC Update Guide](https://msrc.microsoft.com/update-guide)

Microsoft's July release included two critical remote-code-execution issues of note: **CVE-2026-50517**, an M365 Copilot RCE via deserialization of untrusted data, and **CVE-2026-56165**, a Microsoft Account RCE. These sit alongside a large cluster of Azure elevation-of-privilege vulnerabilities across cloud services — Azure Kubernetes Service (**CVE-2026-56163**), Azure App Service on Azure Stack Hub (**CVE-2026-58630**), Azure DNS (**CVE-2026-58275**), Azure Red Hat OpenShift (**CVE-2026-56160**), Azure AI Search (**CVE-2026-56167**) and Azure Key Vault (**CVE-2026-62825**). Correlation analysis flagged "exploitation of vulnerabilities in cloud services with a focus on elevation of privilege" as a distinct critical trend. Separately, the **Windows LegacyHive** zero-day (local privilege escalation on fully-updated Windows) received free unofficial 0patch micropatches ahead of an official fix.

> **SOC Action:** Prioritise the Copilot (CVE-2026-50517) and Microsoft Account (CVE-2026-56165) RCEs in July patching. Review Azure RBAC and audit logs for anomalous role assignments and Key Vault access following the EoP disclosures. For LegacyHive, apply 0patch micropatches on endpoints that cannot wait for the official fix and monitor for unexpected SYSTEM-level token elevation from standard-user processes.

**MITRE ATT&CK:** T1204 (User Execution), T1068 (Exploitation for Privilege Escalation), T1078 (Valid Accounts)

### 3.8 Ransomware-as-a-Service Surge Across Sectors

**Source:** Aggregated from RansomLook leak-site monitoring and [BleepingComputer](https://www.bleepingcomputer.com/) correlation batches 239–252

Ransomware/RaaS was the highest-volume category of the week, driving the bulk of the 354 high-severity postings. Correlation analysis repeatedly flagged **Qilin** (116 reports, the week's most active actor), **The Gentlemen** (103), **DragonForce** (44), **Akira** (22), **Genesis**, **Deadlock**, **Nova**, **Play** and **Arcus Media** as running parallel double-extortion campaigns with overlapping TTPs (phishing for initial access, data encryption for impact) across construction, healthcare, real estate, manufacturing, finance, education, aviation and government targets globally. Notable individual claims include **Clop** targeting PTC Windchill/FlexPLM in data-theft attacks, and **ShinyHunters** leaks fuelling a $2,000 sextortion email wave. Qilin's exploitation of the Palo Alto GlobalProtect flaw (see 3.4) shows RaaS crews rapidly operationalising edge-appliance vulnerabilities for initial access.

> **SOC Action:** Prioritise the edge/VPN and public-app patches in items 3.3–3.6 — these are the initial-access vectors RaaS crews are using. Enforce phishing-resistant MFA on all external access, validate offline/immutable backups and rehearse restoration, and segment to limit lateral movement. Monitor for mass file-rename/encryption behaviour and for bulk outbound data transfer preceding encryption (double extortion). Track leak sites for early victim disclosure of your organisation or key suppliers.

**MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1566 (Phishing), T1204 (User Execution), T1190 (Exploit Public-Facing Application)

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Genesis group expanding across diverse sectors (real estate, healthcare, accounting) | Westlake Realty Group; Williams Accounting Professional; Infinity Pipeline Inc. |
| 🔴 CRITICAL | Qilin persistent RaaS operations targeting multiple sectors globally | Plitvička Jezera National Park; Jubilee Jobs; Guntert & Zimmerman; Principle Diagnostics Laboratory |
| 🔴 CRITICAL | Exploitation of vulnerabilities in software and infrastructure systems | Ongoing PLC exploitation vs US critical infrastructure; Certighost (CVE-2026-54121) AD CS; intercom-client GitHub credential harvesting |
| 🔴 CRITICAL | Cloud-service exploitation focused on elevation of privilege | Azure DNS EoP (CVE-2026-58275); Azure App Service on Azure Stack Hub EoP (CVE-2026-58630) |
| 🔴 CRITICAL | Phishing campaigns exploiting Zimbra webmail vulnerabilities | Russian state-supported Zimbra campaign (AA26-204A); Russia-linked attacks on Zimbra webmail |
| 🔴 CRITICAL | Webshell deployment via WordPress vulnerabilities | Critical wp2shell WordPress flaws exploited; CISA adds four KEV entries |
| 🔴 CRITICAL | Zero-day exploitation of VPN appliances to deploy custom malware | SonicWall SMA1000 zero-days pushing custom malware |
| 🟠 HIGH | Chromium-based browser vulnerabilities being exploited | Chromium CVE-2026-16804/16805/16806/16807 (use-after-free / OOB write) |
| 🟠 HIGH | RaaS groups increasingly targeting multiple sectors with overlapping TTPs | Deadlock, Genesis, DragonForce, Exfilsquad, Arcus Media, Play across retail/gov/education/finance |
| 🟠 HIGH | Phishing remains prevalent across ransomware and malware campaigns | Browser-memory malware build via JavaScript; ShinyHunters-fuelled sextortion |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (116 reports) — most active RaaS crew of the week; also exploiting the Palo Alto GlobalProtect flaw for initial access.
- **The Gentlemen** (103 reports) — high-volume double-extortion operation across multiple sectors.
- **DragonForce** (44 reports) — RaaS targeting retail, medical supply and bioresearch victims.
- **Akira** (22 reports) — continued broad sector targeting including technology and manufacturing.
- **Global Secret Group** (17 reports) — newly prominent actor; first and last seen within the week.
- **Deadlock** (16 reports) — active across construction, technology services and healthcare (Colombia, Thailand).
- **Genesis** (16 reports) — expanding into real estate, healthcare and accounting.
- **Nova** (16 reports) — RaaS activity across finance and public-sector targets.
- **Inc Ransom** (14 reports) — sustained leak-site postings.
- **ShinyHunters** (9 reports) — data leaks fuelling downstream sextortion scams.

### Malware Families
- **RansomLook** (144 reports) — leak-site/tracking taxonomy dominating volume.
- **DragonForce ransomware** (15 reports) — payload behind DragonForce victim claims.
- **RALord** (14 reports) — emerging ransomware family.
- **Chaos Ransomware** (13 reports) — active double-extortion payload.
- **The Gentlemen ransomware** (12 reports) — payload tied to the week's #2 actor.
- **Qilin** (11 reports) — payload behind the week's most active crew.
- **Akira ransomware** (11 reports) — sustained activity.
- **PLAY Ransomware** (9 reports) — multiple hospitality/retail campaigns.
- **IOCONTROL** — ICS-targeting malware in the PLC critical-infrastructure campaign.

## 6. Source Distribution

Counts reflect contributions across the reporting period.

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 218 | [link](https://www.ransomlook.io/) | Ransomware leak-site monitoring; drives the high-severity victim-posting volume |
| Microsoft | 180 | [link](https://msrc.microsoft.com/update-guide) | July release: Copilot/Account RCEs and the Azure EoP cluster, plus kernel/library CVEs |
| BleepingComputer | 58 | [link](https://www.bleepingcomputer.com) | Primary coverage of SharePoint, SonicWall, Check Point, Palo Alto, ServiceNow, Langflow exploitation |
| AlienVault | 31 | [link](https://otx.alienvault.com/) | OTX pulses incl. PLC critical-infrastructure IOCs and Check Point advisory |
| RecordedFutures | 22 | [link](https://www.recordedfuture.com/) | Threat-intel reporting |
| Unknown | 11 | — | Unattributed feed items (kernel/exploit-dev analyses) |
| SANS | 10 | [link](https://isc.sans.edu/) | ISC diary — confirmed wp2shell WordPress exploitation underway |
| Wired Security | 9 | [link](https://www.wired.com/category/security/) | Security news and analysis |
| Schneier | 7 | [link](https://www.schneier.com/) | Commentary and analysis |
| Wiz | 4 | [link](https://www.wiz.io/) | Cloud/exploitation research incl. wp2shell corroboration |
| Upwind | 4 | [link](https://www.upwind.io/) | ArgoCD XSS/cluster-takeover analysis (CVE-2026-xxxx) |
| Cisco Talos | 3 | [link](https://blog.talosintelligence.com/) | Threat research |
| CISA | 3 | [link](https://www.cisa.gov/) | AA26-204A (Zimbra/LAUNDRY BEAR) and KEV additions |
| Crowdstrike | 2 | [link](https://www.crowdstrike.com/blog/) | Adversary reporting |
| CertEU | 2 | [link](https://cert.europa.eu/) | Advisory 2026-009 — critical SharePoint vulnerabilities |
| Unit42 | — | [link](https://unit42.paloaltonetworks.com/) | Russian webmail espionage (CL-STA-1114) |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch and hunt on the actively-exploited edge/app surfaces — Zimbra (CVE-2025-66376), SharePoint (CVE-2026-50522, plus rotate machine keys), SonicWall SMA1000, Check Point (CVE-2026-16232/62144/62145), Palo Alto GlobalProtect, ServiceNow (CVE-2026-6875), Langflow, and wp2shell WordPress (CVE-2026-63030/60137). All are confirmed in-the-wild.
- 🔴 **IMMEDIATE:** For SharePoint, patching is insufficient — rotate ASP.NET machine keys and recycle app pools to evict attackers holding stolen keys (CVE-2026-50522).
- 🔴 **IMMEDIATE:** OT/ICS operators must pull PLCs and engineering workstations off the internet, block the AA26-097A / Cyber Av3ngers IOCs, and integrity-monitor controller logic and HMI values; extend review to Schneider Electric and Siemens gear.
- 🟠 **SHORT-TERM:** Deploy the Microsoft July updates with priority on M365 Copilot RCE (CVE-2026-50517) and Microsoft Account RCE (CVE-2026-56165); audit Azure RBAC/Key Vault after the EoP cluster; apply 0patch micropatches for the Windows LegacyHive zero-day where the official fix is not yet available.
- 🟠 **SHORT-TERM:** Enforce phishing-resistant MFA and IP allow-listing on all remote-access and management interfaces — the common initial-access theme behind both the RaaS surge and the edge-appliance zero-days.
- 🟡 **AWARENESS:** Apply the latest Chromium/browser updates addressing the exploited use-after-free/OOB-write CVEs (CVE-2026-16804/16805/16806/16807).
- 🟡 **AWARENESS:** Brief users on the ShinyHunters-driven $2,000 sextortion email wave and on view-based webmail exploits so they report — rather than dismiss — suspicious mail.
- 🟢 **STRATEGIC:** Validate immutable/offline backups and rehearse restoration; monitor RaaS leak sites (Qilin, The Gentlemen, DragonForce, Clop) for early disclosure of your organisation or key suppliers, and formalise cross-sector intelligence sharing for critical-infrastructure operators.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 575 reports processed across 14 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
