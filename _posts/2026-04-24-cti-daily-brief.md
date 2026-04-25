---
layout: post
title:  "CTI Daily Brief: 2026-04-24 - Shai-Hulud npm worm escalates, UAT-4356 Firestarter persists on Cisco firewalls, UNC6692 abuses Teams to drop Snow malware"
date:   2026-04-25 20:05:39 +0000
description: "Unit 42 details the post-Shai-Hulud npm supply chain landscape with TeamPCP republishing trojanised packages; CISA and NCSC warn that UAT-4356's Firestarter implant survives Cisco ASA/FTD patching; Mandiant exposes UNC6692 using Microsoft Teams helpdesk impersonation to deploy the Snow malware suite; ShinyHunters confirm vishing-led Salesforce theft from ADT; heavy Qilin RaaS activity dominates the leak sites."
category: daily
tags: [cti, daily-brief, qilin, teampcp, uat-4356, unc6692, shinyhunters, shai-hulud, firestarter, snow-malware]
classification: TLP:CLEAR
reporting_period: "2026-04-24"
generated: "2026-04-25"
draft: true
severity: critical
report_count: 53
sources:
  - Unit42
  - BleepingComputer
  - Microsoft
  - RansomLock
  - Wired Security
  - Schneier
  - Elastic Security Labs
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-24 (24h) | TLP:CLEAR | 2026-04-25 |

## 1. Executive Summary

The pipeline processed **53 reports across 8 sources** in the last 24 hours, with one critical-severity item driving the narrative. Unit 42 published a comprehensive update on the post-Shai-Hulud npm threat landscape, attributing a fresh wave of trojanised `@bitwarden/cli` packages and Docker Hub / VS Code distribution channels to the threat cluster **TeamPCP** and warning that wormable token theft is now systematic across CI/CD ecosystems. CISA and the UK NCSC issued a joint advisory on **Firestarter**, a kernel-resident backdoor that **UAT-4356 (the ArcaneDoor actor)** uses to maintain persistence on Cisco Firepower / Secure Firewall appliances even after firmware updates and security patches, with confirmed compromise of a US federal civilian agency dating to early September 2025. Mandiant exposed **UNC6692** abusing Microsoft Teams "IT helpdesk" impersonation to deploy a new modular malware family — **Snow / SnowBelt / SnowGlaze / SnowBasin** — culminating in LSASS dumping, Active Directory database extraction, and exfiltration via LimeWire. **ShinyHunters** confirmed the **ADT** breach as a vishing-driven Okta SSO compromise that pivoted into Salesforce, with the gang claiming 10M PII records and a 27 April leak deadline. Qilin RaaS continued to dominate the criminal leak-site space with 12+ new victims posted in a single day, while Microsoft published a large batch of Linux kernel CVEs (cdc_ncm, ksmbd, mac80211, mt76, NFC NCI) including the high-rated **CVE-2026-41205** Mako path-traversal flaw.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 1 | Unit 42: Shai-Hulud / TeamPCP npm supply chain wave |
| 🟠 **HIGH** | 27 | Qilin/Lamashtu/Inc Ransom/Nightspire/Brain Cipher leak posts; UNC6692 Snow malware; UAT-4356 Firestarter; TGR-STA-1030; CVE-2026-41205 Mako; Linux kernel CVEs (ksmbd, cdc_ncm, mac80211, NFC NCI) |
| 🟡 **MEDIUM** | 14 | ADT/ShinyHunters Salesforce breach; further Linux kernel CVEs (irdma, mt76, mvpp2, udp_tunnel, SRv6); Libopensc CVE-2025-13763 |
| 🟢 **LOW** | 1 | Windows Update forced-restart controls |
| 🔵 **INFO** | 10 | Telegram OSINT chatter; Leak Bazaar listings; Wired weekly roundup; Elastic OTel monitoring of Claude Code/Cowork; CVE-2026-41989 placeholder |

## 3. Priority Intelligence Items

### 3.1 Shai-Hulud "Third Coming" — TeamPCP weaponises npm, Docker Hub and VS Code distribution

**Source:** [Unit 42 — The npm Threat Landscape: Attack Surface and Mitigations](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

Unit 42 frames the September 2025 Shai-Hulud worm as the inflection point that ended the "nuisance" era of npm typosquatting and ushered in systematic supply-chain compromise. A malicious package published as `@bitwarden/cli` v2026.4.0 — impersonating the legitimate Bitwarden CLI — has been linked to a coordinated campaign attributed to **TeamPCP**. On install it executes a multi-stage payload that harvests cloud-provider credentials, CI/CD secrets and developer-workstation tokens, then self-propagates by backdooring every npm package the victim is authorised to publish. Public GitHub repositories pushed by the worm contain the marker string "Shai-Hulud: The Third Coming." The same payload has been observed across Docker Hub images, GitHub Actions and VS Code extensions, indicating that adversaries treat the package registries as a single, fungible distribution surface. Unit 42 highlights three durable shifts: wormable token theft (npm tokens + GitHub PATs), CI/CD-pipeline persistence, and dormant "sleeper" dependencies that activate only under specific environmental conditions.

**Affected:** npm ecosystem, Docker Hub, VS Code Marketplace, GitHub Actions, any organisation publishing or consuming JavaScript/TypeScript packages.

**MITRE ATT&CK:** T1195.002 (Compromise Software Supply Chain), T1059.001 (PowerShell), T1071 (Application Layer Protocol), T1552.001 (Credentials in Files).

> **SOC Action:** Block install of `@bitwarden/cli@2026.4.0` and any unsigned variant in your internal registry/proxy; rotate all npm publish tokens and GitHub Personal Access Tokens issued to developer machines or CI runners in the last 60 days; hunt EDR for `node` / `npm` / `npx` processes spawning child PowerShell or curl with outbound traffic during `postinstall`; query GitHub audit logs for newly created repositories or branches containing the string "Shai-Hulud" and revert; enforce npm provenance / `--ignore-scripts` in CI and require 2FA-on-publish for all internal package owners.

### 3.2 UAT-4356 / ArcaneDoor — Firestarter implant survives Cisco ASA/FTD patching

**Source:** [BleepingComputer — Firestarter malware survives Cisco firewall updates, security patches](https://www.bleepingcomputer.com/news/security/firestarter-malware-survives-cisco-firewall-updates-security-patches/)

CISA and the UK NCSC have released a joint malware analysis warning that the **Firestarter** ELF backdoor, attributed by Cisco Talos to **UAT-4356** (the actor behind the ArcaneDoor cyberespionage campaign), maintains persistence on Cisco Firepower and Secure Firewall appliances running ASA or FTD even after reboot, firmware update and patching. Initial access at a US federal civilian executive-branch agency was assessed to have occurred in early September 2025 — before patches under Emergency Directive 25-03 — via missing-authorization flaw **CVE-2025-20333** and buffer-overflow **CVE-2025-20362**. The actor first stages the **Line Viper** user-mode shellcode loader to harvest VPN session data, certificates and admin credentials, then drops Firestarter, which hooks into the LINA process, modifies `CSP_MOUNT_LIST` to execute on boot, drops itself to `/opt/cisco/platform/logs/var/log/svc_samcore.log`, and reinstates a copy at `/usr/bin/lina_cs`. Persistence triggers via signal handlers on graceful reboot. WebVPN requests carrying a hardcoded identifier deliver in-memory shellcode payloads. Cisco strongly recommends reimaging affected devices.

**Affected:** Cisco Firepower, Cisco Secure Firewall (ASA / FTD); US federal and allied government networks.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1505 (Server Software Component), T1071 (Application Layer Protocol), T1078.001 (Valid Accounts: Local Account), T1542 (Pre-OS Boot).

#### Indicators of Compromise

```
Implant path : /usr/bin/lina_cs
Decoy path   : /opt/cisco/platform/logs/var/log/svc_samcore.log
Boot artefact: CSP_MOUNT_LIST (modified)
Detection cmd: show kernel process | include lina_cs
CVEs         : CVE-2025-20333, CVE-2025-20362
```

> **SOC Action:** Run `show kernel process | include lina_cs` on every Cisco ASA/FTD device — any output indicates compromise, treat the appliance as fully owned and reimage from a known-good image rather than patching in place. Alert on unexpected modifications to `CSP_MOUNT_LIST`. Audit WebVPN access logs for anomalous POSTs from non-corporate ASNs in September–November 2025. Rotate all VPN, SSH, ASDM and SNMP credentials, plus any certificates or pre-shared keys present on potentially compromised devices.

### 3.3 UNC6692 abuses Microsoft Teams to drop the Snow malware suite

**Source:** [BleepingComputer — Threat actor uses Microsoft Teams to deploy new "Snow" malware](https://www.bleepingcomputer.com/news/security/threat-actor-uses-microsoft-teams-to-deploy-new-snow-malware/)

Mandiant attributes the campaign to **UNC6692**, a financially-motivated cluster combining email-bombing for urgency with Microsoft Teams "IT helpdesk" impersonation to coerce victims into installing a "spam-blocking patch." The dropper executes AutoHotkey scripts that side-load **SnowBelt**, a malicious Chrome extension that runs inside a headless Microsoft Edge process to evade user observation; persistence is achieved via scheduled tasks and a Startup-folder shortcut. SnowBelt relays operator commands over a WebSocket tunnel maintained by **SnowGlaze** (a tunneler that also exposes SOCKS proxying for arbitrary TCP routing), terminating in **SnowBasin**, a Python backdoor that runs a local HTTP server and executes attacker-supplied CMD or PowerShell with capabilities for remote shell, file management, screenshot capture, exfiltration and self-termination. Post-compromise tradecraft includes SMB/RDP enumeration, LSASS dumping, pass-the-hash to domain controllers and use of **FTK Imager** to extract the Active Directory database, SYSTEM, SAM and SECURITY hives, with exfiltration via **LimeWire**.

**Affected:** Enterprises with permissive Microsoft Teams external-federation settings; Chrome / Edge users who can sideload extensions; Windows-domain environments.

**MITRE ATT&CK:** T1566.003 (Phishing via Service), T1059.001 (PowerShell), T1059.005 (AutoHotkey), T1176 (Browser Extensions), T1078 (Valid Accounts), T1003 (OS Credential Dumping), T1021 (Remote Services), T1071 (Application Layer Protocol), T1041 (Exfiltration Over C2 Channel).

> **SOC Action:** Restrict Microsoft Teams external federation to an allow-list of trusted tenants and block "anyone with the link" external chats; alert on AutoHotkey (`AutoHotkey.exe`, `.ahk`) execution from user temp/Downloads paths; deploy Chrome Enterprise / Edge policy to block sideloaded extensions and require ExtensionInstallAllowlist; hunt EDR for `msedge.exe --headless` spawning unsigned extensions and for any process opening `lsass` handles outside of approved tooling; alert on installation or execution of `FTK Imager` / `LimeWire` on non-forensic-team endpoints.

### 3.4 ShinyHunters confirm ADT vishing → Okta → Salesforce data theft

**Source:** [BleepingComputer — ADT confirms data breach after ShinyHunters leak threat](https://www.bleepingcomputer.com/news/security/adt-confirms-data-breach-after-shinyhunters-leak-threat/)

ADT detected unauthorised access on 20 April 2026 and has confirmed theft of customer names, phone numbers and addresses, with date-of-birth and last-4 of SSN/Tax ID exposed for a small subset; payment data and customer security systems were unaffected. ShinyHunters has listed ADT on its leak site claiming 10M records and a 27 April 2026 deadline. The threat actor told BleepingComputer the entry vector was a **vishing call to an ADT employee** that captured an Okta SSO credential, which was then used to access the corporate **Salesforce** instance. ShinyHunters has run this exact playbook against Microsoft Entra, Okta and Google SSO accounts since 2024, pivoting from compromised SSO into Salesforce, Microsoft 365, Google Workspace, SAP, Slack, Zendesk, Dropbox and similar SaaS estates.

**Affected:** ADT customers (residential security); broader pattern affects any enterprise running federated SSO into SaaS data stores without phishing-resistant MFA.

**MITRE ATT&CK:** T1566.004 (Phishing: Voice), T1078.004 (Valid Accounts: Cloud Accounts), T1133 (External Remote Services), T1530 (Data from Cloud Storage Object).

> **SOC Action:** Enforce phishing-resistant MFA (FIDO2/passkeys) on all SSO accounts with Salesforce, M365 or other high-value SaaS access — disable phone/SMS/push fallback for these users. Build a Salesforce Event Monitoring detection for bulk `REPORT_EXPORT` and `BULK_API_RESULT` events outside business hours or from new IP ASNs. Configure Okta to alert on impossible-travel and on new device registration following an inbound voice call to the help desk; instruct help-desk staff to refuse credential or MFA resets initiated only via phone.

### 3.5 CVE-2026-41205 — Mako TemplateLookup path traversal via double-slash URI

**Source:** [Microsoft Security Update Guide — CVE-2026-41205](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41205)

Microsoft has published advisory **CVE-2026-41205** describing a path-traversal flaw in the Mako Python templating library: a double-slash prefix in a URI passed to `TemplateLookup` allows an attacker to escape the configured template root and read or modify arbitrary files. Mako is widely embedded in Pyramid, SQLAlchemy tooling, Django integrations and many Python web stacks, so exposure surface is broad. No exploitation in the wild has been reported in this batch.

**Affected:** Python web applications using `mako.lookup.TemplateLookup` with attacker-influenced URI inputs.

> **SOC Action:** Inventory Python applications for Mako usage (`pip list | grep -i mako`) and upgrade to the patched release as soon as available; in the interim, reject any inbound URI containing `//` before it reaches `TemplateLookup`, and add a WAF rule to drop requests with consecutive forward slashes in template-related paths. Review web-server access logs for double-slash anomalies in the last 30 days.

### 3.6 Linux kernel CVE batch — ksmbd UAF, NFC NCI memory corruption, Wi-Fi mt76 / mac80211 issues

**Source:** [Microsoft Security Update Guide — CVE-2026-23428 (ksmbd UAF)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23428), [CVE-2026-23339 (NFC NCI)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23339), [CVE-2026-23315 (mt76 OOB)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23315), [CVE-2026-23447 (cdc_ncm)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23447), [CVE-2026-23444 (mac80211)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23444)

Microsoft republished a sizeable batch of Linux-kernel advisories. The most notable are **CVE-2026-23428** — a use-after-free in `ksmbd`'s `share_conf` during SMB compound-request handling that may allow remote code execution or denial of service against any Linux host exposing in-kernel SMB; **CVE-2026-23339**, a premature skb-free in the NFC NCI subsystem on early error paths that opens memory-corruption primitives; and **CVE-2026-23315**, an out-of-bounds write in MediaTek `mt76_connac2_mac_write_txwi_80211()`. The wider batch (CVE-2026-23434/23438/23439/23442/23446 and others) covers driver memory leaks, race conditions in qdisc reset, and NULL-deref in IPv6 SRv6, all rated medium. The pipeline's correlation engine (batch 88) flagged **T1068 — Exploitation for Privilege Escalation** as the dominant shared TTP across the kernel CVEs.

**Affected:** Linux servers, embedded Linux, network appliances; particularly hosts running ksmbd, Wi-Fi (mac80211 / mt76), or NFC drivers.

> **SOC Action:** Prioritise the ksmbd patch on any Linux host that exposes SMB to untrusted networks — and consider replacing ksmbd with userspace Samba where feasible. For fleet management, deploy the latest stable / LTS kernel in your distro's update channel within the standard 30-day kernel SLA. On endpoints, the NFC, mt76 and mac80211 issues require local adjacency or driver path access; treat them as endpoint-hardening items rather than internet-exposed risks.

### 3.7 TGR-STA-1030 — Continued Central and South America activity

**Source:** [Unit 42 — TGR-STA-1030: New Activity in Central and South America](https://unit42.paloaltonetworks.com/new-activity-central-south-america/)

Unit 42 reports continued activity from threat group **TGR-STA-1030** across multiple Central and South American countries since February 2026, using the same TTPs previously documented. The brief is short and does not enumerate fresh technical indicators, but the persistence of cross-border activity warrants tracking by regional CERTs and multinationals with LATAM operations.

**Affected:** Organisations and government entities across Central and South America.

> **SOC Action:** Pull the prior TGR-STA-1030 IOC set into your detection stack if not already present and apply geo-aware alerting on inbound authentication from LATAM jump-points to corporate VPNs. Brief regional security leads on the campaign's continuing scope.

### 3.8 Qilin RaaS — High-volume leak-site activity (12+ new victims in 24h)

**Source:** [RansomLook — Qilin tracking](https://www.ransomlook.io//group/qilin)

The Qilin ransomware-as-a-service group posted a heavy slate of new victims to its leak site in the reporting period, including **Chase Cooper Limited (RiskLogix Solutions)**, **KEMBA Indianapolis Credit Union**, **First County FCU**, **Chelten House**, **Woodfields Consultants**, **Travel Expert**, **Mid Florida Dermatology & Plastic Surgery**, **LA Woodworks**, **Buckley Powder**, **Cahbo Produkter**, **Leistritz Turbine Technology**, **Dillon Family Medicine** and **SanCor**. Targeted sectors span credit unions, healthcare/dermatology, manufacturing, consulting and food production. Qilin operates a Tor-fronted RaaS leveraging README-RECOVER-[rand]_2.txt-style ransom notes with Jabber and Tox communication channels. **Lamashtu** and **Inc Ransom** also posted, with Lamashtu adding Apple Film Group and Malaysian NPK Fertilizer Sdn. Bhd, and Inc Ransom listing krauseundco. **Brain Cipher** added bridgeway-consulting.co.uk, and **Nightspire** posted Swansea Ambulance Corps.

**Affected:** Small-to-mid-sized enterprises across financial services, healthcare, manufacturing and consulting in the US, UK, EU, LATAM and APAC.

**MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1657 (Financial Theft), T1059 (Command and Scripting Interpreter), T1566 (Phishing).

> **SOC Action:** Assume RaaS operators including Qilin, Lamashtu, Inc Ransom and Brain Cipher are buying initial access from the same broker pool that targets RDP, VPN and exposed RMM tools — block legacy NTLM where possible, enforce MFA on every external service, and run a fresh attack-surface scan for unauthenticated VPN/RMM portals. Subscribe to the relevant leak-site feeds and configure alerts for your supply-chain partners by domain so you receive 24-72h warning before customer notification cycles.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 **Critical** | Application-layer-protocol exploitation in supply-chain attacks | npm Threat Landscape (TeamPCP / Shai-Hulud); Firestarter on Cisco ASA/FTD (UAT-4356) |
| 🟠 **High** | Increased exploitation of privilege-escalation flaws across sectors | CVE-2026-23339 (NFC NCI); CVE-2026-23315 (mt76 Wi-Fi); "When a Supply Chain Compromise Happens, Defenders Deserve More Than Starting From Zero" |
| 🟡 **Medium** | Persistent phishing as the spine of broader campaigns | ADT/ShinyHunters vishing; Telegram-disclosed Maluku Utara breach; ongoing Iran "low and slow" cyber posture |
| 🟠 **High** | Cross-sector RaaS expansion | Qilin (12+ posts), Lamashtu, Inc Ransom, Nightspire, Brain Cipher leak-site activity |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors

- **Qilin** (63 reports) — Most-tracked RaaS operator in the pipeline; heavy daily leak-site cadence, broad sector targeting.
- **The Gentlemen** (58 reports) — Sustained ransomware activity across engineering and technology victims.
- **Coinbase Cartel** (38 reports) — Continued RaaS-style postings.
- **DragonForce** (28 reports) — Active ransomware operator with steady tempo.
- **Nightspire** (27 reports) — Posted Swansea Ambulance Corps and another partial-name victim today.
- **shadowbyt3$** (25 reports) — Ongoing leak-site presence.
- **TeamPCP** (1 report this period; net-new) — Newly attributed by Unit 42 to the Shai-Hulud "Third Coming" npm campaign.
- **UAT-4356 / ArcaneDoor** (1 report this period) — Re-surfaced via the CISA/NCSC Firestarter advisory.
- **UNC6692** (1 report this period) — Mandiant-named actor behind the Snow malware suite.
- **ShinyHunters** (1 report this period) — Vishing → Okta → Salesforce playbook re-confirmed by ADT incident.

### Malware Families

- **RansomLock / RansomLook tooling** (45 / 29 reports) — Aggregator-tagged RaaS infrastructure.
- **RaaS scaffolding** (25 reports) — README-RECOVER ransom-note family, Tox/Jabber comms.
- **DragonForce ransomware** (24 reports).
- **Akira ransomware** (12 reports).
- **Snow / SnowBelt / SnowGlaze / SnowBasin** (net-new this period) — UNC6692 modular browser-extension + Python backdoor suite.
- **Firestarter / Line Viper** (net-new this period) — UAT-4356 LINA-resident Cisco ASA/FTD persistence chain.
- **Shai-Hulud / Shai-Hulud 2.0** (net-new this period) — TeamPCP wormable npm payload.

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| RansomLock | 21 | [link](https://www.ransomlook.io/) | Primary aggregator for Qilin, Lamashtu, Inc Ransom, Nightspire, Brain Cipher leak posts |
| Microsoft (MSRC) | 19 | [link](https://msrc.microsoft.com/update-guide) | Linux kernel CVE batch incl. ksmbd UAF, NFC NCI, mt76, mac80211, Mako CVE-2026-41205 |
| BleepingComputer | 5 | [link](https://www.bleepingcomputer.com/news/security/firestarter-malware-survives-cisco-firewall-updates-security-patches/) | Firestarter, Snow malware, ADT/ShinyHunters, Windows Update controls |
| Unknown / Telegram OSINT | 3 | — | Telegram channel disclosures; channel URLs intentionally omitted |
| Unit42 | 2 | [link](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) | npm threat landscape (critical); TGR-STA-1030 LATAM activity |
| Wired Security | 1 | [link](https://www.wired.com/story/security-news-this-week-discord-sleuths-gained-unauthorized-access-to-anthropics-mythos/) | Weekly roundup |
| Schneier | 1 | [link](https://www.schneier.com/) | Friday Squid Blogging |
| Elastic Security Labs | 1 | [link](https://www.elastic.co/security-labs/claude-code-cowork-monitoring-otel-elastic) | OTel monitoring of Claude Code/Cowork at scale |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Run `show kernel process | include lina_cs` against every Cisco ASA / FTD appliance and reimage any device returning output — Firestarter survives patching, so do not treat the in-place upgrade as remediation. Apply the CVE-2025-20333 / CVE-2025-20362 fixes if not already deployed.
- 🔴 **IMMEDIATE:** Block `@bitwarden/cli@2026.4.0` in your internal npm proxy, rotate every npm publish token and GitHub PAT issued to developer or CI accounts in the last 60 days, and audit GitHub for repos containing the string "Shai-Hulud" — this is the active TeamPCP wormable supply-chain wave.
- 🟠 **SHORT-TERM:** Lock down Microsoft Teams external federation to an allow-list and roll out Chrome / Edge enterprise policies that block sideloaded extensions; alert EDR on AutoHotkey, headless Edge, and `msedge.exe --headless` spawning unsigned extensions to catch UNC6692 Snow-stage activity early.
- 🟠 **SHORT-TERM:** Patch the Linux ksmbd UAF (CVE-2026-23428) on any host exposing SMB, and roll the wider kernel batch in your standard 30-day cycle. Inventory Mako usage and ship the CVE-2026-41205 fix or a WAF rule that strips `//` from template paths.
- 🟡 **AWARENESS:** Brief help-desk and identity teams on the ShinyHunters vishing → Okta → Salesforce pattern; deny credential / MFA resets initiated by phone alone, and switch high-value SSO users to phishing-resistant MFA (FIDO2 / passkeys).
- 🟢 **STRATEGIC:** With Qilin, Lamashtu, Inc Ransom, Brain Cipher and Nightspire all posting in volume, treat external-attack-surface monitoring (RDP, VPN, RMM, Citrix, SSL VPN appliances) as a continuous service rather than a quarterly scan; add supplier domains to leak-site monitoring so you get 24-72h warning before partner notifications.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 53 reports processed across 1 correlation batch. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
