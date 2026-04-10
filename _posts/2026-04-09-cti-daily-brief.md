---
layout: post
title:  "CTI Daily Brief: 2026-04-09 - Flannel cross-node RCE (CVE-2026-32241), iOS kexploit, Iranian ICS targeting, CPUID supply-chain compromise"
date:   2026-04-10 20:05:37 +0000
description: "52 reports processed. Critical Flannel cross-node RCE and an iOS 18/26 kexploit headline the day. Iranian state-backed actors targeting ~4,000 US Rockwell PLCs, a CPUID supply-chain compromise pushing trojanised CPU-Z/HWMonitor, and sustained ransomware pressure from Qilin, The Gentlemen, Inc Ransom, and PEAR dominate the operational picture."
category: daily
tags: [cti, daily-brief, qilin, the-gentlemen, inc-ransom, pear, storm-2755, cve-2026-32241]
classification: TLP:CLEAR
reporting_period: "2026-04-09"
generated: "2026-04-10"
draft: true
severity: critical
report_count: 52
sources:
  - Microsoft
  - RansomLock
  - BleepingComputer
  - RecordedFutures
  - AlienVault
  - Cisco Talos
  - SANS
  - Wired Security
  - Schneier
  - Wiz
  - Upwind
---

| Reporting Period | Classification | Generated |
|------------------|----------------|-----------|
| 2026-04-09 (24h) | TLP:CLEAR | 2026-04-10 |

## 1. Executive Summary

The pipeline processed 52 reports across 12 sources in the last 24 hours, dominated by ransomware operations and a concentrated batch of newly disclosed vulnerabilities from Microsoft's MSRC feed. Two reports were rated critical: CVE-2026-32241, a cross-node remote code execution flaw in Flannel via extension-backend BackendData injection, and an iOS 18.0–18.7.1 / 26.0–26.0.1 full-root "kexploit" surfaced via a Telegram OSINT channel. High-severity operational items include Iranian state-backed targeting of nearly 4,000 internet-exposed Rockwell Automation / Allen-Bradley PLCs, a supply-chain compromise of the CPUID project pushing trojanised CPU-Z and HWMonitor installers, a ransomware attack on Dutch healthcare-software provider ChipSoft disrupting hospitals, and Storm-2755 "payroll pirate" AiTM phishing campaigns against Canadian employees. No new CISA KEV additions were reported in the collection data for this period.

## 2. Severity Distribution

| Severity | Count | Key Drivers |
|----------|-------|-------------|
| 🔴 **CRITICAL** | 2 | CVE-2026-32241 Flannel cross-node RCE; iOS 18/26 kexploit (WIP darksword) |
| 🟠 **HIGH** | 34 | Ransomware (Qilin, The Gentlemen, Inc Ransom, PEAR, ailock, shadowbyt3$); Iranian ICS targeting; CPUID supply-chain; ChipSoft hospital disruption; Storm-2755 payroll pirate; VENOM phishing; LucidRook; Axios npm compromise; MSRC CVE batch |
| 🟡 **MEDIUM** | 5 | Phishing trend reporting; lower-confidence correlation items |
| 🟢 **LOW** | 3 | Minor advisories |
| 🔵 **INFO** | 8 | Landscape commentary, vendor blogs |

## 3. Priority Intelligence Items

### 3.1 CVE-2026-32241 — Flannel cross-node remote code execution (CRITICAL)

**Source:** [Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32241)

Microsoft disclosed a critical vulnerability in Flannel, the Kubernetes CNI plugin, allowing cross-node remote code execution through BackendData injection into the extension backend. Exploitation enables arbitrary code execution that can traverse nodes within a cluster, making this a high-impact lateral-movement primitive for any Kubernetes environment running affected Flannel versions. The MSRC entry notes "information published" with no public exploit code referenced in the current report, but the cross-node scope effectively collapses pod-to-node and node-to-node isolation boundaries in affected clusters.

**Affected:** Kubernetes clusters using Flannel CNI with the extension backend.

> **SOC Action:** Inventory Kubernetes clusters and identify Flannel deployments (`kubectl -n kube-system get ds | grep flannel`). Pin to patched Flannel versions per the MSRC advisory, disable the extension backend if not required, and add detections for anomalous cross-node pod-to-pod traffic and unexpected process execution originating from flannel containers.

### 3.2 iOS 18 & iOS 26 "kexploit" full-root exploit — WIP darksword (CRITICAL)

**Source:** Telegram (channel name redacted)

A Telegram OSINT post (TLP:AMBER+STRICT in the source feed; reproduced here as sanitised narrative only) advertises a work-in-progress "kexploit" claiming full root access on iOS 18.0 through 18.7.1 and iOS 26.0 through 26.0.1. Associated MITRE techniques reference T1068 (Exploitation for Privilege Escalation) and T1059 (Command and Scripting Interpreter). Attribution and claim validation are unconfirmed; treat as an emerging capability claim until corroborated by vendor or independent research.

**Affected:** iOS 18.0–18.7.1 and iOS 26.0–26.0.1.

> **SOC Action:** Enforce MDM policy requiring devices to be upgraded to the latest available iOS build above 26.0.1 where possible. Flag any managed device still running an affected version for priority update. Treat jailbroken or out-of-compliance devices as untrusted and restrict access to corporate resources via conditional access.

### 3.3 Nearly 4,000 US industrial devices exposed to Iranian cyberattacks (HIGH)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/nearly-4-000-us-industrial-devices-exposed-to-iranian-cyberattacks/)

Iranian state-backed activity is targeting internet-exposed Rockwell Automation / Allen-Bradley programmable logic controllers across the United States, with reporting citing operational disruptions and manipulation of HMI/SCADA displays and project-file extraction. The report hedges attribution to "Iranian-affiliated actors"; that hedging is preserved here. Activity aligns with longstanding OT targeting campaigns rather than a newly disclosed vulnerability.

**Affected:** Rockwell Automation / Allen-Bradley PLCs reachable from the public internet; industrial operators with weak OT perimeter segmentation.

> **SOC Action:** Query Shodan/Censys for Rockwell/Allen-Bradley signatures on your public IP ranges (`port:44818 "Allen-Bradley"`). Block inbound CIP/EtherNet-IP (TCP/UDP 44818, 2222) at the perimeter. Validate that engineering workstations and HMIs are segmented from corporate IT, rotate any default or shared PLC credentials, and review project-file access logs for unauthorised downloads.

### 3.4 CPUID supply-chain compromise — trojanised CPU-Z / HWMonitor (HIGH)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/supply-chain-attack-at-cpuid-pushes-malware-with-cpu-z-hwmonitor/)

Attackers compromised a secondary API used by the CPUID project website and rewrote download URLs for CPU-Z and HWMonitor to deliver trojanised installers masquerading as HWiNFO. The malware is multi-stage and primarily in-memory: a Russian-language installer drops a .NET assembly that proxies NTDLL functionality for evasion. This is a classic "legitimate utility as initial access" vector and CPU-Z/HWMonitor are extremely common on IT/engineering endpoints.

**Affected:** Any endpoint where CPU-Z or HWMonitor was downloaded from cpuid.com during the compromise window.

> **SOC Action:** Hunt for recent downloads of `cpu-z*.exe` and `hwmonitor*.exe` from cpuid.com in proxy/web-gateway logs. In EDR, alert on CPU-Z or HWMonitor processes loading .NET assemblies that call NTDLL proxies, spawning PowerShell, or establishing outbound TCP to non-Microsoft IPs. Block installs of these utilities from non-vetted sources until CPUID confirms clean binaries, and consider temporarily blocking the cpuid.com download paths at the web gateway.

### 3.5 Dutch hospitals disrupted after ChipSoft ransomware attack (HIGH)

**Source:** [The Record / Recorded Future](https://therecord.media/chipsoft-ransomware-attack-disrupts-dutch-hospitals)

A ransomware attack on Dutch healthcare-software vendor ChipSoft disrupted digital services used by hospitals and patients across the Netherlands. ChipSoft disabled multiple platforms to contain the incident. No attribution is given in the source; no specific ransomware family is named in the report. This is a third-party / supply-chain healthcare disruption event and reinforces the weekly trend of ransomware pressure on healthcare vendors.

**Affected:** Dutch hospitals dependent on ChipSoft platforms; downstream patient services.

> **SOC Action:** For organisations with ChipSoft or similar EHR/HIS vendor dependencies, validate that ingress from the vendor's management infrastructure is segmented and time-bounded. Confirm offline backups are current and test rapid fail-over for dependent clinical workflows. Review the vendor's IR disclosures for IOCs as they are released.

### 3.6 Storm-2755 "payroll pirate" AiTM phishing against Canadian employees (HIGH)

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-canadian-employees-targeted-in-payroll-pirate-attacks/), [AlienVault OTX](https://otx.alienvault.com/pulse/69d80c2c976a9ec209e19217)

Microsoft Incident Response attributes a financially motivated campaign to Storm-2755, targeting Canadian employees via malvertising and SEO-poisoned fake Microsoft 365 sign-in pages. The actor uses adversary-in-the-middle (AiTM) techniques to capture session cookies and OAuth tokens, bypasses MFA by replaying stolen session material, sets mailbox rules to hide notifications, and modifies direct-deposit details in HR/payroll systems. MITRE techniques cited in the source: T1566 (Phishing), T1078 (Valid Accounts), T1185 (Browser Session Hijacking), T1110 (Brute Force: MFA Bypass), and T1213 (Data from Information Repositories).

**Affected:** Microsoft 365 tenants with Canadian workforce; HR/payroll systems integrated with M365 identity.

#### Indicators of Compromise
```
Technique: T1566 Phishing (malvertising + SEO poisoning)
Technique: T1078 Valid Accounts (replayed session cookies / OAuth tokens)
Technique: T1185 Browser Session Hijacking (AiTM)
Technique: T1110 Brute Force: MFA Bypass
Actor:     Storm-2755
Tooling:   Axios HTTP client used for token replay
```

> **SOC Action:** In Entra ID, require phishing-resistant MFA (FIDO2 / Windows Hello for Business) for payroll and HR roles, and enable token-protection / continuous-access evaluation. Hunt for sign-ins with anomalous `User-Agent` values containing `axios/`, inbox rules that move or delete messages matching `payroll|HR|direct deposit`, and Azure audit events showing direct-deposit or bank-detail changes without a corresponding ticket.

### 3.7 Additional high-impact items (grouped)

- **VENOM phishing-as-a-service** targeting senior executives' Microsoft logins via SharePoint-themed lures with QR codes, AiTM, and device-code flows ([BleepingComputer](https://www.bleepingcomputer.com/news/security/new-venom-phishing-attacks-steal-senior-executives-microsoft-logins/)). **SOC Action:** Block QR-code-embedded attachments at the mail gateway where feasible and disable device-code flow for privileged roles in Entra.
- **LucidRook (UAT-10362)** — Lua-based modular malware delivered via LNK/EXE chains to NGOs and universities in Taiwan, using decoys impersonating government letters and AV executables, exfiltrating over FTP with RSA encryption ([BleepingComputer](https://www.bleepingcomputer.com/news/security/new-lucidrook-malware-used-in-targeted-attacks-on-ngos-universities/)). **SOC Action:** Block LNK execution from email/download paths via ASR rules; alert on processes parenting `ftp.exe` or outbound FTP from user workstations.
- **Axios npm supply-chain compromise** — malicious versions `axios@1.14.1` and `axios@0.30.4` with a postinstall script deploying a RAT ([LevelBlue SpiderLabs](https://www.levelblue.com/blogs/spiderlabs-blog/axios-npm-package-supply-chain-compromise-leads-to-rat-deployment)). **SOC Action:** Pin axios to known-good versions, audit `package-lock.json` across repos for the tagged versions, and alert on `npm`/`node` parent processes spawning `cmd.exe`, `curl`, or `wget`.
- **ScreenConnect in-memory loader** — fake Adobe Acrobat Reader download dropping an obfuscated VBScript loader that uses .NET reflection, PEB manipulation, and UAC-bypass via auto-elevated COM objects ([Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/memory-loader-drops-screenconnect)). **SOC Action:** Alert on `wscript.exe`/`cscript.exe` loading `System.Reflection` or spawning `powershell.exe` to install remote-access tooling; block unapproved RMM agents via application control.
- **MSRC CVE batch** — multiple Linux-kernel apparmor race conditions (CVE-2026-23406/23410/23411), Vim NetBeans command injection (CVE-2026-39881), and Sleuth Kit bugs (CVE-2026-40024/40025/40026). **SOC Action:** Track these in your vulnerability-management pipeline; prioritise the apparmor set for multi-tenant Linux hosts and container builders.
- **Drift crypto theft attributed to UNC4736 / North Korea** — $280M theft via compromised contributors and potentially malicious TestFlight apps ([The Record](https://therecord.media/drift-crypto-theft-post-mortem-north-korea)). **SOC Action:** Review supply-chain hygiene for any crypto or fintech developer environments — enforce signed commits, restrict TestFlight distribution, and treat long-lived contractor identities as a high-risk population.

## 4. AI-Identified Correlation Trends

| Risk | Trend | Supporting Evidence |
|------|-------|---------------------|
| 🔴 CRITICAL | Exploitation of zero-day vulnerabilities in widely used software platforms (batch 59) | "Hackers exploiting Acrobat Reader zero-day flaw since December"; "CVE-2026-2673 OpenSSL TLS 1.3 server may choose unexpected key agreement group" |
| 🟠 HIGH | Increased targeting of critical infrastructure and healthcare sectors by ransomware groups (batch 61) | Nearly 4,000 US industrial devices exposed to Iranian cyberattacks; Dutch hospitals disrupted by ChipSoft ransomware attack |
| 🟠 HIGH | Rise in AI-driven vulnerability discovery and exploitation (batch 61) | Wiz "Claude Mythos" analysis; Wired / Anthropic Mythos cybersecurity-reckoning coverage |
| 🟠 HIGH | Increased use of phishing in ransomware campaigns targeting diverse sectors (batch 60) | UK Electronics by The Gentlemen; Kannarr Eye Care by Inc Ransom; Forestal Atlántico Sur by shadowbyt3$; LucidRook campaign |
| 🟠 HIGH | Ransomware-as-a-service models gaining traction with multiple actors (batch 60) | Chalmers & Kubeck, Guerin Glass, HIGASHIYAMA Industries — all claimed by Qilin |
| 🟠 HIGH | Phishing and credential stuffing in financial services (batch 59) | "When attackers already have the keys, MFA is just another door to open"; $3.6M theft from Bitcoin Depot |
| 🟡 MEDIUM | Phishing remains a prevalent TTP across diverse sectors (batch 61) | wright-ryan.com by Inc Ransom; Drift / UNC4736 theft |

## 5. Trending Entities (Pipeline-Wide)

### Threat Actors
- **Qilin** (49 + 14 reports across casing variants) — Russian-speaking RaaS; today claimed Chalmers & Kubeck, Guerin Glass, and HIGASHIYAMA Industries
- **The Gentlemen** (39 + 17 reports) — Multi-sector ransomware; today claimed UK Electronics and GEM Terminal
- **nightspire** (36 reports) — Active ransomware operator
- **TeamPCP** (31 reports) — Persistent operator
- **dragonforce** (27 reports) — Active RaaS
- **Akira** (22 reports) — Ongoing pressure on mid-market targets
- **Hive** (16 reports) — Continued activity despite historical takedowns
- **Inc Ransom** (RansomLock-tracked) — Today claimed wright-ryan.com, Martek Co. Ltd., Kannarr Eye Care
- **PEAR** — Today claimed Arkansas Oral & Maxillofacial Surgeons and Colonial Presbyterian Church
- **Storm-2755** — AiTM "payroll pirate" campaign against Canadian M365 users
- **UNC4736** (unconfirmed DPRK) — Drift $280M crypto theft
- **UAT-10362** — LucidRook targeting NGOs and universities

### Malware Families
- **ransomware (unspecified)** (28 reports) — Category aggregate
- **DragonForce ransomware** (25 reports)
- **Akira ransomware** (18 reports)
- **RaaS** (13 reports) — Aggregated RaaS tagging
- **PLAY ransomware** (8 reports)
- **AiLock** — RaaS using ChaCha20 + NTRUEncrypt, `.AiLock` extension
- **LucidRook** — New Lua-based modular implant, FTP exfil, RSA-encrypted
- **kexploit** (iOS) — Critical-rated claimed capability
- **VENOM** — AiTM phishing kit targeting executives

## 6. Source Distribution

| Source | Reports | URL | Notes |
|--------|---------|-----|-------|
| Microsoft (MSRC) | 15 | [link](https://msrc.microsoft.com/update-guide/) | CVE batch incl. critical CVE-2026-32241 Flannel RCE and AppArmor race conditions |
| RansomLock | 13 | [link](https://www.ransomlook.io/) | Ransomware leak-site monitoring: Qilin, The Gentlemen, Inc Ransom, PEAR, ailock, shadowbyt3$ |
| BleepingComputer | 7 | [link](https://www.bleepingcomputer.com/news/security/nearly-4-000-us-industrial-devices-exposed-to-iranian-cyberattacks/) | Iranian ICS targeting; CPUID supply-chain; Storm-2755; VENOM; LucidRook |
| RecordedFutures | 6 | [link](https://therecord.media/chipsoft-ransomware-attack-disrupts-dutch-hospitals) | ChipSoft healthcare disruption; Drift/UNC4736 crypto theft |
| AlienVault (OTX) | 3 | [link](https://otx.alienvault.com/pulse/69d80c2c976a9ec209e19217) | ScreenConnect loader; Axios npm compromise; Storm-2755 TTPs |
| Unknown (Telegram OSINT) | 2 | — | iOS kexploit claim; ransomware group tracker (Telegram sources not linked) |
| Cisco Talos | 1 | [link](https://blog.talosintelligence.com/video-the-ttp-ep-22-the-collapse-of-the-patch-window/) | "Collapse of the patch window" — industrialisation of exploitation |
| SANS ISC | 1 | [link](https://isc.sans.edu/diary/rss/32884) | Obfuscated JavaScript phishing chain with AES/MSBuild injection |
| Wiz | 1 | [link](https://www.wiz.io/blog/claude-mythos) | AI-driven vulnerability discovery analysis |
| Wired Security | 1 | [link](https://www.wired.com/) | Anthropic Mythos cybersecurity-reckoning commentary |
| Schneier | 1 | [link](https://www.schneier.com/) | Commentary |
| Upwind | 1 | [link](https://www.upwind.io/) | Vendor analysis |

## 7. Consolidated Recommendations

- 🔴 **IMMEDIATE:** Patch Flannel in all Kubernetes clusters against CVE-2026-32241 and disable the extension backend where it is not required. Cross-node RCE collapses cluster isolation — this should be treated as a top-of-queue action for any platform team running Flannel.
- 🔴 **IMMEDIATE:** Block unsanctioned downloads of CPU-Z and HWMonitor from cpuid.com and hunt for any installations in the last 72 hours in EDR and web-gateway logs. Treat matches as suspected initial-access compromises pending verification.
- 🟠 **SHORT-TERM:** For any fleet with iOS devices, enforce MDM compliance to the latest iOS build above 26.0.1 and flag devices still on 18.0–18.7.1 or 26.0–26.0.1 for priority update given the unconfirmed but credible kexploit claim.
- 🟠 **SHORT-TERM:** Roll out phishing-resistant MFA (FIDO2) and token-protection / CAE for payroll, HR, and executive populations to blunt Storm-2755 and VENOM AiTM campaigns. Hunt for `axios/`-family user agents and anomalous inbox rules targeting payroll keywords.
- 🟠 **SHORT-TERM:** Scan public IP space for exposed Rockwell / Allen-Bradley PLCs (CIP/EtherNet-IP on 44818/2222), block inbound at the perimeter, and validate OT segmentation against IT in line with Iranian state-backed targeting activity.
- 🟡 **AWARENESS:** Pin and audit `axios` npm versions across all repos, and treat postinstall scripts as a high-risk surface in CI/CD. The Axios compromise is a reminder that direct-dependency integrity checks are necessary even for widely trusted packages.
- 🟢 **STRATEGIC:** Account for AI-accelerated vulnerability discovery (Wiz "Claude Mythos" analysis) in patch-SLA planning. The Talos "collapse of the patch window" narrative and the Mythos capability together argue for moving critical-patch windows closer to disclosure-day rather than disclosure + 30.

---
*This brief was generated entirely by AI from automated threat intelligence collection and correlation pipelines, made up of 52 reports processed across 5 correlation batches. A human analyst reviewed and approved this report before publication, but AI-generated analysis may contain errors in attribution, severity assessment, or indicator extraction. Always verify IOCs, CVE details, and threat actor attribution against primary sources before taking operational action.*
